'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-08-03

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from traceback import format_exc

from goodcrypto.mail import contacts, options, user_keys
from goodcrypto.mail.constants import TAG_WARNING
from goodcrypto.mail.i18n_constants import SERIOUS_ERROR_PREFIX, WARNING_PREFIX
from goodcrypto.mail.crypto_software import get_classname, get_key_classname
from goodcrypto.mail.message import constants, encrypt_utils, history, utils
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.history import gen_verification_code
from goodcrypto.mail.message.inspect_utils import get_charset, get_message_id, is_content_type_text
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.utils import i18n
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr import mime_constants



class Encrypt(object):
    """
        Encrypt message filter.

        This class encodes MIME messages using RFC 3156 "MIME Security
        with OpenPGP", specifically section 6.2 "Combined method".
        We send PGP public keys in the header instead of
        in an application/pgp-keys MIME body part so the keys are transparent
        to users who do not yet encrypt, and so we can specify when a key is
        for use with a particular encryption software.
        Section 6.1 of RFC 3156 gives a way to specify what was encrypted.
        We include the encrypted content type in a header instead, apparently
        because section 6.1 looked like it was just for message signatures.
        But that's not how it is used by OpenPGP MIME packages such as EnigMail.
        We need to apply section 6.1 the same way.
    """
    
    DEBUGGING = False
    
    UNABLE_TO_ENCRYPT = i18n("Error while trying to encrypt message from {from_email} to {to_email} using {encryption}")
    POSSIBLE_ENCRYPT_SOLUTION = i18n("Report this error to your sysadmin.")

    def __init__(self, crypto_message):
        '''
            >>> encrypt = Encrypt(None)
            >>> encrypt != None
            True
        '''

        self.log = LogFile()
        self.crypto_message = crypto_message
        self.verification_code = None
        self.ready_to_protect_metadata = False

    def make_message_unreadable(self):
        ''' 
            Encrypt a message if possible or
            add a warning about the danger of sending unencrypted messages.
        '''

        def log_error(error_message):
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            try:
                self.crypto_message.add_tag_once('{} {}'.format(
                    SERIOUS_ERROR_PREFIX, error_message))
            except Exception:
                record_exception()
                self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')


        filtered = encrypted = False
        inner_encrypted_with = []
        try:
            if self.crypto_message is None:
                self.log_message('no crypto message defined')
                self.crypto_message = CryptoMessage()
                from_user = to_user = None
            else:
                from_user = self.crypto_message.smtp_sender()
                to_user = self.crypto_message.smtp_recipient()
            
            self.log_message("trying to encrypt message from {} to {}".format(from_user, to_user))

            self.ready_to_protect_metadata = encrypt_utils.is_ready_to_protect_metadata(from_user, to_user)
    
            encryption_names = utils.get_encryption_software(to_user)
            if encryption_names is None or len(encryption_names) <= 0:
                self.log_message('no encryption software defined for: {}'.format(to_user))
                if options.auto_exchange_keys():
                    # add the public key so the receiver can use crypto in the future
                    self.crypto_message.add_public_key_to_header(from_user)
                # if we're not exchange keys, but we are creating them, then do so now
                elif options.create_private_keys():
                    utils.add_private_key(from_user)

                self.crypto_message.set_filtered(True)
            else:
                try:
                    self.verification_code = gen_verification_code()
                    inner_encrypted_with = self._encrypt_message_with_all(encryption_names)
                    if self.DEBUGGING:
                        self.log_message('message after encryption:\n{}'.format(
                          self.crypto_message.get_email_message().to_string()))
                except MessageException as message_exception:
                    raise MessageException(value=message_exception.value)
                except Exception as exception:
                    log_error(str(exception))
                except IOError as io_error:
                    log_error(io_error.value)

            if self.ready_to_protect_metadata:
                if options.bundle_and_pad():
                    tags_added = self.crypto_message.add_tag_to_message(self.crypto_message.get_tag())
                    self.log_message('tags added to message before bundling: {}'.format(tags_added))
                    message_name = utils.packetize(
                       self.crypto_message, inner_encrypted_with, self.verification_code)
                    if os.stat(message_name).st_size > options.bundled_message_max_size():
                        self.log_message('Message too large to bundle so throwing MessageException')
                        if os.path.exists(message_name):
                            os.remove(message_name)
                        error_message = 'Message too large to send. The maximum size, including attachments, is {} KB.'.format(
                             options.bundle_message_kb())
                        self.log_message(error_message)
                        raise MessageException(value=i18n(error_message))
                    else:
                        self.log_message('message waiting for bundling: {}'.format(
                          self.crypto_message.is_processed()))
                else:
                    # add the original sender and recipient in the header
                    self.crypto_message.get_email_message().add_header(constants.ORIGINAL_FROM, from_user)
                    self.crypto_message.get_email_message().add_header(constants.ORIGINAL_TO, to_user)

                    # even if the inner message isn't encrypted, encrypt 
                    # the entire message to protect the metadata
                    message_id = get_message_id(self.crypto_message.get_email_message())
                    self.crypto_message = encrypt_utils.create_protected_message(
                        self.crypto_message.smtp_sender(), self.crypto_message.smtp_recipient(), 
                        self.crypto_message.get_email_message().to_string(), message_id)
                    self.log_message('added protective layer for metadata')
            elif self.crypto_message.is_crypted():
                # remove the following line if not used by 2015-10-01
                #encrypt_utils.limit_recipients(self.crypto_message)
                if self.DEBUGGING:
                    self.log_message('full encrypted message:\n{}'.format(
                       self.crypto_message.get_email_message().to_string()))
            else:
                self.crypto_message.add_tag_once('{}: {}'.format(
                  TAG_WARNING, i18n('Anyone could have read this message. Use encryption, it works.')))

            if self.crypto_message.is_processed():
                self.log_message('message processed and awaiting bundling')
            else:
                tags = self.crypto_message.get_tag()
                tags_added = self.crypto_message.add_tag_to_message(tags)
                self.log_message('tags added to message: {}'.format(tags_added))
    
                # finally save a record so the user can verify the message was sent encrypted
                if self.crypto_message.is_crypted():
                    self.crypto_message.set_crypted_with(inner_encrypted_with)
                    history.add_encrypted_record(
                      self.crypto_message, self.verification_code)

        except MessageException as message_exception:
            raise MessageException(value=message_exception.value)

        except Exception, IOError:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        if self.crypto_message is not None:
            self.log_message('  final status: filtered: {} encrypted: {}'.format(
                self.crypto_message.is_filtered(), self.crypto_message.is_crypted()))

        return self.crypto_message

    def _encrypt_message_with_all(self, encryption_names):
        '''
            Encrypt the message with each encryption program.
        '''
        SENT_MESSAGE_PRIVATELY = i18n('Sent this message privately.')
        SENT_MESSAGE_PLUS_METADATA_PRIVATELY = i18n('Sent this message and its metadata privately.')
        VERIFICATION_INSTRUCTION = i18n(
          "Check with the sender that their server encrypted this message (sender's verification code: {}).".format(self.verification_code))

        encrypted = fatal_error = False
        error_message = ''
        encrypted_with = []
        encrypted_classnames = []
        to_user = self.crypto_message.smtp_recipient()
        original_payload = self.crypto_message.get_email_message().get_message().get_payload()

        self.log_message("encrypting using {} encryption software".format(encryption_names))
        for encryption_name in encryption_names:
            encryption_classname = get_key_classname(encryption_name)
            if encryption_classname not in encrypted_classnames:
                try:
                    if options.require_key_verified():
                        __, key_ok, __ = contacts.get_fingerprint(to_user, encryption_name)
                        self.log_message("{} {} key verified: {}".format(to_user, encryption_name, key_ok))
                    else:
                        key_ok = True
                        
                    if key_ok:
                        if self._encrypt_message(encryption_name):
                            encrypted_classnames.append(encryption_classname)
                            encrypted_with.append(encryption_name)
                    else:
                        error_message += i18n('You need to verify the {encryption} key for {email} before you can use it.'.format(
                            encryption=encryption_name, email=to_user))
                        self.log_message(error_message)
                except MessageException as message_exception:
                    fatal_error = True
                    error_message += message_exception.value
                    self.log_exception(error_message)
                    break

        # if the user has encryption software defined, then the message 
        # must be encrypted or bounced to the sender
        if len(encrypted_classnames) > 0:
            encrypted = True
        else:
            fatal_error = True
            if error_message is None or len(error_message) <= 0:
                error_message = '{}\n{}'.format(
                    i18n("Message not sent to {email} because there was a problem encrypting. It's possible the recipient's key is missing.".format(
                        email=to_user)),
                    self.POSSIBLE_ENCRYPT_SOLUTION)

            # restore the payload
            self.crypto_message.get_email_message().get_message().set_payload(original_payload)

        if fatal_error:
            self.log_message('raising message exception in _encrypt_message_with_all')
            self.log_message(error_message)
            raise MessageException(value=error_message)

        return encrypted_with

    def _encrypt_message(self, encryption_name):
        ''' 
            Encrypt the message if both To and From have keys.

            Otherwise, if we just have a key for the From, then add it to the header.
        '''

        def prep_crypto_details(init_result):
            result_ok = init_result

            if result_ok:
                from_user_id = utils.get_user_id_matching_email(
                  self.crypto_message.smtp_sender(), private_user_ids)
            else:
                from_user_id = None

            if from_user_id is None:
                # add a key if there isn't one for the sender and we're creating keys
                if options.create_private_keys():
                    utils.add_private_key(
                       self.crypto_message.smtp_sender(), encryption_software=encryption_name)
                else:
                    self.log_message("not creating a new {} key for {} because auto-create disabled".format(
                        encryption_name, from_user_id))
            else:
                self.log_message('found matching user id: {}'.format(from_user_id))
            self.log_message('prep_crypto_details result: {}'.format(result_ok))

            return result_ok

        def get_error_message(users_dict, encryption_name):
            to_user = users_dict[encrypt_utils.TO_KEYWORD]
            from_user = users_dict[encrypt_utils.FROM_KEYWORD]
            passcode = users_dict[encrypt_utils.PASSCODE_KEYWORD]

            if options.clear_sign_email():
                if from_user is None or passcode is None:
                    error_message = '{}  '.format(
                        i18n("Message not sent to {email} because currently there isn't a private {encryption} key for you and your sysadmin requires all encrypted messages also be clear signed.".format(
                            email=to_user, encryption=encryption_name)))
                    if options.create_private_keys():
                        error_message += i18n("GoodCrypto is creating a private key now. You will receive email when your keys are ready so you can resend your message.")
                    else:
                        error_message += i18n("Ask your sysadmin to create a private key for you and then try resending the message.")
                else:
                    error_message = '{}\n{}'.format(
                        i18n(self.UNABLE_TO_ENCRYPT.format(
                            from_email=from_user, to_email=to_user, encryption=encryption_name)),
                        self.POSSIBLE_ENCRYPT_SOLUTION)
            else:
                error_message = '{}\n{}'.format(
                    i18n(self.UNABLE_TO_ENCRYPT.format(
                        from_email=from_user, to_email=to_user, encryption=encryption_name)),
                    self.POSSIBLE_ENCRYPT_SOLUTION)
                
            return error_message


        result_ok = False
        try:
            self.log_message("encrypting message with {}".format(encryption_name))
            crypto = CryptoFactory.get_crypto(encryption_name, get_classname(encryption_name))
            if crypto is None:
                self.log_message("{} is not ready to use".format(encryption_name))
            elif (self.crypto_message is None or 
                  self.crypto_message.smtp_sender() is None or 
                  self.crypto_message.smtp_recipient() is None):
                self.log_message("missing key data to encrypt message")
            else:
                # get all the user ids that have encryption keys
                user_ids = crypto.get_user_ids()
                self.log_message('user ids: {}'.format(user_ids))
                private_user_ids = crypto.get_private_user_ids()
                self.log_message('private user ids: {}'.format(private_user_ids))

                result_ok = private_user_ids is not None and len(private_user_ids) > 0
                if result_ok or options.create_private_keys():

                    result_ok = prep_crypto_details(result_ok)

                    users_dict, result_ok = self._get_crypto_details(encryption_name, user_ids)

                    # regardless if we can encrypt this message, 
                    # add From's public key if we have it and we're exchanging keys
                    if options.auto_exchange_keys() and users_dict[encrypt_utils.FROM_KEYWORD] is not None:
                        self.crypto_message.add_public_key_to_header(users_dict[encrypt_utils.FROM_KEYWORD])
                else:
                    self.log_message("user_ids is not None and len(user_ids) > 0: {}".format(
                        user_ids is not None and len(user_ids) > 0))

                if result_ok:
                    self.log_message("from user ID: {}".format(users_dict[encrypt_utils.FROM_KEYWORD]))
                    self.log_message("to user ID: {}".format(users_dict[encrypt_utils.TO_KEYWORD]))
                    self.log_message("subject: {}".format(
                      self.crypto_message.get_email_message().get_header(mime_constants.SUBJECT_KEYWORD)))
                    
                    result_ok = self._encrypt_message_with_keys(crypto, users_dict)
                    self.log_message('encrypted message: {}'.format(result_ok))
                    if not result_ok:
                        error_message = get_error_message(users_dict, encryption_name)
                        raise MessageException(value=error_message)

                else:
                    # the message hasn't been encrypted, but we have 
                    # successfully processed it
                    self.crypto_message.set_filtered(True)
                    
        except MessageException as message_exception:
            raise MessageException(value=message_exception.value)

        except Exception:
            result_ok = False
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            
        return result_ok


    def _get_crypto_details(self, encryption_name, user_ids):
        '''
            Get the details needed to encrypt a message. 
        '''
        
        from_user_id = to_user_id = passcode = None
        ready_to_encrypt = user_ids is not None and len(user_ids) > 0

        if ready_to_encrypt:
            to_user_id, ready_to_encrypt = self._get_to_crypto_details(encryption_name, user_ids)
            
        if ready_to_encrypt or options.auto_exchange_keys():
            from_user_id, passcode, error_message = self._get_from_crypto_details(encryption_name, user_ids)

        if self.crypto_message is None or self.crypto_message.get_email_message() is None:
            charset = 'UTF-8'
        else:
            charset, __ = get_charset(self.crypto_message.get_email_message().get_message())

        users_dict = {encrypt_utils.TO_KEYWORD: to_user_id, 
                      encrypt_utils.FROM_KEYWORD: from_user_id, 
                      encrypt_utils.PASSCODE_KEYWORD: passcode,
                      encrypt_utils.CHARSET_KEYWORD: charset}

        self.log_message('got crypto details and ready to encrypt: {}'.format(ready_to_encrypt))
        
        return users_dict, ready_to_encrypt


    def _get_from_crypto_details(self, encryption_name, user_ids):
        '''
            Get the from user's details needed to encrypt a message. 
        '''

        error_message = passcode = None
        from_user = self.crypto_message.smtp_sender()

        self.log_message('user ids: {}'.format(user_ids))
        from_user_id = utils.get_user_id_matching_email(from_user, user_ids)
        self.log_message('from_user_id: {}'.format(from_user_id))
        if from_user_id is None:
            passcode = None
            error_message = "No {} key for {}".format(encryption_name, from_user)
            self.log_exception(error_message)
        else:
            passcode = user_keys.get_passcode(from_user, encryption_name)
            if passcode is None:
                error_message = "No private {} key for {}".format(encryption_name, from_user)
                self.log_exception(error_message)
                    
        return from_user_id, passcode, error_message


    def _get_to_crypto_details(self, encryption_name, user_ids):
        '''
            Get the recipient details needed to encrypt a message. 
        '''
        
        from_user = self.crypto_message.smtp_sender()
        to_user = self.crypto_message.smtp_recipient()

        to_user_id = utils.get_user_id_matching_email(to_user, user_ids)
        if to_user_id is None:
            ready_to_encrypt = False
            self.log_exception("No user id for " + encryption_name + " matching To: " + to_user)
        else:
            try:
                contacts.is_key_ok(to_user_id, encryption_name)
                ready_to_encrypt = True
            except CryptoException as exception:
                to_user_id = None
                ready_to_encrypt = False
                self.log_exception(exception.value)
                self.log_message('raising message exception in _get_to_crypto_details')
                raise MessageException(value=exception.value)

        return to_user_id, ready_to_encrypt


    def _encrypt_message_with_keys(self, crypto, users_dict):
        ''' 
            Encrypt a message with the To and From keys.
        '''

        if is_content_type_text(self.crypto_message.get_email_message().get_message()):
            encrypt_utils.encrypt_text_message(self.crypto_message, crypto, users_dict)
        else:
            encrypt_utils.encrypt_mime_message(self.crypto_message, crypto, users_dict)
            
        return self.crypto_message.is_crypted()


    def log_exception(self, msg):
        '''
            Log the message to the local and Exception logs.
        '''

        self.log_message(msg)
        record_exception(message=msg)

    def log_message(self, message):
        '''
            Log the message to the local log.
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

