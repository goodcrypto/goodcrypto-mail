'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-04-06

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import copy, os
from traceback import format_exc

from goodcrypto.mail import contacts, options, user_keys, utils
from goodcrypto.mail.constants import NEVER_ENCRYPT_OUTBOUND
from goodcrypto.mail.i18n_constants import SERIOUS_ERROR_PREFIX, WARNING_PREFIX
from goodcrypto.mail.crypto_rq import search_keyservers_via_rq
from goodcrypto.mail.crypto_software import get_classname, get_key_classname
from goodcrypto.mail.message import constants, encrypt_utils, history
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.history import gen_verification_code
from goodcrypto.mail.message.inspect_utils import get_charset, get_message_id, is_content_type_text
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.metadata import (is_metadata_address, is_ready_to_protect_metadata,
                                              packetize, get_metadata_address)
from goodcrypto.mail.message.tags import add_tag_to_message, USE_ENCRYPTION_WARNING
from goodcrypto.mail.message.utils import add_private_key, log_message_headers
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

    MUST_ENCRYPT_ALL_MAIL = i18n("Message not sent because all messages must be encrypted. Contact your mail administrator if you'd like to be able to send plain text messages to {to_email}.")
    MUST_ENCRYPT_MAIL_TO_USER = i18n("Message not sent because all messages to {to_email} must be encrypted. Contact your mail administrator if you'd like to be able to send plain text messages to this contact.")
    UNABLE_TO_ENCRYPT = i18n("Error while trying to encrypt message from {from_email} to {to_email} using {encryption}")
    MESSAGE_TOO_LARGE = i18n('Message too large to send. The maximum size, including attachments, is {kb_size} KB.')
    POSSIBLE_ENCRYPT_SOLUTION = i18n("Report this error to your mail administrator.")

    def __init__(self, crypto_message):
        '''
            >>> encrypt = Encrypt(None)
            >>> encrypt != None
            True
        '''

        self._log = LogFile()
        self.crypto_message = crypto_message
        self.verification_code = None
        self.ready_to_protect_metadata = False

    def process_message(self):
        '''
            Process a message and encrypt if possible,
            bounce if unable to encrypt and encryption required, or
            add a warning about the danger of sending unencrypted messages.
            Also, add clear sig and DKIM sig if user opted for either or both.
        '''

        def log_error(error_message):
            record_exception()
            self._log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            try:
                self.crypto_message.add_error_tag_once('{} {}'.format(
                    SERIOUS_ERROR_PREFIX, error_message))
            except Exception:
                record_exception()
                self._log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')


        filtered = encrypted = False
        inner_encrypted_with = []
        # a place for the original message in case metadata is protected
        original_crypto_message = None
        try:
            if self.crypto_message is None:
                self._log_message('no crypto message defined')
                self.crypto_message = CryptoMessage()
                from_user = to_user = None
            else:
                from_user = self.crypto_message.smtp_sender()
                to_user = self.crypto_message.smtp_recipient()

            self._log_message("trying to encrypt message from {} to {}".format(from_user, to_user))

            self.verification_code = gen_verification_code()
            self.ready_to_protect_metadata = is_ready_to_protect_metadata(from_user, to_user)

            contact = contacts.get(to_user)
            if contact is None:
                never_encrypt = False
                encryption_names = []

                if options.use_keyservers():
                    # if there's no contact, then start another job
                    # that can determine whether we can find a key
                    self._start_check_for_encryption(from_user, to_user)
            else:
                never_encrypt = contact.outbound_encrypt_policy == NEVER_ENCRYPT_OUTBOUND
                encryption_names = utils.get_encryption_software(to_user)

            if len(encryption_names) <= 0 or never_encrypt:

                self._log_message('{} uses {} known encryption'.format(to_user, len(encryption_names)))

                if not self.ready_to_protect_metadata:
                    if never_encrypt:
                        self._log_message('{} set not to use any encryption'.format(to_user))

                    # fail if encryption is required globally or for this individual
                    elif options.require_outbound_encryption():
                        self._log_message('message not sent because global encryption required')
                        raise MessageException(value=self.MUST_ENCRYPT_ALL_MAIL.format(to_email=to_user))

                    elif contacts.always_encrypt_outbound(to_user):
                        self._log_message('message not sent because encryption required for {}'.format(to_user))
                        raise MessageException(value=self.MUST_ENCRYPT_MAIL_TO_USER.format(to_email=to_user))

                # see if message must be clear signed
                if options.clear_sign_email():
                    self._clear_sign_crypto_message(from_user)

                # add the public key so the receiver can use crypto with us in the future
                if options.auto_exchange_keys():
                    self.crypto_message.add_public_key_to_header(from_user)
                    self._log_message('added {} public key to header'.format(from_user))

                # if we're not exchanging keys, but we are creating them,
                # then start the process in background
                elif options.create_private_keys():
                    add_private_key(from_user)
                    self._log_message('created private key for {} if needed'.format(from_user))

                self.crypto_message.set_filtered(True)

            else:
                try:
                    inner_encrypted_with = self._encrypt_message_with_all(encryption_names)
                    if self.DEBUGGING:
                        self._log_message('message after encryption:\n{}'.format(
                          self.crypto_message.get_email_message().to_string()))
                except MessageException as message_exception:
                    raise MessageException(value=message_exception.value)
                except Exception as exception:
                    log_error(str(exception))
                except IOError as io_error:
                    log_error(io_error.value)

            if self.ready_to_protect_metadata:
                original_crypto_message = copy.copy(self.crypto_message)
                self._protect_metadata(from_user, to_user, inner_encrypted_with)

            else:
                if self.crypto_message.is_crypted():
                    if self.DEBUGGING:
                        self._log_message('full encrypted message:\n{}'.format(
                           self.crypto_message.get_email_message().to_string()))

                elif contacts.never_encrypt_outbound(to_user):
                    self._log_message('{} not using encryption'.format(to_user))
                    self.crypto_message.add_error_tag_once(USE_ENCRYPTION_WARNING)

                elif options.require_outbound_encryption():
                    self._log_message('message not sent because global encryption required')
                    raise MessageException(value=self.MUST_ENCRYPT_ALL_MAIL.format(to_email=to_user))

                elif contacts.always_encrypt_outbound(to_user):
                    self._log_message('message not sent because encryption required for {}'.format(to_user))
                    raise MessageException(value=self.MUST_ENCRYPT_MAIL_TO_USER.format(to_email=to_user))

                else:
                    self.crypto_message.add_error_tag_once(USE_ENCRYPTION_WARNING)

            if self.crypto_message.is_processed():
                self._log_message('message processed and awaiting bundling')
            else:
                tags_added = add_tag_to_message(self.crypto_message)
                self._log_message('tags added to message: {}'.format(tags_added))

                # add the DKIM signature if user opted for it
                self.crypto_message = encrypt_utils.add_dkim_sig_optionally(self.crypto_message)

                self.crypto_message.set_filtered(True)

                # finally save a record so the user can verify what security measures were added
                if (self.crypto_message.is_crypted() or
                    self.crypto_message.is_private_signed() or
                    self.crypto_message.is_clear_signed()):

                    self._add_outbound_record(original_crypto_message, inner_encrypted_with)
                    self._log_message('added outbound history record')

        except MessageException as message_exception:
            raise MessageException(value=message_exception.value)

        except Exception, IOError:
            record_exception()
            self._log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        if self.crypto_message is not None:
            self._log_message('  final status: filtered: {} encrypted: {}'.format(
                self.crypto_message.is_filtered(), self.crypto_message.is_crypted()))

        return self.crypto_message

    def _protect_metadata(self, from_user, to_user, inner_encrypted_with):
        '''
            Protect the message's metadata and resist traffic analysis.
        '''

        if options.bundle_and_pad():
            tags_added = add_tag_to_message(self.crypto_message)
            self._log_message('tags added to message before bundling: {}'.format(tags_added))

            # add the DKIM signature if user opted for it
            self.crypto_message = encrypt_utils.add_dkim_sig_optionally(self.crypto_message)

            message_name = packetize(
               self.crypto_message, inner_encrypted_with, self.verification_code)
            if os.stat(message_name).st_size > options.bundled_message_max_size():
                self._log_message('Message too large to bundle so throwing MessageException')
                if os.path.exists(message_name):
                    os.remove(message_name)
                error_message = MESSAGE_TOO_LARGE.format(kb_size=options.bundle_message_kb())
                self._log_message(error_message)
                raise MessageException(value=error_message)
            else:
                self._log_message('message waiting for bundling: {}'.format(
                  self.crypto_message.is_processed()))

        else:
            self._log_message('protecting metadata')

            # add the original sender and recipient in the header
            self.crypto_message.get_email_message().add_header(constants.ORIGINAL_FROM, from_user)
            self.crypto_message.get_email_message().add_header(constants.ORIGINAL_TO, to_user)

            # add the DKIM signature to the inner message if user opted for it
            self.crypto_message = encrypt_utils.add_dkim_sig_optionally(self.crypto_message)

            self._log_message('DEBUG: logged headers before encrypting with metadata key in goodcrypto.message.utils.log')
            log_message_headers(self.crypto_message, tag='headers before encrypting with metadata key')

            # even if the inner message isn't encrypted, encrypt
            # the entire message to protect the metadata
            message_id = get_message_id(self.crypto_message.get_email_message())
            self.crypto_message = encrypt_utils.create_protected_message(
                self.crypto_message.smtp_sender(), self.crypto_message.smtp_recipient(),
                self.crypto_message.get_email_message().to_string(), message_id)
            self._log_message('added protective layer for metadata')

    def _encrypt_message_with_all(self, encryption_names):
        '''
            Encrypt the message with each encryption program.
        '''
        encrypted = fatal_error = False
        error_message = ''
        encrypted_with = []
        encrypted_classnames = []
        to_user = self.crypto_message.smtp_recipient()
        original_payload = self.crypto_message.get_email_message().get_message().get_payload()

        self._log_message("encrypting using {} encryption software".format(encryption_names))
        for encryption_name in encryption_names:
            encryption_classname = get_key_classname(encryption_name)
            if encryption_classname not in encrypted_classnames:
                try:
                    if options.require_key_verified():
                        __, key_ok, __ = contacts.get_fingerprint(to_user, encryption_name)
                        self._log_message("{} {} key verified: {}".format(to_user, encryption_name, key_ok))
                    else:
                        key_ok = True

                    if key_ok:
                        if self._encrypt_message(encryption_name):
                            encrypted_classnames.append(encryption_classname)
                            encrypted_with.append(encryption_name)
                    else:
                        error_message += i18n('You need to verify the {encryption} key for {email} before you can use it.'.format(
                            encryption=encryption_name, email=to_user))
                        self._log_message(error_message)
                except MessageException as message_exception:
                    fatal_error = True
                    error_message += message_exception.value
                    self._log_exception(error_message)
                    break

        # if the user has encryption software defined, then the message
        # must be encrypted or bounced to the sender
        if len(encrypted_classnames) > 0:
            encrypted = True
        else:
            MSG_NOT_SET = i18n('Message not sent to {email} because there was a problem encrypting.'.format(
                email=to_user))
            fatal_error = True
            if error_message is None or len(error_message) <= 0:
                error_message = '{} {}\n{}'.format(MSG_NOT_SET,
                    i18n("It's possible the recipient's key is missing."),
                    self.POSSIBLE_ENCRYPT_SOLUTION)
            else:
                error_message = '{} {}'.format(MSG_NOT_SET, error_message)

            # restore the payload
            self.crypto_message.get_email_message().get_message().set_payload(original_payload)

        if fatal_error:
            self._log_message('raising message exception in _encrypt_message_with_all')
            self._log_message(error_message)
            raise MessageException(value=error_message)

        return encrypted_with

    def _encrypt_message(self, encryption_name):
        '''
            Encrypt the message if both To and From have keys.

            Otherwise, if we just have a key for the From, then add it to the header.
        '''
        result_ok = False
        try:
            self._log_message("encrypting message with {}".format(encryption_name))
            crypto = CryptoFactory.get_crypto(encryption_name, get_classname(encryption_name))
            if crypto is None:
                self._log_message("{} is not ready to use".format(encryption_name))
            elif (self.crypto_message is None or
                  self.crypto_message.smtp_sender() is None or
                  self.crypto_message.smtp_recipient() is None):
                self._log_message("missing key data to encrypt message")
            else:
                # get all the user ids that have encryption keys
                user_ids = crypto.get_user_ids()
                if self.DEBUGGING: self._log_message('user ids: {}'.format(user_ids))
                private_user_ids = crypto.get_private_user_ids()
                if self.DEBUGGING: self._log_message('private user ids: {}'.format(private_user_ids))

                self._prep_from_user(private_user_ids, encryption_name)
                users_dict, result_ok = self._get_crypto_details(encryption_name, user_ids)
                if result_ok or options.create_private_keys():

                    # regardless if we can encrypt this message,
                    # add From's public key if we have it and we're exchanging keys
                    if options.auto_exchange_keys() and users_dict[encrypt_utils.FROM_KEYWORD] is not None:
                        self.crypto_message.add_public_key_to_header(users_dict[encrypt_utils.FROM_KEYWORD])
                else:
                    self._log_message("user_ids is not None and len(user_ids) > 0: {}".format(
                        user_ids is not None and len(user_ids) > 0))

                if result_ok:
                    self._log_message("from user ID: {}".format(users_dict[encrypt_utils.FROM_KEYWORD]))
                    self._log_message("to user ID: {}".format(users_dict[encrypt_utils.TO_KEYWORD]))
                    self._log_message("subject: {}".format(
                      self.crypto_message.get_email_message().get_header(mime_constants.SUBJECT_KEYWORD)))

                    result_ok = self._encrypt_message_with_keys(crypto, users_dict)
                    self._log_message('encrypted message: {}'.format(result_ok))
                    if not result_ok:
                        error_message = self._get_encrypt_error_message(users_dict, encryption_name)
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
            self._log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return result_ok

    def _encrypt_message_with_keys(self, crypto, users_dict):
        '''
            Encrypt a message with the To and From keys.
        '''

        if is_content_type_text(self.crypto_message.get_email_message().get_message()):
            encrypt_utils.encrypt_text_message(self.crypto_message, crypto, users_dict)
        else:
            encrypt_utils.encrypt_mime_message(self.crypto_message, crypto, users_dict)

        return self.crypto_message.is_crypted()


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
            if ready_to_encrypt and passcode is None and options.clear_sign_email():
                if error_message is not None:
                    error_message += i18n(' and clear signing is required.')
                    if options.create_private_keys():
                        error_message += '\n\n{}'.format(i18n(
                          "You should wait 5-10 minutes and try again. If that doesn't help, then contact your mail administrator."))
                    else:
                        error_message += '\n\n{}'.format(i18n(
                          'Ask your mail administrator to create a private key for you.'))

                self._log_exception(error_message)
                raise MessageException(error_message)

        if self.crypto_message is None or self.crypto_message.get_email_message() is None:
            charset = 'UTF-8'
        else:
            charset, __ = get_charset(self.crypto_message.get_email_message().get_message())

        users_dict = {encrypt_utils.TO_KEYWORD: to_user_id,
                      encrypt_utils.FROM_KEYWORD: from_user_id,
                      encrypt_utils.PASSCODE_KEYWORD: passcode,
                      encrypt_utils.CHARSET_KEYWORD: charset}

        self._log_message('got crypto details and ready to encrypt: {}'.format(ready_to_encrypt))

        return users_dict, ready_to_encrypt


    def _get_from_crypto_details(self, encryption_name, user_ids):
        '''
            Get the from user's details needed to encrypt a message.
        '''

        error_message = passcode = None
        from_user = self.crypto_message.smtp_sender()

        self._log_message('user ids: {}'.format(user_ids))
        from_user_id = utils.get_user_id_matching_email(from_user, user_ids)
        self._log_message('from_user_id: {}'.format(from_user_id))
        if from_user_id is None:
            passcode = None
            error_message = i18n("There isn't a {encryption_name} key for {email}").format(
                encryption_name=encryption_name, email=from_user)
            self._log_message(error_message)
        else:
            passcode = user_keys.get_passcode(from_user, encryption_name)
            if passcode is None:
                error_message = i18n("There isn't a private {encryption_name} key for {email}").format(
                    encryption_name=encryption_name, email=from_user)
                self._log_message(error_message)

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
            self._log_message("No {} key for {}".format(encryption_name, to_user))
        else:
            try:
                contacts.is_key_ok(to_user_id, encryption_name)
                ready_to_encrypt = True
            except CryptoException as exception:
                to_user_id = None
                ready_to_encrypt = False
                self._log_exception(exception.value)
                self._log_message('raising message exception in _get_to_crypto_details')
                raise MessageException(value=exception.value)

        return to_user_id, ready_to_encrypt


    def _prep_from_user(self, private_user_ids, encryption_name):

        result_ok = private_user_ids is not None and len(private_user_ids) > 0
        if result_ok or options.create_private_keys():

            if result_ok:
                from_user_id = utils.get_user_id_matching_email(
                  self.crypto_message.smtp_sender(), private_user_ids)
            else:
                from_user_id = None

            if from_user_id is None:
                # add a key if there isn't one for the sender and we're creating keys
                if options.create_private_keys():
                    add_private_key(
                       self.crypto_message.smtp_sender(), encryption_software=encryption_name)
                else:
                    self._log_message("not creating a new {} key for {} because auto-create disabled".format(
                        encryption_name, from_user_id))
            else:
                self._log_message('found matching user id: {}'.format(from_user_id))

        self._log_message('_prep_from_user: {}'.format(result_ok))

        return result_ok

    def _get_encrypt_error_message(self, users_dict, encryption_name):
        to_user = users_dict[encrypt_utils.TO_KEYWORD]
        from_user = users_dict[encrypt_utils.FROM_KEYWORD]
        passcode = users_dict[encrypt_utils.PASSCODE_KEYWORD]

        if options.clear_sign_email():
            if from_user is None or passcode is None:
                error_message = '{}  '.format(
                    i18n("Message not sent to {email} because currently there isn't a private {encryption} key for you and your mail administrator requires all encrypted messages also be clear signed.".format(
                        email=to_user, encryption=encryption_name)))
                if options.create_private_keys():
                    error_message += i18n("GoodCrypto is creating a private key now. You will receive email when your keys are ready so you can resend your message.")
                else:
                    error_message += '\n\n{}'.format(i18n(
                      'Ask your mail administrator to create a private key for you and then try resending the message.'))
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

    def _clear_sign_crypto_message(self, from_user):
        ''' Clear sign the message. '''

        """
        clear_sign_policy = options.clear_sign_policy()
        if clear_sign_policy == constants.CLEAR_SIGN_WITH_DOMAIN_KEY:
            encryption_names = utils.get_encryption_software(utils.get_domain_email())
        elif clear_sign_policy == constants.CLEAR_SIGN_WITH_SENDER_KEY:
            encryption_names = utils.get_encryption_software(from_user)
        else:
            encryption_names = utils.get_encryption_software(from_user)
            if encryption_names is None or len(encryption_names) <= 0:
                encryption_names = utils.get_encryption_software(from_user)
        """
        encryption_names = utils.get_encryption_software(from_user)
        if len(encryption_names) <= 0:
            signed = False
            self._log_message('unable to clear sign message because no encryption software defined for: {}'.format(from_user))
        else:
            signed = self._clear_sign_message_with_all(encryption_names)
            # the message isn't really encrypted, just signed
            if signed:
                self.crypto_message.set_crypted(False)
                self.crypto_message.set_clear_signed(True)
                self.crypto_message.add_clear_signer(
                   {constants.SIGNER: from_user, constants.SIGNER_VERIFIED: True})
                self._log_message('message clear signed, but not encrypted')
            if self.DEBUGGING:
                self._log_message('message after clear signature:\n{}'.format(
                  self.crypto_message.get_email_message().to_string()))

        return signed

    def _clear_sign_message_with_all(self, encryption_names):
        '''
            Clear sign the message with each encryption program.
        '''
        signed = fatal_error = False
        error_message = ''
        signed_with = []
        encrypted_classnames = []

        self._log_message("signing using {} encryption software".format(encryption_names))
        for encryption_name in encryption_names:
            encryption_classname = get_key_classname(encryption_name)
            if encryption_classname not in encrypted_classnames:
                try:
                    if self._clear_sign_message(encryption_name):
                        signed_with.append(encryption_name)
                        encrypted_classnames.append(encryption_classname)
                except MessageException as message_exception:
                    error_message += message_exception.value
                    self._log_exception(error_message)
                    break

        return signed_with

    def _clear_sign_message(self, encryption_name):
        '''
            Clear sign the message if From has a key.
        '''
        result_ok = False
        try:
            self._log_message("signing message with {}".format(encryption_name))
            crypto = CryptoFactory.get_crypto(encryption_name, get_classname(encryption_name))
            if crypto is None:
                self._log_message("{} is not ready to use".format(encryption_name))
            elif (self.crypto_message is None or
                  self.crypto_message.smtp_sender() is None):
                self._log_message("missing key data to sign message")
            else:
                # get all the private user ids that have encryption keys
                private_user_ids = crypto.get_private_user_ids()
                if self.DEBUGGING: self._log_message('private user ids: {}'.format(private_user_ids))

                result_ok = self._prep_from_user(private_user_ids, encryption_name)
                if result_ok:

                    from_user_id, passcode, error_message = self._get_from_crypto_details(
                        encryption_name, private_user_ids)

                    result_ok = from_user_id is not None and passcode is not None
                else:
                    self._log_message("private_user_ids is not None and len(private_user_ids) > 0: {}".format(
                        private_user_ids is not None and len(private_user_ids) > 0))

                if result_ok:
                    self._log_message("from user ID: {}".format(from_user_id))
                    self._log_message("subject: {}".format(
                      self.crypto_message.get_email_message().get_header(mime_constants.SUBJECT_KEYWORD)))

                    result_ok = self._clear_sign_message_with_keys(crypto, from_user_id, passcode)
                    self._log_message('signed message: {}'.format(result_ok))

                else:
                    # the message hasn't been signed, but we have
                    # successfully processed it
                    self.crypto_message.set_filtered(True)

        except Exception:
            result_ok = False
            record_exception()
            self._log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return result_ok

    def _clear_sign_message_with_keys(self, crypto, from_user_id, passcode):
        '''
            Sign a message with the From key.
        '''

        if is_content_type_text(self.crypto_message.get_email_message().get_message()):
            encrypt_utils.sign_text_message(self.crypto_message, crypto, from_user_id, passcode)
        else:
            encrypt_utils.sign_mime_message(self.crypto_message, crypto, from_user_id, passcode)

        return self.crypto_message.is_crypted()

    def _add_outbound_record(self, original_crypto_message, inner_encrypted_with):
        ''' Add an outbound record that a message was sent privately.'''

        self.crypto_message.set_crypted_with(inner_encrypted_with)
        # use the original message, not the protected one
        if original_crypto_message is None:
            original_crypto_message = copy.copy(self.crypto_message)
        else:
            original_crypto_message.set_crypted(True)
            original_crypto_message.set_crypted_with(inner_encrypted_with)
            original_crypto_message.set_metadata_crypted(True)
            original_crypto_message.set_metadata_crypted_with(self.crypto_message.get_metadata_crypted_with())
            if self.crypto_message.is_private_signed():
                original_crypto_message.set_private_signed(True)
            if self.crypto_message.is_private_sig_verified():
                original_crypto_message.set_private_signers(self.crypto_message.private_signers_list())
            if self.crypto_message.is_clear_signed():
                original_crypto_message.set_clear_signed(True)
            if self.crypto_message.is_clear_sig_verified():
                original_crypto_message.set_clear_signers(self.crypto_message.clear_signers_list())
            if self.crypto_message.is_dkim_signed():
                original_crypto_message.set_dkim_signed(True)
            if self.crypto_message.is_dkim_sig_verified():
                original_crypto_message.set_dkim_sig_verified(True)
        history.add_outbound_record(original_crypto_message, self.verification_code)

    def _start_check_for_encryption(self, from_user, to_user):
        ''' Start checking if the user uses encryption. '''

        # don't look for keys if the to_user's domain is also using goodcrypto
        if contacts.get(get_metadata_address(email=to_user)) is None:
            # start by adding a record so we don't search for a key again
            contact = contacts.add(to_user, None)
            contact.outbound_encrypt_policy = NEVER_ENCRYPT_OUTBOUND

            # search for the keys; if one's found, send email to the from
            # user so they can verify the fingerprint
            search_keyservers_via_rq(to_user, from_user)
        else:
            self._log_message('{} is also using goodcrypto so not searching for a key'.format(to_user))

    def _log_exception(self, msg):
        '''
            Log the message to the local and Exception logs.
        '''

        self._log_message(msg)
        record_exception(message=msg)

    def _log_message(self, message):
        '''
            Log the message to the local log.
        '''

        if self._log is None:
            self._log = LogFile()

        self._log.write_and_flush(message)

