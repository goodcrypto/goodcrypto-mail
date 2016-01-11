'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-02-16

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from email.encoders import encode_7or8bit
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from random import random
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail import contacts, contacts_passcodes, options
from goodcrypto.mail.i18n_constants import SERIOUS_ERROR_PREFIX, WARNING_PREFIX
from goodcrypto.mail.crypto_software import get_classname, get_key_classname
from goodcrypto.mail.message import mime_constants, utils
from goodcrypto.mail.message.constants import PGP_ENCRYPTED_CONTENT_TYPE
from goodcrypto.mail.message.crypto_filter import CryptoFilter
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.history import add_encrypted_record
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.mime_constants import DATE_KEYWORD, MESSAGE_ID_KEYWORD
from goodcrypto.mail.message.utils import get_charset, get_message_id
from goodcrypto.mail.utils.exception_log import ExceptionLog
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.open_pgp_analyzer import OpenPGPAnalyzer
from goodcrypto.oce.utils import parse_address
from goodcrypto.utils import i18n



class EncryptFilter(CryptoFilter):
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
    
    FROM_KEYWORD = 'from'
    TO_KEYWORD = 'to'
    PASSCODE_KEYWORD = 'passcode'
    CHARSET_KEYWORD = 'charset'
    
    UNABLE_TO_ENCRYPT = "Error while trying to encrypt message from {from_email} to {to_email} using {encryption}"
    POSSIBLE_ENCRYPT_SOLUTION = i18n("Report this error to your sysadmin.")

    def __init__(self):
        '''
            >>> encrypt_filter = EncryptFilter()
            >>> encrypt_filter != None
            True
        '''

        super(EncryptFilter, self).__init__()
        
        self.log = LogFile()


    def crypt_from_to(self, crypto_message, from_user, to_user):
        ''' 
            Encrypt a message.

            If the message is encrypted, then the "To:" only includes the "to_user" 
            which helps reduce traffic analysis.
        '''

        def log_error(crypto_message, error_message):
            self.log_message(format_exc())
            self.log_crypto_exception(MessageException(format_exc()))
            try:
                crypto_message.add_tag_once('{} {}'.format(
                    SERIOUS_ERROR_PREFIX, error_message))
            except Exception:
                self.log_message(format_exc())
            
        try:
            filtered = False
            encrypted = False
            
            self.log_message("trying to encrypt message from {} to {}".format(from_user, to_user))
            encryption_names = utils.get_encryption_software(to_user)
            if encryption_names is None or len(encryption_names) <= 0:
                self.log_message("no encryption software defined for {}".format(to_user))
                if options.auto_exchange_keys():
                    # add the public key so the receiver can use crypto in the future
                    crypto_message.add_public_key_to_header(from_user)
                crypto_message.set_filtered(True)
            else:
                try:
                    self._encrypt_message_with_all(encryption_names, crypto_message, from_user, to_user)
                except MessageException as message_exception:
                    raise MessageException(value=message_exception.value)
                except Exception as exception:
                    log_error(crypto_message, str(exception))
                except IOError as io_error:
                    log_error(crypto_message, io_error.value)

            filtered = crypto_message.is_filtered()
            encrypted = crypto_message.is_crypted()
            if encrypted:
                self._limit_recipients(crypto_message, to_user)
                if EncryptFilter.DEBUGGING:
                    self.log_message('Full encrypted message:\n{}'.format(
                       crypto_message.get_email_message().to_string()))
            else:
                crypto_message.add_tag_once('{}{}'.format(
                  WARNING_PREFIX, i18n('Anyone could have read this message. Use encryption, it works.')))

            tags_added = crypto_message.add_tag_to_message()
            self.log_message('Tags added to message: {}'.format(tags_added))

        except MessageException as message_exception:
            raise MessageException(value=message_exception.value)

        except Exception, IOError:
            self.log_message(format_exc())

        self.log_message('  final status: filtered: {} encrypted: {}'.format(filtered, encrypted))

        return filtered, encrypted


    def _encrypt_message_with_all(self, encryption_names, crypto_message, from_user, to_user):
        '''
            Encrypt the message with each encryption program.
        '''
        
        fatal_error = False
        error_message = ''
        encrypted_with = []
        encrypted_classnames = []
        self.log_message("using {} encryption software".format(encryption_names))
        for encryption_name in encryption_names:
            encryption_classname = get_key_classname(encryption_name)
            if encryption_classname not in encrypted_classnames:
                try:
                    if options.require_key_verified():
                        __, key_ok = contacts.get_fingerprint(to_user, encryption_name)
                        self.log_message("{} {} key verified: {}".format(to_user, encryption_name, key_ok))
                    else:
                        key_ok = True
                        
                    if key_ok:
                        if self._encrypt_message(encryption_name, crypto_message, from_user, to_user):
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
        if len(encrypted_classnames) < 1:
            fatal_error = True
            if error_message is None or len(error_message) <= 0:
                error_message = '{}\n{}'.format(
                    i18n("Message not sent to {email} because there was a problem encrypting. It's possible the recipient's key is missing.".format(
                        email=to_user)),
                    self.POSSIBLE_ENCRYPT_SOLUTION)

        else:
            message_id = get_message_id(crypto_message.get_email_message())
            message_date = crypto_message.get_email_message().get_header(DATE_KEYWORD)
            add_encrypted_record(
              from_user, to_user, encrypted_with, message_id, message_date=message_date)
            self.log_message('added encrypted history record')

        if fatal_error:
            self.log_message('raising message exception in _encrypt_message_with_all')
            self.log_message(error_message)
            raise MessageException(value=error_message)


    def _encrypt_message(self, encryption_name, crypto_message, from_user, to_user):
        ''' 
            Encrypt the message if both To and From have keys.

            Otherwise, if we have a key for the From, add it to the header.
        '''

        def prep_crypto_details(init_result):
            ids = user_ids
            result_ok = init_result

            if result_ok:
                from_user_id = utils.get_user_id_matching_email(from_user, private_user_ids)
            else:
                from_user_id = None

            if from_user_id is None:
                # add a key if there isn't one for the sender and we're creating keys
                if options.create_private_keys():
                    crypto_message.create_private_key(encryption_name, from_user)
                else:
                    self.log_message("not creating a new {} key for {} because auto-create disabled".format(
                        encryption_name, from_user_id))
            else:
                self.log_message('found matching user id: {}'.format(from_user_id))

            return ids, result_ok

        def get_error_message(users_dict, encryption_name):
            to_user = users_dict[self.TO_KEYWORD]
            from_user = users_dict[self.FROM_KEYWORD]
            passcode = users_dict[self.PASSCODE_KEYWORD]

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
            elif crypto_message is None or from_user is None or to_user is None:
                self.log_message("missing key data to encrypt message")
            else:
                # get all the user ids that have encryption keys
                user_ids = crypto.get_user_ids()
                self.log_message('user ids: {}'.format(user_ids))
                private_user_ids = crypto.get_private_user_ids()
                self.log_message('private user ids: {}'.format(private_user_ids))

                result_ok = private_user_ids is not None and len(private_user_ids) > 0
                if result_ok or options.create_private_keys():

                    user_ids, result_ok = prep_crypto_details(result_ok)

                    users_dict, result_ok = self._get_crypto_details(
                       crypto_message, encryption_name, from_user, to_user, user_ids)

                    # regardless if we can encrypt this message, 
                    # add From's public key if we have it and we're exchanging keys
                    if options.auto_exchange_keys() and users_dict[self.FROM_KEYWORD] is not None:
                        crypto_message.add_public_key_to_header(users_dict[self.FROM_KEYWORD])
                else:
                    self.log_message("user_ids is not None and len(user_ids) > 0: {}".format(
                        user_ids is not None and len(user_ids) > 0))

                if result_ok:
                    self.log_message("from user ID: {}".format(users_dict[self.FROM_KEYWORD]))
                    self.log_message("to user ID: {}".format(users_dict[self.TO_KEYWORD]))
                    self.log_message("subject: {}".format(
                      crypto_message.get_email_message().get_header(mime_constants.SUBJECT_KEYWORD)))
                    
                    result_ok = self._encrypt_message_with_keys(crypto_message, crypto, users_dict)
                    self.log_message('encrypted message: {}'.format(result_ok))
                    if not result_ok:
                        error_message = get_error_message(users_dict, encryption_name)
                        raise MessageException(value=error_message)

                else:
                    # the message hasn't been encrypted, but we have 
                    # successfully processed it
                    crypto_message.set_filtered(True)
                    
        except MessageException as message_exception:
            raise MessageException(value=message_exception.value)

        except Exception:
            result_ok = False
            self.log_message(format_exc())
            
        return result_ok


    def _get_crypto_details(self, crypto_message, encryption_name, from_user, to_user, user_ids):
        '''
            Get the details needed to encrypt a message. 
        '''
        
        from_user_id = to_user_id = passcode = None
        ready_to_encrypt = user_ids is not None and len(user_ids) > 0

        if ready_to_encrypt:
            to_user_id, ready_to_encrypt = self._get_to_crypto_details(
              crypto_message, encryption_name, from_user, to_user, user_ids)
            
        if ready_to_encrypt or options.auto_exchange_keys():
            from_user_id, passcode, error_message = self._get_from_crypto_details(
                crypto_message, encryption_name, from_user, user_ids)

        if crypto_message is None or crypto_message.get_email_message() is None:
            charset = 'UTF-8'
        else:
            charset, __ = get_charset(crypto_message.get_email_message().get_message())

        users_dict = {self.FROM_KEYWORD: from_user_id, 
                      self.TO_KEYWORD: to_user_id, 
                      self.PASSCODE_KEYWORD: passcode,
                      self.CHARSET_KEYWORD: charset}

        return users_dict, ready_to_encrypt


    def _get_from_crypto_details(self, crypto_message, encryption_name, from_user, user_ids):
        '''
            Get the from user's details needed to encrypt a message. 
        '''

        error_message = None

        self.log_message('user ids: {}'.format(user_ids))
        from_user_id = utils.get_user_id_matching_email(from_user, user_ids)
        if from_user_id is None:
            passcode = None
            error_message = "No {} key for {}".format(encryption_name, from_user)
            self.log_exception(error_message)
        else:
            passcode = contacts_passcodes.get_passcode(from_user, encryption_name)
            if passcode is None:
                error_message = "No private {} key for {}".format(encryption_name, from_user)
                self.log_exception(error_message)
                    
        return from_user_id, passcode, error_message


    def _get_to_crypto_details(self, crypto_message, encryption_name, from_user, to_user, user_ids):
        '''
            Get the recipient details needed to encrypt a message. 
        '''
        
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


    def _encrypt_message_with_keys(self, crypto_message, crypto, users_dict):
        ''' 
            Encrypt a message with the To and From keys.
        '''

        if utils.is_content_type_text(crypto_message.get_email_message().get_message()):
            self._encrypt_text_message(crypto_message, crypto, users_dict)
        else:
            self._encrypt_mime_message(crypto_message, crypto, users_dict)
            
        return crypto_message.is_crypted()


    def _encrypt_text_message(self, crypto_message, crypto, users_dict):
        ''' 
            Encrypt a plain text message.
        '''

        def encrypt_text_part(content, crypto_message, crypto, users_dict):
            if self.DEBUGGING: self.log_message("type of content: {}".format(type(content)))
    
            ciphertext = self._encrypt_byte_array(bytearray(content), crypto, users_dict)
    
            #  if we encrypted successfully, save the results 
            if ciphertext != None and len(ciphertext) > 0:
                crypto_message.get_email_message().get_message().set_payload(ciphertext)
                result_ok = True
            else:
                result_ok = False
                
            return result_ok

        self.log_message("encrypting a text message")
        
        email_message = crypto_message.get_email_message()
        # if multiple users in To or CC, add the info to the top of the message
        to_value = email_message.get_header(mime_constants.TO_KEYWORD)
        cc_value = email_message.get_header(mime_constants.CC_KEYWORD)
        if (to_value is not None and to_value.find(',') > 0) or cc_value is not None:
            address_content = '{}\n'.format(self._create_inner_address_lines(to_value, cc_value))
        else:
            address_content = ''
            
        if utils.is_multipart_message(email_message):
            addresses_added_to_text = addresses_added_to_html = False
            for part in email_message.walk():
                content_type = part.get_content_type()
                if addresses_added_to_text and addresses_added_to_html:
                    content = part.get_payload()
                elif content_type.endswith(mime_constants.HTML_SUB_TYPE):
                    if addresses_added_to_html or len(address_content) <= 0:
                        content = part.get_payload()
                    else:
                        addresses_added_to_html = True
                        content = '{}<p>&nbsp;</p>{}'.format(address_content, content)
                else:
                    if addresses_added_to_text or len(address_content) <= 0:
                        content = part.get_payload()
                    else:
                        addresses_added_to_text = True
                        content = '{}{}'.format(address_content, content)

                result_ok = encrypt_text_part(content, crypto_message, crypto, users_dict)
                if not result_ok:
                    break
        else:
            final_content = '{}{}'.format(address_content, email_message.get_content())
            if self.DEBUGGING: self.log_message("  content:\n{!s}".format(final_content))
            
            result_ok = encrypt_text_part(final_content, crypto_message, crypto, users_dict)
    
        #  if we encrypted successfully, save the results 
        if result_ok:
            crypto_message.set_filtered(True)
            crypto_message.set_crypted(True)

    def _encrypt_mime_message(self, crypto_message, crypto, users_dict):
        ''' 
            Encrypt a MIME message by encrypting the entire original message and creating a new
            plain text message with the payload the encrypted original message. This reduces the
            metadata someone can collect, but it does require the receiving end decrypt the
            message and create a new readable message from the encrypted original message.
        '''

        def copy_item_from_original(msg, keyword):
            value = crypto_message.get_email_message().get_header(keyword)
            if value is not None:
                msg.__setitem__(keyword, value)
            
        self.log_message("encrypting a mime message")
        message = crypto_message.get_email_message().get_message()
        self.log_message("content type: {}".format(message.get_content_type()))

        #  Encrypt the whole message and add it to the body text
        #  This removes important meta data. The recieving end must
        #  decrypt the message, and then create a new message with the original structure.
        self.log_message("about to encrypt mime message")
        ciphertext = self._encrypt_byte_array(
            bytearray(crypto_message.get_email_message().to_string()), crypto, users_dict)
        
        if ciphertext is not None and len(ciphertext) > 0:
            # set up the body parts
            parts = []
            parts.append(
               MIMEApplication(
                 mime_constants.PGP_MIME_VERSION_FIELD, mime_constants.PGP_SUB_TYPE, encode_7or8bit))
            parts.append(
               MIMEApplication(ciphertext, mime_constants.OCTET_STREAM_SUB_TYPE, encode_7or8bit))
    
            boundary = 'Part{}{}--'.format(random(), random())
            charset, __ = get_charset(crypto_message.get_email_message().get_message())
            params = {mime_constants.PROTOCOL_KEYWORD:mime_constants.PGP_TYPE,
                      mime_constants.CHARSET_KEYWORD:charset,}
            msg = MIMEMultipart(mime_constants.ENCRYPTED_SUB_TYPE, boundary, parts, **params)
            self.log_message("part's content type: {}".format(msg.get_content_type()))
            
            # configure the header
            msg.__setitem__(mime_constants.FROM_KEYWORD, users_dict[self.FROM_KEYWORD])
            msg.__setitem__(mime_constants.TO_KEYWORD, users_dict[self.TO_KEYWORD])
            msg.__setitem__(PGP_ENCRYPTED_CONTENT_TYPE, mime_constants.MULTIPART_MIXED_TYPE)
            copy_item_from_original(msg, mime_constants.MESSAGE_ID_KEYWORD)
            copy_item_from_original(msg, mime_constants.SUBJECT_KEYWORD)
            copy_item_from_original(msg, mime_constants.DATE_KEYWORD)
            
            crypto_message.set_email_message(EmailMessage(msg))
            crypto_message.add_public_key_to_header(users_dict[self.FROM_KEYWORD])
            crypto_message.set_filtered(True)
            crypto_message.set_crypted(True)

    def _encrypt_byte_array(self, data, crypto, users_dict):
        ''' 
            Encrypt a byte array.
        '''
        
        from_user = users_dict[self.FROM_KEYWORD]
        to_user = users_dict[self.TO_KEYWORD]
        passcode = users_dict[self.PASSCODE_KEYWORD]
        charset = users_dict[self.CHARSET_KEYWORD]
        clear_sign = options.clear_sign_email()
        
        if from_user is None or passcode is None:
            if clear_sign:
                encrypted_data = None
                self.log_message('cannot send message because no from key and clear signing required')
            else:
                self.log_message('encrypting, but not signing message')
                encrypted_data = crypto.encrypt_and_armor(data, to_user, charset=charset)
        else:
            self.log_message('encrypting and signing')
            self.log_message('clear signing message: {}'.format(clear_sign))
            encrypted_data = crypto.sign_encrypt_and_armor(data,
                from_user, to_user, passcode, clear_sign=clear_sign, charset=charset)

        if encrypted_data is None or len(encrypted_data) <= 0:
            ciphertext = None
            self.log_crypto_exception('no encrypted data')

        else:
            #  ASCII armored plaintext looks just like armored ciphertext,
            #  so check that we actually successfully encrypted
            if data == encrypted_data:
                ciphertext = None
                self.log_crypto_exception('data was not encrypted')
            
            elif not OpenPGPAnalyzer().is_encrypted(encrypted_data, passphrase=passcode, crypto=crypto):
                self.log_crypto_exception('unable to verify data was encrypted')
                # !!!! we're going to use it any ways for now as not too confident about the analyzer
                ciphertext = str(encrypted_data)
                if self.DEBUGGING:
                    self.log_message("ciphertext:\n{}".format(ciphertext))
            
            else:
                ciphertext = str(encrypted_data)
                if self.DEBUGGING:
                    self.log_message("ciphertext:\n{}".format(ciphertext))

        return ciphertext

    def _create_inner_address_lines(self, to_value, cc_value):
        '''
            Create "To" and "Cc" addresses lines for the top of the content.
        '''

        content = '{}: {}\n'.format(mime_constants.TO_KEYWORD, to_value)
        if cc_value is not None:
            content += '{}: {}\n'.format(mime_constants.CC_KEYWORD, cc_value)

        return content
            
    def _limit_recipients(self, crypto_message, to_user):
        '''
            A traffic analysis countermeasure is to only show 1 recipient in the header.
            If there are multiple Tos and CCs, they've been added in the encrypted 
            text section of the message.
        '''

        if to_user is None or crypto_message is None:
            self.log_message('missing key data to limit the recipients')
        else:
            email_message = crypto_message.get_email_message()
            to_value = email_message.get_header(mime_constants.TO_KEYWORD)
            cc_value = email_message.get_header(mime_constants.CC_KEYWORD)
            if (to_value is not None and to_value.find(',') > 0) or cc_value is not None:
                name, address = utils.parse_address(to_user)
                crypto_message.get_email_message().change_header(mime_constants.TO_KEYWORD, address)
                self.log_message('original to: {}'.format(to_value))
                self.log_message('final to: {} <{}>'.format(name, address))
                
                if cc_value is not None:
                    crypto_message.get_email_message().get_message().__delitem__(mime_constants.CC_KEYWORD)
                    self.log_message('original cc: {}'.format(cc_value))

    def log_exception(self, msg):
        '''
            Log the message to the local and Exception logs.
        '''

        self.log_message(msg)
        ExceptionLog.log_message(msg)

    def log_message(self, message):
        '''
            Log the message to the local log.
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

