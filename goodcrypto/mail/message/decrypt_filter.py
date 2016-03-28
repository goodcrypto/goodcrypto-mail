'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-04-15

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, urllib
from datetime import datetime
from email.encoders import encode_base64, encode_quopri
from email.message import Message
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail import contacts, contacts_passcodes, crypto_software, options
from goodcrypto.mail.i18n_constants import SERIOUS_ERROR_PREFIX, WARNING_PREFIX
from goodcrypto.mail.message import decrypt_utils, utils
from goodcrypto.mail.message.constants import PGP_ENCRYPTED_CONTENT_TYPE
from goodcrypto.mail.message.crypto_filter import CryptoFilter
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.header_keys import HeaderKeys
from goodcrypto.mail.message.history import add_decrypted_record, gen_validation_code
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.utils import add_private_key, get_message_id
from goodcrypto.mail.utils import email_in_domain, parse_address
from goodcrypto.mail.utils.exception_log import ExceptionLog
from goodcrypto.mail.utils.notices import notify_user
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.open_pgp_analyzer import OpenPGPAnalyzer
from goodcrypto.utils import i18n
from syr import mime_constants
from syr.html import firewall_html
from syr.timestamp import Timestamp


class DecryptFilter(CryptoFilter):
    '''
        Decrypt message filter.

        This filter tries all known encryption software for the recipient.
        Because encryption may be nested, this class keeps trying until the
        message is decrypted, or no valid encryption program can decrypt it further.

        !!!! If part of a message is plaintext and part encrypted, the decrypted
             text replaces the entire text, and the plaintext part is lost.

        !!!! A multiply-encrypted message may be tagged decrypted if any layer
             is successfully decrypted, even if an inner layer is still encrypted.
             
        See the unit tests to see how to use the DecryptFilter class.
    '''

    DEBUGGING = False
    USE_ANALYZER = False

    #  the encrypted content is the second part; indexing starts at 0
    ENCRYPTED_BODY_PART_INDEX = 1

    def __init__(self):
        '''
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter != None
            True
        '''

        super(DecryptFilter, self).__init__()
        
        self.log = LogFile()
        
        self.recipient = self.crypto_message = None


    def crypt_from(self, crypto_msg, from_user, to_user):
        ''' 
            If the message is encrypted, try to decrypt it. If it's not encrypted, tag it.
            
            See unittests for usage as the test set up is too complex for a doctest.
        '''

        filtered = False
        decrypted = False
        self.crypto_message = crypto_msg
        self.recipient = to_user
 
        if self.crypto_message is None or from_user is None or to_user is None:
            self.log_message("missing key info; crypto_message: {}; from_user: {}; to_user: {}".format(
                self.crypto_message, from_user, to_user))
        else:
            self.log_message("decrypting message from {} to {}".format(from_user, to_user))
            if DecryptFilter.DEBUGGING:
                self.log_message('original message:\n{}'.format(self.crypto_message.get_email_message().to_string()))

            if options.auto_exchange_keys():
                header_keys = HeaderKeys()
                header_keys.manage_keys_in_header(self.recipient, from_user, self.crypto_message)
            
            if self.crypto_message.is_dropped():
                filtered = True
                decrypted = False
                self.log_message("message dropped because of bad key")
                if DecryptFilter.DEBUGGING:
                    self.log_message("message:\n{}".format(self.crypto_message.get_email_message().to_string()))
            else:
                if self.crypto_message.get_email_message().is_probably_pgp():
                    if self.crypto_message.is_dropped():
                        self.log_message("message dropped:\n{}".format(
                            self.crypto_message.get_email_message().to_string()))
                    else:
                        filtered, decrypted = self._decrypt_from(from_user, to_user)
                        if self.DEBUGGING:
                            self.log_message('final decrypted message:\n{}'.format(
                                self.crypto_message.get_email_message().to_string()))
                else:
                    decrypt_utils.check_signature(from_user, self.crypto_message)

                    tag = '{}{}'.format(
                      WARNING_PREFIX, i18n('Anyone could have read this message.'))
                    if self.crypto_message.get_email_message().to_string().find(tag) < 0:
                        self.crypto_message.add_prefix_to_tag(tag)
                        filtered = decrypt_utils.add_tag_to_message(self.crypto_message)
                    else:
                        filtered = True
                    decrypted = False
                    self.log_message("message doesn't appear to be encrypted")

                    add_private_key(to_user)
                        
            self.log_message('  final status: filtered: {} decrypted: {}'.format(filtered, decrypted))

        return filtered, decrypted


    def _decrypt_from(self, from_user, to_user):
        ''' 
            Decrypt a message (internal use only).
        '''

        filtered = False
        decrypted = False

        if self.crypto_message is None or from_user is None or to_user is None:
            self.log_message("missing key info; crypto_message: {}; from_user: {}; to_user: {}".format(
                self.crypto_message, from_user, to_user))
        else:
            try:
                encryption_software = utils.get_encryption_software(to_user)
                if encryption_software and len(encryption_software) > 0:
                    self.log_message("encryption software: {}".format(encryption_software))
                    decrypted = self._decrypt_message(encryption_software, from_user, to_user)
                elif email_in_domain(to_user) and options.create_private_keys():
                    self.crypto_message.add_tag_once(
                      i18n('{email} does not have a matching key to decrypt the message'.format(email=to_user)))
                    add_private_key(to_user, encryption_software=encryption_software)
                    self.log_message("started to create a new {} key for {}".format(encryption_software, to_user))
                else:
                    self.log_message("no encryption software for {}".format(to_user))
                    self.crypto_message.add_tag_once(
                        i18n('{email} does not use any known encryption'.format(email=to_user)))
                    subject = i18n('{} Unable to decrypt message'.format(SERIOUS_ERROR_PREFIX))
                    notify_user(to_user, subject, self.crypto_message.get_email_message().to_string())

                if options.filter_html():
                    self._filter_html()
                else:
                    self.log_message("html filter disabled")
            except CryptoException as crypto_exception:
                raise CryptoException(crypto_exception.value)
            except Exception, IOError:
                self.log_crypto_exception(MessageException(format_exc()))
                self.log_message(format_exc())
                try:
                    self.crypto_message.add_tag(SERIOUS_ERROR_PREFIX)
                except Exception:
                    self.log_message(format_exc())
                
            filtered = decrypt_utils.add_tag_to_message(self.crypto_message)
            self.log_message("finished adding tags to message")

        return filtered, decrypted


    def _decrypt_message(self, encryption_names, from_user, to_user):
        ''' 
            Decrypt a message and add a tag if unsuccessful (internal use only).
        '''

        if encryption_names is None or self.crypto_message is None or to_user is None:
            decrypted = False
            self.log_message('unable to decrypt message when missing data')
        else:
            try:
                decrypted = self._decrypt_with_all_encryption(
                  encryption_names, from_user, to_user)
                    
                #  if the message is still encrypted, log it and tell the user
                if not decrypted and self.crypto_message.get_email_message().is_probably_pgp():
                    if len(encryption_names) > 1:
                        software = encryption_names.__str__()
                    else:
                        software = str(encryption_names[0])
        
                    log_msg = "Failed to decrypt with {}".format(software)
                    self.log_message(log_msg)
                    self.log_message(self.crypto_message.get_email_message().to_string())
                    ExceptionLog.log_message(log_msg)
                    
                    tag = i18n('Unable to decrypt message with {encryption}'.format(encryption=software))
                    self.crypto_message.add_tag_once(tag)
            except CryptoException as crypto_exception:
                raise CryptoException(crypto_exception.value)
            except Exception:
                decrypted = False
                self.log_message(format_exc())
            
        return decrypted

    def _decrypt_with_all_encryption(self, encryption_names, from_user, to_user):
        ''' 
            Decrypt a message using all known encryption (internal use only).
        '''

        decrypted = False
        decrypted_with = []

        try:
            #  the sender probably used the order of services in the
            #  AcceptedEncryptionSoftware header we sent out, so we want to
            #  use them in reverse order
            #  move to the end of the list, and back up
            i = len(encryption_names)
            self.log_message("encrypted {} time(s)".format(i))
            while i > 0:
                i -= 1
                encryption_name = encryption_names[i]
                if self.crypto_message.get_email_message().is_probably_pgp():
                    try:
                        if self._decrypt_message_with_crypto(encryption_name, from_user, to_user):
                            #  if any encryption decrypts, the message was decrypted
                            decrypted = True
                            decrypted_with.append(encryption_name)
                            self.crypto_message.set_crypted(decrypted)
                            self.log_message("decrypted using {}".format(encryption_name))
                    except CryptoException as crypto_exception:
                        raise CryptoException(crypto_exception.value)
                    except Exception:
                        msg = 'could not decrypt with {}.'.format(encryption_name) 
                        self.log_message(msg)
                        self.log_message(format_exc())
                else:
                    self.log_message("message already decrypted, so did not try {}".format(encryption_name))
        except CryptoException as crypto_exception:
            raise CryptoException(crypto_exception.value)
        except Exception:
            self.log_message(format_exc())

        if decrypted:
            validation_code = gen_validation_code()
            message_id = get_message_id(self.crypto_message.get_email_message())
            message_date = self.crypto_message.get_email_message().get_header(mime_constants.DATE_KEYWORD)
            add_decrypted_record(
              from_user, to_user, decrypted_with, message_id, validation_code, message_date=message_date)
            self.log_message('added decrypted record')

            self.add_validation_code(validation_code)

        return decrypted


    def _decrypt_message_with_crypto(self, encryption_name, from_user, to_user):
        ''' 
            Decrypt a message using encryption (internal use only).
        '''

        decrypted = False
        self.log_message("encryption program: {}".format(encryption_name))
        
        passcode = contacts_passcodes.get_passcode(to_user, encryption_name)
        if passcode == None or len(passcode) <= 0:
            tag = '{email} does not have a private {encryption} key.'.format(
               email=to_user, encryption=encryption_name)
            self.log_message(tag)
            self.crypto_message.add_tag_once(tag)
        else:
            # make sure that the key for the recipient is ok; if it's not, a CryptoException is thrown
            __, verified, __ = contacts.is_key_ok(to_user, encryption_name)
            self.log_message('{} {} key pinned'.format(to_user, encryption_name))
            self.log_message('{} {} key verified: {}'.format(to_user, encryption_name, verified))

            crypto = CryptoFactory.get_crypto(encryption_name, crypto_software.get_classname(encryption_name))

            # try to verify signature in case it was clear signed after it was encrypted
            decrypt_utils.check_signature(
               from_user, self.crypto_message, encryption_name=crypto.get_name(), crypto=crypto)

            self.log_message('trying to decrypt using {} private {} key.'.format(to_user, encryption_name))
            if utils.is_open_pgp_mime(self.crypto_message.get_email_message().get_message()):
                decrypted = self._decrypt_open_pgp_mime(from_user, crypto, passcode)
            else:
                decrypted = self._decrypt_inline_pgp(from_user, crypto, passcode)
            self.log_message('decrypted using {} private {} key: {}'.format(to_user, encryption_name, decrypted))
                
            # try to verify signature in case it was clear signed before it was encrypted
            if decrypted:
                decrypt_utils.check_signature(
                   from_user, self.crypto_message, encryption_name=crypto.get_name(), crypto=crypto)
                
                if self.DEBUGGING:
                    self.log_message('decrypted message:\n{}'.format(
                        self.crypto_message.get_email_message().get_message()))

        return decrypted


    def _decrypt_open_pgp_mime(self, from_user, crypto, passcode):
        ''' 
            Decrypt an open PGP MIME message (internal use only).
        '''

        decrypted = False
        plaintext = None
        encrypted_part = None
        
        try:
            self.log_message("message is in OpenPGP MIME format")
            if self.DEBUGGING: self.log_message("{}".format(self.crypto_message.get_email_message().to_string()))
            payloads = self.crypto_message.get_email_message().get_message().get_payload()
            self.log_message("{} parts in message".format(len(payloads)))

            encrypted_part = payloads[self.ENCRYPTED_BODY_PART_INDEX]
            if isinstance(encrypted_part, Message):
                encrypted_part = encrypted_part.get_payload()
            if DecryptFilter.DEBUGGING:
                self.log_message("encrypted_part\n{}".format(encrypted_part))
            plaintext = self._decrypt(from_user, encrypted_part, crypto, passcode)
        except CryptoException as crypto_exception:
            raise CryptoException(crypto_exception.value)
        except Exception:
            self.log_message(format_exc())

        if plaintext == None or encrypted_part is None or plaintext == encrypted_part:
            decrypted = False
            self.log_message("unable to decrypt message")

        else:
            filtered = self._extract_embedded_message(plaintext)
            self.crypto_message.set_filtered(filtered)
            decrypted = self.crypto_message.is_crypted()
        
        return decrypted


    def _decrypt_inline_pgp(self, from_user, crypto, passcode):
        ''' 
            Decrypt an inline PGP message (internal use only).
        '''

        def adjust_attachment_name(part):
            '''Adjust the filename for the attachment.'''

            try:
                filename = part.get_filename()
                if filename and filename.endswith('.pgp'):
                    self.log_message('original attachment filename: {}'.format(filename))
                    end = len(filename) - len('.pgp')
                    part.replace_header(
                      mime_constants.CONTENT_DISPOSITION_KEYWORD, 
                      'attachment; filename="{}"'.format(filename[:end]))
                    filename = part.__getitem__(mime_constants.CONTENT_DISPOSITION_KEYWORD)
                    self.log_message('new attachment filename: {}'.format(filename))
                else:
                    self.log_message('attachment filename: {}'.format(filename))
            except:
                self.log_message(format_exc())


        decrypted = False
        
        self.log_message("message is inline PGP format")
        message = self.crypto_message.get_email_message().get_message()
        self.log_message("message content type is {}".format(message.get_content_type()))
        
        if message.is_multipart():
            for part in message.get_payload():
                content_type = part.get_content_type()
                ciphertext = part.get_payload(decode=True)
                plaintext = self._decrypt(from_user, ciphertext, crypto, passcode)
                if plaintext is not None and plaintext != ciphertext:
                    decrypted = True
                    
                    charset = part.get_charset()
                    self.log_message("message part charset is {}".format(charset))
                    part.set_payload(plaintext, charset=charset)
                    if part.has_key(mime_constants.CONTENT_DISPOSITION_KEYWORD):
                        adjust_attachment_name(part)
                    
                    encoding = part.__getitem__(mime_constants.CONTENT_XFER_ENCODING_KEYWORD)
                    if encoding == mime_constants.QUOTED_PRINTABLE_ENCODING:
                        encode_quopri(part)
                        self.log_message("{} encoded message part".format(encoding))
                    elif encoding == mime_constants.BASE64_ENCODING:
                        encode_base64(part)
                        self.log_message("{} encoded message part".format(encoding))
        else:
            ciphertext = self.crypto_message.get_email_message().get_content()
            plaintext = self._decrypt(from_user, ciphertext, crypto, passcode)

            if plaintext is None or ciphertext is None or plaintext == ciphertext:
                decrypted = False
                self.log_message("unable to decrypt {} message".format(message.get_content_type()))
            else:
                encoding = self.crypto_message.get_email_message().get_message().__getitem__(
                    mime_constants.CONTENT_XFER_ENCODING_KEYWORD)
                if encoding == mime_constants.QUOTED_PRINTABLE_ENCODING:
                    plaintext = encode_quopri(plaintext)
                elif encoding == mime_constants.BASE64_ENCODING:
                    plaintext = encode_base64(plaintext)
                charset, __ = utils.get_charset(message)
                self.crypto_message.get_email_message().set_text(plaintext, charset=charset)
                decrypted = True
        
        return decrypted


    def _decrypt(self, from_user, data, crypto, passcode):
        ''' 
            Decrypt the data from a message (internal use only).
        '''

        def verify_signature(signed_by):
            ''' Verify the message was signed by the sender. '''

            tag = None
            
            if signed_by is None:
                tag = '{}{}'.format(
                    decrypt_utils.get_decrypt_tag(), i18n(', but it was not signed by anyone.'))
            else:
                __, from_user_addr = parse_address(from_user)
                __, signed_by_addr = parse_address(signed_by)
                self.log_message("message encrypted and signed by {}".format(signed_by_addr))

                if from_user_addr == signed_by_addr:
                    # assume the key is ok unless it's required to be verified before we use it
                    key_ok = not options.require_key_verified()
                    if not key_ok:
                        __, key_ok, __ = contacts.get_fingerprint(signed_by_addr, crypto.get_name())

                    if key_ok:
                        tag = '{}{}'.format(
                          decrypt_utils.get_decrypt_tag(), 
                          i18n(' and it was signed by the sender, {email}.'.format(email=signed_by_addr)))
                    else:
                        tag = '{}{}'.format(
                          decrypt_utils.get_decrypt_tag(), 
                          i18n(' and it appears to be signed by the sender, {email}, but the key has not been verified.'.format(
                              email=signed_by_addr)))
                else:
                    tag = '{}{}'.format(
                      decrypt_utils.get_decrypt_tag(), 
                      i18n(', but it was signed by {signer}, not by the sender, {sender}.'.format(
                          signer=signed_by_addr, sender=from_user_addr)))

            if tag is not None:
                self.crypto_message.add_prefix_to_tag_once(tag)
                self.log_message('tag added: {}'.format(tag))


        decrypted_data = signed_by = None

        if crypto is None or data is None:
            decrypted_data = None
            self.log_message("no crypto defined")
        else:
            data_bytearray = bytearray(data)

            #  ASCII armored plaintext looks just like armored ciphertext,
            #  so check that we actually have encrypted data
            if (not self.USE_ANALYZER or 
                OpenPGPAnalyzer().is_encrypted(data_bytearray, passphrase=passcode, crypto=crypto)):

                decrypted_data, signed_by, result_code = crypto.decrypt(data_bytearray, passcode)
                if (decrypted_data == None or 
                    (isinstance(decrypted_data, str) and len(decrypted_data) <= 0)):
                    decrypted_data = None
                    self.log_message("unable to decrypt data")
                    if self.DEBUGGING: self.log_message('data bytearray:\n{}'.format(data_bytearray))
                else:
                    if result_code == 0:
                        verify_signature(signed_by)
                    elif result_code == 2:
                        self.crypto_message.add_tag_once(
                          i18n("Can't verify signature. Ask the sender to use GoodCrypto with auto-key exchange, or you can manually import their public key."))
                    if isinstance(decrypted_data, str):
                        self.log_message('plaintext length: {}'.format(len(decrypted_data)))
                    if self.DEBUGGING: self.log_message('plaintext:\n{}'.format(decrypted_data))
            else:
                decrypted_data = None
                self.log_message("data appeared encrypted, but wasn't")
                if self.DEBUGGING: self.log_message('data:\n{}'.format(data))

        return decrypted_data


    def _extract_embedded_message(self, plaintext):
        '''
            Extract an embedded message.
            
            If the message includes an Open PGP header, then
            save the plaintext in the email message. Otherwise,
            create a new email message from the embedded message.
        '''

        extracted_embedded_message = False
        
        try:
            if self.DEBUGGING: self.log_message('embbedded message:\n{}'.format(plaintext))
            encrypted_type = utils.get_first_header(
                self.crypto_message.get_email_message().get_message(), PGP_ENCRYPTED_CONTENT_TYPE)
            if encrypted_type is None:
                old_message = self.crypto_message.get_email_message().get_message()
                new_message = utils.plaintext_to_message(old_message, plaintext)
                self.crypto_message.get_email_message().set_message(new_message)
                self.crypto_message.set_crypted(True)
                self.log_message("created a new message from the plaintext")
                if self.DEBUGGING: 
                    self.log_message('final message:\n{}'.format(self.crypto_message.get_email_message().to_string()))
            else:
                #  this assumes an embedded mime message
                self.log_message("openpgp mime type: {}".format(encrypted_type))
                embedded_message = EmailMessage(plaintext)
                self.crypto_message.set_email_message(embedded_message)
                self.crypto_message.set_crypted(True)
                extracted_embedded_message = True
                self.log_message("embedded message type is {}".format(
                   embedded_message.get_message().get_content_type()))
        except Exception:
            self.log_message(format_exc())
            ExceptionLog.log_message(format_exc())

        return extracted_embedded_message


    def _filter_html(self):
        ''' 
            Filter HTML to remove malious code (internal use only).
        '''

        try:
            message = self.crypto_message.get_email_message().get_message()
            for part in message.walk():
                part_content_type = part.get_content_type()
                # filter html and plain text 
                if (part_content_type == mime_constants.TEXT_HTML_TYPE or
                    part_content_type == mime_constants.TEXT_PLAIN_TYPE):
                
                    original_payload = part.get_payload()
                    safe_payload = firewall_html(original_payload)
                    if original_payload != safe_payload:
                        try:
                            # strip extraneous </html>
                            HTML_CLOSE = '</html>'
                            if (part_content_type == mime_constants.TEXT_PLAIN_TYPE and
                                safe_payload.lower().find('<html>') < 0):
                                index = safe_payload.find(HTML_CLOSE)
                                if index >= 0:
                                    safe_payload = '{} {}'.format(
                                       safe_payload[0:index], safe_payload[index+len(HTML_CLOSE):])
                        except:
                            self.log_message(format_exc())
                            pass
                        part.set_payload(safe_payload)
                        self.log_message("html filtered {} content".format(part_content_type))
        except Exception:
            self.log_message(format_exc())

    def add_validation_code(self, validation_code):
        ''' Add validation code to message. '''

        goodcrypto_server_url = options.get_goodcrypto_server_url()
        if goodcrypto_server_url and len(goodcrypto_server_url) > 0:
            quoted_code = urllib.quote(validation_code)
            validation_msg = i18n('Verify GoodCrypto decrypted this message: {url}mail/msg-decrypted/{quoted_code}'.format(
                url=goodcrypto_server_url, quoted_code=quoted_code))
        else:
            validation_msg = i18n('Message validation code: {validation_code}'.format(validation_code=validation_code))

        self.crypto_message.add_tag_once(validation_msg)
        self.log_message(validation_msg)

    def log_message(self, message):
        '''
            Log the message to the local log.
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

