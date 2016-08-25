'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-02-01

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, re
from email.encoders import encode_base64, encode_quopri
from email.message import Message
from traceback import format_exc

from goodcrypto.mail import contacts, crypto_software, options, user_keys
from goodcrypto.mail.i18n_constants import SERIOUS_ERROR_PREFIX
from goodcrypto.mail.utils import get_encryption_software
from goodcrypto.mail.message import decrypt_utils, tags, utils
from goodcrypto.mail.message.adjust import plaintext_to_message
from goodcrypto.mail.message.constants import ORIGINAL_FROM, ORIGINAL_TO, PGP_ENCRYPTED_CONTENT_TYPE
from goodcrypto.mail.message.crypto_message import CryptoMessage
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.header_keys import HeaderKeys
from goodcrypto.mail.message.inspect_utils import get_charset, get_first_header, is_open_pgp_mime
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.metadata import get_metadata_address, is_metadata_address
from goodcrypto.mail.message.utils import add_private_key
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.mail.utils.notices import report_unable_to_decrypt
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.open_pgp_analyzer import OpenPGPAnalyzer
from goodcrypto.utils import i18n
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr import mime_constants
from syr.html import firewall_html
from syr.timestamp import Timestamp


class Decrypt(object):
    '''
        Decrypt message filter.

        This filter tries all known encryption software for the recipient.
        Because encryption may be nested, this class keeps trying until the
        message is decrypted, or no valid encryption program can decrypt it further.

        !!!! If part of a message is plaintext and part encrypted, the decrypted
             text replaces the entire text, and the plaintext part is lost.

        !!!! A multiply-encrypted message may be tagged decrypted if any layer
             is successfully decrypted, even if an inner layer is still encrypted.

        See the unit tests to see how to use the Decrypt class.
    '''

    DEBUGGING = False

    #  the encrypted content is the second part; indexing starts at 0
    ENCRYPTED_BODY_PART_INDEX = 1

    def __init__(self, crypto_message):
        '''
            >>> decrypt = Decrypt(None)
            >>> decrypt != None
            True
        '''

        self.log = LogFile()
        self.crypto_message = crypto_message

        self.need_to_send_metadata_key = False

    def process_message(self):
        '''
            If the message is encrypted, try to decrypt it.
            If it's not encrypted, add a warning about the dangers of unencrypted messages.

            See unittests for usage as the test set up is too complex for a doctest.
        '''

        try:
            filtered = decrypted = False

            from_user = self.crypto_message.smtp_sender()
            to_user = self.crypto_message.smtp_recipient()

            if options.verify_dkim_sig():
                self.crypto_message, dkim_sig_verified = decrypt_utils.verify_dkim_sig(self.crypto_message)
                self.log_message('verified dkim signature ok: {}'.format(dkim_sig_verified))

            self.log_message("checking if message from {} to {} needs decryption".format(from_user, to_user))
            if Decrypt.DEBUGGING:
                self.log_message('logged original message headers in goodcrypto.message.utils.log')
                utils.log_message_headers(self.crypto_message, tag='original message headers')

            header_keys = HeaderKeys()
            if options.auto_exchange_keys():
                header_contains_key_info = header_keys.manage_keys_in_header(self.crypto_message)
            else:
                header_contains_key_info = header_keys.keys_in_header(self.crypto_message)

            if self.crypto_message.is_dropped():
                decrypted = False
                self.log_message("message dropped because of bad key in header")
                self.log_message('logged dropped message headers in goodcrypto.message.utils.log')
                utils.log_message_headers(self.crypto_message, tag='dropped message headers')
            else:
                if self.crypto_message.get_email_message().is_probably_pgp():
                    decrypted, decrypted_with = self.decrypt_message()
                    if not decrypted and self.crypto_message.is_metadata_crypted():
                        tags.add_metadata_tag(self.crypto_message)
                        self.log_message("message only encrypted with metadata key")
                else:
                    decrypt_utils.verify_clear_signed(from_user, self.crypto_message)
                    if self.crypto_message.is_metadata_crypted():
                        tags.add_metadata_tag(self.crypto_message)
                        self.log_message("message only encrypted with metadata key")
                    else:
                        tags.add_unencrypted_warning(self.crypto_message)
                        self.log_message("message doesn't appear to be encrypted at all")

                    # create a private key for the recipient if there isn't one already
                    add_private_key(to_user)

            self.need_to_send_metadata_key = (
                # if the metadata wasn't encrypted
                not self.crypto_message.is_metadata_crypted() and
                # but the sender's key was in the header so we know the sender uses GoodCrypto private server
                header_contains_key_info and
                # and we don't have the sender's metadata key
                len(contacts.get_encryption_names(get_metadata_address(email=from_user))) < 1)
            self.log_message('need to send metadata key: {}'.format(self.need_to_send_metadata_key))

            self.log_message('message content decrypted: {}'.format(decrypted))

            # finally save a record so the user can verify the message was received securely
            if decrypted or self.crypto_message.is_metadata_crypted() or self.crypto_message.is_signed():
                decrypt_utils.add_history_and_verification(self.crypto_message)

            if decrypted or self.crypto_message.is_metadata_crypted():
                self.crypto_message.set_crypted(True)
                if not decrypted:
                    self.log_message('metadata tag: {}'.format(self.crypto_message.get_tag()))
            else:
                self.crypto_message.set_crypted(False)

            filtered = tags.add_tag_to_message(self.crypto_message)
            self.crypto_message.set_filtered(filtered)
            self.log_message("finished adding tags to message; filtered: {}".format(filtered))
            self.log_message("message encrypted with: {}".format(self.crypto_message.get_crypted_with()))
            self.log_message("metadata encrypted with: {}".format(self.crypto_message.get_metadata_crypted_with()))

            if self.DEBUGGING:
                self.log_message('logged final decrypted headers in goodcrypto.message.utils.log')
                utils.log_message_headers(self.crypto_message, tag='final decrypted headers')

            self.log_message('  final status: filtered: {} decrypted: {}'.format(
                self.crypto_message.is_filtered(), self.crypto_message.is_crypted()))

        except MessageException as message_exception:
            raise MessageException(value=message_exception.value)

        except:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return self.crypto_message

    def get_crypto_message(self):
        ''' Get the crypto message. '''

        return self.crypto_message

    def decrypt_message(self, filter_msg=True):
        '''
            Decrypt a message and add a tag if unsuccessful (internal use only).
        '''

        encryption_names = self._get_recipient_encryption_software()
        if encryption_names is None or len(encryption_names) < 1 or self.crypto_message is None:
            decrypted = False
            decrypted_with = []
            self.log_message('unable to decrypt message when missing data')
        else:
            try:
                self.log_message('trying to decrypt with: {}'.format(encryption_names))
                decrypted, decrypted_with = self._decrypt_with_all_encryption(encryption_names)

                if decrypted:
                    self.crypto_message.set_crypted_with(decrypted_with)

                #  if the message is still encrypted, log it and tell the user
                elif self.crypto_message.get_email_message().is_probably_pgp():
                    if len(encryption_names) > 1:
                        software = encryption_names.__str__()
                    else:
                        software = str(encryption_names[0])

                    log_msg = "Failed to decrypt with {}".format(software)
                    self.log_message(log_msg)
                    self.log_message('logged failed message headers in goodcrypto.message.utils.log')
                    utils.log_message_headers(self.crypto_message, 'failed message headers')
                    record_exception(message=log_msg)

                    tag = i18n('Unable to decrypt message with {encryption}'.format(encryption=software))
                    self.crypto_message.add_tag_once(tag)

                # don't filter bundled messages; each message will be filtered separately
                if filter_msg and options.filter_html():
                    self._filter_html()
                else:
                    self.log_message("html filter disabled")
            except CryptoException as crypto_exception:
                raise CryptoException(crypto_exception.value)
            except Exception:
                decrypted = False
                record_exception()
                self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return decrypted, decrypted_with

    def needs_metadata_key(self):
        ''' Gets whether the metadata key should be sent. '''

        return self.need_to_send_metadata_key

    def _get_recipient_encryption_software(self):
        '''
            Get the software to decrypt a message for the recipient (internal use only).

            If the user doesn't have a key, then configure one and return None.
        '''

        encryption_software = None

        if self.crypto_message is None:
            self.log_message("missing crypto_message".format(self.crypto_message))
        else:
            try:
                from_user = self.crypto_message.smtp_sender()
                to_user = self.crypto_message.smtp_recipient()
                encryption_software = get_encryption_software(to_user)
                if encryption_software and len(encryption_software) > 0:
                    self.log_message("encryption software: {}".format(encryption_software))
                elif email_in_domain(to_user) and options.create_private_keys():
                    add_private_key(to_user, encryption_software=encryption_software)
                    self.log_message("started to create a new {} key for {}".format(encryption_software, to_user))
                else:
                    self.log_message("no encryption software for {}".format(to_user))
                    self.crypto_message.add_tag_once(
                        i18n('{email} does not use any known encryption'.format(email=to_user)))
                    """
                    subject = i18n('{} Unable to decrypt message'.format(SERIOUS_ERROR_PREFIX))
                    notify_user(to_user, subject, self.crypto_message.get_email_message().to_string())
                    """
                    report_unable_to_decrypt(to_user, self.crypto_message.get_email_message().to_string())
            except CryptoException as crypto_exception:
                raise CryptoException(crypto_exception.value)
            except Exception, IOError:
                utils.log_crypto_exception(MessageException(format_exc()))
                record_exception()
                self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
                try:
                    self.crypto_message.add_tag(SERIOUS_ERROR_PREFIX)
                except Exception:
                    record_exception()
                    self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return encryption_software

    def _decrypt_with_all_encryption(self, encryption_names):
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
                        if self._decrypt_message_with_crypto(encryption_name):
                            #  if any encryption decrypts, the message was decrypted
                            decrypted = True
                            decrypted_with.append(encryption_name)
                            self.crypto_message.set_crypted(decrypted)
                    except CryptoException as crypto_exception:
                        raise CryptoException(crypto_exception.value)
                    except Exception:
                        msg = 'could not decrypt with {}.'.format(encryption_name)
                        self.log_message(msg)
                        self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
                        record_exception()
                else:
                    self.log_message("message already decrypted, so did not try {}".format(encryption_name))
        except CryptoException as crypto_exception:
            raise CryptoException(crypto_exception.value)
        except Exception:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return decrypted, decrypted_with

    def _decrypt_message_with_crypto(self, encryption_name):
        '''
            Decrypt a message using the encryption software (internal use only).
        '''

        decrypted = False
        self.log_message("encryption program: {}".format(encryption_name))

        from_user = self.crypto_message.smtp_sender()
        to_user = self.crypto_message.smtp_recipient()

        passcode = user_keys.get_passcode(to_user, encryption_name)
        if passcode == None or len(passcode) <= 0:
            tag = '{email} does not have a private key configured.'.format(email=to_user)
            self.log_message(tag)
            self.crypto_message.add_tag_once(tag)
        else:
            # make sure that the key for the recipient is ok; if it's not, a CryptoException is thrown
            __, verified, __ = contacts.is_key_ok(to_user, encryption_name)
            self.log_message('{} {} key pinned'.format(to_user, encryption_name))
            self.log_message('{} {} key verified: {}'.format(to_user, encryption_name, verified))

            crypto = CryptoFactory.get_crypto(encryption_name, crypto_software.get_classname(encryption_name))

            # try to verify signature in case it was clear signed after it was encrypted
            decrypt_utils.verify_clear_signed(
               from_user, self.crypto_message, encryption_name=crypto.get_name(), crypto=crypto)

            self.log_message('trying to decrypt using {} private {} key.'.format(to_user, encryption_name))
            if is_open_pgp_mime(self.crypto_message.get_email_message().get_message()):
                decrypted = self._decrypt_open_pgp_mime(from_user, crypto, passcode)
            else:
                decrypted = self._decrypt_inline_pgp(from_user, crypto, passcode)
            self.log_message('decrypted using {} private {} key: {}'.format(to_user, encryption_name, decrypted))

            # try to verify signature in case it was clear signed before it was encrypted
            if decrypted:
                decrypt_utils.verify_clear_signed(
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
            if self.DEBUGGING:
                self.log_message('logged OpenPGP mime headers in goodcrypto.message.utils.log')
                utils.log_message_headers(self.crypto_message, tag='OpenPGP mime headers')

            # remove any clear signed section before decrypting message
            self.crypto_message.get_email_message().remove_pgp_signature_blocks()

            payloads = self.crypto_message.get_email_message().get_message().get_payload()
            self.log_message("{} parts in message".format(len(payloads)))

            encrypted_part = payloads[self.ENCRYPTED_BODY_PART_INDEX]
            if isinstance(encrypted_part, Message):
                encrypted_part = encrypted_part.get_payload()
            if Decrypt.DEBUGGING:
                self.log_message("encrypted_part\n{}".format(encrypted_part))

            plaintext = self._decrypt(from_user, encrypted_part, crypto, passcode)
        except CryptoException as crypto_exception:
            raise CryptoException(crypto_exception.value)
        except Exception:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

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
                record_exception()
                self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')


        decrypted = False

        self.log_message("message is inline PGP format")
        message = self.crypto_message.get_email_message().get_message()
        self.log_message("message content type is {}".format(message.get_content_type()))

        # remove any clear signed section before decrypting message
        self.crypto_message.get_email_message().remove_pgp_signature_blocks()

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
                charset, __ = get_charset(message)
                self.crypto_message.get_email_message().set_text(plaintext, charset=charset)
                decrypted = True

        return decrypted


    def _decrypt(self, from_user, data, crypto, passcode):
        '''
            Decrypt the data from a message (internal use only).
        '''

        decrypted_data = signed_by = None

        if crypto is None or data is None:
            decrypted_data = None
            self.log_message("no crypto defined")
        else:
            data_bytearray = bytearray(data)

            #  ASCII armored plaintext looks just like armored ciphertext,
            #  so check that we actually have encrypted data
            if (OpenPGPAnalyzer().is_encrypted(
                data_bytearray, passphrase=passcode, crypto=crypto)):

                if self.DEBUGGING: self.log_message('data bytearray before decryption:\n{}'.format(data_bytearray))
                decrypted_data, signed_by, result_code = crypto.decrypt(data_bytearray, passcode)
                if (decrypted_data == None or
                    (isinstance(decrypted_data, str) and len(decrypted_data) <= 0)):
                    decrypted_data = None
                    self.log_message("unable to decrypt data")
                    if self.DEBUGGING: self.log_message('data bytearray after decryption:\n{}'.format(data_bytearray))
                else:
                    if result_code == 0:
                        tag = tags.get_decrypt_signature_tag(
                           self.crypto_message, from_user, signed_by, crypto.get_name())
                        if tag is not None:
                            self.crypto_message.add_prefix_to_tag_once(tag)
                            self.log_message('decrypt tag: {}'.format(tag))
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
            encrypted_type = get_first_header(
                self.crypto_message.get_email_message().get_message(), PGP_ENCRYPTED_CONTENT_TYPE)
            if encrypted_type is None:
                old_message = self.crypto_message.get_email_message().get_message()
                new_message = plaintext_to_message(old_message, plaintext)
                self.crypto_message.get_email_message().set_message(new_message)
                self.crypto_message.set_crypted(True)
                self.log_message("created a new message from the plaintext")
                if self.DEBUGGING:
                    self.log_message('logged final embedded message headers in goodcrypto.message.utils.log')
                    utils.log_message_headers(self.crypto_message, tag='final embedded message headers')
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
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

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
                            record_exception()
                            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
                            pass
                        part.set_payload(safe_payload)
                        self.log_message("html filtered {} content".format(part_content_type))
        except Exception:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    def log_message(self, message):
        '''
            Log the message to the local log.
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

