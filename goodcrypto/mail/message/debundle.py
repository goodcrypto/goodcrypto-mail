'''
    Copyright 2015 GoodCrypto
    Last modified: 2015-07-27

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import base64, os, re

from goodcrypto.mail import options
from goodcrypto.mail.utils import get_sysadmin_email, is_metadata_address
from goodcrypto.mail.message import decrypt_utils, utils
from goodcrypto.mail.message.constants import ORIGINAL_FROM, ORIGINAL_TO
from goodcrypto.mail.message.crypto_message import CryptoMessage
from goodcrypto.mail.message.decrypt import Decrypt
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.header_keys import HeaderKeys
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.validator import Validator
from goodcrypto.mail.utils import get_metadata_address
from goodcrypto.mail.utils.notices import notify_user
from goodcrypto.utils import i18n
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr import mime_constants


class Debundle(object):
    '''
        Filter to debundle one or more messages, including
        messages that have been bundled together to stop traffic analysis.

        See the unit tests to see how to use the Debundle class.
    '''

    DEBUGGING = False

    def __init__(self, crypto_message):
        '''
            >>> decrypt = Debundle(None)
            >>> decrypt != None
            True
        '''

        self.log = LogFile()
        self.crypto_message = crypto_message
        self.messages_sent = 0

    def make_messages_readable(self):
        '''
            If the message is an encrypted message to a single individual,
            then decrypt the message and send it to the recipient. If the
            message is an encrypted message that protects metadata and contains
            one or more messages inside, then decrypt the metadata, decrypt the
            inner message(s) and deliver each message to the intended recipient.
            If the message is not encrypted, then just add a warning about 
            receiving unencrypted messages.

            See unittests for usage as the test set up is too complex for a doctest.
        '''

        try:
            filtered = decrypted = metadata_key_sent = False

            from_user = self.crypto_message.smtp_sender()
            to_user = self.crypto_message.smtp_recipient()

            # first see if there's a metadata wrapper
            if is_metadata_address(from_user) and is_metadata_address(to_user):
                metadata_key_sent = self.decrypt_metadata()

            # if only one of to/from is a metadata address, the message is bad
            elif is_metadata_address(from_user) or is_metadata_address(to_user):
                self.log_message("bad envelope: from user: {} to_user: {}".format(from_user, to_user))
                self.crypto_message.drop()

            if not self.crypto_message.is_dropped():
                # now see if there's a bundle of padded messages
                if (is_metadata_address(self.crypto_message.smtp_sender()) and
                    is_metadata_address(self.crypto_message.smtp_recipient())):

                    self.unbundle_wrapped_messages()

                else:
                    self.decrypt_message(metadata_key_sent)
        except:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return self.crypto_message

    def decrypt_metadata(self):
        '''
            Decrypt the wrapper message that protects metadata.
        '''

        metadata_key_sent = False
        from_user = self.crypto_message.smtp_sender()
        to_user = self.crypto_message.smtp_recipient()

        self.log_message("decrypting metadata protected message from {} to {}".format(from_user, to_user))
        if Debundle.DEBUGGING:
            self.log_message('DEBUG: logged original metadata headers in goodcrypto.message.utils.log')
            utils.log_message_headers(self.crypto_message, tag='original metadata headers')

        # the metadata wrapper always includes its own pub key in the header
        # and it must be imported if we don't already have it
        auto_exchange_keys = options.auto_exchange_keys()
        options.set_auto_exchange_keys(True)
        header_keys = HeaderKeys()
        # import the key if it's new, and 
        # verify the key matches the sender's email address and our database
        header_keys.manage_keys_in_header(self.crypto_message)
        new_metadata_key = header_keys.new_key_imported_from_header()
        options.set_auto_exchange_keys(auto_exchange_keys)

        if self.crypto_message.is_dropped():
            decrypted = False
            self.log_message("metadata message dropped because of bad key in header")
            raise MessageException('Metadata message dropped because of a bad key in the header')
        else:
            # before we change anything, send our metadata key to the recipient
            if new_metadata_key:
                metadata_key_sent = decrypt_utils.send_metadata_key(from_user, to_user)
                self.log_message('sent metadata key: {}'.format(metadata_key_sent))

            decrypt = Decrypt(self.crypto_message)
            decrypted, decrypted_with = decrypt.decrypt_message()
            inner_crypto_message = decrypt.get_crypto_message()
            if inner_crypto_message.is_dropped():
                self.log_message('public metadata wrapper dropped')
            else:
                if decrypted:
                    wrapped_crypto_message = self.get_bundled_message(inner_crypto_message)
                    wrapped_crypto_message.set_metadata_crypted(True)
                    wrapped_crypto_message.set_metadata_crypted_with(decrypted_with)
                    self.log_message('created decrypted wrapped message')
                    if self.DEBUGGING:
                        self.log_message('DEBUG: logged decrypted wrapped headers in goodcrypto.message.utils.log')
                        utils.log_message_headers(wrapped_crypto_message, tag='decrypted wrapped headers')
                else:
                    # if it's not encypted, then redirect the message to the sysadmin
                    sysadmin = get_sysadmin_email()
                    wrapped_crypto_message = inner_crypto_message
                    wrapped_crypto_message.set_smtp_recipient(sysadmin)
                    wrapped_crypto_message.get_email_message().change_header(
                           mime_constants.TO_KEYWORD, sysadmin)
                    self.log_message('public metadata wrapper message not encrypted so redirecting to sysadmin')

            # use the new inner crypto message
            self.crypto_message = wrapped_crypto_message

        return metadata_key_sent

    def unbundle_wrapped_messages(self):
        ''' Unbundle messages and send them to their intended recipients. '''

        result_ok = False

        self.log_message('unbundling wrapped messages')
        if self.crypto_message is None:
            self.log_message('no crypto message to unbundle')
        else:
            message = self.crypto_message.get_email_message().get_message()
            if self.DEBUGGING:
                self.log_message('DEBUG: logged wrapped headers in goodcrypto.message.utils.log')
                utils.log_message_headers(message, tag='wrapped headers')

            if message.get_content_type() == mime_constants.MULTIPART_MIXED_TYPE:

                result_ok = self.split_and_send_messages(message)

                # no need to re-inject this message as we've already sent the inner messages to users
                self.crypto_message.set_processed(True)

                result_ok = True

            else:
                result_ok = False
                self.crypto_message.drop()
                self.log_message('dropping message because there are no valid bundled messages; content type: {}'.format(
                   message.get_content_type()))

        return result_ok

    def decrypt_message(self, metadata_key_sent):
        ''' Decrypt a message for the original recipient. '''

        try:
            self.log_message('decrypting message')
            if self.DEBUGGING and self.crypto_message is not None:
                self.log_message(
                    'original message:\n{}'.format(self.crypto_message.get_email_message().to_string()))
            decrypt = Decrypt(self.crypto_message)
            self.crypto_message = decrypt.make_message_readable()

            # send our metadata key to the recipient if needed
            if not metadata_key_sent and decrypt.needs_metadata_key():
                self.log_message('need to send metadata key')
                decrypt_utils.send_metadata_key(
                  self.crypto_message.smtp_sender(), self.crypto_message.smtp_recipient())
                self.log_message('sent metadata key previously: {}'.format(metadata_key_sent))
        except:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            try:
                self.crypto_message.add_tag(SERIOUS_ERROR_PREFIX)
            except Exception:
                record_exception()
                self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            raise MessageException()

    def get_bundled_message(self, crypto_message):
        '''
            Get the message which contains one or more bundled messages.
        '''
        try:
            self.log_message('getting message which contains one or more messages')
            if self.DEBUGGING:
                self.log_message('DEBUG: logged bundled crypto headers in goodcrypto.message.utils.log')
                utils.log_message_headers(crypto_message, 'bundled crypto headers')

            inner_message = crypto_message.get_email_message().get_content()
            inner_crypto_message = CryptoMessage(email_message=EmailMessage(inner_message))

            if self.DEBUGGING:
                self.log_message('DEBUG: logged bundled inner headers in goodcrypto.message.utils.log')
                utils.log_message_headers(crypto_message, 'bundled inner headers')

            original_sender = inner_crypto_message.get_email_message().get_header(ORIGINAL_FROM)
            original_recipient = inner_crypto_message.get_email_message().get_header(ORIGINAL_TO)
            original_subject = inner_crypto_message.get_email_message().get_header(mime_constants.SUBJECT_KEYWORD)

            # if this message is an internal message with a subject, then send it to the sysadmin
            if (original_sender == inner_crypto_message.smtp_sender() and
                original_recipient == inner_crypto_message.smtp_recipient() and
                original_subject is not None):
                sysadmin = get_sysadmin_email()
                inner_crypto_message.set_smtp_recipient(sysadmin)
            else:
                inner_crypto_message.set_smtp_sender(original_sender)
                inner_crypto_message.set_smtp_recipient(original_recipient)

            # remove the original keywords from the message
            inner_crypto_message.get_email_message().delete_header(ORIGINAL_FROM)
            inner_crypto_message.get_email_message().delete_header(ORIGINAL_TO)

            if self.DEBUGGING:
                self.log_message('DEBUG: logged inner crypto headers in goodcrypto.message.utils.log')
                utils.log_message_headers(inner_crypto_message, 'inner crypto headers')
        except Exception:
            record_exception()
            inner_crypto_message = None
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return inner_crypto_message

    def split_and_send_messages(self, message):
        ''' Split a message apart and send each to the intended recipient. '''

        result_ok = False
        self.messages_sent = 0
        try:
            for part in message.walk():
                try:
                    if part.get_content_type() == mime_constants.APPLICATION_ALT_TYPE:
                        content = base64.b64decode(part.get_payload(decode=True))
                        inner_crypto_message = self.create_inner_message(content)

                        if inner_crypto_message is not None:
                            self.log_message('logged inner message headers in goodcrypto.message.utils.log')
                            utils.log_message_headers(inner_crypto_message, tag='inner message headers')
                            ok, __ = self.decrypt_and_send_message(inner_crypto_message)
                            if ok:
                                self.messages_sent += 1
                except:
                    self.log_message('bad part of message discarded')
                    self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
                    record_exception()
            result_ok = True
            self.log_message('good bundled message contains {} inner message(s)'.format(self.messages_sent))
        except:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            result_ok = False

        return result_ok

    def create_inner_message(self, content):
        ''' Create the inner crypto message. '''

        inner_crypto_message = None
        try:
            original_message, addendum = utils.parse_bundled_message(content)
            if original_message is None or len(original_message.strip()) <= 0 or addendum is None:
                self.log_message('discarded padding')
            else:
                sender = addendum[mime_constants.FROM_KEYWORD]
                recipient = addendum[mime_constants.TO_KEYWORD]
                if sender is None or recipient is None:
                    self.log_message('discarded badly formatted message')
                else:
                    if self.DEBUGGING: self.log_message('DEBUG: content of part: {}'.format(content))
                    metadata_crypted_with = self.crypto_message.is_crypted_with()

                    inner_crypto_message = CryptoMessage(EmailMessage(original_message))
                    inner_crypto_message.set_smtp_sender(sender)
                    inner_crypto_message.set_smtp_recipient(recipient)
                    inner_crypto_message.set_metadata_crypted(True)
                    inner_crypto_message.set_metadata_crypted_with(metadata_crypted_with)
                    self.log_message('created message from {}'.format(sender))
                    self.log_message('created message to {}'.format(recipient))
                    if self.DEBUGGING: self.log_message('original message: {}'.format(original_message))
        except:
            inner_crypto_message = None
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return inner_crypto_message

    def decrypt_and_send_message(self, inner_crypto_message):
        ''' Decrypt and send a message. '''

        result_ok = False
        sender = recipient = message = decrypted_crypto_message = None
        try:
            decrypt = Decrypt(inner_crypto_message)
            decrypted_crypto_message = decrypt.make_message_readable()

            sender = decrypted_crypto_message.smtp_sender()
            recipient = decrypted_crypto_message.smtp_recipient()
            message = decrypted_crypto_message.get_email_message().get_message().as_string()
            self.log_message('message to {} decrypted: {}'.format(
               recipient, decrypted_crypto_message.is_crypted()))

            if utils.send_message(sender, recipient, message):
                result_ok = True
                self.log_message('sent message to {}'.format(recipient))
                if self.DEBUGGING: self.log_message('DEBUG: message:\n{}'.format(message))
            else:
                result_ok = False
        except AttributeError as attribute_error:
            result_ok = False
            self.log_message(attribute_error)
        except:
            result_ok = False
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        if not result_ok:
            if recipient is None or message is None:
                self.log_message('unknown recipient')
                subject = i18n('Error delivering message')
                error_message = i18n(
                  'An unexpected error was detected when trying to deliver the attached message.\n\n{}'.format(message))
                notify_user(get_sysadmin_email(), subject, error_message)
            else:
                subject = i18n('Error delivering message from {}'.format(sender))
                error_message = i18n(
                  'An unexpected error was detected when trying to deliver the attached message.\n\n{}'.format(message))
                notify_user(recipient, subject, error_message)
            self.log_message(error_message)

        # we're returning the decrypted message to allow tests to verify everything went smoothly
        return result_ok, decrypted_crypto_message

    def log_message(self, message):
        '''
            Log the message to the local log.
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

