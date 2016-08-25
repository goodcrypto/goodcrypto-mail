'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-01-26

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import sh
from dkim import DKIMException
from smtplib import SMTP

from goodcrypto.mail import options
from goodcrypto.mail.constants import TAG_ERROR
from goodcrypto.mail.message import utils
from goodcrypto.mail.message.crypto_message import CryptoMessage
from goodcrypto.mail.message.debundle import Debundle
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.encrypt import Encrypt
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.metadata import is_metadata_address
from goodcrypto.mail.utils import email_in_domain, get_admin_email, send_message
from goodcrypto.mail.utils.notices import notify_user
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.utils import i18n
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile


class Filter(object):
    '''
        Filters a message through the encrypt or decrypt filter as needed.

        The overall design of this module is trying to emulate a milter
        so if we ever decide to convert from a content filter it will be easier.
    '''

    DEBUGGING = False

    def __init__(self, from_user, to_user, message):
        '''
            >>> # In honor of John Kiriakou, who went to prison for exposing CIA torture.
            >>> # In honor of asn, developer of Obfsproxy.
            >>> filter = Filter('john@goodcrypto.local', 'asn@goodcypto.remote', 'message')
            >>> filter is not None
            True
        '''
        self.log = self.out_message = None

        self.sender = from_user
        self.recipient = to_user
        self.in_message = message

    def process(self):
        ''' Encrypt/decrypt the message, or decide not to. '''

        self.log_message('=== starting to filter mail from {} to {} ==='.format(self.sender, self.recipient))

        self.out_message = self.in_message
        crypto_message = CryptoMessage(
            email_message=EmailMessage(self.in_message), sender=self.sender, recipient=self.recipient)

        if self.possibly_needs_encryption():

            self.process_outbound_message(crypto_message)

        else:
            self.process_inbound_message(crypto_message)

        result_code = self.reinject_message()

        self.log_message('mail filtered ok: {}'.format(result_code))
        self.log_message('=== finished filtering mail from {} to {} ==='.format(self.sender, self.recipient))

        return result_code

    def process_outbound_message(self, crypto_message):
        ''' Process an outbound message, encrypting if approriate. '''

        try:
            # something is wrong if an outbound message is from the metadata address
            # any messages from a metadata address don't pass through the filter
            if is_metadata_address(self.sender):
                self.sender = get_admin_email()
                self.bounce_outbound_message(i18n('Message originating from your metadata address'))
                self.out_message = None
            else:
                encrypt = Encrypt(crypto_message)
                encrypted_message = encrypt.process_message()
                filtered = encrypted_message.is_filtered()
                crypted = encrypted_message.is_crypted()
                processed = encrypted_message.is_processed()

                if encrypted_message.is_dropped():
                    self.out_message = None
                    self.log_message('outbound message dropped')
                elif processed:
                    # nothing to re-inject at this time
                    self.out_message = None
                    self.log_message('outbound message processed')
                else:
                    self.out_message = encrypted_message.get_email_message().to_string()
                    self.sender = encrypted_message.smtp_sender()
                    self.recipient = encrypted_message.smtp_recipient()
                    self.log_message(
                        'outbound sender: {} recipient: {}'.format(self.sender, self.recipient))

                self.log_message('outbound final status: filtered: {} crypted: {}  queued: {}'.format(
                    filtered, crypted, processed))
        except MessageException as message_exception:
            self.bounce_outbound_message(message_exception.value)
            self.out_message = None
        except Exception as exception:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            try:
                self.bounce_outbound_message(exception.value)
            except:
                self.bounce_outbound_message(exception)
            self.out_message = None
        except IOError as ioerror:
            try:
                self.bounce_outbound_message(ioerror.value)
            except:
                self.bounce_outbound_message(ioerror)
            self.out_message = None

    def process_inbound_message(self, crypto_message):
        ''' Process an inbound message, decrypting if appropriate. '''

        try:
            debundled_message = None
            filtered = crypted = processed = False

            if self.DEBUGGING:
                self.log_message(crypto_message.get_email_message().to_string())

            debundle = Debundle(crypto_message)
            debundled_message = debundle.process_message()
            filtered = debundled_message.is_filtered()
            crypted = debundled_message.is_crypted()
            processed = debundled_message.is_processed()

            if debundled_message.is_dropped():
                self.out_message = None
                self.log_message('inbound message dropped')
            elif processed:
                # nothing to re-inject at this time
                self.out_message = None
                self.log_message('inbound message processed')
            else:
                self.out_message = debundled_message.get_email_message().to_string()
                self.sender = debundled_message.smtp_sender()
                self.recipient = debundled_message.smtp_recipient()
                self.log_message(
                    'inbound sender: {} recipient: {}'.format(self.sender, self.recipient))

            self.log_message('inbound final status: filtered: {} crypted: {}  queued: {}'.format(
                filtered, crypted, processed))
        except DKIMException as dkim_exception:
            self.drop_message(dkim_exception)
            self.out_message = None
        except CryptoException as crypto_exception:
            if debundled_message is not None and not debundled_message.is_dropped():
                self.wrap_inbound_message(crypto_exception, debundled_message)
            self.out_message = None
        except MessageException as message_exception:
            if debundled_message is not None and not debundled_message.is_dropped():
                self.wrap_inbound_message(message_exception, debundled_message)
            self.out_message = None
        except Exception as exception:
            self.wrap_inbound_message(exception, debundled_message)
            self.out_message = None
        except IOError as ioerror:
            self.wrap_inbound_message(ioerror, debundled_message)
            self.out_message = None

    def possibly_needs_encryption(self):
        '''
            Determine if the message might need to be encrypted or not.

            It could need encrytion if the sender has the same domain as
            the domain defined in goodcrypto mail server's options. If we're not using
            an SMTP proxy, then it never needs encryption if the message is going
            to and from a user with the domain defined in goodcrypto mail server's options.
        '''

        maybe_needs_encryption = email_in_domain(self.sender)

        self.log_message('possibly needs encryption: {}'.format(maybe_needs_encryption))

        return maybe_needs_encryption

    def get_processed_message(self):
        '''
            Get the message after it has been processed.

            >>> filter = Filter('root', 'root', 'bad message')
            >>> filter.get_processed_message()
        '''
        return self.out_message

    def reinject_message(self, message=None):
        ''' Re-inject message back into queue. '''

        if message is None:
            message = self.out_message

        try:
            if message is None:
                # set to result_ok to True because we've already bounced the message or
                # there isn't anything to bounce because it failed validation
                result_ok = True
                self.log_message('nothing to reinject')
            else:
                self.log_message('starting to re-inject message into postfix queue')
                result_ok = send_message(self.sender, self.recipient, message)
                self.log_message('re-injected message: {}'.format(result_ok))
                if self.DEBUGGING:
                    self.log_message('\n==================\n')
                    self.log_message(message)
                    self.log_message('\n==================\n')
        except Exception as exception:
            result_ok = False
            self.log_message('error while re-injecting message into postfix queue')
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            record_exception()
            try:
                error_message = exception.value
                to_address = self.reject_message(error_message)
                self.log_message('sent notice to {} about {}'.format(to_address, error_message))
            except:
                record_exception()
                self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return result_ok

    def reject_message(self, error_message, message=None):
        '''
            Reject a message that had an unexpected error.

            >>> # This message will fail if testing on dev system
            >>> filter = Filter('root', 'root', 'bad message')
            >>> filter.reject_message('Unknown message')
            u'support@goodcrypto.local'
        '''
        try:
            if message is None:
                message = self.out_message

            if email_in_domain(self.sender):
                to_address = self.sender
                subject = i18n('Undelivered Mail: Unable to send message')
            elif email_in_domain(self.recipient):
                to_address = self.recipient
                subject = i18n('Error: Unable to receive message')
            else:
                to_address = get_admin_email()
                subject = i18n('Message rejected.')

            notice = '{}'.format(error_message)
            if message is not None:
                notice += '\n\n===================\n{}'.format(message)
            notify_user(to_address, subject, notice)
        except:
            raise

        return to_address

    def bounce_outbound_message(self, error_message):
        ''' Bounce a message that a local user originated. '''

        self.log_message(error_message)
        self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        record_exception()

        subject = i18n('{} - Undelivered Mail: Unable to protect message'.format(TAG_ERROR))
        utils.bounce_message(self.in_message, self.sender, subject, error_message)

    def wrap_inbound_message(self, error_message, debundled_message):
        ''' Wrap an inbound message that had a serious error. '''

        self.log_message(error_message)

        body = error_message
        try:
            processed_message = debundled_message.crypto_message
            for tag in processed_message.get_tags():
                body += '\n{}'.format(tag)
        except:
            pass

        subject = i18n('{} - Unable to decrypt message'.format(TAG_ERROR))
        utils.bounce_message(self.in_message, self.recipient, subject, body)

    def drop_message(self, error_message):
        ''' Drop a message that we shouldn't process from a remote user. '''

        self.log_message(error_message)
        self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        record_exception()

        subject = i18n('{} - Unable to decrypt message'.format(TAG_ERROR))
        utils.drop_message(self.in_message, self.recipient, subject, error_message)

    def log_message(self, message):
        '''
            Record debugging messages.

            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> filter = Filter('edward@goodcrypto.local', ['chelsea@goodcrypto.local'], 'message')
            >>> filter.log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.filter.log'))
            True
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

