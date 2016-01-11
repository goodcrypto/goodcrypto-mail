'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-02-16

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
        
import sh
from smtplib import SMTP
from traceback import format_exc
from django.contrib.auth.models import User

from goodcrypto.mail.message.crypto_message import CryptoMessage
from goodcrypto.mail.message.decrypt_filter import DecryptFilter
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.encrypt_filter import EncryptFilter
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.notices import notify_user
from goodcrypto.mail.options import get_domain, get_mail_server_address, get_mta_listen_port
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.utils import i18n
from goodcrypto.utils.log_file import LogFile
from syr.lock import locked


class Pipe(object):
    ''' Pipe a message through the encrypt or decrypt filter as needed. '''

    DEBUGGING = False
    
    USE_SMTP_PROXY = False
    
    def __init__(self, from_user, to_user, message):
        '''
            >>> # In honor of John Kiriakou, who went to prison for exposing CIA torture.
            >>> # In honor of asn, developer of Obfsproxy.
            >>> pipe = Pipe('john@goodcrypto.local', 'asn@goodcypto.remote', 'message')
            >>> pipe is not None
            True
        '''
        self.log = self.out_message = None
        
        self.sender = from_user
        self.recipient = to_user
        self.in_message = message
        
    def process(self):
        ''' Process the message. '''

        def bounce_message(error_message):
            ''' Bounce a message that a local user originated. '''

            self.log_message(error_message)
            self.log_message(format_exc())
            try:
                if self.sender is None:
                    self.log_message('unable to bounce message without a sender')
                else:
                    message = '{}\n\n===================\n{}'.format(
                      error_message, self.in_message)
                    notify_user(self.sender, i18n('Undelivered Mail: Unable to encrypt message'), message)
                    self.log_message('sent note to {} about error.'.format(self.sender))
            except:
                self.log_message(format_exc())

        def drop_message(error_message):
            ''' Drop a message that we shouldn't process from a remote user. '''

            self.log_message(error_message)
            self.log_message(format_exc())
            try:
                if self.recipient is None:
                    self.log_message('unable to notify recipient about dropped message')
                else:
                    message = '{}\n\n===================\n{}'.format(
                      error_message, self.in_message)
                    notify_user(self.recipient, i18n('Error: Unable to decrypt message'), message)
            except:
                self.log_message(format_exc())


        self.log_message('=== starting to filter mail from {} to {} ==='.format(self.sender, self.recipient))

        self.out_message = self.in_message

        # pass through local message if we're not using an SMTP proxy
        if self.possibly_needs_encryption():
            try:
                encrypt_filter = EncryptFilter()
                crypto_message = CryptoMessage(EmailMessage(self.in_message))
                filtered, crypted = encrypt_filter.crypt_from_to(
                   crypto_message, self.sender, self.recipient)
                self.out_message = crypto_message.get_email_message().to_string()
                self.log_message('final status: filtered: {} crypted: {}'.format(filtered, crypted))
                if self.DEBUGGING:
                    self.log_message('\n==================\n')
                    self.log_message(crypto_message.get_email_message().to_string())
                    self.log_message('\n==================\n')
            except MessageException as message_exception:
                bounce_message(message_exception.value)
                self.out_message = None
            except Exception as exception:
                self.log_message(format_exc())
                self.log_message(exception)
                try:
                    bounce_message(exception.value)
                except:
                    bounce_message(exception)
                self.out_message = None
            except IOError as ioerror:
                try:
                    bounce_message(ioerror.value)
                except:
                    bounce_message(ioerror)
                self.out_message = None
        else:
            try:
                decrypt_filter = DecryptFilter()
                crypto_message = CryptoMessage(EmailMessage(self.in_message))
                filtered, crypted = decrypt_filter.crypt_from(
                   crypto_message, self.sender, self.recipient)

                if crypto_message.is_dropped():
                    self.out_message = None
                    self.log_message('message dropped')
                else:
                    self.out_message = crypto_message.get_email_message().to_string()
                    self.log_message('final status: filtered: {} crypted: {}'.format(filtered, crypted))
            except MessageException as message_exception:
                drop_message(message_exception.value)
                self.out_message = None
            except Exception as exception:
                drop_message(exception.value)
                self.out_message = None
            except IOError as ioerror:
                drop_message(ioerror.value)
                self.out_message = None

        result_code = self.reinject_message()
        
        self.log_message('mail filtered ok: {}'.format(result_code))
        self.log_message('=== finished filtering mail from {} to {} ==='.format(self.sender, self.recipient))

        return result_code

    def possibly_needs_encryption(self):
        ''' 
            Determine if the message might need to be encrypted or not.
            
            It could need encrytion if the sender has the same domain as 
            the domain defined in goodcrypto mail's options. If we're not using
            an SMTP proxy, then it never needs encryption if the message is going
            to and from a user with the domain defined in goodcrypto mail's options.
            
            >>> # In honor of Frederic Whitehurst, won the first whistleblowing case against the FBI.
            >>> from goodcrypto.mail.options import get_domain, set_domain
            >>> domain = get_domain()
            >>> set_domain('goodcrypto.local')
            >>> pipe = Pipe('edward@goodcrypto.local', ['frederic@goodcrypto.remote'], 'message')
            >>> pipe.possibly_needs_encryption()
            True
            >>> pipe = Pipe('edward@goodcrypto.local', ['chelsea@goodcrypto.remote'], 'message')
            >>> pipe.possibly_needs_encryption()
            True
            >>> set_domain('GOODCRYPTO.LOCAL')
            >>> pipe = Pipe('edward@goodcrypto.local', ['jesselyn@goodcrypto.remote'], 'message')
            >>> pipe.possibly_needs_encryption()
            True
            >>> set_domain('GoodCrypto.Local')
            >>> pipe = Pipe('edward@goodcrypto.local', ['jesselyn@goodcrypto.remote'], 'message')
            >>> pipe.possibly_needs_encryption()
            True
            >>> pipe = Pipe('frederic@goodcrypto.remote', ['edward@goodcrypto.local'], 'message')
            >>> pipe.recipient = 'edward@goodcrypto.local'
            >>> pipe.possibly_needs_encryption()
            False
            >>> set_domain('GoodCrypto.Local')
            >>> pipe = Pipe('edward@goodcrypto.local', ['frederic@goodcrypto.remote'], 'message')
            >>> pipe.sender = 'not an email address'
            >>> pipe.recipient = 'edward@goodcrypto.local'
            >>> pipe.possibly_needs_encryption()
            False
            >>> set_domain(domain)
        '''

        maybe_needs_encryption = email_in_domain(self.sender)
                
        self.log_message('possibly needs encryption: {}'.format(maybe_needs_encryption))
            
        return maybe_needs_encryption

    def get_processed_message(self):
        ''' 
            Get the message after it has been processed.
            
            >>> pipe = Pipe('root', 'root', 'bad message')
            >>> pipe.get_processed_message()
        '''
        return self.out_message

    def reinject_message(self, message=None):
        ''' Re-inject message back into queue. '''

        if message is None:
            message = self.out_message
            
        # syr.lock.locked() is only a per-process lock
        # syr.lock has a system wide lock, but it is not well tested
        with locked():
            try:
                if message is None:
                    # set to result_ok to True because we've already bounced the message or 
                    # there isn't anything to bounce because it failed validation
                    result_ok = True
                    self.log_message('nothing to reinject')
                else:
                    self.log_message('starting to re-inject message into postfix queue')
                    if self.USE_SMTP_PROXY:
                        server = SMTP(get_mail_server_address(), get_mta_listen_port())
                        #server.set_debuglevel(1)
                        server.sendmail(self.sender, self.recipient, message)
                        server.quit()
                    else:
                        sendmail = sh.Command('/usr/sbin/sendmail')
                        sendmail('-B', '8BITMIME', '-f', self.sender, self.recipient, _in=message)
                    
                    if self.DEBUGGING:
                        self.log_message('\n==================\n')
                        self.log_message(message)
                        self.log_message('\n==================\n')
        
                    result_ok = True
                    self.log_message('finished re-injecting message into postfix queue')
            except Exception as exception:
                result_ok = False
                self.log_message('error while re-injecting message into postfix queue')
                self.log_message(format_exc())
                try:
                    error_message = exception.value
                    to_address = self.reject_message(error_message)
                    self.log_message('sent notice to {} about {}'.format(to_address, error_message))
                except:
                    self.log_message(format_exc())

        return result_ok

    def reject_message(self, error_message, message=None):
        ''' 
            Reject a message that had an unexpected error. 
            
            >>> # This message will fail if testing on dev system
            >>> pipe = Pipe('root', 'root', 'bad message')
            >>> pipe.reject_message('Unknown message')
            u'support@goodcrypto.local'
        '''
        def get_sysadmin_email():
            ''' Get the sysadmin's email.  '''
            
            sysadmin_email = None
            try:
                users = User.objects.filter(is_superuser=True)
                if users and len(users) > 0:
                    for user in users:
                        email = user.email
                        if email is not None and len(email.strip()) > 0:
                            sysadmin_email = email
                            break
            except:
                self.log_message(format_exc())

            if sysadmin_email is None:
                sysadmin_email = 'daemon@{}'.format(get_domain())

            return sysadmin_email

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
                to_address = get_sysadmin_email()
                subject = i18n('Message rejected.')
            
            notice = '{}'.format(error_message)
            if message is not None:
                notice += '\n\n===================\n{}'.format(message)
            notify_user(to_address, subject, notice)
        except:
            raise
            
        return to_address

    def log_message(self, message):
        ''' 
            Record debugging messages. 
            
            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> pipe = Pipe('edward@goodcrypto.local', ['chelsea@goodcrypto.local'], 'message')
            >>> pipe.log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.pipe.log'))
            True
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

