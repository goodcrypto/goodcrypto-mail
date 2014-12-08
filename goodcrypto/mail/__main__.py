'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
        
import sh, sys
from smtplib import SMTP
from traceback import format_exc
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator 

from goodcrypto.mail import international_strings 
from goodcrypto.mail.options import get_domain, get_mail_server_address, get_mta_listen_port
from goodcrypto.mail.message.crypto_message import CryptoMessage
from goodcrypto.mail.message.decrypt_filter import DecryptFilter
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.encrypt_filter import EncryptFilter
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.notices import notify_user
from goodcrypto.mail.models import LongEmailField
from goodcrypto.mail.options import max_message_length, get_domain
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.utils import parse_address
from goodcrypto.utils.log_file import LogFile


class CryptEmail(object):
    ''' Encrypt and decrypt email. '''

    DEBUGGING = False
    
    USE_SMTP_PROXY = False
    
    OK_EXIT = 0
    ERROR_EXIT = -1
    
    def __init__(self):
        '''
            >>> crypt_email = CryptEmail()
            >>> crypt_email is not None
            True
        '''
        self.log = None
        self.in_message = self.out_message = None
        self.sender = self.recipient = None
        self.recipients = []
    
    def process_message(self, sender, recipients):
        ''' Process a message from stdin. '''

        self.log_message('starting goodcrypto mail filter')
        try:
            exit_result = CryptEmail.OK_EXIT
            
            if crypt_email.is_valid(sender, recipients):
                crypt_email.read_message_from_stdin()
                
                # process 1 recipient at a time so we use the correct keys
                for recipient in recipients:
                    crypt_email.recipient = recipient
                    crypt_email.process()
                    if not crypt_email.reinject_message():
                        exit_result = CryptEmail.ERROR_EXIT
                    self.log_message(
                        'finished processing message for {} with result: {}'.format(recipient, exit_result))
            else:
                # if the sender or recipients are bad, then let the MTA's postfix handle it
                if not crypt_email.reinject_message():
                    exit_result = CryptEmail.ERROR_EXIT
                self.log_message('finished processing message with unvalidated email')
        except Exception as exception:
            self.log_message(format_exc())
            exit_result = CryptEmail.ERROR_EXIT
            crypt_email.reject_message(str(exception))
        except IOError as io_error:
            self.log_message(format_exc())
            exit_result = CryptEmail.ERROR_EXIT
            crypt_email.reject_message(str(io_error))

        self.log_message('finished goodcrypto mail filter')
        
        return exit_result

    def is_valid(self, sender, recipients):
        '''
            Are the email addresses valid.

            >>> # In honor of Bunny Greenhouse, who blew the whistle against Halliburton of for waste,
            >>> # fraud, and other abuses with regards to its operations in the Iraq War 
            >>> crypt_email = CryptEmail()
            >>> crypt_email.is_valid('bunny@goodcrypto.local', ['jane@goodcrypto.remote'])
            True
            >>> crypt_email.is_valid('jane@goodcrypto.local', ['very.long.email.address@that.is.longer.than.django.supported.length.of.seventy.five.characters'])
            True

            # Verify that we don't allow bad email addresss.
            # In honor of Jane Turner, an FBI agent, who reported serious misconduct by the FBI
            # concerning failures to  investigate and prosecute crimes against children in Am. Indian Country.
            >>> crypt_email = CryptEmail()
            >>> crypt_email.is_valid('jane.goodcrypto.local', ['bunny@goodcrypto.remote'])
            False
            >>> crypt_email.is_valid('jane@goodcrypto.local', ['bunny.goodcrypto.remote'])
            False
            >>> crypt_email.is_valid('bunny@goodcrypto.local', 
            ...  ['very.long.email.address@that.is.longer.than.django.supported.length.3696.or.rfc.5321.specs.and.must.be.longer.than.254.characters.so.we.will.just.type.nonsense.now.woefsknfmf23rh9lcvjn23jndfmgsfia0sudjn23,4nsdfsdkfs9dfpxcnv,xfwr23ijrkf xd sdfsidjfsjdfkxsdkfhsweir'])
            False
            >>> crypt_email.is_valid(None, [None])
            False
        '''
        def validate_email(email):
            try:
                if email is None:
                    raise ValidationError('Email address does not exist')
                email_validator = EmailValidator()
                email_validator(email)
            except ValidationError as validator_error:
                self.log_message(str(validator_error))
                raise ValidationError(international_strings.BAD_EMAIL_ADDRESS)
                
            return email

        try:
            result_ok = True
            self.sender = validate_email(sender)
            for recipient in recipients:
                self.recipients.append(validate_email(recipient))
    
            if CryptEmail.DEBUGGING:
                self.log_message('sender: {}'.format(self.sender))
                self.log_message('recipients: {}'.format(self.recipients))
        except ValidationError:
            result_ok = False
            
        return result_ok
        
    def read_message_from_stdin(self):
        ''' Read the message from stdin. '''
        
        message = []
        try:
            message_length = 0
            max_characters = max_message_length() * 1024
            
            done = False
            while not done:
                line = raw_input()
                message.append(line)

                if CryptEmail.DEBUGGING:
                    self.log_message(line)
                
                message_length += len(line)
                if max_characters > 0 and message_length > max_characters:
                    done = True
                    self.log_message(
                      'Message rejected because it exceeded {} characters'.format(max_characters))
                    if len(message) > 11:
                        msg = '\n'.join(message[:11])[:200]
                    else:
                        msg = '\n'.join(message)[:200]
                    self.log_message('========\n{}\n======='.format(msg))
                    raise MessageException(
                        international_strings.MESSAGE_EXCEEDED_LIMIT.format(max_characters))
        except MessageException as message_exception:
            raise MessageException(message_exception.value)
        except EOFError:
            pass
        except Exception:
            self.log_message(format_exc())
        
        self.in_message = '\n'.join(message)
        if CryptEmail.DEBUGGING:
            self.log_message(self.in_message)

    def set_message(self, raw_message):
        ''' Set the raw message. '''

        message = []
        try:
            message_length = len(raw_message)
            max_characters = max_message_length() * 1024
            if max_characters > 0 and message_length > max_characters:
                self.log_message(
                  'Message rejected because it exceeded {} characters'.format(max_characters))
                if len(raw_message) > 11:
                    msg = '\n'.join(raw_message[:11])[:200]
                else:
                    msg = '\n'.join(raw_message)[:200]
                self.log_message('========\n{}\n======='.format(msg))
                raise MessageException(international_strings.MESSAGE_EXCEEDED_LIMIT.format(max_characters))
            else:
                message = raw_message.split('\n')
                if CryptEmail.DEBUGGING:
                    self.log_message(message)
        except MessageException as message_exception:
            raise MessageException(message_exception.value)
        except EOFError:
            pass
        except Exception:
            self.log_message(format_exc())
        
        self.in_message = '\n'.join(message)
        if CryptEmail.DEBUGGING:
            self.log_message(self.in_message)

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
                    notify_user(self.sender, international_strings.BOUNCED_ENCRYPTED_SUBJECT, message)
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
                    notify_user(self.recipient, international_strings.BOUNCED_DECRYPTED_SUBJECT, message)
            except:
                self.log_message(format_exc())


        self.out_message = self.in_message

        # pass through local message if we're not using an SMTP proxy
        if self.is_local_message() and not CryptEmail.USE_SMTP_PROXY:
            self.out_message = self.in_message
            self.log_message(
              'passing through local message from {} to {}'.format (self.sender, self.recipient))

        elif self._possibly_needs_encryption():
            try:
                encrypt_filter = EncryptFilter()
                crypto_message = CryptoMessage(EmailMessage(self.in_message))
                filtered, crypted = encrypt_filter.crypt_from_to(
                   crypto_message, self.sender, self.recipient)
                self.out_message = crypto_message.get_email_message().to_string()
                self.log_message('final status: filtered: {} crypted: {}'.format(filtered, crypted))
                if CryptEmail.DEBUGGING:
                    self.log_message('\n==================\n')
                    self.log_message(crypto_message.get_email_message().to_string())
                    self.log_message('\n==================\n')
            except MessageException as message_exception:
                bounce_message(message_exception.value)
                self.out_message = None
            except Exception as exception:
                bounce_message(exception.value)
                self.out_message = None
            except IOError as ioerror:
                bounce_message(ioerror.value)
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

    def get_processed_message(self):
        ''' 
            Get the message after it has been processed.
        '''
        return self.out_message

    def reinject_message(self):
        ''' Re-inject message back into queue. '''
        try:
            if self.out_message is None:
                # set to result_ok to True because we've already bounced the message or 
                # there isn't anything to bounce because it failed validation
                result_ok = True
                self.log_message('rejecting message')
            else:
                self.log_message('starting to re-inject message into postfix queue')
                if CryptEmail.USE_SMTP_PROXY:
                    server = SMTP(get_mail_server_address(), get_mta_listen_port())
                    #server.set_debuglevel(1)
                    server.sendmail(self.sender, self.recipient, self.out_message)
                    server.quit()
                else:
                    sendmail = sh.Command('/usr/sbin/sendmail')
                    sendmail('-B', '8BITMIME', '-f', self.sender, self.recipient, _in=self.out_message)
                
                if CryptEmail.DEBUGGING:
                    self.log_message('\n==================\n')
                    self.log_message(self.out_message)
                    self.log_message('\n==================\n')
    
                result_ok = True
                self.log_message('finished re-injecting message into postfix queue')
        except Exception as exception:
            result_ok = False
            self.log_message('error while re-injecting message into postfix queue')
            self.log_message(format_exc())
            self.reject_message(exception.value)
            
        return result_ok

    def _possibly_needs_encryption(self):
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
            >>> crypt_email = CryptEmail()
            >>> crypt_email.is_valid('edward@goodcrypto.local', ['frederic@goodcrypto.remote'])
            True
            >>> crypt_email.recipient = 'frederic@goodcrypto.remote'
            >>> crypt_email._possibly_needs_encryption()
            True
            >>> crypt_email = CryptEmail()
            >>> crypt_email.is_valid('edward@goodcrypto.local', ['chelsea@goodcrypto.remote'])
            True
            >>> crypt_email.recipient = 'chelsea@goodcrypto.remote'
            >>> crypt_email._possibly_needs_encryption()
            True
            >>> set_domain('GOODCRYPTO.LOCAL')
            >>> crypt_email = CryptEmail()
            >>> crypt_email.is_valid('frederic@GoodCrypto.Local', ['jesselyn@goodcrypto.remote'])
            True
            >>> crypt_email.recipient = 'jesselyn@goodcrypto.remote'
            >>> crypt_email._possibly_needs_encryption()
            True
            >>> set_domain('GoodCrypto.Local')
            >>> crypt_email = CryptEmail()
            >>> crypt_email.is_valid('frederic@goodcrypto.remote', ['edward@goodcrypto.local'])
            True
            >>> crypt_email.recipient = 'edward@goodcrypto.local'
            >>> crypt_email._possibly_needs_encryption()
            False
            >>> set_domain('GoodCrypto.Local')
            >>> crypt_email = CryptEmail()
            >>> crypt_email.sender = 'not an email address'
            >>> crypt_email.recipient = 'edward@goodcrypto.local'
            >>> crypt_email._possibly_needs_encryption()
            False
            >>> set_domain(domain)
        '''

        maybe_needs_encryption = email_in_domain(self.sender)
                
        self.log_message('possibly needs encryption: {}'.format(maybe_needs_encryption))
            
        return maybe_needs_encryption

    def is_local_message(self):
        ''' 
            Determine if the message is local. 
            
            >>> # In honor of Jonathan Fishbein, who is one of the highest ranking 
            >>> # drug whistleblowers in American history 
            >>> from goodcrypto.mail.options import get_domain, set_domain
            >>> domain = get_domain()
            >>> set_domain('goodcrypto.local')
            >>> crypt_email = CryptEmail()
            >>> crypt_email.is_valid('edward@goodcrypto.local', ['chelsea@goodcrypto.local'])
            True
            >>> crypt_email.recipient = 'chelsea@goodcrypto.local'
            >>> crypt_email.is_local_message()
            True
            >>> crypt_email = CryptEmail()
            >>> crypt_email.is_valid('edward@goodcrypto.local', ['jonathan@goodcrypto.remote'])
            True
            >>> crypt_email.recipient = 'jonathan@goodcrypto.remote'
            >>> crypt_email.is_local_message()
            False
            >>> set_domain(domain)
        '''
        
        return email_in_domain(self.sender) and email_in_domain(self.recipient)

    def reject_message(self, error_message):
        ''' 
            Reject a message that had an unexpected error. 
            
            >>> crypt_email = CryptEmail()
            >>> crypt_email.sender = 'root'
            >>> crypt_email.sender = 'root'
            >>> crypt_email.in_message = 'bad message'
            >>> crypt_email.reject_message('Unknown message')
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
            self.log_message('sysadmin: {}'.format(sysadmin_email))

            return sysadmin_email

        try:
            if email_in_domain(self.sender):
                to_address = self.sender
                subject = international_strings.UNABLE_TO_SEND_MESSAGE
            elif email_in_domain(self.recipient):
                to_address = self.recipient
                subject = international_strings.UNABLE_TO_RECEIVE_MESSAGE
            else:
                to_address = get_sysadmin_email()
                subject = international_strings.MESSAGE_REJECTED
            
            message = '{}'.format(error_message)
            if self.in_message is not None:
                message += '\n\n===================\n{}'.format(self.in_message)
            self.log_message('send notice to {} about {}'.format(to_address, error_message))
            notify_user(to_address, subject, message)
        except:
            self.log_message(format_exc())

    def log_message(self, message):
        ''' 
            Record debugging messages. 
            
            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> crypt_email = CryptEmail()
            >>> crypt_email.log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.log'))
            True
        '''

        if self.log is None:
            self.log = LogFile('goodcrypto.mail.log')

        self.log.write(message)

def get_address(argv):
    ''' 
        Get the address from the argument. 
        
        >>> # In honor of First Sergeant T, who publicly denounced and refused to serve in 
        >>> # operations involving the occupied Palestinian territories because of the 
        >>> # widespread surveillance of innocent residents.
        >>> get_address('{t@goodcrypto.local}')
        't@goodcrypto.local'
        >>> get_address('this is a test') is None
        True
        >>> get_address('<t@goodcrypto.local') is None
        True
    '''

    address = None
    try:
        a = argv.strip('{').strip('}')
        # make sure there aren't any system directives
        if a.find('@') > 0 and a.find('<') < 0 and a.find('!') < 0:
            _, address = parse_address(a)
    except Exception:
        crypt_email = CryptEmail()
        crypt_email.log_message(format_exc())

    return address
    
if __name__ == "__main__":
    
    report_usage = True
    exit_result = CryptEmail.OK_EXIT
    
    if sys.argv:
        argv = sys.argv
        if len(argv) >= 3:
            report_usage = False
            
            sender = get_address(argv[1].strip('{').strip('}'))
            recipients = []

            # get all the recipients
            i = 2
            while i < len(argv):
                recipients.append(get_address(argv[i]))
                i += 1

            # ignore the final result because we always want to 
            # return a good exit code so postfix doesn't bounce a
            # message and reveal too much info about any errors;
            # we send email to an internal user whenever appropriate
            crypt_email = CryptEmail()
            crypt_email.process_message(sender, recipients)
    else:
        self.log_message('no args')

    if report_usage:
        print('GoodCrypto Mail')
        print('Usage: cd /var/local/projects/goodcrypto/server/src/mail')
        print('       python __main__.py <sender> <recipient> <message')

    sys.exit(exit_result)

