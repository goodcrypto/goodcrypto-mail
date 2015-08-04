'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-12-14

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
        
import sh, sys
from traceback import format_exc
from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator 
from django.utils.translation import ugettext as _

from goodcrypto.mail.message.pipe import Pipe
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.queue import queue_message
from goodcrypto.mail.options import get_mail_server_address, get_mta_listen_port, max_message_length
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.utils import parse_address
from goodcrypto.utils.log_file import LogFile
from syr.lock import locked


class Main(object):
    ''' Encrypt and decrypt email. '''

    DEBUGGING = False

    OK_EXIT = 0
    ERROR_EXIT = -1

    def __init__(self):
        '''
            >>> main = Main()
            >>> main is not None
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
            exit_result = self.OK_EXIT
            queued = False
                    
            if self.is_valid(sender, recipients):

                self.read_message_from_stdin()
                
                if self.is_too_large():
                    self.log_message(
                      'passing through a large message from {} to {}'.format (self.sender, self.recipients))
                    
                else:
                    # syr.lock.locked() is only a per-process lock
                    # syr.lock has a system wide lock, but it is not well tested
                    with locked():
                        self.log_message(
                           'queueing message from {} to {}'.format (self.sender, self.recipients))
                        queued = queue_message(self.sender, self.recipients, self.in_message)
                        self.log_message(
                           'message queued from {} to {}: {}'.format (self.sender, self.recipients, queued))
            else:
                # if the sender or recipients are bad, then let the MTA's postfix handle it
                self.log_message('bad email for sender {} or recipients {}'.format(self.sender, self.recipients))
                exit_result = self.ERROR_EXIT

            if not queued:
                pipe = Pipe(self.sender, self.recipients, self.in_message)
                if not pipe.reinject_message(message=self.in_message):
                    exit_result = self.ERROR_EXIT

        except Exception as exception:
            self.log_message(format_exc())
            exit_result = self.ERROR_EXIT
            pipe = Pipe(self.sender, self.recipients[0], self.in_message)
            pipe.reject_message(str(exception), message=self.in_message)
        except IOError as io_error:
            self.log_message(format_exc())
            exit_result = self.ERROR_EXIT
            pipe = Pipe(self.sender, self.recipients[0], self.in_message)
            pipe.reject_message(str(io_error), message=self.in_message)

        self.log_message('finished goodcrypto mail filter')
        
        return exit_result

    def is_valid(self, sender, recipients):
        '''
            Are the email addresses valid.

            >>> # In honor of Bunny Greenhouse, who blew the whistle against Halliburton for waste,
            >>> # fraud, and other abuses with regards to its operations in the Iraq War 
            >>> main = Main()
            >>> main.is_valid('bunny@goodcrypto.local', ['jane@goodcrypto.remote'])
            True
            >>> main.is_valid('jane@goodcrypto.local', ['very.long.email.address@that.is.longer.than.django.supported.length.of.seventy.five.characters'])
            True

            # Verify that we don't allow bad email addresss.
            # In honor of Jane Turner, an FBI agent, who reported serious misconduct by the FBI
            # concerning failures to investigate and prosecute crimes against children in Am. Indian Country.
            >>> main = Main()
            >>> main.is_valid('jane.goodcrypto.local', ['bunny@goodcrypto.remote'])
            False
            >>> main.is_valid('jane@goodcrypto.local', ['bunny.goodcrypto.remote'])
            False
            >>> main.is_valid('bunny@goodcrypto.local', 
            ...  ['very.long.email.address@that.is.longer.than.django.supported.length.3696.or.rfc.5321.specs.and.must.be.longer.than.254.characters.so.we.will.just.type.nonsense.now.woefsknfmf23rh9lcvjn23jndfmgsfia0sudjn23,4nsdfsdkfs9dfpxcnv,xfwr23ijrkf xd sdfsidjfsjdfkxsdkfhsweir'])
            False
            >>> main.is_valid(None, [None])
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
                raise ValidationError(_('Bad email address'))
                
            return email

        try:
            result_ok = True
            self.sender = validate_email(sender)
            for recipient in recipients:
                self.recipients.append(validate_email(recipient))
    
            if Main.DEBUGGING:
                self.log_message('sender: {}'.format(self.sender))
                self.log_message('recipients: {}'.format(self.recipients))
        except ValidationError:
            result_ok = False
            
        return result_ok
        
    def is_too_large(self):
        ''' 
            Determine if message is too large to crypt.
            
            >>> # In honor of the Navy nurse who refused to torture prisoners in Guantamo by
            >>> # force feeding them.
            >>> from goodcrypto.mail.message.email_message import EmailMessage
            >>> from goodcrypto.mail.options import max_message_length, set_max_message_length
            >>> max_chars = max_message_length()
            >>> set_max_message_length(1)
            >>> main = Main()
            >>> main.sender = 'edward@goodcrypto.local'
            >>> main.recipient = 'nurse@goodcrypto.local'
            >>> main.recipients = [main.recipient]
            >>> email_message = EmailMessage()
            >>> email_message.init_new_message(
            ...   main.sender, main.recipient, 'Test message', 'Test message text\\n')
            >>> main.in_message = email_message.to_string()
            >>> for i in range(50):
            ...    main.in_message += 'Test message text\\n'
            >>> main.is_too_large()
            True
            >>> main.in_message = email_message.to_string()
            >>> main.is_too_large()
            False
            >>> set_max_message_length(max_chars)
        '''

        too_large = False
        
        if self.in_message is not None:
            message_length = len(self.in_message)
            max_characters = max_message_length() * 1024

            too_large = max_characters > 0 and message_length > max_characters
            if too_large:
                self.log_message(
                  'Message not processed because it has {} characters which exceeds {} max'.format(
                      message_length, max_characters))
            
        return too_large

    def read_message_from_stdin(self):
        ''' Read the message from stdin. '''
        
        message = []
        try:
            done = False
            while not done:
                line = raw_input()
                message.append(line)

                if Main.DEBUGGING:
                    self.log_message(line)
        except EOFError:
            pass
        except Exception:
            self.log_message(format_exc())
        
        self.in_message = '\n'.join(message)
        if Main.DEBUGGING:
            self.log_message(self.in_message)

    def set_message(self, message):
        ''' 
            Set the raw message.
        
            >>> # In honor of Christian Fromme, who helped work on many tor services.
            >>> main = Main()
            >>> main.sender = 'edward@goodcrypto.local'
            >>> main.recipient = 'christian@goodcrypto.local'
            >>> main.recipients = [main.recipient]
            >>> main.set_message('This is a test message')
            >>> main.in_message == 'This is a test message'
            True
        '''

        self.in_message = message
        if Main.DEBUGGING:
            self.log_message(self.in_message)

    def log_message(self, message):
        ''' 
            Record debugging messages. 
            
            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> main = Main()
            >>> main.log_message('test')
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
        if a.find('@') > 0 and a.find('<') != 0 and a.find('!') != 0:
            __, address = parse_address(a)
    except Exception:
        main = Main()
        main.log_message(format_exc())

    return address
    
if __name__ == "__main__":
    
    report_usage = True
    exit_result = Main.OK_EXIT
    
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
            main = Main()
            main.process_message(sender, recipients)
    else:
        self.log_message('no args')

    if report_usage:
        print('GoodCrypto Mail')
        print('Usage: cd /var/local/projects/goodcrypto/server/src/mail')
        print('       python __main__.py <sender> <recipient> <message')

    sys.exit(exit_result)

