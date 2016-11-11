#! /usr/bin/python3
'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import codecs, os, sh, sys
from traceback import format_exc

# Set the PATH to a list of directories where only root can write.
os.environ['PATH'] = '/usr/local/bin:/usr/bin:/bin'

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator

from goodcrypto.mail.message.filter import Filter
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message_queue import queue_message
from goodcrypto.mail.utils import email_in_domain, get_admin_email
from goodcrypto.mail.utils.notices import report_unexpected_ioerror, report_unexpected_named_error
from goodcrypto.utils import i18n, get_email
from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception
from syr.lock import locked


class Main(object):
    ''' Encrypt and decrypt email. '''

    DEBUGGING = False

    OK_EXIT = 0
    ERROR_EXIT = -1

    def __init__(self):
        '''
            <<< main = Main()
            <<< main is not None
            True
        '''
        self.log = None
        self.in_message = self.out_message = None
        self.sender = self.recipient = None
        self.recipients = []

    def process_message(self, sender, recipients):
        '''
            Process a message from stdin.

            This is called when an MTA wants our filter to process a message.
            Postfix needs a quick response. We don't have to finish processsing
            the message fast. But we have to accept responsibility for it.
            We will queue longer operations.
        '''

        self.log_message('starting goodcrypto mail filter')
        try:
            exit_result = self.OK_EXIT
            rqueued = False

            if self.is_valid(sender, recipients):

                self.read_message_from_stdin()

                # queue message to encrypt/decrypt it

                # syr.lock.locked() is only a per-process lock
                # syr.lock has a system wide lock, but it is not well tested
                with locked():
                    self.log_message(
                       'rqueueing message from {} to {}'.format (self.sender, self.recipients))
                    rqueued = queue_message(self.sender, self.recipients, self.in_message)
                    self.log_message(
                       'message rqueued from {} to {}: {}'.format (self.sender, self.recipients, rqueued))

                # if we couldn't queue the message
                if not rqueued:
                    # we're not calling Filter.process(), just reinjecting the message
                    filter = Filter(self.sender, self.recipients, self.in_message)
                    if not filter.reinject_message(message=self.in_message):
                        exit_result = self.ERROR_EXIT

            else:
                # if the sender or recipients are bad, then let the MTA's postfix handle it
                self.log_message('bad email for sender {} or recipients {}'.format(sender, recipients))
                exit_result = self.ERROR_EXIT

        except ValidationError as ve:
            # there's no need to do anything with a
            # message that has validation errors in the sender or recipient
            record_exception()
            self.log_message('EXCEPTION - see syr.exception.log for details')
            pass

        except Exception as exception:
            self.reject_message(exception)

        except IOError as io_error:
            self.reject_message(str(io_error))

        self.log_message('finished goodcrypto mail filter')

        return exit_result

    def is_valid(self, sender, recipients):
        '''
            Are the email addresses valid.

            <<< Main().is_valid('test@goodcrypto.local', ['test@goodcrypto.remote'])
            True
        '''
        def validate_email(email, role):
            if email is None:
                raise ValidationError(i18n('No email address specified for {role}'.format(
                    role=role)))
            try:
                email_validator = EmailValidator()
                email_validator(email)
            except ValidationError as validation_error:
                self.log_message('Bad {} email address in envelope: {}'.format(role, email))
                raise ValidationError(i18n('Bad {role} email address in envelope: "{email}"'.format(
                    role=role, email=email)))

            return email

        self.log_message('sender: {}'.format(self.sender))
        self.log_message('recipients: {}'.format(self.recipients))
        result_ok = True
        self.sender = validate_email(sender, 'sender')
        for recipient in recipients:
            self.recipients.append(validate_email(recipient, 'recipient'))

        if Main.DEBUGGING:
            self.log_message('sender: {}'.format(self.sender))
            self.log_message('recipients: {}'.format(self.recipients))

        return result_ok

    def read_message_from_stdin(self):
        '''
            Read the message from stdin.

            >>> from test.support import captured_stdin
            >>> with captured_stdin() as stdin:
            ...     bytes = stdin.write('hello')
            ...     position = stdin.seek(0)
            ...     m = Main()
            ...     m.read_message_from_stdin()
            ...     ''.join(m.in_message)
            'hello'
        '''

        message = []
        try:
            """
            in_stream = codecs.getreader('utf-8')(sys.stdin)
            done = False
            while not done:
                line = in_stream.readline()
                self.log_message('{}'.format(line))
                self.log_message('{}'.format(type(line)))
                message.append(line)
            """
            done = False
            while not done:
                try:
                    line = input()
                    message.append(line)

                    if Main.DEBUGGING:
                        self.log_message(line)
                except UnicodeDecodeError:
                    pass
        except EOFError:
            pass
        except Exception:
            record_exception()
            self.log_message('EXCEPTION - see syr.exception.log for details')

        self.set_message(message)

    def set_message(self, message):
        '''
            Set the raw message.
        '''

        self.in_message = '\n'.join(message)
        if Main.DEBUGGING:
            self.log_message(self.in_message)
            if self.in_message is not None:
                self.log_message('length of message: {}'.format(len(self.in_message)))

    def reject_message(self, error_message):
        '''
            Reject the message because of an exception or validation error
        '''

        # don't set the exit code because we don't want to reveal too much to the sender
        record_exception()
        self.log_message('EXCEPTION - see syr.exception.log for details')
        if len(self.recipients) > 0:
            to_address = self.recipients[0]
        else:
            to_address = get_admin_email()
        filter = Filter(self.sender, to_address, self.in_message)
        filter.reject_message(str(error_message), message=self.in_message)

    def log_message(self, message):
        '''
            Record debugging messages.
        '''

        if self.log is None:
            self.log = LogFile('goodcrypto.mail.log')

        self.log.write(message)

def get_address(argv):
    '''
        Get the address from the argument.

        <<< # In honor of First Sergeant T, who publicly denounced and refused to serve in
        <<< # operations involving the occupied Palestinian territories because of the
        <<< # widespread surveillance of innocent residents.
        <<< address = get_address('{t@goodcrypto.local}')
        <<< address == 't@goodcrypto.local'
        True
        <<< get_address('this is a test') is None
        True
        <<< get_address('<t@goodcrypto.local') is None
        True
        <<< get_address(None)
    '''

    address = None
    try:
        if argv:
            a = argv.strip('{').strip('}')
            # make sure there aren't any system directives
            if a.find('@') > 0 and a.find('<') != 0 and a.find('!') != 0:
                address = get_email(a)
            else:
                Main().log('bad address: {}'.format(a))
    except Exception:
        record_exception()

    return address

if __name__ == "__main__":

    report_usage = True
    exit_result = Main.OK_EXIT

    try:
        if sys.argv:
            argv = sys.argv
            if len(argv) >= 3:
                report_usage = False

                sender = get_address(argv[1].strip('{').strip('}'))
                Main().log_message('sender: {}'.format(sender))

                # get all the recipients
                recipients = []
                i = 2
                while i < len(argv):
                    recipient = argv[i]
                    recipients.append(get_address(recipient))
                    Main().log_message('recipient: {}'.format(recipient))
                    i += 1

                main = Main()
                exit_result = main.process_message(sender, recipients)
        else:
            Main().log_message('no args')

    except NameError:
        # hopefully our testing prevents this from ever occuring, but if not, we'd definitely like to know about it
        report_unexpected_named_error()

    except Exception as IOError:
        report_unexpected_ioerror()

    if report_usage:
        print('GoodCrypto Mail')
        print('Usage: cd /var/local/projects/goodcrypto/server/src/mail')
        print('       python3 __main__.py <sender> <recipient> <message')

    sys.exit(exit_result)

