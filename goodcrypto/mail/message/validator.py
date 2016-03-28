'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-04-10

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from email.mime.multipart import MIMEMultipart
from StringIO import StringIO
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail.message.message_exception import MessageException


class Validator(object):
    '''  Validates an EmailMessage. '''

    DEBUGGING = False

    def __init__(self, email_message):
        ''' 
            Unparsable messages are wrapped in a valid message. 
            
            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> good_message = get_basic_email_message()
            >>> validator = Validator(good_message)
            >>> validator != None
            True
        '''

        self.log = LogFile()
        self.email_message = email_message
        self.why = None


    def is_message_valid(self):
        '''
             Returns true if the message is parsable, else false.
            
             If a MIME message is not parsable, you should still be able to process it.
             As we find different errors in messages, we should make sure this
             method catches them.

            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> good_message = get_basic_email_message()
            >>> validator = Validator(good_message)
            >>> validator.is_message_valid()
            True
        '''

        is_valid = False
        self.why = None

        if self.email_message is None:
            raise MessageException('Message is None')
        else:
            try:
                self.email_message.write_to(StringIO())
                if Validator.DEBUGGING:
                    self.log_message("message after check:\n{}".format(self.email_message.to_string()))

                self._check_content(self.email_message)
                is_valid = True
                
            except Exception:
                is_valid = False
                
                #  we explicitly want to catch everything here, even NPE
                self.log_message(format_exc())

        self.log_message('message is valid: {}'.format(is_valid))

        return is_valid


    def _check_content(self, part):
        '''
             Make sure we can read the content.
            
            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> good_message = get_basic_email_message()
            >>> validator = Validator(good_message)
            >>> validator._check_content(validator.email_message)
        '''

        content_type = part.get_header('Content-Type')
        self.log_message("MIME part content type: {}".format(content_type))
        content = part.get_content()
        if isinstance(content, MIMEMultipart):
            count = 0
            parts = content
            for sub_part in parts:
                self._check_content(sub_part)
                count += 1
            self.log_message('parts in message: {}'.format(count))
            if count != parts.getCount():
                self.why = "Unable to read all content. Reported: '{}', read: {}".format(
                    parts.getCount(), count)
                raise MessageException(self.why)


    def get_why(self):
        ''' 
            Gets why a message is invalid. Returns null if the message is valid. 

            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> good_message = get_basic_email_message()
            >>> validator = Validator(good_message)
            >>> validator.get_why() is None
            True
        '''

        return self.why

    def log_message(self, message):
        '''
            Log the message to the local log.
            
            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> good_message = get_basic_email_message()
            >>> validator = Validator(good_message)
            >>> validator.log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.validator.log'))
            True
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

