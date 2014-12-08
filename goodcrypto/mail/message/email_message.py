'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-15

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import os
from copy import deepcopy
from email.encoders import encode_base64
from email.generator import Generator
from email.message import Message
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.nonmultipart import MIMENonMultipart
from email.mime.text import MIMEText
from email.parser import Parser
from StringIO import StringIO
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail.international_strings import REMOVED_BAD_HEADER_LINES
from goodcrypto.mail.message import constants, mime_constants
from goodcrypto.mail.message.validator import Validator
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.utils.exception_log import ExceptionLog


class EmailMessage(object):
    '''
        Email Message.

        Messages should be converted to EmailMessage as soon as possible,
        to check whether the message is parsable as part of validating input.

        If a MIME message is not parsable, a new Message will be created that does conform 
        and contains the original unparsable message in the body.
    '''

    DEBUGGING = False
    DEFAULT_CHAR_SET = 'UTF-8'
    
    _last_charset = DEFAULT_CHAR_SET
    _log = None
    _message = None

    def __init__(self, message_or_file=None):
        '''
             Creates an EmailMessage from a Message or a file.
             Non-mime messages are converted to MIME "text/plain".
            
             >>> email_message = EmailMessage()
             >>> type(email_message)
             <class 'goodcrypto.mail.message.email_message.EmailMessage'>
        '''

        self.bad_header_lines = []

        if message_or_file is None:
            EmailMessage._message = Message()

        elif isinstance(message_or_file, Message):
            EmailMessage._message = message_or_file

        elif isinstance(message_or_file, EmailMessage):
            EmailMessage._message = message_or_file.get_message()

        else:
            self.parser = Parser()
            
            try:
                if isinstance(message_or_file, file) or isinstance(message_or_file, StringIO):
                    EmailMessage.log_message('about to parse a message from a file')
                    EmailMessage._message = self.parser.parse(message_or_file)
                    EmailMessage.log_message('parsed message')
                    if self.DEBUGGING:
                        EmailMessage.log_message('{}'.format(self.to_string()))
                else:
                    EmailMessage.log_message('about to parse a message from a string')
                    EmailMessage._message = self.parser.parsestr(message_or_file)
                    EmailMessage.log_message('parsed message')
                    if self.DEBUGGING:
                        EmailMessage.log_message('{}'.format(self.to_string()))
                
                if not self.validate_message():
                    self._create_good_message_from_bad(message_or_file)
            except Exception:
                try:
                    EmailMessage.log_message(format_exc())
                    
                    self._create_good_message_from_bad(message_or_file)
                    
                    # if we still don't have a good message, then blow up
                    if not self.validate_message():
                        EmailMessage.log_message('unable to create a valid message')
                        raise MessageException()
                except Exception:
                    EmailMessage.log_message(format_exc())
                    
        if EmailMessage.DEBUGGING:
            try:
                EmailMessage.log_message(self.to_string())
            except:
                pass


    def get_header(self, key):
        ''' 
            Get a header from an existing message. 
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     email_message.get_header('X-OpenPGP-Accepts')
            'GPG'
        '''
        
        try:
            value = self.get_message().__getitem__(key)
        except Exception:
            value = None
             
        return value


    def add_header(self, key, value):
        ''' 
            Add a header to an existing message. 
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> with open(get_plain_message_name('basic.txt')) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     email_message.add_header('X-OpenPGP-Accepts', 'GPG')
            ...     email_message.get_header('X-OpenPGP-Accepts')
            'GPG'
        '''

        EmailMessage._message.__setitem__(key, value)


    def change_header(self, key, value):
        ''' 
            Change a header to an existing message. 
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('bouncy-castle.txt')) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     email_message.change_header('X-OpenPGP-Accepts', 'TestGPG')
            ...     email_message.get_header('X-OpenPGP-Accepts')
            'TestGPG'
        '''

        if EmailMessage._message.__contains__(key):
            self.delete_header(key)

        self.add_header(key, value)


    def delete_header(self, key):
        ''' 
            Delete a header to an existing message.
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('bouncy-castle.txt')) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     email_message.delete_header('X-OpenPGP-Accepts')
            ...     email_message.get_header('X-OpenPGP-Accepts') is None
            True
        '''
        
        EmailMessage._message.__delitem__(key)


    def get_message(self):
        ''' 
            Get the message.
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_basic_email_message
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER
            >>> email_message = get_basic_email_message()
            >>> email_message.get_message() is not None
            True
            >>> email_message.get_message().get(mime_constants.FROM_KEYWORD) == EDWARD_LOCAL_USER
            True
        '''

        return EmailMessage._message


    def set_message(self, new_message):
        '''
            Set the new message.
            
            # Get a basic message first so we can avoid recursion
            >>> from goodcrypto_tests.mail.mail_test_utils import get_basic_email_message
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER
            >>> basic_email_message = get_basic_email_message().get_message()
            >>> email_message = EmailMessage()
            >>> email_message.get_message().get(mime_constants.FROM_KEYWORD) is None
            True
            >>> email_message.set_message(basic_email_message)
            >>> email_message.get_message().get(mime_constants.FROM_KEYWORD) == EDWARD_LOCAL_USER
            True
        '''

        old_message = EmailMessage._message
        EmailMessage._message = new_message
        
        # restore the old message if the new one isn't valid.
        if not self.validate_message():
            EmailMessage._message = old_message
            EmailMessage.log_message('restored previous message')

    def validate_message(self):
        '''
            Validate a message.
            
            Python's parser frequently accepts a message that has garbage in the header by
            simply adding all header items after the bad header line(s) to the body text;
            this can leave a pretty unmanageable message so we apply our own validation
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_basic_email_message
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER
            >>> email_message = get_basic_email_message()
            >>> email_message.validate_message()
            True
        '''
        try:
            validator = Validator(self)
            if validator.is_message_valid():
                valid = True
                EmailMessage.log_message('message is valid')
            else:
                valid = False
                EmailMessage.log_message('message is invalid')
                EmailMessage.log_message(validator.get_why())
        except Exception, AttributeError:
            valid = False
            EmailMessage.log_message(format_exc())
            
        return valid

    def get_text(self):
        '''
            Gets text from the current Message.
            
            This method works with both plain and MIME messages, except open pgp mime..
            If the message is MIMEMultipart, the text is from the first text/plain part.
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_basic_email_message
            >>> email_message = get_basic_email_message()
            >>> email_message.get_text()
            'Test message text'
        '''

        text = None
        message = self.get_message()

        if EmailMessage.is_open_pgp_mime(message):
            EmailMessage.log_message("unable to get text from openpgp mime message")

        else:
            if message.is_multipart():
                EmailMessage.log_message("message is a MIMEMultipart")

                #  get the first text/plain part
                result_ok = False
                part_index = 0
                parts = message.get_payload()
                while part_index < len(parts) and not result_ok:
                    part = message.get_payload(part_index)
                    content_type = part.get_content_type()
                    if content_type == mime_constants.TEXT_PLAIN_TYPE:
                        text = part.get_payload(decode=True)
                        EmailMessage._last_charset = EmailMessage.get_charset(part)
                        result_ok = True
                    else:
                        EmailMessage.log_message("body part type is " + content_type)
                    part_index += 1
            else:
                text = message.get_payload(decode=True)
                EmailMessage.log_message("content is a String")
                EmailMessage._last_charset = EmailMessage.get_charset(message)

        return text


    def set_text(self, text):
        '''
            Sets text in the current Message.
            
            This method works with both plain and MIME messages, except open pgp mime.
            If the message is MIMEMultipart, the text is set in the first text/plain part.
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_basic_email_message
            >>> email_message = get_basic_email_message()
            >>> email_message.set_text('New test message text')
            True
            >>> email_message.get_text()
            'New test message text'
        '''

        if self.DEBUGGING:
            EmailMessage.log_message("setting text:\n{}".format(text))
        
        text_set = False
        message = self.get_message()
        if EmailMessage.is_open_pgp_mime(message):
            EmailMessage.log_message("unable to set text from openpgp mime message")

        else:
            if message.is_multipart():
                #  set the first text/plain part
                EmailMessage.log_message('setting the first text/plain part')
                text_set = False
                part_index = 0
                parts = self.get_message().get_payload()
                while part_index < len(parts) and not text_set:
                    part = message.get_payload(part_index)
                    content_type = part.get_content_type()
                    if content_type == mime_constants.TEXT_PLAIN_TYPE:
                        part.set_payload(text)
                        text_set = True
                    else:
                        EmailMessage.log_message("body part type is " + content_type)
                    part_index += 1

                if not text_set:
                    new_part = MIMEText(
                      text, mime_constants.PLAIN_SUB_TYPE, EmailMessage.get_charset())
                    message.attach(new_part)
                    text_set = True

            else:
                self.set_content(text, mime_constants.TEXT_PLAIN_TYPE)
                text_set = True
            
        if self.DEBUGGING:
            EmailMessage.log_message("message after setting text:\n" + self.to_string())
            EmailMessage.log_message("set text:\n{}".format(text_set))

        return text_set


    def get_content(self):
        ''' 
            Get the message's content, decoding if bas64 or print-quoted encoded.

            >>> from goodcrypto_tests.mail.mail_test_utils import get_basic_email_message
            >>> email_message = get_basic_email_message()
            >>> email_message.get_content()
            'Test message text'
        '''

        decode = False
        message = self.get_message()
        if message.has_key(mime_constants.CONTENT_XFER_ENCODING_KEYWORD):
            try:
                encoding = message.__getitem__(mime_constants.CONTENT_XFER_ENCODING_KEYWORD)
                if encoding is not None:
                    encoding = encoding.lower()
            except:
                encoding = ''
                current_content_type = ''

            # only use the encoding if it's not a multipart message
            if encoding == 'quoted-printable' or encoding == 'base64':
                current_content_type = self.get_message().get_content_type()
                if (current_content_type is not None and 
                    current_content_type.lower().find(mime_constants.MULTIPART_PRIMARY_TYPE) < 0):
                    decode = True
                    EmailMessage.log_message('decoding payload with {}'.format(encoding))

        try:
            payload = message.get_payload(decode=decode)
        except:
            EmailMessage.log_message(format_exc())
            payload = message.get_payload()
    
        return payload


    def set_content(self, payload, content_type):
        '''
            Set the content of the message.

            >>> from goodcrypto_tests.mail.mail_test_utils import get_basic_email_message
            >>> email_message = get_basic_email_message()
            >>> email_message.set_content('New test message text', mime_constants.TEXT_PLAIN_TYPE)
            >>> email_message.get_content()
            'New test message text'
        '''
        
        # create a new message if one doesn't exist
        if EmailMessage._message is None:
            EmailMessage._message = Message()

        current_content_type = self.get_message().get_content_type()
        if current_content_type is None:
            current_content_type = content_type
        EmailMessage.log_message('current content type: {}'.format(current_content_type))
        EmailMessage.log_message('setting content type: {}'.format(content_type))
        if self.DEBUGGING:
            EmailMessage.log_message('content:\n{}'.format(payload))
        
        current_encoding = EmailMessage._message.__getitem__(mime_constants.CONTENT_XFER_ENCODING_KEYWORD)
        if current_encoding is None:
            EmailMessage._message.__setitem__(mime_constants.CONTENT_XFER_ENCODING_KEYWORD, mime_constants.BITS_8)
            EmailMessage.log_message('setting content encoding: {}'.format(mime_constants.BITS_8))

        # if this is a simple text or html message, then just update the payload
        if (content_type == current_content_type and
            (content_type == mime_constants.TEXT_PLAIN_TYPE or 
             content_type == mime_constants.TEXT_HTML_TYPE)):

            EmailMessage.log_message('updating payload for {} using {} charset'.format(
                content_type, EmailMessage.get_charset()))
            try:
                self.get_message().set_payload(payload, EmailMessage.get_charset())
            except UnicodeEncodeError:
                try:
                    self.get_message().set_payload(payload, 'UTF-8')
                except UnicodeEncodeError:
                    self.get_message().set_payload(payload)
            self.get_message().set_type(content_type)

        else:
            from goodcrypto.mail.message.utils import is_content_type_mime

            EmailMessage.log_message('attaching payload for {}'.format(content_type))
            if content_type == mime_constants.OCTET_STREAM_TYPE:
                part = MIMEBase(mime_constants.APPLICATION_TYPE, mime_constants.OCTET_STREAM_SUB_TYPE)
                part.set_payload(open(payload,"rb").read())
                encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(payload))
                self.get_message().attach(part)

            elif is_content_type_mime(self.get_message()):
                if not self.get_message().is_multipart():
                    self.get_message().set_payload(payload, EmailMessage.get_charset())
                    self.get_message().set_type(content_type)

                elif content_type == mime_constants.TEXT_PLAIN_TYPE:
                    if self.DEBUGGING: EmailMessage.log_message('mime text payload:\n{}'.format(payload))
                    part = MIMEText(payload)
                    if self.DEBUGGING: EmailMessage.log_message('mime text part:\n{}'.format(part))
                    part.set_payload(payload)
                    if self.DEBUGGING: EmailMessage.log_message('mime text part with payload:\n{}'.format(part))
                    self.get_message().attach(part)

                else:
                    primary, _, secondary = content_type.partition(mime_constants.PRIMARY_TYPE_DELIMITER)
                    part = MIMEBase(primary, secondary)
                    part.set_payload(payload)
                    self.get_message().attach(part)

    @staticmethod
    def is_open_pgp_mime(msg=None):
        '''
            Returns true if this is an OpenPGP MIME message.

            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('open-pgp-mime.txt')) as input_file:
            ...     mime_message = EmailMessage(input_file)
            ...     mime_message.is_open_pgp_mime()
            True
        '''

        is_mime_and_pgp = False

        if msg is None:
            msg = EmailMessage._message

        try:
            # the content type is always lower case and always has a value
            content_type = msg.get_content_type()
            EmailMessage.log_message("main content type: {}".format(content_type))
            
            #  if the main type is multipart/encrypted
            if content_type == mime_constants.MULTIPART_ENCRYPTED_TYPE:
                protocol = msg.get_param(mime_constants.PROTOCOL_KEYWORD)
                if protocol == None:
                    EmailMessage.log_message("multipart encrypted, protocol missing")
                else:
                    EmailMessage.log_message("multipart encrypted protocol: {}".format(protocol))
                    is_mime_and_pgp = str(protocol).lower() == mime_constants.PGP_TYPE.lower()

        except MessageException as message_exception:
            EmailMessage.log_exception(message_exception)
            EmailMessage.log_message(format_exc())
        except Exception:
            EmailMessage.log_message(format_exc())

        return is_mime_and_pgp


    def is_probably_pgp(self):
        '''
            Returns true if this is probably an OpenPGP message.
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('open-pgp-mime.txt')) as input_file:
            ...     mime_message = EmailMessage(input_file)
            ...     mime_message.is_probably_pgp()
            True
        '''

        is_pgp = self.is_open_pgp_mime()
        if not is_pgp:
            content = self.get_content()
            if isinstance(content, str):
                is_pgp = (self.contains_pgp_message_delimters(content))

        return is_pgp

    def contains_pgp_message_delimters(self, text):
        '''
            Returns true if text contains PGP message delimiters.
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('open-pgp-mime.txt')) as input_file:
            ...     text = input_file.read()
            ...     email_message = EmailMessage()
            ...     email_message.contains_pgp_message_delimters(text)
            True
        '''

        return (isinstance(text, str) and
                text.find(constants.BEGIN_PGP_MESSAGE) >= 0 and 
                text.find(constants.END_PGP_MESSAGE) >= 0)

    def contains_pgp_signature_delimeters(self, text):
        '''
            Returns true if text contains PGP signature delimiters.
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> with open(get_plain_message_name('pgp-signature.txt')) as input_file:
            ...     text = input_file.read()
            ...     email_message = EmailMessage()
            ...     email_message.contains_pgp_signature_delimeters(text)
            True
        '''

        return (isinstance(text, str) and
                text.find(constants.BEGIN_PGP_SIGNATURE) >= 0 and 
                text.find(constants.END_PGP_SIGNATURE) >= 0)

    def get_pgp_signature_blocks(self):
        '''
            Returns the PGP signature blocks with text, if there are any.
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> with open(get_plain_message_name('pgp-signature.txt')) as input_file:
            ...     mime_message = EmailMessage(input_file)
            ...     signature_blocks = mime_message.get_pgp_signature_blocks()
            ...     len(signature_blocks) > 0
            True
        '''

        def get_signed_data(content):
            ''' Get the signed data. '''

            signature_block = None
            start_index = content.find(constants.BEGIN_PGP_SIGNED_MESSAGE)
            if start_index < 0:
                start_index = content.find(constants.BEGIN_PGP_SIGNATURE)
            end_index = content.find(constants.END_PGP_SIGNATURE)
            if start_index >= 0 and end_index > start_index:
                signature_block = content[start_index:end_index + len(constants.END_PGP_SIGNATURE)]
                
            return signature_block

        def init_new_message(old_message):
            ''' Initialize a new message from the old message. '''
            
            new_message = MIMEMultipart(old_message.get_content_subtype(), old_message.get_boundary())

            for key, value in old_message.items():
                if key is not mime_constants.CONTENT_TYPE_KEYWORD:
                    new_message.add_header(key, value)

            old_params = old_message.get_params()
            new_params = new_message.get_params()
            if old_params is not None:
                for old_param in old_params:
                    if old_param not in new_params:
                        param, value = old_param
                        new_message.set_param(param, value)

            return new_message
            
        def remove_signature(content):
            ''' Remove the signature from the content. '''

            # remove the beginning signature lines
            if content.startswith(constants.BEGIN_PGP_SIGNED_MESSAGE):
                begin_sig_lines = ''
                for line in content.split('\n'):
                    if len(line) <= 0:
                        break
                    else:
                        begin_sig_lines += line
                        begin_sig_lines += '\n'
                content = content[len(begin_sig_lines):]
                
            start_index = content.find(constants.BEGIN_PGP_SIGNATURE)
            end_index = content.find(constants.END_PGP_SIGNATURE)
                
            # remove the signature itself
            start_sig_index = content.find(constants.BEGIN_PGP_SIGNATURE)
            content = content[0:start_sig_index] + content[end_index + len(constants.END_PGP_SIGNATURE):]
            
            # remove the extra characters added around the message itself
            content = content.replace('- {}'.format(constants.BEGIN_PGP_MESSAGE), constants.BEGIN_PGP_MESSAGE)
            content = content.replace('- {}'.format(constants.END_PGP_MESSAGE), constants.END_PGP_MESSAGE)

            return content

        def create_new_payload(old_payload):
            ''' Create a new payload without the signature. '''

            new_payload = MIMENonMultipart(
               old_payload.get_content_maintype(), old_payload.get_content_subtype())
            for key, value in old_payload.items():
                if key not in new_payload.keys():
                    new_payload.add_header(key, value)
            old_params = old_payload.get_params()
            new_params = new_payload.get_params()
            if old_params is not None:
                for old_param in old_params:
                    if old_param not in new_params:
                        param, value = old_param
                        new_payload.set_param(param, value)

            new_payload.set_payload(remove_signature(old_payload.get_payload()))

            return new_payload

        signature_blocks = []
        if self.get_message().is_multipart():
            EmailMessage.log_message('check each of {} parts of message for a signature'.format(
                len(self.get_message().get_payload())))
            part_index = 0
            part_indices = []
            parts = self.get_message().get_payload()
            for part in parts:
                if isinstance(part, str):
                    content = part
                else:
                    content = part.get_payload()
                if self.contains_pgp_signature_delimeters(content):
                    is_signed = True
                    signature_block = get_signed_data(content)
                    if signature_block is not None:
                        signature_blocks.append(signature_block)
                        part_indices.append(part_index)
                part_index += 1

            if len(part_indices) > 0:
                new_message = init_new_message(self.get_message())
                part_index = 0
                payloads = self.get_message().get_payload()
                for payload in payloads:
                    if part_index in part_indices:
                        new_payload = create_new_payload(payload)
                        new_message.attach(new_payload)
                    else:
                        new_message.attach(payload)
                    part_index += 1
                self.set_message(new_message)

        else:
            content = self.get_message().get_payload(decode=True)
            if isinstance(content, str) and self.contains_pgp_signature_delimeters(content):
                is_signed = True
                signature_block = get_signed_data(content)
                if signature_block is not None:
                    signature_blocks.append(signature_block)
                    self.get_message().set_payload(remove_signature(content))
                    EmailMessage.log_message('extracted signature block from content')

        EmailMessage.log_message('total signature blocks: {}'.format(len(signature_blocks)))

        return signature_blocks

    @staticmethod
    def get_charset(part=None):
        '''
            Gets the charset.

            >>> from goodcrypto_tests.mail.mail_test_utils import get_basic_email_message
            >>> email_message = get_basic_email_message()
            >>> email_message.get_charset().lower() == 'utf-8'
            True
        '''

        def find_char_set(part):
    
            charset = None
            try:
                if part.find(mime_constants.CONTENT_TYPE_KEYWORD) >= 0:
                    index = part.find(mime_constants.CONTENT_TYPE_KEYWORD)
                    line = part[index + len(mime_constants.CONTENT_TYPE_KEYWORD):]
                    
                    index = line.lower().find('charset=')
                    if index > 0:
                        charset = line[index + len('charset='):]
                    if charset.find('\r'):
                        charset = charset[:charset.find('\r')]
                    elif charset.find('\n'):
                        charset = charset[:charset.find('\n')]
            except Exception as char_exception:
                EmailMessage.log_message(char_exception)
                EmailMessage.log_message(format_exc())

            if charset is None:
                charset = EmailMessage.DEFAULT_CHAR_SET

            return charset


        try:
            charset = None
            if part is None:
                if EmailMessage._message is not None:
                    charset = EmailMessage._message.get_charset()
                    if charset is None:
                        charset = EmailMessage._message.get_param('charset')
                        EmailMessage.log_message('using message param charset')
            else:
                if isinstance(part, str):
                    charset = find_char_set(part)
                    EmailMessage.log_message('finding charset')
                else:
                    charset = part.get_charset()
                    if charset is None:
                        charset = part.get_param('charset')

            # if unknown than use the last charset
            if charset is None:
                charset = EmailMessage._last_charset
                EmailMessage.log_message('using last charset')

            # if still unknown than use the default
            if charset is None:
                charset = EmailMessage.DEFAULT_CHAR_SET
                EmailMessage.log_message('using default charset')
            
            # the charset should be string
            charset = str(charset)
            
            # remember the last char set used
            EmailMessage._last_charset = charset

        except MessageException as message_exception:
            charset = EmailMessage.DEFAULT_CHAR_SET
            EmailMessage.log_message(message_exception)
        
        return charset


    def write_to(self, output_file):
        '''
            Write message to the specified file.
            
            >>> from goodcrypto.mail.utils.dirs import get_test_directory
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> filename = get_encrypted_message_name('iso-8859-1-binary.txt')
            >>> with open(filename) as input_file:
            ...     output_dir = get_test_directory()
            ...     output_filename = os.path.join(output_dir, 'test-message.txt')
            ...     mime_message = EmailMessage(input_file)
            ...     with open(output_filename, 'w') as out:
            ...         mime_message.write_to(out)
            ...         os.path.exists(output_filename)
            ...         mime_message.write_to(out)
            ...     os.path.exists(output_filename)
            ...     os.remove(output_filename)
            True
            True
            True
            True

            if os.path.exists(output_filename):
                os.remove(output_filename)
        '''

        result_ok = False
        try:
            if isinstance(output_file, file):
                if output_file.closed:
                    with open(output_file.name, 'w') as out:
                        out.write(self.to_string())
                        out.flush()
                else:
                    output_file.write(self.to_string())
                    output_file.flush()

            elif isinstance(output_file, StringIO):
                output_file.write(self.to_string())

            else:
                with open(output_file, 'w') as out:
                    out.write(self.to_string())
                    out.flush()

            result_ok = True
        except Exception:
            EmailMessage.log_message(format_exc())
            raise Exception

        return result_ok


    def to_string(self, charset=None, mangle_from=False):
        '''
            Convert message to a string.
            
            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> filename = get_plain_message_name('basic.txt')
            >>> with open(filename) as input_file:
            ...     file_content = input_file.read().replace('\\r\\n', '\\n')
            ...     input_file.seek(os.SEEK_SET)
            ...     email_message = EmailMessage(input_file)
            ...     file_content.strip() == email_message.to_string().strip()
            True
        '''

        debug_to_string = False
        string = None
        
        try:
            msg = EmailMessage._message
            if charset is None:
                charset = EmailMessage.get_charset()

            #  convert the message
            try:
                file_pointer = StringIO()
                message_generator = Generator(file_pointer, mangle_from_=mangle_from, maxheaderlen=78)
                message_generator.flatten(msg)
                string = file_pointer.getvalue()
            except Exception, AttributeError:
                try:
                    EmailMessage.log_message(format_exc())

                    string = msg.as_string()
                except Exception, AttributeError:
                    #  we explicitly want to catch everything here, even NPE
                    EmailMessage.log_message(format_exc())
    
                    string = '{}\n{}'.format(
                        '\n'.join(self.get_header_lines()),
                        '\n'.join(self.get_content_lines()))

            if debug_to_string:
                EmailMessage.log_message("converting message to string using charset {}".format(charset))
                EmailMessage.log_message("message:\n{}".format(string))

        except IOError as io_error:
            self.last_error = io_error
            EmailMessage.log_message(io_error)
            
        except MessageException as msg_exception:
            self.last_error = msg_exception
            EmailMessage.log_message(msg_exception)

        return string


    def get_header_lines(self):
        '''
            Get message headers as a list of lines.

            The lines follow RFC 2822, with a maximum of 998 characters per line.
            Longer headers are folded using a leading tab.

            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> filename = get_plain_message_name('basic.txt')
            >>> with open(filename) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     len(email_message.get_header_lines()) > 0
            True
        '''

        max_line_length = 998
        
        lines = []
        raw_headers = EmailMessage._message.keys()
        for header in raw_headers:
            value = self.get_header(header)
            if value is None:
                value = ''
            raw_line = '{}: {}'.format(header, value)
            if max_line_length > len(raw_line):
                
                #  add first line from this header
                part_line = raw_line[0:max_line_length]
                lines.append(part_line)
                raw_line = raw_line[:max_line_length]
                
                #  add continuation lines
                while len(raw_line) > max_line_length:
                    #  make space for leading tab
                    part_line = raw_line[0:max_line_length - 1]
                    lines.append("\t" + part_line)
                    raw_line = raw_line[max_line_length - 1:]
                    
            if len(raw_line) > 0:
                lines.append(raw_line)
                
        return lines


    def get_content_lines(self):
        '''
            Gets the message content as a list of lines.
            
            This is the part of the message after the header and the separating blank
            line, with no decoding.

            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> filename = get_plain_message_name('basic.txt')
            >>> with open(filename) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     len(email_message.get_content_lines()) > 0
            True
        '''

        lines = []
        payloads = EmailMessage._message.get_payload()
        if payloads is None:
            EmailMessage.log_message('No content')
        else:
            if isinstance(payloads, str):
                lines = payloads.split()
            else:
                for payload in payloads:
                    if isinstance(payload, Message):
                        lines += payload.as_string()
                    else:
                        lines += payload.split()
                
        return lines

    def _parse_header_line(self, line, last_name):

        name, _, value = line.partition(':')
        if name is not None:
            name = name.strip()
        
        if name is None or len(name) <= 0:
            EmailMessage.log_message("no header name in line: " + line)
            old_value = self.get_header(last_name)
            self.add_header(name, '{} {}\n'.format(old_value.strip('\n'), value.strip()))
        else:
            last_name = name
            if value is None:
                value = ''
            else:
                value = value.strip()

        try:
            # try adding the header line and see if python can parse it
            test_message = Message()
            test_message.__setitem__(name, value)
            temp_header = self.parser.parsestr(test_message.as_string(unixfrom=False))
            if temp_header.__len__() == 0:
                EmailMessage.log_message('bad header: {}'.format(line))
                self.bad_header_lines.append(line)
            else:
                # if the parser accept this header line, then keep it
                self.add_header(name, value)
        except Exception:
            EmailMessage.log_message(format_exc())
            self.bad_header_lines.append(line)

        return name, value, last_name

    def _set_content_encoding(self, name, value):
        
        if name == mime_constants.CONTENT_TYPE_KEYWORD:
            try:
                # try to set the charset
                index = value.find('charset=')
                if index >= 0:
                    charset = value[index + len('charset='):]
                    if charset.startswith('"') and charset.endswith('"'):
                        charset = charset[1:len(charset)-1]
                    EmailMessage._message.set_charset(charset)
            except Exception:
                EmailMessage.log_message(format_exc())
                EmailMessage._message.set_charset(EmailMessage.DEFAULT_CHAR_SET)

        elif name == mime_constants.CONTENT_XFER_ENCODING_KEYWORD:
            encoding_value = EmailMessage._message.get(
               mime_constants.CONTENT_XFER_ENCODING_KEYWORD)
            EmailMessage.log_message('message encoding: {}'.format(encoding_value))
            if encoding_value is None or encoding_value.lower() != value.lower():
                EmailMessage._message.__delitem__(name)
                EmailMessage._message.__setitem__(name, value)
                EmailMessage.log_message('set message encoding: {}'.format(value))

    def _create_new_header(self, message_string):
        '''
            Create a new header from a corrupted message.
            
            @lines     all lines in message.
            @return    lines in body text or None if no body text.
        '''

        last_name = None
        body_text_lines = None

        EmailMessage.log_message('starting to parse headers')
        lines = message_string.split('\n')
        header_count = 0
        for line in lines:

            if line is None or len(line.strip()) <= 0:
                EmailMessage.log_message('finished parsing headers')
                if header_count + 1 <= len(lines):
                    body_text_lines = lines[header_count + 1:]
                else:
                    body_text_lines = []
                break

            else:
                header_count += 1
                name, value, last_name = self._parse_header_line(line, last_name)

                if (name is not None and 
                    (name == mime_constants.CONTENT_TYPE_KEYWORD or 
                     name == mime_constants.CONTENT_XFER_ENCODING_KEYWORD) ):

                    self._set_content_encoding(name, value)

        return body_text_lines


    def _create_new_body_text(self, body):
        '''
            Create the body text from a corrupted message.
            
            @source    input file with message.
            @return    message
        '''

        try:
            body_text = ''
            for line in body:
                body_text += line.encode(EmailMessage.get_charset())
        except Exception as body_exception:
            EmailMessage.log_message(body_exception)
            EmailMessage.log_message(format_exc())
            body_text = ''.join(body)

        if len(self.bad_header_lines) > 0:
            body_text += '\n\n{}\n'.format(REMOVED_BAD_HEADER_LINES)
            for bad_header_line in self.bad_header_lines:
                body_text += '  {}\n'.format(bad_header_line)

        EmailMessage._message.set_payload(body_text)

    def _create_good_message_from_bad(self, source):
        '''
            Create a good message from a source that contains a corrupted message.
            
            @source    lines of message.
            @return    valid message
        '''

        try:
            # start with a fresh message
            EmailMessage._message = Message()
            
            if isinstance(source, file):
                source.seek(os.SEEK_SET)
                message_string = source.read()
            else:
                message_string = source
            
            body_text = self._create_new_header(message_string)    
            if body_text:
                self._create_new_body_text(body_text)

        except Exception as message_exception:
            EmailMessage.log_message(message_exception)
            EmailMessage.log_message(format_exc())
            raise MessageException(message_exception)

    
    def init_new_message(self, from_addr, to_addr, subject, text=None):
        ''' Initialize a basic new message. 
        
            Used primarily for testing.
        '''
        
        self.add_header(mime_constants.FROM_KEYWORD, from_addr)
        self.add_header(mime_constants.TO_KEYWORD, to_addr)
        self.add_header(mime_constants.SUBJECT_KEYWORD, subject)
        
        if text:
            self.set_text(text)


    @staticmethod
    def log_message_exception(exception_error, message, log_msg):
        ''' 
            Log an exception.

            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> EmailMessage.log_message_exception(Exception, 'message', 'log message')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.email_message.log'))
            True
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.utils.exception_log.log'))
            True
        '''

        EmailMessage.log_exception(log_msg, message_exception=exception_error)
        if message != None:
            try:
                EmailMessage.log_message("message:\n" + message.to_string())
            except Exception as exception_error2:
                EmailMessage.log_message("unable to log message: {}".format(exception_error2))


    @staticmethod
    def log_exception(log_msg, message_exception=None):
        ''' 
            Log an exception.

            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> EmailMessage.log_exception('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.email_message.log'))
            True
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.utils.exception_log.log'))
            True
            >>> EmailMessage.log_exception('test', message_exception='message exception')
        '''
            
        EmailMessage.log_message(format_exc())
        ExceptionLog.log_message(format_exc())
        
        EmailMessage.log_message(log_msg)
        ExceptionLog.log_message(log_msg)
        
        if message_exception is not None:
            if type(message_exception) == Exception:
                EmailMessage.log_message(message_exception.value)
                ExceptionLog.log_message(message_exception.value)
            elif type(message_exception) == str:
                EmailMessage.log_message(message_exception)
                ExceptionLog.log_message(message_exception)


    @staticmethod
    def log_message(message):
        ''' 
            Log a message.

            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> EmailMessage.log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.email_message.log'))
            True
        '''
        
        if EmailMessage._log is None:
            EmailMessage._log = LogFile()

        EmailMessage._log.write(message)

