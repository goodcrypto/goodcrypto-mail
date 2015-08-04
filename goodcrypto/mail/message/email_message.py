'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-12-31

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
from django.utils.translation import ugettext as _

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail.message import constants, mime_constants
from goodcrypto.mail.message.validator import Validator
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.utils import get_charset, is_open_pgp_mime
from goodcrypto.mail.utils.exception_log import ExceptionLog


class EmailMessage(object):
    '''
        Email Message.

        Messages should be converted to EmailMessage as soon as possible,
        to check whether the message is parsable as part of validating input.

        If a MIME message is not parsable, a new Message will be created that does conform 
        and contains the original unparsable message in the body.
    '''

    DEBUGGING = True
    
    def __init__(self, message_or_file=None):
        '''
             Creates an EmailMessage from a Message or a file.
             Non-mime messages are converted to MIME "text/plain".
            
             >>> email_message = EmailMessage()
             >>> type(email_message)
             <class 'goodcrypto.mail.message.email_message.EmailMessage'>
        '''

        self.bad_header_lines = []
        self.parser = Parser()

        self._last_charset = constants.DEFAULT_CHAR_SET
        self._log = self._message = None

        if message_or_file is None:
            self._message = Message()

        elif isinstance(message_or_file, Message):
            self._message = message_or_file

        elif isinstance(message_or_file, EmailMessage):
            self._message = message_or_file.get_message()

        else:
            try:
                if isinstance(message_or_file, file) or isinstance(message_or_file, StringIO):
                    self.log_message('about to parse a message from a file')
                    self._message = self.parser.parse(message_or_file)
                    self.log_message('parsed message')
                else:
                    self.log_message('about to parse a message from a string')
                    self._message = self.parser.parsestr(message_or_file)
                    self.log_message('parsed message')
                
                if not self.validate_message():
                    self._create_good_message_from_bad(message_or_file)
            except Exception:
                try:
                    self.log_message(format_exc())
                    
                    self._create_good_message_from_bad(message_or_file)
                    
                    # if we still don't have a good message, then blow up
                    if not self.validate_message():
                        self.log_message('unable to create a valid message')
                        raise MessageException()
                except Exception:
                    self.log_message(format_exc())
                    
        if self.DEBUGGING:
            try:
                self.log_message(self.to_string())
            except:
                pass


    def get_header(self, key):
        ''' 
            Get a header from an existing message. 
            
            >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
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
            
            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
            >>> with open(get_plain_message_name('basic.txt')) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     email_message.add_header('X-OpenPGP-Accepts', 'GPG')
            ...     email_message.get_header('X-OpenPGP-Accepts')
            'GPG'
        '''

        self._message.__setitem__(key, value)


    def change_header(self, key, value):
        ''' 
            Change a header to an existing message. 
            
            >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('bouncy-castle.txt')) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     email_message.change_header('X-OpenPGP-Accepts', 'TestGPG')
            ...     email_message.get_header('X-OpenPGP-Accepts')
            'TestGPG'
        '''

        if self._message.__contains__(key):
            self.delete_header(key)

        self.add_header(key, value)


    def delete_header(self, key):
        ''' 
            Delete a header to an existing message.
            
            >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('bouncy-castle.txt')) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     email_message.delete_header('X-OpenPGP-Accepts')
            ...     email_message.get_header('X-OpenPGP-Accepts') is None
            True
        '''
        
        self._message.__delitem__(key)


    def get_message(self):
        ''' 
            Get the message.
            
            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER
            >>> email_message = get_basic_email_message()
            >>> email_message.get_message() is not None
            True
            >>> email_message.get_message().get(mime_constants.FROM_KEYWORD) == EDWARD_LOCAL_USER
            True
        '''

        return self._message


    def set_message(self, new_message):
        '''
            Set the new message.
            
            # Get a basic message first so we can avoid recursion
            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER
            >>> basic_email_message = get_basic_email_message().get_message()
            >>> email_message = EmailMessage()
            >>> email_message.get_message().get(mime_constants.FROM_KEYWORD) is None
            True
            >>> email_message.set_message(basic_email_message)
            >>> email_message.get_message().get(mime_constants.FROM_KEYWORD) == EDWARD_LOCAL_USER
            True
        '''

        old_message = self._message
        self._message = new_message
        
        # restore the old message if the new one isn't valid.
        if not self.validate_message():
            self._message = old_message
            self.log_message('restored previous message')

    def validate_message(self):
        '''
            Validate a message.
            
            Python's parser frequently accepts a message that has garbage in the header by
            simply adding all header items after the bad header line(s) to the body text;
            this can leave a pretty unmanageable message so we apply our own validation
            
            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER
            >>> email_message = get_basic_email_message()
            >>> email_message.validate_message()
            True
        '''
        try:
            validator = Validator(self)
            if validator.is_message_valid():
                valid = True
                self.log_message('message is valid')
            else:
                valid = False
                self.log_message('message is invalid')
                self.log_message(validator.get_why())
        except Exception, AttributeError:
            valid = False
            self.log_message(format_exc())
            
        return valid

    def get_text(self):
        '''
            Gets text from the current Message.
            
            This method works with both plain and MIME messages, except open pgp mime..
            If the message is MIMEMultipart, the text is from the first text/plain part.
            
            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> email_message = get_basic_email_message()
            >>> email_message.get_text()
            'Test message text'
        '''

        text = None
        message = self.get_message()

        if is_open_pgp_mime(message):
            self.log_message("unable to get text from openpgp mime message")

        else:
            if message.is_multipart():
                self.log_message("message is a MIMEMultipart")

                #  get the first text/plain part
                result_ok = False
                part_index = 0
                parts = message.get_payload()
                while part_index < len(parts) and not result_ok:
                    part = message.get_payload(part_index)
                    content_type = part.get_content_type()
                    if content_type == mime_constants.TEXT_PLAIN_TYPE:
                        text = part.get_payload(decode=True)
                        __, self._last_charset = get_charset(part, self._last_charset)
                        result_ok = True
                    else:
                        self.log_message("body part type is " + content_type)
                    part_index += 1
            else:
                text = message.get_payload(decode=True)
                self.log_message("content is a String")
                __, self._last_charset = get_charset(message, self._last_charset)

        return text


    def set_text(self, text, charset=None):
        '''
            Sets text in the current Message.
            
            This method works with both plain and MIME messages, except open pgp mime.
            If the message is MIMEMultipart, the text is set in the first text/plain part.
            
            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> email_message = get_basic_email_message()
            >>> email_message.set_text('New test message text')
            True
            >>> email_message.get_text()
            'New test message text'
        '''

        if self.DEBUGGING:
            self.log_message("setting text:\n{}".format(text))
        
        text_set = False
        message = self.get_message()
        if message.is_multipart():
            #  set the first text/plain part
            text_set = False
            part_index = 0
            parts = message.get_payload()
            while part_index < len(parts) and not text_set:
                part = message.get_payload(part_index)
                content_type = part.get_content_type()
                if content_type == mime_constants.TEXT_PLAIN_TYPE:
                    part.set_payload(text)
                    text_set = True
                    self.log_message('set the first text/plain part found')
                else:
                    self.log_message("body part type is " + content_type)
                part_index += 1

            if not text_set:
                charset, __ = get_charset(self._message, self._last_charset)
                new_part = MIMEText(text, mime_constants.PLAIN_SUB_TYPE, charset)
                message.attach(new_part)
                text_set = True
                self.log_message('added a new text/plain part with text')

        elif is_open_pgp_mime(message):
            self.log_message("unable to set text from openpgp mime message")

        else:
            self.set_content(text, mime_constants.TEXT_PLAIN_TYPE, charset=charset)
            text_set = True

        if self.DEBUGGING:
            self.log_message("message after setting text:\n" + self.to_string())
            self.log_message("set text:\n{}".format(text_set))

        return text_set


    def get_content(self):
        ''' 
            Get the message's content, decoding if bas64 or print-quoted encoded.

            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
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
            if (encoding == mime_constants.QUOTED_PRINTABLE_ENCODING or 
                encoding == mime_constants.BASE64_ENCODING):
                current_content_type = self.get_message().get_content_type()
                if (current_content_type is not None and 
                    current_content_type.lower().find(mime_constants.MULTIPART_PRIMARY_TYPE) < 0):
                    decode = True
                    self.log_message('decoding payload with {}'.format(encoding))

        try:
            payload = message.get_payload(decode=decode)
        except:
            self.log_message(format_exc())
            payload = message.get_payload()
    
        return payload

    def set_content(self, payload, content_type, charset=None):
        '''
            Set the content of the message.

            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> email_message = get_basic_email_message()
            >>> email_message.set_content('New test message text', mime_constants.TEXT_PLAIN_TYPE)
            >>> email_message.get_content()
            'New test message text'
        '''
        
        # create a new message if one doesn't exist
        if self._message is None:
            self._message = Message()

        current_content_type = self.get_message().get_content_type()
        if current_content_type is None:
            current_content_type = content_type
        self.log_message('current content type: {}'.format(current_content_type))
        self.log_message('setting content type: {}'.format(content_type))
        if self.DEBUGGING:
            self.log_message('content:\n{}'.format(payload))
        
        current_encoding = self._message.__getitem__(mime_constants.CONTENT_XFER_ENCODING_KEYWORD)
        if current_encoding is None:
            self._message.__setitem__(mime_constants.CONTENT_XFER_ENCODING_KEYWORD, mime_constants.BITS_8)
            self.log_message('setting content encoding: {}'.format(mime_constants.BITS_8))

        # if this is a simple text or html message, then just update the payload
        if (content_type == current_content_type and
            (content_type == mime_constants.TEXT_PLAIN_TYPE or 
             content_type == mime_constants.TEXT_HTML_TYPE)):

            if charset is None:
                charset, self._last_charset = get_charset(payload, self._last_charset)
            else:
                if self._last_charset:
                    self._last_charset = constants.DEFAULT_CHAR_SET
            try:
                self.get_message().set_payload(payload, charset)
                self.log_message('set payload with {} charset'.format(charset))
            except UnicodeEncodeError:
                try:
                    self.get_message().set_payload(payload, self._last_charset)
                    self.log_message('set payload with {} charset'.format(self._last_charset))
                except UnicodeEncodeError:
                    self.get_message().set_payload(payload)
                    self.log_message('setting payload without charset')
            self.get_message().set_type(content_type)

        else:
            from goodcrypto.mail.message.utils import is_content_type_mime

            self.log_message('attaching payload for {}'.format(content_type))
            if content_type == mime_constants.OCTET_STREAM_TYPE:
                part = MIMEBase(mime_constants.APPLICATION_TYPE, mime_constants.OCTET_STREAM_SUB_TYPE)
                part.set_payload(open(payload,"rb").read())
                encode_base64(part)
                part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(payload))
                self.get_message().attach(part)

            elif is_content_type_mime(self.get_message()):
                if not self.get_message().is_multipart():
                    if charset is None:
                        charset, self._last_charset = get_charset(payload, self._last_charset)
                    else:
                        if self._last_charset:
                            self._last_charset = constants.DEFAULT_CHAR_SET
                    self.get_message().set_payload(payload, charset)
                    self.log_message('set payload with {} charset'.format(charset))
                    self.get_message().set_type(content_type)

                elif content_type == mime_constants.TEXT_PLAIN_TYPE:
                    if self.DEBUGGING: self.log_message('mime text payload:\n{}'.format(payload))
                    part = MIMEText(payload)
                    if self.DEBUGGING: self.log_message('mime text part:\n{}'.format(part))
                    part.set_payload(payload)
                    if self.DEBUGGING: self.log_message('mime text part with payload:\n{}'.format(part))
                    self.get_message().attach(part)

                else:
                    primary, __, secondary = content_type.partition(mime_constants.PRIMARY_TYPE_DELIMITER)
                    part = MIMEBase(primary, secondary)
                    part.set_payload(payload)
                    self.get_message().attach(part)

    def is_probably_pgp(self):
        '''
            Returns true if this is probably an OpenPGP message.
            
            >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('open-pgp-mime.txt')) as input_file:
            ...     mime_message = EmailMessage(input_file)
            ...     mime_message.is_probably_pgp()
            True
        '''

        is_pgp = is_open_pgp_mime(self.get_message())
        if is_pgp:
            self.log_message('message uses open pgp mime')
        else:
            content = self.get_content()
            if isinstance(content, str):
                is_pgp = self.contains_pgp_message_delimters(content)
                self.log_message('message uses in line pgp: {}'.format(is_pgp))
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, Message):
                        part_content = part.get_payload()
                    else:
                        part_content = part
                        
                    if isinstance(part_content, str):
                        is_pgp = self.contains_pgp_message_delimters(part_content)
                        if is_pgp:
                            self.log_message('part of message uses in line pgp: {}'.format(is_pgp))
                            break
                    else:
                        self.log_message('part of content type is: {}'.format(repr(part_content)))
            else:
                self.log_message('content type is: {}'.format(type(content)))

        return is_pgp

    def contains_pgp_message_delimters(self, text):
        '''
            Returns true if text contains PGP message delimiters.
            
            >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
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
            
            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
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
            
            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
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

        def initialize_new_message(old_message):
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
            self.log_message('check each of {} parts of message for a signature'.format(
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
                new_message = initialize_new_message(self.get_message())
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
                    self.log_message('extracted signature block from content')

        self.log_message('total signature blocks: {}'.format(len(signature_blocks)))

        return signature_blocks

    def write_to(self, output_file):
        '''
            Write message to the specified file.
            
            >>> from goodcrypto.mail.utils.dirs import get_test_directory
            >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
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
            self.log_message(format_exc())
            raise Exception

        return result_ok


    def to_string(self, charset=None, mangle_from=False):
        '''
            Convert message to a string.
            
            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
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
            msg = self._message
            if charset is None:
                charset, __ = get_charset(msg, self._last_charset)

            #  convert the message
            try:
                file_pointer = StringIO()
                message_generator = Generator(file_pointer, mangle_from_=mangle_from, maxheaderlen=78)
                message_generator.flatten(msg)
                string = file_pointer.getvalue()
            except Exception, AttributeError:
                try:
                    self.log_message(format_exc())

                    string = msg.as_string()
                except Exception, AttributeError:
                    #  we explicitly want to catch everything here, even NPE
                    self.log_message(format_exc())
    
                    string = '{}\n{}'.format(
                        '\n'.join(self.get_header_lines()),
                        '\n'.join(self.get_content_lines()))

            if debug_to_string:
                self.log_message("converting message to string using charset {}".format(charset))
                self.log_message("message:\n{}".format(string))

        except IOError as io_error:
            self.last_error = io_error
            self.log_message(io_error)
            
        except MessageException as msg_exception:
            self.last_error = msg_exception
            self.log_message(msg_exception)

        return string


    def get_header_lines(self):
        '''
            Get message headers as a list of lines.

            The lines follow RFC 2822, with a maximum of 998 characters per line.
            Longer headers are folded using a leading tab.

            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
            >>> filename = get_plain_message_name('basic.txt')
            >>> with open(filename) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     len(email_message.get_header_lines()) > 0
            True
        '''

        max_line_length = 998
        
        lines = []
        raw_headers = self._message.keys()
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

            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
            >>> filename = get_plain_message_name('basic.txt')
            >>> with open(filename) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     len(email_message.get_content_lines()) > 0
            True
        '''

        lines = []
        payloads = self._message.get_payload()
        if payloads is None:
            self.log_message('No content')
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
        '''
            Parse a header line (internal user only).
            
            >>> email_message = EmailMessage()
            >>> name, value, last_name = email_message._parse_header_line(
            ...   'Mime-Version: 1.0', 'Subject')
            >>> name
            'Mime-Version'
            >>> value
            '1.0'
        '''

        if line is None:
            name = value = last_name = None
        else:
            name, __, value = line.partition(':')
            if name is not None:
                name = name.strip()
            
            if name is None or len(name) <= 0:
                self.log_message("no header name in line: " + line)
                if last_name is not None:
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
                    self.log_message('bad header: {}'.format(line))
                    self.bad_header_lines.append(line)
                else:
                    # if the parser accept this header line, then keep it
                    self.add_header(name, value)
            except Exception:
                self.log_message(format_exc())
                self.bad_header_lines.append(line)

        return name, value, last_name

    def _set_content_encoding(self, name, value):
        '''
            Set encoding in content (internal use only).
            
            >>> email_message = EmailMessage()
            >>> email_message._set_content_encoding(
            ...   mime_constants.CONTENT_TYPE_KEYWORD, 'charset=utf-8')
        '''
        
        if name is None or value is None:
            self.log_message('no name or value defined while trying to set content encoding')

        elif name == mime_constants.CONTENT_TYPE_KEYWORD:
            try:
                # try to set the charset
                index = value.find('charset=')
                if index >= 0:
                    charset = value[index + len('charset='):]
                    if charset.startswith('"') and charset.endswith('"'):
                        charset = charset[1:len(charset)-1]
                    self._message.set_charset(charset)
            except Exception:
                self.log_message(format_exc())
                self._message.set_charset(constants.DEFAULT_CHAR_SET)

        elif name == mime_constants.CONTENT_XFER_ENCODING_KEYWORD:
            encoding_value = self._message.get(
               mime_constants.CONTENT_XFER_ENCODING_KEYWORD)
            self.log_message('message encoding: {}'.format(encoding_value))
            if encoding_value is None or encoding_value.lower() != value.lower():
                self._message.__delitem__(name)
                self._message.__setitem__(name, value)
                self.log_message('set message encoding: {}'.format(value))

    def _create_new_header(self, message_string):
        '''
            Create a new header from a corrupted message (internal use only).
            
            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
            >>> with open(get_plain_message_name('basic.txt')) as input_file:
            ...    message_string = ''.join(input_file.readlines())
            ...    email_message = EmailMessage()
            ...    body_text_lines = email_message._create_new_header(message_string)
            ...    len(body_text_lines) > 0
            True
        '''

        last_name = None
        body_text_lines = None

        if message_string is None:
            self.log_message('no message string defined to create new header')
        else:
            self.log_message('starting to parse headers')
            lines = message_string.split('\n')
            header_count = 0
            for line in lines:
    
                if line is None or len(line.strip()) <= 0:
                    self.log_message('finished parsing headers')
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
            
            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
            >>> with open(get_plain_message_name('basic.txt')) as input_file:
            ...    email_message = EmailMessage(input_file.readlines())
            ...    email_message._create_new_body_text('Test new body text')
        '''

        try:
            body_text = ''
            charset, __ = get_charset(self._message, self._last_charset)
            for line in body:
                body_text += line.encode(charset)
        except Exception as body_exception:
            self.log_message(body_exception)
            self.log_message(format_exc())
            body_text = ''.join(body)

        if len(self.bad_header_lines) > 0:
            body_text += '\n\n{}\n'.format(_('Removed bad header lines'))
            for bad_header_line in self.bad_header_lines:
                body_text += '  {}\n'.format(bad_header_line)

        self._message.set_payload(body_text)

    def _create_good_message_from_bad(self, source):
        '''
            Create a good message from a source that contains a corrupted message.
            
            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
            >>> with open(get_plain_message_name('bad-basic.txt')) as input_file:
            ...    email_message = EmailMessage()
            ...    email_message._create_good_message_from_bad(input_file)
        '''

        try:
            # start with a fresh message
            self._message = Message()
            
            if isinstance(source, file):
                source.seek(os.SEEK_SET)
                message_string = source.read()
            else:
                message_string = source
            
            body_text = self._create_new_header(message_string)    
            if body_text:
                self._create_new_body_text(body_text)

        except Exception as message_exception:
            self.log_message(message_exception)
            self.log_message(format_exc())
            raise MessageException(message_exception)

    
    def init_new_message(self, from_addr, to_addr, subject, text=None):
        ''' Initialize a basic new message. 
        
            Used primarily for testing.
            
            >>> from_user = 'test@goodcrypto.local'
            >>> to_user = 'test@goodcrypto.remote'
            >>> email_message = EmailMessage()
            >>> email_message.init_new_message(from_user, to_user, "Test message", 'Test body text')
        '''
        
        self.add_header(mime_constants.FROM_KEYWORD, from_addr)
        self.add_header(mime_constants.TO_KEYWORD, to_addr)
        self.add_header(mime_constants.SUBJECT_KEYWORD, subject)
        
        if text:
            self.set_text(text)


    def log_message_exception(self, exception_error, message, log_msg):
        ''' 
            Log an exception.

            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> email_message = EmailMessage()
            >>> email_message.log_message_exception(Exception, 'message', 'log message')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.email_message.log'))
            True
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.utils.exception_log.log'))
            True
        '''

        self.log_exception(log_msg, message_exception=exception_error)
        if message != None:
            try:
                self.log_message("message:\n" + message.to_string())
            except Exception as exception_error2:
                self.log_message("unable to log message: {}".format(exception_error2))


    def log_exception(self, log_msg, message_exception=None):
        ''' 
            Log an exception.

            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> email_message = EmailMessage()
            >>> email_message.log_exception('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.email_message.log'))
            True
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.utils.exception_log.log'))
            True
            >>> email_message.log_exception('test', message_exception='message exception')
        '''
            
        self.log_message(format_exc())
        ExceptionLog.log_message(format_exc())
        
        self.log_message(log_msg)
        ExceptionLog.log_message(log_msg)
        
        if message_exception is not None:
            if type(message_exception) == Exception:
                self.log_message(message_exception.value)
                ExceptionLog.log_message(message_exception.value)
            elif type(message_exception) == str:
                self.log_message(message_exception)
                ExceptionLog.log_message(message_exception)

    def log_message(self, message):
        ''' 
            Log a message.

            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> email_message = EmailMessage()
            >>> email_message.log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.email_message.log'))
            True
        '''
        
        if self._log is None:
            self._log = LogFile()

        self._log.write_and_flush(message)

