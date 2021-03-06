'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-03

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from base64 import b64encode
from copy import deepcopy
from email.encoders import encode_base64
from email.generator import Generator
from email.header import decode_header
from email.message import Message
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.nonmultipart import MIMENonMultipart
from email.mime.text import MIMEText
from email.parser import Parser, BytesParser
from io import IOBase, StringIO
from quopri import encodestring

from goodcrypto.mail.message import constants
from goodcrypto.mail.message.inspect_utils import get_charset, is_open_pgp_mime
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.validator import Validator
from goodcrypto.oce import constants as oce_constants
from goodcrypto.utils import i18n
from goodcrypto.utils.log_file import LogFile
from syr import mime_constants
from syr.exception import record_exception
from syr.python import is_string

class EmailMessage(object):
    '''
        Email Message.

        Messages should be converted to EmailMessage as soon as possible,
        to check whether the message is parsable as part of validating input.

        If a MIME message is not parsable, a new Message will be created that does conform
        and contains the original unparsable message in the body.
    '''

    DEBUGGING = False

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
                if isinstance(message_or_file, IOBase)  or isinstance(message_or_file, StringIO):
                    self.log_message('about to parse a message from a file')
                    try:
                        self._message = self.parser.parse(message_or_file)
                        self.log_message('parsed message from file')
                    except TypeError:
                        message_or_file.seek(0, os.SEEK_SET)
                        self.parser = BytesParser()
                        self._message = self.parser.parse(message_or_file)
                        self.log_message('parsed message from file as bytes')
                else:
                    try:
                        self.log_message('about to parse a message from a string')
                        self._message = self.parser.parsestr(message_or_file)
                        self.log_message('parsed message from string')
                    except TypeError:
                        self.parser = BytesParser()
                        self._message = self.parser.parsebytes(message_or_file)
                        self.log_message('parsed message from bytes')

                if not self.validate_message():
                    self._create_good_message_from_bad(message_or_file)
            except Exception:
                try:
                    self.log_message('EXCEPTION - see syr.exception.log for details')
                    record_exception()

                    self._create_good_message_from_bad(message_or_file)

                    # if we still don't have a good message, then blow up
                    if not self.validate_message():
                        self.log_message('unable to create a valid message')
                        raise MessageException()
                except Exception:
                    record_exception()

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
            ...     crypto_software = email_message.get_header(constants.ACCEPTED_CRYPTO_SOFTWARE_HEADER)
            >>> crypto_software == 'GPG'
            True
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
            ...     email_message.add_header(constants.ACCEPTED_CRYPTO_SOFTWARE_HEADER, 'GPG')
            ...     crypto_software = email_message.get_header(constants.ACCEPTED_CRYPTO_SOFTWARE_HEADER)
            >>> crypto_software == 'GPG'
            True
        '''

        self._message.__setitem__(key, value)


    def change_header(self, key, value):
        '''
            Change a header to an existing message.

            >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('bouncy-castle.txt')) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     email_message.change_header(constants.ACCEPTED_CRYPTO_SOFTWARE_HEADER, 'TestGPG')
            ...     crypto_software = email_message.get_header(constants.ACCEPTED_CRYPTO_SOFTWARE_HEADER)
            >>> crypto_software == 'TestGPG'
            True
        '''

        if key in self._message:
            self._message.replace_header(key, value)
        else:
            self.add_header(key, value)


    def delete_header(self, key):
        '''
            Delete a header to an existing message.

            >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('bouncy-castle.txt')) as input_file:
            ...     email_message = EmailMessage(input_file)
            ...     email_message.delete_header(constants.ACCEPTED_CRYPTO_SOFTWARE_HEADER)
            ...     email_message.get_header(constants.ACCEPTED_CRYPTO_SOFTWARE_HEADER) is None
            True
        '''

        self._message.__delitem__(key)


    def get_message(self):
        '''
            Get the message.

            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> from goodcrypto.oce.test_constants import EDWARD_LOCAL_USER
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
            >>> from goodcrypto.oce.test_constants import EDWARD_LOCAL_USER
            >>> basic_email_message = get_basic_email_message().get_message()
            >>> email_message = EmailMessage()
            >>> email_message.get_message().get(mime_constants.FROM_KEYWORD) is None
            True
            >>> email_message.set_message(basic_email_message)
            >>> email_message.get_message().get(mime_constants.FROM_KEYWORD) == EDWARD_LOCAL_USER
            True
        '''

        old_message = self._message

        if is_string(new_message):
            try:
                if isinstance(self.parser, Parser):
                    self._message = self.parser.parsestr(new_message)
                else:
                    self._message = self.parser.parsebytes(new_message.encode())
            except:
                self._message = old_message
                record_exception()
        else:
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
            this can leave a pretty unmanageable message so we apply our own validation.

            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> from goodcrypto.oce.test_constants import EDWARD_LOCAL_USER
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
        except Exception as AttributeError:
            valid = False
            record_exception()

        return valid

    def get_text(self):
        '''
            Gets text from the current Message.

            This method works with both plain and MIME messages, except open pgp mime.
            If the message is MIMEMultipart, the text is from the first text/plain part.

            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> email_message = get_basic_email_message()
            >>> text = email_message.get_text()
            >>> text == 'Test message text'
            True
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
                        text = self._get_decoded_payload(part)
                        result_ok = True
                    else:
                        self.log_message("body part type is " + content_type)
                    part_index += 1
            else:
                text = self._get_decoded_payload(message)
                self.log_message("payload is a: {}".format(type(text)))

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
            >>> text = email_message.get_text()
            >>> text == 'New test message text'
            True
        '''

        if self.DEBUGGING: self.log_message("setting text:\n{}".format(text))

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
                    self.log_message('the first text/plain part found')
                else:
                    self.log_message('body part type is {}'.format(content_type))
                part_index += 1

            if not text_set:
                charset, __ = get_charset(self._message, self._last_charset)
                self.log_message('no text_set char set: {}'.format(charset))
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
            >>> text = email_message.get_content()
            >>> text == 'Test message text'
            True
        '''

        decode = False
        msg = self.get_message()
        encoding = self.get_header(mime_constants.CONTENT_XFER_ENCODING_KEYWORD)
        if encoding is not None:
            encoding = encoding.lower()
            self.log_message('payloaded encoded with {}'.format(encoding))

            # only use the encoding if it's not a multipart message
            if (encoding == mime_constants.QUOTED_PRINTABLE_ENCODING or
                encoding == mime_constants.BASE64_ENCODING):
                current_content_type = self.get_message().get_content_type()
                if (current_content_type is not None and
                    current_content_type.lower().find(mime_constants.MULTIPART_PRIMARY_TYPE) < 0):
                    decode = True
                    self.log_message('decoding payload with {}'.format(encoding))

        try:
            payload = self._get_decoded_payload(self.get_message(), decode=decode)
            if self.DEBUGGING: self.log_message('decoded payloaded:\n{}'.format(payload))
            self.log_message('type of payload: {}'.format(type(payload)))
        except:
            record_exception()
            payload = message.get_payload()

        return payload

    def set_content(self, payload, content_type, charset=None):
        '''
            Set the content of the message.

            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> email_message = get_basic_email_message()
            >>> email_message.set_content('New test message text', mime_constants.TEXT_PLAIN_TYPE)
            >>> text = email_message.get_content()
            >>> text == 'New test message text'
            True
        '''

        # create a new message if one doesn't exist
        if self._message is None:
            self._message = Message()

        current_content_type = self.get_message().get_content_type()
        if current_content_type is None:
            current_content_type = content_type
        self.log_message('current content type: {}'.format(current_content_type))
        self.log_message('setting content type: {}'.format(content_type))
        if self.DEBUGGING: self.log_message('content:\n{}'.format(payload))

        current_encoding = self.get_header(mime_constants.CONTENT_XFER_ENCODING_KEYWORD)
        if current_encoding is None:
            self._message.__setitem__(mime_constants.CONTENT_XFER_ENCODING_KEYWORD, mime_constants.BITS_8)
            self.log_message('setting content encoding: {}'.format(mime_constants.BITS_8))

        # if this is a simple text or html message, then just update the payload
        if (content_type == current_content_type and
            (content_type == mime_constants.TEXT_PLAIN_TYPE or
             content_type == mime_constants.TEXT_HTML_TYPE)):

            if charset is None:
                charset, self._last_charset = get_charset(payload, self._last_charset)
                self.log_message('getting charset from payload: {}'.format(charset))
            elif self._last_charset is None:
                self._last_charset = constants.DEFAULT_CHAR_SET
                self.log_message('setting last charset to default: {}'.format())
            else:
                self.log_message('using preset charset: {}'.format(charset))

            try:
                self.get_message().set_payload(
                   self.encode_payload(payload, current_encoding), charset=charset)
                self.log_message('set payload with {} charset'.format(charset))
                if self.DEBUGGING: self.log_message('payload set:\n{}'.format(payload))
            except UnicodeEncodeError as error:
                self.log_message(error.reason)
                self.log_message('start: {} end: {}'.format(error.start, error.end))
                self.log_message('object: {}'.format(error.object))
                self.get_message().set_payload(self.encode_payload(payload, current_encoding))
                self.log_message('setting payload without charset')
            self.get_message().set_type(content_type)

        else:
            from goodcrypto.mail.message.inspect_utils import is_content_type_mime

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
                        self.log_message('setting content with char set: {}'.format(charset))
                    else:
                        if self._last_charset is None:
                            self._last_charset = constants.DEFAULT_CHAR_SET
                    self.get_message().set_payload(self.encode_payload(payload, current_encoding), charset)
                    self.log_message('set payload with {} charset'.format(charset))
                    self.get_message().set_type(content_type)

                elif content_type == mime_constants.TEXT_PLAIN_TYPE:
                    if self.DEBUGGING: self.log_message('mime text payload:\n{}'.format(payload))
                    part = MIMEText(payload)
                    if self.DEBUGGING: self.log_message('mime text part:\n{}'.format(part))
                    part.set_payload(self.encode_payload(payload, current_encoding))
                    if self.DEBUGGING: self.log_message('mime text part with payload:\n{}'.format(part))
                    self.get_message().attach(part)

                else:
                    primary, __, secondary = content_type.partition(mime_constants.PRIMARY_TYPE_DELIMITER)
                    part = MIMEBase(primary, secondary)
                    part.set_payload(self.encode_payload(payload, current_encoding))
                    self.get_message().attach(part)

    def encode_payload(self, payload, current_encoding):
        '''
            Encode the payload.

            Test extreme case.
            >>> email_message = EmailMessage()
            >>> email_message.encode_payload(None, None)
        '''
        new_payload = payload
        if payload is not None and current_encoding is not None:
            """
            """
            if current_encoding == mime_constants.BASE64_ENCODING:
                if isinstance(payload, str):
                    payload = payload.encode()
                new_payload = b64encode(payload)
                self.log_message('encoding payload with {}'.format(current_encoding))
            elif current_encoding == mime_constants.QUOTED_PRINTABLE_ENCODING:
                if isinstance(payload, str):
                    payload = payload.encode()
                new_payload = encodestring(payload)
                self.log_message('encoding payload with {}'.format(current_encoding))
        return new_payload

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
        if not is_pgp:
            content = self.get_content()
            if is_string(content):
                is_pgp = self.contains_pgp_message_delimters(content)
                self.log_message('message uses in line pgp: {}'.format(is_pgp))
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, Message):
                        part_content = part.get_payload()
                    else:
                        part_content = part

                    if is_string(part_content):
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
                text.find(oce_constants.BEGIN_PGP_MESSAGE) >= 0 and
                text.find(oce_constants.END_PGP_MESSAGE) >= 0)

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
                text.find(oce_constants.BEGIN_PGP_SIGNATURE) >= 0 and
                text.find(oce_constants.END_PGP_SIGNATURE) >= 0)

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
            start_index = content.find(oce_constants.BEGIN_PGP_SIGNED_MESSAGE)
            if start_index < 0:
                start_index = content.find(oce_constants.BEGIN_PGP_SIGNATURE)
            end_index = content.find(oce_constants.END_PGP_SIGNATURE)
            if start_index >= 0 and end_index > start_index:
                signature_block = content[start_index:end_index + len(oce_constants.END_PGP_SIGNATURE)]

            return signature_block

        signature_blocks = []
        if self.get_message().is_multipart():
            self.log_message('check each of {} parts of message for a signature'.format(
                len(self.get_message().get_payload())))
            part_index = 0
            parts = self.get_message().get_payload()
            for part in parts:
                part_index += 1
                if isinstance(part, str):
                    content = part
                else:
                    content = part.get_payload()
                if self.contains_pgp_signature_delimeters(content):
                    is_signed = True
                    signature_block = get_signed_data(content)
                    if signature_block is not None:
                        signature_blocks.append(signature_block)
                    self.log_message('found signature block in part {}'.format(part_index))
                part_index += 1

        else:
            content = self._get_decoded_payload(self.get_message())
            if isinstance(content, str) and self.contains_pgp_signature_delimeters(content):
                is_signed = True
                signature_block = get_signed_data(content)
                if signature_block is not None:
                    signature_blocks.append(signature_block)
                    self.log_message('found signature block in content')

        self.log_message('total signature blocks: {}'.format(len(signature_blocks)))

        return signature_blocks

    def remove_pgp_signature_blocks(self):
        '''
            Remove the PGP signature blocks, if there are any.

            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
            >>> with open(get_plain_message_name('pgp-signature.txt')) as input_file:
            ...     mime_message = EmailMessage(input_file)
            ...     mime_message.remove_pgp_signature_blocks()
            ...     signature_blocks = mime_message.get_pgp_signature_blocks()
            ...     len(signature_blocks) == 0
            True
        '''

        def remove_signature(content):
            ''' Remove the signature from the content. '''

            # remove the beginning signature lines
            if content.startswith(oce_constants.BEGIN_PGP_SIGNED_MESSAGE):
                begin_sig_lines = ''
                for line in content.split('\n'):
                    if len(line.strip()) <= 0:
                        break
                    else:
                        begin_sig_lines += '{}\n'.format(line)
                content = content[len(begin_sig_lines):]


            # remove the signature itself
            start_index = content.find(oce_constants.BEGIN_PGP_SIGNATURE)
            end_index = content.find(oce_constants.END_PGP_SIGNATURE)
            content = content[0:start_index] + content[end_index + len(oce_constants.END_PGP_SIGNATURE):]

            # remove the extra characters added around the message itself
            content = content.replace('- {}'.format(oce_constants.BEGIN_PGP_MESSAGE), oce_constants.BEGIN_PGP_MESSAGE)
            content = content.replace('- {}'.format(oce_constants.END_PGP_MESSAGE), oce_constants.END_PGP_MESSAGE)

            return content

        try:
            if self.get_message().is_multipart():
                self.log_message('check each of {} parts of message for a signature'.format(
                    len(self.get_message().get_payload())))
                part_index = 0
                parts = self.get_message().get_payload()
                for part in parts:
                    part_index += 1
                    if isinstance(part, str):
                        content = part
                    else:
                        content = self._get_decoded_payload(part)
                    if self.contains_pgp_signature_delimeters(content):
                        charset, __ = get_charset(part)
                        self.log_message('set payload after removing sig with char set: {}'.format(charset))
                        part.set_payload(remove_signature(content), charset=charset)
                        self.log_message('extracted signature block from part {}'.format(part_index))

            else:
                content = self._get_decoded_payload(self.get_message())
                if isinstance(content, str) and self.contains_pgp_signature_delimeters(content):
                    charset, __ = get_charset(part)
                    self.get_message().set_payload(remove_signature(content), charset=charset)
                    self.log_message('extracted signature block from content with char set: {}'.format(charset))
        except:
            self.log_message('EXCEPTION see syr.exception.log')
            record_exception()

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
            if isinstance(output_file, IOBase):
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
            record_exception()
            raise Exception

        return result_ok


    def to_string(self, charset=None, mangle_from=False):
        '''
            Convert message to a string.

            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
            >>> filename = get_plain_message_name('basic.txt')
            >>> with open(filename) as input_file:
            ...     file_content = input_file.read().replace('\\r\\n', '\\n')
            ...     position = input_file.seek(os.SEEK_SET)
            ...     email_message = EmailMessage(input_file)
            ...     file_content.strip() == email_message.to_string().strip()
            True
        '''

        string = None

        try:
            msg = self._message
            if charset is None:
                charset, __ = get_charset(msg, self._last_charset)
                self.log_message('char set in to_string(): {}'.format(charset))

            #  convert the message
            try:
                file_pointer = StringIO()
                message_generator = Generator(file_pointer, mangle_from_=mangle_from, maxheaderlen=78)
                message_generator.flatten(msg)
                string = file_pointer.getvalue()
            except Exception as AttributeError:
                try:
                    self.log_message('unable to flatten message')
                    record_exception(AttributeError)

                    msg = self._message
                    string = msg.as_string()
                except Exception as AttributeError:
                    #  we explicitly want to catch everything here, even NPE
                    self.log_message('unable to convert message as_string')

                    string = '{}\n\n{}'.format(
                        '\n'.join(self.get_header_lines()),
                        '\n'.join(self.get_content_lines()))

                    if self.DEBUGGING: self.log_message("message string:\n{}".format(string))

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
        keys = self._message.keys()
        for key in keys:
            value = self.get_header(key)
            if value is None:
                value = ''
            raw_line = '{}: {}'.format(key, value)
            if len(raw_line) > max_line_length:

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
                lines = payloads.split('\n')
            else:
                for payload in payloads:
                    if isinstance(payload, Message):
                        lines += payload.as_string()
                    else:
                        lines += payload.split('\n')

        return lines

    def _parse_header_line(self, line, last_name):
        '''
            Parse a header line (internal user only).

            >>> email_message = EmailMessage()
            >>> name, value, last_name = email_message._parse_header_line(
            ...   'Mime-Version: 1.0', 'Subject')
            >>> name == 'Mime-Version'
            True
            >>> value == '1.0'
            True
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
                if isinstance(self.parser, Parser):
                    temp_header = self.parser.parsestr(test_message.as_string(unixfrom=False))
                else:
                    temp_header = self.parser.parsebytes(test_message.as_string(unixfrom=False).encode())
                if temp_header.__len__() == 0:
                    self.log_message('bad header: {}'.format(line))
                    self.bad_header_lines.append(line)
                else:
                    # if the parser accept this header line, then keep it
                    self.add_header(name, value)
            except Exception:
                record_exception()
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
                record_exception()
                self._message.set_charset(constants.DEFAULT_CHAR_SET)

        elif name == mime_constants.CONTENT_XFER_ENCODING_KEYWORD:
            encoding_value = self._message.get(
               mime_constants.CONTENT_XFER_ENCODING_KEYWORD)
            self.log_message('message encoding: {}'.format(encoding_value))
            if encoding_value is None or encoding_value.lower() != value.lower():
                self._message.__delitem__(name)
                self._message.__setitem__(name, value)
                self.log_message('set message encoding: {}'.format(value))

    def _get_decoded_payload(self, msg, decode=True):
        '''
            Get the payload and decode it if necessary.

            >>> email_message = EmailMessage()
            >>> email_message._get_decoded_payload(None)
        '''
        if msg is None:
            payload = None
        else:
            payload = msg.get_payload(decode=decode)

            if isinstance(payload, bytearray) or isinstance(payload, bytes):
                charset, __ = get_charset(msg, self._last_charset)
                self.log_message('decoding payload with char set: {}'.format(charset))
                try:
                    payload = payload.decode(encoding=charset)
                except:
                    payload = payload.decode(encoding=charset, errors='replace')


        return payload

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

        charset, __ = get_charset(self._message, self._last_charset)
        self.log_message('creating new body text with char set: {}'.format(charset))
        try:
            body_text = ''
            for line in body:
                body_text += line.encode(charset)
        except Exception as body_exception:
            self.log_message(body_exception)
            record_exception()
            body_text = ''.join(body)

        if len(self.bad_header_lines) > 0:
            body_text += '\n\n{}\n'.format(i18n('Removed bad header lines'))
            for bad_header_line in self.bad_header_lines:
                body_text += '  {}\n'.format(bad_header_line)

        self._message.set_payload(body_text, charset=charset)

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

            if isinstance(source, IOBase):
                source.seek(os.SEEK_SET)
                message_string = source.read()
            else:
                message_string = source

            body_text = self._create_new_header(message_string)
            if body_text:
                self._create_new_body_text(body_text)

        except Exception as message_exception:
            self.log_message(message_exception)
            record_exception()
            raise MessageException(message_exception)

    def init_new_message(self, from_addr, to_addr, subject, text=None):
        ''' Initialize a basic new message.

            Used primarily for testing.

            >>> # In honor of Kirk Wiebe, a whistleblower about Trailblazer, an NSA mass surveillance project.
            >>> from_user = 'kirk@goodcrypto.local'
            >>> to_user = 'kirk@goodcrypto.remote'
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
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'syr.exception.log'))
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
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'syr.exception.log'))
            True
            >>> email_message.log_exception('test', message_exception='message exception')
        '''

        record_exception()

        self.log_message(log_msg)
        record_exception(message=log_msg)

        if message_exception is not None:
            if type(message_exception) == Exception:
                self.log_message(message_exception.value)
                record_exception(message=message_exception.value)
            elif type(message_exception) == str:
                self.log_message(message_exception)
                record_exception(message=message_exception)

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

