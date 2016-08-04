'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-11-28

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import Parser

from goodcrypto.mail.message.inspect_utils import get_charset, get_multientry_header
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr import mime_constants

DEBUGGING = False

_last_error = None
_log = None

def add_multientry_header(message, header_name, multiline_value):
    '''
        Add a multiline header value as one line per header entry.

        Each line of the header value is added as a separate entry in
        the message header. This makes it less likely a message system will
        unexpectedly split a long string. The header name plus a dash and line
        number is used for each line's header entry. Although messages can have
        more than one header with the same name, this assures that the line
        order is significant.

        Example:
        <verbatim>
          Header-Name-1: first line of header value
          Header-Name-2: second line of header value
          Header-Name-3: third line of header value
          ...
        </verbatim>

        A trailing newline may be stripped.

        >>> # Test extreme case
        >>> add_multientry_header(None, None, 'Header-Name')
        1
        >>> # Test extreme case
        >>> add_multientry_header(None, None, None)
        0
    '''

    count = 0
    try:
        if multiline_value:
            for value in multiline_value.split('\n'):
                count += 1
                if message is not None:
                    message.add_header('{}-{}'.format(header_name, count), value)
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return count

def alt_to_text_message(original_message):
    '''
        Change a MIME message into a plain text Message.

        >>> # Test extreme cases
        >>> alt_to_text_message(None) == None
        True
    '''

    text_message = None

    try:
        if original_message:
            content_type = original_message.get_content_type()
            charset, __ = get_charset(original_message)
            log_message("message content type is {}".format(content_type))

            if content_type == mime_constants.MULTIPART_ALT_TYPE:
                plain_text = ''
                for part in original_message.walk():
                    if part.get_content_type() == mime_constants.TEXT_PLAIN_TYPE:
                        if len(plain_text) > 0:
                            plain_text += '\n\n'
                        plain_text += part.get_payload()
                        content_type = part.get_content_type()
                        charset, __ = get_charset(part)
                        log_message("part content type is {}".format(content_type))
                        log_message("part charset is {}".format(charset))

                if len(plain_text) > 0:
                    try:
                        # create a fresh message with the same headers
                        # we'll change some headers and all of the body
                        text_message = MIMEText(plain_text, mime_constants.PLAIN_SUB_TYPE, charset)
                        for key in original_message.keys():
                            if key != mime_constants.CONTENT_TYPE_KEYWORD:
                                text_message.__setitem__(key, original_message.get(key))
                        text_message.set_payload(plain_text, charset)
                    except MessageException as message_exception:
                        record_exception(message=message_exception)

                if type(text_message) == Message and DEBUGGING:
                    log_message("New plain text message:\n" + text_message.as_string())
    except IOError as io_exception:
        record_exception(message=io_exception)
    except MessageException as message_exception:
        record_exception(message=message_exception)

    return text_message

def plaintext_to_message(old_message, plaintext):
    '''
        Create a new Message with only the plain text.


        >>> # Test extreme cases
        >>> plaintext_to_message(None, None) == None
        True
     '''
    new_message = None

    try:
        if old_message and plaintext:
            parser = Parser()
            plain_message = parser.parsestr(plaintext)
            payloads = plain_message.get_payload()
            if isinstance(payloads, list):
                new_message = MIMEMultipart(old_message.get_content_subtype(), old_message.get_boundary())
            else:
                new_message = MIMEText(plain_message.get_payload())

            # save all the headers
            for key, value in old_message.items():
                new_message.add_header(key, value)

            if type(payloads) == list:
                for payload in payloads:
                    new_message.attach(payload)

            # add the content type and encoding from the plain text
            for key, value in plain_message.items():
                if key.lower() == mime_constants.CONTENT_TYPE_KEYWORD.lower():
                    new_message.__delitem__(key)
                    new_message.add_header(key, value)

                elif key.lower() == mime_constants.CONTENT_XFER_ENCODING_KEYWORD.lower():
                    new_message.__delitem__(key)
                    new_message.add_header(key, value)

            if type(new_message) == Message and DEBUGGING:
                log_message('new message:\n{}'.format(new_message.as_string()))

    except IOError as io_exception:
        record_exception(message=io_exception)
    except MessageException as message_exception:
        record_exception(message=message_exception)

    return new_message

def log_message(message):
    '''
        Log a message.

        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.adjust.log'))
        True
    '''
    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

