'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-06-08

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from hashlib import sha224

from goodcrypto.mail.message.constants import DEFAULT_CHAR_SET
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr import mime_constants

DEBUGGING = False

_last_error = None
_log = None

def get_message_id(email_message):
    '''
        Gets the message id or None from an email_message.
        
        >>> # Test extreme case
        >>> get_message_id(None)
    '''

    message_id = None
    try:
        if email_message is not None:
            message_id = email_message.get_header(mime_constants.MESSAGE_ID_KEYWORD)
        if message_id is not None:
            message_id = message_id.strip().strip('<').strip('>')
    except:
        record_exception()

    return message_id

def get_hashcode(message):
    '''
        Gets a hashcode for a message.
        
        >>> from goodcrypto_tests.mail import message_utils
        >>> filename = message_utils.get_plain_message_name('basic.txt')
        >>> with open(filename) as input_file:
        ...     get_hashcode(input_file) is not None
        True
    '''

    hash_code = None
    try:
        from goodcrypto.mail.message.email_message import EmailMessage

        message_string = EmailMessage(message).to_string()
        if message_string == None:
            if isinstance(get_last_error(), Exception):
                raise MessageException("Invalid message")
            else:
                raise MessageException("Invalid message: {}".format(get_last_error()))
        else:
            hash_code = sha224(message_string).hexdigest().upper()
    except Exception as hash_exception:
        set_last_error(hash_exception)
        record_exception()
        message_string = None

    return hash_code

def get_multientry_header(message, header_name):
    '''
        Gets a multientry header value.
        
        A trailing newline may be stripped.
        
        >>> # Test extreme case
        >>> get_multientry_header(None, None)
        ''
    '''

    value = None
    
    try:
        lines = []
        count = 1
    
        line = get_first_header(message, '{}-{}'.format(header_name, count))
        while line != None:
            lines.append(line)
    
            count = count + 1
            line = get_first_header(message, '{}-{}'.format(header_name, count))
    
        value = '\n'.join(lines)
        log_message("{} header: {}".format(header_name, value))
    except:
        record_exception()

    return value.strip()

def get_first_header(message, header_name):
    '''
        Gets the first, usually the only, matching header value.
        
        Python's email.message.get_all() returns an array of header values.
        Almost always there is only one element in the array.
        This method returns the first element of the header array.
        Extra values are logged.
        
        >>> # Test extreme case
        >>> get_first_header(None, None)
    '''

    value = None
    try:
        lines = message.get_all(header_name)
        if lines is not None and len(lines) > 0:
            value = lines[0]
            if len(lines) > 1:
                for line in lines:
                    log_message("For header {} got an unexpected line: {}".format(header_name, line))
    
        if value != None:
            value = value.strip()
    except:
        record_exception()

    return value

def is_multipart_message(message):
    '''
        Returns whether message is a multipart MIME message.
        
        Messages with a text/plain MIME type are considered plain text.

        >>> # Test extreme case
        >>> is_multipart_message(None)
        False
    '''

    from goodcrypto.mail.message.email_message import EmailMessage

    if message is None:
        multipart = False
    elif type(message) == EmailMessage:
        multipart = message.get_message().is_multipart()
    else:
        multipart = message.is_multipart()
        
    return multipart

def is_open_pgp_mime(message):
    '''
        Returns true if this is an OpenPGP MIME message.

        >>> from goodcrypto.mail.message.email_message import EmailMessage
        >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
        >>> with open(get_encrypted_message_name('open-pgp-mime.txt')) as input_file:
        ...     mime_message = EmailMessage(input_file)
        ...     is_open_pgp_mime(mime_message.get_message())
        True
    '''

    is_mime_and_pgp = False

    try:
        from goodcrypto.mail.message.email_message import EmailMessage

        if isinstance(message, EmailMessage):
            message = message.get_message()

        # the content type is always lower case and always has a value
        content_type = message.get_content_type()
        log_message("main content type: {}".format(content_type))
        
        #  if the main type is multipart/encrypted
        if content_type == mime_constants.MULTIPART_ENCRYPTED_TYPE:
            protocol = message.get_param(mime_constants.PROTOCOL_KEYWORD)
            if protocol == None:
                log_message("multipart encrypted, protocol missing")
            else:
                log_message("multipart encrypted protocol: {}".format(protocol))
                is_mime_and_pgp = str(protocol).lower() == mime_constants.PGP_TYPE.lower()

    except MessageException as message_exception:
        log_message(message_exception)
        record_exception(message=message_exception)
    except Exception:
        record_exception()

    return is_mime_and_pgp

def is_content_type_mime(message):
    '''
        Get if content type is mime multipart.
        
        >>> from email.mime.multipart import MIMEMultipart
        >>> message = MIMEMultipart(mime_constants.ENCRYPTED_SUB_TYPE, '==bound')
        >>> is_content_type_mime(message)
        True
    '''

    is_mime = False
    try:
        content_type = message.get_content_type()
        if content_type is not None:
            is_mime = content_type.lower().startswith(mime_constants.MULTIPART_PRIMARY_TYPE)
    except Exception:
        record_exception()

    return is_mime

def is_content_type_text(message):
    '''
        Get if content type is text or html.

        >>> from email.mime.text import MIMEText
        >>> message = MIMEText('Text', mime_constants.PLAIN_SUB_TYPE)
        >>> is_content_type_text(message)
        True
    '''

    is_text = False
    try:
        content_type = message.get_content_type()
        if content_type is not None:
            is_text = content_type.lower().startswith(mime_constants.TEXT_PRIMARY_TYPE)
    except Exception:
        record_exception()

    return is_text

def get_charset(part, last_charset=DEFAULT_CHAR_SET):
    '''
        Gets the charset.

        >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
        >>> email_message = get_basic_email_message()
        >>> get_charset(email_message.get_message())
        ('utf-8', 'utf-8')
    '''

    def find_char_set(part):

        charset = None
        try:
            if part.find(mime_constants.CONTENT_TYPE_KEYWORD) >= 0:
                index = part.find(mime_constants.CONTENT_TYPE_KEYWORD)
                line = part[index + len(mime_constants.CONTENT_TYPE_KEYWORD):]
                log_message('index: {}'.format(index))
                log_message('line: {}'.format(line))
                
                index = line.lower().find('charset=')
                if index > 0:
                    charset = line[index + len('charset='):]
                if charset.find('\r'):
                    charset = charset[:charset.find('\r')]
                elif charset.find('\n'):
                    charset = charset[:charset.find('\n')]
                log_message('charset: {}'.format(charset))
        except Exception as char_exception:
            log_message(char_exception)
            record_exception()

        if charset is None:
            charset = DEFAULT_CHAR_SET
            log_message('using default charset: {}'.format(charset))

        return charset


    try:
        charset = None
        last_character_set = last_charset

        if isinstance(part, str):
            log_message('looking for charset in string: {}'.format(len(part)))
            charset = find_char_set(part)
        else:
            from goodcrypto.mail.message.email_message import EmailMessage

            if isinstance(part, EmailMessage):
                part = part.get_message()
            log_message('looking for charset in Message')
            charset = part.get_charset()
            if charset is None:
                log_message('looking for charset in param')
                charset = part.get_param('charset')

        # if unknown than use the last charset
        if charset is None:
            charset = last_character_set
            log_message('using last charset')

        # if still unknown than use the default
        if charset is None:
            charset = DEFAULT_CHAR_SET
            log_message('using default charset')
        
        # the charset should be string
        charset = str(charset)
        
        # remember the last char set used
        last_character_set = charset

    except MessageException as message_exception:
        charset = DEFAULT_CHAR_SET
        log_message(message_exception)
    
    log_message('{} charset / {} last char set'.format(charset, last_character_set))
    
    return charset, last_character_set

def get_last_error():
    '''
        Get the last error.
        
        >>> set_last_error('test')
        >>> get_last_error()
        'test'
    '''

    global _last_error
    
    return _last_error

def set_last_error(new_error):
    '''
        Set the last error.
        
        >>> set_last_error('test')
        >>> get_last_error()
        'test'
    '''

    global _last_error
    
    _last_error = new_error

def log_message(message):
    '''
        Log a message.

        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.inspect_utils.log'))
        True
    '''
    global _log
    
    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

