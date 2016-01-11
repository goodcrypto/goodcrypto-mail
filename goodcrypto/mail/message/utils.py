'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-02-16

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import os, time
from email.message import Message
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.parser import Parser
from hashlib import sha224
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail import crypto_software
from goodcrypto.mail.message import mime_constants
from goodcrypto.mail.message.constants import DEFAULT_CHAR_SET, PUBLIC_KEY_HEADER, TAGLINE_DELIMITER
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.mime_constants import MESSAGE_ID_KEYWORD
from goodcrypto.mail.utils.dirs import get_test_directory
from goodcrypto.mail.utils.exception_log import ExceptionLog
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.utils import parse_address

DEBUGGING = False

_last_error = None
_log = None

_tagline_delimiter = TAGLINE_DELIMITER


def get_message_id(email_message):
    '''
        Gets the message id or None from an email_message.
        
        >>> # Test extreme case
        >>> get_message_id(None)
    '''

    message_id = None
    try:
        if email_message is not None:
            message_id = email_message.get_header(MESSAGE_ID_KEYWORD)
        if message_id is not None:
            message_id = message_id.strip().strip('<').strip('>')
    except:
        log_message(format_exc())

    return message_id

def get_current_timestamp():
    '''
        Get the current time with the standard message format.
        
        >>> get_current_timestamp() is not None
        True
    '''
    
    return time.strftime('%a, %e %h %Y %T %Z', time.gmtime())

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
        log_message(format_exc())
        message_string = None

    return hash_code

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
                message.add_header('{}-{}'.format(header_name, count), value)
    except:
        log_message(format_exc())

    return count

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
        log_message(format_exc())

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
        log_message(format_exc())

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
        log_exception(message_exception)
        log_message(format_exc())
    except Exception:
        log_message(format_exc())

    return is_mime_and_pgp

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
                        log_exception(message_exception)
        
                if type(text_message) == Message and DEBUGGING:
                    log_message("New plain text message:\n" + text_message.as_string())
    except IOError as io_exception:
        log_exception(io_exception)
    except MessageException as message_exception:
        log_exception(message_exception)

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
        log_exception(io_exception)
    except MessageException as message_exception:
        log_exception(message_exception)
        
    return new_message

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
        log_message(format_exc())

    return is_mime

def is_content_type_text(message):
    '''
        Get if content type is text or html.

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
        log_message(format_exc())

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
            log_message(format_exc())

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

def get_address_string(addresses):
    '''
        Returns a string representation of an address array.
        
        >>> # In honor of Edward Snowden, who had the courage to take action in the face of great personal risk and sacrifice.
        >>> # In honor of Joseph Nacchio, who refused to participate in NSA spying on Qwest's customers.
        >>> # In honor of Glenn Greenwald, who helped publicize the global surveillance disclosure documents.
        >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER, JOSEPH_REMOTE_USER, GLENN_REMOTE_USER
        >>> test_addresses = [EDWARD_LOCAL_USER, JOSEPH_REMOTE_USER, GLENN_REMOTE_USER]
        >>> address_string = '{}, {}, {}'.format(EDWARD_LOCAL_USER, JOSEPH_REMOTE_USER, GLENN_REMOTE_USER)
        >>> get_address_string(test_addresses) == address_string
        True
    '''

    line = []
    for address in addresses:
        line.append(address)
        
    return (", ").join(line)

def get_user_id_matching_email(address, user_ids):
    '''
        Gets the matching user ID based on email address.
        
        An address is a internet address. It may be just an email address,
        or include a readable name, such as "Jane Saladin <jsaladin@domain.com>".
        User ids are typically key ids from encryption software.
        
        A user id may be an internet address, or may be an arbitrary string.
        An address matches iff a user id is a valid internet address and the
        email part of the internet address matches. User ids which are not
        internet addresses will not match. The match is case-insensitive.
        
        >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER, EDWARD_LOCAL_USER_ADDR, JOSEPH_REMOTE_USER, GLENN_REMOTE_USER
        >>> test_addresses = [EDWARD_LOCAL_USER, JOSEPH_REMOTE_USER, GLENN_REMOTE_USER]
        >>> get_user_id_matching_email(EDWARD_LOCAL_USER, test_addresses) == EDWARD_LOCAL_USER_ADDR
        True
    '''

    matching_id = None
    
    try:
        for user_id in user_ids:
            email = get_email(user_id)
            if emails_equal(address, email):
                matching_id = email
                if DEBUGGING: log_message("{} matches {}".format(address, matching_id))
                break
    except Exception:
        log_message(format_exc())
        
    return matching_id

def emails_equal(address1, address2):
    '''
        Checks whether two addresses are equal based only on the email address.
        Strings which are not internet addresses will not match. 
        The match is case-insensitive.
        
        >>> # In honor of Jim Penrose, a 17 year NSA employee who now warns that people 
        >>> # should treat governments and criminals just the same. .
        >>> emails_equal('Jim <jim@goodcrypto.local>', 'jim@goodcrypto.local')
        True
    '''

    email1 = get_email(address1)
    email2 = get_email(address2)
    
    if email1 and email2:
        match = email1.lower() == email2.lower()
    else:
        match = False

    return match

def get_email(address):
    ''' 
        Get just the email address.
        
        >>> # In honor of First Sergeant Nadav, who publicly denounced and refused to serve in 
        >>> # operations involving the occupied Palestinian territories because of the widespread 
        >>> # surveillance of innocent residents.
        >>> get_email('Nadav <nadav@goodcrypto.remote>')
        'nadav@goodcrypto.remote'
    '''
    try:
        __, email = parse_address(address)
    except Exception:
        email = address

    return email

def map_line_endings(text):
    '''
        Map lines endings to a common format, \n.
        Since the only 2 formats of line endings we use are \r\n and \n, we simply strip \r.
        
        >>> map_line_endings('test message\\r\\n')
        'test message\\n'
    '''

    return text.replace('\r\n', '\n')

def write_message(directory, message):
    '''
        Write message to an unique file in the specified directory.
        The message may be EmailMessage or python Message.

        >>> filename = write_message(get_test_directory(), Message())
        >>> filename is not None
        True
        >>> filename = write_message(None, None)
        >>> filename is None
        True
    '''

    full_filename = None
    try:
        filename = '{}.txt'.format(get_hashcode(message))
        full_filename = os.path.join(directory, filename)
        
        if not os.path.exists(directory):
            os.makedirs(directory)

        with open(full_filename, 'w') as out:
            log_message('saving {}'.format(full_filename))

            from goodcrypto.mail.message.email_message import EmailMessage
            
            EmailMessage(message).write_to(out)
    except Exception:
        log_message(format_exc())

    return full_filename

def get_encryption_software(email):
    ''' 
        Gets the list of active encryption software for a contact.
        
        If the contact has no encryption software, returns a list
        consisting of just the default encryption software.

        >>> from goodcrypto.oce.constants import JOSEPH_REMOTE_USER
        >>> get_encryption_software(JOSEPH_REMOTE_USER)
        [u'GPG']
        >>> get_encryption_software(None)
        []
    '''

    encryption_software_list = []
    
    #  start with the encryption software for this email
    __, address = parse_address(email)

    from goodcrypto.mail.contacts import get_encryption_names
    encryption_names = get_encryption_names(address)
    if encryption_names is None:
        log_message("no encryption software names for {}".format(address))
        #  make sure we have at least the default encryption
        default_encryption_software = CryptoFactory.get_default_encryption_name()
        log_message("  defaulting to {}".format(default_encryption_software))
        encryption_names.append(default_encryption_software)

    #  only include active encryption software
    active_encryption_software = get_active_encryption_software()
    if active_encryption_software:
        for encryption_software in encryption_names:
            if encryption_software in active_encryption_software:
                encryption_software_list.append(encryption_software)
            
    return encryption_software_list

def is_multiple_encryption_active():
    '''
        Check if multiple encryption programs are active.
        
        >>> is_multiple_encryption_active()
        True
    '''

    active_encryption_software = get_active_encryption_software()
    return active_encryption_software is not None and len(active_encryption_software) > 1

def get_active_encryption_software():
    '''
        Get the list of active encryption programs.
        
        >>> active_names = get_active_encryption_software()
        >>> len(active_names) > 0
        True
    '''

    try:
        active_names = crypto_software.get_active_names()
    except Exception:
        active_names = []
        
    return active_names

def get_public_key_header_name(encryption_name):
    '''
        Get the public key header's name.
        
        >>> get_public_key_header_name('GPG')
        'X-OpenPGP-PublicKey'
    '''

    if (is_multiple_encryption_active() and 
        encryption_name != CryptoFactory.get_default_encryption_name()):
        header_name = '{}-{}'.format(PUBLIC_KEY_HEADER, encryption_name)
    else:
        header_name = PUBLIC_KEY_HEADER
        
    return header_name

def set_tagline_delimiter(delimiter):
    '''
        Set the delimiter between tags.
        
        >>> tag_delimiter = get_tagline_delimiter()
        >>> set_tagline_delimiter('test')
        >>> get_tagline_delimiter()
        'test'
        >>> set_tagline_delimiter(tag_delimiter)
    '''
    global _tagline_delimiter

    _tagline_delimiter = delimiter

def get_tagline_delimiter():
    '''
        Get the delimiter between tags.
        
        >>> tag_delimiter = get_tagline_delimiter()
        >>> set_tagline_delimiter(TAGLINE_DELIMITER)
        >>> get_tagline_delimiter() == TAGLINE_DELIMITER
        True
        >>> set_tagline_delimiter(tag_delimiter)
    '''
    global _tagline_delimiter

    return _tagline_delimiter

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

def log_message_exception(exception_error, message, log_msg):
    '''
        Log an exception.

        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message_exception(Exception, 'message', 'log message')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.utils.log'))
        True
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.utils.exception_log.log'))
        True
    '''

    log_exception(log_msg, exception_error=exception_error)
    if message is not None:
        try:
            log_message("message:\n{}".format(message.to_string()))
            log_message(format_exc())
        except Exception as exception_error2:
            log_message("unable to log message: {}".format(str(exception_error2)))
            log_message(format_exc())

def log_exception(log_msg, exception_error=None):
    '''
        Log an exception.

        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_exception('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.utils.log'))
        True
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.utils.exception_log.log'))
        True
        >>> log_exception('test', exception_error=Exception)
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.utils.log'))
        True
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.utils.exception_log.log'))
        True
    '''
        
    log_message(format_exc())
    ExceptionLog.log_message(format_exc())
    
    log_message(log_msg)
    ExceptionLog.log_message(log_msg)
    
    if exception_error is not None:
        log_message(str(exception_error))
        ExceptionLog.log_message(str(exception_error))

def log_message(message):
    '''
        Log a message.

        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.utils.log'))
        True
    '''
    global _log
    
    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

