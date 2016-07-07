'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-07-27

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, time
from random import choice
from django.contrib.auth.models import User

from goodcrypto.mail import contacts, crypto_software, options, user_keys
from goodcrypto.mail.contacts import get_contacts_crypto, get_fingerprint
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.message import constants 
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.model_signals import start_setting_fingerprint
from goodcrypto.mail.user_keys import create_user_key, get_passcode
from goodcrypto.mail.utils import email_in_domain, get_metadata_address
from goodcrypto.mail.utils.dirs import get_packet_directory, SafeDirPermissions
from goodcrypto.mail.utils.notices import notify_user
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.utils import get_email, i18n, parse_domain
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr import mime_constants
from syr.fs import get_unique_filename
from syr.message import send_mime_message

DEBUGGING = False
USE_SMTP_PROXY = False

_log = None
_tagline_delimiter = constants.TAGLINE_DELIMITER


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
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        
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

def map_line_endings(text):
    '''
        Map lines endings to a common format, \n.
        Since the only 2 formats of line endings we use are \r\n and \n, we simply strip \r.
        
        >>> map_line_endings('test message\\r\\n')
        'test message\\n'
    '''

    return text.replace('\r\n', '\n')

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
    address = get_email(email)

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
        header_name = '{}-{}'.format(constants.PUBLIC_KEY_HEADER, encryption_name)
    else:
        header_name = constants.PUBLIC_KEY_HEADER
        
    return header_name

def make_public_key_block(from_user, encryption_software=None):
    ''' 
        Make a public key block for the user.
        
        >>> make_public_key_block(None, None)
        []
    '''

    key_block = []
    if from_user is None:
        log_message('missing from user so cannot create key block')
    else:
        pub_key = None
        if encryption_software is None or len(encryption_software) <= 0:
            encryption_software = CryptoFactory.DEFAULT_ENCRYPTION_NAME

        try:
            key_ok, __, __ = contacts.is_key_ok(from_user, encryption_software)
            if key_ok:
                key_crypto = KeyFactory.get_crypto(encryption_software)
                pub_key = key_crypto.export_public(from_user)
            else:
                log_message('{} key is not valid for {}'.format(encryption_software, from_user))
        except CryptoException as crypto_exception:
            log_message(crypto_exception.value)

        if pub_key is None:
            log_message('no {} public key for {}'.format(encryption_software, from_user))
        else:
            # if there is a public key, then prepare if for the header
            header_name = get_public_key_header_name(encryption_software)
            log_message("getting {} public key header block for {} using header {}".format(
                encryption_software, from_user, header_name))

            count = 0
            for value in pub_key.split('\n'):
                count += 1
                key_block.append('{}-{}{}{}'.format(header_name, count, ': ', value))

    return key_block

def add_private_key(email, encryption_software=None):
    '''
        Add a private key if it doesn't exist.

        Creating a key takes minutes so a separate process handles it so no return code.

        >>> add_private_key(None)
    '''
    
    try:
        # only add private keys for members of the domain
        if email_in_domain(email):
            if options.create_private_keys():
                if encryption_software is None or len(encryption_software) <= 0:
                    encryption_software = CryptoFactory.DEFAULT_ENCRYPTION_NAME

                user_key = user_keys.get(email, encryption_software)
                if user_key is None or user_key.passcode is None:
                    log_message('creating private {} key for {}'.format(encryption_software, email))
                    create_user_key(email, encryption_software)
                elif user_key.contacts_encryption.fingerprint is None:
                    log_message('setting private {} key fingerprint for {}'.format(encryption_software, email))
                    start_setting_fingerprint(user_key.contacts_encryption)
                else:
                    log_message('{} already has crypto software defined'.format(email))
            else:
                log_message('creating private key disabled so no key created for {}'.format(email))
        else:
            log_message('{} not a member of {}'.format(email, get_domain()))

    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

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
        >>> set_tagline_delimiter(constants.TAGLINE_DELIMITER)
        >>> get_tagline_delimiter() == constants.TAGLINE_DELIMITER
        True
        >>> set_tagline_delimiter(tag_delimiter)
    '''
    global _tagline_delimiter

    return _tagline_delimiter

def get_metadata_user_details(email, encryption_name):
    '''
        Get the metadata address and key for the encryption program.
        
        >>> get_metadata_user_details(None, None)
        (False, None, None)
    '''

    metadata_address = None
    ok = False

    try:
        metadata_address = get_metadata_address(email=email)
        fingerprint, verified, active = get_fingerprint(metadata_address, encryption_name)
        if fingerprint is None:
            ok = False
            log_message('no fingerprint for {}'.format(metadata_address))
            # queue up to get the fingerprint
            start_setting_fingerprint(get_contacts_crypto(email, encryption_name=encryption_name))
        elif not active:
            ok = False
            log_message('{}  is not active'.format(metadata_address))
        elif options.require_key_verified() and not verified:
            ok = False
            log_message('{}  is not verified and verification required'.format(metadata_address))
        else:
            ok = True
    except:
        ok = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    if not ok:
        metadata_address = None

    return ok, metadata_address, fingerprint

def get_from_metadata_user_details(email, encryption_name):
    '''
        Get the metadata address and key for the encryption program.
        
        >>> get_from_metadata_user_details(None, None)
        (False, None, None)
    '''

    metadata_address = passcode = None
    ok = False

    try:
        ok, metadata_address, fingerprint = get_metadata_user_details(email, encryption_name)
        if ok:
            passcode = get_passcode(metadata_address, encryption_name)
            if passcode is None:
                ok = False
                log_message('no user key for {}'.format(metadata_address))
            else:
                ok = True
                log_message('ready to protect metadata using {}'.format(encryption_name))

        elif fingerprint is None:
            log_message('creating private {} key for {}'.format(encryption_name, email))
            create_user_key(email, encryption_name)
    except:
        ok = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    if not ok:
        metadata_address = passcode = None

    return ok, metadata_address, passcode

def packetize(crypto_message, encrypted_with, verification_code):
    ''' Packetize for later delivery. '''

    try:
        message_name = None
        domain = parse_domain(crypto_message.smtp_recipient())
        dirname = os.path.join(get_packet_directory(), '.{}'.format(domain))
        if not os.path.exists(dirname):
            os.mkdir(dirname, SafeDirPermissions)
            log_message('created packet queue for {}'.format(domain))
        crypto_message.set_processed(True)
        
        encrypted_names = ''
        if crypto_message.is_crypted():
            for encrypted_name in encrypted_with:
                if len(encrypted_names) > 0:
                    encrypted_names += ', '
                encrypted_names += encrypted_name
            log_message('queued message encrypted with: {}'.format(encrypted_names))
        message_name = get_unique_filename(dirname, constants.MESSAGE_PREFIX, constants.MESSAGE_SUFFIX)
        with open(message_name, 'wt') as f:
            f.write(crypto_message.get_email_message().to_string())
            f.write(constants.START_ADDENDUM)
            f.write('{}: {}\n'.format(mime_constants.FROM_KEYWORD, crypto_message.smtp_sender()))
            f.write('{}: {}\n'.format(mime_constants.TO_KEYWORD, crypto_message.smtp_recipient()))
            f.write('{}: {}\n'.format(constants.CRYPTED_KEYWORD, crypto_message.is_crypted()))
            f.write('{}: {}\n'.format(constants.CRYPTED_WITH_KEYWORD, encrypted_names))
            f.write('{}: {}\n'.format(constants.VERIFICATION_KEYWORD, verification_code))
            f.write(constants.END_ADDENDUM)
        log_message('packetized message filename: {}'.format(os.path.basename(message_name)))
    except:
        message_name = None
        crypto_message.set_processed(False)
        error_message = i18n('Unable to packetize message due to an unexpected error.')
        log_message(error_message)
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        record_exception()
        raise MessageException(value=error_message)

    return message_name

def parse_bundled_message(bundled_message):
    ''' 
        Parse a message that was bundled. 
        
        Test extreme cases.
        >>> message, addendum = parse_bundled_message(None)
        >>> message is None
        True
        >>> addendum[mime_constants.FROM_KEYWORD] is None
        True
    '''    
    addendum = {
       mime_constants.FROM_KEYWORD: None,
       mime_constants.TO_KEYWORD: None,
       constants.CRYPTED_KEYWORD: False,
       constants.CRYPTED_WITH_KEYWORD: [],
       constants.VERIFICATION_KEYWORD: None,
    }
    original_message = sender = recipient = crypted_with = None
    crypted = False
    try:
        # separate the original message from the addendum
        i = bundled_message.find(constants.START_ADDENDUM)
        if i > 0:
            msg = bundled_message[i:]
            original_message = bundled_message[:i]
        
        # get the sender
        i = msg.find(mime_constants.FROM_KEYWORD)
        if i > 0:
            sender = msg[i + len(mime_constants.FROM_KEYWORD + ': '):]
            i = sender.find('\n')
            addendum[mime_constants.FROM_KEYWORD] = sender[:i]
        
        # get the recipient
        i = msg.find(mime_constants.TO_KEYWORD)
        if i > 0:
            recipient = msg[i + len(mime_constants.TO_KEYWORD + ': '):]
            i = recipient.find('\n')
            addendum[mime_constants.TO_KEYWORD] = recipient[:i]
        
        # get the crypted status
        i = msg.find(constants.CRYPTED_KEYWORD)
        if i > 0:
            crypted = msg[i + len(constants.CRYPTED_KEYWORD + ': '):]
            i = crypted.find('\n')
            addendum[constants.CRYPTED_KEYWORD] = bool(crypted[:i])
        
        # get the programs the message was encrypted
        i = msg.find(constants.CRYPTED_WITH_KEYWORD)
        if i > 0:
            crypted_with = msg[i + len(constants.CRYPTED_WITH_KEYWORD + ': '):]
            i = crypted_with.find('\n')
            addendum[constants.CRYPTED_WITH_KEYWORD] = crypted_with[:i].split(', ')
        
        # get the verification code that was added to the message if it was encrypted
        i = msg.find(constants.VERIFICATION_KEYWORD)
        if i > 0:
            verification_code = msg[i + len(constants.VERIFICATION_KEYWORD + ': '):]
            i = verification_code.find('\n')
            addendum[constants.VERIFICATION_KEYWORD] = verification_code[:i].split(', ')
    except AttributeError as attribute_exception:
        # common error for "padding" parts of a bundled message
        log_message(attribute_exception)
    except UnboundLocalError as unbound_exception:
        # common error for "padding" parts of a bundled message
        log_message(unbound_exception)
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return original_message, addendum

def send_message(sender, recipient, message):
    ''' 
        Send a message. 

        The message can be a Message in string format or a "Message" class.
    '''

    try:
        log_message('starting to send message')
        if USE_SMTP_PROXY:
            result_ok, msg = send_mime_message(sender, recipient, message, use_smtp_proxy=USE_SMTP_PROXY,
              mta_address=options.mail_server_address(), mta_port=options.mta_listen_port())
        else:
            result_ok, msg = send_mime_message(sender, recipient, message)

        if DEBUGGING and result_ok:
            log_message('=================')
            log_message(msg)
            log_message('=================')
        log_message('finished sending message')
    except Exception as exception:
        result_ok = False
        log_message('error while sending message')
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        record_exception()

    return result_ok

def bounce_message(original_message, sender, subject, error_message):
    ''' 
        Bounce a message that a local user who originated it.
        
        Test extreme case
        >>> bounce_message(None, None, None, None)
        False
    '''

    notified_user = False

    try:
        log_message(error_message)

        if sender is None:
            log_message('unable to bounce message without a sender')
        elif email_in_domain(sender):
            message = '{}\n\n===================\n{}'.format(
              error_message, original_message)
            notified_user = notify_user(sender, subject, message)
            log_message('sent note to {} about error.'.format(sender))
        else:
            log_message('unable to send note to {} about error.'.format(sender))
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return notified_user

def drop_message(original_message, recipient, subject, error_message):
    ''' 
        Drop a message that we shouldn't process from a remote user. 
        
        Test extreme case
        >>> drop_message(None, None, None, None)
        False
    '''

    notified_user = False

    try:
        log_message(error_message)

        if recipient is None:
            log_message('unable to notify recipient about dropped message')
        elif email_in_domain(recipient):
            message = '{}\n\n===================\n{}'.format(
              error_message, original_message)
            notified_user = notify_user(recipient, subject, message)
            log_message('sent note to {} about error.'.format(recipient))
        else:
            log_message('unable to send note to {} about error.'.format(recipient))
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return notified_user

def get_message_id():
    ''' Get a unique message id. '''
    
    Chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.'
    
    random_chars = ''
    for i in range(10):
        random_chars += choice(Chars)

    timestamp = time.strftime('%Y%m%d%H%M%S', time.gmtime())
    message_id = '{}{}@{}'.format(random_chars, timestamp, get_domain())
    
    return message_id

def log_message_headers(original_message, tag='message headers'):
    '''
        Log the headers of a message.
    '''
    from goodcrypto.mail.message.crypto_message import CryptoMessage
    from goodcrypto.mail.message.email_message import EmailMessage

    if type(original_message) is CryptoMessage:
        message = original_message.get_email_message().get_message()
    elif type(original_message) is EmailMessage:
        message = original_message.get_message()
    else:
        message = original_message
    
    log_message(tag)
    for key in message.keys():
        log_message('{}: {}'.format(key, message.get(key)))

def log_crypto_exception(exception, message=None):
    '''
        Log the message to the local and Exception logs.
        
        >>> log_crypto_exception(Exception)
        
        >>> log_crypto_exception(Exception, 'exception message')
    '''
    if message is not None:
        log_message(message)
    
    if exception is not None:
        log_message("Crypto error: {}".format(exception))
        log_message(str(exception))
        record_exception(message=str(exception))

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

