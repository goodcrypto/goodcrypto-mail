'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-03

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, pickle, time
from random import choice

from goodcrypto.mail import contacts, options, user_keys
from goodcrypto.mail.constants import AUTO_GENERATED
from goodcrypto.mail.crypto_queue import queue_sync
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.message import constants
from goodcrypto.mail.utils import email_in_domain, is_multiple_encryption_active
from goodcrypto.mail.utils.notices import notify_user
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception

DEBUGGING = False

_log = None


def get_public_key_header_name(encryption_name):
    '''
        Get the public key header's name.

        >>> header_name = get_public_key_header_name('GPG')
        >>> header_name == 'X-OpenPGP-PublicKey'
        True
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
                if user_key is None:
                    contacts_crypto = contacts.get_contacts_crypto(email, encryption_name=encryption_software)
                    if contacts_crypto is None:
                        # a private user key will automatically be created
                        # when the contact's crypto record is created after the contact is created
                        contacts.add(email, encryption_software, source=AUTO_GENERATED)
                        log_message('add {} key for {}'.format(encryption_software, email))
                    else:
                        log_message('adding private {} user key for {}'.format(encryption_software, email))
                        sync_private_key_via_queue(contacts_crypto)

                elif user_key.contacts_encryption.fingerprint is None:
                    log_message('setting private {} key fingerprint for {}'.format(encryption_software, email))
                    sync_fingerprint_via_queue(user_key.contacts_encryption)
                else:
                    log_message('{} already has crypto software defined'.format(email))
            else:
                log_message('creating private key disabled so no key created for {}'.format(email))
        else:
            log_message('{} not a member of {}'.format(email, get_domain()))

    except Exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

def sync_private_key_via_queue(contacts_encryption):
    '''
        Sync the private key with the database via queue.

        >>> sync_private_key_via_queue(None)
    '''

    if contacts_encryption is not None:
        from goodcrypto.mail.sync_db_with_keyring import sync_private_key

        queue_sync(pickle.dumps(contacts_encryption), sync_private_key)

def sync_fingerprint_via_queue(contacts_encryption):
    '''
        Sync the fingerprint in database via queue.

        >>> sync_fingerprint_via_queue(None)
    '''

    if contacts_encryption is not None:
        from goodcrypto.mail.sync_db_with_keyring import sync_fingerprint

        queue_sync(pickle.dumps(contacts_encryption), sync_fingerprint)

def bounce_message(original_message, user, subject, error_message):
    '''
        Bounce a message that a local user.

        Test extreme case
        >>> bounce_message(None, None, None, None)
        False
    '''

    notified_user = False

    try:
        log_message(error_message)

        if user is None:
            log_message('unable to bounce message without a user email address')
        elif email_in_domain(user):
            message = '{}\n\n===================\n{}'.format(
              error_message, original_message)
            notified_user = notify_user(user, subject, message)
            log_message('sent note to {} about error.'.format(user))
        else:
            log_message('unable to send note to {} about error.'.format(user))
    except:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

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
        log_message('EXCEPTION - see syr.exception.log for details')

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
    try:
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
    except:
        log_message('EXCEPTION - See syr.exception.log')
        record_exception()

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

