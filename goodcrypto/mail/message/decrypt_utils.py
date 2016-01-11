'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-02-16

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from traceback import format_exc

from goodcrypto.mail import crypto_software
from goodcrypto.mail.contacts import is_key_ok
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.options import require_key_verified
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.open_pgp_analyzer import OpenPGPAnalyzer
from goodcrypto.utils import i18n
from goodcrypto.utils.log_file import LogFile
from syr.timestamp import Timestamp

DEBUGGING = True
USE_UTC = True
DEFAULT_CRYPTO = CryptoFactory.DEFAULT_ENCRYPTION_NAME
DECRYPTED_MESSAGE_TAG = '{}{}'.format(i18n('GoodCrypto: '), 
                                      i18n('received this message securely'))


_log = None


def add_tag_to_message(crypto_message):
    '''
        Add tag to a message.
        
        Test adding tags to text/plain
        >>> from goodcrypto.mail.message.crypto_message import CryptoMessage
        >>> from goodcrypto.mail.message.email_message import EmailMessage
        >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
        >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
        ...    crypto_message = CryptoMessage(EmailMessage(input_file))
        ...    crypto_message.set_crypted(True)
        ...    add_tag_to_message(crypto_message)
        ...    final_message_string = crypto_message.get_email_message().to_string()
        ...    final_message_string.strip().find('received this message securely') >= 0
        ...    final_message_string.strip().find('There still appears to be an extra protective layer.') >= 0
        ...    final_message_string.strip().find('<div><hr>') >= 0
        True
        True
        True
        False
    '''

    # update the tags
    tags, filtered = get_tags(crypto_message)
    if tags is None:
        log_message('No tags need to be added to message')
    else:
        tags_added = crypto_message.add_tag_to_message()
        log_message('Tags added to message: {}'.format(tags_added))
        if tags_added:
            log_message(tags)
            if DEBUGGING: log_message(crypto_message.get_email_message().to_string())

    return filtered

def get_tags(crypto_message):
    '''
        Get tags to add to message.
        
        >>> from goodcrypto.mail.message.crypto_message import CryptoMessage
        >>> from goodcrypto.mail.message.email_message import EmailMessage
        >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
        >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
        ...    crypto_message = CryptoMessage(EmailMessage(input_file))
        ...    crypto_message.set_crypted(True)
        ...    tags, filtered = get_tags(crypto_message)
        ...    tags.find('received this message securely') >= 0
        ...    filtered
        True
        True
    '''

    tags = None
    filtered = False

    try:
        if crypto_message.is_crypted():
            log_message("crypted: {}".format(crypto_message.is_crypted()))
            analyzer = OpenPGPAnalyzer()
            content = crypto_message.get_email_message().get_content()
            crypto_message.add_prefix_to_tag_once(get_decrypt_tag())
            if analyzer.is_encrypted(content):
                crypto_message.add_tag_once(i18n('There still appears to be an extra protective layer.'))
                if not DEBUGGING: log_message("message:\n{}".format(crypto_message.get_email_message().to_string()))

        #  if we have something to say, it's still been filtered
        if crypto_message.get_tag() != None and not crypto_message.is_filtered():
            crypto_message.set_filtered(True)
        log_message("filtered: {}".format(crypto_message.is_filtered()))
        if DEBUGGING:
            log_message("message:\n{}".format(crypto_message.get_email_message().to_string()))
        
        tags = crypto_message.get_tag()
        filtered = crypto_message.is_filtered()
                
    except Exception:
        log_message(format_exc())

    return tags, filtered

def get_decrypt_tag():
    '''
        Get the decrypt tag.
        
        >>> from goodcrypto.mail.message.crypto_message import CryptoMessage
        >>> from goodcrypto.mail.message.email_message import EmailMessage
        >>> from goodcrypto_tests.mail.message_utils import get_encrypted_message_name
        >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
        ...    crypto_message = CryptoMessage(EmailMessage(input_file))
        ...    tag = get_decrypt_tag()
        ...    tag.find('received this message securely') >= 0
        True
    '''

    return DECRYPTED_MESSAGE_TAG

def check_signature(email, crypto_message, encryption_name=DEFAULT_CRYPTO, crypto=None):
    '''
        Check the signature if message is signed.
        
        >>> # In honor of Mike Perry, Tor Browser and Tor Performance developer.
        >>> from goodcrypto.mail.message.crypto_message import CryptoMessage
        >>> from goodcrypto.mail.message.email_message import EmailMessage
        >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
        >>> with open(get_plain_message_name('pgp-sig-unknown.txt')) as input_file:
        ...    email = 'mike@goodcrypto.remote'
        ...    crypto_message = CryptoMessage(EmailMessage(input_file))
        ...    check_signature(email, crypto_message, encryption_name=DEFAULT_CRYPTO)
        ...    crypto_message.get_tag()
        'This message was clear signed by an unknown user.'
    '''
    
    def verify_signature(email, signature_blocks, encryption_name=DEFAULT_CRYPTO):
        ''' Verify the signature if message is signed. '''
    
        key_verified = False
        
        # if the message is signed, then verify the signature
        if len(signature_blocks) > 0:
            crypto = CryptoFactory.get_crypto(encryption_name, crypto_software.get_classname(encryption_name))
            log_message('checking if message signed by {}'.format(email))
            for signature_block in signature_blocks:
                if crypto.verify(signature_block, email):
                    # make sure that the key for the sender is ok; if it's not, a CryptoException is thrown
                    __, key_verified = is_key_ok(email, encryption_name)
                    log_message('{} signed message'.format(email))
                    log_message('{} {} key pinned'.format(email, encryption_name))
                    log_message('{} {} key verified: {}'.format(email, encryption_name, key_verified))
                else:
                    log_message('signature block\n{}'.format(signature_block))
                    signer = crypto.get_signer(signature_block)
                    if signer is None:
                        error_message = i18n('This message was clear signed by an unknown user.')
                        log_message(error_message)
                        raise MessageException(error_message)
                    else:
                        error_message = i18n('This message was not clear signed by the sender {email}, but by {signer}.'.format(
                            email=email, signer=signer))
                        log_message(error_message)
                        raise CryptoException(error_message)
        else:
            log_message('message not signed')
            
        return key_verified


    # if the message is signed, then verify the signature
    signature_blocks = crypto_message.get_email_message().get_pgp_signature_blocks()
    if len(signature_blocks) > 0:
        try:
            key_verified = verify_signature(email, signature_blocks, encryption_name=encryption_name)
            if key_verified or not require_key_verified():
                # Translator: Do not alter {email} simply move it wherever would be appropriate in the sentence.
                crypto_message.add_tag_once(i18n('This message was clear signed by {email}.'.format(email=email)))
            else:
                crypto_message.add_tag_once(i18n('This message appears to be clear signed by {email}, but the key has not been verified.'.format(email=email)))
        except MessageException as message_exception:
            crypto_message.add_tag_once(message_exception.value)
    else:
        log_message('no signature block found in this part of message')
        if DEBUGGING:
            log_message('crypto message:\n{}'.format(crypto_message.get_email_message().to_string()))

def log_message(message):
    '''
        Log a message.

        >>> import os
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.decrypt_utils.log'))
        True
    '''
    global _log
    
    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

