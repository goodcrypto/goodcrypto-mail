'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail import crypto_software, international_strings
from goodcrypto.mail.contacts import is_key_ok
from goodcrypto.mail.messages.message_exception import MessageException
from goodcrypto.mail.options import get_validation_code, set_validation_code
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from syr.timestamp import Timestamp

DEBUGGING = False
USE_UTC = True
DEFAULT_CRYPTO = CryptoFactory.DEFAULT_ENCRYPTION_NAME

_log = None


def add_tag_to_message(crypto_message):
    '''
        Add tag to a message.
        
        Test adding tags to text/plain
        >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
        >>> from goodcrypto.mail.messages.email_message import EmailMessage
        >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
        >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
        ...    crypto_message = CryptoMessage(EmailMessage(input_file))
        ...    crypto_message.set_crypted(True)
        ...    add_tag_to_message(crypto_message)
        ...    final_message_string = crypto_message.get_email_message().to_string()
        ...    final_message_string.strip().find('received this message securely, but') >= 0
        ...    final_message_string.strip().find('<div><hr>') >= 0
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

    return filtered

def get_tags(crypto_message):
    '''
        Get tags to add to message.
        
        >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
        >>> from goodcrypto.mail.messages.email_message import EmailMessage
        >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
        >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
        ...    crypto_message = CryptoMessage(EmailMessage(input_file))
        ...    crypto_message.set_crypted(True)
        ...    original_validation_code = get_validation_code()
        ...    set_validation_code(None)
        ...    tags, filtered = get_tags(crypto_message)
        ...    tags.find('received this message securely') >= 0
        ...    tags.find('Validation: magic code') >= 0
        ...    filtered
        ...    set_validation_code(original_validation_code)
        True
        False
        True
    '''

    DECRYPTED_MESSAGE_TAG = '{}{}'.format(
       international_strings.GOODCRYPTO_PREFIX, international_strings.SECURE_MESSAGE_TAG)

    tags = None
    filtered = False

    try:
        if crypto_message.is_crypted():
            log_message("crypted: {}".format(crypto_message.is_crypted()))
            if crypto_message.get_email_message().is_probably_pgp():
                crypto_message.add_prefix_to_tag('{}, {}'.format(
                    DECRYPTED_MESSAGE_TAG, international_strings.STILL_ENCRYPTED_MESSAGE_TAG))
            else:
                crypto_message.add_prefix_to_tag('{}.'.format(DECRYPTED_MESSAGE_TAG))

        #  if we have something to say, it's still been filtered
        if crypto_message.get_tag() != None and not crypto_message.is_filtered():
            crypto_message.set_filtered(True)
        log_message("filtered: {}".format(crypto_message.is_filtered()))
        if DEBUGGING:
            log_message("message:\n{}".format(crypto_message.get_email_message().to_string()))
        
        #  if it's filtered, add the validation tag if appropriate
        if crypto_message.is_filtered():
            try:
                validation_tag = get_validation_tag()
                if validation_tag is not None and len(validation_tag) > 0:
                    crypto_message.add_tag_once('{}{}'.format(
                        international_strings.GOODCRYPTO_PREFIX, validation_tag))
            except Exception:
                log_message(format_exc())

        tags = crypto_message.get_tag()
        filtered = crypto_message.is_filtered()
                
    except Exception:
        log_message(format_exc())

    return tags, filtered

def check_signature(email, crypto_message, encryption_name=DEFAULT_CRYPTO, crypto=None):
    '''
        Check the signature if message is signed.
        
        >>> # In honor of Mike Perry, Tor Browser and Tor Performance developer.
        >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
        >>> from goodcrypto.mail.messages.email_message import EmailMessage
        >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
        >>> with open(get_plain_message_name('pgp-sig-unknown.txt')) as input_file:
        ...    email = 'mike@goodcrypto.remote'
        ...    crypto_message = CryptoMessage(EmailMessage(input_file))
        ...    check_signature(email, crypto_message, encryption_name=DEFAULT_CRYPTO)
        ...    crypto_message.get_tag()
        'This message was signed by an unknown user.'
    '''
    
    def verify_signature(email, signature_blocks, encryption_name=DEFAULT_CRYPTO):
        ''' Verify the signature if message is signed. '''
    
        # if the message is signed, then verify the signature
        if len(signature_blocks) > 0:
            crypto = CryptoFactory.get_crypto(encryption_name, crypto_software.get_classname(encryption_name))
            log_message('checking if message signed by {}'.format(email))
            for signature_block in signature_blocks:
                if crypto.verify(signature_block, email):
                    # make sure that the key for the sender is ok; if it's not, a CryptoException is thrown
                    is_key_ok(email, encryption_name)
                    log_message('{} signed message'.format(email))
                    log_message('{} {} key pinned'.format(email, encryption_name))
                else:
                    log_message('signature block\n{}'.format(signature_block))
                    signer = crypto.get_signer(signature_block)
                    if signer is None:
                        error_message = international_strings.UNKNOWN_SIGNER
                        log_message(error_message)
                        raise MessageException(error_message)
                    else:
                        error_message = international_strings.WRONG_SIGNER.format(email, signer)
                        log_message(error_message)
                        raise CryptoException(error_message)
        else:
            log_message('message not signed')


    # if the message is signed, then verify the signature
    signature_blocks = crypto_message.get_email_message().get_pgp_signature_blocks()
    if len(signature_blocks) > 0:
        try:
            verify_signature(email, signature_blocks, encryption_name=encryption_name)
            crypto_message.add_tag_once(international_strings.SIGNED_BY_TAG.format(email))
        except MessageException as message_exception:
            crypto_message.add_tag_once(message_exception.value)
    else:
        log_message('no signature block found in this part of message')
        if DEBUGGING:
            log_message('crypto message:\n{}'.format(crypto_message.get_email_message().to_string()))

def get_validation_tag():
    ''' 
        If there is a validation code, create a tag with it and a timestamp.

        The validation code should be known only to the local server.
        If the code is exposed, the user should change it.

        The timestamp helps detect tag spoofing. If the timestamp's
        not reasonable, the tag may have been spoofed.

        We plan to append both a message id hash and message timestamp, which
        should uniquely identify a processed message.
        Then an app can let users check for spoofed tags with a lookup.
        Since the timestamp has millisecond resolution, a collision
        will only happen if 2 messages with the same message id are
        processed in the same millisecond. Unless messages are processed
        in parallel, machines will have to speed up a lot for decryption to
        happen that fast. This may not be true with dedicated crypto hardware.
        
        >>> original_validation_code = get_validation_code()
        >>> set_validation_code('test validation')
        >>> get_validation_tag().startswith('Validation: test validation')
        True
        >>> set_validation_code(original_validation_code)
    '''

    validated_tag = []
    
    validation_code = get_validation_code()
    if validation_code != None and len(validation_code.strip()) > 0:
        if validation_code.endswith("\n"):
            validation_code = validation_code.strip()
        validated_tag.append(international_strings.VALIDATION_TAG.format(validation_code))
        validated_tag.append("            at ")
        if USE_UTC:
            validated_tag.append(Timestamp.get_timestamp())
            validated_tag.append(' ')
            validated_tag.append(international_strings.UTC)
        else:
            validated_tag.append(Timestamp.to_local_timestamp())

    return ''.join(validated_tag)


def log_message(message):
    '''
        Log a message.

        >>> import os
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.messages.decrypt_utils.log'))
        True
    '''
    global _log
    
    if _log is None:
        _log = LogFile()

    _log.write(message)

