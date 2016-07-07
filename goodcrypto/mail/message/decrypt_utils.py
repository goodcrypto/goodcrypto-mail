'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-07-27

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import re, urllib

from goodcrypto.mail import crypto_software, options
from goodcrypto.mail.constants import TAG_PREFIX, TAG_WARNING
from goodcrypto.mail.contacts import get_fingerprint, is_key_ok
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.message import history, utils
from goodcrypto.mail.message.constants import ACCEPTED_CRYPTO_SOFTWARE_HEADER
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.utils import get_email, get_metadata_address, get_sysadmin_email
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.open_pgp_analyzer import OpenPGPAnalyzer
from goodcrypto.utils import i18n, get_email
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr.message import prep_mime_message
from syr.timestamp import Timestamp

DEBUGGING = False
USE_UTC = True
DEFAULT_CRYPTO = CryptoFactory.DEFAULT_ENCRYPTION_NAME
RECEIVED_MESSAGE_PRIVATELY = i18n('Received privately')
MESSAGE_VERIFICATION_PREFIX = i18n("Verification code")
UNENCRYPTED_WARNING = i18n('Warning: Anyone could have read this message.')


_log = None


def add_tag_to_message(crypto_message):
    '''
        Add tag to a message.
        
        add_tag_to_message(None)
        False
    '''

    # update the tags
    tags, filtered = get_tags(crypto_message)
    if tags is None or len(tags) <= 0:
        log_message('No tags need to be added to message')
    else:
        tags_added = crypto_message.add_tag_to_message(tags)
        log_message('Tags added to message: {}'.format(tags_added))
        if tags_added:
            log_message(tags)
            if DEBUGGING:
                self.log_message('DEBUG: logged taggged message headers in goodcrypto.message.utils.log')
                utils.log_message_headers(crypto_message, tag='tagged message headers')

    return filtered

def add_metadata_tag(crypto_message):
    ''' Add metadata tag. '''
    
    if crypto_message is None:
        log_message('no crypto_message')
    else:
        tag = '{}.'.format(RECEIVED_MESSAGE_PRIVATELY)
        crypto_message.add_prefix_to_tag_once(tag)
        log_message('metadata tag: {}'.format(tag))

def add_unencrypted_warning(crypto_message):
    ''' Add a warning about unencrypted mail. '''

    tag = UNENCRYPTED_WARNING

    if tag in crypto_message.get_tag():
        log_message('tag already in crypto message tag: {}'.format(tag))
    else:
        crypto_message.add_prefix_to_tag(tag)

def get_tags(crypto_message):
    '''
        Get tags to add to message.
        
        Test extreme cases.
        >>> tags, filtered = get_tags(None)
        >>> tags is None
        True
        >>> filtered
        False
    '''

    decrypt_tags = None
    filtered = False

    try:
        if crypto_message.is_crypted():
            log_message("crypted: {}".format(crypto_message.is_crypted()))
            analyzer = OpenPGPAnalyzer()
            content = crypto_message.get_email_message().get_content()
            tag = crypto_message.get_tag()
            if (RECEIVED_MESSAGE_PRIVATELY not in tag):
                crypto_message.add_prefix_to_tag_once('{}.'.format(RECEIVED_MESSAGE_PRIVATELY))
            if analyzer.is_encrypted(content):
                crypto_message.add_tag_once(i18n('Warning: There still appears to be an extra protective layer.'))
                if DEBUGGING: log_message("message:\n{}".format(crypto_message.get_email_message().to_string()))

        #  if we have something to say, it's still been filtered
        if len(crypto_message.get_tags()) > 0 and not crypto_message.is_filtered():
            crypto_message.set_filtered(True)
        log_message("filtered: {}".format(crypto_message.is_filtered()))
        if DEBUGGING:
            self.log_message('DEBUG: logged tagged and filtered headers in goodcrypto.message.utils.log')
            utils.log_message_headers(crypto_message, tag='tagged and filtered headers')
        
        tags = crypto_message.get_tags()
        log_message('tags: {}'.format(tags))
        if len(tags) > 1:
            new_tags = ['{}:'.format(TAG_PREFIX)]
            for count in range(len(tags)):
                tag = '    {}. {}'.format(count+1, tags[count])
                new_tags.append(tag)
        elif len(tags) > 0:
            if tags[0] == UNENCRYPTED_WARNING:
                new_tags = ['{} {}'.format(TAG_PREFIX, tags[0])]
            else:
                new_tags = ['{}:'.format(TAG_PREFIX), '    {}'.format(tags[0])]
        else:
            new_tags = []

        if len(new_tags) > 0:
            decrypt_tags = '\n'.join(new_tags)

        filtered = crypto_message.is_filtered()
                
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    log_message('decrypt tags: {}'.format(decrypt_tags))

    return decrypt_tags, filtered

def get_encrypt_signature_tag(crypto_message, from_user, signed_by, crypto_name):
    ''' Get the tag when the encrypted message was signed. '''

    tag = None
    
    if signed_by is None:
        tag = '{}, {}'.format(
            RECEIVED_MESSAGE_PRIVATELY, i18n('but the sender is unknown.'))
    else:
        from_user_addr = get_email(from_user)
        signed_by_addr = get_email(signed_by)
        log_message("message encrypted and signed by {}".format(signed_by_addr))

        # if the signer's not a match with the sender, see if the key is used for multiple 
        # email addresses and one of those addresses is the sender's address
        if from_user_addr != signed_by_addr:
            log_message("checking if key is for multiple email addresses")
            from_fingerprint, __, __ = get_fingerprint(from_user_addr, crypto_name)
            if from_fingerprint is not None:
                signer_fingerprint, __, __ = get_fingerprint(signed_by_addr, crypto_name)
                if from_fingerprint == signer_fingerprint:
                    signed_by_addr = from_user_addr
                    log_message("signer key is for multiple addresses, including sender")
            
        if from_user_addr == signed_by_addr:
            # assume the key is ok unless it's required to be verified before we use it
            key_ok = not options.require_key_verified()
            if not key_ok:
                __, key_ok, __ = get_fingerprint(signed_by_addr, crypto_name)

            if key_ok:
                tag = '{}.'.format(RECEIVED_MESSAGE_PRIVATELY)
            else:
                tag = '{}, {}'.format(
                  RECEIVED_MESSAGE_PRIVATELY, 
                  i18n('but the key has not been verified.'.format(email=signed_by_addr)))
        else:
            tag = '{}, {}'.format(
              RECEIVED_MESSAGE_PRIVATELY, 
              i18n('but it was signed by {signer}, not by the sender, {sender}.'.format(
                  signer=signed_by_addr, sender=from_user_addr)))

    log_message('verified sig tag: {}'.format(tag))

    return tag

def verify_clear_signed(email, crypto_message, encryption_name=DEFAULT_CRYPTO, crypto=None):
    '''
        Check the signature if message is clear signed.
        
        >>> # In honor of Mike Perry, Tor Browser and Tor Performance developer.
        >>> from goodcrypto.mail.message.crypto_message import CryptoMessage
        >>> from goodcrypto.mail.message.email_message import EmailMessage
        >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
        >>> with open(get_plain_message_name('pgp-sig-unknown.txt')) as input_file:
        ...    email = 'mike@goodcrypto.remote'
        ...    crypto_message = CryptoMessage(email_message=EmailMessage(input_file))
        ...    verify_clear_signed(email, crypto_message, encryption_name=DEFAULT_CRYPTO)
        ...    crypto_message.get_tag()
        'Signed by an unknown user.'
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
                    try:
                        # make sure that the key for the sender is ok; if it's not, a CryptoException is thrown
                        __, key_verified, __ = is_key_ok(email, encryption_name)
                        log_message('{} signed message'.format(email))
                        log_message('{} {} key pinned'.format(email, encryption_name))
                    except CryptoException:
                        key_verified = False
                        log_message('see contacts.log for details about failure')
                    log_message('{} {} key verified: {}'.format(email, encryption_name, key_verified))
                else:
                    log_message('signature block\n{}'.format(signature_block))
                    signer = crypto.get_signer(signature_block)
                    if signer is None:
                        error_message = i18n('Signed by an unknown user.')
                        log_message(error_message)
                        raise MessageException(error_message)
                    else:
                        error_message = i18n('Warning: Signed by {signer}, *not* by the sender {email}.'.format(
                            signer=get_email(signer), email=get_email(email)))
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
            if key_verified or not options.require_key_verified():
                # Translator: Do not alter {email} simply move it wherever would be appropriate in the sentence.
                crypto_message.add_tag_once(i18n('Signed by {email}.'.format(email=get_email(email))))
            else:
                crypto_message.add_tag_once(i18n('Appears to be clear signed by {email}, but the key has not been verified.'.format(email=get_email(email))))
        except MessageException as message_exception:
            crypto_message.add_tag_once(message_exception.value)
    else:
        log_message('no signature block found in this part of message')

def prep_metadata_key_message(from_user, to_user):
    '''
        Prepare a Message that contains notice about a new metadata key.
    '''
    def get_extra_headers():
        extra_headers = None

        key_block = utils.make_public_key_block(local_metadata_address)
        if len(key_block) > 0:
            extra_headers = []
            for line in key_block:
                name, __, value = line.partition(': ')
                extra_headers.append((name, value))
            extra_headers.append((ACCEPTED_CRYPTO_SOFTWARE_HEADER, ','.join(encryption_software)))

        return extra_headers

    try:
        message = local_metadata_address = remote_metadata_address = None
        if from_user is None or to_user is None:
            log_message('missing user data so unable to prepare metadata key message')

        else:
            # we want to send a message from the original recipient's "no metadata" address
            # to the original sender's "no metadata" address
            remote_metadata_address = get_metadata_address(email=from_user)
            local_metadata_address = get_metadata_address(email=to_user)
            encryption_software = utils.get_encryption_software(local_metadata_address)

            extra_headers = get_extra_headers()
            if extra_headers is None:
                log_message('"no metadata" key is not ready yet')
                for encryption_name in encryption_software:
                    utils.add_private_key(local_metadata_address, encryption_name)
                    log_message('adding a "no metadata" {} key'.format(encryption_name))
            else:
                log_message('preparing a "no metadata" key message')
    
                # this message will be read by the remote user so we use the domain for our own system
                # we don't know that the remote system is configured to protect metadata so we don't
                # state that they "will" have metadata protection
                domain = get_domain()
                subject = 'GoodCrypto - All messages to {domain} can have metadata protection'.format(domain=domain)
                line1 = 'Please be sure to verify the new "_no_metadata_@{domain}" email address before using it.'.format(domain=domain)
                line2 = 'From now on, all messages to {domain} can have the metadata encrypted.'.format(
                        domain=domain)
                text = '{} {}'.format(line1, line2)
                message = prep_mime_message(
                           local_metadata_address, remote_metadata_address, subject, 
                           text=text, extra_headers=extra_headers)
    except:
        message = None
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return message, local_metadata_address, remote_metadata_address

def send_metadata_key(from_user, to_user):
    '''
        Send the local user's metadata key to the sender's metadata address in a new message.
    '''
    try:
        if from_user is None or to_user is None:
            sent_message = False
            log_message('missing user data so message not sent to sysadmin')

        else:
            # it doesn't matter whether the local system wants their users' metadata protected, we want the
            # recipient's system to have the metadata key so they can protect the recipient's metadata
            log_message('preparing to send "no metadata" key')

            message, local_metadata_address, remote_metadata_address = prep_metadata_key_message(
                from_user, to_user)
            utils.send_message(local_metadata_address, remote_metadata_address, message)
            
            sent_message = True
            log_message('sent "no metadata" address to {}'.format(from_user))
    except:
        sent_message = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return sent_message

def add_history_and_verification(crypto_message):
    '''
        Add a history record and a verification tag.
    '''
    if crypto_message is None:
        log_message('crypto message undefined so not adding history or verification')
    else:
        verification_code = history.gen_verification_code()
        history.add_decrypted_record(crypto_message, verification_code)

        goodcrypto_server_url = options.goodcrypto_server_url()
        if goodcrypto_server_url and len(goodcrypto_server_url) > 0:
            quoted_code = urllib.quote(verification_code)
            verification_msg = i18n('Verify this at {url}mail/msg-decrypted/{quoted_code}'.format(
                url=goodcrypto_server_url, quoted_code=quoted_code))
        else:
            verification_msg = '{}: {}'.format(MESSAGE_VERIFICATION_PREFIX, verification_code)
    
        crypto_message.add_tag_once(verification_msg)
        log_message(verification_msg)

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

