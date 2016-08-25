'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-02-02

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, urllib

from goodcrypto.mail import options
from goodcrypto.mail.constants import TAG_PREFIX, TAG_WARNING
from goodcrypto.mail.contacts import get_fingerprint
from goodcrypto.mail.message import constants
from goodcrypto.oce.open_pgp_analyzer import OpenPGPAnalyzer
from goodcrypto.utils import get_email, i18n
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile

DEBUGGING = False

RECEIVED_CONTENT_PRIVATELY = i18n('The content of this message was received privately')
RECEIVED_FULL_MESSAGE_PRIVATELY = i18n('This message was received privately')
UNENCRYPTED_WARNING = i18n('Warning: Anyone could have read this message.')
MESSAGE_VERIFICATION_PREFIX = i18n("Verification code")
MESSAGE_VERIFY_PREFIX = i18n('Verify at:')

_log = None
_tagline_delimiter = constants.TAGLINE_DELIMITER


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

def add_tag_to_message(crypto_message):
    '''
        Add tag to a message.

        >>> add_tag_to_message(None)
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
        tag = '{}.'.format(RECEIVED_FULL_MESSAGE_PRIVATELY)
        crypto_message.add_prefix_to_tag_once(tag)
        log_message('metadata tag: {}'.format(tag))

def add_verification_tag(crypto_message, verification_code):
    ''' Add the verification tag to the message. '''

    goodcrypto_server_url = options.goodcrypto_server_url()
    if goodcrypto_server_url and len(goodcrypto_server_url) > 0:
        quoted_code = urllib.quote(verification_code)
        tag = '{} {}mail/msg-decrypted/{}'.format(
           MESSAGE_VERIFY_PREFIX, goodcrypto_server_url, quoted_code)
    else:
        tag = '{}: {}'.format(MESSAGE_VERIFICATION_PREFIX, verification_code)

    crypto_message.add_tag_once(tag)
    log_message(tag)

def add_unencrypted_warning(crypto_message):
    ''' Add a warning about unencrypted mail. '''

    tag = UNENCRYPTED_WARNING

    if tag in crypto_message.get_email_message().get_content():
        log_message('not adding tag because it is already in crypto message content: {}'.format(tag))
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
            add_crypted_tags(crypto_message)
        if crypto_message.is_clear_signed():
            add_clear_signed_tags(crypto_message)
        if crypto_message.is_dkim_signed():
            add_dkim_tags(crypto_message)

        #  if we have something to say, it's still been filtered
        if len(crypto_message.get_tags()) > 0 and not crypto_message.is_filtered():
            crypto_message.set_filtered(True)
        log_message("filtered: {}".format(crypto_message.is_filtered()))
        if DEBUGGING:
            self.log_message('DEBUG: logged tagged and filtered headers in goodcrypto.message.utils.log')
            utils.log_message_headers(crypto_message, tag='tagged and filtered headers')

        tags = crypto_message.get_tags()
        log_message('tags: {}'.format(tags))
        if len(tags) > 0:
            if len(tags) > 2:
                new_tag = '{}:\n'.format(TAG_PREFIX)
            else:
                new_tag = '{} -'.format(TAG_PREFIX)
            for count in range(len(tags)):
                tag = tags[count]
                if len(tags) > 2:
                    new_tag += '   {}) '.format(count + 1)
                else:
                    new_tag += ' '
                new_tag += tag
                if (not new_tag.endswith('.') and
                    MESSAGE_VERIFICATION_PREFIX not in tag and
                    MESSAGE_VERIFY_PREFIX not in tag):
                    new_tag += '.'
                if len(tags) > 2:
                    new_tag += '\n'
        else:
            new_tag = ''

        if len(new_tag) > 0:
            decrypt_tags = new_tag

        filtered = crypto_message.is_filtered()

    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    log_message('decrypt tags: {}'.format(decrypt_tags))

    return decrypt_tags, filtered

def add_crypted_tags(crypto_message):
    ''' Add tags about the crypto state. '''

    log_message("crypted: {}".format(crypto_message.is_crypted()))

    analyzer = OpenPGPAnalyzer()
    content = crypto_message.get_email_message().get_content()
    tags = crypto_message.get_tags()
    if tags is None:
        tags = []

    if len(crypto_message.get_metadata_crypted_with()) > 0:
        log_message('metadata crypted with: {}'.format(crypto_message.get_metadata_crypted_with()))
        received_privately = RECEIVED_FULL_MESSAGE_PRIVATELY
    else:
        received_privately = RECEIVED_CONTENT_PRIVATELY

    if RECEIVED_FULL_MESSAGE_PRIVATELY in tags:
        pass
    else:
        replaced_tag = found_content_tag = False
        for tag in tags:
            if received_privately in tag:
                tag = tag.replace(RECEIVED_CONTENT_PRIVATELY, RECEIVED_FULL_MESSAGE_PRIVATELY)
                replaced_tag = True
            elif RECEIVED_CONTENT_PRIVATELY in tag:
                found_content_tag = True
        if replaced_tag:
            crypto_message.set_tag(tags)
        elif found_content_tag:
            pass
        else:
            crypto_message.add_prefix_to_tag_once('{}.'.format(received_privately))

    if analyzer.is_encrypted(content):
        crypto_message.add_tag_once(i18n('Warning: There still appears to be an extra protective layer.'))
        if DEBUGGING: log_message("message:\n{}".format(crypto_message.get_email_message().to_string()))

def add_clear_signed_tags(crypto_message):
    ''' Add tags about the clear signer. '''

    Unknown_Signer = i18n('Warning: Content signed by an unknown user')

    log_message("clear signed: {}".format(crypto_message.is_clear_signed()))

    signers = crypto_message.clear_signers_list()
    if len(signers) > 0:
        sender = get_email(crypto_message.smtp_sender())
        for signer_dict in signers:
            signer = signer_dict[constants.SIGNER]
            log_message("clear signed by: {}".format(signer))
            if signer == sender:
                crypto_message.add_tag_once(i18n('Content signed by {email}.'.format(email=signer)))
            elif signer == 'unknown user':
                crypto_message.add_tag_once(Unknown_Signer)
            else:
                crypto_message.add_tag_once(
                 i18n('Warning: Content signed by {email}, not by the sender ({sender}).'.format(
                     email=signer, sender=sender)))
    else:
        crypto_message.add_tag_once(Unknown_Signer)

def add_dkim_tags(crypto_message):
    ''' Add tags about the dkim signature. '''

    log_message("dkim signed: {}".format(crypto_message.is_dkim_signed()))
    log_message("dkim verified: {}".format(crypto_message.is_dkim_sig_verified()))

    if crypto_message.is_dkim_sig_verified():
        crypto_message.add_tag_once(i18n("Verified message originated on sender's mail server."))
    else:
        crypto_message.add_tag_once(i18n("Warning: Unable to verify message originated on sender's mail server."))

def get_decrypt_signature_tag(crypto_message, from_user, signed_by, crypto_name):
    ''' Get the tag when the encrypted message was signed. '''

    tag = None

    if len(crypto_message.get_metadata_crypted_with()) > 0:
        log_message('metadata crypted with: {}'.format(crypto_message.get_metadata_crypted_with()))
        received_privately = RECEIVED_FULL_MESSAGE_PRIVATELY
    else:
        received_privately = RECEIVED_CONTENT_PRIVATELY

    if signed_by is None:
        tag = '{}, {}'.format(received_privately, i18n('but the sender is unknown.'))
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

        # remember that the message was signed
        crypto_message.set_private_signed(True)

        if from_user_addr == signed_by_addr:
            # assume the key is ok unless it's required to be verified before we use it
            key_ok = not options.require_key_verified()
            if not key_ok:
                __, key_ok, __ = get_fingerprint(signed_by_addr, crypto_name)

            if key_ok:
                tag = '{}.'.format(received_privately)
                crypto_message.add_private_signer({
                   constants.SIGNER: signed_by_addr, constants.SIGNER_VERIFIED: True})
                log_message('signed by: {}'.format(crypto_message.private_signers_list()))
            else:
                tag = '{}, {}'.format(
                  received_privately,
                  i18n('but the key has not been verified.'.format(email=signed_by_addr)))
                crypto_message.add_private_signer({
                  constants.SIGNER: signed_by_addr, constants.SIGNER_VERIFIED: False})
                log_message('signed by: {}'.format(crypto_message.private_signers_list()))
        else:
            tag = '{}, {}'.format(
              received_privately,
              i18n('but it was signed by {signer}, not by the sender, {sender}.'.format(
                  signer=signed_by_addr, sender=from_user_addr)))
            crypto_message.add_private_signer({
              constants.SIGNER: signed_by_addr, constants.SIGNER_VERIFIED: False})
            log_message('signed by: {}'.format(crypto_message.private_signers_list()))

    log_message('verified sig tag: {}'.format(tag))

    return tag

def log_message(message):
    '''
        Log a message.

        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.tags.log'))
        True
    '''
    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

