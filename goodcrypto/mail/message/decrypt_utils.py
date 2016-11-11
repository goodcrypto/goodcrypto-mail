'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-03

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import dkim
from email.encoders import encode_base64, encode_quopri

from goodcrypto.mail import crypto_software, options
from goodcrypto.mail.constants import DKIM_WARN_POLICY
from goodcrypto.mail.contacts import is_key_ok
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.message import history, tags, utils
from goodcrypto.mail.message.constants import ACCEPTED_CRYPTO_SOFTWARE_HEADER, CRLF, LF, SIGNER, SIGNER_VERIFIED
from goodcrypto.mail.message.inspect_utils import get_charset
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.tags import add_verification_tag
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.utils import i18n, get_email
from goodcrypto.utils.log_file import LogFile
from syr import mime_constants
from syr.exception import record_exception
from syr.message import prep_mime_message

DEBUGGING = True
USE_UTC = True
DEFAULT_CRYPTO = CryptoFactory.DEFAULT_ENCRYPTION_NAME

# dkim verification in python3 doesn't work so we'll disable it for now
DKIM_VERIFICATION_ACTIVE = False

_log = None


def verify_clear_signed(email, crypto_message, encryption_name=DEFAULT_CRYPTO, crypto=None):
    '''
        Check the signature if message is clear signed and remove signature.

        >>> # In honor of Mike Perry, Tor Browser and Tor Performance developer.
        >>> from goodcrypto.mail.message.crypto_message import CryptoMessage
        >>> from goodcrypto.mail.message.email_message import EmailMessage
        >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
        >>> with open(get_plain_message_name('pgp-sig-unknown.txt')) as input_file:
        ...    email = 'mike@goodcrypto.remote'
        ...    crypto_message = CryptoMessage(email_message=EmailMessage(input_file))
        ...    verify_clear_signed(email, crypto_message, encryption_name=DEFAULT_CRYPTO)
        ...    signers = crypto_message.clear_signers_list()
        ...    signers == [{'signer': 'unknown user', 'verified': False}]
        True
    '''

    def extract_signers(email, signature_blocks, encryption_name=DEFAULT_CRYPTO):
        ''' Extract the signers if message is signed. '''

        known_signers = False

        crypto = CryptoFactory.get_crypto(encryption_name, crypto_software.get_classname(encryption_name))
        log_message('checking if message signed by {}'.format(email))
        for signature_block in signature_blocks:
            if crypto.verify(signature_block, email):
                signer_dict = {
                    SIGNER: email,
                    SIGNER_VERIFIED: True,
                }
                known_signers = True
                log_message('{} signed message'.format(email))
            else:
                log_message('signature block\n{}'.format(signature_block))
                signer = crypto.get_signer(signature_block)
                log_message('unverified signature by {}'.format(signer))
                signer_dict = {
                    SIGNER: signer,
                    SIGNER_VERIFIED: False,
                }

            crypto_message.add_clear_signer(signer_dict)

        log_message('clear signers: {}'.format(crypto_message.clear_signers_list()))

        return known_signers

    # if the message is signed, then verify the signature
    signature_blocks = crypto_message.get_email_message().get_pgp_signature_blocks()
    if len(signature_blocks) > 0:
        crypto_message.set_clear_signed(True)
        log_message('clear signed')

        # remove the signature block if signer known
        # techies won't like this, but it makes the message more readable
        if extract_signers(get_email(email), signature_blocks, encryption_name=encryption_name):
            crypto_message.get_email_message().remove_pgp_signature_blocks()
    else:
        if DEBUGGING:
            log_message('no signature block found in this part of message')

def add_history_and_verification(crypto_message):
    '''
        Add a history record and a verification tag.
    '''
    if crypto_message is None:
        log_message('crypto message undefined so not adding history or verification')
    else:
        verification_code = history.gen_verification_code()
        history.add_inbound_record(crypto_message, verification_code)

        add_verification_tag(crypto_message, verification_code)

def verify_dkim_sig(crypto_message):
    ''' Verify DKIM signature if option selected and header exists. '''

    verified_sig = False
    if crypto_message.get_email_message().get_header('DKIM-Signature') is not None:
        log_message('trying to verify DKIM signature')
        try:
            global _log

            crypto_message.set_dkim_signed(True)

            charset, __ = get_charset(crypto_message.get_email_message())
            log_message('dkim message char set: {}'.format(charset))

            message = crypto_message.get_email_message().to_string().encode()
            if DEBUGGING:
                log_message('headers before DKIM verification:\n{}'.format(
                   crypto_message.get_email_message().get_header_lines()))
                log_message('message:\n{}'.format(message))

            if DKIM_VERIFICATION_ACTIVE:
                verified_sig = dkim.verify(message, logger=_log)
                log_message('DKIM signature verified: {}'.format(verified_sig))

                if verified_sig:
                    crypto_message.get_email_message().delete_header('DKIM-Signature')
                    crypto_message.set_dkim_sig_verified(True)
                elif options.dkim_delivery_policy() == DKIM_WARN_POLICY:
                    crypto_message.get_email_message().delete_header('DKIM-Signature')
                    log_message('dkim policy is to warn and accept message')
                else:
                    raise DKIMException("Unable to verify message originated on sender's mail server.")
            else:
                verified_sig = True # !!!!! fix dkim in python3
                log_message('unable to verify dkim sig with python3')
        except dkim.DKIMException as dkim_exception:
            if options.dkim_delivery_policy() == DKIM_WARN_POLICY:
                crypto_message.get_email_message().delete_header('DKIM-Signature')
                log_message('dkim policy is to warn; {}'.format(dkim_exception))
            else:
                raise dkim.DKIMException(str(dkim_exception))
        except:
            log_message('EXCEPTION - see syr.exception.log for details')
            record_exception()
    else:
        verified_sig = False

    return crypto_message, verified_sig

def re_mime_encode(crypto_message):
    '''
        Re-encode message if it was encoded with base64 or quoted printable.

        >>> from goodcrypto.mail.message.crypto_message import CryptoMessage
        >>> from goodcrypto.mail.message.email_message import EmailMessage
        >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
        >>> with open(get_plain_message_name('basic.txt')) as input_file:
        ...    crypto_message = CryptoMessage(email_message=EmailMessage(input_file))
        ...    re_mime_encode(crypto_message)
        False
    '''
    decoded = re_encoded = False
    message = crypto_message.get_email_message().get_message()
    try:
        encoding = message.__getitem__(mime_constants.CONTENT_XFER_ENCODING_KEYWORD)
    except Exception:
        encoding = None

    if encoding is not None:
        encoding = encoding.lower()

        # only use the encoding if it's not a multipart message
        if (encoding == mime_constants.QUOTED_PRINTABLE_ENCODING or
            encoding == mime_constants.BASE64_ENCODING):
            current_content_type = message.get_content_type()
            if (current_content_type is not None and
                current_content_type.lower().find(mime_constants.MULTIPART_PRIMARY_TYPE) < 0):
                decoded = True
                log_message('payload decoded with {}'.format(encoding))

        if decoded:
            if DEBUGGING:
                log_message('decoded message:\n{}'.format(
                    crypto_message.get_email_message().get_message()))
            if encoding == mime_constants.QUOTED_PRINTABLE_ENCODING:
                encode_quopri(message)
                re_encoded = True
            elif encoding == mime_constants.BASE64_ENCODING:
                encode_base64(message)
                re_encoded = True
            crypto_message.get_email_message().set_message(message)
            log_message('payload re-encoded with {}'.format(encoding))
            if DEBUGGING:
                log_message('encoded message:\n{}'.format(
                    crypto_message.get_email_message().get_message()))

    return re_encoded


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

