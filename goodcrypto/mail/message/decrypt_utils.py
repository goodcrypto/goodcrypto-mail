'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-02-02

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from dkim import DKIM, DKIMException

from goodcrypto.mail import crypto_software, options
from goodcrypto.mail.constants import DKIM_WARN_POLICY
from goodcrypto.mail.contacts import is_key_ok
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.message import history, tags, utils
from goodcrypto.mail.message.constants import ACCEPTED_CRYPTO_SOFTWARE_HEADER, CRLF, LF, SIGNER, SIGNER_VERIFIED
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.tags import add_verification_tag
from goodcrypto.mail.utils import get_email
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.utils import i18n, get_email
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr.message import prep_mime_message
from syr.timestamp import Timestamp

DEBUGGING = False
USE_UTC = True
DEFAULT_CRYPTO = CryptoFactory.DEFAULT_ENCRYPTION_NAME


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
        ...    crypto_message.get_tag()
        'Warning: Content signed by an unknown user.'
    '''

    def extract_signers(email, signature_blocks, encryption_name=DEFAULT_CRYPTO):
        ''' Extract the signers if message is signed. '''

        crypto = CryptoFactory.get_crypto(encryption_name, crypto_software.get_classname(encryption_name))
        log_message('checking if message signed by {}'.format(email))
        for signature_block in signature_blocks:
            if crypto.verify(signature_block, email):
                signer_dict = {
                    SIGNER: email,
                    SIGNER_VERIFIED: True,
                }
                log_message('{} signed message'.format(email))
            else:
                log_message('signature block\n{}'.format(signature_block))
                signer = crypto.get_signer(signature_block)
                log_message('{} signed message'.format(signer))
                if signer is None:
                    signer = 'unknown user'
                else:
                    signer = get_email(signer)

                signer_dict = {
                    SIGNER: signer,
                    SIGNER_VERIFIED: False,
                }

            crypto_message.add_clear_signer(signer_dict)

        log_message('clear signers: {}'.format(crypto_message.clear_signers_list()))

    # if the message is signed, then verify the signature
    signature_blocks = crypto_message.get_email_message().get_pgp_signature_blocks()
    if len(signature_blocks) > 0:
        crypto_message.set_clear_signed(True)
        log_message('clear signed')
        extract_signers(get_email(email), signature_blocks, encryption_name=encryption_name)

        # remove the signature block; techies won't like this, but it makes the message more readable
        crypto_message.get_email_message().remove_pgp_signature_blocks()
    else:
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
            message = crypto_message.get_email_message().to_string()
            if DEBUGGING:
                log_message('headers before DKIM verification:\n{}'.format(
                   crypto_message.get_email_message().get_header_lines()))

            dkim = DKIM(message=message, logger=_log)
            verified_sig = dkim.verify()
            log_message('DKIM signature verified: {}'.format(verified_sig))

            if verified_sig:
                crypto_message.get_email_message().delete_header('DKIM-Signature')
                crypto_message.set_dkim_sig_verified(True)
            elif options.dkim_delivery_policy() == DKIM_WARN_POLICY:
                crypto_message.get_email_message().delete_header('DKIM-Signature')
                log_message('dkim policy is to warn and accept message')
            else:
                raise DKIMException("Unable to verify message originated on sender's mail server.")
        except DKIMException as dkim_exception:
            if options.dkim_delivery_policy() == DKIM_WARN_POLICY:
                crypto_message.get_email_message().delete_header('DKIM-Signature')
                log_message('dkim policy is to warn; {}'.format(dkim_exception))
            else:
                raise DKIMException(str(dkim_exception))
        except:
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            record_exception()
    else:
        verified_sig = False

    return crypto_message, verified_sig

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

