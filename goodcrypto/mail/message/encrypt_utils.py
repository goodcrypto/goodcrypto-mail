'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-01-30

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from datetime import datetime
from dkim import DKIM
from email.encoders import encode_7or8bit
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from random import random

from goodcrypto.mail import contacts, options, user_keys
from goodcrypto.mail.crypto_software import get_classname
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.message import constants, metadata, utils
from goodcrypto.mail.message.crypto_message import CryptoMessage
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.inspect_utils import get_charset, is_multipart_message
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.open_pgp_analyzer import OpenPGPAnalyzer
from goodcrypto.utils import i18n, get_email
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr import mime_constants

DEBUGGING = False

FROM_KEYWORD = 'from'
TO_KEYWORD = 'to'
PASSCODE_KEYWORD = 'passcode'
CHARSET_KEYWORD = 'charset'

log = None

def encrypt_text_message(crypto_message, crypto, users_dict):
    '''
        Encrypt a plain text message.
    '''

    def encrypt_text_part(content, crypto, users_dict):
        if DEBUGGING: log_message("type of content: {}".format(type(content)))

        ciphertext, error_message = encrypt_byte_array(bytearray(content), crypto, users_dict)

        #  if we encrypted successfully, save the results
        if ciphertext is not None and len(ciphertext) > 0:
            crypto_message.get_email_message().get_message().set_payload(ciphertext)
            from_user = users_dict[FROM_KEYWORD]
            log_message('from user: {}'.format(from_user))
            log_message('passcode: {}'.format(users_dict[PASSCODE_KEYWORD]))
            set_sigs(crypto_message, from_user, users_dict[PASSCODE_KEYWORD])
            result_ok = True
        else:
            result_ok = False

        return result_ok, error_message

    log_message("encrypting a text message")

    error_message = None

    email_message = crypto_message.get_email_message()
    if is_multipart_message(email_message):
        for part in email_message.walk():
            result_ok, error_message = encrypt_text_part(part.get_payload(), crypto, users_dict)
            if not result_ok:
                break
    else:
        final_content = email_message.get_content()
        if DEBUGGING: log_message("  content:\n{!s}".format(final_content))

        result_ok, error_message = encrypt_text_part(final_content, crypto, users_dict)

    #  if we encrypted successfully, save the results
    if result_ok:
        crypto_message.set_filtered(True)
        crypto_message.set_crypted(True)

    elif error_message is not None:
        raise MessageException(value=error_message)

def encrypt_mime_message(crypto_message, crypto, users_dict):
    '''
        Encrypt a MIME message by encrypting the entire original message and creating a new
        plain text message with the payload the encrypted original message. This reduces the
        metadata someone can collect, but it does require the receiving end decrypt the
        message and create a new readable message from the encrypted original message.
    '''

    def copy_item_from_original(msg, keyword):
        value = crypto_message.get_email_message().get_header(keyword)
        if value is not None:
            msg.__setitem__(keyword, value)

    log_message("encrypting a mime message")
    message = crypto_message.get_email_message().get_message()
    log_message("content type: {}".format(message.get_content_type()))

    #  Encrypt the whole message and add it to the body text
    #  This removes important meta data. The recieving end must
    #  decrypt the message, and then create a new message with the original structure.
    log_message("about to encrypt mime message")
    ciphertext, error_message = encrypt_byte_array(
        bytearray(crypto_message.get_email_message().to_string()), crypto, users_dict)

    if ciphertext is not None and len(ciphertext) > 0:
        from_user = users_dict[FROM_KEYWORD]
        convert_encrypted_mime_message(
          crypto_message, ciphertext, from_user, users_dict[TO_KEYWORD])
        set_sigs(crypto_message, from_user, users_dict[PASSCODE_KEYWORD])

    elif error_message is not None:
        raise MessageException(value=error_message)

def encrypt_byte_array(data, crypto, users_dict):
    ''' Encrypt a byte array. '''

    error_message = None
    to_user = users_dict[TO_KEYWORD]
    from_user = users_dict[FROM_KEYWORD]
    passcode = users_dict[PASSCODE_KEYWORD]
    charset = users_dict[CHARSET_KEYWORD]
    clear_sign = options.clear_sign_email()

    if from_user is None or passcode is None:
        if clear_sign:
            encrypted_data = None
            error_message = i18n('Cannot send message because no there is no key for the sender and clear signing is required.')
            log_message(error_message)
        else:
            log_message('encrypting, but not signing message')
            encrypted_data, error_message = crypto.encrypt_and_armor(data, to_user, charset=charset)
    else:
        log_message('encrypting and signing')
        log_message('clear signing message: {}'.format(clear_sign))
        encrypted_data, error_message = crypto.sign_encrypt_and_armor(data,
            from_user, to_user, passcode, clear_sign=clear_sign, charset=charset)

    if encrypted_data is None or len(encrypted_data) <= 0:
        ciphertext = None
        utils.log_crypto_exception('no encrypted data')
        utils.log_crypto_exception(error_message)

    else:
        #  ASCII armored plaintext looks just like armored ciphertext,
        #  so check that we actually successfully encrypted
        if data == encrypted_data:
            ciphertext = None
            utils.log_crypto_exception('data was not encrypted')

        elif not OpenPGPAnalyzer().is_encrypted(encrypted_data, passphrase=passcode, crypto=crypto):
            utils.log_crypto_exception('unable to verify data was encrypted')
            # !!!! we're going to use it any ways for now as not too confident about the analyzer
            ciphertext = str(encrypted_data)
            if DEBUGGING:
                log_message("ciphertext:\n{}".format(ciphertext))

        else:
            ciphertext = str(encrypted_data)
            if DEBUGGING:
                log_message("ciphertext:\n{}".format(ciphertext))

    if error_message is not None:
        log_message('Unable to encrypt data because:\n  {}'.format(error_message))

    return ciphertext, error_message

def sign_text_message(crypto_message, crypto, from_user_id, passcode):
    '''
        Sign a plain text message.
    '''

    def sign_text_part(content, crypto, from_user_id, passcode):
        if DEBUGGING: log_message("type of content: {}".format(type(content)))

        ciphertext, error_message = crypto.sign(bytearray(content), from_user_id, passcode)

        #  if we signed successfully, save the results
        if ciphertext != None and len(ciphertext) > 0:
            crypto_message.get_email_message().get_message().set_payload(ciphertext)
            result_ok = True
        else:
            result_ok = False

        return result_ok, error_message

    log_message("signing a text message")

    error_message = None
    email_message = crypto_message.get_email_message()
    if is_multipart_message(email_message):
        for part in email_message.walk():
            result_ok, error_message = sign_text_part(part.get_payload(), crypto, from_user_id, passcode)
            if not result_ok:
                break
    else:
        final_content = email_message.get_content()
        if DEBUGGING: log_message("  content:\n{!s}".format(final_content))

        result_ok, error_message = sign_text_part(final_content, crypto, from_user_id, passcode)

    #  if we signed successfully, save the results
    if result_ok:
        crypto_message.set_filtered(True)
        crypto_message.set_crypted(True)

    elif error_message is not None:
        raise MessageException(value=error_message)

def sign_mime_message(crypto_message, crypto, from_user_id, passcode):
    '''
        Sign a MIME message by signing the entire original message and creating a new
        plain text message with the payload the signed original message. This reduces the
        metadata someone can collect, but it does require the receiving end decrypt the
        message and create a new readable message from the signed original message.
    '''

    def copy_item_from_original(msg, keyword):
        value = crypto_message.get_email_message().get_header(keyword)
        if value is not None:
            msg.__setitem__(keyword, value)

    log_message("signing a mime message")
    message = crypto_message.get_email_message().get_message()
    log_message("content type: {}".format(message.get_content_type()))

    #  Sign the whole message and add it to the body text
    #  This removes important meta data. The recieving end must
    #  decrypt the message, and then create a new message with the original structure.
    log_message("about to sign mime message")
    ciphertext, error_message = crypto.sign(
        bytearray(crypto_message.get_email_message().to_string()), from_user_id, passcode)

    if ciphertext is not None and len(ciphertext) > 0:
        convert_encrypted_mime_message(
          crypto_message, ciphertext, from_user_id, crypto_message.smtp_recipient())

    elif error_message is not None:
        raise MessageException(value=error_message)

def convert_encrypted_mime_message(crypto_message, ciphertext, from_user, to_user):
    '''
        Convert a MIME message that has been signed or encrypted, and creating a new
        plain text message with the payload the encrypted/signed original message. This reduces the
        metadata someone can collect, but it does require the receiving end decrypt the
        message and create a new readable message from the original message.
    '''

    def copy_item_from_original(msg, keyword):
        value = crypto_message.get_email_message().get_header(keyword)
        if value is not None:
            msg.__setitem__(keyword, value)

    if ciphertext is not None and len(ciphertext) > 0:
        # set up the body parts
        parts = []
        parts.append(
           MIMEApplication(
             mime_constants.PGP_MIME_VERSION_FIELD, mime_constants.PGP_SUB_TYPE, encode_7or8bit))
        parts.append(
           MIMEApplication(ciphertext, mime_constants.OCTET_STREAM_SUB_TYPE, encode_7or8bit))

        boundary = 'Part{}{}--'.format(random(), random())
        charset, __ = get_charset(crypto_message.get_email_message().get_message())
        params = {mime_constants.PROTOCOL_KEYWORD:mime_constants.PGP_TYPE,
                  mime_constants.CHARSET_KEYWORD:charset,}
        msg = MIMEMultipart(mime_constants.ENCRYPTED_SUB_TYPE, boundary, parts, **params)
        log_message("part's content type: {}".format(msg.get_content_type()))

        # configure the header
        msg.__setitem__(mime_constants.FROM_KEYWORD, from_user)
        msg.__setitem__(mime_constants.TO_KEYWORD, to_user)
        msg.__setitem__(constants.PGP_ENCRYPTED_CONTENT_TYPE, mime_constants.MULTIPART_MIXED_TYPE)
        copy_item_from_original(msg, mime_constants.MESSAGE_ID_KEYWORD)
        copy_item_from_original(msg, mime_constants.SUBJECT_KEYWORD)
        copy_item_from_original(msg, mime_constants.DATE_KEYWORD)

        crypto_message.set_email_message(EmailMessage(msg))
        crypto_message.add_public_key_to_header(from_user)
        crypto_message.set_filtered(True)
        crypto_message.set_crypted(True)

def create_protected_message(from_user, to_user, data, message_id):
    '''
        Create a new message that protects the metadata.
    '''
    def start_crypto_message():
        from goodcrypto.mail.message.crypto_message import CryptoMessage

        # start a new crypto message
        from_metadata_user = metadata.get_metadata_address(email=from_user)
        to_metadata_user = metadata.get_metadata_address(email=to_user)

        crypto_message = CryptoMessage()
        crypto_message.get_email_message().add_header(
            mime_constants.FROM_KEYWORD, from_metadata_user)
        crypto_message.get_email_message().add_header(
            mime_constants.TO_KEYWORD, to_metadata_user)
        crypto_message.get_email_message().add_header(mime_constants.MESSAGE_ID_KEYWORD, message_id)
        # include the timestamp because some MTAs/spam filters object if it's not set
        crypto_message.get_email_message().add_header(
            mime_constants.DATE_KEYWORD, datetime.utcnow().isoformat(' '))

        return crypto_message

    def encrypt_message(crypto_message, data):

        from goodcrypto.mail.utils import get_encryption_software

        encryption_ready = False
        encrypted_with = []

        # use the metadata address' encryption
        to_metadata_address = metadata.get_metadata_address(email=to_user)
        encryption_names = get_encryption_software(to_metadata_address)
        log_message('{} encryption software for: {}'.format(encryption_names, to_metadata_address))

        if encryption_names is None or len(encryption_names) < 1:
            error_message = i18n(
              'Unable to protect metadata because there are no encryption programs for {}.'.format(to_metadata_address))
            log_message(error_message)
            raise MessageException(value=error_message)
        else:
            # encrypt with each common encryption program
            for encryption_name in encryption_names:
                ready, to_metadata_address, __ = metadata.get_metadata_user_details(
                    to_user, encryption_name)
                log_message('to metadata ready {} '.format(ready))

                if ready:
                    ready, from_metadata_address, passcode = metadata.get_from_metadata_user_details(
                        from_user, encryption_name)
                    log_message('metadata keys ready {}'.format(ready))

                if ready:
                    log_message('protecting metadata with {}'.format(encryption_names))

                    # if we're ready with any key, then the encryption is ready
                    encryption_ready = True

                    from_user_id = get_email(from_metadata_address)
                    to_user_id = get_email(to_metadata_address)
                    crypto_message.set_smtp_sender(from_user_id)
                    crypto_message.set_smtp_recipient(to_user_id)

                    # use the default charset to prevent metadata leakage
                    charset, __ = get_charset(constants.DEFAULT_CHAR_SET)
                    users_dict = {TO_KEYWORD: to_user_id,
                                  FROM_KEYWORD: from_user_id,
                                  PASSCODE_KEYWORD: passcode,
                                  CHARSET_KEYWORD: charset}

                    crypto = CryptoFactory.get_crypto(encryption_name, get_classname(encryption_name))
                    ciphertext, error_message = encrypt_byte_array(data, crypto, users_dict)
                    if ciphertext is not None and len(ciphertext) > 0:
                        crypto_message.get_email_message().get_message().set_payload(ciphertext)

                        crypto_message.add_public_key_to_header(users_dict[FROM_KEYWORD])
                        set_sigs(crypto_message, from_user_id, passcode)
                        crypto_message.set_filtered(True)
                        crypto_message.set_crypted(True)

                        # use the encrypted data for the next level of encryption
                        data = ciphertext

                        encrypted_with.append(encryption_name)
                    else:
                        log_message('unable to encrypt the metadata with {}'.format(encryption_name))
                        raise MessageException(value=error_message)
                else:
                    log_message('unable to protect metadata with {}'.format(encryption_name))

            return encryption_ready, encrypted_with

    try:
        log_message('creating a new message that protects the metadata')
        crypto_message = start_crypto_message()

        if data is None:
            log_message("no data to encrypt")
        else:
            ready, encrypted_with = encrypt_message(crypto_message, data)

            if crypto_message.is_crypted():
                crypto_message.set_metadata_crypted(True)
                crypto_message.set_metadata_crypted_with(encrypted_with)
                log_message('metadata encrypted with: {}'.format(encrypted_with))
                if DEBUGGING:
                    log_message("metadata message:\n{}".format(
                        crypto_message.get_email_message().to_string()))
            elif not ready:
                error_message = i18n('Unable to protect metadata because a key is missing.')
                log_message(error_message)
                raise MessageException(value=error_message)
            else:
                error_message = i18n('Unable to protect metadata even though keys for both servers exist.')
                log_message(error_message)
                raise MessageException(value=error_message)
    except MessageException as message_exception:
        log_message('raising MessageException')
        raise MessageException(value=message_exception.value)
    except:
        error_message = i18n('Unable to protect metadata due to an unexpected error.')
        log_message(error_message)
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        record_exception()
        raise MessageException(value=error_message)

    return crypto_message

def set_sigs(crypto_message, from_user, passcode):
    ''' Set details about the signatures in the crypto message. '''

    if from_user is not None and passcode is not None:
        crypto_message.set_private_signed(True)
        crypto_message.add_private_signer(
            {constants.SIGNER: from_user, constants.SIGNER_VERIFIED: True})
        log_message('message signed by {}'.format(from_user))

        if options.clear_sign_email():
            crypto_message.set_clear_signed(True)
            crypto_message.add_clear_signer(
              {constants.SIGNER: from_user, constants.SIGNER_VERIFIED: True})

def add_dkim_sig_optionally(crypto_message):
    ''' Add DKIM signature if option selected. '''

    if (options.add_dkim_sig() and
        options.dkim_public_key() is not None and
        len(options.dkim_public_key()) > 0):

        log_message('trying to add DKIM signature')

        try:
            global log

            SELECTOR = 'mail'
            PRIVATE_KEY_FILE = '/etc/opendkim/{}/dkim.private.key'.format(get_domain())

            with open(PRIVATE_KEY_FILE, 'rb') as f:
                private_key = f.read()

            # in case there's a mixture of CR-LF and LF lines, convert CR-LF to LF and then all LFs to CR-LFs
            message = crypto_message.get_email_message().to_string().replace(
                constants.CRLF, constants.LF).replace(constants.LF, constants.CRLF)
            dkim = DKIM(message=message, minkey=constants.MIN_DKIM_KEY, logger=log)
            # stop header injections of many headers
            dkim.frozen_sign = set(DKIM.RFC5322_SINGLETON)
            sig = dkim.sign(SELECTOR, get_domain().encode('ascii'), private_key)
            if sig.startswith('DKIM-Signature'):
                signed_message = '{}{}'.format(sig, message)
                crypto_message.get_email_message().set_message(signed_message)
                crypto_message.set_dkim_signed(True)
                crypto_message.set_dkim_sig_verified(True)
                log_message('added DKIM signature successfully')
            else:
                log_message('error trying to add DKIM signature')
        except:
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            record_exception()

    return crypto_message

def log_message(message):
    '''
        Log the message to the local log.
    '''
    global log

    if log is None:
        log = LogFile()

    log.write_and_flush(message)

