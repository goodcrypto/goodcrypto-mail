'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-07-27

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from datetime import datetime
from email.encoders import encode_7or8bit
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from random import random

from goodcrypto.mail import options, user_keys
from goodcrypto.mail.crypto_software import get_classname
from goodcrypto.mail.message import constants, history, utils
from goodcrypto.mail.message.crypto_message import CryptoMessage
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.inspect_utils import get_charset, is_multipart_message
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.utils import get_metadata_address
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

        ciphertext = encrypt_byte_array(bytearray(content), crypto, users_dict)

        #  if we encrypted successfully, save the results 
        if ciphertext != None and len(ciphertext) > 0:
            crypto_message.get_email_message().get_message().set_payload(ciphertext)
            result_ok = True
        else:
            result_ok = False
            
        return result_ok

    log_message("encrypting a text message")
    
    email_message = crypto_message.get_email_message()
    if is_multipart_message(email_message):
        for part in email_message.walk():
            result_ok = encrypt_text_part(part.get_payload(), crypto, users_dict)
            if not result_ok:
                break
    else:
        final_content = email_message.get_content()
        if DEBUGGING: log_message("  content:\n{!s}".format(final_content))
        
        result_ok = encrypt_text_part(final_content, crypto, users_dict)

    #  if we encrypted successfully, save the results 
    if result_ok:
        crypto_message.set_filtered(True)
        crypto_message.set_crypted(True)

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
    ciphertext = encrypt_byte_array(
        bytearray(crypto_message.get_email_message().to_string()), crypto, users_dict)
    
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
        msg.__setitem__(mime_constants.FROM_KEYWORD, users_dict[FROM_KEYWORD])
        msg.__setitem__(mime_constants.TO_KEYWORD, users_dict[TO_KEYWORD])
        msg.__setitem__(constants.PGP_ENCRYPTED_CONTENT_TYPE, mime_constants.MULTIPART_MIXED_TYPE)
        copy_item_from_original(msg, mime_constants.MESSAGE_ID_KEYWORD)
        copy_item_from_original(msg, mime_constants.SUBJECT_KEYWORD)
        copy_item_from_original(msg, mime_constants.DATE_KEYWORD)
        
        crypto_message.set_email_message(EmailMessage(msg))
        crypto_message.add_public_key_to_header(users_dict[FROM_KEYWORD])
        crypto_message.set_filtered(True)
        crypto_message.set_crypted(True)

def encrypt_byte_array(data, crypto, users_dict):
    ''' Encrypt a byte array. '''
    
    to_user = users_dict[TO_KEYWORD]
    from_user = users_dict[FROM_KEYWORD]
    passcode = users_dict[PASSCODE_KEYWORD]
    charset = users_dict[CHARSET_KEYWORD]
    clear_sign = options.clear_sign_email()
    
    if from_user is None or passcode is None:
        if clear_sign:
            encrypted_data = None
            log_message('cannot send message because no from key and clear signing required')
        else:
            log_message('encrypting, but not signing message')
            encrypted_data = crypto.encrypt_and_armor(data, to_user, charset=charset)
    else:
        log_message('encrypting and signing')
        log_message('clear signing message: {}'.format(clear_sign))
        encrypted_data = crypto.sign_encrypt_and_armor(data,
            from_user, to_user, passcode, clear_sign=clear_sign, charset=charset)

    if encrypted_data is None or len(encrypted_data) <= 0:
        ciphertext = None
        utils.log_crypto_exception('no encrypted data')

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

    return ciphertext

def is_ready_to_protect_metadata(from_user, to_user):
    '''
        Determine if encrypt_metadata is True and we have a 
        metadata key for both the sender's and recipient's servers.
    '''

    if from_user is None or to_user is None:
        ready = False
    else:
        ready = options.encrypt_metadata()
        log_message("options set to encrypt metadata: {}".format(ready))
        if ready:
            # first see if we know the metadata address for the recipient's server 
            to_metadata_user = get_metadata_address(email=to_user)
            encryption_names = utils.get_encryption_software(to_metadata_user)
            ready = encryption_names is not None and len(encryption_names) > 0
            log_message("{} uses {} encryption programs".format(to_metadata_user, encryption_names))
            for encryption_name in encryption_names:
                ready, __, __ = utils.get_metadata_user_details(
                    to_user, encryption_name)

                # we only need 1 valid metadata address
                if ready:
                    log_message("recipient's server ready to protect metadata")
                    break

        if ready:
            # then see if we know the metadata address for the sender's server
            from_metadata_user = get_metadata_address(email=from_user)
            encryption_names = utils.get_encryption_software(from_metadata_user)
            ready = encryption_names is not None and len(encryption_names) > 0
            log_message("{} uses {} encryption programs".format(from_metadata_user, encryption_names))
            for encryption_name in encryption_names:
                ready, __, fingerprint = utils.get_from_metadata_user_details(
                    from_user, encryption_name)

                # we only need 1 valid metadata address
                if ready:
                    log_message("sender's server ready to protect metadata")
                    break
                elif fingerprint is None:
                    log_message('creating private {} key for {}'.format(encryption_name, from_user))
                    user_keys.create_user_key(from_user, encryption_name)

    log_message('ready to protect metadata: {}'.format(ready))

    return ready

def create_protected_message(from_user, to_user, data, message_id):
    '''
        Create a new message that protects the metadata.
    '''
    def start_crypto_message():
        
        # start a new crypto message
        from_metadata_user = get_metadata_address(email=from_user)
        to_metadata_user = get_metadata_address(email=to_user)
        
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
        
        encryption_ready = False
        encrypted_with = []
        
        # use the metadata address' encryption
        to_metadata_address = get_metadata_address(email=to_user)
        encryption_names = utils.get_encryption_software(to_metadata_address)
        log_message('{} encryption software for: {}'.format(encryption_names, to_metadata_address))

        if encryption_names is None or len(encryption_names) < 1:
            error_message = i18n(
              'Unable to protect metadata because there are no encryption programs for {}.'.format(to_metadata_address))
            log_message(error_message)
            raise MessageException(value=error_message)
        else:
            # encrypt with each common encryption program
            for encryption_name in encryption_names:
                ready, to_metadata_address, __ = utils.get_metadata_user_details(
                    to_user, encryption_name)
                log_message('to metadata ready {} '.format(ready))
    
                if ready:
                    ready, from_metadata_address, passcode = utils.get_from_metadata_user_details(
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
                    ciphertext = encrypt_byte_array(data, crypto, users_dict)
                    if ciphertext is not None and len(ciphertext) > 0:
                        crypto_message.get_email_message().get_message().set_payload(ciphertext)
                        crypto_message.add_public_key_to_header(users_dict[FROM_KEYWORD])
                        crypto_message.set_filtered(True)
                        crypto_message.set_crypted(True)
    
                        # use the encrypted data for the next level of encryption
                        data = ciphertext
                        
                        encrypted_with.append(encryption_name)
                    else:
                        log_message('unable to encrypt the metadata with {}'.format(encryption_name))
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

def create_inner_address_lines(to_value, cc_value):
    '''
        Create "To" and "Cc" addresses lines for the top of the content.
    '''

    content = '{}: {}\n'.format(mime_constants.TO_KEYWORD, to_value)
    if cc_value is not None:
        content += '{}: {}\n'.format(mime_constants.CC_KEYWORD, cc_value)

    return content

def limit_recipients(crypto_message):
    '''
        Remove this function if not used by 2015-10-01
        
        NOTE: No longer used because we protect metadata separately and it
        appears to confuse people when the original TO isn't visable.
        
        A traffic analysis countermeasure is to only show 1 recipient in the header.
        If there are multiple Tos and CCs, they've been added in the encrypted 
        text section of the message.
    '''

    if crypto_message is None or crypto_message.smtp_recipient() is None:
        log_message('missing key data to limit the recipients')
    else:
        email_message = crypto_message.get_email_message()
        to_value = email_message.get_header(mime_constants.TO_KEYWORD)
        cc_value = email_message.get_header(mime_constants.CC_KEYWORD)
        if (to_value is not None and to_value.find(',') > 0) or cc_value is not None:
            log_message('recipient: {}'.format(crypto_message.smtp_recipient()))
            address = get_email(crypto_message.smtp_recipient())
            crypto_message.get_email_message().change_header(mime_constants.TO_KEYWORD, address)
            log_message('original to: {}'.format(to_value))
            log_message('final to: {}'.format(address))
            
            if cc_value is not None:
                crypto_message.get_email_message().get_message().__delitem__(mime_constants.CC_KEYWORD)
                log_message('original cc: {}'.format(cc_value))

def log_message(message):
    '''
        Log the message to the local log.
    '''
    global log
    
    if log is None:
        log = LogFile()
    
    log.write_and_flush(message)

