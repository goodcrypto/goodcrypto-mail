'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from email.message import Message
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail import contacts, contacts_passcodes, crypto_software, international_strings, options
from goodcrypto.mail.messages import decrypt_utils, mime_constants, utils
from goodcrypto.mail.messages.constants import PGP_ENCRYPTED_CONTENT_TYPE
from goodcrypto.mail.messages.crypto_filter import CryptoFilter
from goodcrypto.mail.messages.email_message import EmailMessage
from goodcrypto.mail.messages.header_keys import HeaderKeys
from goodcrypto.mail.messages.message_exception import MessageException
from goodcrypto.mail.messages.notices import notify_user
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.mail.utils.exception_log import ExceptionLog
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.open_pgp_analyzer import OpenPGPAnalyzer
from syr.html import firewall_html
from syr.timestamp import Timestamp


class DecryptFilter(CryptoFilter):
    '''
        Decrypt message filter.

        This filter tries all known encryption software for the recipient.
        Because encryption may be nested, this class keeps trying until the
        message is decrypted, or no valid encryption program can decrypt it further.

        !!!! If part of a message is plaintext and part encrypted, the decrypted
             text replaces the entire text, and the plaintext part is lost.

        !!!! A multiply-encrypted message may be tagged decrypted if any layer
             is successfully decrypted, even if an inner layer is still encrypted.
             
        See the unit tests to see how to use the DecryptFilter class. Doctests for internal only 
        function are used more to thorough test the code, then to document the function. 
        Frequently non-standard test cases are created to test all paths in the software 
        and not intended to be used as understanding how you should generally use the internal functions.
    '''

    DEBUGGING = False
    USE_ANALYZER = False

    #  the encrypted content is the second part; indexing starts at 0
    ENCRYPTED_BODY_PART_INDEX = 1

    
    
    def __init__(self):
        '''
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter != None
            True
        '''

        super(DecryptFilter, self).__init__()
        
        self.log = LogFile()
        
        self.recipient = None
        self.crypto_message = None


    def crypt_from(self, crypto_msg, from_user, to_user):
        ''' 
            If the message is encrypted, try to decrypt it using the first valid crypto recipient.
            If it's not encrypted, tag it.

            >>> # In honor of Glenn Greenwald, who helped publicize the global surveillance disclosure documents.
            
            >>> # The following test needs to let GoodCrypto Mail encryt a message from a remote user
            >>> # so we can encrypt a message with the key in the header and then we'll change
            >>> # the domain back to goodcrypto.local and delete the remote contact/key
            >>> # and finally verify that we can decrypt a message from a user when the
            >>> # remote user's key is only in the header and not already in our local system
            >>> from time import sleep
            >>> from goodcrypto.mail import contacts, contacts_passcodes
            >>> from goodcrypto.mail.options import auto_exchange_keys, set_auto_exchange_keys, set_domain
            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto.mail.messages.encrypt_filter import EncryptFilter
            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> from goodcrypto.oce import constants as oce_constants
            >>> from goodcrypto.oce.rq_gpg_settings import GPG_QUEUE, GPG_REDIS_PORT
            >>> from goodcrypto.utils.manage_queue import wait_until_queue_empty
            >>> set_domain('goodcrypto.remote')
            >>> email = oce_constants.GLENN_REMOTE_USER
            >>> contacts.add(email, CryptoFactory.DEFAULT_ENCRYPTION_NAME) is not None
            True
            >>> # give the system time to gen the key so we can use it
            >>> sleep(120)
            >>> wait_until_queue_empty(GPG_QUEUE, GPG_REDIS_PORT)
            >>> auto_x_keys = auto_exchange_keys()
            >>> set_auto_exchange_keys(True)
            >>> with open(get_plain_message_name('basic.txt')) as input_file:
            ...     crypto_message = CryptoMessage(EmailMessage(input_file))
            ...     encrypt_filter = EncryptFilter()
            ...     encrypt_filter.crypt_from_to(crypto_message, email, oce_constants.EDWARD_LOCAL_USER)
            ...     contacts.delete(email)
            ...     set_domain('goodcrypto.local')
            ...     dfilter = DecryptFilter()
            ...     dfilter.crypt_from(crypto_message, email, oce_constants.EDWARD_LOCAL_USER)
            ...     raw_message = crypto_message.get_email_message().to_string()
            ...     raw_message.find('GoodCrypto: received this message securely.') > 0
            ...     raw_message.find(international_strings.NEW_KEY_TAGLINE) > 0
            ...     raw_message.find('This message was signed by Glenn <glenn@goodcrypto.remote>.') > 0
            (True, True)
            True
            (True, True)
            True
            True
            True
            >>> set_auto_exchange_keys(auto_x_keys)
            >>> contacts.get(email) is not None
            True
            >>> set_domain('goodcrypto.remote')
            >>> contacts.delete(email)
            True
            >>> set_domain('goodcrypto.local')
            >>> contact = contacts.add(oce_constants.GLENN_REMOTE_USER, CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> contacts.delete_contacts_crypto(oce_constants.GLENN_REMOTE_USER, CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            True
        '''

        filtered = False
        decrypted = False
        self.crypto_message = crypto_msg
        self.recipient = to_user
 
        if self.crypto_message is None or from_user is None or to_user is None:
            self.log.write("missing key info; crypto_message: {}; from_user: {}; to_user: {}".format(
                self.crypto_message, from_user, to_user))
        else:
            self.log.write("decrypting message from {} to {}".format(from_user, to_user))
            if DecryptFilter.DEBUGGING:
                self.log.write('original message:\n{}'.format(self.crypto_message.get_email_message().to_string()))

            if options.auto_exchange_keys():
                header_keys = HeaderKeys()
                header_keys.manage_keys_in_header(self.recipient, from_user, self.crypto_message)
            
            if self.crypto_message.is_dropped():
                filtered = True
                decrypted = False
                self.log.write("message dropped because of bad key")
            else:
                if self.crypto_message.get_email_message().is_probably_pgp():
                    if not self.crypto_message.is_dropped():
                        filtered, decrypted = self._decrypt_from(from_user, to_user)
                else:
                    decrypt_utils.check_signature(from_user, self.crypto_message)
    
                    self.crypto_message.add_prefix_to_tag('{}{}'.format(
                      international_strings.WARNING_PREFIX, international_strings.INSECURE_MESSAGE_TAG))
                    filtered = decrypt_utils.add_tag_to_message(self.crypto_message)
                    decrypted = False
                    self.log.write("message doesn't appear to be encrypted")
    
            self.log.write('  final status: filtered: {} decrypted: {}'.format(filtered, decrypted))

        return filtered, decrypted


    def _decrypt_from(self, from_user, to_user):
        ''' 
            Decrypt a message (internal use only).

            Testing extreme cases only because this is an internal method.
            See the unit tests to see how to use the DecryptFilter class.
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter._decrypt_from(EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR)
            (False, False)
            
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter._decrypt_from(None, None)
            (False, False)
            
            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter.crypto_message = CryptoMessage()
            >>> decrypt_filter._decrypt_from(None, None)
            (False, False)
        '''

        filtered = False
        decrypted = False

        if self.crypto_message is None or from_user is None or to_user is None:
            self.log.write("missing key info; crypto_message: {}; from_user: {}; to_user: {}".format(
                self.crypto_message, from_user, to_user))
        else:
            try:
                encryption_software = utils.get_encryption_software(to_user)
                if encryption_software and len(encryption_software) > 0:
                    self.log.write("encryption software: {}".format(encryption_software))
                    decrypted = self._decrypt_message(encryption_software, from_user, to_user)
                elif email_in_domain(to_user) and options.create_private_keys():
                    self.crypto_message.add_tag_once(international_strings.NO_KEY_TO_DECRYPT.format(to_user))
                    self.crypto_message.create_private_key(encryption_software, to_user)
                    self.log.write("started to create a new {} key for {}".format(encryption_software, to_user))
                else:
                    self.log.write("no encryption software for {}".format(to_user))
                    self.crypto_message.add_tag_once(NO_CRYPTO_TO_DECRYPT.format(to_user))
                    if contacts_passcodes.ok_to_send_notice(to_user, encryption_name, datetime.today()):
                        notify_user(to_user, subject, message)

                if options.filter_html():
                    self._filter_html()
                else:
                    self.log.write("html filter disabled")
            except CryptoException as crypto_exception:
                raise CryptoException(crypto_exception.value)
            except Exception, IOError:
                self.log_crypto_exception(MessageException(format_exc()))
                self.log.write(format_exc())
                try:
                    self.crypto_message.add_tag(
                        international_strings.SERIOUS_ERROR_PREFIX)
                except Exception:
                    self.log.write(format_exc())
                
            filtered = decrypt_utils.add_tag_to_message(self.crypto_message)

        return filtered, decrypted


    def _decrypt_message(self, encryption_names, from_user, to_user):
        ''' 
            Decrypt a message and add a tag if unsuccessful (internal use only).

            >>> # In honor of Coleen Rowley, a former FBI agent and whistleblower about 9-11.
            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR
            >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    decrypt_filter.crypto_message.set_crypted(True)
            ...    decrypt_filter._decrypt_message(
            ...      [CryptoFactory.DEFAULT_ENCRYPTION_NAME],  
            ...      EDWARD_LOCAL_USER_ADDR, 'coleen@goodcrypto.remote')
            ...    decrypt_filter.crypto_message.get_tag().find("coleen@goodcrypto.remote does not have a private GPG key.") >= 0
            ...    decrypt_filter.crypto_message.get_tag().find("Unable to decrypt message with GPG") >= 0
            False
            True
            True
            
            >>> # In honor of Kathryn Bolkovac, a Nebraska cop who served as a peacekeeper in post-war Bosnia and 
            >>> # outed the U.N. for covering up a sex scandal.
            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR
            >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    decrypt_filter.crypto_message.set_crypted(True)
            ...    decrypt_filter._decrypt_message(
            ...     [CryptoFactory.DEFAULT_ENCRYPTION_NAME, 'TestPGP'], 
            ...     EDWARD_LOCAL_USER_ADDR, 'kathryn@goodcrypto.remote')
            ...    decrypt_filter.crypto_message.get_tag().find("kathryn@goodcrypto.remote does not have a private GPG key.") >= 0
            ...    decrypt_filter.crypto_message.get_tag().find("kathryn@goodcrypto.remote does not have a private TestPGP key.") >= 0
            ...    decrypt_filter.crypto_message.get_tag().find("Unable to decrypt message with ['GPG', 'TestPGP']") >= 0
            False
            True
            True
            True
            
            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter._decrypt_message([CryptoFactory.DEFAULT_ENCRYPTION_NAME], None, None)
            False
            
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter._decrypt_message(None, None, None)
            False
        '''

        if encryption_names is None or self.crypto_message is None or to_user is None:
            decrypted = False
            self.log.write('unable to decrypt message when missing data')
        else:
            try:
                decrypted = self._decrypt_with_all_encryption(
                  encryption_names, from_user, to_user)
                    
                #  if the message is still encrypted, log it and tell the user
                if not decrypted and self.crypto_message.get_email_message().is_probably_pgp():
                    if len(encryption_names) > 1:
                        software = encryption_names.__str__()
                    else:
                        software = str(encryption_names[0])
        
                    log_msg = "Failed to decrypt with {}".format(software)
                    self.log.write(log_msg)
                    ExceptionLog.log_message(log_msg)
                    
                    tag = international_strings.UNABLE_TO_DECRYPT.format(software)
                    self.crypto_message.add_tag_once(tag)
            except CryptoException as crypto_exception:
                raise CryptoException(crypto_exception.value)
            except Exception:
                decrypted = False
                self.log.write(format_exc())
            
        return decrypted

    def _decrypt_with_all_encryption(self, encryption_names, from_user, to_user):
        ''' 
            Decrypt a message using all known encryption (internal use only).

            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR
            >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    decrypt_filter._decrypt_with_all_encryption(
            ...      [CryptoFactory.DEFAULT_ENCRYPTION_NAME, 'TestPGP'], 
            ...      CHELSEA_LOCAL_USER_ADDR, EDWARD_LOCAL_USER_ADDR)
            ...    decrypt_filter.crypto_message.is_crypted()
            False
            False

            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR
            >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    decrypt_filter._decrypt_with_all_encryption(
            ...     [CryptoFactory.DEFAULT_ENCRYPTION_NAME], 
            ...     EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR)
            ...    decrypt_filter.crypto_message.is_crypted()
            False
            False

            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter._decrypt_with_all_encryption([CryptoFactory.DEFAULT_ENCRYPTION_NAME], None, None)
            False
            
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter._decrypt_with_all_encryption(None, None, None)
            False
        '''

        decrypted = False
        try:
            #  the sender probably used the order of services in the
            #  AcceptedEncryptionSoftware header we sent out, so we want to
            #  use them in reverse order
            #  move to the end of the list, and back up
            i = len(encryption_names)
            self.log.write("encrypted {} time(s)".format(i))
            while i > 0:
                i -= 1
                encryption_name = encryption_names[i]
                if self.crypto_message.get_email_message().is_probably_pgp():
                    try:
                        if self._decrypt_message_with_crypto(encryption_name, from_user, to_user):
                            #  if any encryption decrypts, the message was decrypted
                            decrypted = True
                            self.crypto_message.set_crypted(decrypted)
                            self.log.write("decrypted using {}".format(encryption_name))
                    except CryptoException as crypto_exception:
                        raise CryptoException(crypto_exception.value)
                    except Exception:
                        msg = 'Could not decrypt with {}.'.format(encryption_name) 
                        self.log.write(msg)
                        self.log.write(format_exc())
                else:
                    self.log.write("message already decrypted, so did not try {}".format(encryption_name))
        except CryptoException as crypto_exception:
            raise CryptoException(crypto_exception.value)
        except Exception:
            self.log.write(format_exc())

        return decrypted


    def _decrypt_message_with_crypto(self, encryption_name, from_user, to_user):
        ''' 
            Decrypt a message using encryption (internal use only).

            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto.mail.messages.encrypt_filter import EncryptFilter
            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR, CHELSEA_PASSPHRASE
            >>> with open(get_plain_message_name('internal-attachment.txt')) as input_file:
            ...    crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    encrypt_filter = EncryptFilter()
            ...    encrypt_filter.crypt_from_to(
            ...      crypto_message, EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR)
            ...    input_message = crypto_message.get_email_message()
            ...    input_message.get_message().get_content_type()
            ...    crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(input_message)
            ...    decrypt_filter._decrypt_message_with_crypto(
            ...      CryptoFactory.DEFAULT_ENCRYPTION_NAME, 
            ...      EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR)
            ...    decrypt_filter.crypto_message.get_email_message().get_message().get_content_type()
            (True, True)
            'multipart/encrypted'
            True
            'multipart/mixed'
            
            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR
            >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    decrypt_filter._decrypt_message_with_crypto(
            ...      CryptoFactory.DEFAULT_ENCRYPTION_NAME, 
            ...      CHELSEA_LOCAL_USER_ADDR, EDWARD_LOCAL_USER_ADDR)
            False
            
            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR
            >>> with open(get_plain_message_name('basic.txt')) as input_file:
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    decrypt_filter._decrypt_message_with_crypto(
            ...      CryptoFactory.DEFAULT_ENCRYPTION_NAME, CHELSEA_LOCAL_USER_ADDR, EDWARD_LOCAL_USER_ADDR)
            False
            
            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR
            >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    decrypt_filter._decrypt_message_with_crypto(
            ...      CryptoFactory.DEFAULT_ENCRYPTION_NAME, CHELSEA_LOCAL_USER_ADDR, EDWARD_LOCAL_USER_ADDR)
            False
            
            >>> # In honor of vmon, Farsi translator and support for Tor.
            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR
            >>> to_user = 'vmon@goodcrypto.local'
            >>> # create a key and database record
            >>> contact = contacts.add(to_user, CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> key_crypto = KeyFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> # then delete the key, but not the database record
            >>> result_ok = key_crypto.delete(to_user)
            >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    decrypt_filter._decrypt_message_with_crypto(
            ...      CryptoFactory.DEFAULT_ENCRYPTION_NAME, EDWARD_LOCAL_USER_ADDR, to_user)
            Traceback (most recent call last):
                ...
            CryptoException: 'There is no GPG key for vmon@goodcrypto.local.'
            >>> contacts.delete(to_user)
            True
        '''

        decrypted = False
        self.log.write("encryption program: {}".format(encryption_name))
        
        passcode = contacts_passcodes.get_passcode(to_user, encryption_name)
        if passcode == None or len(passcode) <= 0:
            tag = international_strings.NO_PRIVATE_KEY.format(to_user, encryption_name)
            self.log.write(tag)
            self.crypto_message.add_tag_once(tag)
        else:
            # make sure that the key for the recipient is ok; if it's not, a CryptoException is thrown
            contacts.is_key_ok(to_user, encryption_name)
            self.log.write('{} {} key pinned'.format(to_user, encryption_name))

            crypto = CryptoFactory.get_crypto(encryption_name, crypto_software.get_classname(encryption_name))

            # try to verify signature in case it was signed after it was encrypted
            decrypt_utils.check_signature(
               from_user, self.crypto_message, encryption_name=crypto.get_name(), crypto=crypto)

            self.log.write('trying to decrypt using {} private {} key.'.format(to_user, encryption_name))
            if self.crypto_message.get_email_message().is_open_pgp_mime():
                decrypted = self._decrypt_open_pgp_mime(crypto, to_user, passcode)
            else:
                decrypted = self._decrypt_original_pgp(crypto, to_user, passcode)
            self.log.write('decrypted using {} private {} key: {}'.format(to_user, encryption_name, decrypted))
                
            # try to verify signature in case it was signed before it was encrypted
            if decrypted:
                decrypt_utils.check_signature(
                   from_user, self.crypto_message, encryption_name=crypto.get_name(), crypto=crypto)

        return decrypted


    def _decrypt_open_pgp_mime(self, crypto, to_user, passcode):
        ''' 
            Decrypt an open PGP MIME message (internal use only).

            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('open-pgp-mime.txt')) as input_file:
            ...    crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    decrypt_filter._decrypt_open_pgp_mime(crypto, None, 'test')
            False

            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter.crypto_message = CryptoMessage(EmailMessage())
            >>> decrypt_filter._decrypt_open_pgp_mime(crypto, None, 'test')
            False
        '''

        decrypted = False
        plaintext = None
        encrypted_part = None
        
        try:
            self.log.write("message is in OpenPGP MIME format")
            if self.DEBUGGING: self.log.write("{}".format(self.crypto_message.get_email_message().to_string()))
            payloads = self.crypto_message.get_email_message().get_message().get_payload()
            self.log.write("{} parts in message".format(len(payloads)))

            encrypted_part = payloads[self.ENCRYPTED_BODY_PART_INDEX]
            if isinstance(encrypted_part, Message):
                encrypted_part = encrypted_part.get_payload()
            if DecryptFilter.DEBUGGING:
                self.log.write("encrypted_part\n{}".format(encrypted_part))
            plaintext = self._decrypt(encrypted_part, crypto, to_user, passcode)
        except CryptoException as crypto_exception:
            raise CryptoException(crypto_exception.value)
        except Exception:
            self.log.write(format_exc())

        if plaintext == None or encrypted_part is None or plaintext == encrypted_part:
            decrypted = False
            self.log.write("unable to decrypt message")

        else:
            filtered = self._extract_embedded_message(plaintext)
            self.crypto_message.set_filtered(filtered)
            decrypted = self.crypto_message.is_crypted()
        
        return decrypted


    def _decrypt_original_pgp(self, crypto, to_user, passcode):
        ''' 
            Decrypt an original open PGP message (internal use only).

            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto.mail.messages.encrypt_filter import EncryptFilter
            >>> from goodcrypto_tests.mail.mail_test_utils import get_basic_email_message
            >>> from goodcrypto.oce import constants as oce_constants
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR, CHELSEA_PASSPHRASE
            >>> crypto_message = CryptoMessage(get_basic_email_message())
            >>> encrypt_filter = EncryptFilter()
            >>> encrypt_filter.crypt_from_to(
            ...    crypto_message, EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR)
            (True, True)
            >>> crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter.crypto_message = crypto_message
            >>> decrypt_filter._decrypt_original_pgp(crypto, EDWARD_LOCAL_USER_ADDR, CHELSEA_PASSPHRASE)
            True
            
            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> with open(get_encrypted_message_name('basic.txt')) as input_file:
            ...    crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    decrypt_filter._decrypt_original_pgp(crypto, None, 'test')
            False

            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter.crypto_message = CryptoMessage(EmailMessage())
            >>> decrypt_filter._decrypt_original_pgp(crypto, None, 'test')
            False
        '''

        decrypted = False
        
        self.log.write("message is in original PGP format")
        message = self.crypto_message.get_email_message().get_message()
        self.log.write("message content type is {}".format(message.get_content_type()))
        
        if message.is_multipart():
            for part in message.get_payload():
                content_type = part.get_content_type()
                ciphertext = part.get_payload(decode=True)
                
                #  ASCII armored plaintext looks just like armored ciphertext,
                #  so check that we actually have encrypted data
                open_pgp_analyzer = OpenPGPAnalyzer()
                if (not self.USE_ANALYZER or 
                   open_pgp_analyzer.is_encrypted(ciphertext, passphrase=passcode, crypto=crypto)):

                    plaintext = self._decrypt(ciphertext, crypto, to_user, passcode)
                    if plaintext is not None and plaintext != ciphertext:
                        decrypted = True
                        part.set_payload(plaintext)
        else:
            ciphertext = self.crypto_message.get_email_message().get_content()
            plaintext = self._decrypt(ciphertext, crypto, to_user, passcode)

            if plaintext is None or ciphertext is None or plaintext == ciphertext:
                decrypted = False
                self.log.write("unable to decrypt {} message".format(message.get_content_type()))
            else:
                self.crypto_message.get_email_message().set_text(plaintext)
                decrypted = True
        
        return decrypted


    def _decrypt(self, data, crypto, to_user, passcode):
        ''' 
            Decrypt the data from a message (internal use only).

            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto.mail.messages.encrypt_filter import EncryptFilter
            >>> from goodcrypto_tests.mail.mail_test_utils import get_basic_email_message
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER_ADDR, CHELSEA_LOCAL_USER_ADDR, CHELSEA_PASSPHRASE
            >>> from_user = EDWARD_LOCAL_USER_ADDR
            >>> to_user = CHELSEA_LOCAL_USER_ADDR
            >>> to_user_passphrase = CHELSEA_PASSPHRASE
            >>> crypto_message = CryptoMessage(get_basic_email_message())
            >>> encrypt_filter = EncryptFilter()
            >>> encrypt_filter.crypt_from_to(crypto_message, from_user, to_user)
            (True, True)
            >>> crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter.crypto_message = crypto_message 
            >>> decrypt_filter._decrypt(decrypt_filter.crypto_message.get_email_message().get_content(), 
            ...   crypto, to_user, to_user_passphrase) is not None
            True

            >>> from goodcrypto.oce.constants import CHELSEA_LOCAL_USER_ADDR, EDWARD_PASSPHRASE
            >>> from_user = CHELSEA_LOCAL_USER_ADDR
            >>> to_user_passphrase = EDWARD_PASSPHRASE
            >>> crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter._decrypt('unencrypted data', crypto, to_user, to_user_passphrase) is None
            True
        '''

        decrypted_data = None

        if crypto is None:
            decrypted_data = None
            self.log.write("no crypto defined")
        else:
            #  ASCII armored plaintext looks just like armored ciphertext,
            #  so check that we actually have encrypted data
            open_pgp_analyzer = OpenPGPAnalyzer()
            if (not self.USE_ANALYZER or 
                open_pgp_analyzer.is_encrypted(data, passphrase=passcode, crypto=crypto)):
                decrypted_data, result_code = crypto.decrypt(data, passcode)
                if decrypted_data == None or len(decrypted_data) <= 0:
                    decrypted_data = None
                    self.log.write("unable to decrypt data")
                    if self.DEBUGGING: self.log.write('data:\n{}'.format(data))
                else:
                    if result_code == 2:
                        self.crypto_message.add_tag_once(international_strings.UNKNOWN_SIG)
                    self.log.write('plaintext length: {}'.format(len(decrypted_data)))
                    if self.DEBUGGING: self.log.write('plaintext:\n{}'.format(decrypted_data))
            else:
                decrypted_data = None
                self.log.write("data appeared encrypted, but wasn't")
                if self.DEBUGGING: self.log.write('data:\n{}'.format(data))

        return decrypted_data


    def _extract_embedded_message(self, plaintext):
        '''
            Extract an embedded message.
            
            If the message includes an Open PGP header, then
            save the plaintext in the email message. Otherwise,
            create a new email message from the embedded message.

            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_encrypted_message_name
            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> with open(get_encrypted_message_name('internal-attachment.txt')) as input_file:
            ...    with open(get_plain_message_name('internal-attachment.txt')) as plaintext_file:
            ...       plaintext = ''.join(plaintext_file.readlines())
            ...       decrypt_filter = DecryptFilter()
            ...       decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...       decrypt_filter._extract_embedded_message(plaintext)
            ...       decrypt_filter.crypto_message.get_email_message().get_message().get_content_type()
            True
            'multipart/mixed'

            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> with open(get_plain_message_name('internal-attachment.txt')) as input_file:
            ...    plaintext = ''.join(input_file.readlines())
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    decrypt_filter._extract_embedded_message(plaintext)
            ...    decrypt_filter.crypto_message.get_email_message().get_message().get_content_type()
            False
            'text/plain'

            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter._extract_embedded_message(None)
            False
        '''

        extracted_embedded_message = False
        
        try:
            if self.DEBUGGING: self.log.write('embbedded message:\n{}'.format(plaintext))
            encrypted_type = utils.get_first_header(
                self.crypto_message.get_email_message().get_message(), PGP_ENCRYPTED_CONTENT_TYPE)
            if encrypted_type is None:
                self.log.write("saved decrypted text in content")
                self.crypto_message.get_email_message().set_text(plaintext)
                self.crypto_message.set_crypted(True)
            else:
                #  this assumes an embedded mime message
                self.log.write("openpgp mime type: {}".format(encrypted_type))
                embedded_message = EmailMessage(plaintext)
                self.crypto_message.set_email_message(embedded_message)
                self.crypto_message.set_crypted(True)
                extracted_embedded_message = True
                self.log.write("embedded message type is {}".format(
                   embedded_message.get_message().get_content_type()))
        except Exception:
            self.log.write(format_exc())
            ExceptionLog.log_message(format_exc())

        return extracted_embedded_message


    def _filter_html(self):
        ''' 
            Filter HTML to remove malious code (internal use only).
             Test adding tags to multipart/mixed
            >>> from goodcrypto.mail.messages.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.mail_test_utils import get_plain_message_name
            >>> with open(get_plain_message_name('bad-html.txt')) as input_file:
            ...    crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    crypto_message.set_crypted(True)
            ...    original_message_string = crypto_message.get_email_message().to_string()
            ...    decrypt_filter = DecryptFilter()
            ...    decrypt_filter.crypto_message = crypto_message
            ...    decrypt_filter._filter_html()
            ...    final_message_string = decrypt_filter.crypto_message.get_email_message().to_string()
            ...    original_message_string != final_message_string
            True

            Test extreme case.
            >>> decrypt_filter = DecryptFilter()
            >>> decrypt_filter._filter_html()
        '''

        try:
            message = self.crypto_message.get_email_message().get_message()
            for part in message.walk():
                part_content_type = part.get_content_type()
                # filter html and plain text 
                if (part_content_type == mime_constants.TEXT_HTML_TYPE or
                    part_content_type == mime_constants.TEXT_PLAIN_TYPE):
                
                    original_payload = part.get_payload()
                    safe_payload = firewall_html(original_payload)
                    if original_payload != safe_payload:
                        try:
                            # strip extraneous </html>
                            HTML_CLOSE = '</html>'
                            if (part_content_type == mime_constants.TEXT_PLAIN_TYPE and
                                safe_payload.lower().find('<html>') < 0):
                                index = safe_payload.find(HTML_CLOSE)
                                if index >= 0:
                                    safe_payload = '{} {}'.format(
                                       safe_payload[0:index], safe_payload[index+len(HTML_CLOSE):])
                        except:
                            self.log.write(format_exc())
                            pass
                        part.set_payload(safe_payload)
                        self.log.write("html filtered {} content".format(part_content_type))
        except Exception:
            self.log.write(format_exc())

