'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-11-19

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.utils.exception_log import ExceptionLog
from goodcrypto.oce.utils import parse_address


class CryptoFilter(object):
    '''
         Common constants and methods for encrypting and decrypting messages.

         The "crypt" methods may be used for either encryption or decryption.

         Subclasses are required to override at least one of 
         <code>crypt_from</code> or <code>crypt_from_to</code>.
    '''

    log = None

    def crypt_from_to(self, crypto_message, from_user, to_user):
        ''' 
            Crypt a message.

            >>> from goodcrypto.mail.message.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> crypto_message = CryptoMessage(get_basic_email_message())
            >>> crypto_filter = CryptoFilter()
            >>> crypto_filter.crypt_from_to(crypto_message, 'edward@goodcrypto.local', 'chelsea@goodcrypto.local')
            (False, False)
        '''

        is_filtered = False
        is_crypted = False

        return is_filtered, is_crypted


    def crypt_from(self, crypto_message, from_user, to_user):
        '''
            Crypt a message.

            >>> from goodcrypto.mail.message.crypto_message import CryptoMessage
            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> crypto_message = CryptoMessage(get_basic_email_message())
            >>> crypto_filter = CryptoFilter()
            >>> crypto_filter.crypt_from(crypto_message, 'edward@goodcrypto.local', 'chelsea@goodcrypto.local')
            (False, False)

            >>> crypto_filter = CryptoFilter()
            >>> crypto_filter.crypt_from(None, 'edward@goodcrypto.local', 'chelsea@goodcrypto.local')
            (False, False)
        '''

        is_filtered = False
        is_crypted = False

        try:
            if to_user == None:
                self.log_crypto_exception(None, "No recipient addresses: {}".format(crypto_message.to_string()))
            else:
                _, address = parse_address(to_user)
                self.log_message("calling crypt_from_to with to_user={}".format(address))
                is_filtered, is_crypted = self.crypt_from_to(crypto_message, from_user, address)
                    
            self.log_message('  crypto status: filtered: {}; encrypted: {}'.format(
                crypto_message.is_filtered(), crypto_message.is_crypted()))
        except Exception:
            self.log_message(format_exc())
            
        self.log_message('  final status: filtered: {}; encrypted: {}'.format(is_filtered, is_crypted))

        return is_filtered, is_crypted

    def log_crypto_exception(self, exception, message=None):
        '''
            Log the message to the local and Exception logs.
            
            >>> CryptoFilter().log_crypto_exception(Exception)
            
            >>> CryptoFilter().log_crypto_exception(Exception, 'exception message')
        '''


        if message is not None:
            self.log_message(message)
        
        if exception is not None:
            self.log_message("Crypto error: {}".format(exception))
            self.log_message(str(exception))
            ExceptionLog.log_message(str(exception))

    def log_message(self, message):
        '''
            Log the message to the local log.
            
            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> CryptoFilter().log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.crypto_filter.log'))
            True
        '''


        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

