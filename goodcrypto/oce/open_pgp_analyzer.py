#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-09-19

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from time import sleep
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory


class OpenPGPAnalyzer(object):
    '''
        OpenPGP analyzer.

        Currently this is a *very* simply analyzer which relies on GPG to list packets.
        
        It would be ideal if we could find a packet analyzer as good as
        Bouncy Castle. Perhaps someone has/will build a command line interface
        to allow 3rd party programs to access this excellent java encryption tool.
    '''


    def __init__(self):
        '''
            >>> analyzer = OpenPGPAnalyzer()
            >>> analyzer != None
            True
        '''

        super(OpenPGPAnalyzer, self).__init__()
        self.log = LogFile()


    def is_encrypted(self, data, passphrase=None, crypto=None):
        '''
            Determines if the data is encrypted.

            >>> from goodcrypto.oce import constants as oce_constants
            >>> plugin = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> encrypted_data = plugin.sign_encrypt_and_armor(
            ...   oce_constants.TEST_DATA_STRING, oce_constants.EDWARD_LOCAL_USER,
            ...   oce_constants.JOSEPH_REMOTE_USER, oce_constants.EDWARD_PASSPHRASE)
            >>> analyzer = OpenPGPAnalyzer()
            >>> analyzer.is_encrypted(
            ...    bytearray(encrypted_data), crypto=plugin, passphrase=oce_constants.EDWARD_PASSPHRASE)
            True
        '''

        encrypted = False
        try:
            if crypto is None or 'list_packets' not in dir(crypto):
                crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            packets = crypto.list_packets(data, passphrase=passphrase)
            encrypted = packets is not None and len(packets) > 0
        except CryptoException as crypto_exception:
            self.log.write(crypto_exception.value)
            
        self.log.write('data encrypted: {}'.format(encrypted))

        return encrypted


    def is_signed(self, data, crypto=None):
        '''
            Determines if the data is signed.

            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER, EDWARD_PASSPHRASE
            >>> plugin = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            >>> signed_data = plugin.sign('This is a test', EDWARD_LOCAL_USER, EDWARD_PASSPHRASE)
            >>> analyzer = OpenPGPAnalyzer()
            >>> analyzer.is_signed(signed_data, crypto=plugin)
            True
        '''

        signed = False
        try:
            if crypto is None:
                crypto = CryptoFactory.get_crypto(CryptoFactory.DEFAULT_ENCRYPTION_NAME)
            signer = crypto.get_signer(data)
            signed = signer is not None and len(signer) > 0
        except CryptoException as crypto_exception:
            self.log.write(crypto_exception.value)
            
        self.log.write('data signed: {}'.format(signed))

        return signed

