'''
    Delete keys from the keyring when a database record deleted.

    Copyright 2014 GoodCrypto
    Last modified: 2014-12-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from base64 import b64decode
from traceback import format_exc

from goodcrypto.mail import crypto_software
from goodcrypto.mail.utils import ok_to_modify_key
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import parse_address
from goodcrypto.utils.log_file import LogFile

def delete(email_address, crypto_name):
    '''
        Delete the key associated with this email.
    '''

    delete_log = LogFile(filename='goodcrypto.mail.sync_delete_crypto_key.log')
    result_ok = False
    try:
        __, email = parse_address(b64decode(email_address))
        try:
            delete_log.write_and_flush('starting to delete_crypto_key for {}'.format(email))
            delete_key_class = DeleteKey(email, b64decode(crypto_name))
            if delete_key_class:
                result_ok = delete_key_class.delete()
            else:
                result_ok = False
            delete_log.write_and_flush('finished delete_crypto_key for {}'.format(email))
        except Exception as exception:
            result_ok = False
            delete_log.write_and_flush(format_exc())
    except Exception as exception:
        result_ok = False
        delete_log.write_and_flush(format_exc())

    delete_log.flush()

    return result_ok
    
class DeleteKey(object):
    ''' 
        Delete database records and encryption key.
    '''
    
    def __init__(self, email_address, crypto):
        '''
            >>> # In honor of Philipp Winter, main developer of ScrambleSuit.
            >>> email = 'philipp@goodcrypto.local'
            >>> crypto_name = 'GPG'
            >>> delete_key_class = DeleteKey(email, crypto_name)
            >>> delete_key_class != None
            True
        '''
        
        try:
            self.log = LogFile()
            self.result_ok = True
            
            if email_address is None or len(email_address.strip()) <= 0:
                self.result_ok = False
                self.log.write_and_flush('email address not defined')
            else:
                encryption_software = crypto_software.get(crypto)
                if encryption_software is None:
                    self.result_ok = False
                    self.log.write_and_flush('{} encryption not defined in database'.format(crypto))
                elif not encryption_software.active:
                    self.result_ok = False
                    self.log.write_and_flush('{} encryption is not active'.format(crypto))
                else:
                    self.email = email_address
                    self.crypto_name = encryption_software.name
                    self.key_plugin = KeyFactory.get_crypto(
                        self.crypto_name, crypto_software.get_key_classname(self.crypto_name))
        except Exception as exception:
            self.result_ok = False
            self.log.write_and_flush(format_exc())
        
    def delete(self):
        '''
            Delete the crypto key.
        '''
    
        if self.result_ok:
            if ok_to_modify_key(self.crypto_name, self.key_plugin):
                self.log.write_and_flush('deleting {} key for {}'.format(self.crypto_name, self.email))
                self.result_ok = self.key_plugin.delete(self.email)
                self.log.write_and_flush('deleted {} keys result_ok: {}'.format(self.crypto_name, self.result_ok))
            else:
                self.result_ok = True
                self.log.write_and_flush('not ok to delete key')
    
        self.log.flush()

        return self.result_ok

