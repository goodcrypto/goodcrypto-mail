'''
    Sync the django database and 
    the encryption databases (i.e., keyrings).

    Copyright 2014 GoodCrypto
    Last modified: 2014-12-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from base64 import b64decode
from traceback import format_exc

from goodcrypto.mail import contacts, crypto_software
from goodcrypto.mail.rq_crypto_settings import FINGERPRINT_SUFFIX
from goodcrypto.mail.utils.queues import remove_queue_semaphore
from goodcrypto.oce import constants as oce_constants
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import parse_address
from goodcrypto.utils.log_file import LogFile
#from syr.log import get_log


def set_fingerprint(email_address, crypto_name):
    '''
        Set the fingerprint in the contacts' crypto record.
    '''

    set_log = LogFile(filename='goodcrypto.mail.sync_crypto_fingerprint.log')
    result_ok = False
    try:
        __, email = parse_address(b64decode(email_address))
        try:
            set_log.write_and_flush('starting to set_fingerprint for {}'.format(email))
            set_fingerprint_class = SetFingerprint(email, b64decode(crypto_name))
            if set_fingerprint_class:
                result_ok = set_fingerprint_class.save()
            else:
                result_ok = False
        except Exception as exception:
            result_ok = False
        finally:
            remove_queue_semaphore(email, FINGERPRINT_SUFFIX)
            set_log.write_and_flush('finished set_fingerprint for {}'.format(email))
    except Exception as exception:
        result_ok = False
        set_log.write_and_flush(format_exc())

    set_log.flush()

    return result_ok


class SetFingerprint(object):
    ''' 
        Set the fingerprint in the crypto's record.
    '''
    
    def __init__(self, email_address, crypto):
        '''
            >>> # In honor of Kevin Dyer, developer of fteproxy used in the Tor project.
            >>> email = 'kevin@goodcrypto.local'
            >>> crypto_name = 'GPG'
            >>> set_fingerprint_class = SetFingerprint(email, crypto_name)
            >>> set_fingerprint_class != None
            True
        '''
        
        try:
            self.log = LogFile()
            
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
                    self.result_ok = self.key_plugin is not None
        except Exception as exception:
            self.result_ok = False
            self.log.write_and_flush(format_exc())

    def save(self):
        '''
            Save the fingerprint in the database.
        '''
        
        if self.result_ok:
            try:
                # the contact's crypto record must exist or we'll get into an infinite loop
                # because whenever we add a contact's encryption for an email in our supported domain,
                # then this class is activated so we can complete the configuration
                contacts_encryption = contacts.get_contacts_crypto(self.email, self.crypto_name)
                if contacts_encryption is None:
                    self.result_ok = False
                    self.log.write_and_flush('no contact encryption record for {}'.format(self.email))
                else:
                    fingerprint, expiration_date = self.key_plugin.get_fingerprint(self.email)
                    if fingerprint is None:
                        self.result_ok = False
                        self.log.write_and_flush('unable to get {} fingerprint for {}'.format(self.crypto_name, self.email))
                    else:
                        self.result_ok = True
                        if (contacts_encryption.fingerprint is not None and
                            contacts_encryption.fingerprint != fingerprint):
                            self.log.write_and_flush('replaced old fingerprint')
            
                        contacts_encryption.fingerprint = fingerprint
                        contacts_encryption.save()
                        self.log.write_and_flush('updated {} fingerprint for {} in database'.format(
                            self.crypto_name, self.email))
            except Exception as exception:
                self.result_ok = False
                self.log.write_and_flush(format_exc())
            
        self.log.flush()

        return self.result_ok

