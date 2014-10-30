'''
    Sync the django database and 
    the encryption databases (i.e., keyrings).

    Copyright 2014 GoodCrypto
    Last modified: 2014-10-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from base64 import b64decode, b64encode
from traceback import format_exc

from goodcrypto.mail import contacts, contacts_passcodes, crypto_software, international_strings
from goodcrypto.mail.messages.notices import notify_user
from goodcrypto.mail.options import get_domain
from goodcrypto.mail.rq_crypto_settings import KEY_SUFFIX
from goodcrypto.mail.utils import email_in_domain, gen_passcode, ok_to_modify_key
from goodcrypto.mail.utils.queues import remove_queue_semaphore
from goodcrypto.oce import constants as oce_constants
from goodcrypto.oce.key.constants import EXPIRES_IN, EXPIRATION_UNIT
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import parse_address
from goodcrypto.utils.log_file import LogFile
#from syr.log import get_log


def manage(email_address, crypto_name):
    '''
        Sync a key pair, and its associated records, for an email address within our domain.
        
        >>> # In honor of Hal Finney, who contributed to PGP and created the first 
        >>> # reusable proof of work system before Bitcoin.
        >>> from goodcrypto.mail import model_signals, sync_delete_key
        >>> model_signals.TESTS_RUNNING = True
        >>> email = 'Hal <hal@goodcrypto.local>'
        >>> crypto_name = 'GPG'
        >>> contact = contacts.add(email, crypto_name)
        >>> contact is not None
        True
        >>> manage(b64encode(email), b64encode(crypto_name))
        True
        >>> sync_delete_key.delete(b64encode(email), b64encode(crypto_name))
        True
        >>> contacts.delete(email)
        True
        >>> model_signals.TESTS_RUNNING = False
    '''

    add_log = LogFile(filename='goodcrypto.mail.sync_private_crypto_key.log')
    result_ok = False
    try:
        _, email = parse_address(b64decode(email_address))
        try:
            add_log.write_and_flush('starting to add_db_key for {}'.format(email))
            sync_db_key_class = SyncDbKey(email, b64decode(crypto_name))
            if sync_db_key_class:
                result_ok = sync_db_key_class.configure()
                add_log.write_and_flush('configure result for {} ok: {}'.format(email, result_ok))
            else:
                result_ok = False
        except Exception as exception:
            result_ok = False
            add_log.write_and_flush(format_exc())
        finally:
            remove_queue_semaphore(email, KEY_SUFFIX)
            add_log.write_and_flush('finished add_db_key for {}'.format(email))
    except Exception as exception:
        result_ok = False
        add_log.write_and_flush(format_exc())

    add_log.flush()

    return result_ok


class SyncDbKey(object):
    ''' 
        Sync database records and a key pair 
        for an email address if its part of the managed domain.
    '''
    
    def __init__(self, email_address, crypto):
        '''
            >>> # In honor of Kathleen Brade, a developer on the Tor project.
            >>> email = 'kathleen@goodcrypto.local'
            >>> crypto_name = 'GPG'
            >>> sync_db_key_class = SyncDbKey(email, crypto_name)
            >>> sync_db_key_class != None
            True
            >>> sync_db_key_class.result_ok
            True
        '''
        
        try:
            self.log = LogFile()
            self.result_ok = True
            _, self.email = parse_address(email_address)
            self.crypto_name = crypto
            self.key_plugin = None
            self.new_key = False
            self.expires_in = contacts_passcodes.get_default_expiration_time()
            self.expiration_unit = contacts_passcodes.get_default_expiration_period()
            self.contacts_passcode = None

            domain = get_domain()
            if domain is None or len(domain.strip()) <= 0:
                self.result_ok = False
                self.log.write_and_flush('domain is not defined')
            elif email_address is None or len(email_address.strip()) <= 0:
                self.result_ok = False
                self.log.write_and_flush('email address not defined')
            elif not email_in_domain(email_address):
                self.result_ok = False
                self.log.write_and_flush('{} email address is not part of managed domain: {}'.format(
                    email_address, domain))
            else:
                encryption_software = crypto_software.get(crypto)
                if encryption_software is None:
                    self.result_ok = False
                    self.log.write_and_flush('{} encryption not defined in database'.format(self.crypto_name))
                elif not encryption_software.active:
                    self.result_ok = False
                    self.log.write_and_flush('{} encryption is not active'.format(self.crypto_name))
                else:
                    self.email = email_address
                    self.crypto_name = encryption_software.name
                    self.key_plugin = KeyFactory.get_crypto(
                        self.crypto_name, crypto_software.get_key_classname(self.crypto_name))

                    self.new_key = False
                    self.expires_in = contacts_passcodes.get_default_expiration_time()
                    self.expiration_unit = contacts_passcodes.get_default_expiration_period()
                    self.log.write_and_flush('initialized {} for {}'.format(self.email, self.crypto_name))

        except Exception as exception:
            self.result_ok = False
            self.log.write_and_flush(format_exc())

    def configure(self):
        '''
            Add a key pair and corresponding database records.

            >>> # In honor of David Fifield, developer and co-inventor of Flash Proxy.
            >>> from goodcrypto.mail import model_signals
            >>> model_signals.TESTS_RUNNING = True
            >>> email = 'david@goodcrypto.local'
            >>> crypto_name = 'GPG'
            >>> contact = contacts.add(email, crypto_name)
            >>> contact != None
            True
            >>> sync_db_key_class = SyncDbKey(email, crypto_name)
            >>> sync_db_key_class.configure()
            True
            >>> contacts.delete(email)
            True
            >>> sync_db_key_class.key_plugin.delete(email)
            True
            >>> model_signals.TESTS_RUNNING = False
        '''
        
        try:
            if self.result_ok:
                self._config_database()
            if self.result_ok:
                self._config_crypto()
            if self.result_ok:
                self._save_fingerprint()
        except Exception as exception:
            self.result_ok = False
            self.log.write_and_flush(format_exc())

        self.log.write_and_flush('configured {} ok: {}'.format(self.email, self.result_ok))
        self.log.flush()

        return self.result_ok

    def _config_database(self):
        ''' 
            Configure the database so we know the passcode for the key.

            >>> # In honor of John Napier Tye, a former State Department official who raised the alarm about 
            >>> # Reagan's executive order 12333 which allows the NSA to circumvent laws preventing surveillance.            >>> from goodcrypto.mail import model_signals
            >>> from goodcrypto.mail import model_signals
            >>> model_signals.TESTS_RUNNING = True
            >>> email = 'john@goodcrypto.local'
            >>> crypto_name = 'GPG'
            >>> contact = contacts.add(email, crypto_name)
            >>> contact != None
            True
            >>> sync_db_key_class = SyncDbKey(email, crypto_name)
            >>> sync_db_key_class._config_database()
            >>> sync_db_key_class.result_ok
            True
            >>> contacts.delete(email)
            True
            >>> model_signals.TESTS_RUNNING = False
        '''
    
        def get_passcode():

            # handle a few special test cases
            if self.email == oce_constants.EDWARD_LOCAL_USER_ADDR:
                new_passcode = oce_constants.EDWARD_PASSPHRASE
            elif self.email == oce_constants.CHELSEA_LOCAL_USER_ADDR:
                new_passcode = oce_constants.CHELSEA_PASSPHRASE
            elif self.email == oce_constants.JULIAN_LOCAL_USER_ADDR:
                new_passcode = oce_constants.JULIAN_PASSPHRASE
            elif self.contacts_passcode.auto_generated:
                new_passcode = gen_passcode()
                self.log.write_and_flush('generated a passcode for {}'.format(self.email))
                
            return new_passcode


        # the contact's crypto record must exist or we'll get into an infinite loop
        # because whenever we add a contact's encryption for an email in our supported domain,
        # then this class is activated so we can complete the configuration
        contacts_crypto = contacts.get_contacts_crypto(self.email, self.crypto_name)
        if contacts_crypto is None:
            self.result_ok = False
            self.log.write_and_flush('no contact encryption record for {}'.format(self.email))
        else:
            contacts_passcodes.create_passcode(self.email, self.crypto_name)
            self.contacts_passcode = contacts_passcodes.get(self.email, self.crypto_name)
            if self.contacts_passcode is None:
                self.result_ok = False
                self.log.write_and_flush("unable to create contacts {} passcode record for {}".format(self.crypto_name, self.email))

            else:
                database_passcode = self.contacts_passcode.passcode
                
        if self.result_ok:
            # if the database doesn't already have a passcode defined, then create and save one now
            if database_passcode is None or len(database_passcode.strip()) <= 0:
                self.contacts_passcode.passcode = get_passcode()
                self.contacts_passcode.save()
                self.log.write_and_flush('updated passcode in database for {}'.format(self.email))

    def _config_crypto(self):
        ''' 
            Configure the encryption software.
        '''

        if ok_to_modify_key(self.crypto_name, self.key_plugin) and self.contacts_passcode is not None:
            self.log.write_and_flush('configuring {} for {}'.format(self.crypto_name, self.email))
            passcode = self.contacts_passcode.passcode
    
            # if there's a matching private key
            if self.key_plugin.private_key_exists(self.email):
                self.result_ok = True
                self.log.write_and_flush('no need to create a {} key because {} already has one'.format(
                    self.crypto_name, self.email))
    
                # verify the passphrase is correct
                if self.key_plugin.sign('Test data', self.email, passcode) is None:
                    self.result_ok = False
                    self.log.write_and_flush("{}'s passphrase does not match {}'s key.".format(self.email, self.crypto_name))
                    notify_user(self.email, 
                        international_strings.MISMATCHED_PASSPHRASES.format(self.email, self.crypto_name),
                        international_strings.MISMATCHED_PASSPHRASES.format(self.email, self.crypto_name))
                else:
                    self.log.write_and_flush("{} {} passphrase is good.".format(self.email, self.crypto_name))
            else:
                # if there is a matching public key, delete it
                if self.key_plugin.public_key_exists(self.email):
                    self.key_plugin.delete(self.email)
                    self.log.write_and_flush("deleted old {} public key for {}".format(self.crypto_name, self.email))

                # add a private key
                user_name = self.contacts_passcode.contacts_encryption.contact.user_name
                if user_name and len(user_name) > 0:
                    full_address = '"{}" <{}>'.format(user_name, self.email)
                    self.log.write_and_flush('user name: {}'.format(user_name))
                    self.log.write_and_flush('email: {}'.format(self.email))
                else:
                    full_address = self.email
    
                self.log.write_and_flush('preparing to create {} key for {}'.format(self.crypto_name, self.email))
                expiration = {EXPIRES_IN: self.expires_in, EXPIRATION_UNIT: self.expiration_unit,}
                self.result_ok, timed_out = self.key_plugin.create(
                    full_address, passcode, expiration, wait_for_results=True)
    
                if self.result_ok:
                    self.new_key = True
                    self.log.write_and_flush('created {} key for {}'.format(self.crypto_name, self.email))
                elif timed_out:
                    self.log.write_and_flush('timed out creating a private {} key for {}.'.format(
                        self.crypto_name, self.email))
                else:
                    self.log.write_and_flush('unable to create a private {} key for {}.'.format(
                        self.crypto_name, self.email))
                    notify_user(self.email, 
                       international_strings.UNABLE_TO_CREATE_KEY.format(self.crypto_name),
                       international_strings.UNABLE_TO_CREATE_KEY.format(self.crypto_name))
        else:
            self.log.write_and_flush('not ok to create private {} key'.format(self.crypto_name))
            self.result_ok = True
            
        return self.result_ok
    
    def _save_fingerprint(self):
        '''
            Save the fingerprint in the database.

            >>> # In honor of Chelsea Manning, who leaked the Iraq and Afgan war reports.
            >>> from goodcrypto.oce.constants import CHELSEA_LOCAL_USER
            >>> email = CHELSEA_LOCAL_USER
            >>> crypto_name = 'GPG'
            >>> sync_db_key_class = SyncDbKey(email, crypto_name)
            >>> sync_db_key_class.contacts_passcode = contacts_passcodes.get(email, crypto_name)
            >>> sync_db_key_class._save_fingerprint()
            >>> sync_db_key_class.result_ok
            True
        '''
        
        if self.key_plugin is None:
            self.log.write_and_flush('no {} plugin defined for {}'.format(self.crypto_name, self.email))
        else:
            fingerprint, _ = self.key_plugin.get_fingerprint(self.email)
            if fingerprint is None:
                self.result_ok = False
                self.log.write_and_flush('unable to get {} fingerprint for {}'.format(self.crypto_name, self.email))
            elif self.contacts_passcode is None:
                self.result_ok = False
                self.log.write_and_flush('no {} passcode record defined for {}'.format(self.crypto_name, self.email))
            else:
                self.result_ok = True
                if (self.contacts_passcode.contacts_encryption.fingerprint is not None and
                    self.contacts_passcode.contacts_encryption.fingerprint != fingerprint):
                    self.log.write_and_flush('replaced old fingerprint')
    
                self.contacts_passcode.contacts_encryption.fingerprint = fingerprint
                self.contacts_passcode.contacts_encryption.verified = True
                self.contacts_passcode.contacts_encryption.save()
                self.log.write_and_flush('updated {} fingerprint for {} in database'.format(self.crypto_name, self.email))

