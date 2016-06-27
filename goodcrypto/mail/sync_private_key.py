'''
    Sync the django database and 
    the encryption databases (i.e., keyrings).

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-04-23

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from base64 import b64decode, b64encode
from traceback import format_exc

from goodcrypto.mail import contacts, contacts_passcodes, crypto_software
from goodcrypto.mail.options import get_domain, get_goodcrypto_server_url
from goodcrypto.mail.rq_crypto_settings import KEY_SUFFIX
from goodcrypto.mail.utils import email_in_domain, gen_passcode, ok_to_modify_key, create_user
from goodcrypto.mail.utils.notices import notify_user
from goodcrypto.mail.utils.queues import remove_queue_semaphore
from goodcrypto.oce import constants as oce_constants
from goodcrypto.oce.key.constants import EXPIRES_IN, EXPIRATION_UNIT
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import parse_address
from goodcrypto.utils import i18n
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
        __, email = parse_address(b64decode(email_address))
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
            __, self.email = parse_address(email_address)
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
                # first, configure the database so the passcode is saved
                self._config_database()
                if self.contacts_passcode is not None:
                    # then, create the public/private key pair
                    self._config_key_pair()
                # configure the user even if the key pair had trouble
                self._create_user()
                # and try to save the fingerprint in case 
                # the key got configured later than expected
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
                
        if self.contacts_passcode is None:
            self.log.write_and_flush("unable to configure contacts' passcode")

    def _config_key_pair(self):
        ''' 
            Configure the key pair for the user.
        '''

        if ok_to_modify_key(self.crypto_name, self.key_plugin):
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

                    MISMATCHED_PASSPHRASES = i18n("{email}'s passphrase does not match {encryption}'s key.".format(
                      email=self.email, encryption=self.crypto_name))
                    notify_user(self.email, MISMATCHED_PASSPHRASES, MISMATCHED_PASSPHRASES)
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
    
                self.log.write_and_flush('preparing to create {} key for {}'.format(
                    self.crypto_name, self.email))
                expiration = {EXPIRES_IN: self.expires_in, EXPIRATION_UNIT: self.expiration_unit,}
                self.result_ok, timed_out = self.key_plugin.create(
                    full_address, passcode, expiration, wait_for_results=True)
    
                if self.result_ok:
                    self.new_key = True
                    self.log.write_and_flush('created {} key for {}'.format(self.crypto_name, self.email))
                    subject = i18n('GoodCrypto - You can now receive private mail')
                    
                    body = i18n('You can now receive private mail from anyone using PGP.')
                    body += '\n\n'
                    body += i18n(
                          "Other GoodCrypto users don't have to do anything.")
                    body += ' '
                    body += i18n(
                       'Other PGP users need to exchange keys with you. Learn more: https://goodcrypto.com/qna/knowledge-base/export-public-key')
                    body += '\n'
                    notify_user(self.email, subject, body)
                elif timed_out:
                    self.log.write_and_flush('timed out creating a private {} key for {}.'.format(
                        self.crypto_name, self.email))
                    subject = i18n("Creating your private key timed out.")
                    notify_user(self.email, 
                       i18n("GoodCrypto - {}".format(subject)),
                       i18n("Your GoodCrypto server is probably very buzy. You might wait a 5-10 minutes and then try sending a message again. If that doesn't work, then ask your sysadmin to create your key manually."))
                else:
                    self.log.write_and_flush('unable to create a private {} key for {}.'.format(
                        self.crypto_name, self.email))
                    
                    subject = i18n('GoodCrypto - Error while creating a private key for you')
                    body = '{}\n{}'.format(
                        subject,
                       i18n("Contact your sysadmin ask them to create it for you manually."))
                    notify_user(self.email, subject, body)
        else:
            self.log.write_and_flush('not ok to create private {} key'.format(self.crypto_name))
            self.result_ok = True
        
        # return the value for the tests
        return self.result_ok

    def _create_user(self):
        '''
            Create a regular user so they can verify messages, fingerprints, etc.
        '''

        password = error_message = None
        try:
            password, error_message = create_user(self.email)
            if password is None and error_message is None:
                # user already exists so nothing to do
                self.log.write_and_flush('{} already has an account'.format(self.email))
    
            elif error_message is not None:
                details = i18n('Ask your sysadmin to add a user for your email account manually.')
                subject = 'GoodCrypto - {}'.format(error_message)
                body = '{}\n{}'.format(error_message, details)
                notify_user(self.email, subject, body)
                self.log.write_and_flush('notified {} about error: {}'.format(self.email, error_message))
    
            else:
                subject = i18n('GoodCrypto - You can now check if a message arrived privately')
                line1 = i18n(
                    'Your sysadmin has installed GoodCrypto to protect your email.')
                line2 = i18n(
                    'You will see a GoodCrypto tag on every message.' +
                    ' The tag tells you whether it arrived privately.')
                line3 = i18n("It's not likely, but that tag might be faked.")

                verify_private_msg = i18n('You can verify a private message is genuine.')
                url = get_goodcrypto_server_url()
                # if we know the private url
                if url is not None and len(url.strip()) > 0:
                    simply_click = i18n('Simply click on the link in the tag.')
                    line4 = '{} {}\n'.format(verify_private_msg, simply_click)
                else:
                    sign_in = i18n('1) Sign in to your GoodCrypto private server')
                    click_mail = i18n('2) Click "Mail"')
                    click_verify = i18n('3) Click "Verify decrypted"')
                    enter_code = i18n('4) Enter the validation code.')
                    line4 = '{}\n   {}\n   {}\n   {}\n   {}\n'.format(
                       verify_private_msg, sign_in, click_mail, click_verify, enter_code)
                    
                line5 = i18n('Use the following credentials:')
                line6 = i18n('    Username: {email}'.format(email=self.email))
                line7 = i18n('    Password: {password}'.format(password=password))
                body = '{line1}\n\n{line2}\n\n{line3} {line4}\n\n{line5}\n   {line6}\n   {line7}\n'.format(
                    line1=line1, line2=line2, line3=line3, line4=line4, line5=line5, line6=line6, line7=line7)
                notify_user(self.email, subject, body)
                self.log.write_and_flush('notified {} about new django account'.format(self.email))
    
            self.log.write_and_flush('error message {} passhrase ok: {}'.format(error_message, password is not None))
        except:
            self.log.write_and_flush(format_exc())

        return password, error_message
        
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
        elif self.contacts_passcode is None:
            self.log.write_and_flush('no {} passcode record defined for {}'.format(self.crypto_name, self.email))
        else:
            fingerprint, __ = self.key_plugin.get_fingerprint(self.email)
            if fingerprint is None:
                self.log.write_and_flush('unable to get {} fingerprint for {}'.format(self.crypto_name, self.email))
            else:
                if (self.contacts_passcode.contacts_encryption.fingerprint is not None and
                    self.contacts_passcode.contacts_encryption.fingerprint != fingerprint):
                    self.log.write_and_flush('replaced old fingerprint')
    
                self.contacts_passcode.contacts_encryption.fingerprint = fingerprint
                self.contacts_passcode.contacts_encryption.verified = True
                self.contacts_passcode.contacts_encryption.save()
                self.log.write_and_flush('updated {} fingerprint for {} in database'.format(self.crypto_name, self.email))

