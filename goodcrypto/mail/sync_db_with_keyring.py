'''
    Sync the django database and 
    the encryption databases (i.e., keyrings).

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-08-02

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, pickle
from base64 import b64decode, b64encode

from goodcrypto.mail import contacts, crypto_software, user_keys, utils
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.options import goodcrypto_server_url
from goodcrypto.mail.rq_crypto_settings import KEY_SUFFIX
from goodcrypto.mail.utils.notices import notify_user
from goodcrypto.oce.key.constants import EXPIRES_IN, EXPIRATION_UNIT
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.utils import i18n, get_email
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile

_log = None


class SyncDbWithKeyring(object):
    ''' 
        Sync database records and a key pair 
        for an email address if its part of the managed domain.
    '''
    
    def __init__(self, contacts_crypto):
        '''
            >>> # In honor of Kathleen Brade, a developer on the Tor project.
            >>> email = 'kathleen@goodcrypto.local'
            >>> crypto_name = 'GPG'
            >>> contact = contacts.add(email, crypto_name)
            >>> contacts_crypto = contacts.get_contacts_crypto(email, crypto_name)
            >>> sync_db_key_class = SyncDbWithKeyring(contacts_crypto)
            >>> sync_db_key_class != None
            True
            >>> sync_db_key_class.result_ok
            True
            >>> contacts.delete(email)
            True
        '''
        
        try:
            self.contacts_crypto = contacts_crypto
            self.user_key = None
            self.new_key = False

            self.result_ok, self.crypto_name, self.email, self.key_plugin = prep_sync(self.contacts_crypto)
            if self.result_ok:
                domain = get_domain()
                if domain is None or len(domain.strip()) <= 0:
                    self.result_ok = False
                    log_message('domain is not defined')
                elif self.email is None or len(self.email.strip()) <= 0:
                    self.result_ok = False
                    log_message('email address not defined')
                elif not utils.email_in_domain(self.email):
                    self.result_ok = False
                    log_message('{} email address is not part of managed domain: {}'.format(
                        self.email, domain))
                else:
                    self.new_key = False
                    self.expires_in = user_keys.get_default_expiration_time()
                    self.expiration_unit = user_keys.get_default_expiration_period()
                    log_message('initialized {} for {}'.format(self.email, self.crypto_name))
            else:
                log_message('initial result is not ok')

        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            self.result_ok = False

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
            >>> contacts_crypto = contacts.get_contacts_crypto(email, crypto_name)
            >>> sync_db_key_class = SyncDbWithKeyring(contacts_crypto)
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
                if self.user_key is not None:
                    # then, create the public/private key pair
                    self._config_key_pair()
                    
                if not utils.is_metadata_address(self.email):
                    # configure a regular user even if the key pair had trouble
                    self._create_user()

                # and try to save the fingerprint in case 
                # the key got configured later than expected
                self._save_fingerprint()
            else:
                log_message('unable to configure because initial result is false')
        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            self.result_ok = False

        log_message('configured {} ok: {}'.format(self.email, self.result_ok))

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
            >>> contacts_crypto = contacts.get_contacts_crypto(email, crypto_name)
            >>> sync_db_key_class = SyncDbWithKeyring(contacts_crypto)
            >>> sync_db_key_class._config_database()
            >>> sync_db_key_class.result_ok
            True
            >>> contacts.delete(email)
            True
            >>> model_signals.TESTS_RUNNING = False
        '''
    
        # the contact's crypto record must exist or we'll get into an infinite loop
        # because whenever we add a contact's encryption for an email in our supported domain,
        # then this class is activated so we can complete the configuration
        if self.contacts_crypto is None:
            self.result_ok = False
            log_message('no contact encryption record for {}'.format(self.email))
        else:
            user_keys.create_user_key(self.email, self.crypto_name)
            self.user_key = user_keys.get(self.email, self.crypto_name)
            if self.user_key is None:
                self.result_ok = False
                log_message("unable to create contacts {} passcode record for {}".format(self.crypto_name, self.email))

            else:
                database_passcode = self.user_key.passcode
                
        if self.result_ok:
            # if the database doesn't already have a passcode defined, then create and save one now
            if database_passcode is None or len(database_passcode.strip()) <= 0:
                self.user_key.passcode = utils.gen_user_passcode(self.email)
                self.user_key.save()
                log_message('updated passcode in database for {}'.format(self.email))
                
        if self.user_key is None:
            log_message("unable to configure contacts' passcode")

    def _config_key_pair(self):
        ''' 
            Configure the key pair for the user.
        '''

        if utils.ok_to_modify_key(self.crypto_name, self.key_plugin):
            log_message('configuring {} for {}'.format(self.crypto_name, self.email))
            passcode = self.user_key.passcode
    
            # if there's a matching private key
            if self.key_plugin.private_key_exists(self.email):
                self.result_ok = True
                log_message('no need to create a {} key because {} already has one'.format(
                    self.crypto_name, self.email))
    
                # verify the passphrase is correct
                if self.key_plugin.sign('Test data', self.email, passcode) is None:
                    self.result_ok = False
                    log_message("{}'s passphrase does not match {}'s key.".format(self.email, self.crypto_name))

                    MISMATCHED_PASSPHRASES = i18n("{email}'s passphrase does not match {encryption}'s key.".format(
                      email=self.email, encryption=self.crypto_name))
                    notify_user(self.email, MISMATCHED_PASSPHRASES, MISMATCHED_PASSPHRASES)
                else:
                    log_message("{} {} passphrase is good.".format(self.email, self.crypto_name))
            else:
                # if there is a matching public key, delete it
                if self.key_plugin.public_key_exists(self.email):
                    self.key_plugin.delete(self.email)
                    log_message("deleted old {} public key for {}".format(self.crypto_name, self.email))

                # add a private key
                user_name = self.user_key.contacts_encryption.contact.user_name
                if user_name and len(user_name) > 0:
                    full_address = '"{}" <{}>'.format(user_name, self.email)
                    log_message('user name: {}'.format(user_name))
                    log_message('email: {}'.format(self.email))
                else:
                    full_address = self.email
    
                log_message('preparing to create {} key for {}'.format(
                    self.crypto_name, self.email))
                expiration = {EXPIRES_IN: self.expires_in, EXPIRATION_UNIT: self.expiration_unit,}
                self.result_ok, timed_out, key_already_existed = self.key_plugin.create(
                    full_address, passcode, expiration, wait_for_results=True)
    
                if self.result_ok:
                    if key_already_existed:
                        log_message('{} key for {} already existed'.format(self.crypto_name, self.email))
                    else:
                        self.new_key = True
                        log_message('created {} key for {}'.format(self.crypto_name, self.email))
                        if not utils.is_metadata_address(self.email):
                            subject = i18n('GoodCrypto - You can now receive private mail')
                            
                            body = i18n('You can now receive private mail.')
                            body += '\n\n'
                            body += i18n(
                                  "GoodCrypto users don't have to do anything. Their mail to you will be private.")
                            body += ' '
                            body += i18n(
                               'Basic PGP users need to exchange keys with you first. Learn more: https://goodcrypto.com/qna/knowledge-base/export-public-key')
                            body += '\n'
                            notify_user(self.email, subject, body)
                elif timed_out:
                    log_message('timed out creating a private {} key for {}.'.format(
                        self.crypto_name, self.email))
                    if not utils.is_metadata_address(self.email):
                        subject = i18n("Creating your private key timed out.")
                        notify_user(self.email, 
                           i18n("GoodCrypto - {}".format(subject)),
                           i18n("Your GoodCrypto server is probably very buzy. You might wait a 5-10 minutes and then try sending a message again. If that doesn't work, then ask your sysadmin to create your key manually."))
                else:
                    log_message('unable to create a private {} key for {}.'.format(
                        self.crypto_name, self.email))

                    if utils.is_metadata_address(self.email):
                        to_email = utils.get_sysadmin_email()
                        subject = i18n('GoodCrypto - Error while creating a private metadata key')
                        body = '{}.\n{}'.format(
                            subject,
                           i18n("Metadata cannot be protected until you create a private key for _no_metadata_@{}".format(get_domain())))
                    else:
                        to_email = self.email
                        subject = i18n('GoodCrypto - Error while creating a private key for you')
                        body = '{}.\n{}'.format(
                            subject,
                           i18n("Contact your sysadmin and ask them to create it for you manually."))
                    notify_user(to_email, subject, body)
        else:
            log_message('not ok to create private {} key'.format(self.crypto_name))
            self.result_ok = True
        
        # return the value for the tests
        return self.result_ok

    def _create_user(self):
        '''
            Create a regular user so they can verify messages, fingerprints, etc.
        '''

        password = error_message = None
        try:
            password, error_message = utils.create_user(self.email)
            if password is None and error_message is None:
                # user already exists so nothing to do
                log_message('{} already has an account'.format(self.email))
    
            elif error_message is not None:
                details = i18n('Ask your sysadmin to add a user for your email account manually.')
                subject = 'GoodCrypto - {}'.format(error_message)
                body = '{}\n{}'.format(error_message, details)
                notify_user(self.email, subject, body)
                log_message('notified {} about error: {}'.format(self.email, error_message))
    
            else:
                subject = i18n('GoodCrypto - You can now check if a message arrived privately')
                line1 = i18n(
                    'Your sysadmin has installed GoodCrypto to protect your email.')
                line2 = i18n(
                    'You will see a GoodCrypto tag on every message.' +
                    ' The tag tells you whether it arrived privately.')
                line3 = i18n("It's not likely, but that tag might be faked.")

                verify_private_msg = i18n('You can verify a private message is genuine.')
                url = goodcrypto_server_url()
                # if we know the private url
                if url is not None and len(url.strip()) > 0:
                    simply_click = i18n('Simply click on the link in the tag.')
                    line4 = '{} {}\n'.format(verify_private_msg, simply_click)
                else:
                    sign_in = i18n('1) Sign in to your GoodCrypto private server')
                    click_mail = i18n('2) Click "Mail"')
                    click_verify = i18n('3) Click "Verify decrypted"')
                    enter_code = i18n('4) Enter the verification code.')
                    line4 = '{}\n   {}\n   {}\n   {}\n   {}\n'.format(
                       verify_private_msg, sign_in, click_mail, click_verify, enter_code)
                    
                line5 = i18n('Use the following credentials:')
                line6 = i18n('    Username: {email}'.format(email=self.email))
                line7 = i18n('    Password: {password}'.format(password=password))
                body = '{line1}\n\n{line2}\n\n{line3} {line4}\n\n{line5}\n   {line6}\n   {line7}\n'.format(
                    line1=line1, line2=line2, line3=line3, line4=line4, line5=line5, line6=line6, line7=line7)
                notify_user(self.email, subject, body)
                log_message('notified {} about new django account'.format(self.email))
    
            log_message('error message {} passhrase ok: {}'.format(error_message, password is not None))
        except:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return password, error_message
        
    def _save_fingerprint(self):
        '''
            Save the fingerprint in the database.

            >>> # In honor of Chelsea Manning, who leaked the Iraq and Afgan war reports.
            >>> from goodcrypto.oce.constants import CHELSEA_LOCAL_USER
            >>> email = CHELSEA_LOCAL_USER
            >>> crypto_name = 'GPG'
            >>> contacts_crypto = contacts.get_contacts_crypto(email, crypto_name)
            >>> contacts_crypto != None
            True
            >>> sync_db_key_class = SyncDbWithKeyring(contacts_crypto)
            >>> sync_db_key_class.user_key = user_keys.get(email, crypto_name)
            >>> sync_db_key_class._save_fingerprint()
            >>> sync_db_key_class.result_ok
            True
        '''
        
        if self.key_plugin is None:
            log_message('no {} plugin defined for {}'.format(self.crypto_name, self.email))
        elif self.user_key is None:
            log_message('no {} passcode record defined for {}'.format(self.crypto_name, self.email))
        else:
            fingerprint, __ = self.key_plugin.get_fingerprint(self.email)
            if fingerprint is None:
                log_message('unable to get {} fingerprint for {}'.format(self.crypto_name, self.email))
            else:
                if (self.user_key.contacts_encryption.fingerprint is not None and
                    self.user_key.contacts_encryption.fingerprint != fingerprint):
                    log_message('replaced old fingerprint')
    
                self.user_key.contacts_encryption.fingerprint = fingerprint
                self.user_key.contacts_encryption.verified = True
                self.user_key.contacts_encryption.save()
                log_message('updated {} fingerprint for {} in database'.format(self.crypto_name, self.email))

class SetFingerprint(object):
    ''' 
        Set the fingerprint in the crypto's record.
    '''
    
    def __init__(self, contacts_crypto):
        '''
            # Test extreme case
            >>> set_fingerprint_class = SetFingerprint(None)
            >>> set_fingerprint_class != None
            True
        '''

        self.contacts_encryption = contacts_crypto
        self.result_ok, self.crypto_name, self.email, self.key_plugin = prep_sync(self.contacts_encryption)

    def save(self):
        '''
            Save the fingerprint in the database.
        '''
        
        if self.result_ok:
            try:
                # the contact's crypto record must exist or we'll get into an infinite loop
                # because whenever we add a contact's encryption for an email in our supported domain,
                # then this class is activated so we can complete the configuration
                if self.contacts_encryption is None:
                    self.result_ok = False
                    log_message('no contact encryption record for {}'.format(self.email))
                else:
                    fingerprint, expiration_date = self.key_plugin.get_fingerprint(self.email)
                    if fingerprint is None:
                        self.result_ok = False
                        log_message('unable to get {} fingerprint for {}'.format(self.crypto_name, self.email))
                    else:
                        self.result_ok = True
                        if (self.contacts_encryption.fingerprint is not None and
                            self.contacts_encryption.fingerprint != fingerprint):
                            log_message('replaced old fingerprint')
            
                        self.contacts_encryption.fingerprint = fingerprint
                        self.contacts_encryption.save()
                        log_message('updated {} fingerprint for {} in database'.format(
                            self.crypto_name, self.email))
            except Exception as exception:
                record_exception()
                log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
                self.result_ok = False
            
        return self.result_ok

class DeleteKey(object):
    ''' 
        Delete database records and encryption key.
    '''
    
    def __init__(self, contacts_crypto):
        '''
            >>> # In honor of Philipp Winter, main developer of ScrambleSuit.
            >>> from goodcrypto.mail import contacts
            >>> email = 'philipp@goodcrypto.local'
            >>> crypto_name = 'GPG'
            >>> contacts_crypto = contacts.get_contacts_crypto(email, crypto_name)
            >>> delete_key_class = DeleteKey(contacts_crypto)
            >>> delete_key_class != None
            True
        '''
        
        self.result_ok, self.crypto_name, self.email, self.key_plugin = prep_sync(contacts_crypto)
        
    def delete(self):
        '''
            Delete the crypto key.
        '''
    
        if self.result_ok:
            if utils.ok_to_modify_key(self.crypto_name, self.key_plugin):
                log_message('deleting {} key for {}'.format(self.crypto_name, self.email))
                self.result_ok = self.key_plugin.delete(self.email)
                log_message('deleted {} keys result_ok: {}'.format(self.crypto_name, self.result_ok))
            else:
                self.result_ok = True
                log_message('not ok to delete key')
    
        return self.result_ok


def sync_private_key(contacts_crypto_encoded):
    '''
        Sync a key pair, and its associated records, for an email address within our domain.
        
        >>> # In honor of Hal Finney, who contributed to PGP and created the first 
        >>> # reusable proof of work system before Bitcoin.
        >>> from goodcrypto.mail import model_signals
        >>> model_signals.TESTS_RUNNING = True
        >>> email = 'Hal <hal@goodcrypto.local>'
        >>> crypto_name = 'GPG'
        >>> contact = contacts.add(email, crypto_name)
        >>> contact is not None
        True
        >>> contacts_crypto = contacts.get_contacts_crypto(email, crypto_name)
        >>> contacts_crypto is not None
        True
        >>> sync_private_key(b64encode(pickle.dumps(contacts_crypto)))
        True
        >>> sync_deletion(b64encode(pickle.dumps(contacts_crypto)))
        True
        >>> contacts.delete(email)
        True
        >>> model_signals.TESTS_RUNNING = False
    '''

    result_ok = False
    try:
        contacts_crypto = pickle.loads(b64decode(contacts_crypto_encoded))
        email = contacts_crypto.contact.email
        try:
            log_message('starting to add_db_key for {}'.format(email))
            sync_db_key_class = SyncDbWithKeyring(contacts_crypto)
            if sync_db_key_class:
                result_ok = sync_db_key_class.configure()
                log_message('configure result for {} ok: {}'.format(email, result_ok))
            else:
                result_ok = False
        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            result_ok = False
        finally:
            log_message('finished add_db_key for {}'.format(email))
    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        result_ok = False

    return result_ok

def sync_fingerprint(contacts_crypto_encoded):
    '''
        Sync the fingerprint in the contacts' crypto record.
    '''

    result_ok = False
    try:
        contacts_crypto = pickle.loads(b64decode(contacts_crypto_encoded))
        email = contacts_crypto.contact.email
        try:
            log_message('starting to sync fingerprint for {}'.format(email))
            set_fingerprint_class = SetFingerprint(contacts_crypto)
            if set_fingerprint_class:
                result_ok = set_fingerprint_class.save()
            else:
                result_ok = False
        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            result_ok = False
        finally:
            log_message('finished set_fingerprint for {}'.format(email))
    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        result_ok = False

    return result_ok

def sync_deletion(contacts_crypto_encoded):
    '''
        Sync deleting the key associated with this contact's crypto.
    '''

    result_ok = False
    try:
        contacts_crypto = pickle.loads(b64decode(contacts_crypto_encoded))
        email = contacts_crypto.contact.email
        try:
            log_message('starting to sync deletion of crypto key for {}'.format(email))
            delete_key_class = DeleteKey(contacts_crypto)
            if delete_key_class:
                result_ok = delete_key_class.delete()
            else:
                result_ok = False
            log_message('finished syncing deletion of crypto key for {}'.format(email))
        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            result_ok = False
    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        result_ok = False

    return result_ok

def prep_sync(contacts_crypto):
    ''' Prepare to sync database and crypto keys. '''
    
    result_ok = True
    crypto_name = email = key_plugin = None
    try:
        if contacts_crypto is None:
            result_ok = False
            log_message('contacts crypto not defined')
        else:
            crypto_name = contacts_crypto.encryption_software.name
            email = contacts_crypto.contact.email

            crypto_record = crypto_software.get(contacts_crypto.encryption_software)
            if crypto_record is None:
                result_ok = False
                log_message('{} encryption not defined in database'.format(crypto_name))
            elif not crypto_record.active:
                result_ok = False
                log_message('{} encryption is not active'.format(crypto_name))
            else:
                key_plugin = KeyFactory.get_crypto(
                    crypto_name, crypto_software.get_key_classname(crypto_name))
                result_ok = key_plugin is not None
                if not result_ok:
                    log_message('key plugin not defined'.format(crypto_name))
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        result_ok = False

    return result_ok, crypto_name, email, key_plugin
    
def log_message(message):
    '''
        Log the message to the local log.
        
        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.sync_db_with_keyring.log'))
        True
    '''
    
    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)


