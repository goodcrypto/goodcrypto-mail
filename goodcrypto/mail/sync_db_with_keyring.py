'''
    Sync the django database and the encryption databases (i.e., keyrings).

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-11-02

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, pickle
from django.db import IntegrityError
from time import sleep

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.mail import contacts, crypto_software, user_keys, utils
from goodcrypto.mail.constants import AUTO_GENERATED
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.options import create_private_keys
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.mail.utils.notices import report_mismatched_password
from goodcrypto.oce.key.constants import EXPIRES_IN, EXPIRATION_UNIT
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import format_fingerprint
from goodcrypto.utils import i18n, get_email
from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception

_log = None


def sync_private_key(contacts_encryption_encoded):
    '''
        Sync a key pair, and its associated records, for an email address within our domain.

        >>> sync_private_key(None)
        False
    '''

    result_ok = False
    if contacts_encryption_encoded is not None:
        try:
            contacts_encryption = pickle.loads(contacts_encryption_encoded)
            email = contacts_encryption.contact.email
            try:
                sync_db_key_class = SyncPrivateKey(contacts_encryption)
                if sync_db_key_class:
                    result_ok = sync_db_key_class.configure()
                else:
                    result_ok = False
            except Exception as exception:
                record_exception()
                log_message('EXCEPTION - see syr.exception.log for details')
                result_ok = False
        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see syr.exception.log for details')
            result_ok = False

    return result_ok

class SyncPrivateKey(object):
    '''
        Sync database records and the crypto's keyring
        for an email address if its part of the managed domain.
    '''

    def __init__(self, contacts_crypto):
        '''
            >>> # In honor of Kathleen Brade, a developer on the Tor project.
            >>> email = 'kathleen@goodcrypto.local'
            >>> crypto_name = 'GPG'
            >>> contact = contacts.add(email, crypto_name)
            >>> contacts_crypto = contacts.get_contacts_crypto(email, crypto_name)
            >>> sync_db_key_class = SyncPrivateKey(contacts_crypto)
            >>> sync_db_key_class != None
            True
            >>> sync_db_key_class.result_ok
            True
        '''

        self.contacts_encryption = contacts_crypto
        self.result_ok = self.contacts_encryption is not None
        self.user_key = None
        self.new_key = False
        self.crypto_name = None
        self.email = None
        self.key_plugin = None

    def configure(self):
        '''
            Add a crypto key pair.

            >>> # In honor of David Fifield, developer and co-inventor of Flash Proxy.
            >>> from time import sleep
            >>> email = 'david@goodcrypto.local'
            >>> crypto_name = 'GPG'
            >>> contact = contacts.add(email, crypto_name)
            >>> contact != None
            True
            >>> contacts_crypto = contacts.get_contacts_crypto(email, crypto_name)
            >>> sync_db_key_class = SyncPrivateKey(contacts_crypto)
            >>> sync_db_key_class.configure()
            True
            >>> contacts.delete(email)
            True
            >>> sync_db_key_class.key_plugin.delete(email)
            True
        '''

        try:
            ok, self.crypto_name, self.email, self.key_plugin = prep_sync(self.contacts_encryption)
            self.result_ok = ok and email_in_domain(self.email)
            if self.result_ok and utils.ok_to_modify_key(self.crypto_name, self.key_plugin):
                log_message('starting SyncPrivateKey.configure for {}'.format(self.email))
                # if there's a matching private key
                if self._need_new_crypto_key():
                    self.result_ok = self._add_crypto_key()
                else:
                    self.result_ok = self._validate_passcode()
                    if self.result_ok:
                        self._save_fingerprint()
            else:
                log_message('{} not ok to configure private key'.format(self.email))
                self.result_ok = False
        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see syr.exception.log for details')
            self.result_ok = False

        log_message('finished SyncPrivateKey.configure for {} ok: {}'.format(self.email, self.result_ok))

        return self.result_ok

    def _add_crypto_key(self):
        '''
            Add a crypto key.

            Test extreme case.
            >>> sync_db_key_class = SyncPrivateKey(None)
            >>> sync_db_key_class._add_crypto_key()
            False
        '''

        try:
            log_message('adding a private {} key for {}'.format(self.crypto_name, self.email))

            # add a private key
            user_name = self.contacts_encryption.contact.user_name
            if user_name and len(user_name) > 0:
                full_address = '"{}" <{}>'.format(user_name, self.email)
                log_message('user name: {}'.format(user_name))
                log_message('email: {}'.format(self.email))
            else:
                full_address = self.email

            passcode = utils.gen_user_passcode(self.email)
            expires_in = user_keys.get_default_expiration_time()
            expiration_unit = user_keys.get_default_expiration_period()
            expiration = {EXPIRES_IN: expires_in, EXPIRATION_UNIT: expiration_unit,}

            self.result_ok, timed_out, fingerprint, key_exists = self.key_plugin.create(
                full_address, passcode, expiration)
            if self.result_ok and not timed_out and not key_exists:
                create_job = self.key_plugin.get_job()
                queue = self.key_plugin.get_queue()

                if queue is None or create_job is None:
                    config_database_and_user(self.email, self.crypto_name, passcode)
                else:
                    args = [self.email, self.crypto_name, passcode]
                    sync_job = queue.enqueue_call(
                        config_database_and_user, args=args, depends_on=create_job)
                    if sync_job is None:
                        log_message('unable to queue job to add a private {} key for {} (job: {})'.format(
                        self.crypto_name, self.email))
                        self.result_ok = False
                    else:
                        log_message('queued adding a private {} key for {} (after job: {})'.format(
                            self.crypto_name, self.email, create_job.get_id()))
            else:
                # if the job timedout or a key exists, then we've failed to add the key properly
                self.result_ok = False
        except:
            self.result_ok = False
            record_exception()
            log_message('EXCEPTION - see syr.exception.log for details')

        log_message('finished adding a private {} key for {} ok: {}'.format(
            self.crypto_name, self.email, self.result_ok))

        return self.result_ok

    def _need_new_crypto_key(self):
        '''
            Determine if we need to create a new crypto key.

            Test extreme case.
            >>> sync_db_key_class = SyncPrivateKey(None)
            >>> sync_db_key_class._need_new_crypto_key()
            False
        '''

        need_key = False

        try:
            # if there's a matching private key
            if self.key_plugin.private_key_exists(self.email):
                log_message("found private {} key for {}: True".format(self.crypto_name, self.email))

                self.user_key = user_keys.get(self.email, self.crypto_name)
                need_key = self.user_key is None
                log_message("found matching db user key record for {}: {}".format(
                    self.email, self.user_key is not None))

            # if there is a matching public key, delete it
            elif self.key_plugin.public_key_exists(self.email):
                need_key = True
                self.key_plugin.delete(self.email)
                log_message("deleted old public {} key for {}".format(self.crypto_name, self.email))

            else:
                need_key = True
        except:
            record_exception()

        log_message("need to create private {} key for {}: {}".format(self.crypto_name, self.email, need_key))

        return need_key


    def _validate_passcode(self):
        '''
            Verify the passcode.

            Test extreme case.
            >>> sync_db_key_class = SyncPrivateKey(None)
            >>> sync_db_key_class._validate_passcode()
            False
        '''

        passcode_ok = False

        if self.user_key is None:
            log_message('no matching {} user key record for {}'.format(self.crypto_name, self.email))
        else:
            passcode = self.user_key.passcode

            # verify the passphrase is correct
            signed_data, error_message = self.key_plugin.sign('Test data', self.email, passcode)
            if signed_data is None:
                passcode_ok = False
                log_message("{}'s passphrase does not match {}'s key.".format(self.email, self.crypto_name))
                if error_message is not None: log_message(error_message)

                report_mismatched_password(self.email, self.crypto_name)
            else:
                passcode_ok = True
                log_message("{} {} passphrase is good.".format(self.email, self.crypto_name))

        return passcode_ok

    def _save_fingerprint(self):
        '''
            Save the fingerprint in the database.

            >>> # In honor of Chelsea Manning, who leaked the Iraq and Afgan war reports.
            >>> from goodcrypto.oce.test_constants import CHELSEA_LOCAL_USER
            >>> email = CHELSEA_LOCAL_USER
            >>> crypto_name = 'GPG'
            >>> contacts_crypto = contacts.get_contacts_crypto(email, crypto_name)
            >>> contacts_crypto != None
            True
            >>> from goodcrypto.mail.user_keys import get
            >>> sync_db_key_class = SyncPrivateKey(contacts_crypto)
            >>> sync_db_key_class.user_key = get(email, crypto_name)
            >>> sync_db_key_class._save_fingerprint()
            >>> sync_db_key_class.result_ok
            True
        '''

        if self.key_plugin is None:
            log_message('no {} plugin defined for {}'.format(self.crypto_name, self.email))
        elif self.user_key is None:
            log_message('no {} user key record defined for {}'.format(self.crypto_name, self.email))
        else:
            fingerprint, __ = self.key_plugin.get_fingerprint(self.email)
            if fingerprint is None:
                log_message('unable to get {} fingerprint for {}'.format(self.crypto_name, self.email))
            else:
                try:
                    if (self.user_key.contacts_encryption.fingerprint is None or
                        self.user_key.contacts_encryption.fingerprint != fingerprint):

                        self.user_key.contacts_encryption.fingerprint = fingerprint
                        self.user_key.contacts_encryption.verified = True
                        if self.user_key.contacts_encryption.source is None:
                            self.user_key.contacts_encryption.source = AUTO_GENERATED
                        self.user_key.contacts_encryption.save()
                        log_message('updated {} fingerprint for {} in database'.format(
                            self.crypto_name, self.email))
                except IntegrityError as ie:
                    if 'insert or update on table "mail_contactscrypto" violates foreign key constraint' in str(ie):
                        log_message('{} crypto key no longer exists for {}'.format(self.crypto_name, self.email))
                    else:
                        raise

def sync_fingerprint(contacts_crypto_encoded):
    '''
        Sync the fingerprint in the contacts' crypto record.

        >>> # Test extremes
        >>> sync_fingerprint(None)
        False
    '''

    result_ok = False
    if contacts_crypto_encoded is not None:
        try:
            contacts_crypto = pickle.loads(contacts_crypto_encoded)
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
                log_message('EXCEPTION - see syr.exception.log for details')
                result_ok = False
            finally:
                log_message('finished set_fingerprint for {}'.format(email))
        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see syr.exception.log for details')
            result_ok = False

    return result_ok

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

    def save(self):
        '''
            Save the fingerprint in the database.

            Test extreme case.
            >>> set_fingerprint_class = SetFingerprint(None)
            >>> set_fingerprint_class.save()
            False
        '''

        self.result_ok, self.crypto_name, self.email, self.key_plugin = prep_sync(self.contacts_encryption)
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
                        log_message('no {} fingerprint found for {}'.format(self.crypto_name, self.email))
                    else:
                        self.result_ok = True
                        try:
                            fingerprint = format_fingerprint(fingerprint)
                            if (self.contacts_encryption.fingerprint is not None and
                                self.contacts_encryption.fingerprint != fingerprint):
                                log_message('replaced old fingerprint {} with {} for {}'.format(
                                    self.contacts_encryption.fingerprint, fingerprint, self.email))

                            # if we created the key, then be sure it's verified
                            if utils.email_in_domain(self.email):
                                if self.contacts_encryption.source is None and create_private_keys():
                                    self.contacts_encryption.source = AUTO_GENERATED
                                if self.contacts_encryption.source == AUTO_GENERATED:
                                    self.contacts_encryption.verified = True

                            self.contacts_encryption.fingerprint = fingerprint
                            self.contacts_encryption.save()
                            log_message('set {} fingerprint for {} in database: {}'.format(
                                self.crypto_name, self.email, fingerprint))
                        except IntegrityError as ie:
                            self.result_ok = False
                            if 'insert or update on table "mail_contactscrypto" violates foreign key constraint' in str(ie):
                                log_message('{} crypto key no longer exists for {}'.format(self.crypto_name, self.email))
                            else:
                                raise
            except Exception as exception:
                record_exception()
                log_message('EXCEPTION - see syr.exception.log for details')
                self.result_ok = False

        return self.result_ok

def sync_deletion(contacts_crypto_encoded):
    '''
        Sync deleting the key associated with this contact's crypto.

        >>> # Test extremes
        >>> sync_deletion(None)
        False
    '''

    result_ok = False
    if contacts_crypto_encoded is not None:
        try:
            contacts_crypto = pickle.loads(contacts_crypto_encoded)
            email = contacts_crypto.contact.email
            fingerprint = contacts_crypto.fingerprint
            encryption_name = contacts_crypto.encryption_software.name
            addresses_with_same_fingerprint = contacts.get_addresses_with_fingerprint(fingerprint, encryption_name)
            if len(addresses_with_same_fingerprint) > 0:
                log_message('{} have the same {} fingerprint so not deleting associated {} key.'.format(
                  ', '.join(addresses_with_same_fingerprint), fingerprint, encryption_name))
            else:
                try:
                    log_message('starting to sync deletion of crypto key for {}'.format(email))
                    delete_key_class = DeleteKey(contacts_crypto)
                    if delete_key_class:
                        result_ok = delete_key_class.delete()
                    else:
                        result_ok = False
                    log_message('finished syncing deletion of crypto key for {}: {}'.format(email, result_ok))
                except Exception as exception:
                    record_exception()
                    log_message('EXCEPTION - see syr.exception.log for details')
                    result_ok = False
        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see syr.exception.log for details')
            result_ok = False

    return result_ok

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

        self.contacts_encryption = contacts_crypto

    def delete(self):
        '''
            Delete the crypto key.

            Test extreme case.
            >>> delete_key_class = DeleteKey(None)
            >>> delete_key_class.delete()
            False
        '''

        self.result_ok, self.crypto_name, self.email, self.key_plugin = prep_sync(self.contacts_encryption)
        if self.result_ok:
            if utils.ok_to_modify_key(self.crypto_name, self.key_plugin):
                log_message('deleting {} key for {}'.format(self.crypto_name, self.email))
                self.result_ok = self.key_plugin.delete(self.email)
                log_message('deleted {} keys result_ok: {}'.format(self.crypto_name, self.result_ok))
            else:
                self.result_ok = True
                log_message('not ok to delete key')

        return self.result_ok


def prep_sync(contacts_crypto):
    '''
        Prepare to sync database and crypto keys.

        Test extreme case.
        >>> prep_sync(None)
        (False, None, None, None)
    '''

    result_ok = True
    crypto_name = email = key_plugin = None
    try:
        if contacts_crypto is None:
            result_ok = False
            log_message('contacts crypto not defined')
        else:
            crypto_name = contacts_crypto.encryption_software.name
            email = contacts_crypto.contact.email

            log_message('preparing to sync db and {} keyring for {}'.format(crypto_name, email))
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
        log_message('{} had an unexpected error'.format(contacts_crypto))
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')
        result_ok = False

    log_message('finished preparing to sync db and keyring for {}'.format(email))

    return result_ok, crypto_name, email, key_plugin

def config_database_and_user(email, crypto_name, passcode):
    '''
        Configure the fingerprint for the user key.

        >>> from goodcrypto.oce.test_constants import CHELSEA_PASSPHRASE, CHELSEA_LOCAL_USER_ADDR
        >>> email = CHELSEA_LOCAL_USER_ADDR
        >>> crypto_name = 'GPG'
        >>> passcode = CHELSEA_PASSPHRASE
        >>> try:
        ...     config_database_and_user(email, crypto_name, passcode)
        ...     fail()
        ... except:
        ...     pass
    '''
    result_ok = timed_out = need_fingerprint = False

    log_message('adding associated user key record for {}'.format(email))
    try:
        user_key = user_keys.add(email, crypto_name, passcode=passcode)
    except Exception as e:
        user_key = None
        log_message(e)
        record_exception()

    if user_key is None:
        result_ok = False
        log_message('unable to add user key record for {}'.format(email))
    else:
        result_ok = True

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

