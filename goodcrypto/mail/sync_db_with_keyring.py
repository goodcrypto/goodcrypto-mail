'''
    Sync the django database and the encryption databases (i.e., keyrings).

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-11-27

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, pickle
from base64 import b64decode, b64encode
from django.db import IntegrityError
from rq import Queue

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.mail import contacts, crypto_software, user_keys, utils
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.message.metadata import is_metadata_address
from goodcrypto.mail.options import create_private_keys, goodcrypto_server_url
from goodcrypto.mail.rq_crypto_settings import KEY_SUFFIX
from goodcrypto.mail.utils import notices
from goodcrypto.oce.key.constants import EXPIRES_IN, EXPIRATION_UNIT
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.utils import i18n, get_email
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile

_log = None


class SyncDbWithKeyring(object):
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
            >>> sync_db_key_class = SyncDbWithKeyring(contacts_crypto)
            >>> sync_db_key_class != None
            True
            >>> sync_db_key_class.result_ok
            True
        '''

        self.contacts_crypto = contacts_crypto
        self.result_ok = self.contacts_crypto is not None
        self.user_key = None
        self.new_key = False
        self.crypto_name = None
        self.email = None
        self.key_plugin = None

    def configure(self):
        '''
            Add a key pair and corresponding database records.

            >>> # In honor of David Fifield, developer and co-inventor of Flash Proxy.
            >>> from time import sleep
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
        '''

        try:
            self.result_ok, self.crypto_name, self.email, self.key_plugin = prep_sync(self.contacts_crypto)
            log_message('starting SyncDbWithKeyring.configure for {}'.format(self.email))
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
                log_message('initial result is not ok')

            if self.result_ok and utils.ok_to_modify_key(self.crypto_name, self.key_plugin):
                # if there's a matching private key
                if self._need_new_key():
                    self.result_ok = self._add_key()
                else:
                    self.result_ok = self._validate_passcode()
                    if self.result_ok:
                        self._save_fingerprint()
        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            self.result_ok = False

        log_message('finished SyncDbWithKeyring.configure for {} ok: {}'.format(self.email, self.result_ok))

        return self.result_ok

    def _add_key(self):
        '''
            Add a key and the associated database records.
            >>> sync_db_key_class = SyncDbWithKeyring(None)
            >>> sync_db_key_class._add_key()
            False
        '''

        try:
            log_message('adding a private {} key for {}'.format(self.crypto_name, self.email))

            # add a private key
            user_name = self.contacts_crypto.contact.user_name
            if user_name and len(user_name) > 0:
                full_address = '"{}" <{}>'.format(user_name, self.email)
                log_message('user name: {}'.format(user_name))
                log_message('email: {}'.format(self.email))
            else:
                full_address = self.email

            expires_in = user_keys.get_default_expiration_time()
            expiration_unit = user_keys.get_default_expiration_period()
            expiration = {EXPIRES_IN: expires_in, EXPIRATION_UNIT: expiration_unit,}

            passcode = utils.gen_user_passcode(self.email)
            self.result_ok, timed_out, key_exists = self.key_plugin.create(full_address, passcode, expiration)
            if self.result_ok and not timed_out and not key_exists:
                create_job = self.key_plugin.get_job()
                queue = self.key_plugin.get_queue()

                if queue is None or create_job is None:
                    _config_database_and_user(
                      b64encode(self.email), b64encode(self.crypto_name), b64encode(passcode), create_job, queue)
                else:
                    args = [b64encode(self.email), b64encode(self.crypto_name), b64encode(passcode),
                           b64encode(create_job.get_id()), b64encode(queue.key)]
                    sync_job = queue.enqueue_call(
                        _config_database_and_user, args=args, depends_on=create_job)
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
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        log_message('finished adding a private {} key for {} ok: {}'.format(
            self.crypto_name, self.email, self.result_ok))

        return self.result_ok

    def _need_new_key(self):
        '''
            Determine if we need to create a new key.
        '''

        need_key = False

        # if there's a matching private key
        if self.key_plugin.private_key_exists(self.email):
            self.user_key = user_keys.get(self.email, self.crypto_name)
            need_key = False
            log_message("found private {} key for {}: True".format(self.crypto_name, self.email))
            log_message("found matching db user key record for {}: {}".format(
                self.email, self.user_key is not None))

        # if there is a matching public key, delete it
        elif self.key_plugin.public_key_exists(self.email):
            need_key = True
            self.key_plugin.delete(self.email)
            log_message("deleted old public {} key for {}".format(self.crypto_name, self.email))

        else:
            need_key = True

        return need_key


    def _validate_passcode(self):
        '''
            Verify the passcode.
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

                notices.report_mismatched_password(self.email, self.crypto_name)
            else:
                passcode_ok = True
                log_message("{} {} passphrase is good.".format(self.email, self.crypto_name))

        return passcode_ok

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
            >>> from goodcrypto.mail.user_keys import get
            >>> sync_db_key_class = SyncDbWithKeyring(contacts_crypto)
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
                        self.user_key.contacts_encryption.save()
                        log_message('updated {} fingerprint for {} in database'.format(
                            self.crypto_name, self.email))
                except IntegrityError as ie:
                    if 'insert or update on table "mail_contactscrypto" violates foreign key constraint' in str(ie):
                        log_message('{} crypto key no longer exists for {}'.format(self.crypto_name, self.email))
                    else:
                        raise

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
                        log_message('unable to get {} fingerprint for {}'.format(self.crypto_name, self.email))
                    else:
                        self.result_ok = True
                        try:
                            if (self.contacts_encryption.fingerprint is not None and
                                self.contacts_encryption.fingerprint != fingerprint):
                                log_message('replaced old fingerprint')

                            # if we created the key, then be sure it's verified
                            if utils.email_in_domain(self.email) and create_private_keys():
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

        self.contacts_encryption = contacts_crypto

    def delete(self):
        '''
            Delete the crypto key.
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


def sync_private_key(contacts_crypto_encoded):
    '''
        Sync a key pair, and its associated records, for an email address within our domain.

        >>> sync_private_key(None)
        False
    '''

    result_ok = False
    if contacts_crypto_encoded is not None:
        try:
            contacts_crypto = pickle.loads(b64decode(contacts_crypto_encoded))
            email = contacts_crypto.contact.email
            try:
                log_message('starting to sync_private_key for {}'.format(email))
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
                log_message('finished sync_private_key for {}'.format(email))
        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            result_ok = False

    return result_ok

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

        >>> # Test extremes
        >>> sync_deletion(None)
        False
    '''

    result_ok = False
    if contacts_crypto_encoded is not None:
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
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        result_ok = False

    log_message('finished preparing to sync db and keyring for {}'.format(email))

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


def _config_database_and_user(
        email_encoded, crypto_name_encoded, passcode_encoded, job_id_encoded, queue_key_encoded):
    '''
        Configure the database and a django user.

        >>> email = 'chelsea@goodcrypto.local'
        >>> crypto_name = 'GPG'
        >>> contacts_crypto = contacts.get_contacts_crypto(email, crypto_name)
        >>> email_encoded = b64encode(email)
        >>> crypto_name_encoded = b64encode(crypto_name)
        >>> try:
        ...     _config_database_and_user(
        ...       email_encoded, crypto_name_encoded, None, None, None)
        ...     fail()
        ... except:
        ...     pass
    '''
    result_ok = timed_out = False

    email = b64decode(email_encoded)
    crypto_name = b64decode(crypto_name_encoded)
    passcode = b64decode(passcode_encoded)
    if job_id_encoded is None:
        job_id = None
    else:
        job_id = b64decode(job_id_encoded)
    if queue_key_encoded is None:
        queue_key = None
    else:
        queue_key = b64decode(queue_key_encoded)

    if job_id is None or queue_key is None:
        result_ok = True
    else:
        log_message('checking queue for results of adding a {} key for {}'.format(crypto_name, email))
        queue = Queue.from_queue_key(queue_key)
        job = queue.fetch_job(job_id)
        if job.is_finished:
            key_plugin = KeyFactory.get_crypto(
                crypto_name, crypto_software.get_key_classname(crypto_name))
            result_ok, timed_out = key_plugin.get_create_results(email, job)
            log_message("results from adding {} key for {} result ok: {}; timed out: {}".format(
                crypto_name, email, result_ok, timed_out))
        elif job.is_failed:
            log_message('add {} key for {} job failed'.format(crypto_name, email))
            result_ok = False

    if result_ok:
        log_message('adding associated user records for {}'.format(email))

        user_key = user_keys.add(email, crypto_name, passcode=passcode)
        result_ok = user_key is not None

        if result_ok:
            # activate the contact's crypto "after save signal" to update the fingerprint
            contacts_crypto = contacts.get_contacts_crypto(email, crypto_name)
            if contacts_crypto and contacts_crypto.fingerprint is None:
                contacts_crypto.save()

            if not is_metadata_address(email):
                log_message('notifying {} about new {} key'.format(email, crypto_name))
                notices.notify_user_key_ready(email)

        else:
            log_message('unable to add {} user key record for {}'.format(crypto_name, email))

    elif timed_out:
        log_message('timed out creating a private {} key for {}.'.format(
            crypto_name, email))
        if not is_metadata_address(email):
            notices.report_key_creation_timedout(email)
    else:
        log_message('unable to create a private {} key for {}.'.format(
            crypto_name, email))

        if is_metadata_address(email):
            to_email = utils.get_sysadmin_email()
            notices.report_metadata_key_creation_error(email)
        else:
            to_email = email
            notices.report_key_creation_error(email)

    if result_ok and not is_metadata_address(email):
        # configure a regular user even if the key pair had trouble
        _create_user(email)

def _create_user(email):
    '''
        Create a regular user so they can verify messages, fingerprints, etc.

        >>> _create_user(None)
        (None, 'Email is not defined so unable to finish configuration.')
    '''

    password, error_message = utils.create_user(email)
    if password is None and error_message is None:
        # user already exists so nothing to do
        log_message('{} already has a db login account'.format(email))

    elif error_message is not None:
        notices.report_error_creating_login(email, error_message)
        log_message("{}'s db login password ok: {}".format(email, password is not None))
        log_message('notified {} about error: {}'.format(email, error_message))

    else:
        notices.send_user_credentials(email, password)
        log_message('notified {} about new django account'.format(email))

    return password, error_message


