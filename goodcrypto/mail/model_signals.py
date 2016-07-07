'''
    Signals from creating and deleting mail models
    with the associated crypto keys.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-07-29

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os.path, pickle
from base64 import b64decode, b64encode
from redis import Redis
from rq import Connection, Queue
from rq.job import Job
from time import sleep

from goodcrypto.mail.rq_crypto_settings import CRYPTO_RQUEUE, CRYPTO_REDIS_PORT, FINGERPRINT_SUFFIX, KEY_SUFFIX
from goodcrypto.mail.rq_postfix_settings import POSTFIX_RQUEUE, POSTFIX_REDIS_PORT
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.utils import get_email
from goodcrypto.utils.constants import REDIS_HOST
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from goodcrypto.utils.manage_rqueue import get_job_count


# the tests themsevles set this variable to True when appropriate
TESTS_RUNNING = False

_log = None

def post_save_contacts_crypto(sender, **kwargs):
    ''' Process the contact's encryption record after it's saved.'''

    if TESTS_RUNNING:
        log_message('tests running so no post save processing')
    else:
        log_message("starting post save for contact's crypto")
        contacts_encryption = kwargs['instance']
        email = contacts_encryption.contact.email
        encryption_software = contacts_encryption.encryption_software.name
        fingerprint = contacts_encryption.fingerprint
        log_message("{}'s {} id: {}".format(email, encryption_software, fingerprint))
    
        if email_in_domain(email):
            from goodcrypto.mail import user_keys

            user_key = user_keys.get(email, encryption_software)
            if (user_key is None or user_key.passcode is None):
                log_message('creating private {} key for {}'.format(encryption_software, email))
                start_adding_private_key(contacts_encryption)
            elif fingerprint is None:
                log_message('setting private {} key id for {}'.format(encryption_software, email))
                start_setting_fingerprint(contacts_encryption)
            else:
                log_message('{} already has {} crypto software defined'.format(email, encryption_software))
        elif fingerprint is None:
            log_message('setting {} key id for {}'.format(encryption_software, email))
            start_setting_fingerprint(contacts_encryption)
        else:
            log_message('{} already has {} crypto software defined'.format(email, encryption_software))

        log_message("finished post save for contact's crypto")
        
def post_delete_contacts_crypto(sender, **kwargs):
    ''' Delete the keys for the contact's encryption. '''

    if TESTS_RUNNING:
        log_message('tests running so no post delete processing')
    else:
        contacts_encryption = kwargs['instance']
        email = contacts_encryption.contact.email
        log_message("starting post delete for {}'s crypto".format(email))
        delete_contacts_crypto(contacts_encryption)
        log_message("finished post delete for {}'s crypto".format(email))

def post_save_options(sender, **kwargs):
    ''' Process the mail server options record after it's saved.'''

    options = kwargs['instance']
    mail_server_address = options.mail_server_address
    goodcrypto_listen_port = options.goodcrypto_listen_port
    mta_listen_port = options.mta_listen_port

    if mail_server_address is not None and len(mail_server_address.strip()) > 0:
        result_ok = add_to_postfix_mta_queue(mail_server_address, goodcrypto_listen_port, mta_listen_port)
        log_message("results from queueing postfix mta job: {}".format(result_ok))

def post_save_internal_settings(sender, **kwargs):
    ''' Process the internal settings record after it's saved.'''

    internal_settings = kwargs['instance']
    domain = internal_settings.domain

    if domain is not None and len(domain.strip()) > 0:
        result_ok = add_to_postfix_mailname_queue(domain)
        log_message("results from queueing postfix mailname job: {}".format(result_ok))

def start_adding_private_key(contacts_encryption):
    '''
        Start the process of adding a private key.
        If one exists, then verify the info in the database matches.
    '''
    try:
        if contacts_encryption is None:
            result = False
            log_message("cannot add private key without a contact's encryption record")
        else:
            from goodcrypto.mail.sync_db_with_keyring import sync_private_key

            email = contacts_encryption.contact.email
            log_message("starting to queue syncing private key for {}".format(email))
            result = add_contacts_crypto_to_queue(contacts_encryption, sync_private_key, suffix=KEY_SUFFIX)
            log_message("finished queuing sync of private key for {}".format(email, result))

    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        result = False
        
    return result
            
def start_setting_fingerprint(contacts_encryption):
    '''
        Start the process of setting a fingerprint if there's a matching key in the database.
    '''
    
    try:
        if contacts_encryption is None:
            result = False
            log_message("cannot set the fingerprint without a contact's encryption")
        else:
            from goodcrypto.mail.sync_db_with_keyring import sync_fingerprint
            
            email = contacts_encryption.contact.email
            log_message("starting to sync fingerprint for {} via rq".format(email))
            result = add_contacts_crypto_to_queue(contacts_encryption, sync_fingerprint, suffix=FINGERPRINT_SUFFIX)
            log_message('finished queueing syncing fingerprint for {}: {}'.format(email, result))
    except Exception as exception:
        result = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result

def delete_contacts_crypto(contacts_encryption):
    '''
        Delete the key(s) for the contact's encryption.
    '''

    try:
        if contacts_encryption is None:
            result = False
            log_message("cannot delete contact's encryption because it is not defined")
        else:
            from goodcrypto.mail.sync_db_with_keyring import sync_deletion
    
            email = contacts_encryption.contact.email
            log_message("starting to queue delete key for {}".format(email))
            result = add_contacts_crypto_to_queue(contacts_encryption, sync_deletion)
            log_message("finished queueing delete key for {}: {}".format(email, result))
    except Exception as exception:
        result = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result

def add_contacts_crypto_to_queue(contacts_encryption, function, suffix=None):
    '''
        Add a job with the contact's encryption to the crypto queue.
    '''

    result_ok = False
    try:
        if contacts_encryption is None or function is None:
            log_message('missing key data: {} contacts_encryption; {} function'.format(
                contacts_encryption, str(function)))
            result_ok = False

        else:
            ONE_MINUTE = 60 #  one minute, in seconds
            DEFAULT_TIMEOUT = 10 * ONE_MINUTE
    
            crypto_jobs = get_job_count(CRYPTO_RQUEUE, CRYPTO_REDIS_PORT)
            redis_connection = Redis(REDIS_HOST, CRYPTO_REDIS_PORT)
            queue = Queue(name=CRYPTO_RQUEUE, connection=redis_connection, async=True)
            secs_to_wait = DEFAULT_TIMEOUT * (queue.count + crypto_jobs + 1)
            job = queue.enqueue_call(function, 
                                     args=[b64encode(pickle.dumps(contacts_encryption))],
                                     timeout=secs_to_wait)

            result_ok = get_job_results(queue, job, secs_to_wait, contacts_encryption.contact.email)
            if job.is_failed:
                result_ok = False
                log_message('job failed for {}'.format(email))
    except Exception as exception:
        result_ok = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result_ok

def add_to_postfix_mta_queue(mail_server_address, goodcrypto_listen_port, mta_listen_port):
    '''
        Add a job to the postfix mta queue.
        
        >>> add_to_postfix_mta_queue('127.0.0.1', 10025, 10026)
        True
    '''

    result_ok = False
    try:
        if mail_server_address is None:
            log_message('missing mta address')
            result_ok = False
        elif mta_listen_port is None:
            log_message('missing mta_listen_port')
            result_ok = False
        elif goodcrypto_listen_port is None:
            log_message('missing goodcrypto_listen_port')
            result_ok = False
        else:
            from goodcrypto.mail.utils.config_postfix import configure_mta

            ONE_MINUTE = 60 #  one minute, in seconds
            DEFAULT_TIMEOUT = 10 * ONE_MINUTE
    
            redis_connection = Redis(REDIS_HOST, POSTFIX_REDIS_PORT)
            queue = Queue(name=POSTFIX_RQUEUE, connection=redis_connection, async=True)
            secs_to_wait = DEFAULT_TIMEOUT * (queue.count + 1)
            job = queue.enqueue_call(configure_mta, 
                                     args=[mail_server_address, goodcrypto_listen_port, mta_listen_port],
                                     timeout=secs_to_wait)

            result_ok = get_job_results(queue, job, secs_to_wait, mail_server_address)

    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result_ok

def add_to_postfix_mailname_queue(domain):
    '''
        Add a job to the postfix mailname queue.
        
        >>> add_to_postfix_mailname_queue('test.local')
        True
    '''

    result_ok = False
    try:
        if domain is None:
            log_message('missing domain')
            result_ok = False
        else:
            from goodcrypto.mail.utils.config_postfix import configure_mailname

            ONE_MINUTE = 60 #  one minute, in seconds
            DEFAULT_TIMEOUT = 10 * ONE_MINUTE
    
            redis_connection = Redis(REDIS_HOST, POSTFIX_REDIS_PORT)
            queue = Queue(name=POSTFIX_RQUEUE, connection=redis_connection, async=True)
            secs_to_wait = DEFAULT_TIMEOUT * (queue.count + 1)
            job = queue.enqueue_call(configure_mailname, 
                                     args=[domain],
                                     timeout=secs_to_wait)

            result_ok = get_job_results(queue, job, secs_to_wait, 'mailname')

    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result_ok

def get_job_results(queue, job, secs_to_wait, purpose):
    ''' Get the initial job results. '''

    if job is None:
        log_message('unable to queue {} postfix job for {}'.format(queue.name, purpose))
    else:
        job_id = job.get_id()

        wait_until_queued(job, secs_to_wait)

        if job.is_failed:
            job_dump = job.dump()
            if 'exc_info' in job_dump:
                error = job_dump['exc_info']
                log_message('{} job exc info: {}'.format(job_id, error))
            elif 'status' in job_dump:
                error = job_dump['status']
                log_message('{} job status: {}'.format(job_id, error))
            job.cancel()
            queue.remove(job_id)

            
        elif job.is_queued or job.is_started or job.is_finished:
            result_ok = True

        else:
            result_ok = False

    return result_ok

def wait_until_queued(job, secs_to_wait):
    ''' Wait until the job is queued or timeout. '''
    
    secs = 0
    while (secs < secs_to_wait and 
           not job.is_queued and 
           not job.is_started and 
           not job.is_finished ):
        sleep(1)
        secs += 1


def log_message(message):
    '''
        Log the message to the local log.
        
        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.model_signals.log'))
        True
    '''
    
    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)


