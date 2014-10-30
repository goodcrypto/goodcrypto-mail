'''
    Signals from creating and deleting mail models
    with the associated crypto keys.

    Copyright 2014 GoodCrypto
    Last modified: 2014-10-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os.path
from base64 import b64decode, b64encode
from redis import Redis
from rq import Connection, Queue
from rq.job import Job
from time import sleep
from traceback import format_exc

from goodcrypto.mail.rq_crypto_settings import CRYPTO_QUEUE, CRYPTO_REDIS_PORT, FINGERPRINT_SUFFIX, KEY_SUFFIX
from goodcrypto.mail.rq_postfix_settings import POSTFIX_QUEUE, POSTFIX_REDIS_PORT
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.mail.utils.queues import queue_ready, remove_queue_semaphore
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.utils.constants import REDIS_HOST
from goodcrypto.utils.log_file import LogFile
from goodcrypto.utils.manage_queue import get_job_count


log = LogFile()

# the tests themsevles set this variable to True when appropriate
TESTS_RUNNING = False

def post_save_contacts_crypto(sender, **kwargs):
    ''' Process the contact's encryption record after it's saved.'''

    if TESTS_RUNNING:
        log.write('tests running so no post save processing')
    else:
        log.write("starting post save for contact's crypto")
        new_record = kwargs['created']
        contacts_encryption = kwargs['instance']
        email = contacts_encryption.contact.email
        crypto_name = contacts_encryption.encryption_software.name
        fingerprint = contacts_encryption.fingerprint
        log.write("{}'s {} fingerprint: {}".format(email, crypto_name, fingerprint))
    
        if contacts_encryption.encryption_software.active:
            if email_in_domain(email) and fingerprint is None and new_record:
                start_adding_private_key(contacts_encryption)
            elif fingerprint is None or len(fingerprint.strip()) <= 0:
                start_setting_fingerprint(contacts_encryption)
            else:
                log.write("no post save processing needed")
        else:
            log.write("no post save processing needed because {} is inactive".format(crypto_name))
        log.write("finished post save for contact's crypto")
        
def post_delete_contacts_crypto(sender, **kwargs):
    ''' Delete the keys for the contact's encryption. '''

    if TESTS_RUNNING:
        log.write('tests running so no post delete processing')
    else:
        log.write("starting post delete for contact's crypto")
        delete_contacts_crypto(kwargs['instance'])
        log.write("finished post delete for contact's crypto")

def post_save_options(sender, **kwargs):
    ''' Process the options record after it's saved.'''

    options = kwargs['instance']
    mail_server_address = options.mail_server_address
    goodcrypto_listen_port = options.goodcrypto_listen_port
    mta_listen_port = options.mta_listen_port
    domain = options.domain

    if mail_server_address is not None and len(mail_server_address.strip()) > 0:
        result_ok = add_to_postfix_queue(mail_server_address, goodcrypto_listen_port, mta_listen_port, domain)
        log.write("results from queueing postfix job: {}".format(result_ok))

def start_adding_private_key(contacts_encryption):
    '''
        Start the process of adding a private key.
        If one exists, then verify the info in the database matches.
    '''
    try:
        if contacts_encryption is None:
            result = False
            log.write("cannot add private key without a contact's encryption")
        else:
            from goodcrypto.mail.sync_private_key import manage
    
            email = contacts_encryption.contact.email
            if queue_ready(email, KEY_SUFFIX):
                log.write("starting to queue managing private key for {}".format(email))
                result = add_to_crypto_queue(email,
                                      contacts_encryption.encryption_software.name, 
                                      manage, 
                                      suffix=KEY_SUFFIX)
            else:
                result = True
                log.write("queue already managing {}".format(email))
            log.write("finished queuing management of private key for {}".format(email, result))

    except Exception as exception:
        result = False
        log.write(format_exc())
        
    return result
            

def start_setting_fingerprint(contacts_encryption):
    '''
        Start the process of setting a fingerprint if there's a matching key.
    '''
    
    try:
        if contacts_encryption is None:
            result = False
            log.write("cannot set the fingerprint without a contact's encryption")
        else:
            from goodcrypto.mail.sync_fingerprint import set_fingerprint
            
            email = contacts_encryption.contact.email
            log.write("starting to queue set fingerprint for {}".format(email))
            if queue_ready(email, FINGERPRINT_SUFFIX):
                result = add_to_crypto_queue(email, 
                                      contacts_encryption.encryption_software.name, 
                                      set_fingerprint, 
                                      suffix=FINGERPRINT_SUFFIX)
            else:
                result = True
            log.write("finished queueing set fingerprint for {}: {}".format(email, result))
    except Exception as exception:
        result = False
        log.write(format_exc())

    return result

def delete_contacts_crypto(contacts_encryption):
    '''
        Delete the key(s) for the contact's encryption.
    '''

    try:
        if contacts_encryption is None:
            result = False
            log.write("cannot delete contact's encryption because it is not defined")
        else:
            from goodcrypto.mail.sync_delete_key import delete
    
            email = contacts_encryption.contact.email
            log.write("starting to queue delete key for {}".format(email))
            result = add_to_crypto_queue(email,
                                  contacts_encryption.encryption_software.name, 
                                  delete)
            log.write("finished queueing delete key for {}: {}".format(email, result))
    except Exception as exception:
        result = False
        log.write(format_exc())
        
    return result

def add_to_crypto_queue(email, encryption_name, function, suffix=None):
    '''
        Add a job to the crypto queue.
    '''

    result_ok = False
    try:
        if email is None or encryption_name is None or function is None:
            log.write('missing key data: {} email; {} encryption name; {} function'.format(
                email, encryption_name, str(function)))
            result_ok = False

        else:
            ONE_MINUTE = 60 #  one minute, in seconds
            DEFAULT_TIMEOUT = 2 * ONE_MINUTE
    
            crypto_plugin = CryptoFactory.get_crypto(encryption_name)
            crypto_jobs = get_job_count(CRYPTO_QUEUE, CRYPTO_REDIS_PORT)
            redis_connection = Redis(REDIS_HOST, CRYPTO_REDIS_PORT)
            queue = Queue(name=CRYPTO_QUEUE, connection=redis_connection, async=True)
            secs_to_wait = DEFAULT_TIMEOUT * (queue.count + crypto_jobs + 1)
            log.write('secs to wait for {} job: {}'.format(queue.name, secs_to_wait))
            job = queue.enqueue_call(func=function, 
                                     args=(b64encode(email), b64encode(encryption_name),),
                                     timeout=secs_to_wait)
            
            result_ok = get_job_results(queue, job, secs_to_wait, email)
            if job.is_failed:
                remove_queue_semaphore(email, suffix)
    except Exception as exception:
        log.write(format_exc())

    return result_ok

def add_to_postfix_queue(mail_server_address, goodcrypto_listen_port, mta_listen_port, domain):
    '''
        Add a job to the postfix queue.
        
        >>> add_to_postfix_queue('127.0.0.1', 10025, 10026, 'goodcrypto.local')
        True
    '''

    result_ok = False
    try:
        if mail_server_address is None:
            log.write('missing mta address')
            result_ok = False
        elif mta_listen_port is None:
            log.write('missing mta_listen_port')
            result_ok = False
        elif goodcrypto_listen_port is None:
            log.write('missing goodcrypto_listen_port')
            result_ok = False
        elif domain is None:
            log.write('missing domain')
            result_ok = False
        else:
            from goodcrypto.mail.utils.config_postfix import configure

            ONE_MINUTE = 60 #  one minute, in seconds
            DEFAULT_TIMEOUT = 2 * ONE_MINUTE
    
            redis_connection = Redis(REDIS_HOST, POSTFIX_REDIS_PORT)
            queue = Queue(name=POSTFIX_QUEUE, connection=redis_connection, async=True)
            secs_to_wait = DEFAULT_TIMEOUT * (queue.count + 1)
            log.write('secs to wait for {} job: {}'.format(queue.name, secs_to_wait))
            job = queue.enqueue_call(func=configure, 
                                     args=(mail_server_address, goodcrypto_listen_port, mta_listen_port, domain),
                                     timeout=secs_to_wait)

            result_ok = get_job_results(queue, job, secs_to_wait, mail_server_address)

    except Exception as exception:
        log.write(format_exc())

    return result_ok

def get_job_results(queue, job, secs_to_wait, purpose):
    ''' Get the initial job results. '''

    if job is None:
        log.write('unable to queue {} postfix job for {}'.format(queue.name, purpose))
    else:
        job_id = job.get_id()

        log.write('{} job(s) in {} queue before this job'.format(queue.count, queue.name))
        wait_until_queued(job, secs_to_wait)

        if job.is_failed:
            job_dump = job.dump()
            if 'exc_info' in job_dump:
                error = job_dump['exc_info']
                log.write('{} job exc info: {}'.format(job_id, error))
            elif 'status' in job_dump:
                error = job_dump['status']
                log.write('{} job status: {}'.format(job_id, error))
            log.write('job dump:\n{}'.format(job_dump))
            job.cancel()
            queue.remove(job_id)

            
        elif job.is_queued or job.is_started or job.is_finished:
            log.write('{} job queued'.format(job_id))
            result_ok = True

        else:
            log.write('{} job results: {}'.format(job_id, job.result))
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
    log.write('seconds until job was queued: {}'.format(secs))



