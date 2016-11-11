'''
    Manage crypto via a queue.

    Copyright 2015-2016 GoodCrypto
    Last modified: 2016-10-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import os, pickle
from redis import Redis
from rq.connections import Connection
from rq.job import Job
from rq.queue import Queue

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.mail.crypto_queue_settings import CRYPTO_RQ, CRYPTO_REDIS_PORT
from goodcrypto.utils.constants import REDIS_HOST
from goodcrypto.utils.log_file import LogFile
from goodcrypto.utils.manage_queues import get_job_count, get_job_results
from syr.exception import record_exception


ONE_MINUTE = 60 #  one minute, in seconds
DEFAULT_TIMEOUT = 10 * ONE_MINUTE


_log = None


def queue_sync(contacts_encryption_encoded, function):
    '''
        Add a job with the contact's encryption to the crypto RQ.

        Test extreme case.
        >>> queue_sync(None, None)
        False
    '''

    result_ok = False
    try:
        if contacts_encryption_encoded is None or function is None:
            log_message('missing key data: {} contacts_encryption; {} function'.format(
                contacts_encryption_encoded, str(function)))
            result_ok = False

        else:
            contacts_encryption = pickle.loads(contacts_encryption_encoded)
            log_message('starting to queue {} crypto job for {}'.format(function, contacts_encryption))
            crypto_jobs = get_job_count(CRYPTO_RQ, CRYPTO_REDIS_PORT)
            redis_connection = Redis(REDIS_HOST, CRYPTO_REDIS_PORT)
            queue = Queue(name=CRYPTO_RQ, connection=redis_connection)
            secs_to_wait = DEFAULT_TIMEOUT * (queue.count + crypto_jobs + 1)
            job = queue.enqueue_call(function,
                                     args=[pickle.dumps(contacts_encryption)],
                                     timeout=secs_to_wait)

            result_ok = get_job_results(queue, job, secs_to_wait, contacts_encryption.contact.email)
            if job.is_failed:
                result_ok = False
                log_message('job failed for {}'.format(email))
    except Exception as exception:
        result_ok = False
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return result_ok

def queue_keyserver_search(email, user_initiated_search, interactive=False):
    '''
        Start the process of searching and retrieving a key from the keyservers.

        # Test extreme cases
        # In honor of Syrian teenager who refused to be a suicide bomber.
        >>> queue_keyserver_search('syrian.teenager@goodcrypto.local', None)
        False
        >>> queue_keyserver_search('syrian.teenager@goodcrypto.local', None, interactive=True)
        False
        >>> queue_keyserver_search(None, 'julian@goodcrypto.local')
        False
    '''

    try:
        if email is None:
            result_ok = False
            log_message("cannot search keyservers without an email address")
        elif user_initiated_search is None:
            result_ok = False
            log_message("require an email where we can send notification if successful")
        else:
            from goodcrypto.mail.keyservers import search_keyservers

            crypto_jobs = get_job_count(CRYPTO_RQ, CRYPTO_REDIS_PORT)
            redis_connection = Redis(REDIS_HOST, CRYPTO_REDIS_PORT)
            queue = Queue(name=CRYPTO_RQ, connection=redis_connection)
            secs_to_wait = DEFAULT_TIMEOUT * (queue.count + crypto_jobs + 1)
            job = queue.enqueue_call(search_keyservers,
                                     args=[
                                       pickle.dumps(email),
                                       pickle.dumps(user_initiated_search),
                                       pickle.dumps(interactive)],
                                     timeout=secs_to_wait)

            result_ok = get_job_results(queue, job, secs_to_wait, email)
            if job.is_failed:
                result_ok = False
                log_message('job failed for {}'.format(email))
            else:
                log_message('queued searching keyservers for a key for {}'.format(email))
    except Exception as exception:
        result_ok = False
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return result_ok

def queue_keyserver_retrieval(fingerprint, encryption_name, user_initiated_search, callback=None):
    '''
        Start the process of retrieving a key from the keyservers.

        # Test extreme cases
        >>> queue_keyserver_retrieval('99C4 402C AE6F 09DB 604D  4A8A 8559 78CF 296D E1CD', 'GPG', None)
        False
        >>> queue_keyserver_retrieval(None, 'GPG', 'julian@goodcrypto.local')
        False
    '''

    try:
        if fingerprint is None:
            result_ok = False
            log_message("cannot retrieve key from keyservers without a fingerprint")
        elif encryption_name is None:
            result_ok = False
            log_message("require an encryption_name")
        elif user_initiated_search is None:
            result_ok = False
            log_message("require an email where we can send notification if successful")
        else:
            from goodcrypto.mail.keyservers import get_key_from_keyservers

            crypto_jobs = get_job_count(CRYPTO_RQ, CRYPTO_REDIS_PORT)
            redis_connection = Redis(REDIS_HOST, CRYPTO_REDIS_PORT)
            queue = Queue(name=CRYPTO_RQ, connection=redis_connection)
            secs_to_wait = DEFAULT_TIMEOUT * (queue.count + crypto_jobs + 1)
            job = queue.enqueue_call(get_key_from_keyservers,
                                     args=[
                                       pickle.dumps(fingerprint),
                                       pickle.dumps(encryption_name),
                                       pickle.dumps(user_initiated_search),
                                       callback],
                                     timeout=secs_to_wait)

            result_ok = get_job_results(queue, job, secs_to_wait, fingerprint)
            if job.is_failed:
                result_ok = False
                log_message('job failed for {}'.format(fingerprint))
            else:
                log_message('queued searching keyservers for a key for {}'.format(fingerprint))
    except Exception as exception:
        result_ok = False
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return result_ok

def log_message(message):
    '''
        Log a message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.crypto_queue.log'))
        True
    '''

    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

