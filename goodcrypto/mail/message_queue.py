'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, os.path
from redis import Redis
from rq.connections import Connection
from rq.job import Job
from rq.queue import Queue
from rq.timeouts import JobTimeoutException
from time import sleep

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.mail.crypto_queue_settings import CRYPTO_RQ, CRYPTO_REDIS_PORT
from goodcrypto.mail.message.filter import Filter
from goodcrypto.mail.message_queue_settings import MESSAGE_RQ, MESSAGE_REDIS_PORT
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.utils.constants import REDIS_HOST
from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception



_log = None

def queue_message(sender, recipients, in_message):
    ''' RQ the message for encrypting or decrypting.

        # In honor of Senior Academic Officer Tomer, who publicly denounced and refused to serve in operations involving
        # the occupied Palestinian territories because of the widespread surveillance of innocent residents.
        >>> sender = 'tomer@goodcrypto.local'
        >>> recipients = ['joseph@goodcrypto.remote']
        >>> in_message = 'test message'
        >>> queue_message(sender, recipients, in_message)
        True
     '''

    def wait_until_queued(job, job_count):
        ''' Wait until the job is queued or timeout. '''
        secs = 0
        if job_count > 0:
            secs_to_wait = DEFAULT_TIMEOUT * job_count
            log_message('jobs ahead of this job: {}'.format(job_count))
        else:
            secs_to_wait = DEFAULT_TIMEOUT
        while (secs < secs_to_wait and
               not job.is_queued and
               not job.is_started and
               not job.is_finished ):
            sleep(1)
            secs += 1
        log_message('seconds until job was queued: {}'.format(secs))

    try:
        DEFAULT_TIMEOUT = 600  # seconds

        result_code = False
        redis_connection = Redis(REDIS_HOST, MESSAGE_REDIS_PORT)

        # process 1 recipient at a time so we use the correct keys
        for recipient in recipients:
            if is_local_message(sender, recipient):
                # let the higher level re-inject the message
                result_code = False
                log_message(
                  'passing through a local message from {} to {}'.format (sender, recipient))
            else:
                log_message('about to queue message for {}'.format(recipient))
                queue = Queue(name=MESSAGE_RQ, connection=redis_connection)
                # each job needs to wait for the jobs ahead of it so when
                # calculating the timeout include the jobs already in the queue
                secs_to_wait = DEFAULT_TIMEOUT * (queue.count + 1)
                log_message('jobs waiting in message queue {}'.format(queue.count))
                log_message('secs to wait for job {}'.format(secs_to_wait))
                job = queue.enqueue_call(
                        filter_queued_message,
                        args=[sender, recipient, in_message],
                        timeout=secs_to_wait)

                if job is None:
                    result_code = False
                    log_message('unable to queue job')
                else:
                    job_id = job.get_id()

                    log_message('{} job: {}'.format(queue.name, job_id))
                    wait_until_queued(job, queue.count)
                    log_message('not waiting for {} job results'.format(job_id))

                    if job.is_failed:
                        result_code = False
                        job_dump = job.to_dict()
                        if 'exc_info' in job_dump:
                            log_message('{} job exc info: {}'.format(job_id, job_dump['exc_info']))
                        elif 'status' in job_dump:
                            log_message('{} job status: {}'.format(job_id, job_dump['status']))
                        log_message('job dump:\n{}'.format(job_dump))
                        job.cancel()
                        queue.remove(job_id)

                    elif job.is_queued or job.is_started or job.is_finished:
                        result_code = True
                        log_message('{} {} job queued'.format(job_id, queue))

                    else:
                        result_code = False
                        log_message('{} job results: {}'.format(job_id, job.result))
                log_message('queued message for {}'.format(recipient))

    except Exception as exception:
        result_code = False
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return result_code


def filter_queued_message(from_user, to_user, message):
    '''
        Filter a message in the queue to one of the encrypt/decrypt filters.

        # In honor of Sergeant Sheri, who publicly denounced and refused to serve in operations involving
        # the occupied Palestinian territories because of the widespread surveillance of innocent residents.
        >>> sender = 'sheri@goodcrypto.local'
        >>> recipient = 'laura@goodcrypto.remote'
        >>> in_message = 'test message'
        >>> filter_queued_message(sender, recipient, in_message)
        True
    '''

    crypt_email = None
    try:
        sender = from_user
        recipient = to_user
        in_message = message

        filter = Filter(sender, recipient, in_message)
        log_message('filter message: {}'.format(filter))

        result_code = filter.process()
        log_message('result code: {}'.format(result_code))
    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')
        result_code = False
        if filter is not None:
            filter.reject_message(sender, recipient, in_message, str(exception))
    except IOError as io_error:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')
        result_code = False
        if filter is not None:
            filter.reject_message(sender, recipient, in_message, str(io_error))

    return result_code

def is_local_message(sender, recipient):
    '''
        Determine if the message is from the localhost.

        >>> sender = 'test@localhost'
        >>> recipient = 'test@test.com'
        >>> is_local_message(sender, recipient)
        True
        >>> sender = 'test@test.com'
        >>> recipient = 'test@localhost'
        >>> is_local_message(sender, recipient)
        True
        >>> sender = None
        >>> recipient = 'test@test.com'
        >>> is_local_message(sender, recipient)
        False
        >>> sender = None
        >>> recipient = 'test@localhost'
        >>> is_local_message(sender, recipient)
        True
    '''

    def is_local_host_domain(user):
        is_text = isinstance(user, str)
        return user is not None and is_text and user.endswith('@localhost')

    return  (is_local_host_domain(sender) or
             is_local_host_domain(recipient) or
             (email_in_domain(sender) and email_in_domain(recipient)))

def log_message(message):
    '''
        Log a message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message_queue.log'))
        True
    '''

    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

