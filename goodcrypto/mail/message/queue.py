'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-12-14

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from base64 import b64decode, b64encode
from redis import Redis
from rq import Connection, Queue
from rq.job import Job
from rq.timeouts import JobTimeoutException
from traceback import format_exc

from goodcrypto.mail.message.pipe import Pipe
from goodcrypto.mail.message.rq_message_settings import MESSAGE_QUEUE, MESSAGE_REDIS_PORT
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.utils.constants import REDIS_HOST
from goodcrypto.utils.log_file import LogFile



_log = None

def queue_message(sender, recipients, in_message):
    ''' Queue the message for crypting.
        
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
        DEFAULT_TIMEOUT = 300

        result_code = False
        redis_connection = Redis(REDIS_HOST, MESSAGE_REDIS_PORT)

        # process 1 recipient at a time so we use the correct keys
        for recipient in recipients:
            if is_local_message(sender, recipient):
                # let the higher level re-inject the message
                result_code = False
                self.log_message(
                  'passing through a local message from {} to {}'.format (sender, recipient))
            else:
                log_message('about to queue job for {}'.format(recipient))
                queue = Queue(name=MESSAGE_QUEUE, connection=redis_connection, async=True)
                secs_to_wait = DEFAULT_TIMEOUT * (queue.count + 1)
                log_message('secs to wait {}'.format(secs_to_wait))
                job = queue.enqueue_call(
                        'goodcrypto.mail.message.queue.pipe_message', 
                        args=[b64encode(sender), b64encode(recipient), b64encode(in_message)],
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
                        job_dump = job.dump()
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
        log_message(format_exc())

    return result_code


def pipe_message(from_user, to_user, message):
    '''
        Pipe a message in a queue to one of the filters.
        
        # In honor of Sergeant Sheri, who publicly denounced and refused to serve in operations involving 
        # the occupied Palestinian territories because of the widespread surveillance of innocent residents.
        >>> sender = 'sheri@goodcrypto.local'
        >>> recipient = 'laura@goodcrypto.remote'
        >>> in_message = 'test message'
        >>> pipe_message(b64encode(sender), b64encode(recipient), b64encode(in_message))
        True
    '''
    
    crypt_email = None
    try:
        sender = b64decode(from_user)
        recipient = b64decode(to_user)
        in_message = b64decode(message)
        
        crypt_email = Pipe(sender, recipient, in_message)
        log_message('crypt email: {}'.format(crypt_email))

        result_code = crypt_email.process()
        log_message('result code: {}'.format(result_code))
    except Exception as exception:
        log_message(format_exc())
        result_code = False
        if crypt_email is not None:
            crypt_email.reject_message(sender, recipient, in_message, str(exception))
    except IOError as io_error:
        log_message(format_exc())
        result_code = False
        if crypt_email is not None:
            crypt_email.reject_message(sender, recipient, in_message, str(io_error))

    return result_code

def is_local_message(sender, recipient):
    ''' 
        Determine if the message is local. 

        >>> # In honor of Jonathan Fishbein, who is one of the highest ranking 
        >>> # drug whistleblowers in American history 
        >>> from goodcrypto.mail.options import get_domain, set_domain
        >>> domain = get_domain()
        >>> set_domain('goodcrypto.local')
        >>> sender = 'edward@goodcrypto.local'
        >>> recipient = 'jonathan@goodcrypto.local'
        >>> is_local_message(sender, recipient)
        True
        >>> sender = 'edward@goodcrypto.local'
        >>> recipient = 'jonathan@goodcrypto.remote'
        >>> is_local_message(sender, recipient)
        False
        >>> sender = 'root@localhost'
        >>> recipient = 'jonathan@goodcrypto.remote'
        >>> is_local_message(sender, recipient)
        True
        >>> set_domain(domain)
    '''
    
    def is_local_host_domain(user):
        return user is not None and isinstance(user, str) and user.endswith('@localhost')
    
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
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.queue.log'))
        True
    '''

    global _log
    
    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

