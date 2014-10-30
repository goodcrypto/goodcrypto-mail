#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from random import uniform
from redis import Redis
from rq import Queue
from time import sleep
from traceback import format_exc

from goodcrypto.utils.constants import REDIS_HOST
from goodcrypto.utils.log_file import LogFile

log = LogFile()

def wait_until_queue_empty(name, port):
    '''
        Wait until the queue is empty.
        
        >>> from goodcrypto.oce.rq_gpg_settings import GPG_QUEUE, GPG_REDIS_PORT
        >>> wait_until_queue_empty(GPG_QUEUE, GPG_REDIS_PORT)
    '''

    redis_connection = Redis(REDIS_HOST, port)
    queue = Queue(name, connection=redis_connection)
    while not queue.is_empty():
        # sleep a random amount of time to minimize deadlock
        secs = uniform(1, 20)
        sleep(secs)

def get_job_count(name, port):
    '''
        Get the jobs in the queue.
        
        >>> from goodcrypto.oce.rq_gpg_settings import GPG_QUEUE, GPG_REDIS_PORT
        >>> wait_until_queue_empty(GPG_QUEUE, GPG_REDIS_PORT)
        >>> get_job_count(GPG_QUEUE, GPG_REDIS_PORT)
        0
    '''

    redis_connection = Redis(REDIS_HOST, port)
    queue = Queue(name, connection=redis_connection)
    if queue.get_job_ids() > 0:
        for job_id in queue.get_job_ids():
            log.write_and_flush('job id: {}'.format(job_id))
    return queue.count

def clear_failed_queue(name, port):
    ''' 
        Clear all the jobs in the failed queue.
        
        >>> from goodcrypto.oce.rq_gpg_settings import GPG_QUEUE, GPG_REDIS_PORT
        >>> clear_failed_queue(GPG_QUEUE, GPG_REDIS_PORT)
    '''

    redis_connection = Redis(REDIS_HOST, port)
    queue = Queue('failed', connection=redis_connection)
    if queue.get_job_ids() > 0:
        log.write('clearing {} failed jobs'.format(name))
        for job_id in queue.get_job_ids():
            job = queue.fetch_job(job_id)
            if job is not None:
                log.write_and_flush('   {}\n\n'.format(job.dump()))
            queue.remove(job_id)

def log_message(message):
    '''
        Log the message.
        
        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test message')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.utils.manage_queue.x.log'))
        True
    '''

    log.write_and_flush(message)


