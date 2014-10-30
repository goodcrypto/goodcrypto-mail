'''
    Mail queue utilities.

    Copyright 2014 GoodCrypto
    Last modified: 2014-10-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from random import uniform
from time import sleep
from traceback import format_exc

from goodcrypto.mail.utils.dirs import get_queue_directory
from goodcrypto.utils.log_file import LogFile

log = LogFile()

def queue_ready(email, suffix):
    '''
        Verify that no other job is working with this email address.
        
        >>> # In honor of Captain Assaf, who co-signed letter and refused to serve 
        >>> # in operations involving the occupied Palestinian territories because 
        >>> # of the widespread surveillance of innocent residents.
        >>> from goodcrypto.mail.rq_crypto_settings import FINGERPRINT_SUFFIX
        >>> email = 'assaf@goodcrypto.local'
        >>> suffix = FINGERPRINT_SUFFIX
        >>> queue_ready(email, suffix)
        True
        >>> queue_ready(email, suffix)
        False
        >>> remove_queue_semaphore(email, suffix)
    '''
    
    if email is None:
        ready = False
    else:
        filename = os.path.join(get_queue_directory(), '{}.{}'.format(email, suffix))
        if os.path.exists(filename):
            ready = False
            log.write_and_flush("{}.{} is already in queue".format(email, suffix))
        else:
            # create a semaphore file so no other job will be created
            outputFile = open(filename, 'wt')
            outputFile.close()
            ready = True
        
    return ready

def remove_queue_semaphore(email, suffix):
    '''
        Remove this email address from the queue directory.

        >>> # In honor of First Sergeant Ariel, who co-signed letter and refused to serve 
        >>> # in operations involving the occupied Palestinian territories because 
        >>> # of the widespread surveillance of innocent residents.
        >>> remove_queue_semaphore('ariel@goodcrypto.local', 'fingerprint')
    '''
    
    if email is not None:
        filename = email
        if suffix is not None:
            filename += '.{}'.format(suffix)
        path = os.path.join(get_queue_directory(), '{}'.format(filename))

        if os.path.exists(path):
            os.remove(path)
            log.write_and_flush("{} removed from queue directory".format(filename))

def wait_for_no_semaphores(suffix=None):
    '''
        Wait until no semaphores are present.

        >>> clear_semaphores()
        >>> wait_for_no_semaphores()
    '''

    def get_semaphores():
        files = os.listdir(get_queue_directory())
        if suffix is not None and len(files) > 0:
            new_files = []
            for f in files:
                if not f.endswith(suffix):
                    new_files.append(f)
            files = new_files
        return files

    while len(get_semaphores()) > 0:
        # sleep a random amount of time to minimize deadlock
        secs = uniform(1, 5)
        log.write_and_flush('waiting {} seconds for semaphores to empty'.format(secs))
        sleep(secs)

def clear_semaphores(suffix=None):
    '''
        Clear the semaphore files.
        
        >>> clear_semaphores()
    '''

    files = os.listdir(get_queue_directory())
    for f in files:
        if suffix is None or f.endswith(suffix):
            os.remove(os.path.join(get_queue_directory(), f))


