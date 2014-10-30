#!/usr/bin/env python
'''
    Basic for data, messages, etc. directories.
    
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-23

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from traceback import format_exc

from goodcrypto.constants import GOODCRYPTO_DATA_DIR
#from syr.sync_function import synchronized


MAIL_DATA_DIR = os.path.join(GOODCRYPTO_DATA_DIR, 'mail')

NoErrors = 1
DataDirBadPermissions = -1
BadPermissionsMessage = "Set the permissions on the directory so GoodCrypto can read, write, and create subdirectories."

#  Safe unix permissions for dirs. 
SafeDirPermissions = 0700

MESSAGES_DIRECTORY = "messages"
NOTICES_DIRECTORY = "notices"
QUEUE_DIRECTORY = 'queue'
TEST_DIRECTORY = "test"

_notices_directory = None
_test_directory = None
_messages_directory = None
_data_directory = None
_queue_directory = None


def dirs_ready():
    '''
        Verify that the data directory is set up
        so Mail can read/write to it.
        
        >>> bool(dirs_ready())
        True
        >>> os.path.exists(MAIL_DATA_DIR)
        True
    '''
    
    def show_error(data_dir):
        error_code = DataDirBadPermissions
        print("Create a directory named: {}".format(data_dir))
        print(BadPermissionsMessage)
        
        return error_code


    error_code = NoErrors
    data_dir = get_data_directory()

    try:
        error_code = NoErrors
        result_ok = True

        if not os.path.exists(data_dir):
            result_ok = _create_data_directory()
            
        if result_ok:
            result_ok = _set_dir_writeable(data_dir)
            
        if result_ok:
            error_code = NoErrors
        else:
            error_code = show_error(data_dir)
    except Exception:
        error_code = show_error(data_dir)
        print(format_exc())

    return error_code


#@synchronized
def get_data_directory():
    '''
        Get data directory.

        >>> get_data_directory() == MAIL_DATA_DIR
        True
        >>> os.path.exists(MAIL_DATA_DIR)
        True
    '''
    global _data_directory

    if _data_directory is None:
        _data_directory = MAIL_DATA_DIR

    if not os.path.exists(_data_directory):
        dirs_ready()

    return _data_directory

#@synchronized
def get_notices_directory():
    '''
        Gets the pathname for the notices directory.

        >>> os.path.exists(get_notices_directory())
        True
    '''

    global _notices_directory

    if _notices_directory is None:
        _notices_directory = _get_directory(get_messages_directory(), NOTICES_DIRECTORY)
    return _notices_directory

#@synchronized
def get_queue_directory():
    '''
        Gets the pathname for the queue directory.

        >>> os.path.exists(get_queue_directory())
        True
    '''

    global _queue_directory

    if _queue_directory is None:
        _queue_directory = _get_directory(MAIL_DATA_DIR, QUEUE_DIRECTORY)

    return _queue_directory

#@synchronized
def get_test_directory():
    '''
        Gets the pathname for the test directory.

        >>> os.path.exists(get_test_directory())
        True
    '''

    global _test_directory

    if _test_directory == None:
        _test_directory = _get_directory(get_messages_directory(), TEST_DIRECTORY)

    return _test_directory

#@synchronized
def get_messages_directory():
    '''
         Gets the pathname for the messages directory.
        
        >>> get_messages_directory() == os.path.join(MAIL_DATA_DIR, MESSAGES_DIRECTORY)
        True
    '''

    global _messages_directory

    if _messages_directory == None:
        _messages_directory = _get_directory(
            get_data_directory(), MESSAGES_DIRECTORY)
    return _messages_directory

def _get_directory(parent_directory, sub_directory):
    '''
        Creates a pathname and directory from the parent directory and subdirectory.
        
        >>> dirname = _get_directory(MAIL_DATA_DIR, 'test')
        >>> os.path.exists(dirname)
        True
        >>> os.rmdir(dirname)
    '''

    dir_file = os.path.join(parent_directory, sub_directory)
    if not os.path.exists(dir_file):
        try:
            os.makedirs(dir_file, SafeDirPermissions)
        except OSError:
            os.mkdir(dir_file, SafeDirPermissions)

    return dir_file

def _create_data_directory():
    '''
        Create the data directory for GoodCrypto.

        >>> dirname = _create_data_directory()
        >>> os.path.exists(MAIL_DATA_DIR)
        True
    '''

    result_ok = True
    
    # create GoodCrypto's data directory, if it doesn't already exist
    data_dir = get_data_directory()
    if not os.path.exists(data_dir):
        os.makedirs(data_dir, SafeDirPermissions)

    result_ok = os.path.exists(data_dir)
    
    return result_ok

def _set_dir_writeable(dirname):
    '''
        Make sure that files/directories can be created in dir.

        >>> _set_dir_writeable(MAIL_DATA_DIR)
        True
    '''

    result_ok = _test_subdir_ok(dirname)
    if not result_ok:
        _set_permissions(dirname)
        result_ok = _test_subdir_ok(dirname)
        
    return result_ok

def _test_subdir_ok(dirname):
    '''
        Make sure that subdirs can be created in the dir.

        >>> _test_subdir_ok(MAIL_DATA_DIR)
        True
        >>> not os.path.exists(os.path.join(MAIL_DATA_DIR, 'zosTest'))
        True
    '''

    result_ok = True
    # verify we can create a subdirectory
    test_dir = os.path.join(dirname, 'zosTest')
    os.mkdir(test_dir)
    if os.path.exists(test_dir) and os.path.isdir(test_dir):
        os.rmdir(test_dir)
    else:
        result_ok = False
        
    return result_ok

def _set_permissions(dirname):
    '''
        Set safe permissions for the dir.
        
        >>> dirname = os.path.join(MAIL_DATA_DIR, 'test')
        >>> os.makedirs(dirname)
        >>> _set_permissions(dirname)
        >>> os.rmdir(dirname)
    '''
    
    os.chmod(dirname, SafeDirPermissions)


if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)

