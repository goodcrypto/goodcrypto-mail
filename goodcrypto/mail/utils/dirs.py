'''
    Basic for data, messages, etc. directories.
    
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-07-29

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os

from goodcrypto.constants import GOODCRYPTO_DATA_DIR
from goodcrypto.utils.exception import record_exception


MAIL_DATA_DIR = os.path.join(GOODCRYPTO_DATA_DIR, 'mail')

NoErrors = 1
DataDirBadPermissions = -1
BadPermissionsMessage = "Set the permissions on the directory so GoodCrypto can read, write, and create subdirectories."

#  Safe unix permissions for dirs. 
SafeDirPermissions = 0700

NOTICES_DIRECTORY = "notices"
PACKETS_DIRECTORY = 'packets'
TEST_DIRECTORY = "test"


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
        record_exception()

    return error_code

def get_data_directory():
    '''
        Get data directory.

        >>> get_data_directory() == MAIL_DATA_DIR
        True
        >>> os.path.exists(MAIL_DATA_DIR)
        True
    '''

    if not os.path.exists(MAIL_DATA_DIR):
        dirs_ready()

    return MAIL_DATA_DIR

def get_notices_directory():
    '''
        Gets the pathname for the notices directory.

        >>> os.path.exists(get_notices_directory())
        True
    '''

    return _get_directory(get_data_directory(), NOTICES_DIRECTORY)

def get_packet_directory():
    '''
        Gets the pathname for the packet directory.

        >>> os.path.exists(get_packet_directory())
        True
    '''

    return  os.path.join(get_data_directory(), PACKETS_DIRECTORY)

def get_test_directory():
    '''
        Gets the pathname for the test directory.

        >>> os.path.exists(get_test_directory())
        True
    '''

    return _get_directory(get_data_directory(), TEST_DIRECTORY)

def _get_directory(parent_directory, sub_directory):
    '''
        Creates a pathname and directory from the parent directory and subdirectory.

        >>> test_dirname = os.path.join(MAIL_DATA_DIR, 'test')
        >>> if os.path.exists(test_dirname):
        ...     filenames = os.listdir(test_dirname)
        ...     if filenames:
        ...         for filename in filenames:
        ...             os.remove(os.path.join(test_dirname, filename))
        >>> os.rmdir(test_dirname)
        >>> dirname = _get_directory(MAIL_DATA_DIR, 'test')
        >>> os.path.exists(dirname)
        True
        >>> filenames = os.listdir(os.path.join(MAIL_DATA_DIR, 'test'))
        >>> if filenames:
        ...     for filename in filenames:
        ...         os.remove(os.path.join(MAIL_DATA_DIR, 'test', filename))
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
        >>> if os.path.exists(dirname):
        ...     filenames = os.listdir(dirname)
        ...     if filenames:
        ...         for filename in filenames:
        ...             os.remove(os.path.join(dirname, filename))
        >>> os.makedirs(dirname)
        >>> _set_permissions(dirname)
        >>> filenames = os.listdir(dirname)
        >>> if filenames:
        ...     for filename in filenames:
        ...         os.remove(os.path.join(dirname, filename))
        >>> os.rmdir(dirname)
    '''
    
    os.chmod(dirname, SafeDirPermissions)


if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)

