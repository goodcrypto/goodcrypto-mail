#!/usr/bin/env python
'''
    Manage GoodCrypto's encryption software.

    Pass the encryption software name to determine if its active, its classname, etc.
    For example:
    <pre>
         active = is_active('GPG')
         classname = get_classname('GPG')
         key_classname = get_key_classname('GPG')
    </pre>
    
    or
    <pre>
        classname = get_classname('GPG')
        active = is_active('GPG')
    </pre>
    
    Copyright 2014 GoodCrypto.
    Last modified: 2014-11-17

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail.models import EncryptionSoftware

_log = None

def is_ok():
    '''
        Determine if all active encryption software have all the required fields
        and that at least one encryption program is active.

        >>> programs = EncryptionSoftware.objects.all()
        >>> is_ok() == (programs is not None and len(programs) > 0)
        True
    '''

    result_ok = True
    try:
        programs = EncryptionSoftware.objects.all()
        if programs is None or len(programs) <= 0:
            result_ok = False
            log_message('no encryption software defined')
        else:
            found_active_program = False
            for program in programs:
                if program.active:
                    result_ok = len(program.name) > 0
                    if result_ok:
                        found_active_program = True
                    else:
                        log_message("{} is missing required data".format(program.name))
                        break

            # there must be 1 active program that's configured properly
            if result_ok and not found_active_program:
                result_ok = False

    except EncryptionSoftware.DoesNotExist:
        result_ok = False
        log_message('no encryption software defined')

    except Exception:
        result_ok = False
        log_message(format_exc())

    return result_ok

def exists(name):
    '''
        Determine if the encryption program exists already.

        Test an unknown name so we're sure of the result.
        >>> exists('Unknown name')
        False
    '''

    program = get(name)
    found = program is not None and program.name == name
    log_message("{} encryption software exists: {}".format(name, found))

    return found

def get(name):
    '''
        Get the encryption program.

        Test an unknown name so we're sure of the result.
        >>> get('Unknown name') is None
        True

        Test the extreme case.
        >>> get(None) is None
        True
    '''    

    if name is None:
        software = None
    else:
        try:
            software = EncryptionSoftware.objects.get(name=name)
        except EncryptionSoftware.DoesNotExist:
            software = None
            log_message('"{}" encryption software does not exist'.format(name))
        except Exception:
            software = None
            log_message(format_exc())

    return software

def set(updated_software):
    '''
        Update the software or add it if it doesn't exist.

        >>> updated_software = EncryptionSoftware(name='test', active=True, classname='goodcrypto.oce.test')
        >>> set(updated_software)
        True
        >>> get('test')
        <EncryptionSoftware: test>
        >>> updated_software.name = 'new_test'
        >>> set(updated_software)
        True
        >>> get('new_test')
        <EncryptionSoftware: new_test>
        >>> delete('new_test')
        True
    '''

    result_ok = True
    try:
        software = get(updated_software.name)
        if software is None:
            software = EncryptionSoftware(
               name=updated_software.name, active=updated_software.active, 
                  classname=updated_software.classname)
            software.save()
            log_message("added encryption program: {}".format(updated_software.name))
        else:
            software.name = updated_software.name
            software.active = updated_software.active
            software.classname = updated_software.classname
            software.save()
            log_message("updated encryption program: {}".format(updated_software.name))
    except Exception:
        result_ok = False
        log_message(format_exc())

    return result_ok

def delete(name_or_software):
    '''
        Delete the encryption software with a matching name.

        >>> updated_software = EncryptionSoftware(name='test', active=True, classname='goodcrypto.oce.test')
        >>> set(updated_software)
        True
        >>> delete('test')
        True
    '''

    result_ok = True
    try:
        if isinstance(name_or_software, str):
            software = get(name_or_software)
        else:
            software = name_or_software
            
        if software is None:
            log_message('nothing to delete')
        else:
            encryption_software = get(software.name)
            if encryption_software is None:
                log_message('{} does not exist so need to delete'.format(name_or_software))
            else:
                encryption_software.delete()
                log_message("deleted {}".format(software.name))
    except Exception:
        result_ok = False
        log_message(format_exc())

    return result_ok

def is_any_encryption_active():
    '''
        Determine if at least one encryption program is active.

        >>> updated_software = EncryptionSoftware(name='test', active=True, classname='goodcrypto.oce.test')
        >>> set(updated_software)
        True
        >>> is_any_encryption_active()
        True
        >>> delete('test')
        True
    '''

    try:
        software = EncryptionSoftware.objects.filter(active=True)
        active = software and len(software) > 0
    except Exception:
        active = False
        log_message(format_exc())
        
    return active

def get_active_names():
    '''
        Get the list of active encryption program names.

        >>> get_active_names() is not None
        True
    '''

    active_names = []
    try:
        programs = EncryptionSoftware.objects.filter(active=True)
        for program in programs:
            active_names.append(program.name)
    except Exception:
        log_message(format_exc())

    log_message("active programs: {}".format(active_names))

    return active_names

def get_encryption_names():
    '''
        Get the list of all encryption program names.

        >>> get_encryption_names() is not None
        True
    '''

    names = []
    try:
        programs = EncryptionSoftware.objects.all()
        for program in programs:
            names.append(program.name)
    except Exception:
        log_message(format_exc())
        
    log_message("encryption software: {}".format(names))

    return names

def is_active(name):
    ''' 
        Determine if the encryption software is active.
        
        >>> is_active('unknown')
        False
        
        >>> is_active(None)
        False
    '''
    
    active = False
    
    software = get(name)
    if software:
        active = software.active

    return active


def get_classname(name):
    ''' 
        Get the classname associated with this encryption software.

        >>> get_classname('unknown') is None
        True
    '''
    
    classname = None
    
    software = get(name)
    if software is not None:
        classname = software.classname

    if classname is not None:
        classname = classname.strip()
        if len(classname) <= 0:
            classname = None

    return classname
    
def get_key_classname(name):
    ''' 
        Get the classname for keys associated with this encryption software.

        >>> get_key_classname('unknown') is None
        True
    '''
    
    key_classname = get_classname(name)
    if key_classname is not None:
        module_name, _, classname = key_classname.rpartition('.')
        prefix, _, suffix = module_name.rpartition('.')
        key_classname = '{}.key.{}.{}'.format(prefix, suffix, classname)
            
    return key_classname

def log_message(message):
    '''
        Log a message to the local log.
        
        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.crypto_software.log'))
        True
    '''
    
    global _log
    
    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

