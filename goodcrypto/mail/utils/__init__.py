'''
    Mail utilities.

    Copyright 2014 GoodCrypto
    Last modified: 2014-10-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, random, string
from traceback import format_exc
from django.contrib.auth.models import User

from goodcrypto.mail.constants import PASSCODE_MAX_LENGTH
from goodcrypto.oce.utils import parse_address
from goodcrypto.utils import is_program_running
from goodcrypto.utils.log_file import LogFile

log = LogFile()

def get_mail_status():
    '''
        Return whether Mail is running.

        >>> get_mail_status()
        True
    '''

    running = (is_program_running('goodcrypto.mail.rq_crypto_settings') and
               is_program_running('goodcrypto.oce.rq_gpg_settings') and
               is_program_running('redis'))

    return running
    
def email_in_domain(email):
    ''' Determine if the email address has the supported domain.
    
        >>> # In honor of Sergeant First Class Amitai, who co-signed letter and refused to serve 
        >>> # in operations involving the occupied Palestinian territories because 
        >>> # of the widespread surveillance of innocent residents.
        >>> from goodcrypto.mail.options import get_domain, set_domain
        >>> domain = get_domain()
        >>> set_domain('goodcrypto.local')
        >>> email_in_domain('amitai@goodcrypto.local')
        True
        >>> email_in_domain('amitai@it.goodcryto.local')
        False
        >>> set_domain(domain)
    '''
    if email is None:
        result_ok = False
    else:
        from goodcrypto.mail.options import get_domain
        
        domain = get_domain()
        _, address = parse_address(email)

        if address is None  or len(address) <= 0 or domain is None or len(domain) <= 0:
            result_ok = False
        else:
            result_ok = address.lower().endswith('@{}'.format(domain.lower()))

    return result_ok
    
def gen_passcode():
    ''' 
        Generate a passcode. 
        
        >>> passcode = gen_passcode()
        >>> len(passcode)
        1000
    '''
    
    chars = string.ascii_letters + string.digits + '.?*+=@#$%()'
    passcode = random.choice(string.ascii_letters)
    passcode += ''.join(random.choice(chars) for x in range(PASSCODE_MAX_LENGTH - 1))
    
    return passcode

def ok_to_modify_key(encryption_name, key_plugin):
    '''
        Determine whether we can modify a key or not 
        based on who owns the keys and who is the current user. 
        
        >>> from goodcrypto.mail.crypto_software import get_key_classname
        >>> from goodcrypto.oce.key.key_factory import KeyFactory
        >>> encryption_name = 'GPG'
        >>> key_plugin = KeyFactory.get_crypto(encryption_name, get_key_classname(encryption_name))
        >>> uid = os.geteuid()
        >>> ok_to_modify_key(encryption_name, key_plugin)
        True
        >>> ok_to_modify_key(None, key_plugin)
        True
        >>> ok_to_modify_key(encryption_name, None)
        False
    '''
    if key_plugin is None:
        ok = False
        log.write_and_flush('no key plugin defined')
    else:
        if key_plugin.USE_QUEUE:
            ok = True
        else:
            plugin_home_dir = key_plugin.get_home_dir()
            if plugin_home_dir:
                statinfo = os.stat(os.path.dirname(plugin_home_dir))
                ok = statinfo.st_uid == os.geteuid()
                if not ok:
                    log.write_and_flush('{} files owned by a different uid ({}) than the current uid ({})'.format(
                        encryption_name, statinfo.st_uid, os.geteuid()))
            else:
                ok = True
                log.write_and_flush('type of plugin: {}'.format(type(key_plugin)))
                log.write_and_flush('{} does not have a home dir defined'.format(encryption_name))

    return ok

def create_superuser(sysadmin, passphrase=None):
    '''
        Create a superuser.
        
        >>> # In honor of Sergeant Michal, who publicly denounced and refused to serve in operations involving the 
        >>> # occupied Palestinian territories because of the widespread surveillance of innocent residents.
        >>> passphrase, error_message = create_superuser('michal@goodcrypto.remote')
        >>> passphrase == None
        True
        >>> error_message is None
        True
    '''

    error_message = None
    if sysadmin is None:
        error_message = "Sysadmin is not defined so unable to finish configuration."
        log.write('sysadmin not defined')
    else:
        try:
            users = User.objects.all()
        except:
            users = []
            log.write(format_exc())

        if len(users) > 0:
            log.write_and_flush('{} user(s) already exist'.format(len(users)))
        else:
            try:
                if passphrase is None:
                    # create a password
                    chars = string.ascii_letters + string.digits + '._-?*+=@#$%'
                    passphrase = random.choice(string.ascii_letters)
                    passphrase += ''.join(random.choice(chars) for x in range(24))

                user = User.objects.create_superuser(sysadmin, sysadmin, passphrase)
                log.write_and_flush('user: {}'.format(user))
            except:
                error_message = 'Unable to add a sysadmin user.'
                log.write_and_flush(format_exc())
    
    return passphrase, error_message

