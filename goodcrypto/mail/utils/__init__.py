'''
    Mail utilities.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-04-16

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, string
from traceback import format_exc
from django.contrib.auth import authenticate
from django.contrib.auth.models import User

from goodcrypto.constants import STATUS_GREEN, STATUS_RED, STATUS_YELLOW
from goodcrypto.mail.constants import PASSCODE_MAX_LENGTH, PASSWORD_MAX_LENGTH
from goodcrypto.mail.options import get_domain, get_mail_server_address
from goodcrypto.oce.utils import parse_address
from goodcrypto.utils import i18n, is_program_running
from goodcrypto.utils.log_file import LogFile

log = LogFile()

def get_mail_status():
    '''
        Return whether Mail is running.

        >>> # This test frequently fails even though all apps are running, 
        >>> # but it never seems to fail in real environment
        >>> get_mail_status()
        'green'
    '''

    programs_running = (is_program_running('goodcrypto.mail.rq_crypto_settings') and
                        is_program_running('goodcrypto.oce.rq_gpg_settings') and
                        is_program_running('redis'))
    """
    log.write('is rq_crypto_settings: {}'.format(is_program_running('goodcrypto.mail.rq_crypto_settings')))
    log.write('is rq_gpg_settings: {}'.format(is_program_running('goodcrypto.oce.rq_gpg_settings')))
    log.write('is redis: {}'.format(is_program_running('redis')))
    """
    
    domain = get_domain()
    mta = get_mail_server_address()
    app_configured = (domain is not None and len(domain.strip()) > 0 and
                      mta is not None and len(mta.strip()) > 0)

    if programs_running:
        if app_configured:
            status = STATUS_GREEN
        else:
            status = STATUS_YELLOW
    else:
        status = STATUS_RED

    return status
    
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
        __, address = parse_address(email)

        if address is None  or len(address) <= 0 or domain is None or len(domain) <= 0:
            result_ok = False
        else:
            result_ok = address.lower().endswith('@{}'.format(domain.lower()))

    return result_ok
    
def gen_passcode(max_length=PASSCODE_MAX_LENGTH):
    ''' 
        Generate a passcode. 
        This will only be used internally so we want as many chars as possible. 

        >>> len(gen_passcode())
        1000
    '''
    
    # the passcode must be random, but the characters must be valid for django
    passcode = ''
    while len(passcode) < max_length:
        new_char = os.urandom(1)
        try:
            new_char.decode('utf-8')
            # the character must be a printable character
            if new_char in string.printable and new_char not in ['\n', '\r', '\t', '"', '`']:
                # and the password must not start or end with a space
                if (new_char == ' ' and 
                    (len(passcode) == 0 or (len(passcode) + 1) == max_length)):
                    pass
                else:
                    passcode += new_char
        except:
            pass

    return passcode

def gen_password(max_length=PASSWORD_MAX_LENGTH):
    ''' 
        Generate a word that a user is likely to use so keep it reasonable. 

        >>> len(gen_password().strip())
        25
    '''
    
    return gen_passcode(max_length=max_length)

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
        ok = True

    return ok

def create_superuser(sysadmin, password=None):
    '''
        Create a django superuser.
        
        >>> # In honor of Sergeant Michal, who publicly denounced and refused to serve in operations involving the 
        >>> # occupied Palestinian territories because of the widespread surveillance of innocent residents.
        >>> password, error_message = create_superuser('michal@goodcrypto.remote')
        >>> password == None
        True
        >>> error_message is None
        True
        >>> __, error_message = create_superuser(None)
        >>> error_message
        'Sysadmin is not defined so unable to finish configuration.'
    '''

    password = error_message = None
    if sysadmin is None:
        error_message = i18n("Sysadmin is not defined so unable to finish configuration.")
        log.write('sysadmin not defined')
    else:
        try:
            users = User.objects.filter(username=sysadmin)
        except:
            users = []
            log.write(format_exc())

        if len(users) > 0:
            log.write_and_flush('{} user named {} already exists'.format(len(users), sysadmin))
        else:
            try:
                if password is None:
                    # create a password
                    password = gen_passcode(max_length=24)

                user = User.objects.create_superuser(sysadmin, sysadmin, password)
                log.write_and_flush('created superuser: {}'.format(user))
            except:
                password = None
                error_message = i18n('Unable to add a sysadmin user named {}.'.format(sysadmin))
                log.write_and_flush(format_exc())
    
    return password, error_message

def create_user(email):
    '''
        Create a regular django user.
        
        >>> __, error_message = create_user(None)
        >>> error_message
        'Email is not defined so unable to finish configuration.'
    '''

    password = error_message = None
    if email is None:
        error_message = i18n("Email is not defined so unable to finish configuration.")
        log.write('email not defined')
    else:
        try:
            users = User.objects.filter(username=email)
        except:
            users = []
            log.write(format_exc())

        if len(users) > 0:
            log.write_and_flush('{} user(s) already exist'.format(len(users)))
        else:
            try:
                # create a password
                password = str(gen_password(max_length=24))

                user = User.objects.create_user(email, email, password)
                log.write_and_flush('created user: {}'.format(user))
            except:
                password = None
                error_message = i18n('Unable to add a regular user for {email}.'.format(email=email))
                log.write_and_flush(format_exc())
    
    return password, error_message

def authenticate_superuser(email, password):
    '''
        Authenticate a django super user.

        >>> __, __, error_message = authenticate_superuser(None, None)
        >>> error_message
        'Email or password are not defined so unable to authenticate user.'
    '''

    ok, user, error_message = authenticate_user(email, password)
    if ok and user is not None:
        ok = user.is_staff and user.is_superuser
        if not ok:
            error_message = i18n("The user is not an authorized superuser.")

    return ok, user, error_message

def authenticate_user(email, password):
    '''
        Authenticate a django user.

        >>> __, __, error_message = authenticate_user(None, None)
        >>> error_message
        'Email or password are not defined so unable to authenticate user.'
    '''

    ok = False
    user = error_message = None
    if email is None or password is None:
        error_message = i18n("Email or password are not defined so unable to authenticate user.")
        log.write(error_message)
    else:
        user = authenticate(username=email, password=password)
        if user is not None:
            # the password verified for the user
            if user.is_active:
                ok = True
                log.write("{} is valid, active and authenticated".format(email))
            else:
                error_message = i18n("The {} account has been disabled.".format(email))
                log.write(error_message)
        else:
            # the authentication system was unable to verify the username and password
            error_message = i18n("The email and password do not match the previously configured account.")

    return ok, user, error_message

def delete_user(email):
    '''
        Delete a django user.
        
        >>> delete_user(None)
        False
    '''

    ok = False
    if email is None:
        ok = False
        log.write('email not defined')
    else:
        try:
            user = User.objects.get(username=email)
        except:
            user = None
            log.write(format_exc())

        if user:
            user.delete()
        else:
            ok = False
    
    return ok


