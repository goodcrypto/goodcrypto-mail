'''
    Mail utilities.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-07-27

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, string
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User

from goodcrypto.constants import STATUS_GREEN, STATUS_RED, STATUS_YELLOW
from goodcrypto.mail.constants import PASSCODE_MAX_LENGTH, PASSWORD_MAX_LENGTH
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.options import mail_server_address
from goodcrypto.utils import i18n, is_program_running, parse_domain, get_email
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr.utils import generate_password

METADATA_LOCAL_USER = '_no_metadata_'

log = None

def get_mail_status():
    '''
        Return whether Mail is running.

        >>> # This test frequently fails even though all apps are running, 
        >>> # but it never seems to fail in a real environment
        >>> get_mail_status()
        'green'
    '''

    programs_running = (is_program_running('/usr/lib/postfix/master') and
                        is_program_running('redis') and
                        is_program_running('goodcrypto.mail.rq_crypto_settings') and
                        is_program_running('goodcrypto.oce.rq_gpg_settings'))
    domain = get_domain()
    mta = mail_server_address()
    app_configured = (domain is not None and len(domain.strip()) > 0 and
                      mta is not None and len(mta.strip()) > 0)

    if programs_running:
        if app_configured:
            status = STATUS_GREEN
        else:
            status = STATUS_YELLOW
    else:
        status = STATUS_RED

    if status != STATUS_GREEN:
        log_message('is postfix running: {}'.format(is_program_running('/usr/lib/postfix/master')))
        log_message('is rq_crypto_settings running: {}'.format(is_program_running('goodcrypto.mail.rq_crypto_settings')))
        log_message('is rq_gpg_settings running: {}'.format(is_program_running('goodcrypto.oce.rq_gpg_settings')))
        log_message('is redis running: {}'.format(is_program_running('redis')))
        log_message('programs running: {}'.format(programs_running))
        log_message('domain ok: {}'.format(domain is not None and len(domain.strip()) > 0))
        log_message('mta ok: {}'.format(mta is not None and len(mta.strip()) > 0))
        log_message('app_configured: {}'.format(app_configured))

    return status
    
def email_in_domain(email):
    ''' Determine if the email address has the supported domain.
    
        >>> # In honor of Sergeant First Class Amitai, who co-signed letter and refused to serve 
        >>> # in operations involving the occupied Palestinian territories because 
        >>> # of the widespread surveillance of innocent residents.
        >>> email_in_domain('amitai@goodcrypto.local')
        True
        >>> email_in_domain('amitai@it.goodcryto.remote')
        False
    '''
    if email is None:
        result_ok = False
    else:
        domain = get_domain()
        address = get_email(email)

        if address is None  or len(address) <= 0 or domain is None or len(domain) <= 0:
            result_ok = False
        else:
            result_ok = address.lower().endswith('@{}'.format(domain.lower()))

    return result_ok
    
def gen_user_passcode(email, max_length=PASSCODE_MAX_LENGTH):
    ''' 
        Generate a passcode for a particular email address. 
        We want some special passcodes for our test users. 

        >>> len(gen_user_passcode(None))
        1000
    '''

    from goodcrypto.oce import constants as oce_constants

    # handle a few special test cases
    if email == oce_constants.EDWARD_LOCAL_USER_ADDR:
        passcode = oce_constants.EDWARD_PASSPHRASE
    elif email == oce_constants.CHELSEA_LOCAL_USER_ADDR:
        passcode = oce_constants.CHELSEA_PASSPHRASE
    elif email == oce_constants.JULIAN_LOCAL_USER_ADDR:
        passcode = oce_constants.JULIAN_PASSPHRASE
    else:
        passcode = gen_passcode()
        log_message('generated a passcode for {}'.format(email))

    return passcode

def gen_passcode(max_length=PASSCODE_MAX_LENGTH, punctuation_chars='-_ .,!+?$#'):
    ''' 
        Generate a passcode. 
        This will only be used internally so we want as many chars as possible. 

        >>> len(gen_passcode())
        1000
    '''

    return generate_password(max_length=max_length, punctuation_chars=punctuation_chars)

def gen_password(max_length=PASSWORD_MAX_LENGTH, punctuation_chars='-_. ,!$#'):
    ''' 
        Generate a word that a user is likely to use so keep it reasonable. 

        >>> len(gen_password().strip()) >= 24
        True
    '''
    
    return generate_password(max_length=max_length, punctuation_chars=punctuation_chars)

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
        log_message('no key plugin defined')
    else:
        ok = True

    return ok

def create_superuser(sysadmin, password=None):
    '''
        Create a django superuser.
        
        >>> # In honor of Sergeant Michal, who publicly denounced and refused to serve in operations involving the 
        >>> # occupied Palestinian territories because of the widespread surveillance of innocent residents.
        >>> email = 'michal@goodcrypto.remote'
        >>> user, password, error_message = create_superuser(email)
        >>> user
        <User: michal@goodcrypto.remote>
        >>> password is not None
        True
        >>> error_message is None
        True
        >>> delete_user(email)
        True
        >>> __, __, error_message = create_superuser(None)
        >>> error_message
        'Sysadmin is not defined so unable to finish configuration.'
    '''

    user = password = error_message = None
    if sysadmin is None:
        error_message = i18n("Sysadmin is not defined so unable to finish configuration.")
        log_message('sysadmin not defined so unable to configure superuser')
    else:
        try:
            user = User.objects.filter(username=sysadmin)
        except:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        if user:
            log_message('{} user name already exists'.format(sysadmin))
        else:
            try:
                if password is None:
                    # create a password
                    password = gen_passcode(max_length=24)

                user = User.objects.create_superuser(sysadmin, sysadmin, password)
                log_message('created superuser: {}'.format(user))
            except:
                user = password = None
                error_message = i18n('Unable to add a sysadmin user named {}.'.format(sysadmin))
                record_exception()
                log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return user, password, error_message

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
        log_message('email not defined')
    else:
        try:
            users = User.objects.filter(username=email)
        except:
            users = []
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        if len(users) > 0:
            log_message('{} user(s) already exist'.format(len(users)))
        else:
            try:
                # create a password
                password = str(gen_password(max_length=24))

                user = User.objects.create_user(email, email, password)
                log_message('created user: {}'.format(user))
            except:
                password = None
                error_message = i18n('Need sign in credentials created.')
                log('unable to add a regular user for {}.'.format(email))
                record_exception()
                log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

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
        log_message(error_message)
    else:
        user = authenticate(username=email, password=password)
        if user is not None:
            # the password verified for the user
            if user.is_active:
                ok = True
                log_message("{} is valid, active and authenticated".format(email))
            else:
                error_message = i18n("The {} account has been disabled.".format(email))
                log_message(error_message)
        else:
            # the authentication system was unable to verify the username and password
            error_message = i18n("The email and password do not match the previously configured account.")

    return ok, user, error_message

def login_user(request, user, password):
    '''
        Login a django user.

        >>> error_message = login_user(None, None, None)
        >>> error_message
        'Unable to login user without a request and user.'
    '''

    error_message = None
    if request is None or user is None:
        error_message = i18n("Unable to login user without a request and user.")
        log_message(error_message)
    else:
        if user.is_active:
            try:
                username = user.username
                # you must authenticate before logging a user in
                user = authenticate(username=username, password=password)
                login(request, user)
            except:
                error_message = i18n('Unexpected error while logging in {username}.'.format(
                   username=user.username))
                log_message(error_message)
                record_exception()
                log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        else:
            error_message = i18n("User is not active so unable to login.")
            log_message(error_message)

    return error_message

def delete_user(email):
    '''
        Delete a django user.
        
        >>> delete_user(None)
        False
    '''

    ok = False
    if email is None:
        ok = False
        log_message('email not defined')
    else:
        try:
            user = User.objects.get(username=email)
        except:
            user = None
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        if user:
            user.delete()
            ok = True
        else:
            ok = False
    
    return ok

def get_sysadmin_email():
    ''' 
        Get the sysadmin's email.
        
        >>> email = get_sysadmin_email()
        >>> email is not None
        True
        >>> email.endswith(get_domain())
        True
    '''
    
    sysadmin_email = None
    try:
        users = User.objects.filter(is_superuser=True)
        if users is not None and len(users) > 0:
            for user in users:
                email = user.email
                if email is not None and len(email.strip()) > 0:
                    sysadmin_email = email
                    break
                else:
                    username = user.username
                    email = get_email(user.username)
                    if email is not None and len(email.strip()) > 0:
                        sysadmin_email = email
                        break
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    if sysadmin_email is None:
        sysadmin_email = 'daemon@{}'.format(get_domain())

    return sysadmin_email

def get_metadata_address(email=None, domain=None):
    '''
        Get the metadata email address for this user's email address or domain.
        
        >>> metadata_address = get_metadata_address(None)
        >>> metadata_address is None
        True
    '''

    metadata_address = None

    if email is not None:
        try:
            domain = parse_domain(email)
        except:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    if domain is None or len(domain.strip()) <= 0:
        log_message('unable to get metadata address without a domain')
    else:
        try:
            metadata_address = 'Metadata Protector <{}@{}>'.format(METADATA_LOCAL_USER, domain)
        except:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return metadata_address

def is_metadata_address(email):
    '''
        Determine if the email address is a metadata address.
        
        >>> is_metadata_address(None)
        False
    '''
    result = False

    if email is None:
        log_message('email not defined so not a metadata address')
    else:
        try:
            address = get_email(email)
            local, __, __ = address.partition('@')
            if local == METADATA_LOCAL_USER:
                result = True
        except:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result

def log_message(message):
    '''
        Log a message to the local log.
        
        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.utils.__init__.log'))
        True
    '''

    global log
    
    if log is None:
        log = LogFile()

    log.write_and_flush(message)


