'''
    Mail utilities.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-03

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, re, string
from socket import AF_INET, AF_INET6, inet_pton
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User

from goodcrypto.constants import STATUS_GREEN, STATUS_RED, STATUS_YELLOW
from goodcrypto.mail.constants import DOMAIN_USER, PASSCODE_MAX_LENGTH, PASSWORD_MAX_LENGTH
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.options import mail_server_address, mta_listen_port
from goodcrypto.utils import i18n, get_email
from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception
from syr.message import send_mime_message
from syr.process import is_program_running
from syr.utils import generate_password

# the tests themsevles set this variable to True when appropriate
TESTS_RUNNING = False

DEBUGGING = False
USE_SMTP_PROXY = False

log = None

def get_mail_status():
    '''
        Return whether Mail is running.

        >>> status = get_mail_status()
        >>> status == 'green'
        True
    '''

    programs_running = is_mail_running()
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
        log_message('is postfix running: {}'.format(is_program_running('postfix/master')))
        log_message('is rqworker running: {}'.format(is_program_running('rqworker')))
        log_message('is redis running: {}'.format(is_program_running('redis')))
        log_message('programs running: {}'.format(programs_running))
        log_message('domain ok: {}'.format(domain is not None and len(domain.strip()) > 0))
        log_message('mta ok: {}'.format(mta is not None and len(mta.strip()) > 0))
        log_message('app_configured: {}'.format(app_configured))

    return status

def is_mail_running():
    '''
        Return true if all programs GoodCrypto mail uses are running.
        This does not mean that GoodCrypto mail is ready to use (i.e., it
        may be running, but not configured yet.)

        >>> is_mail_running()
        True
    '''

    return (is_program_running('postfix/master') and
            is_program_running('redis') and
            is_program_running('/usr/local/bin/rq'))

def is_mta_ok(mail_server_address):
    '''
        Verify the MTA is ok.

        Test extreme cases
        >>> is_mta_ok(None)
        False
    '''

    """
    from smtplib import SMTP, SMTP_SSL
    def smtp_connection_ok(self, mta):
        '''
            Try to connect to the MTA via SMTP and SMTP_SSL.
        '''

        connection_ok = False
        try:
            smtp = SMTP(host=mta)
            smtp.quit()
            connection_ok = True
        except:
            connection_ok = False

        if not connection_ok:
            try:
                smtp = SMTP_SSL(host=mta)
                smtp.quit()
                connection_ok = True
            except:
                connection_ok = False

        return connection_ok
    """

    ok = False

    # the mail_server_address should either be an ip address or a domain
    if mail_server_address is not None:
        mail_server_address = mail_server_address.strip()
        try:
            inet_pton(AF_INET, mail_server_address)
            ok = True
            log_message('mail server address IP4 compliant: {}'.format(ok))
        except:
            ok = False
            record_exception()

        if not ok:
            try:
                inet_pton(AF_INET6, mail_server_address)
                ok = True
                log_message('mail server address IP6 compliant: {}'.format(ok))
            except:
                ok = re.search("^[\\u00c0-\\u01ffa-zA-Z0-9'\-\.]+$", mail_server_address)
                log_message('mail server address ok: {}'.format(ok))

    return ok

def parse_domain(email):
    '''
        Get the domain from the email address.

        >>> domain = parse_domain(None)
        >>> domain is None
        True
    '''

    domain = None

    if email is None:
        log_message('email not defined so no domain')
    else:
        try:
            address = get_email(email)
            __, __, domain = address.partition('@')
        except:
            record_exception()

    return domain

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
        We use special passcodes for our test users.

        >>> len(gen_user_passcode(None))
        1000
    '''

    from goodcrypto.oce import test_constants

    # handle a few special test cases
    if email == test_constants.EDWARD_LOCAL_USER_ADDR:
        passcode = test_constants.EDWARD_PASSPHRASE
    elif email == test_constants.CHELSEA_LOCAL_USER_ADDR:
        passcode = test_constants.CHELSEA_PASSPHRASE
    elif email == test_constants.JULIAN_LOCAL_USER_ADDR:
        passcode = test_constants.JULIAN_PASSPHRASE
    else:
        passcode = gen_passcode()
        log_message('generated a passcode for {}'.format(email))

    return passcode

def gen_passcode(max_length=PASSCODE_MAX_LENGTH, punctuation_chars='-_ .,+?$#'):
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

def create_user_and_notify(email):
    '''
        Create a regular user so they can verify messages, fingerprints, etc.

        >>> password, error_message = create_user_and_notify(None)
        >>> password is None
        True
        >>> error_message == 'Email is not defined so unable to finish configuration.'
        True
    '''

    from goodcrypto.mail.utils import notices

    password, error_message = create_user(email)
    if password is None and error_message is None:
        # user already exists so nothing to do
        log_message('{} already has a db login account'.format(email))

    elif error_message is not None:
        notices.report_error_creating_login(email, error_message)
        log_message("{}'s db login password ok: {}".format(email, password is not None))
        log_message('notified {} about error: {}'.format(email, error_message))

    else:
        notices.send_user_credentials(email, password)
        log_message('notified {} about new django account'.format(email))

    return password, error_message

def create_superuser(admin, password=None):
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
        >>> error_message == 'Email for the admin is not defined so unable to finish configuration.'
        True
    '''

    user = password = error_message = None
    if admin is None:
        error_message = i18n("Email for the admin is not defined so unable to finish configuration.")
        log_message('admin not defined so unable to configure superuser')
    else:
        try:
            user = User.objects.filter(username=admin)
        except:
            record_exception()
            log_message('EXCEPTION - see syr.exception.log for details')

        if user:
            log_message('{} user name already exists'.format(admin))
        else:
            try:
                if password is None:
                    # create a password
                    password = gen_passcode(max_length=24)

                if len(admin) > 30:
                    user_name = admin[:30]
                else:
                    user_name = admin
                user = User.objects.create_superuser(user_name, admin, password)
                log_message('created superuser: {}'.format(user))
            except:
                user = password = None
                error_message = i18n('Unable to add an admin user named {}.'.format(admin))
                record_exception()
                log_message('EXCEPTION - see syr.exception.log for details')

    return user, password, error_message

def create_user(email):
    '''
        Create a regular django user.

        >>> __, error_message = create_user(None)
        >>> error_message == 'Email is not defined so unable to finish configuration.'
        True
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
            log_message('EXCEPTION - see syr.exception.log for details')

        if len(users) > 0:
            log_message('{} user(s) already exist'.format(len(users)))
        else:
            try:
                # create a password
                password = str(gen_password(max_length=24))

                if len(email) > 30:
                    user_name = email[:30]
                else:
                    user_name = email
                user = User.objects.create_user(user_name, email, password)
                log_message('created user: {}'.format(user))
            except:
                password = None
                error_message = i18n('Need sign in credentials created.')
                log_message('unable to add a regular user for {}.'.format(email))
                record_exception()
                log_message('EXCEPTION - see syr.exception.log for details')

    return password, error_message

def authenticate_superuser(email, password):
    '''
        Authenticate a django super user.

        >>> __, __, error_message = authenticate_superuser(None, None)
        >>> error_message == 'Email or password are not defined so unable to authenticate user.'
        True
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
        >>> error_message == 'Email or password are not defined so unable to authenticate user.'
        True
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
        >>> error_message == 'Unable to login user without a request and user.'
        True
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
                log_message('EXCEPTION - see syr.exception.log for details')
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
            log_message('EXCEPTION - see syr.exception.log for details')

        if user:
            user.delete()
            ok = True
        else:
            ok = False

    return ok

def get_admin_email():
    '''
        Get the admin's email.

        >>> email = get_admin_email()
        >>> email is not None
        True
        >>> email.endswith(get_domain())
        True
    '''

    admin_email = None
    try:
        users = User.objects.filter(is_superuser=True)
        if users is not None and len(users) > 0:
            for user in users:
                email = user.email
                if email is not None and len(email.strip()) > 0:
                    admin_email = email
                    break
                else:
                    username = user.username
                    email = get_email(user.username)
                    if email is not None and len(email.strip()) > 0:
                        admin_email = email
                        break
    except:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    if admin_email is None:
        admin_email = 'daemon@{}'.format(get_domain())

    return admin_email

def get_address_string(addresses):
    '''
        Returns a string representation of an address array.

        >>> # In honor of Edward Snowden, who had the courage to take action in the face of great personal risk and sacrifice.
        >>> # In honor of Joseph Nacchio, who refused to participate in NSA spying on Qwest's customers.
        >>> # In honor of Glenn Greenwald, who helped publicize the global surveillance disclosure documents.
        >>> from goodcrypto.oce.test_constants import EDWARD_LOCAL_USER, JOSEPH_REMOTE_USER, GLENN_REMOTE_USER
        >>> test_addresses = [EDWARD_LOCAL_USER, JOSEPH_REMOTE_USER, GLENN_REMOTE_USER]
        >>> address_string = '{}, {}, {}'.format(EDWARD_LOCAL_USER, JOSEPH_REMOTE_USER, GLENN_REMOTE_USER)
        >>> get_address_string(test_addresses) == address_string
        True
    '''

    line = []
    for address in addresses:
        line.append(address)

    return (", ").join(line)

def get_user_id_matching_email(address, user_ids):
    '''
        Gets the matching user ID based on email address.

        An address is a internet address. It may be just an email address,
        or include a readable name, such as "Jane Saladin <jsaladin@domain.com>".
        User ids are typically fingerprints from encryption software.

        A user id may be an internet address, or may be an arbitrary string.
        An address matches iff a user id is a valid internet address and the
        email part of the internet address matches. User ids which are not
        internet addresses will not match. The match is case-insensitive.

        >>> from goodcrypto.oce.test_constants import EDWARD_LOCAL_USER, EDWARD_LOCAL_USER_ADDR, JOSEPH_REMOTE_USER, GLENN_REMOTE_USER
        >>> test_addresses = [EDWARD_LOCAL_USER, JOSEPH_REMOTE_USER, GLENN_REMOTE_USER]
        >>> get_user_id_matching_email(EDWARD_LOCAL_USER, test_addresses) == EDWARD_LOCAL_USER_ADDR
        True
    '''

    matching_id = None

    try:
        for user_id in user_ids:
            email = get_email(user_id)
            if emails_equal(address, email):
                matching_id = email
                if DEBUGGING: log_message("{} matches {}".format(address, matching_id))
                break
    except Exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return matching_id

def emails_equal(address1, address2):
    '''
        Checks whether two addresses are equal based only on the email address.
        Strings which are not internet addresses will not match.
        The match is case-insensitive.

        >>> # In honor of Jim Penrose, a 17 year NSA employee who now warns that people
        >>> # should treat governments and criminals just the same. .
        >>> emails_equal('Jim <jim@goodcrypto.local>', 'jim@goodcrypto.local')
        True
    '''

    email1 = get_email(address1)
    email2 = get_email(address2)

    if email1 and email2:
        match = email1.lower() == email2.lower()
    else:
        match = False

    return match

def get_encryption_software(email):
    '''
        Gets the list of active encryption software for a contact.

        If the contact has no encryption software, returns a list
        consisting of just the default encryption software.

        >>> from goodcrypto.oce.test_constants import JOSEPH_REMOTE_USER
        >>> encryption_software = get_encryption_software(JOSEPH_REMOTE_USER)
        >>> encryption_software == ['GPG']
        True
        >>> get_encryption_software(None)
        []
    '''

    encryption_software_list = []

    try:
        #  start with the encryption software for this email
        address = get_email(email)

        from goodcrypto.mail.contacts import get_encryption_names
        encryption_names = get_encryption_names(address)
        if encryption_names is None:
            log_message("no encryption software names for {}".format(address))
            #  make sure we have at least the default encryption
            default_encryption_software = CryptoFactory.get_default_encryption_name()
            log_message("  defaulting to {}".format(default_encryption_software))
            encryption_names.append(default_encryption_software)

        #  only include active encryption software
        active_encryption_software = get_active_encryption_software()
        if active_encryption_software:
            for encryption_software in encryption_names:
                if encryption_software in active_encryption_software:
                    encryption_software_list.append(encryption_software)
    except:
        encryption_software_list = []
        record_exception()

    return encryption_software_list

def is_multiple_encryption_active():
    '''
        Check if multiple encryption programs are active.

        >>> is_multiple_encryption_active()
        True
    '''

    active_encryption_software = get_active_encryption_software()
    return active_encryption_software is not None and len(active_encryption_software) > 1

def get_active_encryption_software():
    '''
        Get the list of active encryption programs.

        >>> active_names = get_active_encryption_software()
        >>> len(active_names) > 0
        True
    '''

    try:
        from goodcrypto.mail.crypto_software import get_active_names

        active_names = get_active_names()
    except Exception:
        active_names = []
        log_message('no active encryption software')

    return active_names

def write_message(directory, message):
    '''
        Write message to an unique file in the specified directory.
        The message may be EmailMessage or python Message.

        >>> from email.message import Message
        >>> from goodcrypto.mail.utils.dirs import get_test_directory
        >>> filename = write_message(get_test_directory(), Message())
        >>> filename is not None
        True
        >>> filename = write_message(None, None)
        >>> filename is None
        True
    '''

    from goodcrypto.mail.message.inspect_utils import get_hashcode

    full_filename = None
    try:
        if message is not None:
            filename = '{}.txt'.format(get_hashcode(message))
            full_filename = os.path.join(directory, filename)

            if not os.path.exists(directory):
                os.makedirs(directory)

            with open(full_filename, 'w') as out:
                log_message('saving {}'.format(full_filename))

                from goodcrypto.mail.message.email_message import EmailMessage

                EmailMessage(message).write_to(out)
    except Exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return full_filename

def send_message(sender, recipient, message):
    '''
        Send a message.

        The message can be a Message in string format or a "email.Message" class.
    '''

    if TESTS_RUNNING:
        log_message('not sending message when tests running')
        result_ok = True
    else:
        try:
            log_message('starting to send message')
            if USE_SMTP_PROXY:
                result_ok, msg = send_mime_message(sender, recipient, message, use_smtp_proxy=USE_SMTP_PROXY,
                  mta_address=mail_server_address(), mta_port=mta_listen_port())
            else:
                result_ok, msg = send_mime_message(sender, recipient, message)

            if DEBUGGING:
                if result_ok:
                    log_message('=================')
                    log_message(msg)
                    log_message('=================')
            log_message('finished sending message: {}'.format(result_ok))
        except Exception as exception:
            result_ok = False
            log_message('error while sending message')
            log_message('EXCEPTION - see syr.exception.log for details')
            record_exception()

    return result_ok

def get_domain_user():
    '''
        Get the user for a domain key.

        >>> domain = get_domain_user()
        >>> domain == '_domain_'
        True
    '''

    return DOMAIN_USER

def get_domain_email():
    '''
        Get the email address for a domain key.

        >>> domain = get_domain_email()
        >>> domain == '_domain_@goodcrypto.local'
        True
    '''

    return '{}@{}'.format(get_domain_user(), get_domain())

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


