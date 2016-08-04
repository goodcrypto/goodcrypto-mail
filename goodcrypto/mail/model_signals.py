'''
    Signals from creating and deleting mail models
    with the associated crypto keys.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-11-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from base64 import b64decode, b64encode
from redis import Redis
from rq import Connection, Queue
from rq.job import Job

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.mail.crypto_rq import delete_contacts_crypto_via_rq, add_private_key_via_rq, set_fingerprint_via_rq
from goodcrypto.mail.rq_special_settings import SPECIAL_RQ, SPECIAL_REDIS_PORT
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.utils.constants import REDIS_HOST
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from goodcrypto.utils.manage_rq import get_job_count, get_job_results


# the tests themsevles set this variable to True when appropriate
TESTS_RUNNING = False

_log = None

def post_save_contacts_crypto(sender, **kwargs):
    ''' Process the contact's encryption record after it's saved.'''

    if TESTS_RUNNING:
        log_message('tests running so no post save processing')
    else:
        log_message("starting post save for contact's crypto")
        contacts_encryption = kwargs['instance']
        email = contacts_encryption.contact.email
        encryption_software = contacts_encryption.encryption_software.name
        fingerprint = contacts_encryption.fingerprint
        log_message("{}'s {} id: {}".format(email, encryption_software, fingerprint))

        if email_in_domain(email):
            from goodcrypto.mail import user_keys

            user_key = user_keys.get(email, encryption_software)
            if (user_key is None or user_key.passcode is None):
                log_message('creating private {} key for {}'.format(encryption_software, email))
                add_private_key_via_rq(contacts_encryption)
            elif fingerprint is None:
                log_message('setting private {} fingerprint for {}'.format(encryption_software, email))
                set_fingerprint_via_rq(contacts_encryption)
            else:
                log_message('{} already has {} crypto software defined'.format(email, encryption_software))
        elif fingerprint is None:
            log_message('setting {} fingerprint for {}'.format(encryption_software, email))
            set_fingerprint_via_rq(contacts_encryption)
        else:
            log_message('{} already has {} crypto software defined'.format(email, encryption_software))

        log_message("finished post save for contact's crypto")

def post_delete_contacts_crypto(sender, **kwargs):
    ''' Delete the keys for the contact's encryption. '''

    if TESTS_RUNNING:
        log_message('tests running so no post delete processing')
    else:
        contacts_encryption = kwargs['instance']
        email = contacts_encryption.contact.email
        log_message("starting post delete for {}'s crypto".format(email))
        delete_contacts_crypto_via_rq(contacts_encryption)
        log_message("finished post delete for {}'s crypto".format(email))

def post_save_options(sender, **kwargs):
    ''' Process the mail server options record after it's saved.'''

    options = kwargs['instance']
    mail_server_address = options.mail_server_address
    goodcrypto_listen_port = options.goodcrypto_listen_port
    mta_listen_port = options.mta_listen_port

    if mail_server_address is not None and len(mail_server_address.strip()) > 0:
        result_ok = add_to_postfix_mta_queue(mail_server_address, goodcrypto_listen_port, mta_listen_port)

def post_save_internal_settings(sender, **kwargs):
    ''' Process the internal settings record after it's saved.'''

    internal_settings = kwargs['instance']
    domain = internal_settings.domain

    if domain is not None and len(domain.strip()) > 0:
        result_ok = add_to_postfix_mailname_queue(domain)

def add_to_postfix_mta_queue(mail_server_address, goodcrypto_listen_port, mta_listen_port):
    '''
        Add a job to the postfix mta queue.

        >>> add_to_postfix_mta_queue('123.456.789.0', 10025, 10026)
        True

        >>> add_to_postfix_mta_queue('127.0.0.1', 10025, 10026)
        True
    '''

    result_ok = False
    try:
        if mail_server_address is None:
            log_message('missing mta address')
            result_ok = False
        elif mta_listen_port is None:
            log_message('missing mta_listen_port')
            result_ok = False
        elif goodcrypto_listen_port is None:
            log_message('missing goodcrypto_listen_port')
            result_ok = False
        else:
            from goodcrypto.mail.utils.config_postfix import (
                configure_mta, main_needs_configuration, master_needs_configuration)

            main_needs_config, __ = main_needs_configuration(mail_server_address, goodcrypto_listen_port)
            master_needs_config, __ = master_needs_configuration(mta_listen_port)
            if main_needs_config or master_needs_config:

                ONE_MINUTE = 60 #  one minute, in seconds
                DEFAULT_TIMEOUT = 10 * ONE_MINUTE

                if main_needs_config and master_needs_config:
                    log_message('queueing postfix mta job because main and master both need configuration')
                elif main_needs_config:
                    log_message('queueing postfix mta job because main needs configuration: {}:{}'.format(
                        mail_server_address, goodcrypto_listen_port))
                else:
                    log_message('queueing postfix mta job because master needs configuration. {}'.format(
                        mta_listen_port))
                redis_connection = Redis(REDIS_HOST, SPECIAL_REDIS_PORT)
                queue = Queue(name=SPECIAL_RQ, connection=redis_connection, async=True)
                secs_to_wait = DEFAULT_TIMEOUT * (queue.count + 1)
                job = queue.enqueue_call(configure_mta,
                                         args=[
                                           b64encode(mail_server_address),
                                           goodcrypto_listen_port, mta_listen_port],
                                         timeout=secs_to_wait)

                result_ok = get_job_results(queue, job, secs_to_wait, mail_server_address)
                log_message('results from queued job: {}'.format(result_ok))
            else:
                log_message("postfix main.cf and master.cf do not need to be updated")
                result_ok = True

    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result_ok

def add_to_postfix_mailname_queue(domain):
    '''
        Add a job to the postfix mailname queue.

        >>> add_to_postfix_mailname_queue('test.local')
        True
        >>> add_to_postfix_mailname_queue('test.local')
        True
        >>> add_to_postfix_mailname_queue('goodcrypto.local')
        True
    '''

    result_ok = False
    try:
        if domain is None:
            log_message('missing domain')
            result_ok = False
        else:
            from goodcrypto.mail.utils.config_postfix import configure_mailname, mailname_needs_configuration

            needs_configuration, __ = mailname_needs_configuration(domain)
            if needs_configuration:
                ONE_MINUTE = 60 #  one minute, in seconds
                DEFAULT_TIMEOUT = 10 * ONE_MINUTE

                log_message('queueing postfix mailname job for {}'.format(domain))
                redis_connection = Redis(REDIS_HOST, SPECIAL_REDIS_PORT)
                queue = Queue(name=SPECIAL_RQ, connection=redis_connection, async=True)
                secs_to_wait = DEFAULT_TIMEOUT * (queue.count + 1)
                job = queue.enqueue_call(configure_mailname,
                                         args=[b64encode(domain)],
                                         timeout=secs_to_wait)

                result_ok = get_job_results(queue, job, secs_to_wait, 'mailname')
            else:
                log_message('mailname does not need to be updated')
                result_ok = True

    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result_ok

def log_message(message):
    '''
        Log the message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.model_signals.log'))
        True
    '''

    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)


