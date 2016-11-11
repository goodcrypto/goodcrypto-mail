'''
    Keyserver functions enqueued.

    Copyright 2016 GoodCrypto.
    Last modified: 2016-10-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from datetime import date
from time import sleep

from rq.queue import Queue

from goodcrypto.mail import contacts, crypto_software
from goodcrypto.mail.constants import DEFAULT_OUTBOUND_ENCRYPT_POLICY, KEYSERVER
from goodcrypto.mail.keyservers import update_last_access
from goodcrypto.mail.retrieve_key import RetrieveKey
from goodcrypto.mail.utils.notices import notify_new_key_arrived
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import format_fingerprint
from goodcrypto.utils import i18n, parse_address
from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception

_log = None

def get_key(email, crypto_name, keyserver, user_initiated_search, job_id, queue_key):
    '''
        Get a key from the keyserver.

        This function cannot be part of a class because it's
        passed to RQ which only accepts standalone functions, not
        functions in an instance of a class. Also, the function must
        be located in a separate file and imported or defined before
        the class which calls it.

        # Test extreme case
        >>> get_key(None, None, None, None, None, None)
        False
    '''

    GOOD_CONNECTION = i18n('Good connection')

    result_ok = timed_out = False
    output = error = None

    try:
        log_message('starting to get_key for {}'.format(email))

        key_plugin = KeyFactory.get_crypto(crypto_name, crypto_software.get_key_classname(crypto_name))
        if job_id is None or queue_key is None:
            result_ok = False
        else:
            MAX_WAIT = 5 * 60 # seconds

            log_message('checking queue for results of searching for a {} key for {}'.format(
                crypto_name, email))

            queue = Queue.from_queue_key(queue_key, connection=key_plugin.get_queue_connection())
            search_job = queue.fetch_job(job_id)

            # if this function is added to a queue (RQ), then it never starts
            # so we're going to do this the old fashion way
            waited = 0
            while not search_job.is_finished and not search_job.is_failed and waited < MAX_WAIT:
                sleep(1)

            if search_job.is_finished:
                result_ok, timed_out, output, error = key_plugin.get_background_job_results(
                    email, search_job, good_result=key_plugin.get_good_search_result())

                log_message('results from searching for {} key for {}, result ok: {}; timed out: {}'.format(
                    crypto_name, email, result_ok, timed_out))
                if output: log_message(output)
                if error: log_message(error)

            elif search_job.is_failed:
                log_message('searching for {} key for {} job failed'.format(crypto_name, email))
                result_ok = False

            else:
                log_message('searching for {} key for {} job status: {}'.format(
                    crypto_name, email, search_job.get_status()))
                result_ok = False

        if result_ok:
            key_id = key_plugin.parse_keyserver_search(output)
            if key_id is None:
                result_ok = False
                error_message = key_plugin.parse_keyserver_search_error(output, error)
                if error_message is None:
                    # if we didn't find the key, but we connected ok, then
                    # we just want to keep track of the good connection
                    update_last_access(keyserver, crypto_name, date.today(), GOOD_CONNECTION)
                else:
                    update_last_access(keyserver, crypto_name, date.today(), error_message)
            else:
                log_message('starting to retrieve {} key for {} ({}) from {}'.format(crypto_name, email, key_id, keyserver))

                update_last_access(keyserver, crypto_name, date.today(), GOOD_CONNECTION)

                rk= RetrieveKey(email, crypto_name, keyserver, key_id, user_initiated_search)
                if rk:
                    result_ok = rk.start_retrieval()
                    log_message('started retrieval from {}; result for {} ok: {}'.format(keyserver, email, result_ok))
                else:
                    result_ok = False

    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')
        result_ok = False
    finally:
        log_message('finished get_key for {}: {}'.format(email, result_ok))

    return result_ok

def add_contact_records(email_or_fingerprint, crypto_name, user_initiated_search, job_id, queue_key):
    '''
        Add contact and associated crypto records in database.

        This function cannot be part of a class because it's
        passed to RQ which only accepts standalone functions, not
        functions in an instance of a class.  Also, the function must
        be defined before the class which calls it or located in a separate
        file and imported.

        Test extreme case.
        >>> add_contact_records(None, None, None, None, None)
        False
    '''
    result_ok = timed_out = False
    log_message('entered add_contact_records')

    try:
        __, email = parse_address(email_or_fingerprint)
        if email is None:
            key_id = email_or_fingerprint
        else:
            key_id = None

        log_message('adding a {} contact for {} if key retrieved by {} job'.format(
            crypto_name, email_or_fingerprint, job_id))
        key_plugin = KeyFactory.get_crypto(
          crypto_name, crypto_software.get_key_classname(crypto_name))

        if queue_key is None or job_id is None:
            result_ok = False
        else:
            MAX_WAIT = 10 * 60 # seconds

            queue = Queue.from_queue_key(queue_key, connection=key_plugin.get_queue_connection())
            job = queue.fetch_job(job_id)

            # if this function is added to a queue (RQ), then it never starts
            # so we're going to do this the old fashion way
            waited = 0
            while not job.is_finished and not job.is_failed and waited < MAX_WAIT:
                sleep(1)

            if job.is_failed:
                log_message('retrieving {} key for {} job failed'.format(crypto_name, email_or_fingerprint))
                result_ok = False
            else:
                # even if the job timed out, see if the key was retrieved
                result_ok, timed_out, output, error = key_plugin.get_background_job_results(
                   email_or_fingerprint, job)
                log_message("results from retrieving {} key for {}, result ok: {}; timed out: {}".format(
                    crypto_name, email_or_fingerprint, result_ok, timed_out))
                if result_ok:
                    imported_user_ids = key_plugin.parse_keyserver_ids_retrieved(error)
                    log_message("imported user ids: {}".format(imported_user_ids))
                    if len(imported_user_ids) < 1 and error:
                        log_message('error: {}'.format(error))
                if output: log_message('output: {}'.format(output))

        if result_ok:
            id_fingerprint_pairs = []
            for user_id, imported_key_id in imported_user_ids:
                contact = contacts.add(user_id, crypto_name, source=KEYSERVER)
                result_ok = contact is not None
                log_message("added contact's crypto for {}: {}".format(user_id, result_ok))

                if result_ok:
                    # change the outgoing policy if needed
                    if contact.outbound_encrypt_policy != DEFAULT_OUTBOUND_ENCRYPT_POLICY:
                        contact.outbound_encrypt_policy = DEFAULT_OUTBOUND_ENCRYPT_POLICY
                        contact.save()

                    # activate the contact's crypto "after save signal" to update the fingerprint
                    contacts_crypto = contacts.get_contacts_crypto(user_id, crypto_name)
                    if contacts_crypto is not None:
                        if contacts_crypto.fingerprint is None:
                            contacts_crypto.source = KEYSERVER
                            contacts_crypto.save()
                            if key_id is None:
                                fingerprint = imported_key_id
                            else:
                                fingerprint = key_id
                        else:
                            fingerprint = contacts_crypto.fingerprint
                    elif key_id is None:
                        fingerprint = imported_key_id
                    else:
                        fingerprint = key_id

                    id_fingerprint_pairs.append((contact.email, format_fingerprint(fingerprint)))
                else:
                    log_message('unable to add {} contact record for {}'.format(crypto_name, user_id))

            if result_ok and len(id_fingerprint_pairs) > 0:
                log_message('notifying {} about new keys: {}'.format(user_initiated_search, id_fingerprint_pairs))
                notify_new_key_arrived(user_initiated_search, id_fingerprint_pairs)

        elif timed_out:
            log_message('timed out retrieving a {} key for {}.'.format(
                crypto_name, email_or_fingerprint))
        else:
            log_message('unable to retrieve {} key for {}.'.format(
                crypto_name, email_or_fingerprint))

    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')
        result_ok = False

    log_message('ended add_contact_records: {}'.format(result_ok))

    return result_ok

def log_message(message):
    '''
        Log a message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test message')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.keyserver_utils.log'))
        True
    '''

    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

