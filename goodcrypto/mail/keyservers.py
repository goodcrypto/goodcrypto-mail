'''
    Manage keys from keyservers.

    Copyright 2016 GoodCrypto.
    Last modified: 2016-02-20

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.

    Search and retrieving a key from a keyserver requires:
      1. finding if a keyserver has a key for an email
         address and getting the key id if it does
      2. retrieving the key using the key id (you cannot do so with the email address)
      3. finally creating associated database keys
    This multi-step process requires that each step be run from a queue
    so the overall system doesn't bog down waiting on the results. By using the
    "depends-on" capability, you can effectively daisy chain the steps together.
'''
import os, pickle
from base64 import b64decode, b64encode
from datetime import date
from django.db import IntegrityError
from rq import Queue
from time import sleep

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()


from goodcrypto.mail.constants import DEFAULT_KEYSERVER_STATUS, DEFAULT_OUTBOUND_ENCRYPT_POLICY, KEYSERVER
from goodcrypto.mail import contacts, crypto_software
from goodcrypto.mail.models import Keyserver
from goodcrypto.mail.utils import email_in_domain, get_admin_email, notices
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import format_fingerprint
from goodcrypto.utils import i18n, get_email, parse_address
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile

UNKNOWN_EMAIL = 'Unknown'

_log = None

def get(name, encryption_name):
    '''
        Get the key server.

        Test extreme case
        >>> server = get(None, None)
        >>> server == None
        True
    '''

    if name is None:
        server = None
    else:
        try:
            server = Keyserver.objects.get(name=name, encryption_software__name=encryption_name)
        except Keyserver.DoesNotExist:
            server = None
            log_message('"{}" keyserver does not exist'.format(name))
        except Exception:
            server = None
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return server

def add(name, encryption_name):
    '''
        Add a key server.

        Test extreme case
        >>> server = add(None, None)
        >>> server == None
        True
    '''

    if name is None or encryption_name is None:
        server = None
    else:
        server = get(name, encryption_name)
        if server is None:
            encryption_software = crypto_software.get(encryption_name)
            server = Keyserver.objects.create(name=name, encryption_software=encryption_software,
              last_status=DEFAULT_KEYSERVER_STATUS)
            log_message('added "{}" keyserver'.format(name))

    return server

def update_last_access(name, encryption_name, access_date, status):
    '''
        Update the last time the keyserver accessed.

        Test extreme case
        >>> update_last_access(None, None, None, None)
        False
    '''

    result_ok = True
    if status is None:
        status = DEFAULT_KEYSERVER_STATUS

    try:
        server = get(name, encryption_name)
        if server is None:
            encryption_software = crypto_software.get(encryption_name)
            server = Keyserver(
              name=name, encryption_software=encryption_software,
              active=True, last_date=access_date, last_status=status)
            server.save()
            log_message("added keyserver: {}".format(name))
        else:
            server.last_date = access_date
            server.last_status = status
            server.save()
            log_message("updated {} keyserver: {}".format(name, server.last_status))
    except Exception:
        result_ok = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result_ok

def delete(name, encryption_name):
    '''
        Delete the keyserver with a matching name.

        Test extreme case
        >>> delete(None, None)
        True
    '''

    result_ok = True
    try:
        server = get(name, encryption_name)
        if server is None:
            log_message('{} does not exist so need to delete'.format(name))
        else:
            server.delete()
            log_message("deleted {}".format(name))
    except Exception:
        result_ok = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result_ok

def get_active_keyservers(encryption_name):
    '''
        Get the list of active keyserver names.

        Test extreme case
        >>> len(get_active_keyservers(None)) == 0
        True
    '''

    active_keyservers = []
    try:
        servers = Keyserver.objects.filter(active=True, encryption_software__name=encryption_name)
        for server in servers:
            active_keyservers.append(server.name)
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return active_keyservers

def search_keyservers_for_key(email_encoded, first_contacted_by_encoded, interactive=False):
    '''
        Search all active keyservers for a key for the email address.
        Don't report the error unless the search was started interactively.

        >>> search_keyservers_for_key(None, None)
        False
        >>> search_keyservers_for_key(None, None, interactive=True)
        False
    '''

    found_key = False
    try:
        email = pickle.loads(b64decode(email_encoded))
        first_contacted_by = pickle.loads(b64decode(first_contacted_by_encoded))
        log_message('starting to search keyservers for {}'.format(email))

        encryption_names = crypto_software.get_active_names()
        if len(encryption_names) <= 0:
            log_message('no active encryption so cannot search keyservers')
        else:
            current_encryption = 0
            for encryption_name in encryption_names:
                current_encryption += 1
                key_plugin = KeyFactory.get_crypto(
                   encryption_name, crypto_software.get_key_classname(encryption_name))
                log_message('search {} keyservers for {} key'.format(encryption_name, email))

                current_keyserver = 0
                keyservers = sorted(get_active_keyservers(encryption_name))
                for keyserver in keyservers:
                    log_message('searching {} for {}'.format(keyserver, email))
                    search_keyserver = SearchKeyserver(
                      email, encryption_name, keyserver, first_contacted_by)
                    if search_keyserver:
                        result_ok = search_keyserver.start_search()
                        log_message('started search on {}; result for {} ok: {}'.format(keyserver, email, result_ok))

                    current_keyserver += 1
                    if result_ok and (
                       current_keyserver < len(keyservers) or current_encryption < len(encryption_names)):

                        remaining_servers = len(keyservers) - current_keyserver
                        if search_found_key(email, encryption_name, keyserver, key_plugin, remaining_servers):
                            found_key = True
                            break

                if interactive and not found_key:
                    notices.report_no_key_on_keyserver(first_contacted, email, encryption_name)
    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return found_key

def search_found_key(email, encryption_name, keyserver, key_plugin, remaining_servers):
    '''
        Check to see if a search on a keyserver found the key.

        >>> search_found_key(None, None, None, None, None)
        False
    '''

    found_key = False
    try:
        # we'll wait for the search results, but also so we don't drain the resources of
        # the goodcrypto private server but starting too many keyserver searches at once
        log_message('waiting to search next keyserver; {} {} keyservers remaining'.format(
            remaining_servers, encryption_name))

        # sleep to give the search time to process
        sleep(5 * 60)

        # don't keep looking if we got a key from the keyserver
        fingerprint, __ = key_plugin.get_fingerprint(email)
        if fingerprint is None:
            log_message('no key found for {} on {} keyserver'.format(email, keyserver))
        else:
            found_key = True
            log_message('found key for {} on {} keyserver'.format(email, keyserver))
    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        found_key = False

    return found_key

class SearchKeyserver(object):
    '''
        Search for a key from keyserver.
    '''

    def __init__(self, email, encryption_name, keyserver, first_contacted_by):
        '''
            >>> # In honor of Werner Koch, developer of gpg.
            >>> email = 'wk@gnupg.org'
            >>> crypto_name = 'GPG'
            >>> srk_class = SearchKeyserver(email, crypto_name, 'pgp.mit.edu', 'julian@goodcrypto.local')
            >>> srk_class != None
            True
            >>> srk_class = SearchKeyserver(None, crypto_name, 'pgp.mit.edu', 'julian@goodcrypto.local')
            >>> srk_class != None
            True
            >>> srk_class = SearchKeyserver(email, None, 'pgp.mit.edu', 'julian@goodcrypto.local')
            >>> srk_class != None
            True
            >>> srk_class = SearchKeyserver(email, crypto_name, None, 'julian@goodcrypto.local')
            >>> srk_class != None
            True
            >>> srk_class = SearchKeyserver(None, None, None, None)
            >>> srk_class != None
            True
        '''

        self.email = email
        self.encryption_name = encryption_name
        self.keyserver = keyserver
        self.first_contacted_by = first_contacted_by
        self.key_plugin = None

    def start_search(self):
        '''
            Queue searching the keyserver. When the job finishes, the key
            will be retrieved from another queued job which is dependent
            on the search's job.

            Test extreme case.
            >>> srk_class = SearchKeyserver(None, None, None, None)
            >>> srk_class.start_search()
            False
        '''

        try:
            if self._is_ready_for_search():
                result_ok = True

                # start the search, but don't wait for the results
                self.key_plugin.search_for_key(self.email, self.keyserver)
                search_job = self.key_plugin.get_job()
                queue = self.key_plugin.get_queue()

                # if the search job or queue are done, then retrieve the key
                if queue is None or search_job is None:
                    q = j = None
                    if queue is not None:
                        q = b64encode(queue)
                    if search_job is not None:
                        j = b64encode(search_job)
                    retrieve_key(
                      b64encode(pickle.dumps(self.email)), b64encode(pickle.dumps(self.encryption_name)),
                      b64encode(pickle.dumps(self.keyserver)),
                      b64encode(pickle.dumps(self.first_contacted_by)), j, q)
                else:
                    # otherwise, set up another job in the queue to retrieve the
                    # key as soon as the search for the key id is finished
                    args = [b64encode(pickle.dumps(self.email)),
                            b64encode(pickle.dumps(self.encryption_name)),
                            b64encode(pickle.dumps(self.keyserver)),
                            b64encode(pickle.dumps(self.first_contacted_by)),
                            b64encode(search_job.get_id()), b64encode(queue.key)]
                    retrieve_job = queue.enqueue_call(
                        retrieve_key, args=args, depends_on=search_job)
                    if retrieve_job is None:
                        log_message('unable to queue job to retrieve {} key for {} (job: {})'.format(
                           self.encryption_name, self.email))
                        result_ok = False
                    else:
                        log_message('queued retrieving {} key for {} (after job: {})'.format(
                            self.encryption_name, self.email, search_job.get_id()))
            else:
                result_ok = False

        except Exception as exception:
            result_ok = False
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        log_message('finished starting search on {} for {} ok: {}'.format(
            self.keyserver, self.email, result_ok))

        return result_ok

    def _is_ready_for_search(self):
        '''
            Verify that we're ready to search for this key.

            Test extreme case.
            >>> srk_class = SearchKeyserver(None, None, None, None)
            >>> srk_class._is_ready_for_search()
            False
        '''

        ready = False
        try:
            ready = (self.email is not None and
                     self.encryption_name is not None and
                     self.keyserver is not None and
                     self.first_contacted_by is not None and
                     not email_in_domain(self.email))

            if ready:
                self.key_plugin = KeyFactory.get_crypto(
                   self.encryption_name, crypto_software.get_key_classname(self.encryption_name))
                ready = self.key_plugin is not None

            if ready:
                # make sure we don't already have crypto defined for this user
                contacts_crypto = contacts.get_contacts_crypto(self.email, self.encryption_name)
                if contacts_crypto is None or contacts_crypto.fingerprint is None:
                    fingerprint, expiration = self.key_plugin.get_fingerprint(self.email)
                    if fingerprint is not None:
                        ready = False
                        log_message('{} public key exists for {}: {}'.format(
                            self.encryption_name, self.email, fingerprint))
                else:
                    ready = False
                    log_message('crypto for {} already defined'.format(self.email))

        except Exception as exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            ready = False

        return ready

def get_key_from_keyservers(fingerprint_encoded, encryption_name_encoded, first_contacted_by_encoded):
    '''
        Check each active keyserver until we find a key matching the fingerprint.

        >>> get_key_from_keyservers(None, None, None)
        False
    '''

    found_key = False
    try:
        fingerprint = pickle.loads(b64decode(fingerprint_encoded))
        encryption_name = pickle.loads(b64decode(encryption_name_encoded))
        first_contacted_by = pickle.loads(b64decode(first_contacted_by_encoded))
        log_message('starting to retrieve {} key from keyservers for {}'.format(encryption_name, fingerprint))

        current_keyserver = 0
        keyservers = get_active_keyservers(encryption_name)
        for keyserver in keyservers:
            log_message('getting key for {} from {}'.format(fingerprint, keyserver))
            retrieve_key_class = RetrieveKey(UNKNOWN_EMAIL, encryption_name, keyserver, fingerprint, first_contacted_by)
            if retrieve_key_class:
                result_ok = retrieve_key_class.start_retrieval()
                log_message('started retrieval from {}; result for {} ok: {}'.format(keyserver, fingerprint, result_ok))
            else:
                result_ok = False

            if result_ok and current_keyserver < len(keyservers):

                key_plugin = KeyFactory.get_crypto(
                   encryption_name, crypto_software.get_key_classname(encryption_name))

                current_keyserver += 1
                remaining_servers = len(keyservers) - current_keyserver
                if key_retrieved(fingerprint, encryption_name, keyserver, key_plugin, remaining_servers):
                    found_key = True
                    break

        if not found_key:
            notices.report_no_matching_fingerprint_on_keyserver(
               first_contacted_by, fingerprint, encryption_name)

    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return found_key

def key_retrieved(fingerprint, encryption_name, keyserver, key_plugin, remaining_servers):
    '''
        Check to see if a retrieval on a keyserver got the key.

        >>> key_retrieved(None, None, None, None, None)
        False
    '''

    found_key = False
    try:
        # we'll wait for the search results, but also so we don't drain the resources of
        # the goodcrypto private server but starting too many keyserver searches at once
        log_message('waiting to try next keyserver; {} {} keyservers remaining'.format(
            remaining_servers, encryption_name))

        # sleep to give the search time to process
        sleep(5 * 60)

        # don't keep looking if we got a key from the keyserver
        user_ids = key_plugin.get_user_ids_from_fingerprint(fingerprint)
        if len(user_ids) > 0:
            found_key = True
            log_message('found key for {} on {} keyserver'.format(fingerprint, keyserver))
        else:
            log_message('no key found for {} on {} keyserver'.format(fingerprint, keyserver))
    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        found_key = False

    return found_key

def retrieve_key(email_encoded, crypto_name_encoded, keyserver_encoded, first_contacted_by_encoded,
                 job_id_encoded=None, queue_key_encoded=None):
    '''
        Retrieve a key from the keyserver.

        This function is called from SearchKey class

        # Test extreme case
        >>> retrieve_key(None, None, None, None)
        False
        >>> retrieve_key(None, None, None, None, job_id_encoded=None, queue_key_encoded=None)
        False
    '''

    GOOD_CONNECTION = i18n('Good connection')

    result_ok = timed_out = False
    output = error = email = None

    try:
        email = pickle.loads(b64decode(email_encoded))
        encryption_name = pickle.loads(b64decode(crypto_name_encoded))
        keyserver = pickle.loads(b64decode(keyserver_encoded))
        first_contacted_by = pickle.loads(b64decode(first_contacted_by_encoded))
        key_plugin = KeyFactory.get_crypto(encryption_name, crypto_software.get_key_classname(encryption_name))

        if job_id_encoded is None:
            job_id = None
        else:
            job_id = b64decode(job_id_encoded)
        if queue_key_encoded is None:
            queue_key = None
        else:
            queue_key = b64decode(queue_key_encoded)

        if job_id is None or queue_key is None:
            result_ok = True
        else:
            log_message('checking queue for results of searching for a {} key for {}'.format(
                encryption_name, email))

            queue = Queue.from_queue_key(queue_key)
            search_job = queue.fetch_job(job_id)

            if search_job.is_finished:
                result_ok, timed_out, output, error = key_plugin.get_background_job_results(
                    email, search_job, good_result=key_plugin.get_good_search_result())

                log_message('results from searching for {} key for {}, result ok: {}; timed out: {}'.format(
                    encryption_name, email, result_ok, timed_out))
                if output: log_message(output)
                if error: log_message(error)

            elif search_job.is_failed:
                log_message('searching for {} key for {} job failed'.format(encryption_name, email))
                result_ok = False

        if result_ok:
            key_id = key_plugin.parse_keyserver_search(output)
            if key_id is None:
                result_ok = False
                error_message = key_plugin.parse_keyserver_search_error(output, error)
                if error_message is None:
                    # if we didn't find the key, but we connected ok, then
                    # we just want to keep track of the good connection
                    update_last_access(keyserver, encryption_name, date.today(), GOOD_CONNECTION)
                else:
                    update_last_access(keyserver, encryption_name, date.today(), error_message)
            else:
                log_message('starting to retrieve {} key for {} ({}) from {}'.format(encryption_name, email, key_id, keyserver))

                update_last_access(keyserver, encryption_name, date.today(), GOOD_CONNECTION)

                retrieve_key_class = RetrieveKey(email, encryption_name, keyserver, key_id, first_contacted_by)
                if retrieve_key_class:
                    result_ok = retrieve_key_class.start_retrieval()
                    log_message('started retrieval from {}; result for {} ok: {}'.format(keyserver, email, result_ok))
                else:
                    result_ok = False

    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        result_ok = False
    finally:
        log_message('finished retrieve_key for {}: {}'.format(email, result_ok))

    return result_ok

class RetrieveKey(object):
    '''
        Retrieve a key from a keyserver.
    '''

    def __init__(self, email, encryption_name, keyserver, key_id, first_contacted_by):
        '''
            >>> # In honor of Werner Koch, developer of gpg.
            >>> email = 'wk@gnupg.org'
            >>> crypto_name = 'GPG'
            >>> srk_class = RetrieveKey(email, crypto_name, 'pgp.mit.edu', 'F2AD85AC1E42B367', 'chelsea@goodcrypto.local')
            >>> srk_class = RetrieveKey(None, crypto_name, 'pgp.mit.edu', 'F2AD85AC1E42B367', 'chelsea@goodcrypto.local')
            >>> srk_class = RetrieveKey(email, None, 'pgp.mit.edu', 'F2AD85AC1E42B367', 'chelsea@goodcrypto.local')
            >>> srk_class = RetrieveKey(email, crypto_name, None, 'F2AD85AC1E42B367', 'chelsea@goodcrypto.local')
            >>> srk_class = RetrieveKey(None, None, None, None, None)
        '''

        self.email = email
        self.encryption_name = encryption_name
        self.keyserver = keyserver
        self.key_id = key_id
        self.first_contacted_by = first_contacted_by

        self.key_plugin = None

    def start_retrieval(self):
        '''
            Queue retrieving key from the keyserver. When the job finishes, associated
            database entries will be made from another queued job which is dependent on
            the key retrieval's job.

            Test extreme case.
            >>> rk_class = RetrieveKey(None, None, None, None, None)
            >>> rk_class.start_retrieval()
            False
        '''

        try:
            result_ok = (self.email is not None and
                         self.encryption_name is not None and
                         self.keyserver is not None and
                         self.key_id is not None and
                         self.first_contacted_by is not None and
                         not email_in_domain(self.email))

            if result_ok:
                self.key_plugin = KeyFactory.get_crypto(
                   self.encryption_name, crypto_software.get_key_classname(self.encryption_name))
                result_ok = self.key_plugin is not None

            if result_ok:
                self.key_plugin.retrieve_key(self.key_id, self.keyserver)
                retrieve_job = self.key_plugin.get_job()
                queue = self.key_plugin.get_queue()

                if self.email == UNKNOWN_EMAIL:
                    email_or_fingerprint = self.key_id
                else:
                    email_or_fingerprint = self.email

                if queue is None or retrieve_job is None:
                    q = j = None
                    if queue is not None:
                        q = b64encode(queue)
                    if retrieve_job is not None:
                        j = b64encode(retrieve_job)
                    add_contact_records(b64encode(pickle.dumps(email_or_fingerprint)),
                                        b64encode(pickle.dumps(self.encryption_name)),
                                        b64encode(pickle.dumps(self.first_contacted_by)), j, q)
                else:
                    # otherwise, set up another job in the queue to retrieve the
                    # key as soon as the search for the key id is finished
                    args = [b64encode(pickle.dumps(email_or_fingerprint)),
                           b64encode(pickle.dumps(self.encryption_name)),
                            b64encode(pickle.dumps(self.first_contacted_by)),
                            b64encode(retrieve_job.get_id()), b64encode(queue.key)]
                    add_job = queue.enqueue_call(
                        add_contact_records, args=args, depends_on=retrieve_job)
                    if add_job is None:
                        log_message('unable to queue job to retrieve {} key for {} (job: {})'.format(
                           self.encryption_name, self.email))
                        result_ok = False
                    else:
                        log_message('queued retrieving {} key for {} (after job: {})'.format(
                            self.encryption_name, self.email, retrieve_job.get_id()))

        except Exception as exception:
            result_ok = False
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        log_message('finished retreive for {} ok: {}'.format(self.email, result_ok))

        return result_ok

def add_contact_records(
     email_or_fingerprint_encoded, encryption_name_encoded, first_contacted_by_encoded, job_id_encoded, queue_key_encoded):
    '''
        Add contact and associated crypto records in database.

        Test extreme case.
        >>> add_contact_records(None, None, None, None, None)
        False
    '''
    result_ok = timed_out = False

    try:
        email_or_fingerprint = pickle.loads(b64decode(email_or_fingerprint_encoded))
        encryption_name = pickle.loads(b64decode(encryption_name_encoded))
        first_contacted_by = pickle.loads(b64decode(first_contacted_by_encoded))
        if job_id_encoded is None:
            job_id = None
        else:
            job_id = b64decode(job_id_encoded)
        if queue_key_encoded is None:
            queue_key = None
        else:
            queue_key = b64decode(queue_key_encoded)

        if job_id is None or queue_key is None:
            result_ok = True
        else:
            __, email = parse_address(email_or_fingerprint)
            if email is None:
                key_id = email_or_fingerprint
            else:
                key_id = None

            log_message('checking queue for results of retrieving a {} key for {}'.format(
                encryption_name, email_or_fingerprint))
            queue = Queue.from_queue_key(queue_key)
            job = queue.fetch_job(job_id)
            if job.is_finished:
                plugin = KeyFactory.get_crypto(
                   encryption_name, crypto_software.get_key_classname(encryption_name))
                result_ok, timed_out, output, error = plugin.get_background_job_results(email_or_fingerprint, job)
                log_message("results from retrieving {} key for {}, result ok: {}; timed out: {}".format(
                    encryption_name, email_or_fingerprint, result_ok, timed_out))
                imported_user_ids = plugin.parse_keyserver_retrieve(error)
                if output: log_message('output: {}'.format(output))
            elif job.is_failed:
                log_message('retrieving {} key for {} job failed'.format(encryption_name, email_or_fingerprint))
                result_ok = False

        if result_ok:
            id_fingerprint_pairs = []
            for user_id, imported_key_id in imported_user_ids:
                contact = contacts.add(user_id, encryption_name, source=KEYSERVER)
                result_ok = contact is not None
                log_message("added contact's crypto for {}: {}".format(user_id, result_ok))

                if result_ok:
                    # change the outgoing policy if needed
                    if contact.outbound_encrypt_policy != DEFAULT_OUTBOUND_ENCRYPT_POLICY:
                        contact.outbound_encrypt_policy = DEFAULT_OUTBOUND_ENCRYPT_POLICY
                        contact.save()

                    # activate the contact's crypto "after save signal" to update the fingerprint
                    contacts_crypto = contacts.get_contacts_crypto(user_id, encryption_name)
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
                    log_message('unable to add {} contact record for {}'.format(encryption_name, user_id))

            if result_ok:
                log_message('notifying {} about new keys: {}'.format(first_contacted_by, id_fingerprint_pairs))
                notices.notify_new_key_arrived(first_contacted_by, id_fingerprint_pairs)

        elif timed_out:
            log_message('timed out retrieving a {} key for {}.'.format(
                encryption_name, email))
        else:
            log_message('unable to retrieve {} key for {}.'.format(
                encryption_name, email))

    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        result_ok = False

    return result_ok

def log_message(message):
    '''
        Log a message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.keyservers.log'))
        True
    '''

    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

