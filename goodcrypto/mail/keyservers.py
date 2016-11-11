'''
    Manage keys from keyservers.

    Copyright 2016 GoodCrypto.
    Last modified: 2016-10-29

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
from datetime import date
from time import sleep

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()


from goodcrypto.mail.constants import DEFAULT_KEYSERVER_STATUS, UNKNOWN_EMAIL
from goodcrypto.mail import contacts, crypto_software
from goodcrypto.mail.models import Keyserver
from goodcrypto.mail.retrieve_key import RetrieveKey
from goodcrypto.mail.search_keyserver import SearchKeyserver
from goodcrypto.mail.utils import notices
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import format_fingerprint
from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception

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
            log_message('EXCEPTION - see syr.exception.log for details')

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
        log_message('EXCEPTION - see syr.exception.log for details')

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
        log_message('EXCEPTION - see syr.exception.log for details')

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
        log_message('EXCEPTION - see syr.exception.log for details')

    return active_keyservers

def search_keyservers(email_encoded, user_initiated_search_encoded, interactive=False):
    '''
        Search all active keyservers for a key for the email address.
        Don't report the error unless the search was started interactively.

        >>> search_keyservers(None, None)
        False
        >>> search_keyservers(None, None, interactive=True)
        False
    '''

    found_key = False
    try:
        email = pickle.loads(email_encoded)
        user_initiated_search = pickle.loads(user_initiated_search_encoded)
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
                      email, encryption_name, keyserver, user_initiated_search)
                    if search_keyserver:
                        result_ok = search_keyserver.start_search()
                        log_message('started search on {}; result for {} ok: {}'.format(keyserver, email, result_ok))

                    current_keyserver += 1
                    if result_ok and (
                       current_keyserver < len(keyservers) or current_encryption < len(encryption_names)):

                        if is_key_found(email, encryption_name, keyserver, key_plugin):
                            found_key = True
                            break
                        else:
                            remaining_servers = len(keyservers) - current_keyserver
                            log_message('key not found yet; {} {} keyservers remaining'.format(
                                remaining_servers, encryption_name))
    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return found_key

def is_key_found(email, encryption_name, keyserver, key_plugin):
    '''
        Check to see if a search on a keyserver found the key.

        >>> is_key_found(None, None, None, None)
        False
    '''
    MAX_WAIT = 10

    found_key = False
    try:
        # we'll wait for the search results, but also so we don't drain the resources of
        # the goodcrypto private server by starting too many keyserver searches at once
        log_message('waiting for search results from {}'.format(keyserver))

        wait = 0
        while not found_key and wait < MAX_WAIT:
            sleep(30)
            wait += 1

            fingerprint, __, __ = contacts.get_fingerprint(email, encryption_name)
            found_key = fingerprint is not None

        if found_key:
            try:
                found_key, __, __ = contacts.is_key_ok(email, encryption_name)
            except CryptoException:
                found_key = False

        if found_key:
            log_message('search found key for {} on {} keyserver'.format(email, keyserver))
        else:
            log_message('no key found for {} on {} keyserver during search'.format(email, keyserver))
    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')
        found_key = False

    return found_key

def get_key_from_keyservers(fingerprint_encoded, encryption_name_encoded, user_initiated_search_encoded):
    '''
        Check each active keyserver until we find a key matching the fingerprint.

        >>> get_key_from_keyservers(None, None, None)
        False
    '''

    found_key = False
    try:
        fingerprint = pickle.loads(fingerprint_encoded)
        encryption_name = pickle.loads(encryption_name_encoded)
        user_initiated_search = pickle.loads(user_initiated_search_encoded)

        current_keyserver = 0
        keyservers = get_active_keyservers(encryption_name)
        if len(keyservers) > 0:
            log_message('starting to retrieve {} key from keyservers for {}'.format(encryption_name, fingerprint))
        else:
            log_message('no active {} keyservers so unable to search for {}'.format(encryption_name, fingerprint))

        for keyserver in keyservers:
            log_message('getting key for {} from {}'.format(fingerprint, keyserver))
            retrieve_key_class = RetrieveKey(UNKNOWN_EMAIL, encryption_name, keyserver, fingerprint, user_initiated_search)
            if retrieve_key_class:
                result_ok = retrieve_key_class.start_retrieval()
                log_message('started retrieval from {}; result for {} ok: {}'.format(keyserver, fingerprint, result_ok))
            else:
                result_ok = False

            if result_ok and current_keyserver < len(keyservers):

                key_plugin = KeyFactory.get_crypto(
                   encryption_name, crypto_software.get_key_classname(encryption_name))

                current_keyserver += 1
                if is_key_retrieved(fingerprint, encryption_name, keyserver, key_plugin):
                    found_key = True
                    break
                else:
                    remaining_servers = len(keyservers) - current_keyserver
                    log_message('key not found yet; {} {} keyservers remaining to search'.format(
                        remaining_servers, encryption_name))

        if not found_key:
            notices.report_no_matching_fingerprint_on_keyserver(
               user_initiated_search, fingerprint, encryption_name)

    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return found_key

def is_key_retrieved(fingerprint, encryption_name, keyserver, key_plugin):
    '''
        Check to see if a retrieval on a keyserver got the key.

        >>> is_key_retrieved(None, None, None, None)
        False
    '''

    found_key = False
    try:
        # we'll wait for the search results, but also so we don't drain the resources of
        # the goodcrypto private server but starting too many keyserver searches at once
        log_message('waiting to see if {} had key for {}'.format(keyserver, fingerprint))

        # sleep to give the search time to process
        sleep(5 * 60)

        # don't keep looking if we got a key from the keyserver
        user_ids = key_plugin.get_user_ids_from_fingerprint(fingerprint)
        if len(user_ids) > 0:
            found_key = True
            log_message('retrieval found key for {} on {} keyserver'.format(fingerprint, keyserver))
        else:
            log_message('no key found for {} on {} keyserver'.format(fingerprint, keyserver))
    except Exception as exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')
        found_key = False

    return found_key

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

