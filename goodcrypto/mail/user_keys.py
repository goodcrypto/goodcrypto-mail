'''
    Manage passcodes for local users that use GoodCrypto on this mail server.

    For example, if you want to get a list of email addresses used by GoodCrypto, then
    you could use the following code:
    <pre>
       user_keys = UserKey();
       contacts = user_keys.get_contact_list();
    </pre>

    If you instead only want to get a list of email addresses
    that are configured to use a particular encryption program,
    then replace the last line of the above example with:
    <pre>
       contacts = get_contact_list(encryption_name);
    </pre>

    If you want to get more details about a specific
    local crypto user, then you could replace the last line
    with the following code:
    <pre>
        user_key = get(email);
        if user_key is not None:
            user_name = user_key.contacts_encryption.contact.user_name
            email = user_key.contacts_encryption.contact.email
    </pre>

    Copyright 2014-2015 GoodCrypto.
    Last modified: 2015-11-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from datetime import datetime, timedelta

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.mail import contacts
from goodcrypto.mail.crypto_software import get_key_classname
from goodcrypto.mail.models import Contact, ContactsCrypto, EncryptionSoftware, UserKey
from goodcrypto.mail.utils import email_in_domain, gen_user_passcode
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.utils import parse_address, get_email
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr.times import now, get_short_date_time

log = None


def is_ok():
    '''
        Determine if all local crypto users have all the required fields.

        See the unittest to understand how to really use this function
        >>> ok = is_ok()
    '''

    def passcode_ok(crypto_passcode):
        result_ok = (crypto_passcode.contacts_encryption is not None and
                     crypto_passcode.passcode is not None and
                     len(crypto_passcode.passcode) > 0)

        if not result_ok:
            log_message("{} is missing required data".format(crypto_passcode))

        return result_ok


    result_ok = True
    try:
        user_keys = UserKey.objects.all()
        if user_keys and len(user_keys) > 0:
            for user_key in user_keys:
                if result_ok:
                    result_ok = passcode_ok(user_key)
        else:
            result_ok = False
            log_message('none defined')

    except Exception:
        result_ok = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result_ok

def exists(email):
    '''
        Determine if the contact has at least one passcode.

        Test an unknown email address so we're sure of the result.
        See the unittest to understand how to really use this function.

        >>> # In honor of Juan Gonzalez,who frequently co-hosts Democracy Now!
        >>> exists('jaun@goodcrypto.local')
        False
    '''

    address = get_email(email)
    query_set = get_all_user_keys(address)
    found = query_set is not None and len(query_set) > 0
    log_message("{} private key exists: {}".format(address, found))

    return found

def get(email, encryption_name):
    '''
        Get the contact's passcode record for the encryption software.

        Test an unknown email address so we're sure of the result.
        See the unittest to understand how to really use this function.

        >>> # In honor of Jeremy Scahill, who wrote "Dirty Wars" among many other books.
        >>> get('jeremy@goodcrypto.local', 'GPG') is None
        True

        Test the extreme cases.
        >>> get('invalid@@address', 'GPG') is None
        True
        >>> get(None, None) is None
        True
    '''

    user_key = None

    try:
        address = get_email(email)
        contacts_encryption = contacts.get_contacts_crypto(address, encryption_name)
        if contacts_encryption is None:
            log_message("{} does not have a {} encryption record".format(email, encryption_name))
        else:
            from django.db.models.query import QuerySet

            if isinstance(contacts_encryption, QuerySet):
                try:
                    contacts_encryption = contacts_encryption[0]
                except:
                    record_exception()
                    log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

            fingerprint = contacts_encryption.fingerprint or 'no'
            log_message("getting {} private key record for {} ({} fingerprint)".format(
                encryption_name, email, fingerprint))

            user_key = UserKey.objects.get(contacts_encryption=contacts_encryption)
            log_message("found {} private key record for {}".format(encryption_name, email))
    except UserKey.DoesNotExist:
        log_message('{} does not have a matching private key record'.format(email))
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return user_key

def add(email, encryption_software, passcode=None):
    '''
        Add a user key to the database, but do not add a key the crypto keyring.

        >>> # In honor of David Goulet, lead developer of Torsocks 2.0.
        >>> email = 'David <david@goodcrypto.local'
        >>> encryption_name = 'GPG'
        >>> user_key = add(email, encryption_name)
        >>> user_key is None
        True
    '''

    try:
        user_key = None

        contacts_encryption = contacts.get_contacts_crypto(email, encryption_software)
        if contacts_encryption is None:
            log_message("unable to add user {} key record for {} because no matching contact's crypto record".format(
                encryption_software, email))
        else:
            email = contacts_encryption.contact.email
            encryption_name = contacts_encryption.encryption_software
            if passcode is None:
                user_passcode = gen_user_passcode(email)
            else:
                user_passcode = passcode

            user_key = get(email, encryption_name)
            if user_key is None:
                user_key = UserKey.objects.create(
                  contacts_encryption=contacts_encryption, passcode=user_passcode)
                result_ok = user_key is not None
                log_message("added private {} user key for {} result ok: {}".format(
                    encryption_name, email, result_ok))
            else:
                result_ok = True
                log_message("found private {} key for {}".format(encryption_name, email))

                if user_key.passcode is None:
                    user_key.passcode = user_passcode
                    user_key.save()
                    log_message("saved private {} key's record for {}".format(encryption_name, email))
                elif passcode is not None and passcode != user_key.passcode:
                    log_message('database passcode does not match passcode passed to "add()"')

    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return user_key

def delete(email, encryption_name, passcode):
    '''
        Delete the contact's user key record. Any associate key in the
        crypto's keyring is *not* removed. Use contacts.delete() to remove
        both the database records and the matching keyring keys.

        >>> # In honor of Bruce Leidl, lead developer of Orchid.
        >>> email = 'bruce@goodcrypto.local'
        >>> delete(email, 'GPG', 'secret')
        False
    '''

    try:
        user_key = get(email, encryption_name)
        if user_key:
            if user_key.passcode == passcode:
                user_key.delete()
                result_ok = True
            else:
                result_ok = False
                log_message("{} passcodes don't match so not deleting {}".format(encryption_name, email))
        else:
            result_ok = False
            log_message("no contact's {} user key record to delete for {}".format(encryption_name, email))
    except Exception:
        result_ok = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return result_ok

def get_passcode(email, encryption_name):
    '''
        Get the passcode for the encryption program for the contact.
        The email can be an RFC address or just the email address.

        >>> len(get_passcode('edward@goodcrypto.local', 'GPG')) > 0
        True
        >>> get_passcode('edward@goodcrypto.local', 'TestBC') is None
        True
    '''

    passcode = None

    try:
        if email_in_domain(email):
            address = get_email(email)
            user_key = get(address, encryption_name)
            if user_key:
                passcode = user_key.passcode
                if passcode and len(passcode) > 0:
                    log_message("private {} key configured for {}".format(encryption_name, email))
                else:
                    log_message('{} does not have a {} private key configured'.format(email, encryption_name))
            else:
                log_message('{} does not have a matching contact'.format(email))
        else:
            log_message('{} not part of managed domain so no private user key'.format(email))
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return passcode

def get_all_user_keys(email):
    '''
        Get the query set for all the user keys for all the encryption software.

        The email can be an RFC address or just the email address.

        >>> # In honor of Nick Mathewson, one of the three original designers of Tor.
        >>> from time import sleep
        >>> from django.db.models.query import QuerySet
        >>> from goodcrypto.oce.rq_gpg_settings import GPG_RQ, GPG_REDIS_PORT
        >>> from goodcrypto.utils.manage_rq import wait_until_queue_empty
        >>> email = 'nick@goodcrypto.local'
        >>> contact = Contact.objects.create(user_name='Nick', email=email)
        >>> encryption_software = EncryptionSoftware.objects.get(name='GPG')
        >>> contacts_encryption = ContactsCrypto.objects.create(
        ...    contact=contact, encryption_software=encryption_software)
        >>> sleep(150)
        >>> wait_until_queue_empty(GPG_RQ, GPG_REDIS_PORT)
        >>> len(get_all_user_keys(contact.email)) == 1
        True
        >>> isinstance(get_all_user_keys(contact.email), QuerySet)
        True
        >>> contacts.delete(email)
        True
        >>> wait_until_queue_empty(GPG_RQ, GPG_REDIS_PORT)
    '''

    query_set = None
    try:
        if email is None:
            log_message('missing data to get user key')
        else:
            address = get_email(email)
            query_set = UserKey.objects.filter(contacts_encryption__contact__email=address)
            if query_set is None:
                log_message("{} does not have any encryption program with a private key defined".format(email))
            else:
                log_message("{} has {} encryption program(s) with private key(s)".format(email, len(query_set)))
    except UserKey.DoesNotExist:
        log_message('{} does not have any encryption programs with private keys defined'.format(email))
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return query_set

def get_encryption_names(email):
    '''
        Get a list of all the encryption program names for this email.

        The email can be an RFC address or just the email address.

        In honor of Brandon Bryant, a whistleblower about the US drone program.
        >>> len(get_encryption_names('edward@goodcrypto.local')) > 0
        True
        >>> len(get_encryption_names('brandon@goodcrypto.remote')) > 0
        False
    '''

    encryption_programs = []
    address = get_email(email)
    if address is not None and len(address) > 0:
        query_set = get_all_user_keys(address)
        if query_set is None:
            log_message("no encryption software for this contact")
        else:
            log_message("{} has {} encryption programs".format(email, len(query_set)))
            for user_key in query_set:
                encryption_programs.append(user_key.contacts_encryption.encryption_software.name)
                log_message("{} encryption software: {}".format(email, encryption_programs))

    return encryption_programs

def get_contact_list(encryption_name=None):
    '''
        Get a list of all the email addresses or
        a list of all email addresses that use the encryption program.

        >>> len(get_contact_list()) >= 2
        True
        >>> len(get_contact_list('TestPGP')) == 0
        True
    '''

    try:
        query_set = None
        if encryption_name is None:
            query_set = UserKey.objects.all()
        else:
            query_set = UserKey.objects.filter(
                contacts_encryption__encryption_software__name=encryption_name)
    except UserKey.DoesNotExist:
        log_message("no passcodes defined for any contacts")
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    contacts = []
    if query_set is None:
        log_message("no contacts' passcodes matching criteria defined")
    else:
        for user_key in query_set:
            email = user_key.contacts_encryption.contact.email
            if not email in contacts:
                contacts.append(email)
                log_message("email address: {}".format(email))

    return contacts

def get_default_expiration_time():
    '''
        Get the default expiration time for a key.

        >> get_default_expiration_time()
        1
    '''

    return UserKey.DEFAULT_EXPIRATION_TIME

def get_default_expiration_period():
    '''
        Get the default expiration period for a key.

        >> get_default_expiration_period()
        'Years'
    '''

    return UserKey.DEFAULT_EXPIRATION_PERIOD


def log_message(message):
    '''
        Log a message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.user_keys.log'))
        True
    '''

    global log

    if log is None:
        log = LogFile()

    log.write_and_flush(message)


