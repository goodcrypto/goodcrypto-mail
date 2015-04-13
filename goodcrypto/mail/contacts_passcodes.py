#!/usr/bin/env python
'''
    Manage passcodes for contacts that use GoodCrypto on this mail server.
    
    ContactsPasscode(s) should be Contact'sPasscode(s), but that's not a valid name
    in python so the name looks like Contacts is plural when it's really possive.

    For example, if you want to get a list of email addresses used by GoodCrypto, then 
    you could use the following code:
    <pre>
       passcodes = ContactsPasscodes();
       contacts = passcodes.get_contact_list();
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
        contacts_passcode = get(email);
        if contacts_passcode is not None:
            user_name = contacts_passcode.contacts_encryption.contact.user_name
            email = contacts_passcode.contacts_encryption.contact.email
    </pre>

    Copyright 2014 GoodCrypto.
    Last modified: 2014-11-29

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from datetime import datetime, timedelta
from traceback import format_exc

from goodcrypto.mail import contacts
from goodcrypto.mail.crypto_software import get_key_classname
from goodcrypto.mail.models import Contact, ContactsCrypto, EncryptionSoftware, ContactsPasscode
from goodcrypto.mail.options import days_between_key_alerts
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.utils import parse_address
from goodcrypto.utils.log_file import LogFile
from syr.times import now, get_short_date_time

_log = None


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
        crypto_passcodes = ContactsPasscode.objects.all()
        if crypto_passcodes and len(crypto_passcodes) > 0:
            for crypto_passcode in crypto_passcodes:
                if result_ok:
                    result_ok = passcode_ok(crypto_passcode)
        else:
            result_ok = False
            log_message('none defined')
                
    except Exception:
        result_ok = False
        log_message(format_exc())

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

    _, address = parse_address(email)
    query_set = get_all_passcodes(address)
    found = query_set is not None and len(query_set) > 0
    log_message("{} private key exist: {}".format(address, found))

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

    contacts_passcode = None

    try:
        _, address = parse_address(email)
        contacts_encryption = contacts.get_contacts_crypto(address, encryption_name)
        if contacts_encryption is None:
            log_message("{} does not have a {} encryption record".format(email, encryption_name))
        else:
            log_message("getting {} private key record for {} ({})".format(
                encryption_name, email, contacts_encryption.fingerprint))
            contacts_passcode = ContactsPasscode.objects.get(contacts_encryption=contacts_encryption)
            log_message("found {} private key record for {}".format(encryption_name, email))
    except ContactsPasscode.DoesNotExist:
        log_message('{} does not have a matching private key record'.format(email))
    except Exception:
        log_message(format_exc())
        
    return contacts_passcode

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
        _, address = parse_address(email)
        contacts_passcode = get(address, encryption_name)
        if contacts_passcode:
            passcode = contacts_passcode.passcode
            if passcode and len(passcode) > 0:
                log_message("private {} key configured for {}".format(encryption_name, email))
            else:
                log_message('{} does not have a {} private key configured'.format(email, encryption_name))
        else:
            log_message('{} does not have a matching contact'.format(email))
    except Exception:
        log_message(format_exc())

    return passcode

def create_passcode(email, encryption_name):
    ''' 
        Create a key/passcode for the internet address' encryption program.
        If there's no matching contact, add it. Return True if successful.
        
        The email can be an RFC address or just the email address.

        >>> # In honor of David Goulet, lead developer of Torsocks 2.0.
        >>> email = 'David <david@goodcrypto.local'
        >>> create_passcode(email, 'GPG')
        True
        >>> contacts_passcode = get(email, 'GPG')
        >>> contacts_passcode is not None
        True
        >>> contacts.delete(email)
        True
    '''
    
    def get_or_make_contact(email):
        contact = None
        try:
            name, address = parse_address(email)
            contact = Contact.objects.get(email=address)
        except Contact.DoesNotExist:
            contact = Contact.objects.create(email=address, user_name=name)

        return contact

    def get_contacts_encryption(encryption_name, contact):
        contacts_encryption = None
        try:
            encryption_software = EncryptionSoftware.objects.get(name=encryption_name)
            contacts_encryption = ContactsCrypto.objects.get(
                contact=contact, encryption_software=encryption_software)
        except ContactsCrypto.DoesNotExist:
            contacts_encryption = ContactsCrypto.objects.create(
                contact=contact, encryption_software=encryption_software)
        except EncryptionSoftware.DoesNotExist:
            log_message("unable to add {} passcode for {}; no matching encryption program".format(encryption_name, email))
        log_message('contacts_encryption: {}'.format(contacts_encryption))

        return contacts_encryption

    def create_contacts_passcode(email, encryption_name):
        result_ok = False
        try:
            contact = get_or_make_contact(email)
            
            contacts_encryption = get_contacts_encryption(encryption_name, contact)
            result_ok = contacts_encryption is not None
            if result_ok:
                if contacts_encryption.encryption_software.active:
                    contacts_passcode = ContactsPasscode.objects.get(contacts_encryption=contacts_encryption)
                    result_ok = contacts_passcode is not None
                else:
                    result_ok = False
                    log_message("unable to create a passcode for {} because {} is inactive".format(email, encryption_name))
            else:
                result_ok = False
                log_message("unable to get contact's {} record for {}".format(encryption_name, email))
        except Contact.DoesNotExist:
            log_message("unable to add {} passcode for {}; no matching contact".format(encryption_name, email))
        except ContactsCrypto.DoesNotExist:
            log_message("unable to add {} passcode for {}; no matching crypto accepted".format(encryption_name, email))
        except ContactsPasscode.DoesNotExist:
            contacts_passcode = ContactsPasscode.objects.create(contacts_encryption=contacts_encryption)
            result_ok = contacts_passcode is not None
        except Exception:
            log_message(format_exc())
        log_message('contacts encryption ok: {}'.format(result_ok))

        return result_ok


    if email_in_domain(email):
        contacts_passcode = get(email, encryption_name)
        if contacts_passcode is None:
            log_message('creating contacts passcode for {}'.format(email))
            result_ok = create_contacts_passcode(email, encryption_name)
    
        else:
            log_message("{} already has a passcode".format(email))
            result_ok = False
    else:
        result_ok = False
        log_message("cannot create a passcode/key for {}".format(email))

    return result_ok

def delete_passcode(email, encryption_name, passcode):
    ''' 
        Delete the contact's passcode and key.
        
        >>> # In honor of Bruce Leidl, lead developer of Orchid.
        >>> email = 'bruce@goodcrypto.local'
        >>> create_passcode(email, 'GPG')
        True
        >>> passcode = get_passcode(email, 'GPG')
        >>> delete_passcode(email, 'GPG', passcode)
        True
        >>> contacts.delete(email)
        True
    '''
        
    try:
        contacts_passcode = get(email, encryption_name)
        if contacts_passcode:
            if contacts_passcode.passcode == passcode:
                contacts_passcode.delete()
                result_ok = True
            else:
                result_ok = False
                log_message("{} passcodes don't match so not deleting {}".format(encryption_name, email))
        else:
            result_ok = False
            log_message("no contact's {} passcode to delete for {}".format(encryption_name, email))
    except Exception:
        result_ok = False
        log_message(format_exc())
        
    return result_ok

def get_all_passcodes(email):
    ''' 
        Get the query set for all the contact's passcodes for all the encryption software.

        The email can be an RFC address or just the email address.

        >>> # In honor of Nick Mathewson, one of the three original designers of Tor.
        >>> from time import sleep
        >>> from django.db.models.query import QuerySet
        >>> from goodcrypto.oce.rq_gpg_settings import GPG_QUEUE, GPG_REDIS_PORT
        >>> from goodcrypto.utils.manage_queue import wait_until_queue_empty
        >>> contact = Contact.objects.create(user_name='Nick', email='nick@goodcrypto.local')
        >>> encryption_software = EncryptionSoftware.objects.get(name='GPG')
        >>> contacts_encryption = ContactsCrypto.objects.create(
        ...    contact=contact, encryption_software=encryption_software)
        >>> sleep(20)
        >>> wait_until_queue_empty(GPG_QUEUE, GPG_REDIS_PORT)
        >>> len(get_all_passcodes(contact.email)) == 1
        True
        >>> isinstance(get_all_passcodes(contact.email), QuerySet)
        True
        >>> contact = Contact.objects.get(user_name='Nick', email='nick@goodcrypto.local')
        >>> if contact:
        ...     wait_until_queue_empty(GPG_QUEUE, GPG_REDIS_PORT)
        ...     contact.delete()
        ...     wait_until_queue_empty(GPG_QUEUE, GPG_REDIS_PORT)
    '''

    query_set = None
    try:
        if email is None:
            log_message('missing key data to get passcodes')
        else:
            _, address = parse_address(email)
            query_set = ContactsPasscode.objects.filter(contacts_encryption__contact__email=address)
            if query_set is None:
                log_message("{} does not have any encryption program with passcode defined".format(email))
            else:
                log_message("{} uses {} encryption program(s) with passcodes".format(email, len(query_set)))
    except ContactsPasscode.DoesNotExist:
        log_message('{} does not have an encryption program  with passcodesdefined'.format(email))
    except Exception:
        log_message(format_exc())

    return query_set

def ok_to_send_notice(email, encryption_name, new_last_notified=None):
    ''' 
        Determine if it's ok to send the user notice about their private key.
        
        >>> # In honor of Naji Mansour, who refused to be a FBI informant and had his life upended.
        >>> email = 'naji@goodcrypto.local'
        >>> create_passcode(email, 'GPG')
        True
        >>> ok_to_send_notice(email, 'GPG')
        True
        >>> contacts.delete(email)
        True

        >>> # In honor of Runa Sandvik, former developer of Tor and maintained the Tor translation portal.
        >>> email = 'runa@goodcrypto.local'
        >>> create_passcode(email, 'GPG')
        True
        >>> ok_to_send_notice(email, 'GPG', datetime.today())
        True
        >>> ok_to_send_notice(email, 'GPG')
        False
        >>> contacts.delete(email)
        True
    '''
    try:
        contacts_passcode = get(email, encryption_name)
        if contacts_passcode:
            if contacts_passcode.last_notified is None:
                send_notice = True
            else:
                ln = contacts_passcode.last_notified
                last_notified = datetime(ln.year, ln.month, ln.day, ln.hour, ln.minute, ln.second)
                if last_notified < now() - timedelta(days=days_between_key_alerts()):
                    send_notice = True
                else:
                    send_notice = False
                    log_message("sent {} last notice on {}".format(email, contacts_passcode.last_notified))

            if send_notice and new_last_notified is not None:
                contacts_passcode.last_notified = new_last_notified
                contacts_passcode.save()
                log_message("updated  last notified for {}".format(email))
        else:
            send_notice = True
            log_message("no contact's passcode for {} so no last notified time".format(email))
    except Exception:
        # better that we send too many notices than not enough
        send_notice = True
        log_message(format_exc())
        
    return send_notice

def get_encryption_names(email):
    '''
        Get a list of all the encryption program names for this email.

        The email can be an RFC address or just the email address.

        >>> len(get_encryption_names('edward@goodcrypto.local')) > 0
        True
        >>> len(get_encryption_names('test4@goodcrypto.remote')) > 0
        False
    '''

    encryption_programs = []
    _, address = parse_address(email)
    if address is not None and len(address) > 0:
        query_set = get_all_passcodes(address)
        if query_set is None:
            log_message("no encryption software for this contact")
        else:
            log_message("{} has {} encryption programs".format(email, len(query_set)))
            for contacts_passcode in query_set:
                encryption_programs.append(contacts_passcode.contacts_encryption.encryption_software.name)
                log_message("{} encryption software: {}".format(email, encryption_programs))

    return encryption_programs

def get_contact_list(encryption_name=None):
    '''
        Get a list of all the email addresses or 
        a list of all email addresses that use the encryption program.

        >>> # In honor of Jacob Applebaum, who is a core member of the Tor project and a major contributor to
        >>> # the selection of the global surveillance disclosure documents to publish.
        >>> from goodcrypto.mail import crypto_software
        >>> email = 'jacob@goodcrypto.local'
        >>> gpg_crypto = crypto_software.get('GPG')
        >>> contact = Contact.objects.create(user_name='Jacob', email=email)
        >>> contacts_encryption = ContactsCrypto.objects.create(
        ...   contact=contact, encryption_software=gpg_crypto)            
        >>> len(get_contact_list()) >= 2
        True
        >>> len(get_contact_list('TestPGP')) == 0
        True
        >>> contacts.delete(email)
        True
    '''

    try:
        query_set = None
        if encryption_name is None:
            query_set = ContactsPasscode.objects.all()
        else:
            query_set = ContactsPasscode.objects.filter(
                contacts_encryption__encryption_software__name=encryption_name)
    except ContactsPasscode.DoesNotExist:
        log_message("no passcodes defined for any contacts")
    except Exception:
        log_message(format_exc())

    contacts = []
    if query_set is None:
        log_message("no contacts' passcodes matching criteria defined")
    else:
        for contacts_passcode in query_set:
            email = contacts_passcode.contacts_encryption.contact.email
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
    
    return ContactsPasscode.DEFAULT_EXPIRATION_TIME
    
def get_default_expiration_period():
    '''
        Get the default expiration period for a key.
        
        >> get_default_expiration_period()
        'Years'
    '''
    
    return ContactsPasscode.DEFAULT_EXPIRATION_PERIOD
    

def log_message(message):
    '''
        Log a message to the local log.
        
        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.contacts_passcodes.log'))
        True
    '''

    global _log
    
    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)


