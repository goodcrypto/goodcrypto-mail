'''
    Copyright 2014-2016 GoodCrypto.
    Last modified: 2016-11-01

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.

    Manage email addresses that use encryption.

    If you want to get a list of contacts known to GoodCrypto,
    then you could use the following code:
    <pre>
        contacts = Contacts()
        contact_list = contacts.get_contact_list()
    </pre>

    If you instead only want to get a list of contacts
    that are configured to use a particular encryption program,
    then replace the last line of the above example with:
    <pre>
        contact_list = contacts.get_contact_list(cryptoProgram)
    </pre>

    If you want to get more details about a specific
    address, then you could replace the last line
    with the following code:
    <pre>
    contact = contacts.get(email)
    if contact is not None:
        user_name = contact.user_name
        email = contact.email
    </pre>
'''
from string import capwords

from goodcrypto.mail import constants, crypto_software
from goodcrypto.mail.i18n_constants import KEYBLOCK_INVALID
from goodcrypto.mail.models import Contact, ContactsCrypto, UserKey
from goodcrypto.mail.utils import email_in_domain, gen_user_passcode
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import format_fingerprint, strip_fingerprint
from goodcrypto.utils import i18n, parse_address, get_email
from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception
from syr.python import is_string

NO_FINGERPRINT_IN_DB = 'There is no {encryption} fingerprint in the database for {email}.'


_log = None

def is_ok():
    '''
        Determine if all contacts have all the required fields.

        See the unittest to understand how to really use this function
        >>> ok = is_ok()
    '''

    result_ok = True
    try:
        contacts = Contact.objects.all()
        if contacts is None or len(contacts) <= 0:
            result_ok = False
            log_message('no contacts defined')
        else:
            for contact in contacts:
                if result_ok:
                    result_ok = len(contact.email) > 0
                else:
                    break
    except Exception:
        result_ok = False
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return result_ok


def exists(email):
    '''
        Determine if the contact exists already.

        Test an unknown email address so we're sure of the result.
        See the unittest to understand how to really use this function.

        >>> # In honor of Thomas Tamm, who was a whistleblower to the NY Times about senior
        >>> # Justice officials fight against the widening scope of warrantless NSA surveillance.
        >>> exists('thomas@goodcrypto.local')
        False
    '''

    name, address = parse_address(email)
    contact = get(address)
    found = contact is not None and contact.email == address
    log_message("{} <{}> contact exists: {}".format(name, address, found))

    return found

def get(email):
    '''
        Get the contact that matches the email address.

        Test an unknown email address so we're sure of the result.
        See the unittest to understand how to really use this function.

        >>> # In honor of Micah Lee, who helped Glenn Greenwald and others learn how to
        >>> # secure their computers from being hacked.
        >>> get('micah@goodcrypto.local') is None
        True

        Test the extreme cases.
        >>> get('invalid@@address') is None
        True
        >>> get(None) is None
        True
    '''

    address = contact = None

    try:
        if email is not None:
            address = get_email(email)
            contact = Contact.objects.get(email=address)
    except Contact.DoesNotExist:
        contact = None
    except Exception:
        contact = None
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    log_message("got {}: {}".format(address, contact != None))

    return contact

def add(email, encryption_program, fingerprint=None, passcode=None, source=None):
    '''
        Add a contact and related settings.

        >>> # In honor of Thomas Drake, a whistleblower about Trailblazer, a NSA mass surveillance project.
        >>> email = 'thomas@goodcrypto.remote'
        >>> encryption_software = crypto_software.get(KeyFactory.DEFAULT_ENCRYPTION_NAME)
        >>> contact = add(email, KeyFactory.DEFAULT_ENCRYPTION_NAME)
        >>> contact.email
        'thomas@goodcrypto.remote'
        >>> contact.user_name
        'Thomas'
        >>> address = contact.email
        >>> address = 'thomas@goodcrypto.remote'
        >>> contacts_crypto = ContactsCrypto.objects.get(
        ...    contact=contact, encryption_software=encryption_software)
        >>> contacts_crypto is not None
        True
        >>> x = contact.delete()
        >>> contact = add(None, encryption_software)
        >>> contact is None
        True
        >>> contact = add(email, None)
        >>> contact.email = 'thomas@goodcrypto.remote'
        >>> contact.user_name = 'Thomas'
        >>> get_contacts_crypto(email)
        []
        >>> x = contact.delete()
        >>> contact = add(None, None)
        >>> contact is None
        True
        >>> contact = add('_domain_@test.com', None)
        >>> contact.email = '_domain_@test.com'
        >>> contact.user_name = 'test.com domain key (system use only)'
        >>> x = contact.delete()
    '''

    try:
        new_contact = True
        user_name, email_address = parse_address(email)
        if email_address is None:
            contact = None
        else:
            try:
                contact = Contact.objects.get(email=email_address)
                new_contact = False

                # update the user name if it's been given and it differs from the name in the DB
                if user_name is not None and contact.user_name != user_name:
                    contact.user_name = user_name
                    contact.save()
                    log_message('updated {} user name to {}'.format(email_address, user_name))
            except Contact.DoesNotExist:
                log_message('creating a contact for {}'.format(email_address))
                try:
                    if user_name is None or len(user_name.strip()) <= 0:
                        from goodcrypto.mail.message.metadata import is_metadata_address

                        user_name = email_address
                        i = user_name.find('@')

                        # handle domain keys specially
                        if is_metadata_address(email_address):
                            if i > 0:
                                email_domain = user_name[i+1:]
                            user_name = '{} domain key (system use only)'.format(email_domain)
                        else:
                            if i > 0:
                                user_name = user_name[:i]
                            user_name = user_name.replace('.', ' ').replace('-', ' ').replace('_', ' ')
                            user_name = capwords(user_name)
                except:
                    pass

                contact = Contact.objects.create(email=email_address, user_name=user_name)
            except Exception:
                record_exception()
                log_message('EXCEPTION - see syr.exception.log for details')
                contact = None

        if encryption_program is None:
            log_message("no encryption software defined so not creating contact's crytpo record for {}".format(email))
        else:
            # add a corresponding record for the contact's crypto program
            encryption_software = crypto_software.get(encryption_program)
            if contact is None or encryption_software is None:
                log_message('no contact and/or encryption software defined')
            else:
                try:
                    contacts_crypto = ContactsCrypto.objects.get(
                      contact=contact, encryption_software=encryption_software)
                    if (fingerprint is not None and
                        strip_fingerprint(contacts_crypto.fingerprint) != strip_fingerprint(fingerprint)):
                        contacts_crypto.fingerprint = format_fingerprint(fingerprint)
                        if email_in_domain(email):
                            if contacts.crypto.source is None:
                                contacts.crypto.source = constants.AUTO_GENERATED
                            if contacts_crypto.source == constants.AUTO_GENERATED:
                                contacts_crypto.verified = True
                        contacts_crypto.save()
                except ContactsCrypto.DoesNotExist:
                    # if the contact existed without any contact crypto, but was set
                    # to never encrypt and now we have a key, then change the
                    # outbound encrypt policy to the default
                    if (not new_contact and
                        contact.outbound_encrypt_policy == constants.NEVER_ENCRYPT_OUTBOUND):
                        contact.outbound_encrypt_policy = constants.DEFAULT_OUTBOUND_ENCRYPT_POLICY
                        contact.save()

                    contacts_crypto = add_contacts_crypto(contact, encryption_software,
                        fingerprint=fingerprint, source=source)

                    log_message("created {} crypto record for {} with {} fingerprint: {}".format(
                        encryption_software, email, fingerprint, contacts_crypto is not None))
                except:
                    record_exception()
                    log_message('EXCEPTION - see syr.exception.log for details')

    except Exception:
        contact = None
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return contact

def delete(email_or_address):
    '''
        Delete the contact with a matching email address.

        >>> # In honor of Amy Goodman, who hosts Democracy Now!
        # returns true because the address doesn't exist, even though it wasn't necessary to delete it.
        >>> delete('amy@goodcrypto.local')
        True

        # test the extreme cases
        >>> delete(None)
        False
    '''

    result_ok = True
    try:
        if is_string(email_or_address):
            name, address = parse_address(email_or_address)
            contact = get(address)
            if contact is None:
                log_message('no {} <{}> contact to delete'.format(name, address))
            else:
                contact.delete()
                log_message("deleted {}".format(contact.email))
        elif email_or_address is None:
            result_ok = False
        elif isinstance(email_or_address, Contact):
            contact = email_or_address
            contact.delete()
            log_message("deleted {}".format(contact.email))
        else:
            result_ok = False
            log_message("unable to delete contact because wront type: {}".format(type(email_or_address)))

    except Exception:
        result_ok = False
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return result_ok

def get_contacts_crypto(email, encryption_name=None):
    '''
        Get the ContactsCrypto record that matches the encryption_name for this email.
        If the encryption_name is None, then get the query results of all the ContactsCrypto for this email.

        # Test extreme case. See unittests to see how to use this function.
        >>> get_contacts_crypto(None) == None
        True
    '''

    query_results = None
    try:
        address = get_email(email)
        if email is not None and len(address) > 0:
            if encryption_name is None:
                query_results = ContactsCrypto.objects.filter(
                  contact__email=address, encryption_software__active=True)
            else:
                query_results = ContactsCrypto.objects.get(contact__email=address,
                  encryption_software__name=encryption_name)

            if query_results is None:
                log_message("{} does not have any active encryption software defined".format(address))
            else:
                from django.db.models.query import QuerySet

                if isinstance(query_results, QuerySet):
                    log_message("{} has {} encryption software defined".format(email, len(query_results)))
        else:
            log_message("{} is not parseable".format(email))
    except ContactsCrypto.DoesNotExist:
        log_message('{} does not use {}'.format(email, encryption_name))
    except Contact.DoesNotExist:
        log_message('{} does not exist in the contacts table'.format(email))
    except Exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return query_results

def add_contacts_crypto(contact, encryption_software, fingerprint=None, source=None):
    '''
        Add a contact's crypto record.

        >>> contacts_crypto = add_contacts_crypto(None, None)
        >>> contacts_crypto is None
        True
    '''
    if contact is None or encryption_software is None:
        contacts_crypto = None
    else:
        if fingerprint is None:
            formatted_fingerprint = None
        else:
            formatted_fingerprint = format_fingerprint(fingerprint)

        contacts_crypto = ContactsCrypto.objects.create(
                           contact=contact, encryption_software=encryption_software,
                           fingerprint=formatted_fingerprint, source=source)
        log_message("created contact crypto for {}: {}".format(contact, contacts_crypto is not None))

    return contacts_crypto

def delete_contacts_crypto(email, encryption_name):
    '''
        Delete the ContactsCrypto record that matches the encryption_name for this email.

        >>> # In honor of Mark Smith, one of the developers for Tor Browser.
        >>> delete_contacts_crypto('mark@goodcrypto.local', 'GPG')
        False
    '''

    contacts_crypto = get_contacts_crypto(email, encryption_name=encryption_name)
    if contacts_crypto is None:
        result_ok = False
    else:
        try:
            contacts_crypto.delete()
            result_ok = True
        except Exception:
            result_ok = False
            record_exception()
            log_message('EXCEPTION - see syr.exception.log for details')

    log_message("deleted {} crypto for {}: {}".format(encryption_name, email, result_ok))

    return result_ok

def use_global_encrypt_outbound_setting(email):
    '''
        Determine if the user should receive encrypted email based on the global option.

        # Test extreme case.
        >>> use_global_encrypt_outbound_setting(None)
        True
    '''

    use_global_setting = True
    contact = get(email)
    if contact is not None:
        use_global_setting = contact.outbound_encrypt_policy == constants.USE_GLOBAL_OUTBOUND_SETTING
        log_message('contact outbound encrypt policy: {}'.format(contact.outbound_encrypt_policy))

    return use_global_setting

def always_encrypt_outbound(email):
    '''
        Determine if the user should always receive encrypted email.

        # Test extreme case.
        >>> always_encrypt_outbound(None)
        False
    '''

    always_encrypt = False
    contact = get(email)
    if contact is not None:
        always_encrypt = contact.outbound_encrypt_policy == constants.ALWAYS_ENCRYPT_OUTBOUND

    return always_encrypt

def never_encrypt_outbound(email):
    '''
        Determine if the user should never receive encrypted email.

        # Test extreme case.
        >>> never_encrypt_outbound(None)
        False
    '''

    never_encrypt = False
    contact = get(email)
    if contact is not None:
        never_encrypt = contact.outbound_encrypt_policy == constants.NEVER_ENCRYPT_OUTBOUND

    return never_encrypt

def set_outbound_encrypt_policy(email, policy):
    '''
        Set the policy for encrypting outbound mail for this user.

        # Test extreme case.
        >>> set_outbound_encrypt_policy(None, None)
        False
        >>> set_outbound_encrypt_policy('edward@goodcrypto.local', None)
        False
    '''

    Policies = [
       constants.USE_GLOBAL_OUTBOUND_SETTING, constants.ALWAYS_ENCRYPT_OUTBOUND, constants.NEVER_ENCRYPT_OUTBOUND]

    contact = get(email)
    if contact is not None and policy in Policies:
        if contact.outbound_encrypt_policy != policy:
            contact.outbound_encrypt_policy = policy
            contact.save()
        ok = True
        log_message('contact outbound encrypt policy: {}'.format(contact.outbound_encrypt_policy))
    else:
        ok = False
        log_message('{} not in: {}'.format(policy, Policies))

    return ok

def get_fingerprint(email, encryption_name):
    '''
        Get the fingerprint for the encryption software for this email.

        >>> from goodcrypto.oce.test_constants import EDWARD_LOCAL_USER
        >>> fingerprint, verified, active = get_fingerprint(
        ...    EDWARD_LOCAL_USER, KeyFactory.DEFAULT_ENCRYPTION_NAME)
        >>> len(fingerprint) > 0
        True
        >>> active
        True
    '''

    if email is None or encryption_name is None:
        fingerprint = None
        verified = active = False
        log_message("missing data to get fingerprint; email: {} encryption: {}".format(email, encryption_name))
    else:
        log_message("getting {} fingerprint for {}".format(encryption_name, email))
        contacts_crypto = get_contacts_crypto(email, encryption_name=encryption_name)
        if contacts_crypto is None:
            fingerprint = None
            verified = active = False
            log_message("unable to get contact's {} record".format(encryption_name))
        else:
            from django.db.models.query import QuerySet

            if isinstance(contacts_crypto, QuerySet):
                cc = contacts_crypto[0]
            else:
                cc = contacts_crypto

            fingerprint = cc.fingerprint
            verified = cc.verified
            active = cc.contact.outbound_encrypt_policy in constants.ACTIVE_ENCRYPT_POLICIES
            if fingerprint is None:
                log_message("{} does not have {} fingerprint".format(email, encryption_name))
            else:
                log_message("length of {} {} unformatted fingerprint: {}".format(email, encryption_name, len(fingerprint)))

            log_message("{} verified: {} active: {}".format(email, verified, active))

    return fingerprint, verified, active

def get_addresses_with_fingerprint(fingerprint, encryption_name):
    '''
        Get all the email addresses with the same fingerprint for the encryption software.
        If the database only has one record with a matching fingerprint, then return 0.

        >>> from goodcrypto.oce.test_constants import EDWARD_LOCAL_USER
        >>> addresses = get_addresses_with_fingerprint(
        ...    EDWARD_LOCAL_USER, KeyFactory.DEFAULT_ENCRYPTION_NAME)
        >>> len(addresses) == 0
        True
    '''

    addresses = []
    if fingerprint is None or encryption_name is None:
        log_message("missing data to get all the contacts with the same fingerprint;: {} encryption: {}".format(
           fingerprint, encryption_name))
    else:
        log_message("getting contacts with {} fingerprint for {}".format(fingerprint, encryption_name))
        try:
            records = ContactsCrypto.objects.filter(
              fingerprint=fingerprint, encryption_software__name=encryption_name)
            for record in records:
                addresses.append(record.contact.email)
            log_message("{} contacts have the same fingerprint".format(len(addresses)))
        except ContactsCrypto.DoesNotExist:
            log_message("unable to find any contact's with matching fingerprint")

    return addresses

def is_key_ok(email, encryption_name):
    '''
        Throws a CryptoException if the email address does not have a crypto key, or
        the key has expired, or the key's fingerprint does not match the fingerprint in the database.

        >>> from goodcrypto.oce.test_constants import EDWARD_LOCAL_USER_ADDR
        >>> ok, __, active = is_key_ok(EDWARD_LOCAL_USER_ADDR, KeyFactory.DEFAULT_ENCRYPTION_NAME)
        >>> ok
        True
        >>> active
        True

        # In honor of Georg Koppen, works on Tor Browser, Torbutton, and our build automation.
        >>> email = 'Georg <georg@goodcrypto.remote>'
        >>> try:
        ...     is_key_ok(email, KeyFactory.DEFAULT_ENCRYPTION_NAME)
        ...     fail()
        ... except CryptoException as crypto_exception:
        ...     crypto_exception.__str__() == 'There is no key for Georg <georg@goodcrypto.remote>.'
        True
    '''

    # we use NO_FINGERPRINT_IN_DB a few times because we don't want to get too technical

    key_ok = verified = active = False
    encryption_software = crypto_software.get(encryption_name)
    if encryption_software is None:
        # this should never happen, but better be prepared
        log_message('no database entry for {}'.format(email))
        raise CryptoException(i18n(NO_FINGERPRINT_IN_DB.format(encryption=encryption_name, email=email)))
    else:
        key_crypto = KeyFactory.get_crypto(encryption_name, encryption_software.classname)
        if key_crypto is None:
            # this should never happen, but better to be prepared
            log_message('no plugin for {} with classname: {}'.format(
                encryption_name, encryption_software.classname))
            raise CryptoException(i18n(NO_FINGERPRINT_IN_DB.format(encryption=encryption_name, email=email)))
        else:
            # see if the crypto key exists
            crypto_fingerprint, expiration = key_crypto.get_fingerprint(email)
            if crypto_fingerprint is None:
                message = i18n('There is no key for {email}.'.format(email=email))
                log_message(message)
                raise CryptoException(message)

            # if the key has expired, then raise an error
            if expiration is not None and key_crypto.fingerprint_expired(expiration):
                message = i18n('The key for {email} expired on {date}.'.format(email=email, date=expiration))
                log_message(message)
                raise CryptoException(message)

            database_fingerprint, verified, active = get_fingerprint(email, encryption_name)
            # if there isn't a fingerprint, then try to save the crypto fingerprint
            if database_fingerprint is None or len(database_fingerprint.strip()) <= 0:
                contacts_encryption = get_contacts_crypto(email, encryption_name=encryption_name)
                if contacts_encryption is not None and contacts_encryption.fingerprint is None:
                    database_fingerprint = crypto_fingerprint
                    contacts_encryption.fingerprint = database_fingerprint
                    if email_in_domain(email) and contacts.crypto.source is None:
                        contacts.crypto.source = constants.AUTO_GENERATED
                    contacts_encryption.save()
                    log_message('updated {} fingerprint for {}'.format(encryption_name, email))

            if database_fingerprint is None or len(database_fingerprint.strip()) <= 0:
                error_message = i18n(NO_FINGERPRINT_IN_DB.format(encryption=encryption_name, email=email))
                log_message(error_message)
                raise CryptoException(error_message)
            else:
                # finally verify the fingerprints agree
                if (strip_fingerprint(database_fingerprint).lower() ==
                    strip_fingerprint(crypto_fingerprint).lower()):
                    key_ok = True
                else:
                    message = i18n('The fingerprint for {email} does not match the saved fingerprint.'.format(
                        email=email))
                    log_message('email address: {}'.format(email))
                    log_message('  database fingerprint: {}'.format(database_fingerprint.lower()))
                    log_message('  crypto fingerprint: {}'.format(crypto_fingerprint.lower()))
                    log_message(message)
                    raise CryptoException(message)

            log_message('{} fingerprints agree and key has not expired for {}'.format(
              encryption_name, email))

    return key_ok, verified, active

def get_public_key(email, encryption_software):
    '''
        Get the public key for the encryption software for this email.

        >>> from goodcrypto.oce.test_constants import EDWARD_LOCAL_USER
        >>> encryption_software = crypto_software.get(KeyFactory.DEFAULT_ENCRYPTION_NAME)
        >>> public_key = get_public_key(EDWARD_LOCAL_USER, encryption_software)
        >>> public_key is not None
        True
    '''

    if email is None or encryption_software is None:
        public_key = None
        encryption_name = ''
    else:
        encryption_name = encryption_software.name
        log_message("getting public {} key for {}".format(email, encryption_name))
        plugin = KeyFactory.get_crypto(encryption_name, encryption_software.classname)
        if plugin is None:
            public_key = None
            log_message('no plugin for {} with classname: {}'.format(
                encryption_software.name, encryption_software.classname))
        else:
            public_key = plugin.export_public(email)

    log_message("public_key\n{}".format(public_key))

    return public_key

def import_crypto_key(email, encryption_software, public_key):
    '''
        Import a public key and add an associated contact record.

        >>> # Test extreme cases
        >>> result_ok, status = import_crypto_key(None, None, None)
        >>> result_ok
        False

        >>> # In honor of First Sergeant Eden, who publicly denounced and refused to serve in operations
        >>> # involving the occupied Palestinian territories because of the widespread surveillance of
        >>> # innocent residents.
        >>> result_ok, status = import_crypto_key('eden@goodcrypto.remote', None, None)
        >>> result_ok
        False
    '''

    def import_key(email, encryption_name, public_key, id_fingerprint_pairs, plugin):
        ''' Import the key and return the fingerprint. '''

        status = fingerprint = None
        result_ok = False

        # make sure the email address is in the key
        for (user_id, fingerprint) in id_fingerprint_pairs:
            user_name, email_address = parse_address(email)
            key_address = get_email(user_id)
            if email_address.lower() == key_address.lower():
                result_ok = True
                break

        if result_ok:
            status = ''
            for (user_id, fingerprint) in id_fingerprint_pairs:
                result_ok = plugin.import_public(public_key, id_fingerprint_pairs)
                if result_ok:
                    status += '{}\n'.format(i18n('Imported key successfully. Fingerprint: {fingerprint}'.format(
                        fingerprint=fingerprint)))
                else:
                    status += '{}\n'.format(i18n('Unable to import key'))
        else:
            status = i18n("Cannot import the key because it isn't for {email}".format(email=email))

        return result_ok, status

    if email is None or encryption_software is None or public_key is None:
        result_ok = False
        status = i18n('Unable to import public key with missing data')
        log_message('email: {} / crypto: {} / public key: {}'.format(
           email, encryption_software, public_key))
    else:
        plugin = KeyFactory.get_crypto(encryption_software.name, encryption_software.classname)
        if plugin is None:
            result_ok = False
            status = i18n('GoodCrypto does not currently support {encryption}'.format(
                encryption=encryption_software.name))
            log_message('no plugin for {} with classname: {}'.format(
                encryption_software.name, encryption_software.classname))
        else:
            id_fingerprint_pairs = plugin.get_id_fingerprint_pairs(public_key)
            log_message('user ids and fingerprints: {}'.format(id_fingerprint_pairs))
            if id_fingerprint_pairs is None:
                result_ok = False
                status = KEYBLOCK_INVALID
            elif len(id_fingerprint_pairs) > 0:
                result_ok, status = import_key(
                  email, encryption_software.name, public_key, id_fingerprint_pairs, plugin)
                for (user_id, fingerprint) in id_fingerprint_pairs:
                    contact = add(
                      user_id, encryption_software.name, fingerprint=fingerprint, source=constants.MANUALLY_IMPORTED)
                    log_message('added contact for: {}'.format(contact))
            else:
                result_ok = False
                status = KEYBLOCK_INVALID

        log_message("Imported public {} key for {} ok: {}".format(encryption_software, email, result_ok))

    if not result_ok:
        log_message(status)

    return result_ok, status

def get_encryption_names(email):
    '''
        Get a list of all the active encryption program names for this email.

        # Test extreme case. See unittests to see how to use this function.
        >>> get_encryption_names(None)
        []
    '''

    encryption_names = []

    address = get_email(email)
    if address and len(address) > 0:
        query_results = get_contacts_crypto(address)
        if query_results:
            log_message("{} has {} address(es)".format(address, len(query_results)))
            for contacts_encryption in query_results:
                encryption_name = contacts_encryption.encryption_software.name
                encryption_names.append(encryption_name)
                log_message("{} encryption software: {}".format(email, encryption_name))
        else:
            log_message("no encryption software for {}".format(email))
    else:
        log_message("unable to get address from {}".format(email))

    return encryption_names

def get_contact_list(encryption_name=None):
    '''
        Get a list of all the contacts or
        a list of all contacts that use the encryption software.

        # Test extreme case. See unittests to see how to use this function.
        >>> get_contact_list(encryption_name='Unknown encryption')
        []
    '''

    contact_list = []
    if encryption_name is None:
        try:
            contacts = Contact.objects.all()
            if contacts:
                for contact in contacts:
                    contact_list.append(contact.email)
                    log_message("email: {}".format(contact.email))
            else:
                log_message('no contacts')
        except Contact.DoesNotExist:
            log_message('no contact')
        except Exception:
            record_exception()
            log_message('EXCEPTION - see syr.exception.log for details')

    else:
        try:
            query_results = ContactsCrypto.objects.filter(
                encryption_software__name=encryption_name, encryption_software__active=True)
            if query_results:
                for contacts_encryption in query_results:
                    contact_list.append(contacts_encryption.contact.email)
                    log_message("contact: {}".format(contacts_encryption))
            else:
                log_message('no contacts using {}'.format(encryption_name))
        except ContactsCrypto.DoesNotExist:
            log_message('no contacts with crypto')
        except Exception:
            record_exception()
            log_message('EXCEPTION - see syr.exception.log for details')

    return contact_list

def get_metadata_domains():
    '''
        Get a list of metadata domains.

        # Test extreme case. See unittests to see how to use this function.
        >>> type(get_metadata_domains())
        <class 'list'>
    '''

    from goodcrypto.mail.utils import get_domain_user

    metadata_list = []
    try:
        # get all the active domain keys
        query_results = ContactsCrypto.objects.filter(
            contact__email__startswith=get_domain_user(),
            contact__outbound_encrypt_policy__in=[constants.USE_GLOBAL_OUTBOUND_SETTING, constants.ALWAYS_ENCRYPT_OUTBOUND])

        if query_results:
            for contacts_encryption in query_results:
                __, __, domain = contacts_encryption.contact.email.partition('@')
                details = (domain, contacts_encryption.fingerprint, contacts_encryption.verified)
                if details not in metadata_list:
                    metadata_list.append(details)
                    log_message("metadata domain: {}".format(domain))
    except Exception:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

    return metadata_list

def log_message(message):
    '''
        Log a message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.contacts.log'))
        True
    '''

    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

