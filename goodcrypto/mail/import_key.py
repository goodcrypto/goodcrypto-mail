'''
    Import a key interactively.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-02-20

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from django.shortcuts import redirect, render_to_response
from django.template import RequestContext
from django.template.context_processors import csrf

from goodcrypto.mail import contacts, crypto_software
from goodcrypto.mail.constants import MANUALLY_IMPORTED
from goodcrypto.mail.crypto_rq import retrieve_key_from_keyservers_via_rq, search_keyservers_via_rq
from goodcrypto.mail.forms import ImportKeyFromKeyserverForm, ImportKeyFromFileForm, MAX_PUBLIC_KEY_FILEZISE
from goodcrypto.mail.i18n_constants import KEYBLOCK_INVALID
from goodcrypto.mail.keyservers import get_active_keyservers
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import strip_fingerprint
from goodcrypto.utils import i18n, parse_address
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile

log = None

MISSING_DATA_STATUS = i18n('Unable to import key with missing data')


def get_user_input(request):
    ''' Get the details about importing a key from the user.'''

    response = None
    form_template = 'mail/import_key.html'
    if request.method == 'POST':
        try:
            # check for a field that is only in the "from file" form
            if request.POST.get('submit') == i18n('Import'):
                form = ImportKeyFromFileForm(request.POST, request.FILES)
                if form.is_valid():
                    response = import_key_from_file(request, form)
                else:
                    form_from_server = ImportKeyFromKeyserverForm()
                    params = {
                       'form_from_file': form,
                       'form_from_server': form_from_server,
                       'selected_tab': 0}
            else:
                form = ImportKeyFromKeyserverForm(request.POST)
                if form.is_valid():
                    response = import_key_from_keyserver(request, form)
                else:
                    form_from_file = ImportKeyFromFileForm()
                    params = {
                       'form_from_file': form_from_file,
                       'form_from_server': form,
                       'selected_tab': 1}
                    response = render_to_response(
                        form_template, params, context_instance=RequestContext(request))

            if response is None:
                response = render_to_response(
                   form_template, params, context_instance=RequestContext(request))
        except Exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        if response is None:
            log_message('post: {}'.format(request.POST))

    if response is None:
        log_message('request: {}'.format(request))
        form_from_file = ImportKeyFromFileForm()
        form_from_server = ImportKeyFromKeyserverForm()
        params = {'form_from_file': form_from_file, 'form_from_server': form_from_server}
        response = render_to_response(
            form_template, params, context_instance=RequestContext(request))

    return response


def import_key_from_file(request, form):
    ''' Import a key from a file and create corresponding contact.'''

    response = keyblock = status = None
    try:
        log_message('importing key from file')

        key_file = request.FILES['key_file']
        encryption_software = form.cleaned_data['encryption_software']
        user_name = form.cleaned_data['user_name']
        fingerprint = form.cleaned_data['fingerprint']
        passcode = form.cleaned_data['passcode']

        MAX_SIZE = MAX_PUBLIC_KEY_FILEZISE
        if key_file.size > MAX_SIZE:
            log_message('key file too large: {}'.format(key_file.size))
            title = i18n("Import {encryption_software} Key for {email}".format(
                encryption_software=encryption_software, email=email))
            result = i18n('The key file is too long. The maximum size is {}. If you are sure the size is correct, contact support@goodcrypto.com.'.format(MAX_SIZE))
            data = {'title': title, 'result': result}
            template = 'mail/key_error_results.html'
        else:
            keyblock = key_file.read()
            result_ok, status, fingerprint_ok, id_fingerprint_pairs = import_key_now(
                encryption_software, keyblock, user_name, fingerprint, passcode)

            if result_ok:
                results_label, email = status.split(':')
                final_status = '{results} for {email}'.format(results=results_label, email=email)

                if fingerprint_ok:
                    warnings = None
                else:
                    warnings = i18n('The fingerprint that you entered and none of the fingerprints from the imported key match.')

                page_title = i18n("Imported {encryption_software} Key Successfully".format(
                                encryption_software=encryption_software))
                data = {'page_title': page_title, 'status': final_status, 'fingerprints': id_fingerprint_pairs, 'warnings': warnings}
                template = 'mail/import_from_file_results.html'
            else:
                page_title = i18n("Import {encryption_software} Key Error".format(
                    encryption_software=encryption_software))
                if status is None: status = MISSING_DATA_STATUS
                data = {'page_title': page_title,
                        'result': status}
                template = 'mail/key_error_results.html'
                log_message('error importing key from file')
    except:
        page_title = i18n("Import Key Error")
        if status is None: status = MISSING_DATA_STATUS
        data = {'page_title': page_title,
                'result': status}
        template = 'mail/key_error_results.html'
        log_message('exception importing key from file')
        record_exception()

    response = render_to_response(template, data, context_instance=RequestContext(request))

    return response

def import_key_now(encryption_name, keyblock, user_name, possible_fingerprint, passcode):
    ''' Import if key is ok and doesn't exist. '''

    fingerprint_ok = True
    id_fingerprint_pairs = []

    if encryption_name is None or keyblock is None:
        result_ok = False
        fingerprint_ok = False
        status = MISSING_DATA_STATUS
        log_message('crypto: {} / keyblock is None: {}'.format(
           encryption_name, keyblock is None))
    else:
        encryption_software = crypto_software.get(encryption_name)
        plugin = KeyFactory.get_crypto(encryption_software.name, encryption_software.classname)
        if plugin is None:
            result_ok = False
            status = ('GoodCrypto does not currently support {encryption}').format(
                encryption=encryption_software.name)
            log_message('no plugin for {} with classname: {}'.format(
                encryption_software.name, encryption_software.classname))
        else:
            id_fingerprint_pairs = plugin.get_id_fingerprint_pairs(keyblock)
            if id_fingerprint_pairs is None or len(id_fingerprint_pairs) <= 0:
                result_ok = False
                status = KEYBLOCK_INVALID
            else:
                result_ok = True
                for (user_id, fingerprint) in id_fingerprint_pairs:
                    if email_in_domain(user_id):
                        if passcode is None or len(passcode.strip()) <= 0:
                            result_ok = False
                            status = ('You must include the passcode when importing a key for {email}').format(email=user_id)
                            break

                    if result_ok:
                        # make sure we don't already have crypto defined for this user
                        contacts_crypto = contacts.get_contacts_crypto(user_id, encryption_name)
                        if contacts_crypto is None or contacts_crypto.fingerprint is None:
                            fingerprint, expiration = plugin.get_fingerprint(user_id)
                            if fingerprint is not None:
                                log_message('{} key exists for {}: {}'.format(
                                    encryption_name, user_id, fingerprint))
                                result_ok = False
                        else:
                            result_ok = False

                        if not result_ok:
                            status = ('A {encryption_name} key already exists for {email}. If you have a new key, then delete the Contact and then try importing the key again.').format(
                                encryption_name=encryption_name, email=user_id)
                            break

                # import the key if this is a new contact
                if result_ok:
                    log_message('importing keys for {}'.format(id_fingerprint_pairs))
                    result_ok, status, fingerprint_ok = _import_key_add_contact(
                        keyblock, user_name, possible_fingerprint, passcode, id_fingerprint_pairs, plugin)
                else:
                    log_message('unable to import keys for {}'.format(id_fingerprint_pairs))

    log_message("Imported public {} key ok: {}".format(encryption_name, result_ok))
    log_message("    Status: {}".format(status))

    return result_ok, status, fingerprint_ok, id_fingerprint_pairs

def _import_key_add_contact(keyblock, user_name, possible_fingerprint, passcode, id_fingerprint_pairs, plugin):
    '''
        Import keys and create associated contact records.

    '''
    def update_contact(contact, crypto_name, fingerprint):
        fingerprint_ok = True
        try:
            if (user_name is not None and
                (contact.user_name is None or len(contact.user_name.strip()) <= 0)):
                contact.user_name = user_name.strip()
                contact.save()
                log_message('updated user name')
            else:
                log_message('user name: {}'.format(user_name))
                log_message('contact user name: {}'.format(contact.user_name))
            if possible_fingerprint is not None and len(possible_fingerprint.strip()) > 0:
                if strip_fingerprint(possible_fingerprint).lower() == strip_fingerprint(fingerprint).lower():
                    contacts_crypto = contacts.get_contacts_crypto(user_id, plugin.get_name())
                    contacts_crypto.verified = True
                    contacts_crypto.save()
                    log_message('verified fingerprint')
                else:
                    fingerprint_ok = False
                    log_message('possible fingerprint: {}'.format(strip_fingerprint(possible_fingerprint).lower()))
                    log_message('imported fingerprint: {}'.format(strip_fingerprint(fingerprint).lower()))
        except:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return  fingerprint_ok


    result_ok = True
    fingerprint_ok = True
    status = i18n('Imported key:')

    if plugin is None:
        result_ok = False
        fingerprint_ok = False
    else:
        result_ok = plugin.import_public(keyblock, id_fingerprint_pairs)
        log_message('imported key: {}'.format(result_ok))

    if result_ok:
        crypto_name = plugin.get_name()

        local_users = []
        for (user_id, fingerprint) in id_fingerprint_pairs:
            if email_in_domain(user_id):
                local_users.append(user_id)

            if user_name is not None:
                full_email = '{} <{}>'.format(user_name, user_id)
            else:
                full_email = user_id
            contact = contacts.add(full_email, crypto_name, passcode=passcode, source=MANUALLY_IMPORTED)
            if contact is None:
                log_message('unable to add contact for {}'.format(user_id))
            else:
                if not update_contact(contact, plugin.get_name(), fingerprint):
                    fingerprint_ok = False
                status += ' {}'.format(user_id)

        if len(local_users) > 0:
            for local_user in local_users:
                if not plugin.is_passcode_valid(local_user, passcode, key_exists=True):
                    result_ok = False
                    status = ('The passcode is not correct for the imported key for {email}').format(email=user_id)
                    log_message(status)
                    break
            for (user_id, __) in id_fingerprint_pairs:
                if not result_ok:
                    contacts.delete(user_id)
                    log_message('deleted {}'.format(user_id))
    else:
        result_ok = False
        status = KEYBLOCK_INVALID

    log_message(status)

    return result_ok, status, fingerprint_ok

def import_key_from_keyserver(request, form):
    ''' Import a key from a keyserver, if found. '''

    MISSING_USER_EMAIL_ERROR = i18n(
      'Unable to search for keys. Searches can take a long time so when the search finds a key, you would receive an email message.<p>Your User account does not have an email address defined so searches cannot be performed. Contact your mail administrator and request they enter your email address in your User account.')
    UNEXPECTED_START_SEARCH_ERROR = i18n('An unexpected error was detected when starting search for the key. Contact your mail administrator.')
    NO_ACTIVE_KEYSERVERS_ERROR = i18n('Unable to search for key because there are no active keyservers. Contact your mail administrator.')
    UNEXPECTED_SEARCH_ERROR = i18n('Unexpected error while starting search for key. Contact your mail administrator.')

    response = status = None
    try:
        log_message('searching for key on keyservers and importing if found')

        email_or_fingerprint = form.cleaned_data['email_or_fingerprint']
        encryption_software = form.cleaned_data['encryption_software']

        user_requesting_search = request.user.email
        if user_requesting_search is None or len(user_requesting_search) <= 0:
            status = MISSING_USER_EMAIL_ERROR
        else:
            max_wait_time = len(get_active_keyservers(KeyFactory.DEFAULT_ENCRYPTION_NAME)) * 5 * 60
            if max_wait_time > 0:
                __, email = parse_address(email_or_fingerprint)
                if email is None:
                    fingerprint = email_or_fingerprint
                    result_ok = retrieve_key_from_keyservers_via_rq(
                        fingerprint, encryption_software.name, user_requesting_search)
                    log_message('started retrieving key using {} key id'.format(fingerprint))
                else:
                    result_ok = search_keyservers_via_rq(email, user_requesting_search, interactive=True)
                    log_message('started searching for key for {}'.format(email))

                if result_ok:
                    page_title = i18n("Starting search for Key")
                    data = {'page_title': page_title,
                            'status': 'Searches can take a long time. You will receive email if a key was successfully imported.'}
                    template = 'mail/import_from_keyserver_results.html'
                else:
                    status = UNEXPECTED_START_SEARCH_ERROR
            else:
                status = NO_ACTIVE_KEYSERVERS_ERROR
    except:
        status = UNEXPECTED_SEARCH_ERROR
        record_exception()

    if status is not None:
        page_title = i18n("Import Key From Keyserver Error")
        data = {'page_title': page_title,
                'result': status}
        template = 'mail/key_error_results.html'
        log_message(status)

    response = render_to_response(template, data, context_instance=RequestContext(request))

    return response

def log_message(message):
    ''' Log a message to the local log. '''

    global log

    if log is None:
        log = LogFile()

    log.write_and_flush(message)


