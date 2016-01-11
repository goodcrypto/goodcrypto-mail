'''
    Mail views

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-02-23

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os.path, re, urllib
from traceback import format_exc

from django.shortcuts import redirect, render, render_to_response
from django.http import HttpResponse, HttpResponseRedirect, HttpResponsePermanentRedirect
from django.template import RequestContext

from goodcrypto.mail import contacts, crypto_software, forms, options
from goodcrypto.mail.api import MailAPI
from goodcrypto.mail.i18n_constants import ERROR_PREFIX, PUBLIC_KEY_INVALID
from goodcrypto.mail.message import history
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import format_fingerprint, strip_fingerprint
from goodcrypto.utils import i18n
from goodcrypto.utils.log_file import LogFile
from syr.user_tests import superuser_required
from syr.utils import get_remote_ip

log = LogFile()


def home(request):
    '''Show the home page.'''

    domain = options.get_domain()
    mta = options.get_mail_server_address()
    if (domain is None or len(domain.strip()) <= 0 or
        mta is None or len(mta.strip()) <= 0):
        log.write('redirecting to system configuration; domain: {}; mta: {}'.format(domain, mta))
        response = HttpResponseRedirect('/system/configure/')
    else:
        template = 'mail/home.html'
        response = render_to_response(
            template, {'domain': domain, 'mta': mta}, context_instance=RequestContext(request))

    return response

def view_fingerprint(request):
    '''View the fingerprint for a user.'''

    if options.login_to_view_fingerprints() and not request.user.is_authenticated():
        response = redirect('/login/?next={}'.format(request.path))
    else:
        response = None
        form = forms.GetFingerprintForm()
        if request.method == 'POST':
            
            email = None
            encryption_software = None
            
            form = forms.GetFingerprintForm(request.POST)
            if form.is_valid():
                try:
                    email = form.cleaned_data['email']
                    encryption_software = form.cleaned_data['encryption_software']

                    page_title = i18n('{encryption_software} Fingerprint for {email}'.format(
                        encryption_software=encryption_software, email=email))

                    fingerprint, verified = contacts.get_fingerprint(email, encryption_software.name)
                    if fingerprint is None:
                        fingerprint = i18n('No fingerprint defined')
                        verified_msg = ''
                    elif request.user.is_authenticated():
                        if verified:
                            checked = 'checked'
                        else:
                            checked = None
                        form_template = 'mail/verify_fingerprint.html'
                        response = render_to_response(
                            form_template, {'form': form, 
                                            'page_title': page_title,
                                            'email': email, 
                                            'encryption_name': encryption_software.name,
                                            'fingerprint': format_fingerprint(fingerprint),
                                            'checked': checked}, 
                                            context_instance=RequestContext(request))

                    if response is None:
                        response = show_fingerprint(request, email, fingerprint, verified, page_title)
                except Exception:
                    log.write(format_exc())
    
            if response is None:
                log.write('view fingerprint post: {}'.format(request.POST))
    
        if response is None:
            form_template = 'mail/get_fingerprint.html'
            response = render_to_response(
                form_template, {'form': form}, context_instance=RequestContext(request))

    return response

def verify_fingerprint(request):
    '''Verify the fingerprint for a user.'''

    if not request.user.is_authenticated():
        response = redirect('/login/?next={}'.format(request.path))
    else:
        response = None
        form = forms.VerifyFingerprintForm()
        if request.method == 'POST':

            verified = False
            email = encryption_name = fingerprint = None

            form = forms.VerifyFingerprintForm(request.POST)
            if form.is_valid():
                try:
                    verified = form.cleaned_data['verified']
                    email = form.cleaned_data['email']
                    encryption_name = form.cleaned_data['encryption_name']
                    fingerprint = form.cleaned_data['fingerprint']

                    contacts_crypto = contacts.get_contacts_crypto(email, encryption_name)
                    if (contacts_crypto.fingerprint == strip_fingerprint(fingerprint) and
                        contacts_crypto.verified != verified):

                        contacts_crypto.verified = verified
                        contacts_crypto.save()

                    email = contacts_crypto.contact.email
                    encryption_software = contacts_crypto.encryption_software
                    fingerprint = contacts_crypto.fingerprint
                    page_title = i18n('{encryption_software} Fingerprint for {email}'.format(
                        encryption_software=encryption_software, email=email))

                    response = show_fingerprint(request, email, fingerprint, verified, page_title)
                except Exception:
                    log.write(format_exc())
    
            if response is None:
                log.write('verify fingerprint post: {}'.format(request.POST))
    
        if response is None:
            form_template = 'mail/get_fingerprint.html'
            response = render_to_response(
                form_template, {'form': form}, context_instance=RequestContext(request))

    return response

def verify_encrypted(request):
    '''Get message id that the user wants to verify.'''

    if not request.user.is_authenticated():
        response = redirect('/login/?next={}'.format(request.path))
    else:
        response = None
        form = forms.VerifyEncryptForm()
        form_template = 'mail/verify_message.html'
        if request.method == 'POST':
            
            message_id = None
            form = forms.VerifyEncryptForm(request.POST)
            if form.is_valid():
                try:
                    message_id = urllib.quote(form.cleaned_data['message_id'])
                    response = HttpResponseRedirect('/mail/msg-encrypted/{}'.format(message_id))
                except Exception:
                    log.write(format_exc())
    
            if response is None:
                log.write('post: {}'.format(request.POST))
    
        if response is None:
            params = {'form': form, 
                      'header': i18n('Verify Message Encrypted by GoodCrypto'),
                      'url': 'verify_encrypted'}
            response = render_to_response(
                form_template, params, context_instance=RequestContext(request))

    return response

def msg_encrypted(request, message_id):
    '''Show whether the message was encrypted message.'''

    if not request.user.is_authenticated():
        response = redirect('/login/?next={}'.format(request.path))
    else:
        try:
            template = 'mail/history.html'
            result_headers = []
            results = []
            error_message = None

            email = request.user.email
            records = history.get_encrypted_messages(email)
            if records:
                # narrow the messages to those matching the message id
                records = records.filter(message_id=urllib.unquote(message_id))

            if records:
                headline = i18n('Verified message sent securely from {email}'.format(email=email))
                result_headers = get_history_report_header('To')
                for record in records:
                    results.append(get_encrypt_tupple(record))
            else:
                headline = i18n('Message not sent securely from {email}'.format(email=email))
                error_message = i18n('GoodCrypto did <font color="red">not</font> send message  securely from {email} (message id: {message_id}).'.format(
                    email=email, message_id=message_id))
                log.write(error_message)

            params = {'email': email,
                      'status': history.get_encrypted_message_status(),
                      'headline': headline,
                      'result_headers': result_headers,
                      'results': results,
                      'error_message': error_message}
            response = render_to_response(
                template, params, context_instance=RequestContext(request))
        except Exception:
            log.write(format_exc())

    return response

def show_encrypted_history(request):
    '''Show the history of encrypted messages for the logged in user.'''

    if not request.user.is_authenticated():
        response = redirect('/login/?next={}'.format(request.path))
    else:
        try:
            result_headers = []
            results = []
            error_message = None

            template = 'mail/history.html'
            records = history.get_encrypted_messages(request.user.email)
            if records:
                result_headers = get_history_report_header('To')
                for record in records:
                    results.append(get_encrypt_tupple(record))
            params = {'email': request.user.email,
                      'status': history.get_encrypted_message_status(),
                      'headline': 'History of messages sent securely from {}'.format(request.user.email),
                      'result_headers': result_headers,
                      'results': results,
                      'error_message': error_message}
            response = render_to_response(
                template, params, context_instance=RequestContext(request))
        except Exception:
            log.write(format_exc())

    return response

def verify_decrypted(request):
    '''Get validation code that the user wants to verify.'''

    if not request.user.is_authenticated():
        response = redirect('/login/?next={}'.format(request.path))
    else:
        response = None
        form = forms.VerifyDecryptForm()
        form_template = 'mail/verify_message.html'
        if request.method == 'POST':
            
            validation_code = None
            form = forms.VerifyDecryptForm(request.POST)
            if form.is_valid():
                try:
                    validation_code = urllib.quote(form.cleaned_data['validation_code'])
                    response = HttpResponseRedirect('/mail/msg-decrypted/{}'.format(validation_code))
                except Exception:
                    log.write(format_exc())
    
            if response is None:
                log.write('post: {}'.format(request.POST))
    
        if response is None:
            params = {'form': form, 
                      'header': i18n('Verify Message Decrypted by GoodCrypto'),
                      'url': 'verify_decrypted'}
            response = render_to_response(
                form_template, params, context_instance=RequestContext(request))

    return response

def msg_decrypted(request, validation_code):
    '''Show whether the message was decrypted.'''

    if not request.user.is_authenticated():
        response = redirect('/login/?next={}'.format(request.path))
    else:
        try:
            template = 'mail/history.html'
            result_headers = []
            results = []
            error_message = None

            email = request.user.email
            records = history.get_decrypted_messages(email)
            if records:
                # narrow the messages to those matching the message id
                records = records.filter(validation_code=urllib.unquote(validation_code))

            if records:
                headline = i18n('Verified message received securely for {email}'.format(email=email))
                result_headers = get_history_report_header('From')
                for record in records:
                    results.append(get_decrypt_tupple(record))
            else:
                headline = i18n('Message not received securely for {email}'.format(email=email))
                error1 = i18n('GoodCrypto did <font color="red">not</font> receive this message securely for <strong>{email}</strong> (validation code: {validation_code}).'.format(
                    email=email, validation_code=validation_code))
                error2 = i18n('If the message has a tag which states it was received securely for {email}, then someone has tampered with the message.'.format(
                    email=email))
                error_message = '{} {}'.format(error1, error2)
                log.write(error_message)

            params = {'email': request.user.email,
                      'status': history.get_decrypted_message_status(),
                      'headline': headline,
                      'result_headers': result_headers,
                      'results': results,
                      'error_message': error_message}
            response = render_to_response(
                template, params, context_instance=RequestContext(request))
        except Exception:
            log.write(format_exc())
            response = HttpResponseRedirect('/mail/verify_decrypted/')

    return response

def show_decrypted_history(request):
    '''Show the history of decrypted messages for the logged in user.'''

    if not request.user.is_authenticated():
        response = redirect('/login/?next={}'.format(request.path))
    else:
        try:
            template = 'mail/history.html'
            result_headers = []
            results = []
            error_message = None

            records = history.get_decrypted_messages(request.user.email)
            if records:
                result_headers = get_history_report_header('From')
                for record in records:
                    results.append(get_decrypt_tupple(record))
            params = {'email': request.user.email,
                      'status': history.get_decrypted_message_status(),
                      'headline': 'History of messages received securely for {}'.format(request.user.email),
                      'result_headers': result_headers,
                      'results': results,
                      'error_message': error_message}
            response = render_to_response(
                template, params, context_instance=RequestContext(request))
        except Exception:
            log.write(format_exc())

    return response

def get_history_report_header(address_label):
    '''Set up the report header for a history report.'''

    result_headers = []
    result_headers.append({'sortable': True, 'url_primary': '#{}'.format(address_label), 'text': '{}'.format((address_label))})
    result_headers.append({'sortable': True, 'url_primary': '#Date', 'text': i18n('Date')})
    result_headers.append({'sortable': True, 'url_primary': '#ID', 'text': i18n('Message ID')})
    result_headers.append({'sortable': True, 'url_primary': '#SecuredWith', 'text': i18n('Secured with')})
    result_headers.append({'sortable': True, 'url_primary': '#ValidationCode', 'text': i18n('ValidationCode')})

    return result_headers

def get_encrypt_tupple(record):
    '''Get the encrypt record tupple. '''

    return get_record_tupple(record, record.recipient)
                       
def get_decrypt_tupple(record):
    '''Get the decrypt record tupple. '''

    return get_record_tupple(record, record.sender)
                       
def get_record_tupple(record, address):
    '''Get the decrypt record tupple. '''

    return (address, record.message_date, record.message_id, 
             str(record.encryption_programs), record.validation_code)
                       
def export_key(request):
    '''Export the public key for a user.'''

    def get_safe_name(email):
        try:
            name = ''
            for letter in email:
                if letter == '@' or letter == '.' or letter == '-':
                    name += '_'
                elif re.match('[A-Za-z0-9]', letter):
                    name += letter
        except Exception:
            name = email
            log.write(format_exc())
            
        return name

    if options.login_to_export_keys() and not request.user.is_authenticated():
        response = redirect('/login/?next={}'.format(request.path))
    else:
        response = None
        form = forms.ExportKeyForm()
        form_template = 'mail/export_key.html'
        if request.method == 'POST':
            response = None
            form = forms.ExportKeyForm(request.POST)
            if form.is_valid():
                try:
                    email = form.cleaned_data['email']
                    encryption_software = form.cleaned_data['encryption_software']
    
                    public_key = contacts.get_public_key(email, encryption_software)
                    if public_key is None or len(public_key) <= 0:
                        data = {'title': i18n("Export {encryption_software} Key Error".format(
                                    encryption_software=encryption_software)),
                                'result': i18n('Your GoodCrypto server does not have a public {encryption_software} key defined for {email}'.format(
                                    encryption_software=encryption_software, email=email))}
                        template = 'mail/key_error_results.html'
                        response = render_to_response(
                            template, data, context_instance=RequestContext(request))
                    else:
                        name = get_safe_name(email)
                        log.write('export {} public {} key to {}'.format(email, encryption_software, name))
                        response = HttpResponse(public_key, content_type='application/text')
                        response['Content-Disposition'] = 'attachment; filename="{}.asc"'.format(name)
                except Exception:
                    log.write(format_exc())
    
            if response is None:
                log.write('post: {}'.format(request.POST))
    
        if response is None:
            response = render_to_response(
                form_template, {'form': form}, context_instance=RequestContext(request))

    return response

def import_key(request):
    ''' Import a public key.'''

    if not request.user.is_authenticated():
        response = redirect('/login/?next={}'.format(request.path))
    else:
        response = None
        form = forms.ImportKeyForm()
        form_template = 'mail/import_key.html'
        if request.method == 'POST':
            try:
                form = forms.ImportKeyForm(request.POST, request.FILES)
                if form.is_valid(): 
                    response = import_public_key(request, form)
            except Exception:
                log.write(format_exc())
    
            if response is None:
                log.write('post: {}'.format(request.POST))
    
        if response is None:
            response = render_to_response(
                form_template, {'form': form}, context_instance=RequestContext(request))

    return response


def import_public_key(request, form):
    ''' Import a public key and create corresponding contact.'''

    response = None
    public_key_file = request.FILES['public_key_file']
    encryption_software = form.cleaned_data['encryption_software']
    user_name = form.cleaned_data['user_name']
    fingerprint = form.cleaned_data['fingerprint']

    MAX_SIZE = forms.MAX_PUBLIC_KEY_FILEZISE
    if public_key_file.size > MAX_SIZE:
        log.write('public key file too large: {}'.format(public_key_file.size))
        title = i18n("Import Public {encryption_software} Key for {email}".format(
            encryption_software=encryption_software, email=email))
        result = i18n('The public key file is too long. The maximum size is {}. If you are sure the size is correct, contact support@goodcrypto.com.'.format(MAX_SIZE))
        data = {'title': title, 'result': result}
        template = 'mail/key_error_results.html'
    else:
        public_key = public_key_file.read()
        result_ok, status, fingerprint_ok, id_fingerprint_pairs = import_key_now(
            encryption_software, public_key, user_name, fingerprint)

        if result_ok:
            results_label, email = status.split(':')
            final_status = '{results} for {email}'.format(results=results_label, email=email)

            if fingerprint_ok:
                warnings = None
            else:
                warnings = i18n('The fingerprint that you entered and none of the fingerprints from the imported key match.')

            page_title = i18n("Imported Public {encryption_software} Key Successfully".format(
                            encryption_software=encryption_software))
            data = {'page_title': page_title, 'status': final_status, 'fingerprints': id_fingerprint_pairs, 'warnings': warnings}
            template = 'mail/import_key_results.html'
        else:
            page_title = i18n("Import Public {encryption_software} Key Error".format(
                encryption_software=encryption_software))
            data = {'page_title': page_title,
                    'result': status}
            template = 'mail/key_error_results.html'
            log.write('error importing public {} key:\n{}'.format(encryption_software, public_key))

    response = render_to_response(template, data, context_instance=RequestContext(request))
        
    return response


def import_key_now(encryption_name, public_key, user_name, possible_fingerprint):
    '''
        Import if public key is ok and doesn't exist.
    '''

    fingerprint_ok = True
    id_fingerprint_pairs = None

    if encryption_name is None or public_key is None:
        result_ok = False
        status = i18n('Unable to import public key with missing data')
        log.write('crypto: {} / public key: {}'.format(
           encryption_name, public_key))
    else:
        encryption_software = crypto_software.get(encryption_name)
        plugin = KeyFactory.get_crypto(encryption_software.name, encryption_software.classname)
        if plugin is None:
            result_ok = False
            status = ('GoodCrypto does not currently support {encryption}').format(
                encryption=encryption_software.name)
            log.write('no plugin for {} with classname: {}'.format(
                encryption_software.name, encryption_software.classname))
        else:
            id_fingerprint_pairs = plugin.get_id_fingerprint_pairs(public_key)
            if id_fingerprint_pairs is None:
                result_ok = False
                status = PUBLIC_KEY_INVALID
            else:
                result_ok = True
                for (user_id, fingerprint) in id_fingerprint_pairs:
                    if email_in_domain(user_id):
                        result_ok = False
                        status = ('You may not import a public key for {email}').format(email=user_id)
                        break
                    else:
                        # make sure we don't already have crypto defined for this user
                        contacts_crypto = contacts.get_contacts_crypto(user_id, encryption_name)
                        if contacts_crypto is None or contacts_crypto.fingerprint is None:
                            fingerprint, expiration = plugin.get_fingerprint(user_id)
                            if fingerprint is not None:
                                log.write('{} public key exists for {}: {}'.format(
                                    encryption_name, user_id, fingerprint))
                                result_ok = False
                        else:
                            result_ok = False

                        if not result_ok:
                            status = ('A {encryption_name} key already exists for {email}. Delete the key and then try importing.').format(
                                encryption_name=encryption_name, email=user_id)
                            break

                # import the key if this is a new contact
                if result_ok:
                    log.write('importing keys for {}'.format(id_fingerprint_pairs))
                    result_ok, status, fingerprint_ok = _import_key_add_contact(
                        public_key, user_name, possible_fingerprint, id_fingerprint_pairs, plugin)
                else:
                    log.write('unable to import keys for {}'.format(id_fingerprint_pairs))

    log.write("Imported public {} key ok: {}".format(encryption_name, result_ok))
    log.write("    Status: {}".format(status))

    return result_ok, status, fingerprint_ok, id_fingerprint_pairs
    
def _import_key_add_contact(public_key, user_name, possible_fingerprint, id_fingerprint_pairs, plugin):
    '''
        Import public keys and create associated contact records.
        
    '''
    def update_contact(contact, crypto_name, fingerprint):
        fingerprint_ok = True
        try:
            if (user_name is not None and 
                (contact.user_name is None or len(contact.user_name.strip()) <= 0)):
                contact.user_name = user_name.strip()
                contact.save()
                log.write('updated user name')
            else:
                log.write('user name: {}'.format(user_name))
                log.write('contact user name: {}'.format(contact.user_name))
            if possible_fingerprint is not None and len(possible_fingerprint.strip()) > 0:
                if strip_fingerprint(possible_fingerprint).lower() == strip_fingerprint(fingerprint).lower():
                    contacts_crypto = contacts.get_contacts_crypto(user_id, plugin.get_name())
                    contacts_crypto.verified = True
                    contacts_crypto.save()
                    log.write('verified fingerprint')
                else:
                    fingerprint_ok = False
        except:
            log.write(format_exc())
            
        return  fingerprint_ok
        
        
    result_ok = True
    fingerprint_ok = True
    status = i18n('Imported public key:')
    
    result_ok = plugin.import_public(public_key, id_fingerprint_pairs)
    log.write('imported key: {}'.format(result_ok))
    if result_ok:
        i = 0
        for (user_id, fingerprint) in id_fingerprint_pairs:
            contact = contacts.add(user_id, plugin.get_name())
            if contact is None:
                log.write('unable to add contact for {}'.format(user_id))
            else:
                if not update_contact(contact, plugin.get_name(), fingerprint):
                    fingerprint_ok = False
                status += ' {}'.format(user_id)
            i += 1
    else:
        result_ok = False
        status = PUBLIC_KEY_INVALID
        
    log.write(status)

    return result_ok, status, fingerprint_ok
    
def configure(request):
    ''' Show how to configure mta. '''
    
    template = 'mail/configure.html'
    return render_to_response(
        template, {'domain': options.get_domain()}, context_instance=RequestContext(request))

@superuser_required
def get_diagnostic_logs(request):
    ''' We need to let the sysadmin review the diagnostic logs,
        but the logs are owned by goodcrypto, not www-data so
        we'll need to consider how to do this.
    '''
    
    return HttpResponse(i18n('Coming soon'))

def api(request):
    '''
        Interface with the client through the API.
    
        All requests must be via a POST.
    '''

    try:
        referer = request.META.get('HTTP_REFERER', 'unknown')
        http_user_agent = request.META.get('HTTP_USER_AGENT', 'unknown')
        remote_ip = get_remote_ip(request)
        log.write('{} called mail api from {} with {} user agent'.format(remote_ip, referer, http_user_agent))
        if remote_ip == '127.0.0.1':
            response = MailAPI().interface(request)
        else:
            # redirect attempts at using the api from outside the localhost
            response = HttpResponsePermanentRedirect('/')
    except:
        log.write(format_exc())
        response = HttpResponsePermanentRedirect('/')

    return response

def show_fingerprint(request, email, fingerprint, verified, page_title):
    ''' Show the fingerprint. '''
    
    if verified:
        verified_msg = i18n('Yes')
    else:
        verified_msg = i18n('No')

    log.write('showing {} fingerprint verified: {}'.format(email, verified))
    
    template = 'mail/show_fingerprint.html'
    data = {'page_title': page_title,
            'fingerprint': format_fingerprint(fingerprint),
            'verified': verified_msg}
    return render_to_response(template, data, context_instance=RequestContext(request))


