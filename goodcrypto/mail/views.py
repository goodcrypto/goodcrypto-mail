'''
    Mail views

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-12-01

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os.path, re, urllib
from django.shortcuts import redirect, render_to_response
from django.http import HttpResponse, HttpResponseRedirect, HttpResponsePermanentRedirect
from django.template import RequestContext
from django.template.context_processors import csrf

from goodcrypto.mail import contacts, crypto_software, forms, options
from goodcrypto.mail.api import MailAPI
from goodcrypto.mail.i18n_constants import ERROR_PREFIX, PUBLIC_KEY_INVALID
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.message import history
from goodcrypto.mail.message.metadata import get_metadata_user
from goodcrypto.mail.models import MessageHistory
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import format_fingerprint, strip_fingerprint
from goodcrypto.utils import i18n
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from reinhardt.utils import is_secure_connection
from syr.user_tests import superuser_required
from syr.utils import get_remote_ip

ENCRYPTED_STATUS = i18n('encrypted')
DECRYPTED_STATUS = i18n('decrypted')
NOT_SENT_PRIVATELY = i18n('GoodCrypto did <font color="red">not</font> send message privately from <strong>{email}</strong> (verification code: {verification_code}).')
TAMPERED_SENT_WARNING = i18n("If the message has a tag which states it was sent privately from {email} and you're double checked the verification code, then someone probably tampered with the message.")
NOT_RECEIVED_PRIVATELY = i18n('GoodCrypto did <font color="red">not</font> receive a message privately for <strong>{email}</strong> with the verification code: <strong>{verification_code}</strong>')
TAMPERED_RECEIVED_WARNING = i18n("If the message has a tag which states it was received privately and you're double checked the verification code, then someone probably tampered with the message.")
NOT_EXCHANGED_PRIVATELY = i18n('GoodCrypto did <font color="red">not</font> exchange a message privately for <strong>{email}</strong> with the verification code: <strong>{verification_code}</strong>')
TAMPERED_EXCHANGED_WARNING = i18n("If the message has a tag which states it was exchanged privately and you're double checked the verification code, then someone probably tampered with the message.")

log = None


def home(request):
    '''Show the home page.'''

    domain = get_domain()
    if domain is None or len(domain.strip()) <= 0:
        log_message('redirecting to system configuration')
        response = HttpResponseRedirect('/system/customize/')
    else:
        is_secure = is_secure_connection(request)
        params = {
            'domain': domain, 
            'secure': is_secure,
            'fingerprint_login_req': options.login_to_view_fingerprints(),
            'export_login_req': options.login_to_export_keys()
        }
        mta = options.mail_server_address()
        if mta is not None and len(mta.strip()) > 0:
            params['mta'] = mta

        template = 'mail/home.html'
        response = render_to_response(template, params, context_instance=RequestContext(request))

    return response

def show_protection(request):
    '''Show the protection for messages.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        is_secure = is_secure_connection(request)
        template = 'mail/protection.html'
        params = {
            'secure': is_secure,
            'encrypt_metadata': options.encrypt_metadata(),
            'bundle_and_pad': options.bundle_and_pad(),
            'require_key_verified': options.require_key_verified(),
            'filter_html': options.filter_html(),
            'clear_sign': options.clear_sign_email(),
            'add_dkim_sig': options.add_dkim_sig(),
        }
        response = render_to_response(
            template, params, context_instance=RequestContext(request))

    return response

def view_fingerprint(request):
    '''View the fingerprint for a user.'''

    if options.login_to_view_fingerprints() and not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
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

                    page_title = i18n('{encryption_software} fingerprint for {email}'.format(
                        encryption_software=encryption_software, email=email))

                    fingerprint, verified, active = contacts.get_fingerprint(email, encryption_software.name)
                    if fingerprint is None:
                        fingerprint = i18n('No fingerprint defined')
                        checked = None
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
                                            'checked': checked,
                                            'active': active},
                                            context_instance=RequestContext(request))

                    if response is None:
                        response = show_fingerprint(request, email, fingerprint, verified, active, page_title)
                except Exception:
                    record_exception()
                    log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

            if response is None:
                log_message('view fingerprint post: {}'.format(request.POST))

        if response is None:
            form_template = 'mail/get_fingerprint.html'
            response = render_to_response(
                form_template, {'form': form}, context_instance=RequestContext(request))

    return response

def verify_fingerprint(request):
    '''Verify the fingerprint for a user.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
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
                    key_id = form.cleaned_data['key_id']

                    contacts_crypto = contacts.get_contacts_crypto(email, encryption_name)
                    active = contacts_crypto.active
                    if (contacts_crypto.fingerprint == strip_fingerprint(key_id) and
                        contacts_crypto.verified != verified):

                        contacts_crypto.verified = verified
                        contacts_crypto.save()

                    email = contacts_crypto.contact.email
                    encryption_software = contacts_crypto.encryption_software
                    key_id = contacts_crypto.fingerprint
                    page_title = i18n('{encryption_software} fingerprint for {email}'.format(
                        encryption_software=encryption_software, email=email))

                    response = show_fingerprint(request, email, key_id, verified, active, page_title)
                except Exception:
                    record_exception()
                    log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

            if response is None:
                log_message('verify key_id post: {}'.format(request.POST))

        if response is None:
            form_template = 'mail/get_fingerprint.html'
            response = render_to_response(
                form_template, {'form': form}, context_instance=RequestContext(request))

    return response

def verify_crypted(request):
    '''Get verification code that the user wants to verify.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        response = None
        form = forms.VerifyMessageForm()
        form_template = 'mail/verify_message.html'
        if request.method == 'POST':
            form = forms.VerifyMessageForm(request.POST)
            if form.is_valid():
                template = 'mail/verified_decrypted.html'
                log_message('verification code: {}'.format(form.cleaned_data['verification_code']))
                params, status = get_crypted_params(
                   request.user.email, form.cleaned_data['verification_code'])
                if 'error_message' in params and params['error_message'] is not None:
                    log_message('retry verification code: {}'.format(urllib.quote(form.cleaned_data['verification_code'])))
                    retry_params = get_crypted_params(
                       request.user.email, urllib.quote(form.cleaned_data['verification_code']))
                    if 'error_message' in retry_params and retry_params['error_message'] is None:
                        params = retry_params
                    log_message('retry params: {}'.format(retry_params))
                elif status == ENCRYPTED_STATUS:
                    template = 'mail/verified_encrypted.html'
                    log_message('using encrypted verification page')

                response = render_to_response(
                    template, params, context_instance=RequestContext(request))
            else:
                log_message('form not valid')

            if response is None:
                log_message('post: {}'.format(request.POST))

        if response is None:
            log_message('no response for verifying message crypted so redisplaying main page')
            params = {'form': form,
                      'main_headline': 'Verify Message',
                      'url': 'verify_crypted'}
            response = render_to_response(
                form_template, params, context_instance=RequestContext(request))

    return response

def msg_encrypted(request, verification_code):
    '''Show whether the message was encrypted message.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        try:
            template = 'mail/verified_encrypted.html'
            result_headers = []
            results = []
            error_message = None

            email = request.user.email
            records = history.get_encrypted_messages(email)
            if records:
                # narrow the messages to those matching the verification_code
                records = records.filter(verification_code=urllib.unquote(verification_code))
            if not records:
                try:
                    # use the verification_code without unquoting it in case they pasted it into a url field
                    records = records.filter(verification_code=verification_code)
                except:
                    pass

            if records:
                main_headline = i18n('Verified')
                subheadline = i18n('Message sent privately')
                for record in records:
                    results.append((record.sender, record.message_date, record.message_id,
                                    history.get_status(record.status),))
            else:
                main_headline = i18n('<font color="red">Not</font> Verified')
                subheadline = i18n('Message not sent privately')
                error1 = NOT_SENT_PRIVATELY.format(email=email, verification_code=verification_code)
                error2 = TAMPERED_SENT_WARNING.format(email=email)
                error_message = '{} {}'.format(error1, error2)
                log_message(error_message)

            params = {'email': email,
                      'main_headline': main_headline,
                      'subheadline': subheadline,
                      'results': results,
                      'error_message': error_message}
            response = render_to_response(
                template, params, context_instance=RequestContext(request))
        except Exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return response

def show_encrypted_history(request):
    '''Show the history of encrypted messages for the logged in user.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        try:
            result_headers = []
            results = []
            error_message = None

            template = 'mail/encrypted_history.html'
            records = history.get_encrypted_messages(request.user.email)
            if records:
                for record in records:
                    results.append(
                     (record.recipient, record.message_date, record.subject,
                     history.get_status(record.status), record.message_id,))

            params = {'email': request.user.email,
                      'results': results,
                      'error_message': error_message}
            response = render_to_response(
                template, params, context_instance=RequestContext(request))
        except Exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            response = HttpResponseRedirect('/mail/show_encrypted_history/')

    return response

def msg_decrypted(request, verification_code):
    '''Show whether the message was decrypted.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        try:
            template = 'mail/verified_decrypted.html'
            result_headers = []
            results = []
            error_message = None

            email = request.user.email
            records = history.get_decrypted_messages(email)
            if records:
                # narrow the messages to those matching the verification_code
                records = records.filter(verification_code=urllib.unquote(verification_code))

            if records:
                main_headline = i18n('Verified')
                subheadline = i18n('Message received privately')
                for record in records:
                    results.append((record.sender, record.message_date, record.message_id,
                                    history.get_status(record.status),
                                    record.verification_code,))
            else:
                main_headline = i18n('<font color="red">Not</font> Verified')
                subheadline = i18n('Message not received privately')
                error1 = NOT_RECEIVED_PRIVATELY.format(email=email, verification_code=verification_code)
                error2 = TAMPERED_RECEIVED_WARNING
                error_message = '{} {}'.format(error1, error2)
                log_message(error_message)

            params = {'email': request.user.email,
                      'main_headline': main_headline,
                      'subheadline': subheadline,
                      'results': results,
                      'error_message': error_message}
            response = render_to_response(
                template, params, context_instance=RequestContext(request))
        except Exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            response = HttpResponseRedirect('/mail/verify_crypted/')

    return response

def show_decrypted_history(request):
    '''Show the history of decrypted messages for the logged in user.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        try:
            template = 'mail/decrypted_history.html'
            result_headers = []
            results = []
            error_message = None

            records = history.get_decrypted_messages(request.user.email)
            if records:
                for record in records:
                    verification = get_formatted_verification_code(record.verification_code, 'msg-decrypted')
                    results.append(
                     (record.sender, record.message_date, record.subject,
                     history.get_status(record.status), verification,))
            params = {'email': request.user.email,
                      'results': results,
                      'error_message': error_message}
            response = render_to_response(
                template, params, context_instance=RequestContext(request))
        except Exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            response = HttpResponseRedirect('/mail/show_decrypted_history/')

    return response

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
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return name

    if options.login_to_export_keys() and not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
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
                        log_message('export {} public {} key to {}'.format(email, encryption_software, name))
                        response = HttpResponse(public_key, content_type='application/text')
                        response['Content-Disposition'] = 'attachment; filename="{}.asc"'.format(name)
                except Exception:
                    record_exception()
                    log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

            if response is None:
                log_message('post: {}'.format(request.POST))

        if response is None:
            response = render_to_response(
                form_template, {'form': form}, context_instance=RequestContext(request))

    return response

def import_key(request):
    ''' Import a public key.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
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
                record_exception()
                log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

            if response is None:
                log_message('post: {}'.format(request.POST))

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
        log_message('public key file too large: {}'.format(public_key_file.size))
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
            log_message('error importing public {} key:\n{}'.format(encryption_software, public_key))

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
        log_message('crypto: {} / public key: {}'.format(
           encryption_name, public_key))
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
                                log_message('{} public key exists for {}: {}'.format(
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
                    log_message('importing keys for {}'.format(id_fingerprint_pairs))
                    result_ok, status, fingerprint_ok = _import_key_add_contact(
                        public_key, user_name, possible_fingerprint, id_fingerprint_pairs, plugin)
                else:
                    log_message('unable to import keys for {}'.format(id_fingerprint_pairs))

    log_message("Imported public {} key ok: {}".format(encryption_name, result_ok))
    log_message("    Status: {}".format(status))

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
        except:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return  fingerprint_ok


    result_ok = True
    fingerprint_ok = True
    status = i18n('Imported public key:')

    result_ok = plugin.import_public(public_key, id_fingerprint_pairs)
    log_message('imported key: {}'.format(result_ok))
    if result_ok:
        i = 0
        for (user_id, fingerprint) in id_fingerprint_pairs:
            contact = contacts.add(user_id, plugin.get_name())
            if contact is None:
                log_message('unable to add contact for {}'.format(user_id))
            else:
                if not update_contact(contact, plugin.get_name(), fingerprint):
                    fingerprint_ok = False
                status += ' {}'.format(user_id)
            i += 1
    else:
        result_ok = False
        status = PUBLIC_KEY_INVALID

    log_message(status)

    return result_ok, status, fingerprint_ok

def configure(request):
    ''' Show how to configure mta. '''

    template = 'mail/configure.html'
    return render_to_response(
        template, {'domain': get_domain()}, context_instance=RequestContext(request))

def api(request):
    '''
        Interface with the client through the API.

        All requests must be via a POST.
    '''

    try:
        referer = request.META.get('HTTP_REFERER', 'unknown')
        http_user_agent = request.META.get('HTTP_USER_AGENT', 'unknown')
        remote_ip = get_remote_ip(request)
        log_message('{} called mail api from {} with {} user agent'.format(remote_ip, referer, http_user_agent))
        if remote_ip == '127.0.0.1':
            response = MailAPI().interface(request)
        else:
            # redirect attempts at using the api from outside the localhost
            response = HttpResponsePermanentRedirect('/')
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        response = HttpResponsePermanentRedirect('/')

    return response

def show_fingerprint(request, email, fingerprint, verified, active, page_title):
    ''' Show the fingerprint. '''

    if verified:
        verified_msg = i18n('Yes')
    else:
        verified_msg = i18n('No')
    if active:
        active_msg = i18n('Yes')
    else:
        active_msg = i18n('No')

    log_message('showing {} fingerprint verified: {}'.format(email, verified))

    template = 'mail/show_fingerprint.html'
    data = {'page_title': page_title,
            'fingerprint': format_fingerprint(fingerprint),
            'verified': verified_msg,
            'active': active_msg}
    return render_to_response(template, data, context_instance=RequestContext(request))

def get_crypted_params(email, verification_code):
    '''Get the params for a response to verify a message was crypted by GoodCrypto.'''

    params = {}
    results = []
    status = DECRYPTED_STATUS
    error_message = None

    try:
        records = history.get_validated_messages(email, verification_code)
        if records:
            if len(records) == 1:
                record = records[0]
                if record.sender == email:
                    main_headline = i18n('Verified')
                    subheadline = i18n('Message sent privately')
                    for record in records:
                        results.append((record.sender, record.message_date, record.message_id,
                                        history.get_status(record.status),))
                    status = ENCRYPTED_STATUS
                else:
                    main_headline = i18n('Verified')
                    subheadline = i18n('Message received privately')
                    for record in records:
                        results.append((record.sender, record.message_date, record.message_id,
                                        history.get_status(record.status),
                                        record.verification_code,))
                    status = DECRYPTED_STATUS
            else:
                main_headline = i18n('Verified')
                subheadline = i18n('Exchanged the messages privately')
                for record in records:
                    results.append((record.sender, record.message_date, record.message_id,
                                    history.get_status(record.status),
                                    record.verification_code,))
        else:
            main_headline = i18n('<font color="red">Not</font> Verified')
            subheadline = i18n('Message not exchanged privately')
            error1 = NOT_EXCHANGED_PRIVATELY.format(email=email, verification_code=verification_code)
            error2 = TAMPERED_EXCHANGED_WARNING
            error_message = '{} {}'.format(error1, error2)
            log_message(error_message)

        params = {'email': email,
                  'main_headline': main_headline,
                  'subheadline': subheadline,
                  'results': results,
                  'error_message': error_message,}
        log_message('params:\n{}'.format(params))
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return params, status

def get_formatted_verification_code(verification_code, partial_link):
    ''' Create a link for the verification code. '''

    try:
        code = verification_code
        quoted_code = urllib.quote(code)
        verification = '<a href="/mail/{}/{}">{}</a>'.format(partial_link, quoted_code, code)
    except:
        verification = code

    return verification

def show_metadata_domains(request):
    '''Show domains that have metadata keys.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        try:
            metadata_list = contacts.get_metadata_domains()
            if len(metadata_list) > 0:
                error_message = None
            else:
                error_message = i18n("There aren't any domains ready to protect metadata, yet.")

            template = 'mail/metadata_domains.html'
            params = {'metadata_list': metadata_list,
                      'error_message': error_message}
            response = render_to_response(
                template, params, context_instance=RequestContext(request))
        except Exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            response = HttpResponseRedirect('/mail/show_metadata_domains/')

    return response

def log_message(message):
    '''
        Log a message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.views.log'))
        True
    '''

    global log

    if log is None:
        log = LogFile()

    log.write(message)


