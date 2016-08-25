'''
    Mail views

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-02-04

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os.path, re, urllib
from django.shortcuts import redirect, render_to_response
from django.http import HttpResponse, HttpResponseRedirect, HttpResponsePermanentRedirect
from django.template import RequestContext
from django.template.context_processors import csrf

from goodcrypto.mail import config_postfix, contacts, crypto_software, forms, options
from goodcrypto.mail.api import MailAPI
from goodcrypto.mail.constants import ACTIVE_ENCRYPT_POLICIES
from goodcrypto.mail.forms import PrepPostfixForm
from goodcrypto.mail.i18n_constants import ERROR_PREFIX, PUBLIC_KEY_INVALID
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.message import history
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import format_fingerprint, strip_fingerprint
from goodcrypto.utils import get_ip_address, i18n
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from reinhardt.utils import is_secure_connection
from syr.user_tests import superuser_required
from syr.utils import get_remote_ip

ENCRYPTED_STATUS = i18n('encrypted')
DECRYPTED_STATUS = i18n('decrypted')
SIGNED_STATUS = i18n('signed')
NOT_SENT_PRIVATELY = i18n('GoodCrypto did <font color="red">not</font> send message privately from <strong>{email}</strong> (verification code: {verification_code}).')
TAMPERED_SENT_WARNING = i18n("If the message has a tag which states it was sent privately from {email} and you're double checked the verification code, then someone probably tampered with the message.")
NOT_RECEIVED_PRIVATELY = i18n('GoodCrypto did <font color="red">not</font> receive a message for <strong>{email}</strong> with the verification code: <strong>{verification_code}</strong>')
TAMPERED_RECEIVED_WARNING = i18n("If the message has a tag which states it was received privately and you're double checked the verification code, then someone probably tampered with the message.")
NOT_EXCHANGED_PRIVATELY = i18n('GoodCrypto did <font color="red">not</font> exchange a message for <strong>{email}</strong> with the verification code: <strong>{verification_code}</strong>')
TAMPERED_EXCHANGED_WARNING = i18n("If the message has a tag which states it was exchanged privately or signed and you're double checked the verification code, then someone probably tampered with the message.")

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
            'require_outbound_encryption': options.require_outbound_encryption(),
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
                                            'active': active,
                                            'requires': options.require_key_verified()},
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
                    if (contacts_crypto.fingerprint == strip_fingerprint(key_id) and
                        contacts_crypto.verified != verified):

                        contacts_crypto.verified = verified
                        contacts_crypto.save()
                        log_message('updated verify field for {}'.format(email))

                    email = contacts_crypto.contact.email
                    active = contacts_crypto.contact.outbound_encrypt_policy in ACTIVE_ENCRYPT_POLICIES
                    encryption_software = contacts_crypto.encryption_software.name
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
                    retry_params, __ = get_crypted_params(
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
            records = history.get_outbound_messages(email)
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
                sent_privately = sent_with_sig = False
                for record in records:
                    results.append({'email': record.sender, 'record': record})
                    if record.content_protected or record.metadata_protected:
                        sent_privately = True
                    if record.private_signed or record.clear_signed or record.dkim_signed:
                        sent_with_sig = True

                main_headline = i18n('Verified')
                if sent_privately and sent_with_sig:
                    subheadline = i18n('Message sent privately and signed')
                elif sent_privately:
                    subheadline = i18n('Message sent privately')
                elif sent_with_sig:
                    subheadline = i18n('Message sent signed')
            else:
                main_headline = i18n('<font color="red">Not</font> Verified')
                subheadline = i18n('Message not sent privately nor signed')
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
            records = history.get_outbound_messages(request.user.email)
            if records:
                for record in records:
                    verification_link = get_formatted_verification_link(
                        record.verification_code, 'msg-encrypted')
                    results.append({
                      'email': record.recipient, 'record': record, 'verification_link': verification_link})

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
            records = history.get_inbound_messages(email)
            if records:
                # narrow the messages to those matching the verification_code
                records = records.filter(verification_code=urllib.unquote(verification_code))

            if records:
                received_privately = received_with_sig = False
                for record in records:
                    results.append({'email': record.sender, 'record': record})
                    if record.content_protected or record.metadata_protected:
                        received_privately = True
                    if record.private_signed or record.clear_signed or record.dkim_signed:
                        received_with_sig = True

                main_headline = i18n('<font color="green">Verified</font>')
                if received_privately and received_with_sig:
                    subheadline = i18n('Message received privately and signed')
                elif received_privately:
                    subheadline = i18n('Message received privately')
                elif received_with_sig:
                    subheadline = i18n('Message received signed')
            else:
                main_headline = i18n('<font color="red">Not</font> Verified')
                subheadline = i18n('Message not received privately nor signed.')
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


            records = history.get_inbound_messages(request.user.email)
            if records:
                for record in records:
                    verification_link = get_formatted_verification_link(record.verification_code, 'msg-decrypted')
                    results.append({
                      'email': record.sender, 'record': record, 'verification_link': verification_link})
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
                    log_message('possible fingerprint: {}'.format(strip_fingerprint(possible_fingerprint).lower()))
                    log_message('imported fingerprint: {}'.format(strip_fingerprint(fingerprint).lower()))
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
            if user_name is not None:
                full_email = '{} <{}>'.format(user_name, user_id)
            else:
                full_email = user_id
            contact = contacts.add(full_email, plugin.get_name())
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

    log_message('showing {} fingerprint verified: {}'.format(email, verified))
    log_message('require verification {}'.format(options.require_key_verified()))

    template = 'mail/show_fingerprint.html'
    data = {'page_title': page_title,
            'fingerprint': format_fingerprint(fingerprint),
            'verified': verified,
            'active': active,
            'requires': options.require_key_verified()}
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
                    if record.content_protected or record.metadata_protected:
                        subheadline = i18n('Message sent privately')
                        status = ENCRYPTED_STATUS
                    else:
                        subheadline = i18n('Message sent with signature')
                        status = SIGNED_STATUS
                    for record in records:
                        results.append({'email': record.sender, 'record': record})
                else:
                    main_headline = i18n('Verified')
                    if record.content_protected or record.metadata_protected:
                        subheadline = i18n('Message received privately')
                        status = DECRYPTED_STATUS
                    else:
                        subheadline = i18n('Message received with signature')
                        status = SIGNED_STATUS
                    for record in records:
                        results.append({'email': record.sender, 'record': record})
            else:
                main_headline = i18n('Verified')
                subheadline = i18n('Exchanged the messages privately')
                for record in records:
                    results.append({'email': record.sender, 'record': record})
        else:
            main_headline = i18n('<font color="red">Not</font> Verified')
            subheadline = i18n('Message not exchanged privately nor signed')
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

def get_formatted_verification_link(verification_code, partial_link):
    ''' Create a link for the verification code. '''

    try:
        code = verification_code
        quoted_code = urllib.quote(code)
        link = '/mail/{}/{}'.format(partial_link, quoted_code, code)
    except:
        link = code

    return link

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
                      'encrypt_metadata': options.encrypt_metadata(),
                      'require_key_verified': options.require_key_verified(),
                      'error_message': error_message}
            response = render_to_response(
                template, params, context_instance=RequestContext(request))
        except Exception:
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            response = HttpResponseRedirect('/mail/show_metadata_domains/')

    return response

def prep_postfix(request):
    ''' Prepare Postfix for GoodCrypto.'''

    if not request.user.is_authenticated() or not request.user.is_superuser:
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        template = 'mail/postfix_prep.html'
        if request.method == 'POST':
            try:
                form = PrepPostfixForm(request.POST)
                if form.is_valid():
                    response = get_postfix_config(form, request)

                else:
                    response = render_to_response(template, {'form': form,},
                        context_instance=RequestContext(request))
                    log_message('integrate postfix form had errors')
            except:
                log_message('EXCEPTION - see goodcrypto.utils.exception.log for more details')
                record_exception()
                response = render_to_response(template, {'form': form,},
                    context_instance=RequestContext(request))

        else:
            ip_address = get_goodcrypto_private_server_ip(request)
            if ip_address is not None and len(ip_address) > 0:
                form = PrepPostfixForm(initial={'goodcrypto_private_server_ip': ip_address})
            else:
                form = PrepPostfixForm()
            response = render_to_response(template, {'form': form},
                context_instance=RequestContext(request))

    return response

def get_postfix_config(form, request):
    ''' Get the postfix config from the form. '''

    log_message('postfix form is valid')
    private_server_ip = form.cleaned_data.get('goodcrypto_private_server_ip')
    main_cf_lines = form.cleaned_data.get('main_cf')
    master_cf_lines = form.cleaned_data.get('master_cf')
    alias_lines = form.cleaned_data.get('aliases')

    new_main_cf_lines, __, mta_ip, ssl_cert_file, ssl_key_file, other_filters = config_postfix.config_main_conf(
        main_cf_lines.replace('\r\n','\n').replace('\r','\n').split('\n'), private_server_ip)

    # abort if TLS is not configured
    if ssl_cert_file is None or ssl_key_file is None:
        error = config_postfix.ERROR_MESSAGE

        response = render_to_response(template, {'form': form, 'error_message': error},
            context_instance=RequestContext(request))
    else:
        if other_filters:
            warning = config_postfix.WARNING_MESSAGE
        else:
            warning = None

        new_master_cf_lines = config_postfix.config_master_lines(
            master_cf_lines.replace('\r\n','\n').replace('\r','\n').split('\n'),
            mta_ip, private_server_ip, ssl_cert_file, ssl_key_file)

        if alias_lines is None or len(alias_lines) <= 0:
            alias_lines = []
            new_alias_file = True
        else:
            alias_lines = alias_lines.replace('\r\n','\n').replace('\r','\n').split('\n')
            new_alias_file = False
        new_alias_lines = config_postfix.config_alias_lines(alias_lines)

        params = {'main_cf_lines': '\n'.join(new_main_cf_lines),
                  'master_cf_lines': '\n'.join(new_master_cf_lines),
                  'alias_lines': '\n'.join(new_alias_lines),
                  'new_alias_file': new_alias_file,
                  'warning': warning,
        }
        response = render_to_response('mail/postfix_results.html', params,
            context_instance=RequestContext(request))

    return response

def get_goodcrypto_private_server_ip(request):
    ''' Get the ip address for the goodcrypto private server. '''

    ip_address = get_ip_address(request=request)
    if ip_address is None:
        url = options.goodcrypto_server_url()
        if url is not None:
            m = re.match('^https?://(.*):8\d\d\d/$', url)
            if m:
                ip_address = m.group(1)

    # don't accept local address or local virtual address as the ip address
    if ip_address == '127.0.0.1' or ip_address == '10.0.2.15':
        ip_address = None

    log_message('ip address: {}'.format(ip_address))

    return ip_address

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

    log.write_and_flush(message)


