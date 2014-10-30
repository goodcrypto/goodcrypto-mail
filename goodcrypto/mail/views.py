'''
    Mail views

    Copyright 2014 GoodCrypto
    Last modified: 2014-10-06

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os.path, re
from traceback import format_exc

from django.shortcuts import render, render_to_response
from django.http import HttpResponse, HttpResponseRedirect
from django.template import RequestContext

from goodcrypto.api_constants import SYSTEM_API_URL
from goodcrypto.mail import contacts, crypto_software, international_strings
from goodcrypto.mail.api import MailAPI
from goodcrypto.mail.forms import FingerprintForm, ExportKeyForm, ImportKeyForm
from goodcrypto.mail.options import get_domain
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import format_fingerprint, strip_fingerprint
from goodcrypto.utils.log_file import LogFile
from syr.user_tests import superuser_required, staff_required

log = LogFile()


def home(request):
    '''Show the home page.'''

    form_template = 'mail/home.html'
    if request.method == 'POST':
        
        try:
            if 'action' in request.POST:
                action = request.POST.__getitem__('action')
                log.write('action: {}'.format(action))
                if action is None:
                    response = HttpResponseRedirect('/admin/mail/')
                elif action.strip() == 'View fingerprint':
                    response = view_fingerprint(request)
                elif action.strip() == 'View pubic key':
                    response = view_key(request)
                if action.strip() == 'Import key':
                    response = import_key(request)
                else:
                    response = HttpResponseRedirect('/admin/mail/')
            else:
                log.write('post: {}'.format(request.POST))
                response = render(request, form_template)
        except Exception:
            log.write(format_exc())
            response = render(request, form_template)
    else:
        response = render(request, form_template)

    return response


def view_fingerprint(request):
    '''View the fingerprint for a user.'''

    response = None
    form = FingerprintForm()
    form_template = 'mail/fingerprint.html'
    if request.method == 'POST':
        
        email = None
        encryption_software = None
        
        form = FingerprintForm(request.POST)
        if form.is_valid():
            try:
                email = form.cleaned_data['email']
                encryption_software = form.cleaned_data['encryption_software']

                fingerprint, verified = contacts.get_fingerprint(email, encryption_software.name)
                if fingerprint is None:
                    fingerprint = international_strings.NO_FINGERPRINT
                    verified_msg = ''
                else:
                    if verified:
                        verified_msg = international_strings.VERIFIED
                    else:
                        verified_msg = international_strings.NOT_VERIFIED
                form_data = {'form': form, 
                             'fingerprint_label': 'Fingerprint:', 
                             'fingerprint': format_fingerprint(fingerprint), 
                             'verified': verified_msg}
                response = render_to_response(
                    form_template, form_data, context_instance=RequestContext(request))
            except Exception:
                log.write(format_exc())

        if response is None:
            log.write('post: {}'.format(request.POST))

    if response is None:
        response = render_to_response(
            form_template, {'form': form}, context_instance=RequestContext(request))

    return response

def configure(request):
    ''' Show how to configure mta. '''
    
    template = 'mail/configure.html'
    return render_to_response(
        template, {'domain': get_domain()}, context_instance=RequestContext(request))
    
def api(request):
    '''Interface with the client through the API.
    
       All requests must be via a POST.
    '''

    try:
        response = MailAPI().interface(request)
    except:
        log.write(format_exc())
        response = HttpResponsePermanentRedirect(SYSTEM_API_URL)

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
            log.write(format_exc())
            
        return name

    response = None
    form = ExportKeyForm()
    form_template = 'mail/export_key.html'
    if request.method == 'POST':
        response = None
        form = ExportKeyForm(request.POST)
        if form.is_valid():
            try:
                email = form.cleaned_data['email']
                encryption_software = form.cleaned_data['encryption_software']
                name = get_safe_name(email)
                log.write('export {} public {} key to {}'.format(email, encryption_software, name))

                public_key = contacts.get_public_key(email, encryption_software)
                if public_key is None or len(public_key) <= 0:
                    form_data = {'form': form, 'results_label': international_strings.ERROR_PREFIX, 
                                 'result': international_strings.NO_PUBLIC_KEY}
                    response = render_to_response(
                        form_template, form_data, context_instance=RequestContext(request))
                else:
                    name = get_safe_name(email)
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


@staff_required
def import_key(request):
    ''' Import a public key and create corresponding contact.'''

    response = None
    form = ImportKeyForm()
    form_template = 'mail/import_key.html'
    if request.method == 'POST':
        response = None
        encryption_name = None
        
        form = ImportKeyForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                public_key_file = request.FILES['public_key_file']
                encryption_software = form.cleaned_data['encryption_software']
                user_name = form.cleaned_data['user_name']
                fingerprint = form.cleaned_data['fingerprint']
                
                if public_key_file.size > 100000:
                    log.write('public key file too large: {}'.format(public_key_file.size))
                    form_data = {'form': form, 'results_label': international_strings.ERROR_PREFIX, 
                                 'error_result': international_strings.PUBLIC_KEY_FILE_TOO_LONG, 'status': ''}
                    response = render_to_response(
                        form_template, form_data, context_instance=RequestContext(request))
                else:
                    public_key = public_key_file.read()
                    result_ok, status, fingerprint_ok = import_public_key(
                        encryption_software, public_key, user_name, fingerprint)
                    if result_ok:
                        results_label, email = status.split(':')
                        if not fingerprint_ok:
                            fingerprint_label = international_strings.FINGERPRINT_WARNING
                            fingerprint_result = international_strings.MISMATCHED_FINGERPRINT
                        else:
                            fingerprint_label = fingerprint_result = ''
                        form.cleaned_data['user_name'] = ''
                        form.cleaned_data['fingerprint'] = ''
                        form_data = {'form': form, 'results_label': '{}:'.format(results_label), 
                                     'status': email, 'error_result': '',
                                     'fingerprint_label': fingerprint_label,
                                     'fingerprint_result': fingerprint_result}
                    else:
                        form_data = {'form': form, 'results_label': international_strings.ERROR_PREFIX, 
                                     'error_result': status, 'status': '', 'fingerprint': None}
                        log.write('error importing public {} key:\n{}'.format(encryption_software, public_key))
                    response = render_to_response(
                        form_template, form_data, context_instance=RequestContext(request))
            except Exception:
                log.write(format_exc())

        if response is None:
            log.write('post: {}'.format(request.POST))

    if response is None:
        response = render_to_response(
            form_template, {'form': form}, context_instance=RequestContext(request))

    return response


def import_public_key(encryption_name, public_key, user_name, possible_fingerprint):
    '''
        Import if public key is ok and doesn't exist.
    '''

    fingerprint_ok = True

    if encryption_name is None or public_key is None:
        result_ok = False
        status = international_strings.IMPORT_MISSING_DATA
        log.write('crypto: {} / public key: {}'.format(
           encryption_name, public_key))
    else:
        encryption_software = crypto_software.get(encryption_name)
        plugin = KeyFactory.get_crypto(encryption_software.name, encryption_software.classname)
        if plugin is None:
            result_ok = False
            status = international_strings.CRYPTO_NOT_SUPPORTED.format(encryption_software.name)
            log.write('no plugin for {} with classname: {}'.format(
                encryption_software.name, encryption_software.classname))
        else:
            user_ids = plugin.get_user_ids_from_key(public_key)
            if user_ids is None:
                result_ok = False
                status = international_strings.PUBLIC_KEY_INVALID
            else:
                result_ok = True
                for user_id in user_ids:
                    if email_in_domain(user_id):
                        result_ok = False
                        status = international_strings.IMPORT_NOT_PERMITTED.format(user_id)
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
                            status = international_strings.PUBLIC_KEY_EXISTS.format(user_id)
                            break

                # import the key if this is a new contact
                if result_ok:
                    log.write('importing keys for {}'.format(user_ids))
                    result_ok, status, fingerprint_ok = _import_key_add_contact(
                        public_key, user_name, possible_fingerprint, user_ids, plugin)
                else:
                    log.write('unable to import keys for {}'.format(user_ids))

    log.write("Imported public {} key ok: {}".format(encryption_name, result_ok))
    log.write("    Status: {}".format(status))

    return result_ok, status, fingerprint_ok
    
def _import_key_add_contact(public_key, user_name, possible_fingerprint, user_ids, plugin):
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
            if possible_fingerprint is not None:
                if strip_fingerprint(possible_fingerprint) == strip_fingerprint(fingerprint):
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
    status = international_strings.IMPORTED_KEYS
    
    fingerprints = plugin.import_public(public_key)
    log.write('fingerprints for imported keys: {}'.format(fingerprints))
    if fingerprints is None or len(fingerprints) <= 0:
        result_ok = False
        status = international_strings.PUBLIC_KEY_INVALID
    else:
        i = 0
        for user_id in user_ids:
            contact = contacts.add(user_id, plugin.get_name())
            if contact is None:
                log.write('unable to add contact for {}'.format(user_id))
            else:
                if not update_contact(contact, plugin.get_name(), fingerprints[i]):
                    fingerprint_ok = False
                status += ' {}'.format(user_id)
            i += 1
        
    log.write(status)

    return result_ok, status, fingerprint_ok
    

