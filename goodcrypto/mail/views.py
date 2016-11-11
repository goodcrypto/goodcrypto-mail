'''
    Mail views

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-11-06

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import re
from django.shortcuts import redirect, render_to_response
from django.http import HttpResponse, HttpResponseRedirect, HttpResponsePermanentRedirect
from django.template import RequestContext
from django.template.context_processors import csrf

from goodcrypto.mail import contacts, crypto_software, forms, options
from goodcrypto.mail.api import MailAPI
from goodcrypto.mail.constants import ACTIVE_ENCRYPT_POLICIES
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.message_security import (prompt_for_code, show_outbound_msg, show_all_outbound,
                                              show_inbound_msg, show_all_inbound)
from goodcrypto.mail.tools import prep_mta_postfix
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import format_fingerprint, strip_fingerprint
from goodcrypto.utils import get_ip_address, i18n
from goodcrypto.utils.log_file import LogFile
from reinhardt.utils import is_secure_connection
from syr.exception import record_exception
from syr.user_tests import superuser_required
from syr.utils import get_remote_ip

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
            'export_login_req': options.login_to_export_keys(),
            'use_keyservers': options.use_keyservers()
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
                    log_message('EXCEPTION - see syr.exception.log for details')

            if response is None:
                log_message('view fingerprint post: {}'.format(request.POST))

        if response is None:
            form_template = 'mail/get_fingerprint.html'
            form = forms.GetFingerprintForm()
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
                    log_message('EXCEPTION - see syr.exception.log for details')

            if response is None:
                log_message('verify key_id post: {}'.format(request.POST))

        if response is None:
            form_template = 'mail/get_fingerprint.html'
            form = forms.VerifyFingerprintForm()
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
        response = prompt_for_code(request)

    return response

def msg_encrypted(request, verification_code):
    '''Show whether the outbound message had any security protection.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        response = show_outbound_msg(request, verification_code)

    return response

def show_encrypted_history(request):
    '''Show the history of outbound messages with security for the logged in user.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        response = show_all_outbound(request)

    return response

def msg_decrypted(request, verification_code):
    '''Show whether the inbound message had security protection.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        response = show_inbound_msg(request, verification_code)

    return response

def show_decrypted_history(request):
    '''Show the history of inbound messages with security protection for the logged in user.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        response = show_all_inbound(request)

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
            log_message('EXCEPTION - see syr.exception.log for details')

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
                    log_message('EXCEPTION - see syr.exception.log for details')

            if response is None:
                log_message('post: {}'.format(request.POST))

        if response is None:
            response = render_to_response(
                form_template, {'form': form}, context_instance=RequestContext(request))

    return response

def import_key_from_file(request):
    ''' Import a key or a key pair if for a local user from a file.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        from goodcrypto.mail.import_key import import_file_tab

        response = import_file_tab(request)

    return response

def import_key_from_keyserver(request):
    ''' Import a key from a keyserver.'''

    if not request.user.is_authenticated():
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        from goodcrypto.mail.import_key import import_keyserver_tab

        response = import_keyserver_tab(request)

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
            log_message('EXCEPTION - see syr.exception.log for details')
            response = HttpResponseRedirect('/mail/show_metadata_domains/')

    return response

def prep_postfix(request):
    ''' Prepare the mail server for GoodCrypto.'''

    if not request.user.is_authenticated() or not request.user.is_superuser:
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        template = 'mail/postfix_prep.html'
        if request.method == 'POST':
            try:
                form = forms.PrepPostfixForm(request.POST)
                if form.is_valid():
                    response = get_postfix_config(template, form, request)
                else:
                    response = render_to_response(template, {'form': form,},
                        context_instance=RequestContext(request))
                    log_message('integrate postfix form had errors')
            except:
                log_message('EXCEPTION - see syr.exception.log for more details')
                record_exception()
                response = render_to_response(template, {'form': form,},
                    context_instance=RequestContext(request))

        else:
            ip_address = get_goodcrypto_private_server_ip(request)
            if ip_address is not None and len(ip_address) > 0:
                postfix_form = forms.PrepPostfixForm(
                  initial={'goodcrypto_private_server_ip': ip_address})
            else:
                postfix_form = forms.PrepPostfixForm()
            response = render_to_response(template, {'postfix_form': postfix_form},
                context_instance=RequestContext(request))

    return response

def get_postfix_config(template, form, request):
    ''' Get the postfix config from the form. '''

    log_message('postfix form is valid')
    private_server_ip = form.cleaned_data.get('goodcrypto_private_server_ip')
    main_cf_lines = form.cleaned_data.get('main_cf')
    master_cf_lines = form.cleaned_data.get('master_cf')
    alias_lines = form.cleaned_data.get('aliases')

    new_main_cf_lines, __, mta_ip, ssl_cert_file, ssl_key_file, other_filters = prep_mta_postfix.config_main_conf(
        main_cf_lines.replace('\r\n','\n').replace('\r','\n').split('\n'), private_server_ip)

    # abort if TLS is not configured
    if ssl_cert_file is None or ssl_key_file is None:
        error = prep_mta_postfix.ERROR_MESSAGE

        response = render_to_response(template, {'form': form, 'error_message': error},
            context_instance=RequestContext(request))
    else:
        if other_filters:
            warning = prep_mta_postfix.WARNING_MESSAGE
        else:
            warning = None

        new_master_cf_lines = prep_mta_postfix.config_master_lines(
            master_cf_lines.replace('\r\n','\n').replace('\r','\n').split('\n'),
            mta_ip, private_server_ip, ssl_cert_file, ssl_key_file)

        if alias_lines is None or len(alias_lines) <= 0:
            alias_lines = []
            new_alias_file = True
        else:
            alias_lines = alias_lines.replace('\r\n','\n').replace('\r','\n').split('\n')
            new_alias_file = False
        new_alias_lines = prep_mta_postfix.config_alias_lines(alias_lines)

        params = {'main_cf_lines': '\n'.join(new_main_cf_lines),
                  'master_cf_lines': '\n'.join(new_master_cf_lines),
                  'alias_lines': '\n'.join(new_alias_lines),
                  'new_alias_file': new_alias_file,
                  'warning': warning,
        }
        response = render_to_response('mail/postfix_results.html', params,
            context_instance=RequestContext(request))

    return response

def prep_exim(request):
    ''' Prepare Exim for GoodCrypto.'''

    if not request.user.is_authenticated() or not request.user.is_superuser:
        context = {}
        context.update(csrf(request))
        response = redirect('/login/?next={}'.format(request.path), context)
    else:
        template = 'mail/exim_prep.html'
        if request.method == 'POST':
            try:
                form = forms.PrepEximForm(request.POST)
                if form.is_valid():
                    response = get_exim_config(form, request)
                else:
                    response = render_to_response(template, {'form': form,},
                        context_instance=RequestContext(request))
                    log_message('integrate exim form had errors')
            except:
                log_message('EXCEPTION - see syr.exception.log for more details')
                record_exception()
                response = render_to_response(template, {'form': form,},
                    context_instance=RequestContext(request))

        else:
            ip_address = get_goodcrypto_private_server_ip(request)
            if ip_address is not None and len(ip_address) > 0:
                exim_form = forms.PrepEximForm(initial={'goodcrypto_private_server_ip': ip_address})
            else:
                exim_form = forms.PrepEximForm()
            response = render_to_response(template, {'exim_form': exim_form},
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
        log_message('EXCEPTION - see syr.exception.log for details')
        response = HttpResponsePermanentRedirect('/')

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

    log.write_and_flush(message)


