'''
    GoodCrypto utilities.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-10-07

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, re, sh
from datetime import datetime, timedelta
from email.utils import parseaddr
from socket import inet_pton, AF_INET, AF_INET6

from goodcrypto.constants import TIMESTAMP_PATH
from goodcrypto.utils.exception import record_exception
from syr.net import hostaddress
from syr.times import one_month_before
from syr.utils import trim
from syr.log import get_log

log = get_log()

def show_template(request, original_url, prefix='', params={}):
    '''Render a plain html file and cache the results.'''

    def show_url(base_url, suffix=''):

        template = base_url + suffix
        if template.endswith('.log') or template.endswith('.java'):
            return wrap_raw(request, template)
        else:
            return render(request, template, params)

    def try_home_index(base_url):
        try:
            response = show_url(os.path.join(base_url, 'home.html'))
        except TemplateDoesNotExist:
            response = show_url(os.path.join(base_url, 'index.html'))
        return response

    # import late so apps that don't require django, don't require
    # DJANGO_SETTINGS_MODULE just because this class is imported
    from django.http import Http404
    from django.shortcuts import render
    from django.template import TemplateDoesNotExist

    response = None

    try:
        # some browsers add a slash, even to .html files
        if original_url.endswith('.html/'):
            orignal_url = original_url[:len(original_url)-1]
        base_url = original_url
        if len(prefix) > 0:
            if not prefix.endswith('/'):
                prefix += '/'
            if base_url.startswith('/'):
                base_url = base_url[1:]
            base_url = prefix + base_url
        if base_url.startswith('/'):
            base_url = original_url[1:]

        if base_url.endswith('/'):
            try:
                response = try_home_index(base_url)
            except TemplateDoesNotExist:
                url = base_url[:-1]
                response = show_url(url, '.html')

        else:
            try:
                response = show_url(base_url)
            except:
                if base_url.find('.html') > 0:
                    record_exception()
                else:
                    try:
                        response = show_url(base_url, '.html')
                    except TemplateDoesNotExist:
                        response = try_home_index(base_url)
    except:
        record_exception()

    if response is None:
        log('unable to find template for: %r' % original_url)
        raise Http404, original_url

    return response


def debug_logs_enabled():
    '''
       Get whether to enable mail debug logs.
       This routine is used in OCE which might not have access to the mail app
       so the function is in the package instead of mail.

       >>> debug_logs_enabled()
       True
    '''


    try:
        from goodcrypto.mail import options

        debugging_enabled = options.debug_logs_enabled()
    except Exception:
        debugging_enabled = True

    return debugging_enabled

def is_mta_ok(mail_server_address):
    '''
        Verify the MTA is ok.

        Test extreme cases
        >>> is_mta_ok(None)
        False
    '''

    """
    from smtplib import SMTP, SMTP_SSL
    def smtp_connection_ok(self, mta):
        '''
            Try to connect to the MTA via SMTP and SMTP_SSL.
        '''

        connection_ok = False
        try:
            smtp = SMTP(host=mta)
            smtp.quit()
            connection_ok = True
        except:
            connection_ok = False

        if not connection_ok:
            try:
                smtp = SMTP_SSL(host=mta)
                smtp.quit()
                connection_ok = True
            except:
                connection_ok = False

        return connection_ok
    """

    ok = False

    # the mail_server_address should either be an ip address or a domain
    if mail_server_address is not None:
        mail_server_address = mail_server_address.strip()
        try:
            inet_pton(AF_INET, mail_server_address)
            ok = True
            log('mail server address IP4 compliant: {}'.format(ok))
        except:
            ok = False
            record_exception()

        if not ok:
            try:
                inet_pton(AF_INET6, mail_server_address)
                ok = True
                log('mail server address IP6 compliant: {}'.format(ok))
            except:
                match = re.search("^[\u00c0-\u01ffa-zA-Z0-9'\-\.]+$", mail_server_address)
                if match:
                    ok = True
                log('mail server address ok: {}'.format(ok))

    return ok

def get_ip_address(request=None):
    ''' Get the ip address from the request or return None. '''

    ip_address = None
    try:
        ip_address = hostaddress()
        if (ip_address is None or
            ip_address == '127.0.0.1' or
            ip_address == '10.0.2.2' or
            ip_address == '10.0.2.15'):
            if request and 'HTTP_X_REAL_IP' in request.META:
                ip_address = request.META['HTTP_X_REAL_IP']
            elif request and 'HTTP_X_FORWARDED_FOR' in request.META:
                ip_address = request.META['HTTP_X_FORWARDED_FOR']
            elif request and 'REMOTE_ADDR' in request.META:
                ip_address = request.META['REMOTE_ADDR']
            else:
                ip_address = None

        if ip_address == '127.0.0.1' or ip_address == '10.0.2.2' or ip_address == '10.0.2.15':
            ip_address = None

        if request and 'HTTP_X_REAL_IP' in request.META:
            log('x-real-ip address: {}'.format(request.META['HTTP_X_REAL_IP']))
        if request and 'HTTP_X_FORWARDED_FOR' in request.META:
            log('x-forwarded-for address: {}'.format(request.META['HTTP_X_FORWARDED_FOR']))
        if request and 'REMOTE_ADDR' in request.META:
            log('remote address: {}'.format(request.META['REMOTE_ADDR']))
    except:
        record_exception()

    log('ip address: {}'.format(ip_address))

    return ip_address

def parse_address(email, charset=None):
    '''
        Parse an email address into its name and address.

        >>> # In honor of Lieutenant Yonatan, who publicly denounced and refused to serve in operations involving
        >>> # the occupied Palestinian territories because of the widespread surveillance of innocent residents.
        >>> parse_address('Lieutenant <lieutenant@goodcrypto.local>')
        ('Lieutenant', 'lieutenant@goodcrypto.local')
    '''

    try:
        if email is None:
            name = None
            address = None
        else:
            (name, address) = parseaddr(email)
            if charset is not None and name is not None:
                try:
                    name = name.decode(charset, 'replace')
                except Exception:
                    record_exception()
    except Exception:
        record_exception()
        name = None
        address = None

    return name, address

def parse_domain(email):
    '''
        Get the domain from the email address.

        >>> domain = parse_domain(None)
        >>> domain is None
        True
    '''

    domain = None

    if email is None:
        log('email not defined so no domain')
    else:
        try:
            address = get_email(email)
            __, __, domain = address.partition('@')
        except:
            record_exception()

    return domain

def get_email(address):
    '''
        Get just the email address.

        >>> # In honor of First Sergeant Nadav, who publicly denounced and refused to serve in
        >>> # operations involving the occupied Palestinian territories because of the widespread
        >>> # surveillance of innocent residents.
        >>> get_email('Nadav <nadav@goodcrypto.remote>')
        'nadav@goodcrypto.remote'
    '''
    try:
        __, email = parse_address(address)
    except Exception:
        email = address

    return email

def i18n(raw_message):
    '''
        Convert a raw message to an internationalized string.

        >>> i18n('Test message')
        'Test message'
        >>> i18n('Test with variable: {variable}'.format(variable='test variable'))
        'Test with variable: test variable'
        >>> i18n(u'Test with variable: {variable}'.format(variable='test variable'))
        u'Test with variable: test variable'
    '''

    """
    try:
        from django.utils.translation import ugettext_lazy

        unicode_message = ugettext_lazy(raw_message)
        try:
            message = '{}'.format(unicode_message)
        except:
            message = unicode_message
            record_exception()
            log('trying to internationalize: {}'.format(raw_message))
    except:
        message = raw_message
        record_exception()
        log('trying to internationalize: {}'.format(raw_message))
    """
    message = raw_message

    return message

def get_iso_timestamp():
    '''
        Get the timestamp ISO was created.

        >>> get_iso_timestamp() is not None
        True
    '''

    iso_timestamp = None
    if os.path.exists(TIMESTAMP_PATH):
        with open(TIMESTAMP_PATH) as f:
            iso_timestamp = f.read()

    if iso_timestamp is None:
        iso_timestamp = one_month_before(datetime.utcnow()).isoformat(' ')

    return iso_timestamp.strip()

