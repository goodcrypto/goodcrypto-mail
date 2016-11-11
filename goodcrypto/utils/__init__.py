'''
    GoodCrypto utilities.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-11-03

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from __future__ import unicode_literals

# goodcrypto.specs still runs under python2
import sys
IS_PY2 = sys.version_info[0] == 2

import os, re
from datetime import datetime, timedelta
from email.utils import parseaddr
if IS_PY2:
    from urlparse import urljoin, urlparse
else:
    from urllib.parse import urlparse

from django.core.exceptions import ValidationError
from django.core.validators import EmailValidator

from goodcrypto.constants import TIMESTAMP_PATH
from syr.exception import record_exception
from syr.net import hostaddress
from syr.times import one_month_before
from syr.utils import trim
from syr.log import get_log

log = get_log()

def show_template(request, original_url, prefix='', params={}):
    '''Render a plain html file and cache the results.'''

    def show_regular_url(base_url, params):
        try:
            response = show_url(base_url, params=params)
        except:
            if base_url.find('.html') > 0:
                response = None
                record_exception()
            else:
                try:
                    response = show_url(base_url, '.html', params=params)
                except TemplateDoesNotExist:
                    response = try_home_index(base_url, params=params)

        return response

    def show_url(base_url, suffix='', params={}):

        template = base_url + suffix
        if template.endswith('.log') or template.endswith('.java'):
            return wrap_raw(request, template)
        else:
            return render(request, template, params)

    def try_home_index(base_url, params=params):
        try:
            response = show_url(os.path.join(base_url, 'home.html'), params=params)
            if response is None:
                response = show_url(os.path.join(base_url, 'index.html'), params=params)
        except TemplateDoesNotExist:
            response = show_url(os.path.join(base_url, 'index.html'), params=params)
        return response

    # import late so apps that don't require django, don't require
    # DJANGO_SETTINGS_MODULE just because this class is imported
    from django.http import Http404, HttpResponse
    from django.shortcuts import render
    from django.template import TemplateDoesNotExist

    response = None

    try:
        # some browsers add a slash, even to .html files
        if original_url.endswith('.html/'):
            orignal_url = original_url[:len(original_url)-1]

        u = urlparse(original_url)
        base_url = u.path
        if params is None or len(params) < 1:
            params = u.params

        if prefix is not None and len(prefix) > 0:
            if not prefix.endswith('/'):
                prefix += '/'
            if base_url.startswith('/'):
                base_url = base_url[1:]
            base_url = prefix + base_url
        if base_url.startswith('/'):
            base_url = base_url[1:]

        if base_url.endswith('/'):
            try:
                response = try_home_index(base_url, params=params)
            except TemplateDoesNotExist:
                url = base_url[:-1]
                response = show_url(url, '.html', params=params)

        else:
            # ignore font urls
            m = re.match('.*?fonts/(.*)', base_url)
            if m:
                response = HttpResponse('')
            else:
                response = show_regular_url(base_url, params)
    except:
        record_exception()

    if response is None:
        log('unable to find template for: %r' % original_url)
        raise Http404(original_url)

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
        >>> name, address = parse_address('Lieutenant <lieutenant@goodcrypto.local>')
        >>> name == 'Lieutenant'
        True
        >>> address == 'lieutenant@goodcrypto.local'
        True
    '''

    try:
        if email is None:
            name = address = None
        else:
            (name, address) = parseaddr(email)
            if charset is not None and name is not None:
                try:
                    name = name.decode(charset, 'replace')
                except Exception:
                    record_exception()
            try:
                email_validator = EmailValidator()
                email_validator(address)
            except ValidationError as validator_error:
                log('{} invalid: {}'.format(email, validator_error))
                name = address = None
    except Exception:
        record_exception()
        name = address = None

    return name, address

def get_email(address):
    '''
        Get just the email address.

        >>> # In honor of First Sergeant Nadav, who publicly denounced and refused to serve in
        >>> # operations involving the occupied Palestinian territories because of the widespread
        >>> # surveillance of innocent residents.
        >>> email = get_email('Nadav <nadav@goodcrypto.remote>')
        email == 'nadav@goodcrypto.remote'
        True
    '''
    try:
        if not isinstance(address, str):
            address = address.decode()
        __, email = parse_address(address)
    except Exception:
        email = address

    return email

def i18n(raw_message):
    '''
        Convert a raw message to an internationalized string.

        >>> msg = i18n('Test message')
        msg == 'Test message'
        True
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
        iso_timestamp = one_month_before(datetime.utcnow()).isoformat(str(' '))

    return iso_timestamp.strip()

