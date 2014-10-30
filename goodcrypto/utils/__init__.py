'''
    GoodCrypto utilities.
    
    Copyright 2014 GoodCrypto
    Last modified: 2014-09-30

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import sh
from traceback import format_exc

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
                    log(format_exc())
                else:
                    try:
                        response = show_url(base_url, '.html')
                    except TemplateDoesNotExist:
                        response = try_home_index(base_url)
    except:
        log(format_exc())

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

def is_program_running(search_string):
    '''
        Return whether a program is running.

        >>> is_running('nginx')
        True
        >>> is_running('nothing.is.running')
        False
    '''

    try:
        psgrep_result = sh.psgrep(search_string)
        log('psgrep_result: {}'.format(psgrep_result))
        log('exit code: {}'.format(psgrep_result.exit_code))
        log('stdout: {}'.format(psgrep_result.stdout))
    except sh.ErrorReturnCode as e:
        running = False
        log('got sh error while searching for: {}{}'.format(search_string, e))
    else:
        running = (psgrep_result.exit_code == 0) and (psgrep_result.stdout != '')
    log('{} is running: {}'.format(search_string, running))

    return running


