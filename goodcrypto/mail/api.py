'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-04-16

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import json, os
from traceback import format_exc

from django.shortcuts import render_to_response
from django.template import RequestContext
from django.http import HttpResponsePermanentRedirect

from goodcrypto import api_constants
from goodcrypto.mail import contacts, options
from goodcrypto.mail.forms import APIForm
from goodcrypto.mail.utils import get_mail_status, create_superuser
from goodcrypto.oce.utils import format_fingerprint
from goodcrypto.utils.log_file import LogFile
from syr.utils import get_remote_ip, strip_input



class MailAPI(object):
    '''Handle the API for GoodCrypto Mail.'''
    
    def __init__(self):
        self.log = None
        
    def interface(self, request):
        '''Interface with the server through the API.
        
           All requests must be via a POST.
        '''
    
        # final results and error_messages of the actions
        result = None
        
        ok = False
        response = None
    
        try:
            self.action = self.domain = self.mail_server_address = None
            self.public_key = self.encryption_name = self.email = self.fingerprint = None
            self.user_name = self.sysadmin = self.password = None
            self.ip = get_remote_ip(request)
            self.log_message('attempting mail api call from {}'.format(self.ip))

            if request.method == 'POST':
                try:
                    form = APIForm(request.POST)
                    if form.is_valid():
                        cleaned_data = form.cleaned_data

                        self.action = cleaned_data.get(api_constants.ACTION_KEY)
                        self.log_message('action: {}'.format(self.action))
                        if self.action == api_constants.CREATE_SUPERUSER:
                            self.sysadmin = strip_input(cleaned_data.get(api_constants.SYSADMIN_KEY))
                            self.log_message('sysadmin: {}'.format(self.sysadmin))
                        elif self.action == api_constants.CONFIGURE:
                            self.domain = strip_input(cleaned_data.get(api_constants.DOMAIN_KEY))
                            self.log_message('domain: {}'.format(self.domain))
                            self.mail_server_address = strip_input(cleaned_data.get(api_constants.MTA_ADDRESS_KEY))
                            self.log_message('mail_server_address: {}'.format(self.mail_server_address))
                        elif self.action == api_constants.GET_FINGERPRINT:
                            self.encryption_name = strip_input(cleaned_data.get(api_constants.ENCRYPTION_NAME_KEY))
                            self.log_message('encryption_name: {}'.format(self.encryption_name))
                            self.email = strip_input(cleaned_data.get(api_constants.EMAIL_KEY))
                            self.log_message('email: {}'.format(self.email))
                            self.password = strip_input(cleaned_data.get(api_constants.PASSWORD_KEY))
                        elif self.action == api_constants.IMPORT_KEY:
                            self.public_key = strip_input(cleaned_data.get(api_constants.PUBLIC_KEY))
                            self.encryption_name = strip_input(cleaned_data.get(api_constants.ENCRYPTION_NAME_KEY))
                            self.log_message('encryption_name: {}'.format(self.encryption_name))
                            self.fingerprint = strip_input(cleaned_data.get(api_constants.FINGERPRINT_KEY))
                            self.log_message('fingerprint: {}'.format(self.fingerprint))
                            self.user_name = strip_input(cleaned_data.get(api_constants.USER_NAME_KEY))
                            self.log_message('user_name: {}'.format(self.user_name))
                            self.sysadmin = strip_input(cleaned_data.get(api_constants.SYSADMIN_KEY))
                            self.log_message('sysadmin: {}'.format(self.sysadmin))
                            self.password = strip_input(cleaned_data.get(api_constants.PASSWORD_KEY))
                        elif self.action == api_constants.GET_CONTACT_LIST:
                            self.encryption_name = strip_input(cleaned_data.get(api_constants.ENCRYPTION_NAME_KEY))
                            self.log_message('encryption_name: {}'.format(self.encryption_name))
                            self.sysadmin = strip_input(cleaned_data.get(api_constants.SYSADMIN_KEY))
                            self.log_message('sysadmin: {}'.format(self.sysadmin))
                            self.password = strip_input(cleaned_data.get(api_constants.PASSWORD_KEY))

                        result = self.take_api_action()
    
                    else:
                        result = self.format_bad_result('Invalid form')
                        self.log_attempted_access(result)
                
                        self.log_message('api form is not valid')
                        self.log_bad_form(request, form)
                    
                except:
                    result = self.format_bad_result('Unknown error')
                    self.log_attempted_access(result)

                    self.log_message(format_exc())
                    self.log_message('unexpected error while parsing input')
            else:
                self.log_attempted_access('Attempted GET connection')
                
                self.log_message('redirecting api GET request to website')
                response = HttpResponsePermanentRedirect('/')
                        
            if response is None:
                response = self.get_api_response(request, result)
                
        except:
            self.log_message(format_exc())
            response = HttpResponsePermanentRedirect('/')
    
        return response
    
    
    def take_api_action(self):
    
        result = None
        
        ok, error_message = self.is_data_ok()
        if ok:
            if self.action == api_constants.CONFIGURE:
                mail_options = options.get_options()
                mail_options.domain = self.domain
                mail_options.mail_server_address = self.mail_server_address
                options.save_options(mail_options)
                result = self.format_result(api_constants.CONFIGURE, ok)
                self.log_message('configure result: {}'.format(result))

            elif self.action == api_constants.CREATE_SUPERUSER:
                password, error_message = create_superuser(self.sysadmin)
                if password is None:
                    result = self.format_bad_result(error_message)
                else:
                    result = self.format_message_result(api_constants.CREATE_SUPERUSER, ok, password)
                self.log_message('create user result: {}'.format(result))

            elif self.action == api_constants.STATUS:
                result = self.format_result(api_constants.STATUS, get_mail_status())
                self.log_message('status result: {}'.format(result))
                
            elif self.action == api_constants.IMPORT_KEY:
                from goodcrypto.mail.views import import_key_now
                
                result_ok, status, fingerprint_ok = import_key_now(
                    self.encryption_name, self.public_key, self.user_name, self.fingerprint)
                if result_ok:
                    __, email = status.split(':')
                    result = self.format_message_result(api_constants.IMPORT_KEY, True, email)
                else:
                    result = self.format_bad_result(status)
                self.log_message('import key result: {}'.format(result))

            elif self.action == api_constants.GET_CONTACT_LIST:
                
                email_addresses = contacts.get_contact_list(self.encryption_name)
                addresses = '\n'.join(email_addresses)
                result = self.format_message_result(api_constants.GET_CONTACT_LIST, True, addresses)
                self.log_message('{} {} contacts found'.format(len(email_addresses), self.encryption_name))

            elif self.action == api_constants.GET_FINGERPRINT:
                
                fingerprint, verified, active = contacts.get_fingerprint(self.email, self.encryption_name)
                if fingerprint is None:
                    ok = False
                    error_message = 'No {} fingerprint for {}'.format(self.encryption_name, self.email)
                    result = self.format_bad_result(error_message)
                    self.log_message('bad result: {}'.format(result))
                else:
                    message = 'Fingerprint {} verified: {}'.format(format_fingerprint(fingerprint), verified)
                    result = self.format_message_result(api_constants.GET_FINGERPRINT, True, message)
                    self.log_message(message)

            else:
                ok = False
                error_message = 'Bad action: {}'.format(self.action)
                result = self.format_bad_result(error_message)
                self.log_message('bad action result: {}'.format(result))
    
        else:
            result = self.format_bad_result(error_message)
            self.log_message('data is bad')

        return result
    
    def is_data_ok(self):
        '''Check if all the required data is present.'''
        
        error_message = ''
        ok = False
        
        if self.has_content(self.action):
            if self.action == api_constants.CONFIGURE:
                if self.has_content(self.domain) and self.has_content(self.mail_server_address):
                    ok = True
                    self.log_message('minimum configure data found')

            elif self.action == api_constants.CREATE_SUPERUSER:
                if self.has_content(self.sysadmin):
                    ok = True
                    self.log_message('minimum create user data found: {}'.format(self.sysadmin))

            elif self.action == api_constants.STATUS:
                ok = True
                self.log_message('status request found')

            elif self.action == api_constants.GET_FINGERPRINT:
                if (self.has_content(self.encryption_name) and 
                    self.has_content(self.email)):
                    ok = True
                    self.log_message('minimum get fingerprint data found')

            elif self.action == api_constants.IMPORT_KEY:
                if (self.has_content(self.public_key) and 
                    self.has_content(self.encryption_name) and 
                    self.has_content(self.sysadmin) and
                    self.has_content(self.password)):
                    ok = True
                    self.log_message('minimum import key data found')

            elif self.action == api_constants.GET_CONTACT_LIST:
                if (self.has_content(self.encryption_name) and 
                    self.has_content(self.sysadmin) and
                    self.has_content(self.password)):
                    ok = True
                    self.log_message('minimum get contact list data found')

            if not ok:
                error_message = 'Missing required data'
                self.log_message('missing required data')

        else:
            ok = False
            error_message = 'Missing required action'
            self.log_message('missing required action')
            
        return ok, error_message

    def has_content(self, value):
        '''Check that the value has content.'''
        
        try:
            str_value = str(value)
            if str_value is None or len(str_value.strip()) <= 0:
                ok = False
            else:
                ok = True
        except:
            ok = False
            self.log_message(format_exc())
            
        return ok
            
    def format_result(self, action, ok, error_message=None):
        '''Format the action's result.'''
    
        if error_message is None:
            result = {api_constants.ACTION_KEY: action, api_constants.OK_KEY: ok}
        else:
            result = {
              api_constants.ACTION_KEY: action, 
              api_constants.OK_KEY: ok, 
              api_constants.ERROR_KEY: error_message
            }
            
        return result
        
    def format_message_result(self, action, ok, message):
        '''Format the action's result.'''
    
        result = {
          api_constants.ACTION_KEY: action, 
          api_constants.OK_KEY: ok, 
          api_constants.MESSAGE_KEY: message
        }
            
        return result

    def format_bad_result(self, error_message):
        '''Format the bad result for the action.'''
        
        result = None
        
        if self.action and len(self.action) > 0:
            result = self.format_result(self.action, False, error_message=error_message)
        else:
            result = self.format_result('Unknown', False, error_message=error_message)
            
        self.log_message('action result: {}'.format(error_message))
    
        return result
        
    
    def get_api_response(self, request, result):
        ''' Get API reponse as JSON. '''

        json_result = json.dumps(result)
        self.log_message('json results: {}'.format(''.join(json_result)))
    
        response = render_to_response('mail/api_response.html',
            {'result': ''.join(json_result),}, 
            context_instance=RequestContext(request))
        
        return response
    
    
    def log_attempted_access(self, results):
        '''Log an attempted access to the api.'''
     
        self.log_message('attempted access from {} for {}'.format(self.ip, results))
        
    def log_bad_form(self, request, form):
        ''' Log the bad fields entered.'''
        
        # see django.contrib.formtools.utils.security_hash()
        # for example of form traversal
        for field in form:
            if (hasattr(form, 'cleaned_data') and 
                field.name in form.cleaned_data):
                name = field.name
            else:
                # mark invalid data
                name = '__invalid__' + field.name
            self.log_message('name: {}; data: {}'.format(name, field.data))
        try:
            if form.name.errors:
                self.log_message('  ' + form.name.errors)
            if form.email.errors:
                self.log_message('  ' + form.email.errors)
        except:
            pass
    
        self.log_message('logged bad api form')

    def log_message(self, message):
        '''
            Log the message to the local log.
            
            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> MailAPI().log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.api.log'))
            True
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

