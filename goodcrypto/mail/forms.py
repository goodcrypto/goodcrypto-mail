'''
    Mail app forms.

    Copyright 2014 GoodCrypto
    Last modified: 2014-12-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from traceback import format_exc

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import ugettext_lazy as _
from smtplib import SMTP, SMTP_SSL

from goodcrypto import api_constants
from goodcrypto.mail import models
from goodcrypto.mail.options import get_domain
from goodcrypto.mail.utils import email_in_domain, gen_passcode
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.utils.log_file import LogFile
from reinhardt.admin_extensions import RequireOneFormSet

_log = LogFile()


class EncryptionSoftwareForm(forms.ModelForm):

    def clean(self):
        cleaned_data = super(EncryptionSoftwareForm, self).clean()
        
        name = cleaned_data.get('name')
        classname = cleaned_data.get('classname')
        crypto = CryptoFactory.get_crypto(name, classname)
        if not crypto or not crypto.is_available():
            error_message = _('{encryption} is not available.').format(encryption=name)
            _log.write(error_message)
            raise ValidationError(error_message)

        return cleaned_data

    class Meta:
        model = models.EncryptionSoftware
        fields = ['name', 'active', 'classname']

    class Media:
        js = ('/static/js/admin_js.js',)

class ContactAdminForm(forms.ModelForm):
    
    class Meta:
        model = models.Contact
        fields = ['email', 'user_name']

    class Media:
        js = ('/static/js/admin_js.js',)

class ContactsCryptoAdminForm(forms.ModelForm):
    
    class Meta:
        model = models.ContactsCrypto
        fields = ['contact', 'encryption_software', 'fingerprint', 'verified']

    class Media:
        js = ('/static/js/admin_js.js',)

class ContactsPasscodeAdminForm(forms.ModelForm):
    
    def clean(self):
        '''
            Clean data for a contact's passcode.
        
            >>> # In honor of Kirk Wiebe, a whistleblower about Trailblazer, an NSA mass surveillance project.
            >>> from goodcrypto.mail.model_signals import TESTS_RUNNING
            >>> TESTS_RUNNING = True
            >>> gpg = models.EncryptionSoftware.objects.create(
            ...   name='TestKirkGPG', active=True, classname='goodcrypto.oce.gpg_plugin.GPGPlugin')
            >>> contact = models.Contact.objects.create(email='kirk@goodcrypto.remote')
            >>> contacts_crypto = models.ContactsCrypto.objects.create(contact=contact, encryption_software=gpg)
            >>> contacts_passcode = models.ContactsPasscode.objects.create(contacts_encryption=contacts_crypto)
            >>> form = ContactsPasscodeAdminForm(instance=contacts_passcode)
            >>> form.clean()
            Traceback (most recent call last):
                ...
            ValidationError: [u'kirk@goodcrypto.remote does not use the goodcrypto.local domain so unable to create a private key.']
            >>> contact.delete()
            >>> gpg.delete()
            >>> TESTS_RUNNING = False
            
            >>> # In honor of Captain D, who co-signed letter and refused to serve in operations involving 
            >>> # the occupied Palestinian territories because of the widespread surveillance of innocent residents.
            >>> from goodcrypto.mail.model_signals import TESTS_RUNNING
            >>> TESTS_RUNNING = True
            >>> gpg = models.EncryptionSoftware.objects.create(
            ...   name='TestDGPG', active=True, classname='goodcrypto.oce.gpg_plugin.GPGPlugin')
            >>> contact = models.Contact.objects.create(email='captain.d@goodcrypto.local')
            >>> contacts_crypto = models.ContactsCrypto.objects.create(contact=contact, encryption_software=gpg)
            >>> contacts_passcode = models.ContactsPasscode.objects.create(contacts_encryption=contacts_crypto, 
            ...  passcode=None, auto_generated=False)
            >>> form = ContactsPasscodeAdminForm(instance=contacts_passcode)
            >>> form.clean()
            Traceback (most recent call last):
                ...
            ValidationError: [u''You must enter a passcode or add a check mark to "Auto generate" it.']
            >>> contact.delete()
            >>> gpg.delete()
            >>> TESTS_RUNNING = False
        '''

        cleaned_data = super(ContactsPasscodeAdminForm, self).clean()

        contacts_encryption = cleaned_data.get('contacts_encryption')
        auto_generated = cleaned_data.get('auto_generated')
        passcode = cleaned_data.get('passcode')

        # we can only create passcodes for users with supported domain
        if contacts_encryption is not None and contacts_encryption.contact is not None:
            email = contacts_encryption.contact.email
            if not email_in_domain(email):
                error_message = _('{email} does not use the {domain} domain so unable to create a private key.').format(
                    email=email, domain=get_domain())
                _log.write(error_message)
                raise ValidationError(error_message)
            else:
                _log.write('email is ok')
        else:
            _log.write('contact encryption is None')
            
        # generate the passcode if none was provide and we're allowed to generate one
        if auto_generated and (passcode is None or len(passcode.strip()) <= 0):
            passcode = gen_passcode()
            _log.write('generated a passcode')
            cleaned_data['passcode'] = passcode

        if passcode is None or len(passcode.strip()) <= 0:
            error_message = _('You must enter a passcode or add a check mark to "Auto generate" it.')
            _log.write(error_message)
            raise ValidationError(error_message)
        else:
            _log.write('passcode is ok')

        return cleaned_data

    class Meta:
        model = models.ContactsPasscode
        fields = ['contacts_encryption', 
                  'passcode', 
                  'auto_generated', 
                  'expires_in', 
                  'expiration_unit', 
                  'last_notified']
    
    class Media:
        js = ('/static/js/admin_js.js',)


class OptionsAdminForm(forms.ModelForm):

    def smtp_connection_ok(self, mta, mta_listen_port):
        '''
            Try to connect to the MTA via SMTP and SMTP_SSL.
        '''
        
        connection_ok = False
        try:
            smtp = SMTP(host=mta, port=mta_listen_port)
            smtp.quit()
            connection_ok = True
        except:
            connection_ok = False

        if not connection_ok:
            try:
                smtp = SMTP_SSL(host=mta, port=mta_listen_port)
                smtp.quit()
                connection_ok = True
            except:
                connection_ok = False
            
        return connection_ok

    def clean(self):
        '''Verify there is only 1 general info record.'''

        error = None
        
        cleaned_data = super(OptionsAdminForm, self).clean()
        # the domain should always be lower case
        domain = cleaned_data.get('domain')
        if domain is not None:
            cleaned_data['domain'] = domain.lower()
        
        # the MTA IP or domain
        mail_server_address = cleaned_data.get('mail_server_address')
        if mail_server_address is not None and len(mail_server_address.strip()) > 0:
            mta_listen_port = cleaned_data.get('mta_listen_port')
            if not self.smtp_connection_ok(mail_server_address, mta_listen_port):
                raise ValidationError(_('Unable to connect to the mail transport agent (MTA) via port {mta_port}.').format(
                    mta_port=mta_listen_port))

        # if we're adding a record
        if self.adding:
            try:
                records = models.Options.objects.all()
                if records and len(records) > 0:
                    raise ValidationError(_('You may only have one mail options record. Either change the current record or delete it before adding.'))
            except models.Options.DoesNotExist:
                pass

        return cleaned_data

    class Meta:
        model = models.Options
        fields = ['domain', 
                  'mail_server_address', 
                  'auto_exchange', 
                  'create_private_keys', 
                  'clear_sign',
                  'filter_html', 
                  'max_message_length', 
                  'debugging_enabled',
        ]


class ContactsCryptoInlineFormSet(RequireOneFormSet):
 
    def clean(self):
        
        super(ContactsCryptoInlineFormSet, self).clean()
        for error in self.errors:
            if error:
                _log.write('errors %r' % error)
                return

        # 1 contact encryption records required and allowed
        good_programs = 0

        deleted_forms = self.deleted_forms
        total_forms = self.total_form_count()
        _log.write('total forms: %r' % total_forms)
        _log.write('deleted forms: %r' % deleted_forms)
        for i in range(0, total_forms):
            form = self.forms[i]
            if form not in deleted_forms:
                for key in form.cleaned_data.keys():
                    _log.write('key: {}'.format(key))
                    if (key == 'encryption_software' and len(str(form.cleaned_data[key])) > 0):
                        good_programs += 1
                        _log.write('good contact encryption program: %r' % form.cleaned_data[key])

        _log.write('total good contact encryption programs: {}'.format(good_programs))
        if good_programs < 1:
            raise ValidationError(_('You must include at least one encryption program for this contact.'))

class FingerprintForm(forms.Form):
    
    email = forms.EmailField(max_length=254,
       help_text=_('Enter the email address whose fingerprint you want to verify.'),)
    encryption_software = forms.ModelChoiceField(
       queryset=models.EncryptionSoftware.objects.filter(active=True), empty_label=None,
       help_text=_('Select the encryption software for the key.'),)


class ExportKeyForm(forms.Form):
    
    email = forms.EmailField(max_length=254,
       help_text=_('Enter the email address whose public key you want exported.'),)
    encryption_software = forms.ModelChoiceField(
       queryset=models.EncryptionSoftware.objects.filter(active=True), empty_label=None,
       help_text=_('Select the type of encryption software associated with the key.'),)


class ImportKeyForm(forms.Form):
    
    public_key_file = forms.FileField(max_length=500000,
       help_text=_('Select the file that contains the public key.'),)
    encryption_software = forms.ModelChoiceField(
       queryset=models.EncryptionSoftware.objects.filter(active=True), empty_label=None,
       help_text=_('Select the type of encryption software associated with the key.'),)
    user_name = forms.CharField(max_length=100, required=False,
       help_text='Printable name of the contact in case the key does not contain it. Optional.')
    fingerprint = forms.CharField(max_length=100, required=False,
       help_text="The fingerprint for the contact's public key, if known. Optional.")



API_Actions = (
    (api_constants.STATUS, api_constants.STATUS), 
    (api_constants.CONFIGURE, api_constants.CONFIGURE),
    (api_constants.CREATE_USER, api_constants.CREATE_USER),
    (api_constants.IMPORT_KEY, api_constants.IMPORT_KEY),
    (api_constants.GET_FINGERPRINT, api_constants.GET_FINGERPRINT),
    (api_constants.GET_CONTACT_LIST, api_constants.GET_CONTACT_LIST),
)

class APIForm(forms.Form):
    '''Handle a command through the API.'''
    
    action = forms.ChoiceField(required=False, 
       choices=API_Actions,
       error_messages={'required': _('You must select an action.')})
      
    sysadmin = forms.EmailField(required=False)

    password = forms.CharField(max_length=100, required=False)
      
    domain = forms.CharField(max_length=100, required=False)
       
    mail_server_address = forms.CharField(max_length=100, required=False)
       
    goodcrypto_listen_port = forms.IntegerField(required=False)
       
    mta_listen_port = forms.IntegerField(required=False)

    user_name = forms.CharField(max_length=100, required=False)
      
    email = forms.EmailField(required=False)

    fingerprint = forms.CharField(max_length=100, required=False)
       
    encryption_name = forms.CharField(max_length=100, required=False)
      
    public_key = forms.CharField(max_length=100000, required=False)

