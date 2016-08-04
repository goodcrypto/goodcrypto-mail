'''
    Mail app forms.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-11-11

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from django import forms
from django.forms.widgets import HiddenInput
from django.core.exceptions import ValidationError

from goodcrypto import api_constants
from goodcrypto.mail import models
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.options import mta_listen_port
from goodcrypto.mail.utils import config_dkim
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.utils.log_file import LogFile
from goodcrypto.utils import i18n, is_mta_ok
from reinhardt.admin_extensions import RequireOneFormSet

_log = LogFile()


class EncryptionSoftwareForm(forms.ModelForm):

    def clean(self):
        cleaned_data = super(EncryptionSoftwareForm, self).clean()

        name = cleaned_data.get('name')
        classname = cleaned_data.get('classname')
        crypto = CryptoFactory.get_crypto(name, classname)
        if not crypto or not crypto.is_available():
            error_message = i18n('{encryption} is not available.'.format(encryption=name))
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
        fields = ['contact', 'encryption_software', 'fingerprint', 'verified', 'active']

    class Media:
        js = ('/static/js/admin_js.js',)

class OptionsAdminForm(forms.ModelForm):

    def clean(self):
        '''Verify there is only 1 general info record.'''

        error = None

        cleaned_data = super(OptionsAdminForm, self).clean()

        # the mail_server_address should either be an ip address or a domain
        mail_server_address = cleaned_data.get('mail_server_address')
        if is_mta_ok(mail_server_address):
            _log.write('mail server address ok')
            self.cleaned_data['mail_server_address'] = mail_server_address
        else:
            del self.cleaned_data['mail_server_address']
            _log.write('deleted mail server address from cleaned data')

            if mail_server_address is None or len(mail_server_address.strip()) <= 0:
                error_message = i18n('You need to define the mail server address (MTA).')
            else:
                error_message = i18n('The mail server address contains one or more bad characters or spaces.')
            _log.write(error_message)

            raise forms.ValidationError(error_message, code='invalid')

        encrypt_metadata = cleaned_data.get('encrypt_metadata')
        bundle_and_pad = cleaned_data.get('bundle_and_pad')
        if bundle_and_pad and not encrypt_metadata:
            del self.cleaned_data['encrypt_metadata']
            _log.write('deleted encrypt_metadata from cleaned data')
            del self.cleaned_data['bundle_and_pad']
            _log.write('deleted bundle_and_pad from cleaned data')

            error_message = i18n('You can only bundle and pad messages if you also encrypt metadata. Either add a check mark to "Encrypt metadata" or remove the check mark from "Bundle and pad".')
            _log.write(error_message)

            raise forms.ValidationError(error_message, code='invalid')

        add_dkim_sig = cleaned_data.get('add_dkim_sig')
        dkim_public_key = cleaned_data.get('dkim_public_key')
        if add_dkim_sig:
            if not dkim_public_key or len(dkim_public_key.strip()) <= 0:
                config_dkim.start(get_domain())
                _log.write('starting to configure dkim')

        return cleaned_data

    class Meta:
        model = models.Options
        fields = [
                  'mail_server_address',
                  'goodcrypto_server_url',
                  'auto_exchange',
                  'create_private_keys',
                  'clear_sign',
                  'require_key_verified',
                  'login_to_view_fingerprints',
                  'login_to_export_keys',
                  'filter_html',
                  'debugging_enabled',
                  'encrypt_metadata',
                  'bundle_and_pad',
                  'bundle_frequency',
                  'bundle_message_kb',
                  'add_dkim_sig',
                  'verify_dkim_sig',
                  'dkim_delivery_policy',
                  'dkim_public_key',
        ]

    """
    class Media:
        js = ('/static/js/admin_js.js',)
    """

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
            raise ValidationError(i18n('You must include at least one encryption program for this contact.'))

class GetFingerprintForm(forms.Form):

    email = forms.EmailField(max_length=254,
       help_text=i18n('Enter the email address whose fingerprint you want to verify.'),)
    encryption_software = forms.ModelChoiceField(
       queryset=models.EncryptionSoftware.objects.filter(active=True), empty_label=None,
       help_text=i18n('Select the encryption software for the key.'),)


class VerifyFingerprintForm(forms.Form):

    email = forms.EmailField(max_length=254, widget=HiddenInput,)
    encryption_name = forms.CharField(max_length=100, widget=HiddenInput,)
    key_id = forms.CharField(max_length=100, widget=HiddenInput,)
    verified = forms.BooleanField(required=False,
       help_text=i18n('Add a check mark if you checked the fingerprint is correct for the user.'),)


class VerifyMessageForm(forms.Form):

    verification_code = forms.CharField(widget=forms.TextInput(attrs={'size':'{}'.format(
       models.MessageHistory.MAX_VERIFICATION_CODE)}),
       help_text=i18n('Enter the verification code to check if GoodCrypto encrypted or decrypted your message.'),)

class ExportKeyForm(forms.Form):

    email = forms.EmailField(max_length=254,
       help_text=i18n('Enter the email address whose public key you want exported.'),)
    encryption_software = forms.ModelChoiceField(
       queryset=models.EncryptionSoftware.objects.filter(active=True), empty_label=None,
       help_text=i18n('Select the type of encryption software associated with the key.'),)

MAX_PUBLIC_KEY_FILEZISE = 500000
class ImportKeyForm(forms.Form):

    public_key_file = forms.FileField(max_length=MAX_PUBLIC_KEY_FILEZISE,
       help_text=i18n('Select the file that contains the public key.'),)
    encryption_software = forms.ModelChoiceField(
       queryset=models.EncryptionSoftware.objects.filter(active=True), empty_label=None,
       help_text=i18n('Select the type of encryption software associated with the key.'),)
    user_name = forms.CharField(max_length=100, required=False,
       help_text='Printable name of the contact in case the key does not contain it. Optional.')
    fingerprint = forms.CharField(max_length=100, required=False,
       help_text="The fingerprint for the contact's public key, if known. Optional.")

API_Actions = (
    (api_constants.STATUS, api_constants.STATUS),
    (api_constants.CONFIGURE, api_constants.CONFIGURE),
    (api_constants.CREATE_SUPERUSER, api_constants.CREATE_SUPERUSER),
    (api_constants.IMPORT_KEY, api_constants.IMPORT_KEY),
    (api_constants.GET_FINGERPRINT, api_constants.GET_FINGERPRINT),
    (api_constants.GET_CONTACT_LIST, api_constants.GET_CONTACT_LIST),
)

class APIForm(forms.Form):
    '''Handle a command through the API.'''

    action = forms.ChoiceField(required=False,
       choices=API_Actions,
       error_messages={'required': i18n('You must select an action.')})

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

