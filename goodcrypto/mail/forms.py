'''
    Mail app forms.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-02-17

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import re
from django import forms
from django.forms.models import BaseInlineFormSet
from django.forms.widgets import HiddenInput
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address

from goodcrypto import api_constants
from goodcrypto.mail.constants import DEFAULT_KEYSERVER_STATUS, PASSCODE_MAX_LENGTH
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.options import mta_listen_port
from goodcrypto.mail.utils import config_dkim
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.utils import strip_fingerprint
from goodcrypto.utils.log_file import LogFile
from goodcrypto.utils import i18n, is_mta_ok, parse_address
from reinhardt.admin_extensions import ShowOneFormSet

_log = LogFile()

class PrepPostfixForm(forms.Form):
    '''
        Prepare postfix for GoodCrypto.
    '''

    def clean(self):
        cleaned_data = super(PrepPostfixForm, self).clean()

        # clean up simple errors
        goodcrypto_private_server_ip = cleaned_data.get('goodcrypto_private_server_ip')
        if goodcrypto_private_server_ip is not None:
            goodcrypto_private_server_ip = goodcrypto_private_server_ip.strip()
        validate_ipv46_address(goodcrypto_private_server_ip)
        self.cleaned_data['goodcrypto_private_server_ip'] = goodcrypto_private_server_ip

        return cleaned_data

    goodcrypto_private_server_ip = forms.CharField(required=True,
        help_text=i18n("The IP address for your GoodCrypto private server. For example, 194.10.34.1"),)
    main_cf = forms.CharField(required=True,
       widget=forms.Textarea(attrs={'rows':10, 'cols':100, 'class': "input-xlarge"}),
       label='main.cf content',
       help_text=i18n("Paste the full content of your mail server's /etc/postfix/main.cf file."),)
    master_cf = forms.CharField(required=True,
       widget=forms.Textarea(attrs={'rows':10, 'cols':100, 'class': "input-xlarge"}),
       label='master.cf content',
       help_text=i18n("Paste the full content of your mail server's /etc/postfix/master.cf file."),)
    aliases = forms.CharField(required=False,
       widget=forms.Textarea(attrs={'rows':5, 'cols':100, 'class': "input-xlarge"}),
       label='aliases content',
       help_text=i18n("Paste the full content of your mail server's aliases file. Leave blank if you don't use aliases."),)

class PrepEximForm(forms.Form):
    '''
        Prepare exim for GoodCrypto.
    '''

    def clean(self):
        cleaned_data = super(PrepEximForm, self).clean()

        # clean up simple errors
        goodcrypto_private_server_ip = cleaned_data.get('goodcrypto_private_server_ip')
        if goodcrypto_private_server_ip is not None:
            goodcrypto_private_server_ip = goodcrypto_private_server_ip.strip()
        validate_ipv46_address(goodcrypto_private_server_ip)
        self.cleaned_data['goodcrypto_private_server_ip'] = goodcrypto_private_server_ip

        return cleaned_data

    goodcrypto_private_server_ip = forms.CharField(required=True,
        help_text=i18n("The IP address for your GoodCrypto private server. For example, 194.10.34.1"),)
    config_file = forms.CharField(required=False,
       widget=forms.Textarea(attrs={'rows':5, 'cols':100, 'class': "input-xlarge"}),
       label='aliases content',
       help_text=i18n("Paste the full content of your mail server's aliases file. Leave blank if you don't use aliases."),)

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
        from goodcrypto.mail.models import EncryptionSoftware

        model = EncryptionSoftware
        fields = ['name', 'active', 'classname']

    class Media:
        js = ('/static/js/admin_js.js',)

class KeyserverAdminForm(forms.ModelForm):

    def clean(self):
        cleaned_data = super(KeyserverAdminForm, self).clean()

        status = cleaned_data.get('last_status')
        if status is None or len(status) < 0:
            cleaned_data['last_status'] = DEFAULT_KEYSERVER_STATUS

        return cleaned_data

    class Meta:
        from goodcrypto.mail.models import Keyserver

        model = Keyserver
        fields = ['name', 'active', 'last_date', 'last_status']

    class Media:
        js = ('/static/js/admin_js.js',)

class ContactAdminForm(forms.ModelForm):

    class Meta:
        from goodcrypto.mail.models import Contact

        model = Contact
        fields = ['email', 'user_name', 'outbound_encrypt_policy']

    class Media:
        js = ('/static/js/admin_js.js',)

class ContactsCryptoAdminForm(forms.ModelForm):

    class Meta:
        from goodcrypto.mail.models import ContactsCrypto

        model = ContactsCrypto
        fields = ['contact', 'encryption_software', 'fingerprint', 'verified']

    class Media:
        js = ('/static/js/admin_js.js',)

class OptionsAdminForm(forms.ModelForm):

    def clean(self):
        '''Verify there is only 1 general info record.'''

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
        from goodcrypto.mail.models import Options

        model = Options
        fields = [
                  'mail_server_address',
                  'goodcrypto_server_url',
                  #'auto_exchange',
                  #'create_private_keys',
                  'clear_sign',
                  'clear_sign_policy',
                  'require_outbound_encryption',
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

class ContactsCryptoInlineFormSet(BaseInlineFormSet):

    pass
    """
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

        return cleaned_data
    """

class GetFingerprintForm(forms.Form):

    from goodcrypto.mail.models import EncryptionSoftware

    email = forms.EmailField(max_length=254,
       help_text=i18n('Enter the email address whose fingerprint you want to verify.'),)
    encryption_software = forms.ModelChoiceField(
       queryset=EncryptionSoftware.objects.filter(active=True), empty_label=None,
       help_text=i18n('Select the encryption software for the key.'),)


class VerifyFingerprintForm(forms.Form):

    email = forms.EmailField(max_length=254, widget=HiddenInput, required=False,)
    encryption_name = forms.CharField(max_length=100, widget=HiddenInput, required=False,)
    key_id = forms.CharField(max_length=100, widget=HiddenInput, required=False,)
    verified = forms.BooleanField(required=False,
       help_text=i18n('Add a check mark if you confirmed the fingerprint is correct for the user.'),)

class VerifyMessageForm(forms.Form):

    from goodcrypto.mail.models import MessageHistory

    verification_code = forms.CharField(widget=forms.TextInput(attrs={'size':'{}'.format(
       MessageHistory.MAX_VERIFICATION_CODE)}),
       help_text=i18n('Enter the verification code to check if GoodCrypto encrypted or decrypted your message.'),)

class ExportKeyForm(forms.Form):

    from goodcrypto.mail.models import EncryptionSoftware

    email = forms.EmailField(max_length=254,
       help_text=i18n('Enter the email address whose public key you want exported.'),)
    encryption_software = forms.ModelChoiceField(
       queryset=EncryptionSoftware.objects.filter(active=True), empty_label=None,
       help_text=i18n('Select the type of encryption software associated with the key.'),)

MAX_PUBLIC_KEY_FILEZISE = 500000
class ImportKeyFromFileForm(forms.Form):

    from goodcrypto.mail.models import EncryptionSoftware

    key_file = forms.FileField(max_length=MAX_PUBLIC_KEY_FILEZISE,
       help_text=i18n('Select the file that contains the key.'),)
    encryption_software = forms.ModelChoiceField(
       queryset=EncryptionSoftware.objects.filter(active=True), empty_label=None,
       help_text=i18n('Select the type of encryption software associated with the key.'),)
    user_name = forms.CharField(max_length=100, required=False,
       help_text='Printable name of the contact in case the key does not contain it. Optional.')
    fingerprint = forms.CharField(max_length=100, required=False,
       help_text="The fingerprint for the contact's public key, if known. Optional.")
    passcode = forms.CharField(max_length=PASSCODE_MAX_LENGTH, required=False,
       help_text="If you're importing a private key, then you must enter its passphrase.")

class ImportKeyFromKeyserverForm(forms.Form):

    def clean(self):
        '''Verify there is only 1 general info record.'''

        error_message = None
        cleaned_data = super(ImportKeyFromKeyserverForm, self).clean()

        email_or_fingerprint = cleaned_data.get('email_or_fingerprint')
        __, email = parse_address(email_or_fingerprint)
        if email is None:
            fingerprint = strip_fingerprint(email_or_fingerprint)
            m = re.match('^[0-9A-Fa-f]+$', fingerprint)
            if m:
                if len(fingerprint) < 16:
                    error_message = i18n('Either enter a valid email address or a fingerprint that is least 16 characters')
            else:
                error_message = i18n('Either enter a valid email address or a fingerprint which must contain only numbers and the letters A through F.')

            if error_message is not None:
                _log.write(error_message)
                raise forms.ValidationError(error_message, code='invalid')

        return cleaned_data

    from goodcrypto.mail.models import EncryptionSoftware

    email_or_fingerprint = forms.CharField(max_length=100, required=True,
       help_text="The email for the contact or the fingerprint for the contact's key.")
    encryption_software = forms.ModelChoiceField(
       queryset=EncryptionSoftware.objects.filter(active=True), empty_label=None,
       help_text=i18n('Select the type of encryption software associated with the key.'),)

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

    admin = forms.EmailField(required=False)

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

