'''
    Admin for GoodCrypto Mail.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-07-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from django.contrib import admin
from django.utils.safestring import mark_safe
from django_singleton_admin.admin import SingletonAdmin

from goodcrypto.mail import forms, models
from goodcrypto.utils import i18n
from reinhardt.admin_extensions import CustomModelAdmin, CustomStackedInline


class ContactsCryptoInline(CustomStackedInline):
    
    extra = 0
    readonly_fields = ('fingerprint',)
            
    staff_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (('encryption_software',),
                       ('fingerprint',), ('verified',), ('active',),
                      )
        }),
    )
    superuser_fieldsets = staff_fieldsets
    
    model = models.ContactsCrypto
    formset = forms.ContactsCryptoInlineFormSet
    
    verbose_name = i18n('encryption software used by this contact')
    verbose_name_plural = verbose_name

class Contact(CustomModelAdmin):
    form = forms.ContactAdminForm
    inlines = [ContactsCryptoInline]
    search_fields = ['email', 'user_name']
    
    save_on_top = True

    list_display = ('email', 'user_name',)
    staff_list_display = list_display
    superuser_list_display = list_display
    list_display_links = ('email',)
    
    staff_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (('email',), ('user_name',),)
        }),
    )
    superuser_fieldsets = staff_fieldsets

admin.site.register(models.Contact, Contact)

class Options(SingletonAdmin):
    # indent the labels
    metadata_label = mark_safe('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{}'.format(i18n('Metadata Protection')))
    traffic_analysis_label = mark_safe('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{}'.format(i18n('Traffic Analysis Protection (Experimental)')))
    tighter_security_label = mark_safe('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{}'.format(i18n('Tighter security')))
    misc_label = mark_safe('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{}'.format(i18n('Other')))

    save_on_top = True

    """
    DISABLE metadata and traffic analysis
        (metadata_label, {
            'fields': ('encrypt_metadata',)
        }),
        DISABLE metadata and traffic analysis
        (traffic_analysis_label, {
            'fields': ('bundle_and_pad', 'bundle_message_kb', 'bundle_frequency',)
        }),
    """
    form = forms.OptionsAdminForm
    fieldsets = (
        (None, {
            'fields': (
                       'mail_server_address',
                       'goodcrypto_server_url',
                       'auto_exchange',
                       'create_private_keys',
                      )
        }),
        (tighter_security_label, {
            'fields': (
                       'require_key_verified',
                       'login_to_view_fingerprints',
                       'login_to_export_keys',
                       'filter_html',
                      )
        }),
        (misc_label, {
            'fields': (
                       'clear_sign',
                       'debugging_enabled',
                      )
        }),
    )
admin.site.register(models.Options, Options)

