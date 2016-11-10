'''
    Admin for GoodCrypto Mail.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-04-06

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
    readonly_fields = ('fingerprint', 'source',)

    staff_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (('encryption_software',),
                       ('fingerprint',), ('verified',), ('source',),
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
    search_fields = ['email', 'user_name', 'outbound_encrypt_policy']
    radio_fields = {'outbound_encrypt_policy': admin.HORIZONTAL}

    save_on_top = True

    list_display = ('email', 'user_name', 'outbound_encrypt_policy',)
    staff_list_display = list_display
    superuser_list_display = list_display
    list_display_links = ('email',)

    staff_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (('email', ), ('user_name',), ('outbound_encrypt_policy',))
        }),
    )
    superuser_fieldsets = staff_fieldsets

admin.site.register(models.Contact, Contact)

class Keyserver(CustomModelAdmin):
    form = forms.KeyserverAdminForm
    search_fields = ['name', 'active', 'last_date', 'last_status']

    list_display = ('name', 'active', 'last_date', 'last_status',)
    staff_list_display = list_display
    superuser_list_display = list_display
    list_display_links = ('name',)

    ordering = ['-active', 'name']

    staff_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (('name', 'active'), ('last_date', 'last_status'),)
        }),
    )
    superuser_fieldsets = staff_fieldsets

admin.site.register(models.Keyserver, Keyserver)

class Options(SingletonAdmin):
    # indent the labels
    metadata_protection_label = mark_safe('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{}'.format(i18n('Metadata & Traffic Analysis Protection')))
    tighter_security_label = mark_safe('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{}'.format(i18n('Tighter security')))
    sig_label = mark_safe('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{}'.format(i18n('Signatures')))
    misc_label = mark_safe('&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{}'.format(i18n('Other')))

    save_on_top = True
    readonly_fields = ('dkim_public_key',)

    form = forms.OptionsAdminForm
    fieldsets = (
        (None, {
            'fields': (
                       'mail_server_address',
                       'goodcrypto_server_url',
                       #'auto_exchange',
                       #'create_private_keys',
                      )
        }),
        (metadata_protection_label, {
            'fields': ('encrypt_metadata', 'bundle_and_pad', 'bundle_message_kb', 'bundle_frequency',)
        }),
        (tighter_security_label, {
            'fields': (
                       'require_outbound_encryption',
                       'require_key_verified',
                       'login_to_view_fingerprints',
                       'login_to_export_keys',
                       'filter_html',
                      )
        }),
        (sig_label, {
            'fields': (
                       'clear_sign',
                       #'clear_sign_policy',
                       'add_dkim_sig',
                       'verify_dkim_sig',
                       'dkim_delivery_policy',
                       'dkim_public_key',
                      )
        }),
        (misc_label, {
            'fields': (
                       'use_keyservers',
                       'add_long_tags',
                       'debugging_enabled',
                      )
        }),
    )
admin.site.register(models.Options, Options)

