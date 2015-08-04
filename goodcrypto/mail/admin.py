'''
    Admin for GoodCrypto Mail.

    Copyright 2014 GoodCrypto
    Last modified: 2014-12-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from django.contrib import admin
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext as _

from goodcrypto.mail import forms, models
from reinhardt.admin_extensions import CustomModelAdmin, CustomStackedInline, RequireOneFormSet

# indent the 'Details' and 'Advanced' labels
details_label = mark_safe('<label>&nbsp;</label>{}'.format(_('Details')))
advanced_label = mark_safe('<label>&nbsp;</label>{}'.format(_('Advanced')))



class ContactsCryptoInline(CustomStackedInline):
    
    extra = 0
    readonly_fields = ('fingerprint',)
            
    staff_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (('encryption_software',),
                       ('fingerprint', 'verified',),
                      )
        }),
    )
    superuser_fieldsets = staff_fieldsets
    
    model = models.ContactsCrypto
    formset = forms.ContactsCryptoInlineFormSet
    
    verbose_name = _('encryption software used by this contact')
    verbose_name_plural = verbose_name

class Contact(CustomModelAdmin):
    form = forms.ContactAdminForm
    inlines = [ContactsCryptoInline]
    search_fields = ['email', 'user_name']
    
    list_display = ('email', 'user_name',)
    staff_list_display = list_display
    superuser_list_display = list_display
    list_display_links = ('email',)
    
    staff_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (('email', 'user_name'),)
        }),
    )
    superuser_fieldsets = staff_fieldsets

admin.site.register(models.Contact, Contact)



class Options(CustomModelAdmin):
    form = forms.OptionsAdminForm
    
    readonly_fields = ('domain',)

    list_display = ('mail_server_address','auto_exchange', 'create_private_keys', 'clear_sign', 'filter_html', 'max_message_length',)
    staff_list_display = list_display
    superuser_list_display = list_display
    list_display_links = list_display
    
    staff_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': (('mail_server_address'),
                      )
        }),
    )
    superuser_fieldsets = (
        (None, {
            'fields': (
                       'mail_server_address',
                       'auto_exchange',
                       'create_private_keys',
                       'clear_sign',
                       'require_key_verified',
                       'filter_html',
                       'login_to_view_fingerprints',
                       'login_to_export_keys',
                       #'add_keys_to_keyservers',
                       #'verify_new_keys_with_keyservers',
                       'max_message_length',
                       'debugging_enabled',
                      )
        }),
    )
    
    def get_form(self, request, obj=None, **kwargs):
        '''Add the current user to the form.'''
        
        form = super(Options, self).get_form(request, obj, **kwargs)
        form.adding = obj == None
        return form
        
admin.site.register(models.Options, Options)



