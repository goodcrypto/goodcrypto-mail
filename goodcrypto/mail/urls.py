'''
    Urls for Mail

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-12-07

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

from django.conf.urls import *
from django.core.urlresolvers import reverse

from goodcrypto.mail import views

urlpatterns = patterns('',

    url(r'^$', views.home, name='home'),
    url(r'view_fingerprint/?', views.view_fingerprint, name='view_fingerprint'),
    url(r'verify_fingerprint/?', views.verify_fingerprint, name='verify_fingerprint'),
    url(r'export_key/?', views.export_key, name='export_key'),
    url(r'import_key/?', views.import_key, name='import_key'),

    url(r'verify_crypted/?$', views.verify_crypted, name='verify_crypted'),

    url(r'msg-encrypted/(.*)/?$', views.msg_encrypted, name='msg_encrypted'),
    url(r'show_encrypted_history/?', views.show_encrypted_history, name='show_encrypted_history'),

    url(r'msg-decrypted/(.*)/?$', views.msg_decrypted, name='msg_decrypted'),
    url(r'show_decrypted_history/?', views.show_decrypted_history, name='show_decrypted_history'),

    url(r'^show_protection/?', views.show_protection, name='mail_show_protection'),
    url(r'^show_metadata_domains/?', views.show_metadata_domains, name='mail_show_metadata_domains'),

    url(r'^configure/?', views.configure, name='mail_configure'),

    #url(r'^api/?', views.api, name='mail_api'),
)

