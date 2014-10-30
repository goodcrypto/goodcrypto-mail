'''
    Urls for Mail
   
    Copyright 2014 GoodCrypto
    Last modified: 2014-09-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

from django.conf.urls import *
from django.core.urlresolvers import reverse 

from goodcrypto.mail import views

urlpatterns = patterns('',

    url(r'^$', views.home, name='home'),
    url(r'view_fingerprint/?', views.view_fingerprint, name='view_fingerprint'),
    url(r'export_key/?', views.export_key, name='export_key'),
    url(r'import_key/?', views.import_key, name='import_key'),

    url(r'^configure/?', views.configure, name='mail_configure'),
    url(r'^api/?', views.api, name='mail_api'),
)

