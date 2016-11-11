'''
    Configure the environment for django and dbuild.

    Copyright 2015-2016 GoodCrypto
    Last modified: 2016-10-26
'''
import os

def setup(settings='goodcrypto.settings'):
    ''' Set up the environment for django. '''

    # limit the path to known locations
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    # set django settings before importing any classes that might include django
    os.environ['DJANGO_SETTINGS_MODULE'] = settings

    # set up django before we access the django database
    import django
    try:
        if not django.apps.registry.apps.app_configs:
            django.setup()
    except AttributeError:
        django.setup()

