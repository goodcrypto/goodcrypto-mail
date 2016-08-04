'''
    Configure the environment for django and goodcrypto.

    Copyright 2015 GoodCrypto
    Last modified: 2015-11-22
'''
import os

def setup():
    ''' Set up the environment for django. '''
    
    # limit the path to known locations
    os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
    # set django settings before importing any classes that might include django
    os.environ['DJANGO_SETTINGS_MODULE'] = 'goodcrypto.settings'
    
    # set up django before we access the django database
    import django
    try:
        if not django.apps.registry.apps.app_configs:
            django.setup()
    except AttributeError:
        django.setup()

