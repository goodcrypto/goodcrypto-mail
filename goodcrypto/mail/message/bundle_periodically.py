#! /usr/bin/python
'''
    Copyright 2015 GoodCrypto
    Last modified: 2015-07-27

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, sys
from datetime import datetime, timedelta
from time import sleep

# limit the path to known locations
os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'
# set django settings before importing any classes that might include djano
os.environ['DJANGO_SETTINGS_MODULE'] = 'goodcrypto.settings'

import django
from django.utils.timezone import utc
django.setup()

from goodcrypto.mail import options
from goodcrypto.mail.constants import TAG_ERROR
from goodcrypto.mail.internal_settings import get_date_queue_last_active, set_date_queue_last_active
from goodcrypto.mail.message.bundle import Bundle
from goodcrypto.mail.utils import get_sysadmin_email
from goodcrypto.mail.utils.notices import notify_user
from goodcrypto.utils import i18n
from goodcrypto.utils.exception import record_exception
from syr import mime_constants
from syr.log import get_log

class BundlePeriodically(object):
    ''' 
        Check to see if it's time to bundle and pad messages.
    '''

    def __init__(self):
        '''
            >>> bundle = BundlePeriodically()
            >>> bundle is not None
            True
        '''
        self.DEBUGGING = False

        # we want this log regardless of the user settings
        # because this is a background task
        self.log = get_log()
        
        
    def ready_to_run(self):
        ''' Check to see if it's time to run the bundle and again. '''
    
        if options.encrypt_metadata() and options.bundle_and_pad():

            if options.bundle_frequency() == options.bundle_hourly():
                frequency = timedelta(hours=1)
            elif options.bundle_frequency() == options.bundle_daily():
                frequency = timedelta(days=1)
            elif options.bundle_frequency() == options.bundle_weekly():
                frequency = timedelta(weeks=1)
            else:
                frequency = timedelta(hour=1)

            next_run = get_date_queue_last_active() + frequency
            
            ready = next_run <= datetime.utcnow()
            if not ready:
                self.log('bundle and pad messages next: {}'.format(next_run))

        else:
            self.log('not bundling and padding messages')
            ready = False
            
        return ready

    def bundle_and_pad_messages(self):
        ''' Bundle and pad messages. '''

        try:
            self.log('starting to bundle and pad messages')
            Bundle().bundle_and_pad()
            set_date_queue_last_active(datetime.utcnow())
            ok = True
            self.log('finished bundling and padding messages')
        except Exception as exception:
            ok = False
            subject = '{} - Unable to send bundled messages'.format(TAG_ERROR)
            notify_user(get_sysadmin_email(), subject, '{}\n\n{}'.format(subject, exception))
            record_exception()
            self.log('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return ok

def main():
    # sleep is measured in seconds
    ONE_HOUR = 60 * 60

    while True:
        try:
            bp = BundlePeriodically()
            if bp.ready_to_run():
                bp.bundle_and_pad_messages()
        except Exception as exception:
            record_exception()
            subject = '{} - Unable to send bundled messages periodically'.format(TAG_ERROR)
            notify_user(get_sysadmin_email(), subject, '{}\n\n{}'.format(subject, exception))

        sleep(ONE_HOUR)

if __name__ == "__main__":
    
    main()

