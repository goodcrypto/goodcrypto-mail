#! /usr/bin/python
'''
    Copyright 2015 GoodCrypto
    Last modified: 2015-11-27

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, sys
from datetime import datetime, timedelta
from time import sleep

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from django.utils.timezone import utc
from goodcrypto.constants import WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP
from goodcrypto.mail import options
from goodcrypto.mail.constants import TAG_ERROR
from goodcrypto.mail.internal_settings import get_date_queue_last_active, set_date_queue_last_active
from goodcrypto.mail.message.bundle import Bundle
from goodcrypto.mail.utils import get_sysadmin_email
from goodcrypto.mail.utils.notices import report_unable_to_send_bundled_messages
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

        self.log('started periodic padding and packetization of messages')


    def ready_to_run(self):
        ''' Check to see if it's time to run the bundle and again. '''

        if options.encrypt_metadata() and options.bundle_and_pad():

            if options.bundle_frequency() == options.bundle_hourly():
                if WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP:
                    frequency = timedelta(minutes=10)
                else:
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
            self.log('not padding and packetizing messages')
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
            report_unable_to_send_bundled_messages(exception)
            """
            subject = '{} - Unable to send bundled messages'.format(TAG_ERROR)
            notify_user(get_sysadmin_email(), subject, '{}\n\n{}'.format(subject, exception))
            record_exception()
            """
            self.log('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return ok

def main():
    # sleep is measured in seconds
    if WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP:
        PERIOD = 10 * 60
    else:
        PERIOD = 60 * 60

    while True:
        try:
            bp = BundlePeriodically()
            if bp.ready_to_run():
                bp.bundle_and_pad_messages()
        except Exception as exception:
            """
            subject = '{} - Unable to send bundled messages periodically'.format(TAG_ERROR)
            notify_user(get_sysadmin_email(), subject, '{}\n\n{}'.format(subject, exception))
            record_exception()
            """
            report_unable_to_send_bundled_messages(exception)
            print(str(exception))

        sleep(PERIOD)

if __name__ == "__main__":

    print()
    print('GoodCrypto Padding and Packetization')
    print('Copyright 2015 GoodCrypto.com')
    main()

