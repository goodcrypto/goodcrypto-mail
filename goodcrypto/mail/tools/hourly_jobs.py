#! /usr/bin/python3
'''
    Copyright 2015-2016 GoodCrypto
    Last modified: 2016-10-26
'''
# limit the path to known locations
from os import environ
environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

import os, sh, sys
from time import sleep
from traceback import format_exc

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from syr.log import get_log

log = get_log()

def main():
    '''
        This program is necessary because if cron detects an error in any job,
        it does not run any other jobs that are in the cron.hourly directory.
    '''

    # sleep is measured in seconds
    ONE_HOUR = 60 * 60

    while True:
        log('starting hourly jobs')
        try:
            run = sh.Command('/usr/local/sbin/disable-spyware')
            run()
        except:
            log(format_exc())

        """
        # we need a variable which enables/disables wireless and then runs this when appropriate
        try:
            run = sh.Command('/usr/local/sbin/disable-wireless')
            run()
        except:
            log(format_exc())
        """

        try:
            run = sh.Command('/usr/local/sbin/goodcrypto-bundle')
            run()
            log('bundled and padded waiting messages')
        except:
            log(format_exc())

        log('finished hourly jobs')
        sleep(ONE_HOUR)

if __name__ == "__main__":
    main()
    sys.exit(0)

