#! /usr/bin/python3
'''
    Copyright 2015-2016 GoodCrypto
    Last modified: 2016-10-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import sys
from time import sleep

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.constants import WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP
from goodcrypto.mail.message.bundle import Bundle
from goodcrypto.mail.utils.notices import report_unable_to_send_bundled_messages

def main():
    # sleep is measured in seconds
    if WARNING_WARNING_WARNING_TESTING_ONLY_DO_NOT_SHIP:
        PERIOD = 10 * 60
    else:
        PERIOD = 60 * 60

    while True:
        try:
            bundle = Bundle()
            if bundle.ready_to_run():
                bundle.bundle_and_pad_messages()
        except Exception as exception:
            report_unable_to_send_bundled_messages(exception)
            print(str(exception))

        sleep(PERIOD)

if __name__ == "__main__":

    print()
    print('GoodCrypto Padding and Packetization')
    print('Copyright 2015-2016 GoodCrypto.com')
    main()

