#! /usr/bin/python3
'''
    Clear jobs from failed queue.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-26
'''
# limit the path to known locations
from os import environ
environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

import os, sys

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.oce.crypto_factory import CryptoFactory

def main(encryption_name):
    '''
        Clear all failed jobs.

        >>> main('GPG')
    '''

    plugin = CryptoFactory.get_crypto(encryption_name)
    plugin.wait_until_queue_empty()

if __name__ == '__main__':
    main(sys.argv[1])

