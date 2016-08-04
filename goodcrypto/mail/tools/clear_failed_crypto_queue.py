#! /usr/bin/python
'''
    Clear jobs from failed queue.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-11-22
'''
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

