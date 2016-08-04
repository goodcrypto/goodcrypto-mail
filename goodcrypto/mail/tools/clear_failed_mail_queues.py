#! /usr/bin/python
'''
    Clear jobs from failed mail, keys, and special queues.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-11-22
'''
import os

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.mail.message.rq_message_settings import MESSAGE_RQ, MESSAGE_REDIS_PORT
from goodcrypto.mail.rq_crypto_settings import CRYPTO_RQ, CRYPTO_REDIS_PORT
from goodcrypto.mail.rq_special_settings import SPECIAL_RQ, SPECIAL_REDIS_PORT
from goodcrypto.utils.manage_rq import clear_failed_queue

def main():
    '''
        Clear all failed jobs from the keys and special queues.

        >>> main()
    '''

    clear_failed_queue(MESSAGE_RQ, MESSAGE_REDIS_PORT)
    clear_failed_queue(CRYPTO_RQ, CRYPTO_REDIS_PORT)
    clear_failed_queue(SPECIAL_RQ, SPECIAL_REDIS_PORT)

if __name__ == '__main__':
    main()

