#! /usr/bin/python
'''
    Import all public keys from a directory.

    Each file must contain one public key and
    the filename must match the key's email address.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-11-22
'''
import os, sys

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.mail import crypto_software
from goodcrypto.mail.contacts import import_public_key
from goodcrypto.oce import gpg_constants
from syr.log import get_log

log = get_log()

def main(argv):

    parent_dir = '/var/local/projects/goodcrypto/server/data/oce/pubkeys'
    extension = '.asc'
    crypto_name = gpg_constants.ENCRYPTION_NAME

    # use the args passed on the command line
    if argv and len(argv) >= 1:
        parent_dir = argv[0]
        if len(argv) >= 2:
            extension = argv[1]
        if len(argv) >= 3:
            crypto_name = argv[2]

        import_all_keys(parent_dir, extension, crypto_name)

    else:
        print('usage: import_public_keys parent_directory [extension encryption_name]')

def import_all_keys(parent_dir, extension, crypto_name):

    crypto = crypto_software.get(crypto_name)
    filenames = os.listdir(parent_dir)
    for filename in filenames:
        if filename.endswith(extension):
            email = filename[:len(filename) - len(extension)]
            with open(os.path.join(parent_dir, filename), 'rt') as f:
                public_key = f.read()
                result_ok, status = import_public_key(email, crypto, public_key)
                if not result_ok:
                    print(status)

if __name__ == '__main__':
    main(sys.argv[1:])

