#! /usr/bin/python3
'''
    Make private keys for all users in the supported domain.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-26
'''

# limit the path to known locations
from os import environ
environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

import os, sys
from goodcrypto.mail import contacts, crypto_software
from goodcrypto.mail.constants import AUTO_GENERATED
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.utils import parse_address
from syr.log import get_log

log = get_log()

def main(argv):
    # set the defaults
    crypto_name = CryptoFactory.DEFAULT_ENCRYPTION_NAME

    # use the args passed on the command line
    if argv and len(argv) >= 1:
        pathname = argv[0]
        if len(argv) >= 2:
            crypto_name = argv[1]

        crypto = crypto_software.get(crypto_name)
        if crypto is None:
            print('{} encryption not defined in database'.format(crypto_name))
        else:
            domain = get_domain()
            with open(pathname, 'rt') as f:
                lines = f.readlines()
                for line in lines:
                    if len(line.strip()) > 0 and not line.startswith('#'):
                        make_key(line, domain, crypto_name)
    else:
        print_usage()

def make_key(line, domain, crypto_name):
    ''' Make a private key if its in the domain.'''

    user_name, email = parse_address(line)
    if email is None:
        print('{} is not a valid email address'.format(line))
    elif email_in_domain(email):
        if user_name is None or len(user_name.strip()) <= 0:
            full_address = email
        else:
            full_address = '{} <{}>'.format(user_name, email)
        contacts.add(full_address, crypto_name, source=AUTO_GENERATED)
    else:
        print('{} not in the domain: {}'.format(line, domain))

def print_usage():
    ''' Print the usage to the user. '''

    print('usage: python3 make_private_keys.py [pathname]')
    print('       pathname must include the full path to a file that contains 1 email per line.')
    print('       Only email addresses with matching domains to the one support by GoodCrypto will be used.')
    print('       A new key will be generated and the associated contact record added to the database.')

if __name__ == '__main__':
    main(sys.argv[1:])

