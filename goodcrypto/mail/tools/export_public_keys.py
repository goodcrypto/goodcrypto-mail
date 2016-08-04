#! /usr/bin/python
'''
    Export all public keys for the domain.
    
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-07-08
'''
import os, sys
from goodcrypto.mail import crypto_software
from goodcrypto.mail.contacts import get_public_key
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.models import Contact
from goodcrypto.oce.crypto_factory import CryptoFactory
from syr.log import get_log

log = get_log()

def main(argv):
    # set the defaults
    crypto_name = CryptoFactory.DEFAULT_ENCRYPTION_NAME
    parent_dir = '/var/local/projects/goodcrypto/server/data/oce/pubkeys'
    
    # use the args passed on the command line
    if argv and len(argv) >= 1:
        parent_dir = argv[0]
        if len(argv) >= 2:
            crypto_name = argv[1]

    if not os.path.exists(parent_dir):
        os.makedirs(parent_dir)

    domain = get_domain()

    gpg_crypto = crypto_software.get(crypto_name)
    contacts = Contact.objects.filter(email__iendswith=domain)
    for contact in contacts:
        email = contact.email
        public_key = get_public_key(email, gpg_crypto)
        filename = os.path.join(parent_dir, email + '.asc')
        with open(filename, 'wt') as f:
            f.write(public_key)

if __name__ == '__main__':
    main(sys.argv[1:])

