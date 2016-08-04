#! /usr/bin/python
'''
    Copyright 2015 GoodCrypto
    Last modified: 2015-07-08
'''
import os, sys
from syr.openssl import generate_certificate, move_private_key

def main(domain='goodcrypto.private.server.website'):
    '''
        Generate certficate for postfix.
        
        >>> main(domain='test.domain.com')
        New postfix certificate generated
    '''
    
    # generate a key for postfix
    dirname = '/etc/postfix/'
    if os.path.exists(dirname):
        generate_certificate(domain, dirname, private_key_name='server.key', public_cert_name='server.crt')
        move_private_key(dirname, 'server.key')

    return 'New postfix certificate generated'


if __name__ == "__main__":
    if sys.argv:
        argv = sys.argv
        if len(argv) > 1:
            domain = argv[1]
            main(domain=domain)
        else:
            main()
    else:
        main()

