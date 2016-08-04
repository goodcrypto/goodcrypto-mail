#! /usr/bin/python
'''
    Copyright 2015 GoodCrypto
    Last modified: 2015-07-08
'''
import os, sh, sys
from syr.openssl import generate_certificate, move_private_key

def main(domain='goodcrypto.private.server.website'):
    '''
        Generate postgresql certficate.
        
        >>> main(domain='test.domain.com')
        New certificate(s) generated
    '''
    
    # generate a key for postgres and be sure the ownship is correct
    dirname = '/var/local/projects/goodcrypto/server/data/db/postgresql'
    if os.path.exists(dirname) and not os.path.islink(dirname):
        generate_certificate(domain, dirname, private_key_name='server.key', public_cert_name='server.crt')
        sh.chown('postgres:postgres', os.path.join(dirname, 'server.crt'))
        move_private_key(dirname, 'server.key')
        sh.chown('postgres:postgres', os.path.join(dirname, 'server.key'))

    return 'New certificate(s) generated'


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

