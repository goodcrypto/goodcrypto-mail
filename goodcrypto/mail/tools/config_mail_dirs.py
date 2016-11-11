#! /usr/bin/python3
'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-15-26
'''
# limit the path to known locations
from os import environ
environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

import os, sh, sys

from goodcrypto.mail.constants import USE_POSTGRESQL
from syr.log import get_log

log = get_log()


def main():

    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..', 'data'))
    log('data dir: {}'.format(data_dir))

    # gpg insists on these permissions
    oce_gpg_dir = '{}/oce/.gnupg'.format(data_dir)
    if os.path.exists(oce_gpg_dir):
        sh.chmod('--recursive', 'go-rwx', oce_gpg_dir)
        log('prepared oce')

    if USE_POSTGRESQL:
        # postgres must own its config dir
        sh.chown('-h', '--recursive', 'postgres:postgres', '/etc/postgresql')

    # we need a dir for other persistent data that is not normally in data_dir)
    persistent_dir = '{}/persistent'.format(data_dir)
    if not os.path.exists(persistent_dir):
        sh.mkdir('--parents', persistent_dir)
    sh.chown('goodcrypto:goodcrypto', persistent_dir)
    sh.chmod('g+rx', persistent_dir)
    sh.chmod('o-rwx', persistent_dir)
    log('prepared {}'.format(persistent_dir))

    # root should own these subdirectories
    django_dir = '{}/django'.format(persistent_dir)
    if not os.path.exists(django_dir):
        sh.mkdir(django_dir)
    sh.chown('goodcrypto:goodcrypto', django_dir)
    sh.chmod('go-rwx', django_dir)

    return 0

if __name__ == "__main__":
    return_code = main()
    sys.exit(return_code)

