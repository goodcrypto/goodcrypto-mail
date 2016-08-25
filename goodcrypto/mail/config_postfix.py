#! /usr/bin/python
'''
    Copyright 2015 GoodCrypto
    Last modified: 2016-01-24

    Run tools/goodcrypto/prep_postfix_config_tgz.py
    after making any changes to this file.
'''
import os

# limit the path to known locations
os.environ['PATH'] = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'

# change to the current directory where all the other files needed are
os.chdir(os.path.abspath(os.path.dirname(__file__)))

import re, sh, sys
from datetime import datetime
from shutil import copy
from socket import gethostname, gethostbyname

CONFIG_FILENAME = 'goodcrypto_postfix.conf'

POSTFIX_DIR = '/etc/postfix'
MAIN_CONFIG = 'main.cf'
MASTER_CONFIG = 'master.cf'
ALIASES = 'aliases'
ALIASES_DB = 'aliases.db'

ERROR_MESSAGE_RAW = ('ERROR: GoodCrypto requires your mail server is configured for TLS. ' +
                     'The TLS certificate and key files are missing. ' +
                     'See http://www.postfix.org/TLS_README.html#server_tls or contact support@goodcrypto.com')
WARNING_MESSAGE_RAW = ('WARNING: Other content filters found. You will need to adapt main.cf to handle multiple filters manually before using GoodCrypto. ' +
                       'See https://goodcrypto.com//qna/knowledge-base/configure-with-other-filters')

try:
    from goodcrypto.utils import i18n

    ERROR_MESSAGE = i18n(ERROR_MESSAGE_RAW)
    WARNING_MESSAGE = i18n(WARNING_MESSAGE_RAW)
except:
    ERROR_MESSAGE = ERROR_MESSAGE_RAW
    WARNING_MESSAGE = WARNING_MESSAGE_RAW

def main(private_server_ip):
    '''
        If the user agrees, configure postfix on this
        computer to work with their GoodCrypto server.
    '''

    if sh.whoami().strip() != 'root':
        print('')
        print('ERROR: You must be root to run this program.')
        exit()

    print('')
    print('GoodCrypto.com')
    response = raw_input('Integrate postfix with your GoodCrypto private server (y/N)? ')

    if response.lower().startswith('y'):
        configure(private_server_ip)
    else:
        print('Canceled integration')

def configure(private_server_ip):
    '''
        Configure postfix to work with your GoodCrypto server.
    '''

    if private_server_ip is not None and len(private_server_ip.strip()) > 0:
        main_config = os.path.join(POSTFIX_DIR, MAIN_CONFIG)
        master_config = os.path.join(POSTFIX_DIR, MASTER_CONFIG)

        backup_current_config(main_config, master_config)

        config_postfix(private_server_ip, main_config, master_config)

        # now restart postfix
        #postfix = sh.service('postfix', 'restart')
        print('')
        print('Review the {} and {} files.'.format(main_config, master_config))
        print('If everything looks ok, then restart postfix.')
        print('')
    else:
        print('The IP address for your GoodCrypto private server is undefined.')

def config_postfix(private_server_ip, main_config, master_config):
    ''' Configure postfix for goodcrypto. '''

    # configure postfix main, master, and aliases files
    aliases_filename, mta_ip, ssl_cert_file, ssl_key_file = config_main(
        main_config, private_server_ip)
    config_aliases(aliases_filename)
    config_master(master_config, mta_ip, private_server_ip, ssl_cert_file, ssl_key_file)

def config_main(main_config, private_server_ip):
    ''' Configure postfix's main.cf. '''

    # read the current configuration
    with open(main_config) as f:
        lines = f.readlines()

    # modify the lines for GoodCrypto private server content filter
    new_lines, aliases_filename, mta_ip, ssl_cert_file, ssl_key_file, other_filters = config_main_conf(
        lines, private_server_ip)

    if other_filters:
        print('')
        print(WARNING_MESSAGE)
        print('')

    # abort if TLS is not configured
    if ssl_cert_file is None or ssl_key_file is None:
        print('')
        print(ERROR_MESSAGE)
        print('')
        exit()

    # save the updated configuration
    with open(main_config, 'wt') as f:
        f.write(''.join(new_lines))

    return aliases_filename, mta_ip, ssl_cert_file, ssl_key_file

def config_main_conf(lines, private_server_ip):
    ''' Parse and update the lines for main.cf '''

    aliases_filename = ssl_cert_file = ssl_key_file = None
    mydomain  = myhostname = myorigin = None
    set_mynetworks = set_interfaces = set_transport = False
    set_bounce = set_xforward_hosts = set_content_filter = other_filters = False

    for i in range(len(lines)):
        if lines[i].startswith('mydomain'):
            m = re.match('^mydomain\ *=\ *(.*)', lines[i])
            if m:
                mydomain = m.group(1)
                # don't save variables
                if mydomain.startswith('$'):
                    mydomain = None
        elif lines[i].startswith('myhostname'):
            m = re.match('^myhostname\ *=\ *(.*)', lines[i])
            if m:
                myhostname = m.group(1)
                # don't save variables
                if myhostname.startswith('$'):
                    myhostname = None
        elif lines[i].startswith('myorigin'):
            m = re.match('^myorigin\ *=\ *(.*)', lines[i])
            if m:
                myorigin = m.group(1)
                # don't save variables
                if myorigin.startswith('$'):
                    myorigin = None
        elif lines[i].startswith('mynetworks'):
            lines[i] = '{} {}\n'.format(lines[i].strip(), private_server_ip)
            set_mynetworks = True
        elif lines[i].startswith('inet_interfaces'):
            lines[i] = 'inet_interfaces = all\n'
            set_interfaces = True
        elif lines[i].startswith('default_transport'):
            lines[i] = '#' + lines[i]
            set_transport = True
        elif lines[i].startswith('soft_bounce'):
            lines[i] = 'soft_bounce = yes\n'
            set_bounce = True
        elif lines[i].startswith('smtpd_authorized_xforward_hosts'):
            lines[i] = 'smtpd_authorized_xforward_hosts = $mynetworks\n'
            set_xforward_hosts = True
        elif lines[i].startswith('content_filter'):
            lines[i] = '#' + lines[i]
            other_filters = True
        elif lines[i].startswith('alias_maps'):
            m = re.match('^alias_maps(\ *)=.*:(.*)', lines[i])
            if m:
                aliases_filename = m.group(2)
        elif lines[i].startswith('smtpd_tls_cert_file'):
            m = re.match('^smtpd_tls_cert_file\ *=\ *(.*)', lines[i])
            if m:
                ssl_cert_file = m.group(1)
        elif lines[i].startswith('smtpd_tls_key_file'):
            m = re.match('^smtpd_tls_key_file\ *=\ *(.*)', lines[i])
            if m:
                ssl_key_file = m.group(1)

    # add any missing lines
    if not set_mynetworks:
        mynetworks = '127.0.0.1 {}.'.format(private_server_ip)
        lines.append('mynetworks = {}\n'.format(mynetworks))
    if not set_interfaces:
        lines.append('inet_interfaces = all\n')
    if not set_bounce:
        lines.append('soft_bounce = yes\n')
    if not set_xforward_hosts:
        lines.append('smtpd_authorized_xforward_hosts = $mynetworks\n')
    if not set_content_filter:
        lines.append('content_filter = scan:{}:10025\n'.format(private_server_ip))
    if aliases_filename is None:
        aliases_filename = os.path.join(POSTFIX_DIR, 'aliases')
        lines.append('alias_maps = hash:{}\n'.format(aliases_filename))
        lines.append('alias_database = hash:{}\n'.format(aliases_filename))

    mta_ip = get_mta_ip(mydomain, myhostname, myorigin)

    return lines, aliases_filename, mta_ip, ssl_cert_file, ssl_key_file, other_filters

def get_mta_ip(mydomain, myhostname, myorigin):
    ''' Get the ip address for the mta. '''

    # if the value
    if mydomain is not None:
        domain = mydomain
    elif myhostname is not None:
        domain = myhostname
    elif myorigin is not None:
        domain = myorigin
    else:
        domain = gethostname()

    # get the mta's ip address
    try:
        mta_ip = gethostbyname(domain)
    except:
        mta_ip = '127.0.0.1'

    return mta_ip

def config_aliases(aliases_filename):
    ''' Configure aliases for the metadata. '''

    if os.path.exists(aliases_filename):
        # read the current configuration
        with open(aliases_filename) as f:
            lines = f.readlines()
    else:
        lines = []

    new_lines = config_alias_lines(lines)
    if new_lines != lines:
        with open(aliases_filename, 'wt') as f:
            f.write(''.join(new_lines))
        sh.newaliases()

def config_alias_lines(lines):
    ''' Configure lines in aliases for the metadata. '''

    # make sure the following matches mail/constants.py
    # can't import the variable because this runs on as
    # as stand-alone app without the goodcrypto package.
    DOMAIN_USER = '_domain_'

    if DOMAIN_USER not in ''.join(lines):
        lines.append('{}: /dev/null\n'.format(DOMAIN_USER))

    return lines

def config_master(master_config, mta_ip, private_server_ip, ssl_cert_file, ssl_key_file):
    ''' Configure postfix's master.cf. '''

    # read the current configuration
    with open(master_config) as f:
        lines = f.readlines()

    new_lines = config_master_lines(lines, mta_ip, private_server_ip, ssl_cert_file, ssl_key_file)

    # save the updated configuration
    with open(master_config, 'wt') as f:
        f.write(''.join(new_lines))

def config_master_lines(lines, mta_ip, private_server_ip, ssl_cert_file, ssl_key_file):
    ''' Configure lines in postfix's master.cf. '''

    # comment out any previous scan lines
    found_scan = False
    for i in range(len(lines)):
        if lines[i].startswith('scan'):
            lines[i] = '#' + lines[i]
            found_scan = True
        elif found_scan:
            m = re.match('^\ *-o.*$', lines[i])
            if m:
                lines[i] = '#' + lines[i]
            else:
                found_scan = False

    # add the sections for GoodCrypto's content filter
    lines.append("# add the next 2 sections for GoodCrypto's content filter\n")
    lines.append('scan      unix  -       -       n       -       10      smtp\n')
    lines.append('    -o smtp_send_xforward_command=yes\n')
    lines.append('    -o disable_mime_output_conversion=yes\n')
    lines.append('    -o smtp_generic_maps=\n')
    lines.append('    -o smtp_helo_timeout=120\n')
    lines.append('    -o smtp_connect_timeout=120\n')
    lines.append('    -o receive_override_options=no_address_mappings\n')
    lines.append('    -o smtpd_tls_cert_file={}\n'.format(ssl_cert_file))
    lines.append('    -o smtpd_tls_key_file={}\n'.format(ssl_key_file))
    lines.append('{}:10026 inet  n       -       n       -       10      smtpd\n'.format(mta_ip))
    lines.append('    -o content_filter= \n')
    lines.append('    -o receive_override_options=no_unknown_recipient_checks,no_header_body_checks,no_milters\n')
    lines.append('    -o mynetworks={}\n'.format(private_server_ip))
    lines.append('    -o smtpd_authorized_xforward_hosts=$mynetworks\n')
    lines.append('    -o smtpd_helo_restrictions=\n')
    lines.append('    -o smtpd_client_restrictions=\n')
    lines.append('    -o smtpd_sender_restrictions=\n')
    lines.append('    -o smtpd_recipient_restrictions=permit_mynetworks,reject\n')
    lines.append('    -o smtp_helo_timeout=120\n')
    lines.append('    -o smtp_connect_timeout=120\n')
    lines.append('    -o smtpd_tls_cert_file={}\n'.format(ssl_cert_file))
    lines.append('    -o smtpd_tls_key_file={}\n'.format(ssl_key_file))

    return lines

def backup_current_config(main_config, master_config):
    ''' Backup the current postfix configuration files. '''

    backup_dirname = get_unique_dirname(POSTFIX_DIR, 'backup').strip('.')
    os.mkdir(backup_dirname)

    copy(main_config, os.path.join(backup_dirname, MAIN_CONFIG))
    copy(master_config, os.path.join(backup_dirname, MASTER_CONFIG))

    aliases_filename = aliases_database = None
    with open(main_config) as f:
        lines = f.readlines()
        for line in lines:
            m = re.match('^alias_maps(\ *)=.*:(.*)', line)
            if m:
                aliases_filename = m.group(2)
                if os.path.exists(aliases_filename):
                    copy(aliases_filename, os.path.join(backup_dirname, ALIASES))
            m = re.match('^alias_database(\ *)=.*:(.*)', line)
            if m:
                alias_database = m.group(2)
                if os.path.exists(aliases_filename):
                    copy(alias_database, os.path.join(backup_dirname, os.path.basename(alias_database)))

    print('')
    print('Backed up your current confirguration in:')
    print('   {}'.format(backup_dirname))

    return aliases_filename, alias_database

def get_unique_dirname(dirname, prefix):
    ''' Get a unique dirname. '''

    now = datetime.now()
    base_filename = '%s-%d-%02d-%02d-%02d-%02d-%02d' % (
     prefix, now.year, now.month, now.day, now.hour, now.minute, now.second)
    filename = base_filename

    if os.path.exists(os.path.join(dirname, filename)):
        i = 1
        filename = '%s-%02d' % (base_filename, i)
        while os.path.exists(os.path.join(dirname, filename)):
            i += 1
            filename = '%s-%02d' % (base_filename, i)

    return os.path.join(dirname, filename)

def how_it_works():

    print('Error - unable to configure your MTA for GoodCrypto')
    print('You must pass the IP address of your GoodCrypto private server')
    print('For example, config_postfix.py 192.128.0.10')

if __name__ == "__main__":

    if sys.argv:
        argv = sys.argv
        if len(argv) > 1:
            main(argv[1])
        else:
            how_it_works()
    else:
        how_it_works()

