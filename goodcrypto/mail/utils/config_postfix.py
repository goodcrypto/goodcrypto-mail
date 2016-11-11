'''
    Configure the GoodCrypto private server's postfix
    to work with the domain's MTA.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-26

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, re, sh

from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception

log = LogFile()

MAIN_FILENAME = '/etc/postfix/main.cf'
MASTER_FILENAME = '/etc/postfix/master.cf'
MAILNAME_FILE = '/etc/mailname'

def configure_mta(mail_server_address, goodcrypto_listen_port, mta_listen_port):
    '''
        Configure postfix to work with the main MTA.
    '''

    try:
        new_configuration = False

        if not isinstance(mail_server_address, str):
            mail_server_address = mail_server_address.decode()

        if configure_main(mail_server_address, mta_listen_port):
            new_configuration = True
            log.write_and_flush('new main config')

        if configure_master(goodcrypto_listen_port):
            new_configuration = True
            log.write_and_flush('new master config')

        if new_configuration:
            # restart postfix with the new settings
            log.write_and_flush('restarting postfix')
            sh.service('postfix', 'restart')
            log.write_and_flush('postfix restarted')
    except Exception:
        log.write_and_flush('EXCEPTION - see syr.exception.log')
        record_exception()
        raise

    return new_configuration

def configure_main(mail_server_address, mta_listen_port):
    '''
        Configure main.cf.
    '''

    if not isinstance(mail_server_address, str):
        mail_server_address = mail_server_address.decode()
            
    new_configuration, new_lines = main_needs_configuration(mail_server_address, mta_listen_port)
    if new_configuration:
        try:
            with open(MAIN_FILENAME, 'wt') as output_file:
                bytes = output_file.write(''.join(new_lines))
            log.write_and_flush('updated postfix main.cf ({} bytes)'.format(bytes))
        except:
            record_exception()

    return new_configuration

def main_needs_configuration(mail_server_address, mta_listen_port):
    '''
        Determine if main.cf needs to be configured.
    '''

    new_configuration = False
    new_lines = []

    if not isinstance(mail_server_address, str):
        mail_server_address = mail_server_address.decode()

    with open(MAIN_FILENAME, 'r') as input_file:
        lines = input_file.readlines()

    for line in lines:
        l = line.lower()
        if l.startswith('mynetworks'):
            new_line = 'mynetworks = localhost 10.0.2.2 {}'.format(str(mail_server_address))
            if new_line.strip() != line.strip():
                log.write_and_flush('original line: {}'.format(line))
                new_configuration = True
                line = '{}\n'.format(new_line)
                log.write_and_flush('new line: {}'.format(line.strip()))
        elif l.startswith('default_transport'):
            new_line = 'default_transport = smtp:[{}]:{}'.format(
                                 str(mail_server_address), mta_listen_port)
            if new_line.strip() != line.strip():
                new_configuration = True
                line = '{}\n'.format(new_line)
                log.write_and_flush('new line: {}'.format(line.strip()))
        new_lines.append(line)

    return new_configuration, new_lines

def configure_master(goodcrypto_listen_port):
    '''
        Configure master.cf.
    '''

    new_configuration, new_lines = master_needs_configuration(goodcrypto_listen_port)
    if new_configuration:
        with open(MASTER_FILENAME, 'wt') as output_file:
            output_file.write(''.join(new_lines))
        log.write_and_flush('updated postfix master.cf')

    return new_configuration

def master_needs_configuration(goodcrypto_listen_port):
    '''
        Determine if the master.cf needs to be configured.
    '''

    new_configuration = False
    new_lines = []

    with open(MASTER_FILENAME, 'r') as input_file:
        lines = input_file.readlines()

    for line in lines:
        l = line.lower()
        m = re.match(r'^\d+\.\d+\.\d+\.\d+:(\d{2,5}) .*', l)
        if m and (int(m.group(1)) != goodcrypto_listen_port):
            new_line = line.replace(m.group(1), str(goodcrypto_listen_port))
            if new_line != line:
                log.write_and_flush('original line: {}'.format(line))
                new_configuration = True
                line = new_line
                log.write_and_flush('new line: {}'.format(line.strip()))
        new_lines.append(line)

    return new_configuration, new_lines

def configure_mailname(domain):
    '''
        Configure mailname
    '''

    if not isinstance(domain, str):
        domain = domain.decode()

    new_configuration, new_lines = mailname_needs_configuration(domain)
    if new_configuration:
        with open(MAILNAME_FILE, 'wt') as output_file:
            output_file.write(''.join(new_lines))
        log.write_and_flush('updated mailname')

        # restart postfix with the new settings
        sh.service('postfix', 'restart')
        log.write_and_flush('postfix restarted')

    return new_configuration

def mailname_needs_configuration(domain):
    '''
        Determine if mailname to be configured.
    '''

    new_configuration = False
    new_lines = []

    if not isinstance(domain, str):
        domain = domain.decode()

    if os.path.exists(MAILNAME_FILE):
        with open(MAILNAME_FILE, 'r') as input_file:
            lines = input_file.readlines()
            new_configuration = len(lines) <= 0
    
        for line in lines:
            line = line.strip('\n')
            log.write_and_flush('line: {}'.format(line))
            if domain != line:
                log.write_and_flush('original domain: {}'.format(line))
                new_configuration = True
                line = domain
                log.write_and_flush('new domain: {}'.format(domain))
            new_lines.append(line)
    else:
        new_configuration = True

    return new_configuration, new_lines

if __name__ == "__main__":
    import doctest
    doctest.testmod()

