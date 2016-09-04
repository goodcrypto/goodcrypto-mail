'''
    Configure the GoodCrypto private server's postfix 
    to work with the domain's MTA.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-02-19
    IMPORTANT: The doc tests in this module can only be run as root.

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import re, sh
from base64 import b64decode
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile

log = LogFile()

MAIN_FILENAME = '/etc/postfix/main.cf'
MASTER_FILENAME = '/etc/postfix/master.cf'
MAILNAME_FILE = '/etc/mailname'

def configure_mta(mail_server_address, goodcrypto_listen_port, mta_listen_port):
    '''
        Configure postfix to work with the main MTA.

        >>> with open(MASTER_FILENAME) as f:
        ...     master_contents = f.read()
        >>> with open(MAIN_FILENAME) as f:
        ...     main_contents = f.read()
        ...     configure_mta('125.6.78.1', 10021, 10022)
        ...     configure_mta('125.6.78.1', 10021, 10022)
        True
        False
        >>> with open(MASTER_FILENAME, 'wt') as f:
        ...     f.write(master_contents)
        >>> with open(MAIN_FILENAME, 'wt') as f:
        ...     f.write(main_contents)
    '''

    try:
        new_configuration = False

        mail_server_address = b64decode(mail_server_address)

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
        log.write_and_flush('EXCEPTION - see goodcrypto.utils.exception.log')
        record_exception()
        raise

    return new_configuration

def configure_main(mail_server_address, mta_listen_port):
    '''
        Configure main.cf.

        >>> with open(MAIN_FILENAME) as f:
        ...     main_contents = f.read()
        ...     configure_main('123.456.789.0', 10024)
        ...     configure_main('123.456.789.0', 10024)
        True
        False
        >>> with open(MAIN_FILENAME, 'wt') as f:
        ...     f.write(main_contents)
    '''

    new_configuration, new_lines = main_needs_configuration(mail_server_address, mta_listen_port)
    if new_configuration:
        try:
            with open(MAIN_FILENAME, 'wt') as output_file:
                output_file.write(''.join(new_lines))
            log.write_and_flush('updated postfix main.cf')
        except:
            record_exception()

    return new_configuration

def main_needs_configuration(mail_server_address, mta_listen_port):
    '''
        Determine if main.cf needs to be configured.

        >>> new_config, __ = main_needs_configuration('123.456.789.0', 10024)
        >>> new_config
        True
    '''

    new_configuration = False

    with open(MAIN_FILENAME, 'rt') as input_file:
        lines = input_file.readlines()

    new_lines = []
    for line in lines:
        l = line.lower()
        if l.startswith('mynetworks'):
            new_line = 'mynetworks = localhost 10.0.2.2 {}\n'.format(mail_server_address)
            if new_line != line:
                new_configuration = True
                line = new_line
                log.write_and_flush('new line: {}'.format(line.strip()))
        elif l.startswith('default_transport'):
            new_line = 'default_transport = smtp:[{}]:{}\n'.format(mail_server_address, mta_listen_port)
            if new_line != line:
                new_configuration = True
                line = new_line
                log.write_and_flush('new line: {}'.format(line.strip()))
        new_lines.append(line)

    return new_configuration, new_lines

def configure_master(goodcrypto_listen_port):
    '''
        Configure master.cf.

        >>> with open(MASTER_FILENAME) as f:
        ...     main_contents = f.read()
        ...     configure_master(10023)
        ...     configure_master(10023)
        True
        False
        >>> with open(MASTER_FILENAME, 'wt') as f:
        ...     f.write(main_contents)
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

        >>> new_config, __ = master_needs_configuration(10023)
        >>> new_config
        True
        >>> new_config, __ = master_needs_configuration(10028)
        >>> new_config
        False
    '''

    new_configuration = False

    with open(MASTER_FILENAME, 'rt') as input_file:
        lines = input_file.readlines()

    new_lines = []
    for line in lines:
        l = line.lower()
        m = re.match('^\d+\.\d+\.\d+\.\d+:(\d{2,5}) .*', l)
        if m and (m.group(1) != str(goodcrypto_listen_port)):
            new_line = line.replace(m.group(1), str(goodcrypto_listen_port))
            if new_line != line:
                new_configuration = True
                line = new_line
                log.write_and_flush('new line: {}'.format(line.strip()))
        new_lines.append(line)

    return new_configuration, new_lines

def configure_mailname(domain):
    '''
        Configure mailname

        >>> with open(MAILNAME_FILE) as f:
        ...     mailname = f.read()
        ...     configure_mailname('new_test')
        ...     configure_mailname('new_test')
        True
        False
        >>> with open(MAILNAME_FILE, 'wt') as f:
        ...     f.write(mailname)
    '''

    new_configuration, new_lines = mailname_needs_configuration(b64decode(domain))
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

        >>> new_config, __ = mailname_needs_configuration('new_test')
        >>> new_config
        True
    '''

    new_configuration = False

    with open(MAILNAME_FILE, 'rt') as input_file:
        lines = input_file.readlines()

    new_lines = []
    for line in lines:
        if domain != line:
            new_configuration = True
            line = domain
            log.write_and_flush('new domain: {}'.format(domain))
        new_lines.append(line)

    return new_configuration, new_lines

if __name__ == "__main__":
    import doctest
    doctest.testmod()

