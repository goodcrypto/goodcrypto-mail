'''
    Configure postfix to work with the main MTA

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-06-08
    IMPORTANT: The doc tests in this module can only be run as root.

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import re, sh
from goodcrypto.utils.exception import record_exception
from syr.log import get_log

log = get_log()

def configure_mta(mail_server_address, in_port, out_port):
    '''
        Configure postfix to work with the main MTA.
        
        >>> with open('/etc/postfix/master.cf') as f:
        ...     master_contents = f.read()
        >>> with open('/etc/postfix/main.cf') as f:
        ...     main_contents = f.read()
        ...     configure_mta('125.6.78.1', 10021, 10022)
        ...     configure_mta('125.6.78.1', 10021, 10022)
        True
        False
        >>> with open('/etc/postfix/master.cf', 'wt') as f:
        ...     f.write(master_contents)
        >>> with open('/etc/postfix/main.cf', 'wt') as f:
        ...     f.write(main_contents)
    '''
    
    try:
        new_configuration = False
        
        if configure_main(mail_server_address, out_port):
            new_configuration = True
        
        if configure_master(in_port):
            new_configuration = True

        if new_configuration:
            # restart postfix with the new settings
            sh.service('postfix', 'restart')
            log.write('postfix restarted')
    except Exception:
        record_exception()
        raise

    return new_configuration
    
def configure_main(mail_server_address, out_port):
    '''
        Configure main.cf.
        
        >>> with open('/etc/postfix/main.cf') as f:
        ...     master_contents = f.read()
        ...     configure_main('123.456.789.0', 10024)
        ...     configure_main('123.456.789.0', 10024)
        True
        False
        >>> with open('/etc/postfix/main.cf', 'wt') as f:
        ...     f.write(master_contents)
    '''
    
    new_configuration = False

    filename = '/etc/postfix/main.cf'
    with open(filename, 'rt') as input_file:
        lines = input_file.readlines()

    new_lines = []
    for line in lines:
        l = line.lower()
        if l.startswith('mynetworks'):
            new_line = 'mynetworks = localhost 10.0.2.2 {}\n'.format(mail_server_address)
            if new_line != line:
                new_configuration = True
                line = new_line
                log.write('new line: {}'.format(line))
        elif l.startswith('default_transport'):
            new_line = 'default_transport = smtp:[{}]:{}\n'.format(mail_server_address, out_port)
            if new_line != line:
                new_configuration = True
                line = new_line
                log.write('new line: {}'.format(line))
        new_lines.append(line)                

    if new_configuration:
        with open(filename, 'wt') as output_file:
            output_file.write(''.join(new_lines))
        log.write('updated postfix main.cf')

    return new_configuration

def configure_master(in_port):
    '''
        Configure master.cf.
        
        >>> with open('/etc/postfix/master.cf') as f:
        ...     main_contents = f.read()
        ...     configure_master(10023)
        ...     configure_master(10023)
        True
        False
        >>> with open('/etc/postfix/master.cf', 'wt') as f:
        ...     f.write(main_contents)
    '''
    
    new_configuration = False

    filename = '/etc/postfix/master.cf'
    with open(filename, 'rt') as input_file:
        lines = input_file.readlines()
    
    new_lines = []
    for line in lines:
        l = line.lower()
        m = re.match('^0.0.0.0:(\d{2,5}) .*', l)
        if m:
            new_line = line.replace(m.group(1), str(in_port))
            if new_line != line:
                new_configuration = True
                line = new_line
                log.write('new line: {}'.format(line))
        new_lines.append(line)

    if new_configuration:
        with open(filename, 'wt') as output_file:
            output_file.write(''.join(new_lines))
        log.write('updated postfix master.cf')

    return new_configuration

def configure_mailname(domain):
    '''
        Configure mailname

        >>> with open('/etc/mailname') as f:
        ...     mailname = f.read()
        ...     configure_mailname('new_test')
        ...     configure_mailname('new_test')
        True
        False
        >>> with open('/etc/mailname', 'wt') as f:
        ...     f.write(mailname)
    '''
    
    new_configuration = False

    filename = '/etc/mailname'
    with open(filename, 'rt') as input_file:
        lines = input_file.readlines()
    
    new_lines = []
    for line in lines:
        if domain != line:
            new_configuration = True
            line = domain
            log.write('new domain: {}'.format(domain))
        new_lines.append(line)

    if new_configuration:
        with open(filename, 'wt') as output_file:
            output_file.write(''.join(new_lines))
        log.write('updated mailname')

        # restart postfix with the new settings
        sh.service('postfix', 'restart')
        log.write('postfix restarted')

    return new_configuration

if __name__ == "__main__":
    import doctest
    doctest.testmod()

