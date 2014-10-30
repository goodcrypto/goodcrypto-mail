'''
    Configure postfix to work with the main MTA

    Copyright 2014 GoodCrypto
    Last modified: 2014-10-13

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import re, sh
from traceback import format_exc
from syr.log import get_log

log = get_log()

def configure(mail_server_address, in_port, out_port, domain):
    '''
        Configure postfix to work with the main MTA and domain.
        
        >>> configure('125.6.78.1', 10021, 10022, 'test')
        True
        >>> configure('125.6.78.1', 10021, 10022, 'test')
        False
    '''
    
    try:
        new_configuration = False
        
        if configure_main(mail_server_address, out_port):
            new_configuration = True
        
        if configure_master(in_port):
            new_configuration = True

        if configure_mailname(domain):
            new_configuration = True

        if new_configuration:
            # restart postfix with the new settings
            sh.service('postfix', 'restart')
            log.write('postfix restarted')
    except Exception:
        log.write(format_exc())
        raise

    return new_configuration
    
def configure_main(mail_server_address, out_port):
    '''
        Configure main.cf.
        
        >>> configure_main('123.456.789.0', 10024)
        True
        >>> configure_main('123.456.789.0', 10024)
        False
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
        
        >>> configure_master(10023)
        True
        >>> configure_master(10023)
        False
    '''
    
    new_configuration = False

    filename = '/etc/postfix/master.cf'
    with open(filename, 'rt') as input_file:
        lines = input_file.readlines()
    
    new_lines = []
    for line in lines:
        l = line.lower()
        m = re.match('^(\d{2,5}) .*', l)
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

        >>> configure_mailname('new_test')
        True
        >>> configure_mailname('new_test')
        False
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
        log.write('updated postfix master.cf')

    return new_configuration

if __name__ == "__main__":
    import doctest
    doctest.testmod()

