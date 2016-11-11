'''
    Configure DKIM for the local domain.

    Copyright 2015-2016 GoodCrypto
    Last modified: 2016-10-31
    IMPORTANT: The doc tests in this module can only be run as root.

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, re, sh
from redis import Redis
from rq.queue import Queue

# set up django early
from goodcrypto.utils import gc_django
gc_django.setup()

from goodcrypto.mail.options import set_dkim_public_key
from goodcrypto.system.special_queue_settings import SPECIAL_RQ, SPECIAL_REDIS_PORT
from goodcrypto.utils.constants import REDIS_HOST
from goodcrypto.utils.log_file import LogFile
from goodcrypto.utils.manage_queues import get_job_results
from syr.exception import record_exception

log = LogFile()

def start(domain):
    ''' Start to configure DKIM for the domain. '''

    try:
        if domain is None:
            log.write_and_flush('no domain defined so dkim cannot be configured')
        else:
            ONE_MINUTE = 60 #  one minute, in seconds
            DEFAULT_TIMEOUT = 10 * ONE_MINUTE

            log.write_and_flush('configuring dkim for: {}'.format(domain))

            redis_connection = Redis(REDIS_HOST, SPECIAL_REDIS_PORT)
            queue = Queue(name=SPECIAL_RQ, connection=redis_connection)
            secs_to_wait = DEFAULT_TIMEOUT * (queue.count + 1)
            job = queue.enqueue_call(configure,
                                     args=[domain],
                                     timeout=secs_to_wait)

            result_ok = get_job_results(queue, job, secs_to_wait, 'dkim')

            log.write_and_flush('dkim configuration queued: {}'.format(result_ok))

    except:
        # right now we don't require dkim be configured
        record_exception()

def configure(domain):
    '''
        Configure DKIM for the local domain.

        >>> # save the original conf and host files
        >>> from shutil import copy2
        >>> copy2('/etc/opendkim/opendkimhosts', '/etc/opendkim/opendkimhosts.local')
        >>> copy2('/etc/opendkim.conf', '/etc/opendkim/opendkim.conf.local')
        >>> # set up template files
        >>> copy2('/etc/opendkim/opendkimhosts.template', '/etc/opendkim/opendkimhosts')
        >>> copy2('/etc/opendkim/opendkim.conf.template', '/etc/opendkim.conf')
        >>> configure('goodcrypto.remote')
        True
        >>> os.remove('/etc/opendkim/goodcrypto.remote/dkim.public.key')
        >>> os.remove('/etc/opendkim/goodcrypto.remote/dkim.private.key')
        >>> os.rmdir('/etc/opendkim/goodcrypto.remote')
        >>> # restore the conf and hosts files
        >>> copy2('/etc/opendkim/opendkimhosts.local', '/etc/opendkim/opendkimhosts')
        >>> copy2('/etc/opendkim/opendkim.conf.local', '/etc/opendkim.conf')
        >>> results = sh.service('opendkim', 'restart')
    '''

    try:
        new_configuration = False

        if domain is None:
            log.write_and_flush('cannot config dkim without a domain defined')
        else:
            if configure_conf(domain):
                new_configuration = True

            if configure_hosts(domain):
                new_configuration = True

            if configure_key(domain):
                new_configuration = True

            if new_configuration:
                # restart opendkim with the new settings
                sh.service('opendkim', 'restart')
                log.write_and_flush('opendkim restarted')
    except Exception:
        record_exception()
        raise

    return new_configuration

def configure_conf(domain):
    '''
        Configure opendkim.conf.

        >>> # save the original conf file
        >>> from shutil import copy2
        >>> copy2('/etc/opendkim.conf', '/etc/opendkim/opendkim.conf.local')
        >>> # set up template files
        >>> copy2('/etc/opendkim/opendkim.conf.template', '/etc/opendkim.conf')
        >>> configure_conf('goodcrypto.remote')
        True
        >>> # restore the conf file
        >>> copy2('/etc/opendkim/opendkim.conf.local', '/etc/opendkim.conf')
    '''

    new_configuration = False

    filename = '/etc/opendkim.conf'
    with open(filename, 'rt') as input_file:
        lines = input_file.readlines()

    for line in lines:
        if 'DOMAIN' in line:
            line = line.replace('DOMAIN', domain)
            new_configuration = True

    if new_configuration:
        with open(filename, 'wt') as output_file:
            output_file.write(''.join(lines))
        log.write_and_flush('updated opendkim.conf')

    return new_configuration

def configure_hosts(domain):
    '''
        Configure opendkimhosts.

        >>> # save the original hosts files
        >>> from shutil import copy2
        >>> copy2('/etc/opendkim/opendkimhosts', '/etc/opendkim/opendkimhosts.local')
        >>> # set up template files
        >>> copy2('/etc/opendkim/opendkimhosts.template', '/etc/opendkim/opendkimhosts')
        >>> configure_hosts('goodcrypto.remote')
        True
        >>> # restore the hosts file
        >>> copy2('/etc/opendkim/opendkimhosts.local', '/etc/opendkim/opendkimhosts')
    '''

    new_configuration = False

    filename = '/etc/opendkim/opendkimhosts'
    with open(filename, 'rt') as input_file:
        lines = input_file.readlines()

    for line in lines:
        if 'DOMAIN' in line:
            line = line.replace('DOMAIN', domain)
            new_configuration = True

    if new_configuration:
        with open(filename, 'wt') as output_file:
            output_file.write(''.join(lines))
        log.write_and_flush('updated opendkim master.cf')

    return new_configuration

def configure_key(domain):
    '''
        Configure key.

        >>> configure_key('goodcrypto.remote')
        True
    '''
    '''
        >>> os.remove('/etc/opendkim/goodcrypto.remote/dkim.public.key')
        >>> os.remove('/etc/opendkim/goodcrypto.remote/dkim.private.key')
        >>> os.rmdir('/etc/opendkim/goodcrypto.remote')
    '''

    new_configuration = ok = False

    dirname = os.path.join('/etc/opendkim', domain)
    public_key_filename = os.path.join(dirname, 'dkim.public.key')
    private_key_filename = os.path.join(dirname, 'dkim.private.key')

    if not os.path.exists(dirname):
        os.mkdir(dirname)

    if os.path.exists(public_key_filename) and os.path.exists(private_key_filename):
        with open(public_key_filename, 'rb') as input_file:
            lines = input_file.readlines()
            new_configuration = domain not in ''.join(lines)

        if not new_configuration:
            with open(private_key_filename, 'rb') as input_file:
                lines = input_file.readlines()
                new_configuration = (
                    '-----BEGIN RSA PRIVATE KEY-----' not in ''.join(lines) and
                    '-----END RSA PRIVATE KEY-----' not in ''.join(lines))
    else:
        new_configuration = True

    if new_configuration:
        # remove any old files
        if os.path.exists(public_key_filename): os.remove(public_key_filename)
        if os.path.exists(private_key_filename): os.remove(private_key_filename)

        try:
            # long args not recognozied
            results = sh.opendkim_genkey(
                     '-r',
                     '-h', 'rsa-sha256',
                     '-D', dirname,
                     '-d', domain,
                     '-s', 'mail',
                     '-b', '2048')

            opendkim_public_filename = os.path.join(dirname, 'mail.txt')
            opendkim_private_filename = os.path.join(dirname, 'mail.private')

            if (results.exit_code == 0 and
                os.path.exists(opendkim_public_filename) and
                os.path.exists(opendkim_private_filename)):

                # rename the key files
                os.rename(opendkim_public_filename, public_key_filename)
                os.rename(opendkim_private_filename, private_key_filename)

                # set the permissions
                sh.chown('opendkim:goodcrypto', dirname)
                os.chmod(dirname, 0o750)
                sh.chown('opendkim:goodcrypto', public_key_filename)
                os.chmod(public_key_filename, 0o640)
                sh.chown('opendkim:goodcrypto', private_key_filename)
                os.chmod(private_key_filename, 0o640)

                save_public_key(public_key_filename)

            else:
                log.write_and_flush('results after trying to genkey: {}'.format(results.exit_code))
                log.write_and_flush('  stdout: {}'.format(results.stdout))
                log.write_and_flush('  stderr: {}'.format(results.stderr))
                raise

        except:
            log.write_and_flush('EXCEPTION - See syr.exception.log for more details')
            record_exception()
            raise
    else:
        save_public_key(public_key_filename)

    return new_configuration

def save_public_key(public_key_filename):
    ''' Save the public key in the database. '''

    try:
        # get the public key
        public_key = None
        with open(public_key_filename) as public_key_file:
            lines = public_key_file.readlines()
            for line in lines:
                m = re.match('mail._domainkey IN TXT \"v=DKIM1; h=rsa-sha256; k=rsa; p=(.*?)\"', line)
                if m:
                    public_key = m.group(1)
                else:
                    m = re.match('\s+\"p=(.*?)\"', line)
                    if m:
                        public_key = m.group(1)
                    else:
                        m = re.match('\s+\"(.*?)\"', line)
                        if m and public_key is not None:
                            public_key += m.group(1)

        if public_key is not None:
            set_dkim_public_key(public_key)
            log.write_and_flush('set the dkim pub key to: {}'.format(public_key))
        else:
            log.write_and_flush('unable to parse the dkim public key from:\n{}'.format(lines))
    except:
        log.write_and_flush('EXCEPTION - See syr.exception.log for more details')
        record_exception()

if __name__ == "__main__":
    import doctest
    doctest.testmod()

