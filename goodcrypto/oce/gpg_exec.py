#!/usr/bin/env python
'''
    Single module where gpg is invoked. 
    
    GPG should never be directly invoked from anywhere else.

    Copyright 2014 GoodCrypto
    Last modified: 2014-10-25

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, sh
from base64 import b64decode, b64encode
from random import uniform
from tempfile import gettempdir
from time import sleep
from traceback import format_exc

from goodcrypto.oce import gpg_constants
from goodcrypto.oce.constants import LOG_PASSPHRASES
from goodcrypto.oce.key.gpg_utils import parse_fingerprint_and_expiration
from goodcrypto.oce.rq_gpg_settings import GPG_QUEUE, GPG_REDIS_PORT
from goodcrypto.oce.utils import is_expired
from goodcrypto.utils.log_file import LogFile
from goodcrypto.utils.manage_queue import get_job_count
from syr.cli import minimal_env
from syr.lock import locked


def execute_gpg_command(home_dir, timeout, initial_args, passphrase=None, data=None):
    '''
        Issue a GPG command in its own worker so there are no concurrency challenges.
    '''
    
    log = LogFile(filename='goodcrypto.oce.gpg_exec_queue.log')
    gpg_exec = None
    try:
        gpg_exec = GPGExec(home_dir, timeout)
        log.write_and_flush('gpg exec: {}'.format(gpg_exec))
        gpg_exec.wait_for_other_gpg_jobs()
        
        if initial_args is not None:
            new_args = []
            for arg in initial_args:
                new_args.append(b64decode(arg))
            initial_args = new_args
        if passphrase is not None:
            passphrase = b64decode(passphrase)
        if data is not None:
            data = b64decode(data)

        result_code, gpg_output, gpg_error = gpg_exec.execute(initial_args, passphrase, data)
        
        log.write_and_flush('result code: {}'.format(result_code))
        if gpg_output is not None: 
            gpg_output = b64encode(gpg_output)
        if gpg_error is not None: 
            gpg_error = b64encode(gpg_error)
    except Exception as exception:
        result_code = gpg_constants.ERROR_RESULT
        gpg_output = None
        gpg_error = b64encode(str(exception))
        log.write_and_flush(exception)

        if gpg_exec is not None and gpg_exec.gpg_home is not None:
            gpg_exec.clear_gpg_lock_files()
            gpg_exec.clear_gpg_tmp_files()

    log.flush()

    return result_code, gpg_output, gpg_error


class GPGExec(object):
    '''
        Execute a gpg command.
        
        gpg expects single tasks so we use redis to queue tasks.
        
        -fd: 0 = stdin
             1 = stdout
             2 = stderr
    '''

    DEBUGGING = False
    CONF_FILENAME = 'gpg.conf'
    
    def __init__(self, home_dir, timeout):
        '''
            Create a new GPGExec object.  
            
            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> gpg_exec != None
            True
        '''

        self.log = LogFile()

        self.gpg_home = home_dir
        self.timeout = timeout * 1000 # in ms
        
        self.result_code = gpg_constants.ERROR_RESULT
        self.gpg_output = None
        self.gpg_error = None

        self.set_up_conf()

        # --no-tty: Do not write anything to TTY
        # --homedir: home directory for gpg's keyring files
        # --verbose: give details if error
        # --no-options: For security, we don't want to use file options.
        # --ignore-time-conflict: Since different machines have different ideas of what time it is, we want to ignore time conflicts.
        # --ignore-valid-from: "valid-from" is just a different kind of time conflict.
        # --batch: We're always in batch mode.
        # --lock-once: Lock the databases the first time a lock is requested and do not release the lock until the process terminates. 
        # --always-trust: We don't have any trust infrastructure yet.
        # --utf8-strings: Assume all arguments are in UTF-8 format.
        # --no-secmem-warning: Gpg (used to?) complains about mem unless we're root, and we shouldn't be running as root.
        # redirect stdout and stderr so we can exam the results as needed
        self.gpg = sh.gpg.bake(_bg=True, no_tty=True, verbose=True, homedir=self.gpg_home,
           no_options=True, ignore_time_conflict=True, ignore_valid_from=True, batch=True, 
           always_trust=True, lock_once=True, _env=minimal_env())

    def execute(self, initial_args, passphrase=None, data=None):
        '''
            Issue a gpg command.
            
            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> len(gpg_exec.execute(['--version'])) > 0
            True
        '''
        
        result_ok = False
        ready_to_run = True
        email_semaphore = None
        try:
            # if creating a key, see if it is being created with another task
            if gpg_constants.GEN_KEY in initial_args and data is not None:
                ready_to_run, email_semaphore = self.prep_to_gen_key(data)
                if ready_to_run:
                    self.log_message('ready to gen key with args: {}'.format(initial_args))
                    self.prep_and_run(initial_args, passphrase, data)
                else:
                    self.result_code = True
                    self.gpg_output = self.gpg_error = ''

            # if deleting a key, get the fingerprint for the user, and then run the command
            elif gpg_constants.DELETE_KEYS in initial_args:
                fingerprint = self.prep_to_delete_key(initial_args)
                if fingerprint is not None:
                    new_args = [gpg_constants.DELETE_KEYS, fingerprint]
                    self.log_message('ready to delete key with args: {}'.format(new_args))
                    self.prep_and_run(new_args)

            else:
                self.prep_and_run(initial_args, passphrase, data)
            
            if GPGExec.DEBUGGING:
                if self.gpg_output is not None:
                    self.log_message('gpg_output: {}'.format(self.gpg_output))
                if self.gpg_error is not None:
                    self.log_message('gpg_error: {}'.format(self.gpg_error))

        finally:
            # remove the temporary file if we created it
            if ready_to_run and email_semaphore is not None and os.path.exists(email_semaphore):
                os.remove(email_semaphore)
                self.log_message('removed email file: {}'.format(email_semaphore))

        self.log.flush()

        return self.result_code, self.gpg_output, self.gpg_error

    def prep_and_run(self, initial_args, passphrase=None, data=None):
        '''
            Prepare and then run a gpg command.
            
            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> gpg_exec.prep_and_run(['--version'])
        '''
        
        result_ok = False
        try:
            stdin = []
            args = initial_args

            if passphrase and len(passphrase) > 0:
                if LOG_PASSPHRASES:
                    self.log_message('DEBUG ONLY! passphrase: "{}"'.format(passphrase))
                else:
                    self.log_message('passphrase supplied')

                # passphrase will be passed on stdin, file descriptor 0 is stdin
                passphraseOptions = ['--passphrase-fd', '0']
                args.append(passphraseOptions)
                stdin.append('{}{}'.format(passphrase, gpg_constants.EOL))


            if data and len(data) > 0:
                stdin.append('{}{}'.format(data, gpg_constants.EOL))

            if GPGExec.DEBUGGING:
                if LOG_PASSPHRASES and stdin:
                    self.log_message("gpg args: {} stdin: {}".format(args, stdin))
                else:
                    self.log_message("gpg args:")
                    for arg in args:
                        self.log_message('  {}'.format(arg))
            
            result_ok = self.run_gpg(args, stdin)
            self.log_message("gpg command result_ok: {}".format(result_ok))
            if GPGExec.DEBUGGING:
                self.log_message("gpg output: {}".format(self.gpg_output))
                self.log_message("gpg error: {}".format(self.gpg_error))

        except Exception as exception:
            result_ok = False
            self.result_code = gpg_constants.ERROR_RESULT
            self.gpg_error = str(exception)
                
            self.log_message('result code: {}'.format(self.result_code))
            self.log_message("gpg error: {}".format(self.gpg_error))
            self.log_message("exception: \n{}".format(format_exc()))
            
    def run_gpg(self, args, stdin):
        ''' Run the GPG command.
            
            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> gpg_exec.run_gpg(['--version'], stdin=None)
            True
        '''

        try:
            self.log_message('--- started executing: {} ---'.format(args[0]))
            self.log.write_and_flush('home dir: {}'.format(self.gpg_home))
            self.log.write_and_flush('timeout: {}'.format(self.timeout))

            if stdin and len(stdin) > 0:
                gpg_process = self.gpg(*args, _in=stdin, _timeout=self.timeout, _ok_code=[0,2])
            else:
                gpg_process = self.gpg(*args, _timeout=self.timeout, _ok_code=[0,2])
    
            gpg_results = gpg_process.wait()
    
            self.log_message('--- finished executing: {} ---'.format(args[0]))
            
            self.result_code = gpg_results.exit_code
            self.gpg_output = gpg_results.stdout
            self.gpg_error = gpg_results.stderr
            
            if GPGExec.DEBUGGING:
                self.log_message('gpg results: {}'.format(self.result_code))
                if self.gpg_output and type(self.gpg_output) == str:
                    self.log_message(self.gpg_output)
                if self.gpg_error and type(self.gpg_output) == str:
                    self.log_message(self.gpg_error)

        except sh.ErrorReturnCode as exception:
            self.result_code = exception.exit_code
            
            if self.gpg_error is None:
                self.gpg_error = exception.stderr

            # get the essence of the error
            self.gpg_error = exception.stderr
            if self.gpg_error and self.gpg_error.find(':'):
                self.gpg_error = self.gpg_error[self.gpg_error.find(':') + 1:]
            if self.gpg_error and self.gpg_error.find(':'):
                self.gpg_error = self.gpg_error[self.gpg_error.find(':') + 1:]

            self.log_message('exception result code: {}'.format(self.result_code))
            if exception:
                self.log_message("exception:\n==============\n{}\n============".format(exception))

        return self.result_code == gpg_constants.GOOD_RESULT

    def prep_to_gen_key(self, data):
        ''' 
            Prepare to generate a key and make sure there aren't any dups.
            
            >>> # In honor of Lutz Janicke, who is a current OpenSSL development team member.
            >>> email = 'lutz@goodcrypto.local'
            >>> email_semaphore = '/tmp/__keygen.{}__'.format(email)
            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> data = '{}{}{}'.format(gpg_constants.NAME_EMAIL, email, gpg_constants.EOL)
            >>> gpg_exec.prep_to_gen_key(data)
            (True, '/tmp/__keygen.lutz@goodcrypto.local__')
            >>> gpg_exec.prep_to_gen_key(data)
            (False, '/tmp/__keygen.lutz@goodcrypto.local__')
            >>> os.remove(email_semaphore)
        '''

        ready_to_run = True
        email_semaphore = email = None

        # parse the email address from the data
        start_index = data.find(gpg_constants.NAME_EMAIL)
        if start_index >= 0:
            start_index += len(gpg_constants.NAME_EMAIL)
            end_index = start_index + data[start_index:].find(gpg_constants.EOL)
            if end_index > 0:
                self.log_message('data: {}'.format(data[start_index:end_index]))
                email = data[start_index:end_index].strip().lower()

        # see if a key creation is in progress
        if email is None:
            self.log_message('email is not defined in {}'.format(data))
        else:
            email_semaphore = os.path.join(gettempdir(), '__keygen.{}__'.format(email))
            if os.path.exists(email_semaphore):
                ready_to_run = False
                self.log_message('email file exists: {}'.format(email_semaphore))
            else:
                with open(email_semaphore, 'wt') as f:
                    f.write('creating key for {}'.format(email))
                self.log_message('created email semaphore: {}'.format(email_semaphore))
                
                ready_to_run = self.check_for_dups(email)

        return ready_to_run, email_semaphore

    def check_for_dups(self, email):
        ''' 
            Check for dups; delete any expired keys. 
            
            >>> # In honor of Steve Marquess, who is a current OpenSSL development team member.
            >>> email = 'steve@goodcrypto.local'
            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> gpg_exec.check_for_dups(email)
            True
            >>> gpg_exec.check_for_dups('edward@goodcrypto.local')
            False
        '''
        
        ready_to_run = True
        
        done = False
        while not done:
            self.prep_and_run([gpg_constants.GET_FINGERPRINT, '<{}>'.format(email)])
            if self.result_code == gpg_constants.GOOD_RESULT:
                fingerprint, expiration = parse_fingerprint_and_expiration(self.gpg_output)
                if is_expired(expiration):
                    self.prep_and_run([gpg_constants.DELETE_KEYS, fingerprint])
                    self.log_message('delete expired key for {}'.format(email))
                else:
                    # check if this key is private 
                    self.prep_and_run([gpg_constants.LIST_SECRET_KEYS, fingerprint])
                    if self.result_code == gpg_constants.GOOD_RESULT:
                        self.log_message('key already exists for {}'.format(email))
                        ready_to_run = False
                        done = True
                    else:
                        self.prep_and_run([gpg_constants.DELETE_KEYS, fingerprint])
                        self.log_message('delete public key for {} so we could create private key'.format(email))
            else:
                done = True

        return ready_to_run

    def prep_to_delete_key(self, initial_args):
        ''' 
            Prepare to delete a key. 

            >>> # In honor of Bodo Moller, who is a current OpenSSL development team member.
            >>> email = 'bodo@goodcrypto.local'
            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> fingerprint = gpg_exec.prep_to_delete_key([gpg_constants.DELETE_KEYS, email])
            >>> fingerprint is None
            True
            >>> fingerprint = gpg_exec.prep_to_delete_key([gpg_constants.DELETE_KEYS, 'edward@goodcrypto.local'])
            >>> fingerprint is not None and len(fingerprint) > 0
            True
        '''
        
        fingerprint = None
        
        if len(initial_args) == 2:
            # get the user's fingerprint
            self.prep_and_run([gpg_constants.GET_FINGERPRINT, '<{}>'.format(initial_args[1])])
            if self.result_code == gpg_constants.GOOD_RESULT:
                fingerprint, expiration = parse_fingerprint_and_expiration(self.gpg_output)
        else:
            self.log_message('wrong initial args to delete key: {}'.format(initial_args))

        return fingerprint
        
    def set_up_conf(self):
        ''' 
            Set up the GPG conf file, if it doesn't exist. 
        	
            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> gpg_exec.set_up_conf()
        '''

        try:
            if self.gpg_home is None:
                self.log_message('gpg home not defined yet')
            else:
                gpg_conf = os.path.join(self.gpg_home, self.CONF_FILENAME)
                if not os.path.exists(gpg_conf):
                    lines = []
                    lines.append('#\n')
                    lines.append('# This is an adpation of the Riseup OpenPGP Best Practices\n')
                    lines.append('# https://help.riseup.net/en/security/message-security/openpgp/best-practices\n')
                    lines.append('#\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# behavior\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# Disable inclusion of the version string in ASCII armored output\n')
                    lines.append('no-emit-version\n')
                    lines.append('# Disable comment string in clear text signatures and ASCII armored messages\n')
                    lines.append('no-comments\n')
                    lines.append('# Display long key IDs\n')
                    lines.append('keyid-format 0xlong\n')
                    lines.append('# List all keys (or the specified ones) along with their fingerprints\n')
                    lines.append('with-fingerprint\n')
                    lines.append('# Display the calculated validity of user IDs during key listings\n')
                    lines.append('list-options show-uid-validity\n')
                    lines.append('verify-options show-uid-validity\n')
                    lines.append('# Try to use the GnuPG-Agent. With this option, GnuPG first tries to connect to\n')
                    lines.append('# the agent before it asks for a passphrase.\n')
                    lines.append('use-agent\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# keyserver -- goodcrypto relies on per-to-per key exchange, not key servers\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# This is the server that --recv-keys, --send-keys, and --search-keys will\n')
                    lines.append('# communicate with to receive keys from, send keys to, and search for keys on\n')
                    lines.append('# keyserver hkps://hkps.pool.sks-keyservers.net\n')
                    lines.append('# Provide a certificate store to override the system default\n')
                    lines.append('# Get this from https://sks-keyservers.net/sks-keyservers.netCA.pem\n')
                    lines.append('# keyserver-options ca-cert-file=/usr/local/etc/ssl/certs/hkps.pool.sks-keyservers.net.pem\n')
                    lines.append('# Set the proxy to use for HTTP and HKP keyservers - default to the standard\n')
                    lines.append('# local Tor socks proxy\n')
                    lines.append('# It is encouraged to use Tor for improved anonymity. Preferrably use either a\n')
                    lines.append('# dedicated SOCKSPort for GnuPG and/or enable IsolateDestPort and\n')
                    lines.append('# IsolateDestAddr\n')
                    lines.append('#keyserver-options http-proxy=socks5-hostname://127.0.0.1:9050\n')
                    lines.append("# Don't leak DNS, see https://trac.torproject.org/projects/tor/ticket/2846\n")
                    lines.append('keyserver-options no-try-dns-srv\n')
                    lines.append('# When using --refresh-keys, if the key in question has a preferred keyserver\n')
                    lines.append('# URL, then disable use of that preferred keyserver to refresh the key from\n')
                    lines.append('keyserver-options no-honor-keyserver-url\n')
                    lines.append('# When searching for a key with --search-keys, include keys that are marked on\n')
                    lines.append('# the keyserver as revoked\n')
                    lines.append('keyserver-options include-revoked\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# algorithm and ciphers\n')
                    lines.append('#-----------------------------\n')
                    lines.append('# list of personal digest preferences. When multiple digests are supported by\n')
                    lines.append('# all recipients, choose the strongest one\n')
                    lines.append('personal-cipher-preferences AES256 AES192 AES CAST5\n')
                    lines.append('# list of personal digest preferences. When multiple ciphers are supported by\n')
                    lines.append('# all recipients, choose the strongest one\n')
                    lines.append('personal-digest-preferences SHA512 SHA384 SHA256 SHA224\n')
                    lines.append('# message digest algorithm used when signing a key\n')
                    lines.append('cert-digest-algo SHA512\n')
                    lines.append('# This preference list is used for new keys and becomes the default for\n')
                    lines.append('# "setpref" in the edit menu\n')
                    lines.append('default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed\n')
                    '''
                    lines.append('# when outputting certificates, view user IDs distinctly from keys:\n')
                    lines.append('fixed-list-mode\n')
                    lines.append("# long keyids are more collision-resistant than short keyids (it's trivial to make a key with any desired short keyid)")
                    lines.append('keyid-format 0xlong\n')
                    lines.append('# when multiple digests are supported by all recipients, choose the strongest one:\n')
                    lines.append('personal-digest-preferences SHA512 SHA384 SHA256 SHA224\n')
                    lines.append('# preferences chosen for new keys should prioritize stronger algorithms: \n')
                    lines.append('default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 BZIP2 ZLIB ZIP Uncompressed\n')
                    lines.append("# If you use a graphical environment (and even if you don't) you should be using an agent:")
                    lines.append('# (similar arguments as  https://www.debian-administration.org/users/dkg/weblog/64)\n')
                    lines.append('use-agent\n')
                    lines.append('# You should always know at a glance which User IDs gpg thinks are legitimately bound to the keys in your keyring:\n')
                    lines.append('verify-options show-uid-validity\n')
                    lines.append('list-options show-uid-validity\n')
                    lines.append('# include an unambiguous indicator of which key made a signature:\n')
                    lines.append('# (see http://thread.gmane.org/gmane.mail.notmuch.general/3721/focus=7234)\n')
                    lines.append('sig-notation issuer-fpr@notations.openpgp.fifthhorseman.net=%g\n')
                    lines.append('# when making an OpenPGP certification, use a stronger digest than the default SHA1:\n')
                    lines.append('cert-digest-algo SHA256\n')
                    '''
    
                    self.log_message('creating {}'.format(gpg_conf))
                    with open(gpg_conf, 'wt') as f:
                        for line in lines:
                            f.write(line)
                    sh.chmod('0400', gpg_conf)
                    self.log_message('created {}'.format(gpg_conf))
        except Exception:
            self.log_message(format_exc())

    def wait_for_other_gpg_jobs(self):
        ''' 
            Wait until gpg lock files are gone or timeout whichever comes first.

            Lock files are in gpg home directory and are in the form
            ".*.lock", ".?*", or possibly "trustdb.gpg.lock".
            
            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> gpg_exec.wait_for_other_gpg_jobs()
        '''

        with locked():
            try:
                done = False
                while not done:
                    psgrep_result = sh.psgrep('/usr/bin/gpg')
                    if (psgrep_result.exit_code == 0) and (psgrep_result.stdout == ''):
                        done = True
                    else:
                        self.log_message('psgrep_result: {}'.format(psgrep_result))
                        self.log_message('exit code: {}'.format(psgrep_result.exit_code))
                        self.log_message('stdout: {}'.format(psgrep_result.stdout))
    
                        # sleep a random amount of time to minimize deadlock
                        secs = uniform(1, 10)
                        sleep(secs)
            except sh.ErrorReturnCode as e:
                pass
    
            # gpg should not be running
            self.clear_gpg_lock_files()
            self.clear_gpg_tmp_files()

    def clear_gpg_lock_files(self):
        ''' 
            Delete gpg lock files.

            Warning: Calling this method when a valid lock file exists can have very
            serious consequences.

            Lock files are in gpg home directory and are in the form
            ".*.lock", ".?*", or possibly "trustdb.gpg.lock".
            
            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> gpg_exec.clear_gpg_lock_files()
            
            >>> gpg_exec = GPGExec(None, 1)
            >>> gpg_exec.clear_gpg_lock_files()
        '''

        try:
            if self.gpg_home is None:
                self.log_message("unable to clear gpg's lock files because home dir unknown")
            else:
                filenames = os.listdir(self.gpg_home)
                if filenames and len(filenames) > 0:
                    for name in filenames:
                        if name.endswith(gpg_constants.LOCK_FILE_SUFFIX):
                            os.remove(os.path.join(self.gpg_home, name))
                            self.log_message("deleted lock file " + name)
        except Exception:
            self.log_message(format_exc())

    def clear_gpg_tmp_files(self):
        ''' 
            Delete gpg tmp files.

            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> gpg_exec.clear_gpg_tmp_files()
            
            >>> gpg_exec = GPGExec(None, 1)
            >>> gpg_exec.clear_gpg_tmp_files()
        '''

        TmpPREFIX = 'tmp'
        TmpSUFFIX = '~'

        try:
            if self.gpg_home is None:
                self.log_message("unable to clear gpg's tmp files because home dir unknown")
            else:
                filenames = os.listdir(self.gpg_home)
                if filenames and len(filenames) > 0:
                    for name in filenames:
                        if name.startswith(TmpPREFIX) and name.endswith(TmpSUFFIX):
                            os.remove(os.path.join(self.gpg_home, name))
        except Exception:
            self.log_message(format_exc())

    def log_message(self, message):
        '''
            Log the message.
            
            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> gpg_exec = GPGExec('/var/local/projects/goodcrypto/server/data/oce/.gnupg', 1)
            >>> gpg_exec.log_message('test message')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.oce.gpg_exec.x.log'))
            True
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

