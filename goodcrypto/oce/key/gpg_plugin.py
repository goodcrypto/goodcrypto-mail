#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, re, shutil
from tempfile import mkdtemp
from time import sleep
from traceback import format_exc

from goodcrypto.oce import gpg_constants
from goodcrypto.oce.constants import LOG_PASSPHRASES
from goodcrypto.oce.gpg_plugin import GPGPlugin as GPGCryptoPlugin
from goodcrypto.oce.key.abstract_key import AbstractKey
from goodcrypto.oce.key.gpg_constants import NAME, PUBLIC_KEY_PREFIX, USER_ID_PACKET_PREFIX
from goodcrypto.oce.key.gpg_utils import get_standardized_expiration, parse_fingerprint_and_expiration
from goodcrypto.oce.utils import is_expired, parse_address
#from syr.sync_function import synchronized


class GPGPlugin(GPGCryptoPlugin, AbstractKey):
    '''
        Gnu Privacy Guard crypto key plugin.

        For the functions that usually insist on /dev/tty, use --batch and specify the key by
        using the fingerprint, with no spaces.

        !!!! Warning: Code here should be careful to only allow one instance of gpg at a time.
    '''

    # we want to use RSA for both the master key and all sub-keys
    # DSA appears to have been comprimised because the 'standard' key size
    # is only 1024 which is bad guys likely have rainbow tables to crack
    DefaultKeyLength = '4096'
    DefaultKeyType = 'RSA'
    DefaultSubkeyType = 'RSA'

    def __init__(self):
        '''
            Creates a new GPGPlugin object.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin != None
            True
        '''

        super(GPGPlugin, self).__init__()


    #@synchronized
    def get_plugin_name(self):
        '''
            Get the plugin's name.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.get_plugin_name() == 'goodcrypto.oce.key.gpg_plugin.GPGPlugin'
            True
        '''

        return NAME


    #@synchronized
    def get_plugin_version(self):
        '''
            Get the version of this plugin's implementation.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> version = plugin.get_plugin_version()
            >>> version is not None
            True
            >>> version == '0.1'
            True
        '''

        return '0.1'


    def is_function_supported(self, func):
        '''
            Returns whether the specified function is supported.

            >>> from goodcrypto.oce.key.constants import CREATE_FUNCTION
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.is_function_supported(CREATE_FUNCTION)
            True
            >>> plugin.is_function_supported('non_existant_function')
            False
        '''

        try:
            function_supported = func in dir(self)
        except Exception:
            function_supported = False
            self.log_message(format_exc())

        return function_supported


    def create(self, user_id, passcode, expiration=None, wait_for_results=False):
        '''
            Create a new key. If wait_for_results is False, then start the process, but
            don't wait for the results.

            If the key already exists and hasn't expired, then return True without creating a new key.
            If key generated while waiting or key generation started successfully when not waiting, 
            then return True; otherwise, False.

            >>> # In honor of Moritz Bartl, advocate for the Tor project.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> if os.path.exists('/var/local/projects/goodcrypto/server/data/special_test_oce'):
            ...     rmtree('/var/local/projects/goodcrypto/server/data/special_test_oce')
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/special_test_oce/.gnupg')
            True
            >>> ok, _ = plugin.create('moritz@goodcrypto.local', 'a secret code')
            >>> ok
            True
            >>> sleep(30)
            >>> from shutil import rmtree
            >>> if os.path.exists('/var/local/projects/goodcrypto/server/data/special_test_oce/.gnupg'):
            ...     rmtree('/var/local/projects/goodcrypto/server/data/special_test_oce/.gnupg')
            >>> if os.path.exists('/var/local/projects/goodcrypto/server/data/special_test_oce'):
            ...     rmtree('/var/local/projects/goodcrypto/server/data/special_test_oce')

            >>> # In honor of Roger Dingledine, one of the original developers of the Tor project.
            >>> from goodcrypto.oce.key.constants import EXPIRES_IN, EXPIRATION_UNIT
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> email = 'roger@goodcrypto.local'
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> ok, _ = plugin.create(email, 'a secret code', wait_for_results=True)
            >>> ok
            True
            >>> ok, _ = plugin.create(email, 'another code', wait_for_results=True)
            >>> ok
            False
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        result_code = gpg_constants.ERROR_RESULT
        try:
            self.log_message('gen key for {} that expires within {}'.format(user_id, expiration))
            if LOG_PASSPHRASES:
                self.log_message('DEBUG ONLY! passcode: {}'.format(passcode))
    
            name, email = parse_address(user_id)
            if name == None or len(name) <= 0:
                index = email.find('@')
                if index > 0:
                    name = email[:index].capitalize()
                else:
                    name = email
    
            expires_in, expiration_unit = get_standardized_expiration(expiration)
    
            data = ''
            data += '{}{}{}'.format(gpg_constants.KEY_TYPE, self.DefaultKeyType, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.KEY_LENGTH, self.DefaultKeyLength, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.SUBKEY_TYPE, self.DefaultSubkeyType, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.SUBKEY_LENGTH, self.DefaultKeyLength, gpg_constants.EOL)
            data += '{}{}{}{}'.format(gpg_constants.EXPIRE_DATE, expires_in, expiration_unit, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.KEY_PASSPHRASE, passcode, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.NAME_REAL, name, gpg_constants.EOL)
            data += '{}{}{}'.format(gpg_constants.NAME_EMAIL, email, gpg_constants.EOL)
            data += '{}{}'.format(gpg_constants.COMMIT_KEY, gpg_constants.EOL)
    
            if GPGPlugin.DEBUGGING:
                if LOG_PASSPHRASES:
                    self.log_message(data)
                else:
                    self.log_message('Name-Real: {}'.format(name))
                    self.log_message('Name-Email: {}'.format(email))
                    self.log_message('Expire-Date: {}{}'.format(expires_in, expiration_unit))

            # use the default timeout unless waiting for results
            if wait_for_results or self.USE_QUEUE:
                self.timeout = 20 * self.ONE_MINUTE 
                
            result_code, gpg_output, gpg_error = self.gpg_command(
                [gpg_constants.GEN_KEY], data=data, wait_for_results=wait_for_results)
            self.log_message('created key for {} <{}>: {} result code'.format(name, email, result_code))
            if gpg_output: self.log_message(gpg_output)
            if gpg_error: self.log_message(gpg_error)

        except Exception as exception:
            self.handle_unexpected_exception(exception)
        finally:
            self.log_message('finished trying to gen key for {}'.format(user_id))

        return result_code == gpg_constants.GOOD_RESULT, result_code == gpg_constants.TIMED_OUT_RESULT


    def delete(self, user_id):
        '''
            Delete an existing key, or key pair, from the keyring.

            >>> # In honor of Caspar Bowden, advocate for Tor in Europe.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> ok, _ = plugin.create('caspar@goodcrypto.local', 'test passphrase', wait_for_results=True)
            >>> ok
            True
            >>> plugin.delete('caspar@goodcrypto.local')
            True
            >>> plugin.delete('unknown@goodcrypto.local')
            False
            >>> plugin.delete(None)
            False
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        result_ok = True
        try:
            if user_id is None:
                result_ok = False
                self.log_message('no need to delete key for blank user id')
            else:
                _, address = parse_address(user_id)
                self.log_message('deleting: {}'.format(address))
                tries = 0
                done = False
                while not done:
                    # delete the public and private key -- do *not* include <> or quotes
                    args = [gpg_constants.DELETE_KEYS, address]
                    result_code, gpg_output, gpg_error = self.gpg_command(args, wait_for_results=True)
                    tries += 1
                    if result_code != 0:
                        done = True
                        # if this is the first attempt and it failed, then remember that result
                        if tries == 1:
                            result_ok = False
                            if gpg_output: self.log_message(gpg_output)
                            if gpg_error: self.log_message(gpg_error)
        except Exception as exception:
            result_ok = False
            self.log_message(format_exc())
            self.handle_unexpected_exception(exception)

        self.log_message('delete ok: {}'.format(result_ok))

        return result_ok


    def delete_private_key_only(self, user_id):
        '''
            Delete an existing secret key from the keyring.

            GPG (as of 1.2.3) has a bug that allows more than ine unrelated key to
            have the same user id.
            If there is more than one key that matches the user id, all will be deleted.

            >>> # In honor of Griffin Boyce, a developer for browser extensions to let 
            >>> # people volunteer to become a Flash Proxy for censored users.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> ok, _ = plugin.create('griffin@goodcrypto.local', 'test passphrase', wait_for_results=True)
            >>> ok
            True
            >>> plugin.delete_private_key_only('unknown@goodcrypto.local')
            False
            >>> plugin.delete_private_key_only(None)
            False
            >>> plugin.delete_private_key_only('griffin@goodcrypto.local')
            True
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        result_code = gpg_constants.ERROR_RESULT
        self.log_message('delete private key for user_id: {}'.format(user_id))
        try:
            # batch mode requires that we use the fingerprint instead of the email address
            fingerprint, expiration = self.get_fingerprint(user_id)
            if expiration:
                self.log_message('{} key expired on {}'.format(user_id, expiration))

            result_ok = fingerprint is not None
            if result_ok:
                # delete the private key
                args = [gpg_constants.DELETE_SECRET_KEY, fingerprint]
                result_code, gpg_output, gpg_error = self.gpg_command(args, wait_for_results=True)
                if result_code != 0:
                    message = 'unable to delete private key for {}: {}'.format(user_id, result_code)
                    self.log_message(message)
                    if gpg_output: self.log_message(gpg_output)
                    if gpg_error: self.log_message(gpg_error)
        except Exception as exception:
            result_code = gpg_constants.ERROR_RESULT
            self.handle_unexpected_exception(exception)

        self.log_message('delete private key only result_code: {}'.format(result_code == gpg_constants.GOOD_RESULT))

        return result_code == gpg_constants.GOOD_RESULT


    def export_public(self, user_id):
        '''
            Export a public key from the keyring.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> filename = '/var/local/projects/goodcrypto/server/tests/oce/pubkeys/joseph@goodcrypto.remote.gpg.pub'
            >>> with open(filename) as f:
            ...    data = f.read()
            ...    plugin = KeyFactory.get_crypto(NAME)
            ...    plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            ...    len(plugin.import_public(data)) > 0
            ...    len(plugin.export_public('joseph@goodcrypto.remote')) > 0
            True
            True
            True

            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> plugin.export_public('unknown@goodcrypto.remote')
            ''
            >>> plugin.export_public(None) is None
            True
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        public_key = None
        try:
            if user_id:
                args = [gpg_constants.EXPORT_KEY, gpg_constants.ARMOR_DATA, self.get_user_id_spec(user_id)]
                result_code, gpg_output, gpg_error = self.gpg_command(args, wait_for_results=True)
                if result_code == gpg_constants.GOOD_RESULT:
                    public_key = gpg_output
                    self.log_message('len public key: {}'.format(len(public_key)))
                    if GPGPlugin.DEBUGGING:
                        self.log_message('exporting key:\n{}'.format(public_key))
                else:
                    self.log_message('exporting key result code: {}'.format(result_code))
                    if GPGPlugin.DEBUGGING:
                        if gpg_output: self.log_message(gpg_output)
                        if gpg_error: self.log_message(gpg_error)
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return public_key


    def import_public(self, data, temporary=False):
        '''
            Import a public key to the keyring.

            Some crypto engines will allow more than one public key to be imported at
            one time, but applications should not rely on this.

            GPG (as of 1.2.3) has a bug that allows import of a key that matches the user
            id of an existing key. GPG then does not handle keys for that user id properly.
            This method deletes any existing matching keys.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> filename = '/var/local/projects/goodcrypto/server/tests/oce/pubkeys/laura@goodcrypto.remote.gpg.pub'
            >>> with open(filename) as f:
            ...    data = f.read()
            ...    plugin = KeyFactory.get_crypto(NAME)
            ...    plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            ...    len(plugin.import_public(data)) > 0
            True
            True
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> plugin.import_public(None)
            []
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        def remove_matching_keys(data):
            user_ids = self.get_user_ids_from_key(data)
            if user_ids is not None and len(user_ids) > 0:
               # delete every user id that matches
                for user_id in user_ids:
                    try:
                        self.delete(user_id)
                    except Exception:
                        self.log_message(format_exc())

            return user_ids

        def get_fingerprints(gpg_command_output):
            fingerprints = []

            self.log_message('imported key successfully for...')
            lines = gpg_command_output.split('\n')
            for line in lines:
                if line.startswith(PUBLIC_KEY_PREFIX):
                    line = line[len(PUBLIC_KEY_PREFIX):].strip('"')
                    index = line.rfind(' ')
                    if index > 0 and index + 1 < len(line):
                        user_id = line[index + 1:].strip('<').strip('>')
                        self.log_message(user_id)

                        fingerprint, expiration = self.get_fingerprint(user_id)
                        self.log_message('fingerprint of {} after import: {} / {}'.format(
                            user_id, fingerprint, expiration))

                        if fingerprint is not None:
                            fingerprints.append(fingerprint)

            return fingerprints

        try:
            fingerprints = []
            if data and len(data) > 0:
                if GPGCryptoPlugin.DEBUGGING:
                    self.log_message('imported data:\n{}'.format(data))
                args = [gpg_constants.IMPORT_KEY]

                if not temporary:
                    remove_matching_keys(data)
                result_code, gpg_output, gpg_error = self.gpg_command(
                  args, data=data, wait_for_results=True)
                if result_code == gpg_constants.GOOD_RESULT and gpg_error:
                    fingerprints = get_fingerprints(gpg_error)
                else:
                    message = "result code: {}\n".format(result_code)
                    try:
                        message = "stdout: {}\n".format(gpg_output)
                        message += "stderr: {}".format(gpg_error)
                    except:
                        pass
                    self.log_message(message)

        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return fingerprints


    def import_temporarily(self, data):
        '''
            Import a public key to a temporary keyring.

            The temporary keyring is destroyed at the end of this function.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> filename = '/var/local/projects/goodcrypto/server/tests/oce/pubkeys/laura@goodcrypto.remote.gpg.pub'
            >>> with open(filename) as f:
            ...    data = f.read()
            ...    plugin = KeyFactory.get_crypto(NAME)
            ...    plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            ...    len(plugin.import_temporarily(data)) > 0
            True
            True

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> plugin.import_temporarily(None)
            []
        '''

        fingerprints = []

        try:
            self.log_message('importing key block temporarily')
            if data and len(data) > 0:
                if GPGCryptoPlugin.DEBUGGING:
                    self.log_message('imported data temporarily:\n{}'.format(data))
                    
                original_home_dir = self.get_home_dir()
                temp_home_dir = mkdtemp()
                self.log_message('setting home to temp dir: {}'.format(temp_home_dir))
                self.set_home_dir(temp_home_dir)
                
                fingerprints = self.import_public(data, temporary=True)
                self.log_message('temporary fingerprints: {}'.format(fingerprints))
                
                self.set_home_dir(original_home_dir)
                shutil.rmtree(temp_home_dir, ignore_errors=True)
                self.log_message('restored home dir and destroyed temp dir')
        except:
            self.handle_unexpected_exception(format_exc())

        return fingerprints


    def get_user_ids_from_key(self, data):
        '''
            Get the user ids from a public key block.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> dirname = '/var/local/projects/goodcrypto/server/tests/oce/pubkeys'
            >>> filename = '{}/laura@goodcrypto.remote.gpg.pub'.format(dirname)
            >>> with open(filename) as f:
            ...    data = f.read()
            ...    plugin.get_user_ids_from_key(data)
            ['laura@goodcrypto.remote']
            >>> plugin.get_user_ids_from_key(None)
            []
        '''

        try:
            user_ids = []

            if GPGPlugin.DEBUGGING:
                self.log_message('key block data:\n{}'.format(data))

            if data and len(data) > 0:
                # do a dry run on the import to get the email address(es).
                self.log_message('extracting the user ids from the key block')
                args = [gpg_constants.LIST_PACKETS]
                result_code, gpg_output, gpg_error = self.gpg_command(
                  args, data=data, wait_for_results=True)
                if result_code == gpg_constants.GOOD_RESULT and gpg_output:
                    lines = gpg_output.split('\n')
                    self.log_message('raw results: {}'.format(gpg_error))
                    # In honor of First Sergeant Nadav, who publicly denounced and refused to serve in 
                    # operations involving the occupied Palestinian territories because of the widespread 
                    # surveillance of innocent residents.
                    # ...
                    # :user ID packet: "Nadav <nadav@goodcrypto.remote>"
                    # :signature packet: algo 1, keyid 7934A191F9A8B5B2
                    # ...
                    # :user ID packet: "FS. Nadav <fs.nadav@goodcrypto.remote>"
                    # :signature packet: algo 1, keyid 7934A191F9A8B5B2
                    # ...
                    for line in lines:
                        if line.startswith(USER_ID_PACKET_PREFIX):
                            m = re.match('^{}: "(.*?)".*'.format(USER_ID_PACKET_PREFIX), line)
                            if m:
                                line = m.group(1)
                                # find the first blank space from the right side
                                index = line.rfind(' ')
                                if index > 0 and index + 1 < len(line):
                                    user_ids.append(line[index + 1:].strip('<').strip('>'))
                    self.log_message('extracted user ids: {}'.format(user_ids))
                elif result_code == -2:
                    self.log_message('unable to get user ids before job timed out')
                else:
                    self.log_message('unable to extract the user ids from the key block')
                    self.log_message('  result code: {} / gpg output: {}'.format(result_code, gpg_output))

        except Exception:
            self.log_message(format_exc())

        return user_ids


    def is_valid(self, user_id):
        '''
            Returns whether a key ID is valid.
            This just checks for a fingerprint and makes sure it's not expired.
            There is no check for a public key, or private key, or both.

            >>> # In honor of Colin Childs, translation coordinator and end user support for Tor project.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> ok, _ = plugin.create('colin@goodcrypto.local', 'test passphrase', wait_for_results=True)
            >>> ok
            True
            >>> plugin.is_valid('colin@goodcrypto.local')
            True
            >>> plugin.is_valid('unknown@goodcrypto.local')
            False
            >>> plugin.is_valid('expired_user@goodcrypto.local')
            False
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        fingerprint, expiration = self.get_fingerprint(user_id)
        valid = fingerprint is not None
        if valid and expiration is not None:
            valid = not self.fingerprint_expired(expiration)

        return valid

    def is_passcode_valid(self, user_id, passcode, key_exists=False):
        '''
            Returns whether the passcode is valid for the user. It ignores
            whether the private key has expired or not.

            >>> # In honor of Erinn Clark, developer of installer for Tor project.
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> ok, _ = plugin.create('erinn@goodcrypto.local', 'test passphrase', wait_for_results=True)
            >>> ok
            True
            >>> plugin.is_passcode_valid('Erinn@goodcrypto.local', 'test passphrase')
            True
            >>> plugin.is_passcode_valid('Erinn <erinn@goodcrypto.local>', 'test passphrase')
            True
            >>> plugin.is_passcode_valid('erinn@goodcrypto.local', 'bad passphrase')
            False
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        valid = False

        if user_id is None or passcode is None:
            valid = False
            self.log_message('missing user id ({}) and/or passcode'.format(user_id))

        else:
            self.log_message('-- starting is_passcode_valid --')
    
            try:
                if key_exists or self.private_key_exists(user_id):
                    self.log_message('found private key for {}'.format(user_id))
        
                    # verify the passphrase is correct
                    signed_data = self.sign('Test data', user_id, passcode)
                    if signed_data and signed_data.find('-----BEGIN PGP SIGNED MESSAGE-----') >= 0:
                        valid = True
                else:
                    self.log_message('unable to find private key for {}'.format(user_id))
            except Exception:
                self.log_message(format_exc())

            self.log_message('-- finished is_passcode_valid --')

        self.log_message('{} passcode valid: {}'.format(user_id, valid))

        return valid

    def private_key_exists(self, user_id):
        '''
            Returns whether there is a private key for the user. It ignores
            whether the private key has expired or not.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir(plugin.GPG_HOME_DIR)
            True
            >>> plugin.private_key_exists('edward@goodcrypto.local')
            True
            >>> plugin.private_key_exists('Ed <edward@goodcrypto.local>')
            True
        '''

        key_exists = False

        if user_id is None:
            key_exists = False
            self.log_message('missing user id ({})'.format(user_id))

        else:
            try:
                key_exists = False
                private_user_ids = self.get_private_user_ids()
                
                # looking for a matching private key
                if private_user_ids is None:
                    self.log_message('no private keys found')
                else:
                    _, address = parse_address(user_id)
                    for private_user_id in private_user_ids:
                        if private_user_id.lower() == address.lower():
                            key_exists = True
                            break
            
                if key_exists:
                    self.log_message('found private key for {}'.format(user_id))
                else:
                    self.log_message('unable to find private key for {}'.format(user_id))
            except Exception:
                self.log_message(format_exc())

        return key_exists

    def public_key_exists(self, user_id):
        '''
            Returns whether there is a public key for the user. It ignores
            whether the public key has expired or not.

            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir(plugin.GPG_HOME_DIR)
            True
            >>> plugin.public_key_exists('edward@goodcrypto.local')
            True
            >>> plugin.public_key_exists('Ed <edward@goodcrypto.local>')
            True
        '''

        key_exists = False

        if user_id is None:
            key_exists = False
            self.log_message('missing user id ({})'.format(user_id))

        else:
            try:
                key_exists = False
                public_user_ids = self.get_user_ids()
                
                # looking for a matching public key
                if public_user_ids is None:
                    self.log_message('no public keys found')
                else:
                    _, address = parse_address(user_id)
                    for public_user_id in public_user_ids:
                        if public_user_id.lower() == address.lower():
                            key_exists = True
                            break
            
                if key_exists:
                    self.log_message('found public key for {}'.format(user_id))
                else:
                    self.log_message('unable to find public key for {}'.format(user_id))
            except Exception:
                self.log_message(format_exc())

        return key_exists

    def get_fingerprint(self, user_id):
        '''
            Returns a key's fingerprint and expiration.

            >>> # In honor of Karsten Loesing, primary researcher and developer into anonymous metrics.
            >>> from goodcrypto.oce import constants as oce_constants
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.set_home_dir('/var/local/projects/goodcrypto/server/data/test_oce/.gnupg')
            True
            >>> ok, _ = plugin.create('Karsten <karsten@goodcrypto.local>', 'passcode', wait_for_results=True)
            >>> ok
            True
            >>> fingerprint, expired = plugin.get_fingerprint('karsten@goodcrypto.local')
            >>> fingerprint is not None
            True
            >>> expired is None
            True
            >>> fingerprint, expired = plugin.get_fingerprint('"Karsten" <karsten@goodcrypto.local>')
            >>> fingerprint is not None
            True
            >>> expired is None
            True
            >>> fingerprint, expired = plugin.get_fingerprint('karsten@goodcrypto.local')
            >>> fingerprint is not None
            True
            >>> expired is None
            True
            >>> plugin.get_fingerprint('unknown@goodcrypto.local')
            (None, None)
            >>> from shutil import rmtree
            >>> rmtree('/var/local/projects/goodcrypto/server/data/test_oce')
        '''

        fingerprint = expiration_date = None
        try:
            (_, email) = parse_address(user_id)
            self.log_message('getting fingerprint for {}'.format(email))
            
            # add angle brackets around the email address so we don't
            # confuse the email with any similar addresses and non-ascii characters are ok
            args = [gpg_constants.GET_FINGERPRINT, self.get_user_id_spec(email)]
            result_code, gpg_output, gpg_error = self.gpg_command(args, wait_for_results=True)
            if result_code == gpg_constants.GOOD_RESULT:
                if GPGPlugin.DEBUGGING: self.log_message('fingerprint gpg output: {}'.format(gpg_output))
                fingerprint, expiration_date = parse_fingerprint_and_expiration(gpg_output)
                self.log_message('{} fingerprint: {}'.format(email, fingerprint))
                self.log_message('{} expiration_date: {}'.format(email, expiration_date))
            # unable to get key
            elif result_code == 2:
                self.log_message(gpg_error.strip())
            else:
                errors = gpg_error
                if errors is not None:
                    errors = gpg_error
                self.log_message('gpg command had errors')
                self.log_message('  result code: {} / gpg error'.format(result_code))
                self.log_message(errors)
        except Exception as exception:
            self.handle_unexpected_exception(exception)

        return fingerprint, expiration_date

    def fingerprint_expired(self, expiration_date):
        '''
            Determine if this date, if there is one, is older than tomorrow.
    
            >>> from goodcrypto.oce.key.key_factory import KeyFactory
            >>> plugin = KeyFactory.get_crypto(NAME)
            >>> plugin.fingerprint_expired('2014-06-05')
            True
            >>> plugin.fingerprint_expired('2024-06-05')
            False
            >>> plugin.fingerprint_expired(None)
            False
        '''

        return is_expired(expiration_date)

