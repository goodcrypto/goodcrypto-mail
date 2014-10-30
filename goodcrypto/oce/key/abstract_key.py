#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

from abc import ABCMeta, abstractmethod


class AbstractKey(object):
    ''' Key interface for the Open Crypto Engine. '''

    __metaclass__ = ABCMeta


    @abstractmethod
    def get_plugin_name(self):
        '''
            Get the plugin's name.

            @return                                              Name of the plugin
        '''


    @abstractmethod
    def get_plugin_version(self):
        '''
            Get the version of this plugin's implementation, i.e. the CORBA servant's version.

            @return                                              Plugin version
        '''


    @abstractmethod
    def get_crypto_version(self):
        '''
            Get the version of the underlying crypto.

            @return                                              Crypto version
        '''


    @abstractmethod
    def is_function_supported(self, func):
        '''
            Returns whether the specified function is supported.

            @param  func  The function to check
            @return       Whether the function is supported
        '''


    @abstractmethod
    def create(self, user_id, passcode, expiration=None, wait_for_results=False):
        '''
            Creating a new key pair.

            @param  user_id                     ID for the new key. This is typically an email address.
            @param  passcode                    Passphrase
            @param  expiration                  Time until the key expires.
            @param  wait_for_results            True if key should be created and results returned.
        '''


    @abstractmethod
    def delete(self, user_id):
        '''
            Delete an existing key, or key pair, from the keyring.

            @param  user_id                                       ID for the key. This is typically an email address.
        '''


    @abstractmethod
    def export_public(self, user_id):
        '''
            Export a public key from the keyring.

            @param  user_id                                       ID for the key. This is typically an email address.
            @return                                              Public key
        '''


    @abstractmethod
    def import_public(self, data, temporary=False):
        '''
            Add a public key to the keyring.

            @param  data                     Public key block.
            @return      List of fingerprints of the user ids imported or an empty list of none imported.
        '''


    @abstractmethod
    def import_temporarily(self, data):
        '''
            Add a public key to a temporary keyring.

            The temporary keyring is destroyed at the end of this function.

            @param  data                    Public key data.
            @return      List of fingerprints of the user ids imported or an empty list of none imported.
        '''


    @abstractmethod
    def get_user_ids_from_key(self, data):
        '''
            Get the user ids from a key block.

            @param  data               Public key block.
            @return   List of user ids or an empty list if no users contained in key block.
        '''


    @abstractmethod
    def is_valid(self, user_id):
        '''
            Whether a key ID is valid.

            @param  user_id                                       ID for the key. This is typically an email address.
            @return                                              Whether the key ID is valid
        '''


    @abstractmethod
    def is_passcode_valid(self, user_id, passcode):
        '''
            Whether the passcode is valid for the user.
        '''


    @abstractmethod
    def private_key_exists(self, user_id):
        '''
            Whether there is a private key for the user.
        '''


    @abstractmethod
    def public_key_exists(self, user_id):
        '''
            Whether there is a public key for the user.
        '''


    @abstractmethod
    def get_fingerprint(self, user_id, temp_keyring_args=None):
        '''
            Returns a key's fingerprint and the expiration date.

            @param  user_id                                       ID for the key. This is typically an email address.
            @return                                              Fingerprint
        '''

    @abstractmethod
    def fingerprint_expired(self, expiration):
        ''' Determine if the expiration, if there is one, is older than tomorrow. '''


