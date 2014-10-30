#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-09-19

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.oce.crypto_factory import CryptoFactory
#from syr.sync_function import synchronized


class KeyFactory(CryptoFactory):
    '''
        Provides instances of key management for cryptographic software and services.

        It may make more sense to make the methods in CryptoFactory
        non-static and override just the get_crypto_plugin_class_prefix and get_plugin_map methods.
    '''

    DEBUGGING = False
    KEY_CLASS_SUFFIX = "key."

    _log = None

    #  each plugin should be a singleton
    _key_plugins = {}
    _saved_class_prefix = ''
    _saved_crypto_plugins = {}


    @staticmethod
    ##@synchronized
    def get_default_crypto():
        '''
            Get the default instance of a crypto key.

            >>> default_plugin = KeyFactory.get_default_crypto()
            >>> type(default_plugin)
            <class 'goodcrypto.oce.key.gpg_plugin.GPGPlugin'>
            >>> default_plugin.get_plugin_name() == 'goodcrypto.oce.key.gpg_plugin.GPGPlugin'
            True
            >>> KeyFactory.get_default_encryption_name() in KeyFactory.get_plugin_map()
            True
            >>> from goodcrypto.oce.crypto_factory import CryptoFactory
            >>> default_plugin in CryptoFactory.get_plugin_map()
            False
        '''

        KeyFactory.setup_key_crypto()
        plugin = CryptoFactory.get_default_crypto()
        KeyFactory.reset_key_crypto()

        return plugin

    @staticmethod
    def get_crypto(encryption_name, plugin_classname=None):
        '''
            Get the crypto matching the given name.

            Get the interface to GPG which is supplied with GoodCrypto Mail
            >>> KeyFactory._key_plugins = {}
            >>> gpg_plugin = KeyFactory.get_crypto('GPG')
            >>> type(gpg_plugin)
            <class 'goodcrypto.oce.key.gpg_plugin.GPGPlugin'>
            >>> gpg_plugin.get_plugin_name() == 'goodcrypto.oce.key.gpg_plugin.GPGPlugin'
            True
            >>> KeyFactory.get_name('GPG') in KeyFactory.get_plugin_map()
            True

            Get the interface to GPG using a different name.
            >>> KeyFactory._key_plugins = {}
            >>> gpg_plugin = KeyFactory.get_crypto('TestGPG', 'goodcrypto.oce.gpg_plugin.GPGPlugin')
            >>> type(gpg_plugin)
            <class 'goodcrypto.oce.key.gpg_plugin.GPGPlugin'>
            >>> gpg_plugin.get_plugin_name() == 'goodcrypto.oce.key.gpg_plugin.GPGPlugin'
            True

            Get the interface to a crypto package not supplied with GoodCrypto Mail. You must
            include the classname for the plugin *and* the plugin must be in the dist-packages or site-packages.
            This returns None because there is no mycrypto.key.test_plugin.py, otherwise it would
            return <class 'mycrypto.key.test_plugin.TestPlugin'>
            >>> KeyFactory._key_plugins = {}
            >>> test_plugin = KeyFactory.get_crypto('TestPlugin', 'mycrypto.key.test_plugin.TestPlugin')
            >>> type(test_plugin)
            <type 'NoneType'>

            Get the interface to a crypto package not supplied GoodCrypto Mail
            If you fail to include the classname, then there's no plugin
            >>> KeyFactory._key_plugins = {}
            >>> unknown_plugin = KeyFactory.get_crypto('Test')
            >>> type(unknown_plugin)
            <type 'NoneType'>
        '''

        KeyFactory.log_debug('getting key crypto: {}'.format(encryption_name))
        KeyFactory.setup_key_crypto()
        
        # get the key plugin classname if the standard plugin classname was passed in
        if (plugin_classname is not None and
            plugin_classname.startswith(KeyFactory.CRYPTO_PLUGIN_CLASS_PREFIX) and
            not plugin_classname.startswith(KeyFactory.get_crypto_plugin_class_prefix())):

            index = plugin_classname.find(KeyFactory.CRYPTO_PLUGIN_CLASS_PREFIX)
            suffix = plugin_classname[index+len(KeyFactory.CRYPTO_PLUGIN_CLASS_PREFIX):]
            key_plugin_classname = '{}{}'.format(KeyFactory.get_crypto_plugin_class_prefix(), suffix)
        else:
            key_plugin_classname = plugin_classname

        plugin = CryptoFactory.get_crypto(encryption_name, plugin_classname=key_plugin_classname)
        KeyFactory.reset_key_crypto()
        KeyFactory.log_debug('got {} key plugin: {}'.format(encryption_name, type(plugin)))

        return plugin

    @staticmethod
    def get_classname(encryption_name):
        '''
            Get the classname for the named encryption.

            Assumes that the software is part of goodcrypto's oce package
            and follows that package's naming convention.

            >>> KeyFactory.get_classname('GPG')
            'goodcrypto.oce.key.gpg_plugin.GPGPlugin'

            >>> KeyFactory.get_classname('Test')
            'goodcrypto.oce.key.test_plugin.TestPlugin'
        '''

        KeyFactory.log_debug('getting key classname: {}'.format(encryption_name))
        KeyFactory._saved_class_prefix = KeyFactory.get_crypto_plugin_class_prefix()
        if not KeyFactory._saved_class_prefix.endswith(KeyFactory.KEY_CLASS_SUFFIX):
            KeyFactory.set_crypto_plugin_class_prefix(KeyFactory._saved_class_prefix + KeyFactory.KEY_CLASS_SUFFIX)
        plugin_classname = CryptoFactory.get_classname(encryption_name)
        KeyFactory.set_crypto_plugin_class_prefix(KeyFactory._saved_class_prefix)
        KeyFactory.log_debug('got {} key classname: {}'.format(encryption_name, plugin_classname))

        return plugin_classname

    @staticmethod
    def get_name(crypto):
        '''
            Get the name for the encryption software.

            >>> KeyFactory.get_name('GPG')
            'GPG'

            >>> KeyFactory._key_plugins = {}
            >>> gpg_plugin = KeyFactory.get_crypto('GPG')
            >>> KeyFactory.get_name(gpg_plugin)
            'gpg_plugin.GPG'
        '''

        name = ''
        KeyFactory.log_debug('getting key name for {}'.format(crypto))
        KeyFactory.setup_key_crypto()
        try:
            name = CryptoFactory.get_name(crypto)
        except Exception as exception:
            if type(exception) != AttributeError:
                KeyFactory.log_debug(format_exc())
            try:
                if isinstance(crypto, str):
                    name = crypto
                else:
                    KeyFactory.log_debug('crypto type: {}'.format(type(crypto)))
                    name = crypto.get_name()
            except Exception:
                KeyFactory.log_debug(format_exc())

        KeyFactory.reset_key_crypto()
        KeyFactory.log_debug('got key name: {}'.format(name))

        return name


    @staticmethod
    def get_plugin_map():
        '''
             Get the plugin map. Each plugin should be a singleton.

            >>> from importlib import import_module
            >>> plugin_module = import_module('goodcrypto.oce.key.gpg_plugin')
            >>> KeyFactory.set_plugin_map({'GPG': plugin_module})
            >>> 'GPG' in KeyFactory.get_plugin_map()
            True
        '''

        KeyFactory.log_debug('getting key plugin map: {}'.format(KeyFactory._key_plugins))
        return KeyFactory._key_plugins


    @staticmethod
    def setup_key_crypto():
        '''
            Configure CryptoFactory to use KeyFactory's prefix/suffix and plugin map.

            >>> from importlib import import_module
            >>> gpg_module = import_module('goodcrypto.oce.gpg_plugin')
            >>> CryptoFactory.set_plugin_map({'GPG': gpg_module})
            >>> gpg_key_module = import_module('goodcrypto.oce.key.gpg_plugin')
            >>> crypto_module = CryptoFactory.get_plugin_map()['GPG']
            >>> gpg_module == crypto_module
            True
            >>> CryptoFactory.get_crypto_plugin_class_prefix()
            'goodcrypto.oce.'
            >>> KeyFactory._key_plugins = {'GPG': gpg_key_module}
            >>> KeyFactory.setup_key_crypto()
            >>> crypto_module = CryptoFactory.get_plugin_map()['GPG']
            >>> gpg_module == crypto_module
            False
            >>> gpg_key_module == crypto_module
            True
            >>> CryptoFactory.get_crypto_plugin_class_prefix()
            'goodcrypto.oce.key.'
            >>> KeyFactory.reset_key_crypto()
        '''

        #  temporarily change the plugin class prefix
        KeyFactory._saved_class_prefix = KeyFactory.get_crypto_plugin_class_prefix()
        if not KeyFactory._saved_class_prefix.endswith(KeyFactory.KEY_CLASS_SUFFIX):
            KeyFactory.set_crypto_plugin_class_prefix(KeyFactory._saved_class_prefix + KeyFactory.KEY_CLASS_SUFFIX)

        #  temporarily change the plugin map
        KeyFactory._saved_crypto_plugins = CryptoFactory.get_plugin_map()
        KeyFactory.log_debug('set key plugins: {}'.format(KeyFactory._key_plugins))
        CryptoFactory.set_plugin_map(KeyFactory._key_plugins)

    @staticmethod
    def reset_key_crypto():
        '''
            Configure CryptoFactory to use KeyFactory's prefix/suffix and plugin map.

            >>> from importlib import import_module
            >>> gpg_module = import_module('goodcrypto.oce.gpg_plugin')
            >>> CryptoFactory.set_plugin_map({'GPG': gpg_module})
            >>> crypto_module = CryptoFactory.get_plugin_map()['GPG']
            >>> gpg_module == crypto_module
            True
            >>> CryptoFactory.get_crypto_plugin_class_prefix()
            'goodcrypto.oce.'
            >>> KeyFactory._key_plugins = {}
            >>> KeyFactory.setup_key_crypto()
            >>> 'GPG' not in CryptoFactory.get_plugin_map()
            True
            >>> CryptoFactory.get_crypto_plugin_class_prefix()
            'goodcrypto.oce.key.'
            >>> KeyFactory.reset_key_crypto()
            >>> CryptoFactory.get_crypto_plugin_class_prefix()
            'goodcrypto.oce.'
            >>> crypto_module = CryptoFactory.get_plugin_map()['GPG']
            >>> gpg_module == crypto_module
            True
        '''

        #  restore original settings
        KeyFactory.set_plugin_map(CryptoFactory.get_plugin_map())
        KeyFactory.log_debug('got key plugins: {}'.format(KeyFactory.get_plugin_map()))
        KeyFactory.set_crypto_plugin_class_prefix(KeyFactory._saved_class_prefix)
        KeyFactory.log_debug('restored crypto plugins: {}'.format(KeyFactory._saved_crypto_plugins))
        CryptoFactory.set_plugin_map(KeyFactory._saved_crypto_plugins)


    @staticmethod
    def log_debug(message):
        '''
            Log a message.

            >>> KeyFactory._log = None
            >>> KeyFactory.log_debug('Test message')
            >>> KeyFactory.log_debug(Exception)
        '''

        if KeyFactory.DEBUGGING:
            if KeyFactory._log is None:
                KeyFactory._log = LogFile()
    
            KeyFactory._log.write(message)



if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)

