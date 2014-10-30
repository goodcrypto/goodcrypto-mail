#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-09-19

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os, sh
from importlib import import_module
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile


class CryptoFactory(object):
    ''' 
        Provides instances of cryptographic software or services.
        
        Access to crypto software and services should only be gained through 
        CryptoFactory.get_crypto(). 
    '''

    DEBUGGING = False
    
    # Prefix for classes provided in the GoodCrypto OCE package.
    CRYPTO_PLUGIN_CLASS_PREFIX = 'goodcrypto.oce.'

    # Suffix for classes provided in the GoodCrypto OCE package.
    CRYPTO_PLUGIN_CLASS_SUFFIX = 'Plugin'

    # Name of default crypto service to use. 
    DEFAULT_ENCRYPTION_NAME = 'GPG'
    

    # each plugin should be a singleton
    _plugins = {}
    _class_prefix = CRYPTO_PLUGIN_CLASS_PREFIX
    _log = None


    @staticmethod
    def get_default_crypto():
        ''' 
            Get the default instance of crypto.

            >>> default_crypto = CryptoFactory.get_default_crypto()
            >>> default_crypto is not None
            True
        '''

        return CryptoFactory.get_crypto(CryptoFactory.get_default_encryption_name())


    @staticmethod
    def get_crypto(encryption_name, plugin_classname=None):
        '''
            Get an instance to the interface to the encryption software matching the given name.
            If the encryption name isn't supplied by GoodCrypto, then the plugin_classname
            must be passed.

            Get the interface to GPG which is supplied with GoodCrypto Mail
            >>> _plugins = {}
            >>> _class_prefix = CryptoFactory.CRYPTO_PLUGIN_CLASS_PREFIX
            >>> gpg_plugin = CryptoFactory.get_crypto('GPG')
            >>> gpg_plugin is not None
            True
            >>> CryptoFactory.get_name('GPG') in CryptoFactory.get_plugin_map()
            True
            
            Get the interface to a crypto package not supplied with GoodCrypto Mail. You must
            include the classname for the plugin *and* the plugin must be in the site-packages.
            This returns None because there is no mycrypto.test_plugin.py, otherwise it would
            return <class 'mycrypto.test_plugin.TestPlugin'>
            >>> test_plugin = CryptoFactory.get_crypto('Test', 'mycrypto.test_plugin.TestPlugin')
            >>> type(test_plugin)
            <type 'NoneType'>

            Get the interface to a crypto package not supplied GoodCrypto Mail
            If you fail to include the classname, then there's no plugin
            >>> unknown_plugin = CryptoFactory.get_crypto('Test')
            >>> type(unknown_plugin)
            <type 'NoneType'>
        '''

        def get_plugin_from_classname(name):
            classname = CryptoFactory.get_classname(name)
            if classname is None or name is None:
                plugin = None
                CryptoFactory.log_message('missing key data; classname {}; name: {}'.format(classname, name))
            elif classname.lower() == name.lower():
                plugin = None
                CryptoFactory.log_message('classname and encryption name are the same: {}'.format(classname))
            else:
                plugin = CryptoFactory.get_plugin_from_map(classname)
    
            if plugin is None:
                plugin = CryptoFactory.get_plugin_instance(name, classname)
                
            return plugin
        
        if encryption_name is None:
            plugin = None
        else:
            plugin = CryptoFactory.get_plugin_from_map(encryption_name.upper())

            if plugin is None and plugin_classname is not None and len(plugin_classname.strip()) > 0:
                plugin = CryptoFactory.get_plugin_instance(encryption_name, plugin_classname)
                
            if plugin is None:
                plugin = get_plugin_from_classname(encryption_name)
                
            if plugin is None:
                plugin = get_plugin_from_classname(encryption_name.upper())
    
            if plugin is None:
                plugin = get_plugin_from_classname(encryption_name.lower())
    
        return plugin


    @staticmethod
    def get_classname(encryption_name):
        ''' 
            Get the classname for the named encryption software.
            
            Assumes that the software is part of goodcrypto's oce package
            and follows that package's naming convention.

            >>> _plugins = {}
            >>> _class_prefix = CryptoFactory.CRYPTO_PLUGIN_CLASS_PREFIX
            >>> CryptoFactory.get_classname('GPG')
            'goodcrypto.oce.gpg_plugin.GPGPlugin'
            
            >>> CryptoFactory.get_classname('Test')
            'goodcrypto.oce.test_plugin.TestPlugin'
        '''

        new_name = encryption_name
        prefix = CryptoFactory.get_crypto_plugin_class_prefix()

        if encryption_name is not None and not encryption_name.startswith(prefix):
            # e.g., encryption_name = 'GPG'
            #       new_name = 'goodcrypto.oce.gpg_plugin.GPGPlugin'
            new_name = '{}{}_{}.{}'.format(
                prefix, new_name.lower(), CryptoFactory.CRYPTO_PLUGIN_CLASS_SUFFIX.lower(), new_name)
            if not encryption_name.endswith(CryptoFactory.CRYPTO_PLUGIN_CLASS_SUFFIX):
                new_name = new_name + CryptoFactory.CRYPTO_PLUGIN_CLASS_SUFFIX

        return new_name

     
    @staticmethod
    def get_name(name_or_module):
        '''
            Get the short name for the named encryption software.

            >>> CryptoFactory.get_name('GPG')
            'GPG'
       '''
        
        if isinstance(name_or_module, str):
            module_name = name_or_module
        else:
            try:
                module_name = name_or_module.get_plugin_name()
            except AttributeError:
                module_name = name_or_module.__name__

        new_name = ''
        if module_name.startswith(CryptoFactory.get_crypto_plugin_class_prefix()):
            new_name = module_name[len(CryptoFactory.get_crypto_plugin_class_prefix()):]
        else:
            new_name = module_name
            
        if new_name.endswith(CryptoFactory.CRYPTO_PLUGIN_CLASS_SUFFIX):
            new_length = new_name.find(CryptoFactory.CRYPTO_PLUGIN_CLASS_SUFFIX)
            new_name = new_name[0: new_length]
            
        return new_name


    @staticmethod
    def get_default_encryption_name():
        ''' 
            Get the default encryption software name.

            >>> _plugins = {}
            >>> _class_prefix = CryptoFactory.CRYPTO_PLUGIN_CLASS_PREFIX
            >>> CryptoFactory.get_default_encryption_name()
            'GPG'
        '''

        return CryptoFactory.DEFAULT_ENCRYPTION_NAME


    @staticmethod
    def get_crypto_plugin_class_prefix():
        ''' 
            Gets the package prefix for crypto plugin class names.
            
            >>> _plugins = {}
            >>> _class_prefix = CryptoFactory.CRYPTO_PLUGIN_CLASS_PREFIX
            >>> CryptoFactory.get_crypto_plugin_class_prefix()
            'goodcrypto.oce.'
        '''

        CryptoFactory.debug_message('get class prefix: {}'.format(CryptoFactory._class_prefix))
        return CryptoFactory._class_prefix


    @staticmethod
    def set_crypto_plugin_class_prefix(prefix):
        ''' 
            Sets the package prefix for crypto plugin class names.
            
            >>> _plugins = {}
            >>> _class_prefix = CryptoFactory.CRYPTO_PLUGIN_CLASS_PREFIX
            >>> CryptoFactory.set_crypto_plugin_class_prefix('mycrypto.')
            >>> CryptoFactory.get_crypto_plugin_class_prefix()
            'mycrypto.'
            >>> CryptoFactory.set_crypto_plugin_class_prefix(CryptoFactory.CRYPTO_PLUGIN_CLASS_PREFIX)
            >>> CryptoFactory.get_crypto_plugin_class_prefix()
            'goodcrypto.oce.'
        '''

        CryptoFactory._class_prefix = prefix
        CryptoFactory.debug_message('set class prefix: {}'.format(CryptoFactory._class_prefix))


    @staticmethod
    def set_plugin_map(new_plugins):
        ''' 
            Set the map of plugins.

            >>> _plugins = {}
            >>> _class_prefix = CryptoFactory.CRYPTO_PLUGIN_CLASS_PREFIX
            >>> plugin_module = import_module('goodcrypto.oce.gpg_plugin')
            >>> CryptoFactory.set_plugin_map({'GPG': plugin_module})
            >>> 'GPG' in CryptoFactory.get_plugin_map()
            True
        '''

        CryptoFactory._plugins = new_plugins
        CryptoFactory.debug_message('set plugin map: {}'.format(CryptoFactory._plugins))


    @staticmethod
    def get_plugin_map():
        ''' 
            Get the map of plugins.  Each plugin should be a singleton.

            >>> _plugins = {}
            >>> _class_prefix = CryptoFactory.CRYPTO_PLUGIN_CLASS_PREFIX
            >>> plugin_module = import_module('goodcrypto.oce.gpg_plugin')
            >>> CryptoFactory.set_plugin_map({'GPG': plugin_module})
            >>> 'GPG' in CryptoFactory.get_plugin_map()
            True
        '''

        CryptoFactory.debug_message('get plugin map: {}'.format(CryptoFactory._plugins))
        return CryptoFactory._plugins


    @staticmethod
    def set_plugin(encryption_name, plugin):
        ''' 
            Set an instance of a plugin to the encryption name, in upper case.
            Each plugin should be a singleton.
            
            >>> _plugins = {}
            >>> _class_prefix = CryptoFactory.CRYPTO_PLUGIN_CLASS_PREFIX
            >>> plugin_module = import_module('goodcrypto.oce.gpg_plugin')
            >>> CryptoFactory.set_plugin('GPG', plugin_module)
            >>> 'GPG' in CryptoFactory.get_plugin_map()
            True

            >>> CryptoFactory._plugins = None
            >>> plugin_module = import_module('goodcrypto.oce.gpg_plugin')
            >>> CryptoFactory.set_plugin('gpg', plugin_module)
            >>> 'GPG' in CryptoFactory.get_plugin_map()
            True
        '''

        if CryptoFactory._plugins is None:
            CryptoFactory._plugins = {}

        if encryption_name is None:
            CryptoFactory.log_message('unable to add plugin without a name')
        else:
            CryptoFactory._plugins[encryption_name.upper()] = plugin


    @staticmethod
    def get_plugin_from_map(encryption_name):
        ''' 
             Get the plugin from the map.

            >>> _plugins = {}
            >>> _class_prefix = CryptoFactory.CRYPTO_PLUGIN_CLASS_PREFIX
            >>> plugin_module = import_module('goodcrypto.oce.gpg_plugin')
            >>> CryptoFactory.set_plugin('GPG', plugin_module)
            >>> plugin = CryptoFactory.get_plugin_from_map('GPG')
            >>> type(plugin)
            <type 'module'>

             This maps from a plugin name, such as GPG, to an instance of that plugin.
             Each plugin should be a singleton.

            @param    readable name of the plugin
            @return    The PluginMap value
        '''

        try:
            if encryption_name is None:
                plugin = None
            else:
                plugin = CryptoFactory._plugins[encryption_name]
        except Exception:
            plugin = None

        return plugin


    @staticmethod
    def get_plugin_instance(encryption_name, plugin_classname):
        ''' 
            Get the instance of a class from the name of the module and class. 
            
            Get the interface to GPG which is supplied with GoodCrypto Mail
            >>> _plugins = {}
            >>> _class_prefix = CryptoFactory.CRYPTO_PLUGIN_CLASS_PREFIX
            >>> gpg_plugin = CryptoFactory.get_plugin_instance('GPG', 'goodcrypto.oce.gpg_plugin.GPGPlugin')
            >>> type(gpg_plugin)
            <class 'goodcrypto.oce.gpg_plugin.GPGPlugin'>
        '''

        plugin = None
        if encryption_name is not None:
            try:
                module_name, x, classname = plugin_classname.rpartition('.')
                plugin_module = import_module(module_name)
                plugin = getattr(plugin_module, classname)()
            except Exception as e:
                CryptoFactory.debug_message('did not find class: {}: {}'.format(plugin_classname, e))
                new_plugin_className = CryptoFactory.get_classname(plugin_classname)
                if new_plugin_className == plugin_classname:
                    CryptoFactory.log_message('no alternate plugin class name available for {}'.format(plugin_classname))
                else:
                    plugin = CryptoFactory.get_crypto(new_plugin_className)
    
            if plugin == None:
                CryptoFactory.log_message('Unable to load plugin class: {}'.format(plugin_classname))
            else:
                CryptoFactory.debug_message('got plugin class: {}'.format(plugin_classname))
                CryptoFactory.set_plugin(encryption_name, plugin)

        return plugin


    @staticmethod
    def log_message(message):
        '''  
            Log a message.
            
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> CryptoFactory._log = None
            >>> CryptoFactory.log_message('Test message')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.oce.crypto_factory.x.log'))
            True
        '''
        
        if CryptoFactory._log is None:
            CryptoFactory._log = LogFile()

        CryptoFactory._log.write_and_flush(message)


    @staticmethod
    def debug_message(message):
        '''  
            Log a message if DEBUGGING is true.
            
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> debug = CryptoFactory.DEBUGGING
            >>> CryptoFactory.DEBUGGING = True
            >>> CryptoFactory._log = None
            >>> CryptoFactory.debug_message('Debug message')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.oce.crypto_factory.x.log'))
            True
            >>> CryptoFactory.DEBUGGING = debug
        '''
        
        if CryptoFactory.DEBUGGING:
            if CryptoFactory._log is None:
                CryptoFactory._log = LogFile()
    
            CryptoFactory._log.write_and_flush(message)

