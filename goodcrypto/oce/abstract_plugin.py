#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-09-20

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import os
from abc import abstractmethod
from traceback import format_exc

from goodcrypto.oce.abstract_crypto import AbstractCrypto


class AbstractPlugin(AbstractCrypto):
    ''' Pluggable crypto service superclass for the Open Crypto Engine. 
    
        AbstractPlugin is an API for a specific implemention of a crypto algorithm.
        AbstractCrypto describes the crypto algorithm, such as PGP.
        AbstractPlugin inherits from AbstractCrypto.
        For example, GPGPlugin is an instance of AbstractPlugin which implements
        an API for the GPG program.
    '''


    @abstractmethod
    def get_plugin_name(self):
        '''
            Get the OCE plugin classname.

            @return classname of plugin
        '''
        
    @abstractmethod
    def get_plugin_version(self):
        '''
            Get the OCE plugin version.

            @return plugin version
        '''
        
    @abstractmethod
    def set_executable(self, pathname):
        ''' 
            Set executable pathname.
            This default implementation does nothing because some plugins don't have an executable.

            @param  pathname executable pathname
        '''

    @abstractmethod
    def get_executable(self):
        ''' 
            Get executable pathname.
            This default implementation returns null.

            @return executable pathname
        '''


    @abstractmethod
    def get_default_executable(self):
        ''' 
            Get default executable pathname.
            This default implementation returns null.

            @return default executable pathname
        '''


    @abstractmethod
    def set_home_dir(self, dirname):
        '''
            Sets the home dir, if used by plugin.
        '''

    @abstractmethod
    def get_home_dir(self):
        '''
            Gets the home dir, if used by plugin.
        '''

    def get_default_home_dir(self):

        defaultHomeDir = os.environ['HOME']
        self.log_message("default home dir is " + defaultHomeDir)

        return defaultHomeDir


    def get_job_count(self):
        '''
            Get the jobs in the queue.
        '''
        
        return 0
    
    def wait_until_queue_empty(self):
        '''
            Wait until the queue is empty.
        '''

        pass
    
    def clear_failed_queue(self):
        ''' 
            Clear all the jobs in the failed queue.
        '''

        pass

