#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-01-04

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from __future__ import print_function

import os, re, sh, sys, time
from syr.log import get_log
from syr.python import caller_module_name
from traceback import format_exc
#from syr.sync_function import synchronized

# delete in python 3
import sys
reload(sys)
sys.setdefaultencoding('utf-8')


class LogFile(object):
    '''
        Logs to a file if logging is enabled.

        A copy of every entry in every log, except the IgnoredLog, is
        also logged to a log called master.log.
    '''

    def __init__(self, filename=None):
        ''' 
            Create a log file named after the class that called this constructor.
            
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> filename = 'goodcrypto.utils.log_file.log'
            >>> if os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), filename)): os.remove(os.path.join(BASE_LOG_DIR, whoami(), filename))
            >>> log = LogFile(filename)
            >>> log.logging_enabled = True
            >>> log.write('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), filename))
            True
            >>> if os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), filename)): os.remove(os.path.join(BASE_LOG_DIR, whoami(), filename))
        '''

        try:
            from goodcrypto.utils import debug_logs_enabled
            self.logging_enabled = debug_logs_enabled()
        except Exception, IOError:
            from syr.log import _debug
            _debug(format_exc(), force=True)
            self.logging_enabled = True

        try:
            if filename is None:
                # try to find the name of the caller
                filename = caller_module_name(ignore=[__file__,'log.py'])
        except Exception:
            filename = 'goodcrypto.utils.log'
    
        # get to a reasonable filename if the entire path was included
        if filename.startswith('/'):
            filename = os.path.basename(filename)
            
        # strip off standard python extensions
        if filename.endswith('.py') or filename.endswith('.pyc'):
            filename, __, __ = filename.rpartition('.')
        
        if not filename.endswith('.log'):
            filename = '{}.log'.format(filename)

        self.log = get_log(filename)

    #@synchronized
    def write(self, message):
        '''
            Print logging data, a message, and an end of line to the log.
        
            This method is "static synchronized" to partially avoid concurrency issues in the
            middle of a line. We can still have different instances of Log which are
            going to the same place interleaving their messages, though.
            
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> filename = 'test_log_file.log'
            >>> if os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), filename)): os.remove(os.path.join(BASE_LOG_DIR, whoami(), filename))
            >>> log = LogFile(filename)
            >>> log.logging_enabled = False
            >>> log.write('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), filename))
            False
            >>> if os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), filename)): os.remove(os.path.join(BASE_LOG_DIR, whoami(), filename))
            
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> filename = 'test_log_file.log'
            >>> if os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), filename)): os.remove(os.path.join(BASE_LOG_DIR, whoami(), filename))
            >>> log = LogFile(filename)
            >>> log.logging_enabled = True
            >>> log.write('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), filename))
            True
            >>> if os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), filename)): os.remove(os.path.join(BASE_LOG_DIR, whoami(), filename))
        '''

        if self.logging_enabled:
            self.log(message)
    
    def write_and_flush(self, message):
        '''
            Write and flush a message. 
            Use this when rqworker won't save log messages.
            
            >>> log = LogFile('test.log')
            >>> log.write_and_flush('test')
        '''

        if self.logging_enabled:
            m = re.match('^.*(\.log)', self.log.pathname)
            if m:
                filename = self.log.pathname.replace(m.group(1), '.log')
            else:
                filename = '{}.x'.format(self.log.pathname)
            with open(filename, 'at') as f:
                t = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                f.write('{} {}\n'.format(t, repr(message)))
            #from syr.log import _debug, _DEFAULT_PERMS
            #_debug(message, force=True, filename=filename, mode=_DEFAULT_PERMS)

    def flush(self):
        '''
            Flush the log to disk.
        
            >>> log = LogFile('test.log')
            >>> log.write('test')
            >>> log.flush()
        '''

        self.log.flush()


