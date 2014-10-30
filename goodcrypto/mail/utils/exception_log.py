#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-08-26

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

from syr.log import get_log


class ExceptionLog(object):
    ''' 
        A central log for exceptions that logs regardless of the user's preferences because
        these are serious errors. This log is for exceptions of all kinds, not just python Exceptions.
    '''
    
    _log = None
    
    @staticmethod
    def log_message(message):
        ''' 
            Gets the ExceptionLog singleton.

            >>> from os.path import exists, join
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> ExceptionLog.log_message('test')
            >>> exists(join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.utils.exception_log.log'))
            True
        '''
        
        if ExceptionLog._log is None:
            ExceptionLog._log = get_log()

        ExceptionLog._log(message)

