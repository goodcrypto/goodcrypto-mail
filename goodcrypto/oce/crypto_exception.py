#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-06-13

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

class CryptoException(Exception):
    ''' Crypto exception.  '''

    def __init__(self, value=None):
        ''' 
            Constructor for the CryptoException.
            
            >>> try:
            ...     raise CryptoException()
            ... except CryptoException as exception:
            ...     print(exception.value)
            None
            
            >>> raise CryptoException('oops')
            Traceback (most recent call last):
                ...
            CryptoException: 'oops'
        '''

        if value is None:
            super(CryptoException, self).__init__()
        else:
            super(CryptoException, self).__init__(value)
            
        self.value = value

    def __str__(self):
        ''' 
            Get the string representation of the exception. 
            
            >>> message_exception = CryptoException()
            >>> str(message_exception)
            'None'

            >>> message_exception = CryptoException('error message')
            >>> str(message_exception)
            "'error message'"
        '''
        
        return repr(self.value)

