'''
    Copyright 2014 GoodCrypto
    Last modified: 2015-07-08

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

class MessageException(Exception):

    def __init__(self, value=None):
        ''' 
            Constructor for the MessageException object.
            
            >>> try:
            ...     raise MessageException()
            ... except MessageException as exception:
            ...     print(exception.value)
            None
            
            >>> raise MessageException('oops')
            Traceback (most recent call last):
                ...
            MessageException: 'oops'
        '''

        if value is None:
            super(MessageException, self).__init__()
        else:
            super(MessageException, self).__init__(value)
            
        self.value = value

    def __str__(self):
        ''' 
            Get the string representation of the exception. 
            
            >>> message_exception = MessageException()
            >>> str(message_exception)
            'None'

            >>> message_exception = MessageException('error message')
            >>> str(message_exception)
            "'error message'"
        '''
        
        return repr(self.value)

if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)

