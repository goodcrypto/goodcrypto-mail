'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-26

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

            >>> message = 'oops'
            >>> try:
            ...     raise MessageException('oops')
            ...     fail()
            ... except MessageException as message_exception:
            ...     str(message_exception) == message
            True
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
            >>> isinstance(message_exception.__str__(), str)
            True
        '''

        return str(self.value)

if __name__ == "__main__":
    import doctest
    doctest.testmod(verbose=True)

