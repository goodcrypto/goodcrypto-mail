#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from datetime import date
from traceback import format_exc

from goodcrypto.oce.key.constants import EXPIRES_IN, EXPIRATION_UNIT
from goodcrypto.oce.utils import strip_fingerprint
from goodcrypto.utils.log_file import LogFile

_log = LogFile()



def get_standardized_expiration(expiration):
    '''
        Change the expiration dictionary into its 2 components: number of units and units.
        
        If the expiration is None, then use the default that the key never expires.
        Adjust any errors in formatting (e.g., units should be '' for days, 
        'w' for weeks, 'm' for months, and 'y' for years.
        
        >>> get_standardized_expiration(None)
        (0, '')
        
        >>> get_standardized_expiration({EXPIRES_IN: 1, EXPIRATION_UNIT: 'y',})
        (1, 'y')
        
        >>> get_standardized_expiration({EXPIRES_IN: 5, EXPIRATION_UNIT: 'd',})
        (5, '')
        
        >>> get_standardized_expiration({EXPIRES_IN: 99,})
        (99, 'y')

        >>> get_standardized_expiration({EXPIRATION_UNIT: 'd',})
        (0, '')
        
        >>> get_standardized_expiration({EXPIRES_IN: 2, EXPIRATION_UNIT: 'weeks',})
        (2, 'w')
        
        >>> get_standardized_expiration({EXPIRES_IN: 10, EXPIRATION_UNIT: 'j',})
        (10, 'y')
    '''

    expires_in = None
    expiration_unit = None
    
    if expiration is not None:
        if expiration.has_key(EXPIRES_IN):
            expires_in = expiration[EXPIRES_IN]
        if expiration.has_key(EXPIRATION_UNIT):
            expiration_unit = expiration[EXPIRATION_UNIT]

    if expires_in is None or expires_in == 0:
        # never have the key expire
        expires_in = 0
        expiration_unit = ''
    elif expiration_unit is None:
        # set the units to year if undefined
        expiration_unit = 'y'
    else:
        expiration_unit = expiration_unit.strip().lower()
        if len(expiration_unit) > 1:
            expiration_unit = expiration_unit[:1]
        if expiration_unit == 'd':
            expiration_unit = ''
        elif expiration_unit == 'w' or expiration_unit == 'm' or expiration_unit == 'y':
            pass
        else:
            expiration_unit = 'y'

    return expires_in, expiration_unit

def parse_fingerprint_and_expiration(output):
    '''
        Parse the output for the fingerprint and the expiration date.
        
        >>> # In honor of Tim Hudson, who co-developed the SSLeay library that OpenSSL is based.
        >>> output = 'pub   4096R/CC95031C 2014-06-14\\nKey fingerprint = 69F9 99F3 6802 4CDD FEBD  266E 95B7 2664 CC95 031C\\nuid                  Tim <Tim@goodcrypto.local>\\nsub   4096R/156739BF 2014-06-14        '
        >>> parse_fingerprint_and_expiration(output)
        ('69F999F368024CDDFEBD266E95B72664CC95031C', None)

        >>> parse_fingerprint_and_expiration(None)
        (None, None)
    '''

    fingerprint = expiration_date = None
    if output is not None:
        for line in output.split('\n'):
            if expiration_date is None:
                expiration_date = _parse_expiration_date(line)
            fingerprint = _parse_fingerprint(line)
            if fingerprint and len(fingerprint) > 0:
                break

        fingerprint = strip_fingerprint(fingerprint)
                
    return fingerprint, expiration_date
    
def _parse_expiration_date(line):
    '''
        Parse the expiration date, if there is one, from the line.

        >>> _parse_expiration_date('pub   4096R/8FD9B90B 2013-11-19 [expires: 2014-11-19]')
        '2014-11-19'
        >>> _parse_expiration_date('pub   4096R/8FD9B90B 2013-11-19') is None
        True
        >>> _parse_expiration_date('Key fingerprint = 12345678') is None
        True
    '''

    PUB_LINE = 'pub'
    EXPIRES_START = '['
    EXPIRES_END = ']'

    expiration_date = None
    try:
        if line:
            if line.startswith(PUB_LINE) and line.find(EXPIRES_START) > 0:
                index = line.find(EXPIRES_START) + len(EXPIRES_START)
                line = line[index:]
                index = line.find(EXPIRES_END)
                if index > 0:
                    line = line[:index]
                index = line.find(': ')
                if index > 0:
                    expiration_date = line[index + len(': '):].strip()
    except Exception:
        _log.write(format_exc())

    return expiration_date

def _parse_fingerprint(line):
    '''
        Parse the fingerprint from the line.

        >>> _parse_fingerprint('Key fingerprint =12345678') == '12345678'
        True
        >>> _parse_fingerprint('The GPG Key fingerprint =12345678') == '12345678'
        True
        >>> _parse_fingerprint('Key fingerprint = 12345678') == '12345678'
        True
        >>> _parse_fingerprint('key Fingerprint =12345678') == '12345678'
        True
        >>> _parse_fingerprint('Schl.-Fingerabdruck =12345678') == '12345678'
        True
        >>> _parse_fingerprint('schl.-fingerabdruck =12345678') == '12345678'
        True
        >>> _parse_fingerprint('schl.-fingerabdruck =') == None
        True
        >>> _parse_fingerprint('123456789') == None
        True
        >>> _parse_fingerprint(123) == None
        True
    '''

    FINGERPRINT_PREFIX1 = 'key fingerprint ='
    FINGERPRINT_PREFIX2 = 'key fingerprint='
    FINGERPRINT_PREFIX3 = 'schl.-fingerabdruck ='
    FINGERPRINT_PREFIX4 = 'schl.-fingerabdruck='

    fingerprint = None
    try:
        prefix = FINGERPRINT_PREFIX1
        index = line.lower().find(FINGERPRINT_PREFIX1)
        if index < 0:
            prefix = FINGERPRINT_PREFIX2
            index = line.lower().find(FINGERPRINT_PREFIX2)
        if index < 0:
            prefix = FINGERPRINT_PREFIX3
            index = line.lower().find(FINGERPRINT_PREFIX3)
        if index < 0:
            prefix = FINGERPRINT_PREFIX4
            index = line.lower().find(FINGERPRINT_PREFIX4)

        if index >= 0:
            offset = index + len(prefix)
            suffix = line[offset:].strip()
            if len(suffix) > 0:
                fingerprint = suffix
    except Exception:
        _log.write('Unable to _parse: {}'.format(line))
        _log.write(format_exc())

    return fingerprint

