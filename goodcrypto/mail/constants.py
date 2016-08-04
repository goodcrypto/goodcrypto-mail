'''
    Constants for GoodCrypto Mail.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-11-29

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
USER = 'goodcrypto'
USER_GROUP = USER

PASSCODE_MAX_LENGTH = 1000
PASSWORD_MAX_LENGTH = 25

TAG_PREFIX = 'GoodCrypto'
TAG_WARNING = '{} Warning'.format(TAG_PREFIX)
TAG_ERROR = '{} Error'.format(TAG_PREFIX)

# short form of time periods
HOURS_CODE = 'h'
DAYS_CODE = 'd'
WEEKS_CODE = 'w'
MONTHS_CODE = 'm'
YEARS_CODE = 'y'

# delivery policies if DKIM verification fails
DKIM_WARN_POLICY = 'warn'
DKIM_DROP_POLICY = 'drop'
DEFAULT_DKIM_POLICY = DKIM_WARN_POLICY

USE_POSTGRESQL = True

