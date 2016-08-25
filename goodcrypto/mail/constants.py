'''
    Constants for GoodCrypto Mail.

    Copyright 2014-2015 GoodCrypto
    Last modified: 2016-01-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
USER = 'goodcrypto'
USER_GROUP = USER

# the user for the shared domain email (e.g., _domain_@example.com)
DOMAIN_USER = '_domain_'

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

# outbound encrypt policy
USE_GLOBAL_OUTBOUND_SETTING = 'global'
ALWAYS_ENCRYPT_OUTBOUND = 'always'
NEVER_ENCRYPT_OUTBOUND = 'never'
DEFAULT_OUTBOUND_ENCRYPT_POLICY = USE_GLOBAL_OUTBOUND_SETTING
ACTIVE_ENCRYPT_POLICIES = [
    USE_GLOBAL_OUTBOUND_SETTING,
    ALWAYS_ENCRYPT_OUTBOUND
]

# clear sign policies
CLEAR_SIGN_WITH_DOMAIN_KEY = 'domain'
CLEAR_SIGN_WITH_SENDER_KEY = 'sender'
CLEAR_SIGN_WITH_SENDER_OR_DOMAIN = 'sender_or_domain'
DEFAULT_CLEAR_SIGN_POLICY = CLEAR_SIGN_WITH_DOMAIN_KEY

# delivery policies if DKIM verification fails
DKIM_WARN_POLICY = 'warn'
DKIM_DROP_POLICY = 'drop'
DEFAULT_DKIM_POLICY = DKIM_WARN_POLICY

USE_POSTGRESQL = True

