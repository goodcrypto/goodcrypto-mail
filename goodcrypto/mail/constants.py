'''
    Constants for GoodCrypto Mail.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-26

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

# outbound encrypt policy (max 10 characters)
USE_GLOBAL_OUTBOUND_SETTING = 'global'
ALWAYS_ENCRYPT_OUTBOUND = 'always'
NEVER_ENCRYPT_OUTBOUND = 'never'
DEFAULT_OUTBOUND_ENCRYPT_POLICY = USE_GLOBAL_OUTBOUND_SETTING
ACTIVE_ENCRYPT_POLICIES = [
    USE_GLOBAL_OUTBOUND_SETTING,
    ALWAYS_ENCRYPT_OUTBOUND
]

# keyserver status (max 50 characters)
KEYSERVER_CONNECTION_OK = 'OK'
DEFAULT_KEYSERVER_STATUS = 'No attempt to contact yet'

# source of key (max 10 characters)
AUTO_GENERATED = 'automatic'
MESSAGE_HEADER = 'header'
KEYSERVER = 'keyserver'
MANUALLY_IMPORTED = 'manual'

# clear sign policies
CLEAR_SIGN_WITH_DOMAIN_KEY = 'domain'
CLEAR_SIGN_WITH_SENDER_KEY = 'sender'
CLEAR_SIGN_WITH_SENDER_OR_DOMAIN = 'sender_or_domain'
DEFAULT_CLEAR_SIGN_POLICY = CLEAR_SIGN_WITH_DOMAIN_KEY

# delivery policies if DKIM verification fails
DKIM_WARN_POLICY = 'warn'
DKIM_DROP_POLICY = 'drop'
DEFAULT_DKIM_POLICY = DKIM_WARN_POLICY

UNKNOWN_EMAIL = 'Unknown'

USE_POSTGRESQL = True

# used by postfix
POSTFIX_FILTER_PORT = 10027

# used by keyservers
HKP_PORT = 11371




