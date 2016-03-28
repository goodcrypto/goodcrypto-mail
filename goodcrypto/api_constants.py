'''
    API Constants for GoodCrypto.

    Copyright 2014-2015 Good Crypto
    Last modified: 2015-04-04

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

# IMPORTANT: Be sure to co-ordinate all URLs and KEYs with both sides of the APIs

SERVER_API_URL = 'https://goodcrypto.com/server/api/'
MAIL_API_URL = 'http://127.0.0.1:8080/mail/api'
WEB_API_URL = 'http://127.0.0.1:8080/web/api'
SYSTEM_API_URL = 'http://127.0.0.1:8080/system/customize/'

# the shared dictionary keys
ACTION_KEY = 'action'
OK_KEY = 'ok'
ERROR_KEY = 'error'
MESSAGE_KEY = 'message'
SYSADMIN_KEY = 'sysadmin'
PASSWORD_KEY = 'password'

# the dictionary keys for the Mail and Web APIs
DOMAIN_KEY = 'domain'
MTA_ADDRESS_KEY = 'mail_server_address'
PUBLIC_KEY = 'public_key'
FINGERPRINT_KEY = 'fingerprint'
USER_NAME_KEY = 'user_name'
ENCRYPTION_NAME_KEY = 'encryption_name'
EMAIL_KEY = 'email'

# the actions for the Mail and Web API
# don't forget to add the actions to forms.py
STATUS = 'status'
CONFIGURE = 'configure'
CREATE_SUPERUSER = 'create_superuser'
IMPORT_KEY = 'import_key'
GET_FINGERPRINT = 'get_fingerprint'
GET_CONTACT_LIST = 'get_contact_list_key'

# the dictionary keys for the Server API
DOMAIN_KEY = 'domain'
PIN_KEY = 'pin'

