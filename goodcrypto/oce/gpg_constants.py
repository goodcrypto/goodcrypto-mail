#!/usr/bin/env python
'''
    Public constants for GNU Privacy Guard.
    
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-16

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import os

#  Name of the plugin.
NAME = 'goodcrypto.oce.gpg_plugin.GPGPlugin'

#  Name of the GPG encryption software. 
ENCRYPTION_NAME = "GPG"

#  Directory for GPG keyrings. 
DIR_NAME = ".gnupg"

#  Filename of GPG public keyring. 
PUBLIC_KEY_FILENAME = "pubring.gpg"

#  Filename of GPG secret keyring. 
SECRET_KEY_FILENAME = "secring.gpg"

# End of line
EOL = os.linesep

# result codes
GOOD_RESULT = 0
ERROR_RESULT = -1
TIMED_OUT_RESULT = -2

# suffix for lock files
LOCK_FILE_SUFFIX = ".lock"

# gpg commands
GET_FINGERPRINT = '--fingerprint'
GET_VERSION = '--version'
LIST_PUBLIC_KEYS = '--list-public-keys'
LIST_SECRET_KEYS = '--list-secret-keys'
GEN_KEY = '--gen-key'
EXPORT_KEY = '--export'
IMPORT_KEY = '--import'
DRY_RUN = '--dry-run'

DELETE_KEYS = '--delete-secret-and-public-key'
DELETE_SECRET_KEY = '--delete-secret-key'

DECRYPT_DATA = '--decrypt'
ENCRYPT_DATA = '--encrypt'
ARMOR_DATA = '--armor'
VERIFY = '--verify'
LIST_PACKETS = '--list-packets'

SIGN = '--sign'
CLEAR_SIGN = '--clearsign'
LOCAL_USER = '--local-user'
RECIPIENT = '--recipient'

OPEN_PGP = '--openpgp'
CHARSET = '--charset'
UTF8 = 'utf-8'
WITH_COLONS = '--with-colons'

# Used to gen a key
KEY_TYPE = 'Key-Type: '
KEY_LENGTH = 'Key-Length: '
SUBKEY_TYPE = 'Subkey-Type: '
SUBKEY_LENGTH = 'Subkey-Length: '
EXPIRE_DATE = 'Expire-Date: '
KEY_PASSPHRASE = 'Passphrase: '
NAME_REAL = 'Name-Real: '
NAME_EMAIL = 'Name-Email: '
COMMIT_KEY = '%commit'

