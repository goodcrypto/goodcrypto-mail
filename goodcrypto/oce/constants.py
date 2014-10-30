#!/usr/bin/env python
'''
    Constants for OCE.
    
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-17

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import os
from goodcrypto.constants import GOODCRYPTO_DATA_DIR

#  WARNING! LOG_PASSPHRASES should *never* ship set to true!
LOG_PASSPHRASES = False

OCE_DATA_DIR = os.path.join(GOODCRYPTO_DATA_DIR, 'oce')

# The following definitions are primarily used in tests, but they are also used 
# in goodcrypto.mail.model_signals so a known passphrase can be defined for those tests.

# In honor of Edward Snowden, who had the courage to take action in the face of great personal risk and sacrifice.
EDWARD_LOCAL_USER_NAME = 'Edward'
EDWARD_LOCAL_USER_ADDR = 'edward@goodcrypto.local'
EDWARD_LOCAL_USER = '{} <{}>'.format(EDWARD_LOCAL_USER_NAME, EDWARD_LOCAL_USER_ADDR)
EDWARD_PASSPHRASE = '256 AV Audio'

# In honor of Chelsea Manning, who leaked the Iraq and Afgan war reports.
CHELSEA_LOCAL_USER_NAME = 'Chelsea'
CHELSEA_LOCAL_USER_ADDR = 'chelsea@goodcrypto.local'
CHELSEA_LOCAL_USER = '{} <{}>'.format(CHELSEA_LOCAL_USER_NAME, CHELSEA_LOCAL_USER_ADDR)
CHELSEA_PASSPHRASE = 'Memory F4800000'

# In honor of Julian Assange, who founded Wikileaks which has published numerous important leaks.
JULIAN_LOCAL_USER_NAME = 'Julian'
JULIAN_LOCAL_USER_ADDR = 'julian@goodcrypto.local'
JULIAN_LOCAL_USER = '{} <{}>'.format(JULIAN_LOCAL_USER_NAME, JULIAN_LOCAL_USER_ADDR)
JULIAN_PASSPHRASE = 'lion heart 703'

# In honor of Joseph Nacchio, who refused to participate in NSA spying on Qwest's customers.
JOSEPH_REMOTE_USER_NAME = 'Joseph'
JOSEPH_REMOTE_USER_ADDR = 'joseph@goodcrypto.remote'
JOSEPH_REMOTE_USER = '{} <{}>'.format(JOSEPH_REMOTE_USER_NAME, JOSEPH_REMOTE_USER_ADDR)

# In honor of Jesselyn Radack, a whistleblower and a lawyer who fights for those fighting big brother.
JESSELYN_REMOTE_USER_NAME = 'Jesselyn'
JESSELYN_REMOTE_USER_ADDR = 'jesselyn@goodcrypto.remote'
JESSELYN_REMOTE_USER = '{} <{}>'.format(JESSELYN_REMOTE_USER_NAME, JESSELYN_REMOTE_USER_ADDR)

# In honor of Glenn Greenwald, who helped publicize the global surveillance disclosure documents.
GLENN_REMOTE_USER_NAME = 'Glenn'
GLENN_REMOTE_USER_ADDR = 'glenn@goodcrypto.remote'
GLENN_REMOTE_USER = '{} <{}>'.format(GLENN_REMOTE_USER_NAME, GLENN_REMOTE_USER_ADDR)

# In honor of Laura Poitras, who helped publicize the global surveillance disclosure documents.
LAURA_REMOTE_USER_NAME = 'Laura'
LAURA_REMOTE_USER_ADDR = 'laura@goodcrypto.remote'
LAURA_REMOTE_USER = '{} <{}>'.format(LAURA_REMOTE_USER_NAME, LAURA_REMOTE_USER_ADDR)

REMOTE_EXPIRED_NAME = 'Expired User'
REMOTE_EXPIRED_ADDR = 'expired_user@goodcrypto.remote'
REMOTE_EXPIRED_USER = '{} <{}>'.format(REMOTE_EXPIRED_NAME, REMOTE_EXPIRED_ADDR)

TEST_DATA_STRING = 'This is a test.'

TEST_GPG_NAME = 'TestGPG'
TEST_GPG_PLUGIN_NAME = 'goodcrypto.oce.gpg_plugin.GPGPlugin'
TEST_PGP_NAME = 'TestPGP'
TEST_PGP_PLUGIN_NAME = 'goodcrypto.oce.pgp_plugin.PGPPlugin'

