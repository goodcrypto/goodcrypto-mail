#!/usr/bin/env python
'''
    Constant declarations for the GNU Privacy Guard key plugin.

    Copyright 2014 GoodCrypto
    Last modified: 2014-10-23

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

#  Name of the plugin.
NAME = "goodcrypto.oce.key.gpg_plugin.GPGPlugin"

# prefix for the public key info on import
PUBLIC_KEY_PREFIX = 'gpg: pub'
ALT_KEY_PREFIX = 'gpg: key'

# prefixes for the public key block
USER_ID_PACKET_PREFIX = ':user ID packet'
SIGNATURE_PACKET_PREFIX = ':signature packet'
KEY_ID_LABEL = 'keyid'

