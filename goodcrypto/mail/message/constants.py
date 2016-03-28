#!/usr/bin/env python
'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-04-15

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.

    Constants for GoodCrypto messages.

    As of 2005.12.24 the X-OpenPGP-xxx headers got zero google matches, so 
    it didn't conflict with any existing header.
    As of 2006.05.04 Google appears to have changed how they search for,
    e.g. 'X-OpenPGP-Accepts', so this check is not as effective.
'''

BEGIN_PGP_MESSAGE = '-----BEGIN PGP MESSAGE-----'
END_PGP_MESSAGE = '-----END PGP MESSAGE-----'

BEGIN_PGP_SIGNED_MESSAGE = '-----BEGIN PGP SIGNED MESSAGE-----'
BEGIN_PGP_SIGNATURE = '-----BEGIN PGP SIGNATURE-----'
END_PGP_SIGNATURE = '-----END PGP SIGNATURE-----'


#  Email header for public key of sender. 
PUBLIC_KEY_HEADER = 'X-OpenPGP-PublicKey'

#  Email header for public fingerprint of sender. 
PUBLIC_FINGERPRINT_HEADER = 'X-{}-Fingerprint'

#  Email header for openpgp services accepted. 
ACCEPTED_CRYPTO_SOFTWARE_HEADER = 'X-OpenPGP-Accepts'

# Email header for openpgp mime type.
# RFC 3156 doesn't specify what was encrypted, so this custom header does.      
PGP_ENCRYPTED_CONTENT_TYPE = 'X-OpenPGP-EncryptedContentType'

NEW_LINE = '\n'

'''
     We can't use the tagline delimiter from RFC 3676 Usenet
     Signature Convention because Outlook strips these taglines,
     even though the standard says it's so mail clients can
     strip taglines for replies, not all taglines.
'''
TAGLINE_DELIMITER_3676 = '--'

#  We'd like to use <hr> but can't because bayesian spam filters score html badly.
TAGLINE_DELIMITER_HTML = '<hr>'
TAGLINE_DELIMITER = '____________________________________________________________________________'

CRLF = '\r\n'

DEFAULT_CHAR_SET = 'UTF-8'

