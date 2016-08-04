'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-11-13

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.

    Constants for GoodCrypto messages.

    As of 2005.12.24 the X-OpenPGP-xxx headers got zero google matches, so
    it didn't conflict with any existing header.
    As of 2006.05.04 Google appears to have changed how they search for,
    e.g. 'X-OpenPGP-Accepts', so this check is not as effective.
'''

#  Email header for public key of sender.
PUBLIC_KEY_HEADER = 'X-OpenPGP-PublicKey'

#  Email header for public fingerprint of sender.
PUBLIC_FINGERPRINT_HEADER = 'X-{}-Fingerprint'

#  Email header for openpgp services accepted.
ACCEPTED_CRYPTO_SOFTWARE_HEADER = 'X-OpenPGP-Accepts'

# Email header for openpgp mime type.
# RFC 3156 doesn't specify what was encrypted, so this custom header does.
PGP_ENCRYPTED_CONTENT_TYPE = 'X-OpenPGP-EncryptedContentType'

# the original sender and recipient for a message encrypted to protect metadata
ORIGINAL_FROM = 'X-ORIGINAL-FROM'
ORIGINAL_TO = 'X-ORIGINAL-TO'

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
TAGLINE_DELIMITER = '__________________________________________________________'

LF = '\n'
CRLF = '\r\n'

DEFAULT_CHAR_SET = 'UTF-8'

# constants for queuing messages to prevent tracking
MESSAGE_PREFIX = 'msg'
MESSAGE_SUFFIX = 'txt'
START_ADDENDUM = '\n\n-----START OF GOODCRYPTO ADDENDUM-----\n'
END_ADDENDUM = '-----END OF GOODCRYPTO ADDENDUM-----\n'

# extra details needed in a queued message
CRYPTED_KEYWORD = 'crypted'
CRYPTED_WITH_KEYWORD = 'crypted-with'
VERIFICATION_KEYWORD = 'verification-code'

MIN_DKIM_KEY = 2048

