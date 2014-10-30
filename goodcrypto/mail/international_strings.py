#!/usr/bin/env python
'''
    Internationalized messages used in GoodCrypto.

    Copyright 2014 GoodCrypto
    Last modified: 2014-10-23

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

from goodcrypto.utils.internationalize import translate

GOODCRYPTO_PREFIX = translate('GoodCrypto: ')
WARNING_PREFIX = translate('GoodCrypto warning: ')
ERROR_PREFIX = translate('Error:')
SERIOUS_ERROR_PREFIX = translate('Serious error:')

MISMATCHED_FINGERPRINTS = translate('The {} fingerprint for {} does not match the saved fingerprint.')
ONLY_ONE_OPTION = translate('You may only have one Options record. Either change the current record or delete it before adding.')

# mail/__main__.py
BOUNCED_ENCRYPTED_SUBJECT = translate('Undelivered Mail: Unable to encrypt message')
BOUNCED_DECRYPTED_SUBJECT = translate('Error: Unable to decrypt message')
MESSAGE_EXCEEDED_LIMIT = translate('Message exceeded limit of {} characters.')
MESSAGE_REJECTED = translate('Message rejected.')
UNABLE_TO_SEND_MESSAGE = translate('Undelivered Mail: Unable to send message')
UNABLE_TO_RECEIVE_MESSAGE = translate('Error: Unable to receive message')
BAD_EMAIL_ADDRESS = translate('Bad email address')

# mail/admin.py
DETAILS_LABEL = translate('<label>&nbsp;</label>Details')
ADVANCED_LABEL = translate('<label>&nbsp;</label>Advanced')
CONTACTS_CRYPTO_INLINE_NAME = translate('encryption software used by this contact')

# mail/contacts.py
KEY_IMPORT_GOOD = translate('Imported key successfully. Fingerprint: {}')
NO_FINGERPRINT_IN_DB = translate('There is no {} fingerprint in the database for {}.')
NO_KEY_EXISTS = translate('There is no {} key for {}.')
KEY_EXPIRED_ON = translate('The {} key for {} expired on {}.')
MULTIPLE_KEYS = translate("Public key doesn't contain just 1 user's key: {} keys")
ONLY_1_KEY_ALLOWED = translate('Public key must contain 1 key. It contains {} keys.')
WRONG_CONTACT_KEY = translate("Cannot import {} key because it isn't for {}")
IMPORT_MISSING_DATA = translate('Unable to import public key with missing data')
CRYPTO_NOT_SUPPORTED = translate('GoodCrypto does not currently support {}')
PUBLIC_KEY_INVALID = translate('Public key invalid -- no user ids found')

# mail/forms.py
CRYPTO_NOT_AVAILABLE = translate('{} is not available.')
NEED_PASSCODE = translate('You must enter a passcode or add a check mark to "Auto generate" it.')
MISSING_MAIL_OPTIONS = translate('You may only have one mail options record. Either change the current record or delete it before adding.')
MISSING_CRYPTO = translate('You must include at least one encryption program for this contact.')
VERIFY_FINGERPRINT_HELP = translate('Enter the email address whose fingerprint you want to verify.')
SELECT_CRYPTO_HELP = translate('Select the encryption software for the key.')
EXPORT_KEY_HELP = translate('Enter the email address whose public key you want exported.')
SELECT_KEY_CRYPTO_HELP = translate('Select the encryption software for the key.')
SELECT_KEY_IMPORT_HELP = translate("Select the user whose public key you want to import. If the key doesn't match this email address it will *not* be imported.")
SELECT_CRYPTO_FOR_KEY_HELP = translate('Select the encryption software for the key.')
UPLOAD_PUBLIC_KEY_HELP = translate('Enter the filename, including the path, for the file containing the public key.')
ONLY_ONE_OPTION = translate('You may only have one Options record. Either change the current record or delete it before adding.')
NO_ANSWER_FROM_MTA = translate('Unable to connect to the mail transport agent (MTA) via port {}.')

# mail/messages/decrypt_filter.py
# We don't mention goodcrypto.com's site because it will increase the probability the message is flagged as spam
INSECURE_MESSAGE_TAG = translate('Anyone could have read this message.')
SIGNED_BY_TAG = translate('This message was signed by {}.')
NO_KEY_TO_DECRYPT = translate('{} does not have a matching key to decrypt the message')
NO_CRYPTO_TO_DECRYPT = translate('{} does not use any known encryption')
NO_PRIVATE_KEY = translate('{} does not have a private {} key.')
UNABLE_TO_DECRYPT = translate('Unable to decrypt message with {}')
UNKNOWN_SIG = translate("Can't check signature. Ask the sender to use GoodCrypto, or get and verify their public key.")

# mail/messages/decrypt_utils.py
SECURE_MESSAGE_TAG = translate('received this message securely')
STILL_ENCRYPTED_MESSAGE_TAG = translate('but there appears to be an extra protective layer.')
UNKNOWN_SIGNER = translate('This message was signed by an unknown user.')
WRONG_SIGNER = translate('This message was not signed by {}, but by {}.')
UTC = translate('UTC')
VALIDATION_TAG = translate("Validation: {}\n")

# mail/messages/email_messages.py
REMOVED_BAD_HEADER_LINES = translate('Removed bad header lines')

# mail/messages/encrypt_filter.py
ENCRYPTION_WORKS = translate('Anyone could have read this message. Use encryption, it works.')
# We aren't using the following text because it will increase the probability the message is flagged as spam
HELP_LINE = translate('Stop snoops reading your email. http:#goodcrypto.com')
UNABLE_TO_SEND = translate("Message not sent to {} because currently there isn't a private {} key for you and your sysadmin requires all encrypted messages also be clear signed.")
POSSIBLE_SEND_SOLUTION1 = translate("GoodCrypto is creating a private key now. You can try resending the message in 10-20 minutes.")
POSSIBLE_SEND_SOLUTION2 = translate("Ask your sysadmin to create a private key for you and then try resending the message.")
UNABLE_TO_ENCRYPT = translate("Error while trying to encrypt message from {} to {} using {}")
POSSIBLE_ENCRYPT_SOLUTION = translate("Report this error to your sysadmin.")

# mail/messages/header_keys.py
NEW_KEY_TAGLINE = translate('You received a new public key. Please verify it.')
VERIFY_NEW_KEY_TAGLINE = translate('Check with the sender to verify the key. Otherwise, someone could spoof secure mail from this user.')
"""
= translate('An unexpected error ocurred while processing this message')
= translate('Could not import new {} key for {}')
= translate('A new {} key arrived for {} that is not the same as the current key')
= translate("Contact the sender and verify if they've changed their {} key.")
= translate('If they *do* have a new key, then use your GoodCrypto server to delete the contact and ask them to resend the message.')
= translate('If the sender has *not* replaced their key, then reconfirm the fingerprint in your GoodCrypto server.')
= translate('Remember, never use email for the verification of fingerprints and header_keys.')
= translate('Missing the key for {}')
= translate('The message arrived with a key that matches the fingerprint in your GoodCrypto server, but that key is missing.')
= translate('The message arrived with a key that does not match the fingerprint in your GoodCrypto server and the key is missing.')
= translate('This should never happen so you need to communicate with the user *without* using email.')
= translate('*After* you verify that the following fingerprint is correct')
= translate('    fingerprint: {}')
= translate('then, use your GoodCrypto server to delete the {} contact.')
= translate('Next, ask {} to resend the message.')
= translate('Finally, verify the new fingerprint with {}. Remember *not* to use email for the verification or someone could insert a bad key.')
= translate("The {} key for {} expired on {}.")
= translate('First, use your GoodCrypto server to delete the {} contact.')
= translate('Next, ask {} to create a new key and resend the message.')
= translate('Finally, verify the new fingerprint with {}. Do not use email for the verification or someone could insert a bad key.')
= translate("Keys do not match {}")
= translate("You received a message from {} that has a key which is different than the existing key in the {} database.")
= translate('First, contact {} and see if they have changed their key. If they have use your GoodCrypto server to delete their contact.')
= translate('Next, ask {} to create a new key and resend the message.')
= translate('Finally, verify the new fingerprint with {}. Do not use email for the verification or someone could insert a bad key.')
= translate('Of course, if they have not changed their key, then future messages with the bad key will continue to be saved as attachment and not decrypted.')
= translate('Message included a {} key for {} when the message was sent from {}.')
= translate('Message included multiple {} keys for "{}", but only a key from the sender, {}, can be imported.')
= translate('Unable to save the {} fingerprint in the database.')
= translate('The {} fingerprint for {} could not be saved.')
= translate('Forward this email message to your system or mail administrator immediately.')
"""

# mail/models.py
ENABLE_DEBUGGING_FIELD = translate('Enable diagnostic logs?')
ENABLE_DEBUGGING_HELP = translate('Activate logs to help debug unexpected behavior.')
"""
= translate('Name')
= translate('Name of the encryption software (e.g., GPG).')
= translate('Active?')
= translate('Is encryption software installed and available?')
= translate('Classname')
= translate("Leave blank unless you are using encryption software not supplied by GoodCrypto. See GoodCrypto's OCE docs for more details.")
= translate('encryption software')
= translate('encryption software')
= translate("Email address")
= translate('Email')
= translate('Email address of someone that uses encryption software.')
= translate('User name')
= translate('Printable name for the user. It is not required, but strongly recommended as encryption software often requires it.')
= translate('contact')
= translate('contacts')
= translate('Email address.')
= translate('Encryption software used by this contact.')
= translate('Fingerprint')
= translate("The fingerprint for the contact's public key.")
= translate('Verified?')
= translate('IMPORTANT: You should verify this fingerprint in a secure manner, not via email.')
= translate("contact's encryption software")
= translate("contacts' encryption software")
= translate('Days')
= translate('Weeks')
= translate('Months')
= translate('Years')
= translate('Encryption software used by a contact.')
= translate('Passcode')
= translate('Secret passcode, also known as a passphrase, used with this encryption software. It is recommended that you allow GoodCrypto to create the passcode because it should be long and difficult to remember.')
= translate('Auto generate?')
= translate('Add a check mark if you want GoodCrypto to generate a private passcode.')   
= translate('Expires in')
= translate('The quantity of time the key is valid. If set to 0, it never expires which is not recommended.')
= translate('The unit of time the key is valid.')
= translate('Last notified')
= translate('Last date a notice about this key was sent to the user.')
= translate('passcode')
= translate('passcodes')
= translate('Domain')
= translate("The domain managed by GoodCrypto.")
= translate('Auto exchange keys')
= translate("Automatically exchange keys and always include the sender's key in the header.")
= translate('Validation code')
= translate('A secret code added to all decrypted messages so you have increased confidence the message was decrypted by GoodCrypto.')
= translate('Accept self signed certs')
= translate('Recognize self signed certificates.')
= translate('Create private keys')
= translate("Generate private keys for users who don't have any keys automatically.")
= translate('Days between key alerts')
= translate("GoodCrypto sends alerts about errors with keys. How many days between notices would you like to users to receive those notices?.")
= translate('Require signature')
= translate("If you require a signature, then all outbound encrypted mail will include the sender's encrypted signature.")
= translate('Filter HTML')
= translate("GoodCrypto can remove HTML that may harm your system.")
= translate('Encrypt entire message')
= translate("Select this option if you want the entire message, not just the body and attachments, encrypted. You should only use this if you know your only exchange encrypted mail with contacts support the special 'EncryptedContentType'.")
= translate('Subject for encrypted messages')
= translate("If you opt to encrypt the entire messages, then whatever you enter in this field will be the subject for your encrypted message.")
= translate('Max size of a message')
= translate('The maximum length, in Megabytes, of messages, including attachments, accepted. This helps prevent your mail system from being DOSed.')
= translate('Use US standards')
= translate("Use the standards supported by US government. We strongly recommend you set this to False.")
= translate('options')
"""

# mail/sync_databases.py
MISMATCHED_PASSPHRASES = translate("{}'s passphrase does not match {}'s key.")
UNABLE_TO_CREATE_KEY = translate('Unable to create a private {} key.')
WRONG_DOMAIN = translate('{} does not use the {} domain so unable to create a private key.')

# mail/views.py
NO_FINGERPRINT = translate('No fingerprint defined')
VERIFIED = translate('Verified')
NOT_VERIFIED = translate('Not verified')
NO_PUBLIC_KEY = translate('No public key defined')
PUBLIC_KEY_FILE_TOO_LONG = translate('The public key file is too long.')
PUBLIC_KEY_IMPORTED = translate('{} public key(s) imported.')
IMPORT_NOT_PERMITTED = translate('You may not import a public key for {}')
PUBLIC_KEY_EXISTS = translate('A key already exists for {}. Delete the key and then try importing.')
IMPORTED_KEYS = translate('Imported public key:')
STATUS_PREFIX = translate('Result:')
FINGERPRINT_WARNING = translate('Warning:')
MISMATCHED_FINGERPRINT = translate('Fingerprints did not match')

