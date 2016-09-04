'''
    Send notices from the GoodCrypto Server daemon.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-01-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from email.utils import formataddr
from traceback import format_exc

from goodcrypto.mail.constants import DOMAIN_USER, TAG_ERROR, TAG_PREFIX, TAG_WARNING
from goodcrypto.mail.i18n_constants import SERIOUS_ERROR_PREFIX
from goodcrypto.mail.internal_settings import get_domain
from goodcrypto.mail.message.inspect_utils import get_hashcode
from goodcrypto.mail.message.metadata import is_metadata_address
from goodcrypto.mail.options import goodcrypto_server_url, require_key_verified
from goodcrypto.mail.utils import get_admin_email, send_message, write_message
from goodcrypto.mail.utils.dirs import get_notices_directory
from goodcrypto.oce.utils import format_fingerprint
from goodcrypto.utils import get_email, i18n, parse_domain
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr.message import prep_mime_message


USE_SMTP = False

#  Notices From: address.
NOTICE_FROM_NAME = 'GoodCrypto Private Server Daemon'
NOTICE_FROM_EMAIL = 'mailer-daemon@{}'.format(get_domain())
NOTICE_FROM_ADDRESS = (NOTICE_FROM_NAME, NOTICE_FROM_EMAIL)
NOTICE_FROM_ADDR = formataddr(NOTICE_FROM_ADDRESS)

# shared details
CREDENTIALS_SUBJECT = i18n('GoodCrypto - Save these credentials')
VERIFY_HEADER = i18n('To verify a message was received privately:')

_log = None


def send_user_credentials(email, password):
    '''
        Email the user with their credentials to access private website.

        >>> send_user_credentials('edward@goodcrypto.local', 'test-password')
    '''

    subject = CREDENTIALS_SUBJECT
    paragraph1 = i18n(
        'Your mail administrator has installed GoodCrypto to protect your email.')

    paragraph2 = '{} {}'.format(
        i18n('You will see a GoodCrypto tag on every message.'),
        _get_paragraph_about_goodcrypto())

    url = goodcrypto_server_url()

    # if we know the private url
    if url is not None and len(url.strip()) > 0:
        verify_private_msg = VERIFY_HEADER
        username = i18n('   Username: {email}'.format(email=email))
        pwd = i18n('   Password: {password}'.format(password=password))
        simply_click = i18n('Simply click on the link in the tag.')
        sign_in = i18n('When you are prompted to sign in to your GoodCrypto private server, use:')
        paragraph3 = '{} {} {}\n{}\n{}\n'.format(verify_private_msg, simply_click, sign_in, username, pwd)
    else:
        paragraph3 = _get_credential_paragraph(email, password)

    body = '{paragraph1}\n\n{paragraph2}\n\n{paragraph3}\n'.format(
        paragraph1=paragraph1, paragraph2=paragraph2, paragraph3=paragraph3)
    notify_user(email, subject, body)

def send_admin_credentials(admin, password, domain):
    '''
        Email the admin password.

        >>> send_admin_credentials('edward@goodcrypto.local', 'test-password', 'goodcrypto.local')
        True
    '''

    try:
        result_ok = False

        subject = CREDENTIALS_SUBJECT
        paragraph1 = i18n('You have successfully configured GoodCrypto to protect {domain}.'.format(domain=domain))

        paragraph2 = '{} {}'.format(
            i18n('Every message will have a GoodCrypto tag.'),
            _get_paragraph_about_goodcrypto())

        paragraph3 = _get_credential_paragraph(admin, password)

        paragraph4 = i18n('To make it easier for users to verify private messages, in the Mail options you can include the url for your GoodCrypto private server. ' +
                     'Then private messages will include a simply verification link.')

        body = '{paragraph1}\n\n{paragraph2}\n\n{paragraph3}\n\n{paragraph4}\n'.format(
            paragraph1=paragraph1, paragraph2=paragraph2, paragraph3=paragraph3, paragraph4=paragraph4)

        result_ok = notify_user(admin, subject, body)
        if result_ok:
            log_message('notified {} about new admin account'.format(admin))
        else:
            log_message('unable to notify user about account; see notices.log for details')
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for more details')

    return result_ok

def notify_user_key_ready(email):
    '''
        Notify the user their crypto key is ready.

        >>> notify_user_key_ready('edward@goodcrypto.local')
    '''

    subject = i18n('GoodCrypto - You can now receive private mail')

    body = i18n('Other people can now send you mail privately. GoodCrypto will handle the details automatically for you.')
    body += ' '
    body += i18n(
        "With people who don't have GoodCrypto, follow these instructions: https://goodcrypto.com/qna/knowledge-base/export-public-key.\n")
    notify_user(email, subject, body)

def notify_new_key_arrived(to_user, id_fingerprint_pairs):
    '''
        Notify user a new key arrived.

        >>> notify_new_key_arrived(None, None)
    '''

    if to_user is None or id_fingerprint_pairs is None:
        pass
    else:
        # use the first email address from the imported key
        email, __ = id_fingerprint_pairs[0]

        header = i18n("To be safe, verify their key now by following these instructions:")
        tip = i18n("https://goodcrypto.com/qna/knowledge-base/user-verify-key")
        regular_notice = True
        if require_key_verified():
            regular_notice = False
            if is_metadata_address(email):
                domain = parse_domain(email)
                subject = i18n('Mail to {domain} cannot be sent until you verify the metadata key'.format(domain=domain))
                body = i18n("You received a public key for the email address(es) below. No one can send mail to users with this domain until you verify the key and update the database if it's okay. Otherwise, any mail sent to {domain} will be returned to the sender.".format(domain)),
            else:
                subject = i18n('Mail to {email} cannot be sent until you verify their key'.format(email=email))
                body = i18n("You received a public key for the email address(es) below. You cannot send mail until you check with the sender to verify the key and update the database if it's okay. Otherwise, any mail you send to this user will be returned to you."),
        else:
            if is_metadata_address(email):
                domain = parse_domain(email)
                subject = 'Metadata protection to {domain} is now ready'.format(domain=domain)
                body = 'Unless you disable metadata protection, all mail to {domain} will now have both metadata and content encrypted.'.format(
                        domain=domain)
            else:
                subject = i18n('Mail to {email} is now private'.format(email=email))
                body = i18n(
                  "The content of all messages to {email} will be protected.  ".format(email=email))
        body_text = "{}\n\n{} {}\n".format(
            body,
            header,
            tip)

        for (user_id, fingerprint) in id_fingerprint_pairs:
            body_text += "    {}: {}".format(user_id, format_fingerprint(fingerprint))

        if regular_notice:
            prefix = TAG_PREFIX
        else:
            prefix = TAG_WARNING

        notify_user(to_user, '{} - {}'.format(prefix, str(subject)), body_text)

def report_key_creation_timedout(email):
    '''
        Report that creating a key timed out.

        >>> report_key_creation_timedout('chelsea@goodcrypto.local')
    '''

    subject = i18n("Creating your private key timed out.")
    notify_user(email,
       i18n("GoodCrypto - {}".format(subject)),
       i18n("Your GoodCrypto server is probably very buzy. You might wait a 5-10 minutes and then try sending a message again. If that doesn't work, then ask your mail administrator to create your key manually."))

def report_key_creation_error(email):
    '''
        Report that an error occurred creating a key.

        >>> report_key_creation_error('chelsea@goodcrypto.local')
    '''

    subject = i18n('GoodCrypto - Error while creating a private key for you')
    body = '{}.\n{}'.format(
        subject,
       i18n("Contact your mail administrator and ask them to create it for you manually."))
    notify_user(email, subject, body)

def report_metadata_key_creation_error(email):
    '''
        Report that an error occurred creating a metadata key.

        >>> report_metadata_key_creation_error('chelsea@goodcrypto.local')
    '''

    subject = i18n('GoodCrypto - Error while creating a private metadata key')
    body = '{}.\n{}'.format(
        subject,
       i18n("Metadata cannot be protected until you create a private key for {}@{}".format(
           DOMAIN_USER, get_domain())))
    notify_user(email, subject, body)

def report_error_creating_login(email, error_message):
    ''' Report an error happened while creating login credentials.

        >>> report_error_creating_login('chelsea@goodcrypto.local', 'Unable to create user')
    '''

    details = i18n('Ask your mail administrator to add a user for your email account manually.')
    subject = 'GoodCrypto - {}'.format(error_message)
    body = '{}\n{}'.format(error_message, details)
    notify_user(email, subject, body)

def report_mismatched_password(email, encryption_name):
    ''' Report password doesn't match on in keyring.

        >>> report_mismatched_password('chelsea@goodcrypto.local', 'GPG')
    '''

    MISMATCHED_PASSPHRASES = i18n("{email}'s passphrase does not match {encryption}'s key.".format(
      email=email, encryption=encryption_name))
    notify_user(email, MISMATCHED_PASSPHRASES, MISMATCHED_PASSPHRASES)

def report_bad_bundled_encrypted_message(to_domain, bundled_messages):
    ''' Report unable to create an encrypted bundled message.
    '''

    subject = i18n('{} - Unable to send messages to {domain}'.format(TAG_WARNING, domain=to_domain))

    line1 = i18n('Your GoodCrypto private server tried to send messages to {domain} using the {user} keys. It was unable to do so.'.format(
        domain=to_domain, user=DOMAIN_USER))
    line2 = i18n("You should verify that you have a contact and key for both your domain and {domain}'s domain.".format(domain=to_domain))
    line3 = i18n("You can disable bundling and padding messages, but it means that your users will be easier to track.")

    # leave a trailing space in case we add a 4th line
    admin_message = '{}\n\n{}\n\n{} '.format(line1, line2, line3)

    if len(bundled_messages) > 0:
        line4 = i18n("Also, {} messages to {domain} will be lost if you disable bundling before resolving the current problem.".format(
            len(bundled_messages), domain=to_domain))
        admin_message += line4

    admin = get_admin_email()
    notify_user(admin, subject, admin_message)
    log_message('sent bad encrypted bundle message notice to {}\n{}'.format(admin, admin_message))

def report_replacement_key(to_user, from_user, encryption_name, id_fingerprint_pairs, crypto_message):
    '''
        Report that the key in the header doesn't match an existing key.

        >>> report_replacement_key('chelsea@goodcrypto.local', 'joseph@goodcrypto.remote', 'GPG', None, None)
        'GoodCrypto Warning - A new key arrived for joseph@goodcrypto.remote that is not the same as the current key'
    '''

    subject = i18n('{warning} - A new key arrived for {email} that is not the same as the current key'.format(
        warning=TAG_WARNING, email=from_user))
    tag = subject

    message_lines = []

    message_lines.append(i18n(
      "Contact the sender and verify if they've changed their {encryption} key.".format(encryption=encryption_name)))
    message_lines.append('\n\n')

    message_lines.append(i18n('If they *do* have a new key, then use your GoodCrypto server to delete the contact and ask them to resend the message.'))
    message_lines.append('\n\n')

    message_lines.append(i18n(
      'If the sender has *not* replaced their key, then reconfirm the fingerprint in your GoodCrypto server.'))
    message_lines.append('\n\n')

    message_lines.append(i18n(
      'Remember, never use email for the verification of fingerprints and header keys.'))
    message_lines.append('\n\n')

    if id_fingerprint_pairs is not None:
        message_lines.append(i18n('Details about the new key:\n'))
        for (user_id, fingerprint) in id_fingerprint_pairs:
            message_lines.append('{}\n'.format(i18n('    user: {email}'.format(email=user_id))))
            message_lines.append('{}\n\n'.format(i18n('    fingerprint: {fingerprint}'.format(
                fingerprint=fingerprint))))

    _notify_recipient(subject, message_lines, crypto_message)

    return tag

def report_missing_key(to_user, from_user, key_matches, id_fingerprint_pairs, crypto_message):
    '''
        Report a key is missing for the user.

        >>> report_missing_key('chelsea@goodcrypto.local', 'joseph@goodcrypto.remote', True, None, None)
        'GoodCrypto Warning - No public key for joseph@goodcrypto.remote'
    '''
    subject = i18n('{warning} - No public key for {email}'.format(
        warning=TAG_WARNING, email=from_user))
    tag = subject

    message_lines = []
    if key_matches:
        message_lines.append(i18n('A message arrived with a key that matches a known fingerprint in your GoodCrypto server database, but that key is missing in the keyring or needs to be verified before it can be used.'))
    else:
        message_lines.append(i18n('A message arrived with a key that does not match the fingerprint in your GoodCrypto server and the key is missing.'))
    message_lines.append('\n\n')

    message_lines.append('{}\n\n'.format(i18n('First, contact the user and verify that the following fingerprint is correct:')))
    if id_fingerprint_pairs is not None:
        for (user_id, fingerprint) in id_fingerprint_pairs:
            message_lines.append('{}\n'.format(i18n('    user: {email}'.format(email=user_id))))
            message_lines.append('{}\n\n'.format(i18n('    fingerprint: {fingerprint}'.format(
                fingerprint=fingerprint))))
    message_lines.append(i18n(
      'Next, use your GoodCrypto private server to delete the {email} contact.'.format(email=from_user)))
    message_lines.append(i18n('Next, ask {email} to resend the message.'.format(email=from_user)))
    message_lines.append(i18n(
      'Finally, verify the new fingerprint with {email}. Remember not to use email for the verification or someone could insert a bad key.'.format(
          email=from_user)))

    _notify_recipient(subject, message_lines, crypto_message)

    return tag

def report_expired_key(to_user, from_user, encryption_name, expiration, crypto_message):
    '''
        Report a key expired.

        >>> report_expired_key('chelsea@goodcrypto.local', 'joseph@goodcrypto.remote', 'GPG', None, None)
        'The GPG key for joseph@goodcrypto.remote expired on None.'
    '''

    tag = i18n("The {encryption} key for {email} expired on {date}.".format(
        encryption=encryption_name, email=from_user, date=expiration))
    subject = i18n('{warning} - Received a message from {email} with a key that expired on {date}'.format(
      warning=TAG_WARNING, email=from_user, date=expiration))

    message_lines = []
    message_lines.append(i18n(
      'First, use your GoodCrypto server to delete the {email} contact.'.format(email=from_user)))
    message_lines.append(i18n('Next, ask {email} to create a new key and resend the message.'.format(email=from_user)))
    message_lines.append(i18n(
      'Finally, verify the new fingerprint with {email}. Do not use email for the verification or someone could insert a bad key.'.format(
          email=from_user)))

    _notify_recipient(subject, message_lines, crypto_message)

    return tag

def report_mismatched_keys(to_user, from_user, encryption_name, crypto_message):
    '''
        Report the keys don't match.

        >>> report_mismatched_keys('chelsea@goodcrypto.local', 'joseph@goodcrypto.remote', 'GPG', None)
        'GoodCrypto Warning - Keys do not match joseph@goodcrypto.remote'
    '''
    subject = i18n("{warning} - Keys do not match {email}".format(
      warning=TAG_WARNING, email=from_user))
    tag = subject

    message_lines = []
    message_lines.append(i18n(
       "You received a message from {email} that has a key which is different than the existing key in the {encryption} database.".format(
           email=from_user, encryption=encryption_name)))
    message_lines.append('\n\n')

    message_lines.append(i18n(
      'First, contact {email} and see if they have changed their key. If they have use your GoodCrypto server to delete their contact.'.format(email=from_user)))
    message_lines.append(
        i18n('Next, ask {email} to create a new key and resend the message.'.format(email=from_user)))
    message_lines.append(i18n(
      'Finally, verify the new fingerprint with {email}. Do not use email for the verification or someone could insert a bad key.'.format(email=from_user)))
    message_lines.append('\n\n')

    message_lines.append(i18n(
      'Of course, if they have not changed their key, then future messages with the bad key will continue to be saved as attachment and not decrypted.'))

    _notify_recipient(subject, message_lines, crypto_message)

    return tag

def report_no_matching_fingerprint_on_keyserver(to_user, fingerprint, encryption_name):
    '''
        Report unable to find a matching fingerprint on any of the active keyservers.

        >>> report_no_matching_fingerprint_on_keyserver('chelsea@goodcrypto.local', '12345', 'GPG')
    '''

    subject = i18n("Unable to find key that matches the fingerprint.")
    notify_user(to_user,
       i18n("GoodCrypto - {}".format(subject)),
       i18n("Your GoodCrypto server searched the active keyservers and was unable to find a {} key that matches {}.".format(
           encryption_name, fingerprint)))

def report_no_key_on_keyserver(to_user, email, encryption_name):
    '''
        Report unable to find a key for the email on any of the active keyservers.

        >>> report_no_key_on_keyserver('chelsea@goodcrypto.local', 'joseph@goodcrypto.remote', 'GPG')
    '''

    subject = i18n("Unable to find key for {}".format(email))
    notify_user(to_user,
       i18n("GoodCrypto - {}".format(subject)),
       i18n("Your GoodCrypto server searched the active keyservers and was unable to find a {} key. All messages to {} will be sent in plain text until they start using GoodCrypto or you import their key.".format(
             encryption_name, email)))

def report_error_verifying_key(to_user, from_user, encryption_name, crypto_message):
    '''
        Report the key comparison got an error during comparison.

        >>> report_error_verifying_key('chelsea@goodcrypto.local', 'joseph@goodcrypto.remote', 'GPG', None)
        'GoodCrypto Warning - Unable to verify fingerprint for joseph@goodcrypto.remote'
    '''
    subject = i18n("{warning} - Unable to verify fingerprint for {email}".format(
       warning=TAG_WARNING, email=from_user))
    tag = subject

    message_lines = []
    message_lines.append(
      i18n('The message arrived with a key, but unable to compare the {encryption} fingerprint.'.format(encryption=encryption_name)))
    message_lines.append(i18n('It is possible the database was just busy, but if this happens again please report it to your mail administrator immediately.'))

    _notify_recipient(subject, message_lines, crypto_message)

    return tag

def report_bad_header_key(to_user, from_user, user_ids, encryption_name, crypto_message):
    '''
        Report the header's key doesn't match the sender.

        >>> user_ids = ['laura@goodcrypto.remote']
        >>> report_bad_header_key('chelsea@goodcrypto.local', 'joseph@goodcrypto.remote', user_ids, 'GPG', None)
        'The message included a GPG key for laura@goodcrypto.remote, but the message was sent from joseph@goodcrypto.remote.'
    '''
    subject = i18n("{warning} - Message contained a bad key in header".format(
        warning=TAG_WARNING))

    if len(user_ids) == 1:
        tag = i18n('The message included a {encryption} key for {email}, but the message was sent from {from_email}.'.format(
           encryption=encryption_name, email=user_ids[0], from_email=from_user))
    else:
        tag = i18n('The message included multiple {encryption} keys for "{ids}", but only a key from the sender, {email}, can be imported.'.format(
            encryption=encryption_name, ids=', '.join(user_ids), email=from_user))

    message_lines = []
    message_lines.append(tag)

    _notify_recipient(subject, message_lines, crypto_message)

    return tag


def report_db_error(to_user, from_user, encryption_name, crypto_message):
    '''
        Report a database error to the user.

        >>> report_db_error('chelsea@goodcrypto.local', 'joseph@goodcrypto.remote', 'GPG', None)
        'The GPG fingerprint for joseph@goodcrypto.remote could not be saved.'
    '''

    subject = i18n('{warning} - Unable to save the {encryption} fingerprint in the database.'.format(
        warning=TAG_WARNING, encryption=encryption_name))
    tag = i18n('The {encryption} fingerprint for {email} could not be saved.'.format(
                  encryption=encryption_name, email=from_user))

    message_lines = []
    message_lines.append(tag)
    message_lines.append('\n')
    message_lines.append(i18n('Forward the body of this email message to your system or mail administrator immediately.'))

    _notify_recipient(subject, message_lines, crypto_message)

    return tag

def report_unable_to_send_bundled_messages(exception):
    '''
        Report unable to send bundled messages.

        >>> report_unable_to_send_bundled_messages(None)
    '''

    subject = '{} - Unable to send bundled messages periodically'.format(TAG_ERROR)
    notify_user(get_admin_email(), subject, '{}\n\n{}'.format(subject, exception))
    record_exception()

def report_unable_to_decrypt(to_user, message):
    '''
        Report unable to decrypto message.

        >>> report_unable_to_decrypt('chelsea@goodcrypto.local', 'test')
    '''

    subject = i18n('{} Unable to decrypt message'.format(SERIOUS_ERROR_PREFIX))
    notify_user(to_user, subject, message)

def report_message_undeliverable(message, sender):
    ''' Report an unexpected error when delivering a message.

        >>> report_message_undeliverable('Serious error', None)
    '''

    subject = i18n('Error delivering message')
    if sender is not None:
        subject += ' '
        subject += i18n('from {sender}'.format(sender=sender))
    error_message = i18n(
      'An unexpected error was detected when trying to deliver the attached message.\n\n{}'.format(message))
    notify_user(get_admin_email(), subject, error_message)

def report_unexpected_ioerror():
    ''' Report an unexpected ioerror or exception.

        >>> report_unexpected_ioerror()
    '''

    subject = '{} - Serious unexpected exception'.format(TAG_ERROR)
    body = 'A serious, unexpected exception was detected while processing mail. If you contact support@goodcrypto.com, please include the Traceback.\n{}'.format(format_exc())
    notify_user(get_admin_email(), subject, body)
    record_exception()

def report_unexpected_named_error():
    ''' Report an unexpected named error.

        >>> report_unexpected_named_error()
    '''

    # hopefully our testing prevents this from ever occuring, but if not, we'd definitely like to know about it
    subject = '{} - Serious unexpected NameError'.format(TAG_ERROR)
    body = 'A serious, unexpected NameError was detected while processing mail. Please send the Traceback to support@goodcrypto.com\n{}'.format(format_exc())
    notify_user(get_admin_email(), subject, body)
    record_exception()

def notify_user(to_address, subject, text=None, attachment=None, filename=None):
    ''' Send a notice to the user.

        In honor of Noel David Torres, Spanish translator of Tor.
        >>> notify_user('noel@goodcrypto.local', 'test notice', 'test message')
        True
        >>> notify_user(None, 'test notice', 'test message')
        False
        >>> notify_user('noel@goodcrypto.local', None, 'test message')
        True
        >>> notify_user(None, None)
        False
    '''

    message = None
    try:
        # all messages to the metadata user should get routed to the admin
        if is_metadata_address(to_address):
            to_address = get_admin_email()

        message = create_notice_message(
            to_address, subject, text=text, attachment=attachment, filename=filename)
        if message is None:
            result_ok = False
            log_message('unable to create notice to {} about {}'.format(to_address, subject))
        else:
            log_message('starting to send notice to {} about {}'.format(to_address, subject))

            from_addr = NOTICE_FROM_EMAIL
            to_addr = get_email(to_address)

            if to_addr is None or message is None:
                result_ok = False
                log_message('no to address to send notice')
            else:
                result_ok = send_message(from_addr, to_addr, message)
                log_message('sent notice to {}'.format(to_address))
    except:
        result_ok = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    if not result_ok and message is not None:
        _save(message)

    log_message('final result: {}'.format(result_ok))

    return result_ok


def create_notice_message(to_address, subject, text=None, attachment=None, filename=None):
    '''
        Creates a notice message.

        >>> # In honor of Sukhbir Singh, developed and maintains TorBirdy.
        >>> message = create_notice_message('sukhbir@goodcrypto.remote', 'test notice')
        >>> 'To: sukhbir@goodcrypto.remote' in message
        True
        >>> 'From: GoodCrypto Private Server Daemon <mailer-daemon' in message
        True
        >>> 'Subject: test notice' in message
        True
    '''

    message = prep_mime_message(
      NOTICE_FROM_ADDR, to_address, subject, text=text, attachment=attachment, filename=filename)

    return message


def _notify_recipient(to_user, subject, body, crypto_message=None):
    '''
        Send a message to the recipient (internal use only).
    '''

    if to_user is None or body is None:
        log_message('unable to send notice because missing data')
        log_message('recipient_to_notify: {}'.format(to_user))
        log_message('subject: {}'.format(subject))
        log_message('body: {}'.format(body))
    else:
        log_message('notifying {} about "{}"'.format(to_user, subject))
        if crypto_message is None:
            notify_user(to_user, subject, body)
        else:
            ORIGINAL_MESSAGE_ATTACHED = ' The original message is attached.'
            if type(body) is list:
                body = ' '.join(body)
            body += '\n\n{}\n'.format(ORIGINAL_MESSAGE_ATTACHED)
            log_message(' including original message as an attachment')
            attachment = crypto_message.get_email_message().to_string()
            filename = '{}.txt'.format(get_hashcode(attachment))
            notify_user(to_user, subject, body, attachment=attachment, filename=filename)

def _save(message):
    ''' Save the notice (internal use only).

        In honor of Rob Thomas, Tor advocate.
        >>> notice_filename = _save(create_notice_message('rob@goodcrypto.remote', 'test notice'))
        >>> os.remove(os.path.join(get_notices_directory(), notice_filename))
        >>> _save(None)
    '''

    try:
        if message is None:
            notice_filename = None
            log_message('no notice to save')
        else:
            log_message('saving: {}'.format(message))
            notice_filename = write_message(get_notices_directory(), message)
    except:
        notice_filename = None
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        record_exception()

    return notice_filename


def log_message(message):
    '''
        Record debugging messages.

        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.utils.notices.log'))
        True
    '''

    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

def _get_credential_paragraph(email, password):
    '''
        Get the paragraph with the credentials.

        >>> paragraph = _get_credential_paragraph('edward@goodcrypto.local', 'test-password')
        >>> len(paragraph) > 0
        True
    '''

    verify_private_msg = VERIFY_HEADER
    username = i18n('   Username: {email}'.format(email=email))
    pwd = i18n('   Password: {password}'.format(password=password))

    sign_in = i18n('1) Go to your GoodCrypto private server. When you are prompted, use:')
    click_mail = i18n('2) Click "Mail"')
    click_verify = i18n('3) Click "Verify"')
    enter_code = i18n('4) Cut and paste the verification code from the message.')
    paragraph = '{verify}\n   {sign_in}\n   {username}\n   {pwd}\n   {click_mail}\n   {click_verify}\n   {code}\n'.format(
       verify=verify_private_msg, sign_in=sign_in, username=username, pwd=pwd,
       click_mail=click_mail, click_verify=click_verify, code=enter_code)

    return paragraph

def _get_paragraph_about_goodcrypto():
    '''
        Get paragraph with details about how GoodCrypto works.

        >>> paragraph = _get_paragraph_about_goodcrypto()
        >>> len(paragraph) > 0
        True
    '''

    # do *not* remove the trailing white space inside the ''
    paragraph = i18n(
        'The tag tells you if the message arrived privately. ' +
        "Although it's not likely, that tag could be faked. " +
        'So each private message also includes a verification code.')

    return paragraph


