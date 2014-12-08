'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail import contacts, crypto_software, international_strings
from goodcrypto.mail.international_strings import SERIOUS_ERROR_PREFIX
from goodcrypto.mail.message import mime_constants, utils
from goodcrypto.mail.message.constants import PUBLIC_KEY_HEADER
from goodcrypto.mail.message.notices import notify_user
from goodcrypto.mail.message.utils import get_hashcode
from goodcrypto.mail.utils.exception_log import ExceptionLog
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import parse_address, format_fingerprint
from goodcrypto.utils.internationalize import translate


class HeaderKeys(object):
    '''
        Manage keys from a message's header.
        
        It's important that we only import a key if it's new. If it's
        not new, then we must be careful deciding whether to use the key or not.
        
        The following table shows the possible conditions that we must handle. It assumes 
        the message's header key is never missing, otherwise we wouldn't call this class.
        
        Received key in header so check db and crypto package.
        | saved in db  | crypto package | action    | unit test                             |
        |--------------|----------------|-----------|---------------------------------------|
        | match        | match          | use       | test_all_matching_keys                |
        | match        | no match       | drop      | test_db_fingerprint_bad_crypto_key    |
        | match        | missing        | drop      | test_db_fingerprint_no_crypto_key     |
        | no match     | match          | drop      | test_bad_fingerprint_matching_crypto  |
        | no match     | no match       | drop      | test_bad_fingerprint_bad_crypto       |
        | no match     | missing        | drop      | test_bad_fingerprint_missing_crypto   |
        | missing      | match          | add to db | test_crypto_key_no_db_fingerprint     |
        | missing      | no match       | drop      | test_bad_crypto_key_no_db_fingerprint |
        | missing      | missing        | import    | test_no_existing_keys                 |
    '''
    
    DEBUGGING = False
    
    def __init__(self):
        '''
            >>> header_keys = HeaderKeys()
            >>> header_keys != None
            True
        '''
        
        self._log = LogFile()
        self._recipient = None

    def manage_keys_in_header(self, msg_recipient, from_user, crypto_message):
        '''
            Manage all the public keys in the message's header.
        '''
        try:
            self._recipient = msg_recipient

            name, address = parse_address(from_user)
            if address is None or crypto_message is None or crypto_message.get_email_message() is None:
                self._log.write('missing data so cannot import key')
                self._log.write('   from user: {}'.format(from_user))
                self._log.write('   address: {}'.format(address))
                self._log.write('   crypto message: {}'.format(crypto_message))
                if crypto_message is not None: self._log.write('   email message: {}'.format(crypto_message.get_email_message()))
            else:
                accepted_crypto_packages = self._import_accepted_crypto_software(from_user, crypto_message)
                if accepted_crypto_packages is None or len(accepted_crypto_packages) <= 0:
                    self._log.write("checking for default key for {} <{}>".format(name, address))
                    tag, dropped = self._manage_key_header(address, crypto_message, 
                       CryptoFactory.get_default_encryption_name(), PUBLIC_KEY_HEADER)
                else:
                    self._log.write("checking for {} keys".format(accepted_crypto_packages))
                    for encryption_name in accepted_crypto_packages:
                        # see if there's a the key block for this encryption program
                        header_name = utils.get_public_key_header_name(encryption_name)
                        key_block = utils.get_multientry_header(
                          crypto_message.get_email_message().get_message(), header_name)
                        # see if there's a plain key block
                        if ((key_block is None or len(key_block) <= 0) and 
                            len(accepted_crypto_packages) == 1):
                            self._log.write("no {} public key in header so trying generic header".format(encryption_name))
                            key_block = utils.get_multientry_header(
                              crypto_message.get_email_message().get_message(), PUBLIC_KEY_HEADER)

                        tag, dropped = self._manage_key_header(
                          address, crypto_message, encryption_name, key_block)
                        if dropped:
                            break
        except:
            self._log.write(format_exc())
            ExceptionLog.log_message(format_exc())
            crypto_message.add_tag_once(translate('An unexpected error ocurred while processing this message'))
    
    
    def _manage_key_header(self, from_user, crypto_message, encryption_name, key_block):
        '''
            Manage a key in the header for the encryption software.
        '''
    
        tag = None
        dropped = False
        
        try:
            if key_block == None or len(key_block) <= 0:
                self._log.write("no {} public key in header".format(encryption_name))
            else:
                if self.DEBUGGING:
                    self._log.write("{} key from message:\n{}".format(encryption_name, key_block))

                tag, dropped = self._manage_public_key(from_user, crypto_message, encryption_name, key_block)

                if dropped:
                    crypto_message.set_dropped(True)
                if tag is not None and len(tag.strip()) > 0:
                    crypto_message.add_tag_once(tag)
        except:
            ExceptionLog.log_message(format_exc())
            
        return tag, dropped
    
    def _manage_public_key(self, from_user, crypto_message, encryption_name, key_block):
        '''
            Manage a public key for the encryption software.
        '''
    
        tag = None
        dropped = False
        user_ids = None

        key_crypto = KeyFactory.get_crypto(
          encryption_name, crypto_software.get_key_classname(encryption_name))
        if key_crypto is None:
            self._log.write('no key crypto for {}'.format(encryption_name))
        else:
            user_ids = key_crypto.get_user_ids_from_key(key_block)

        if user_ids is None:
            self._log.write('no user keys in key block')
        else:
            self._log.write("key block includes key for {}".format(user_ids))
            if len(user_ids) > 0 and from_user in user_ids:
                #  see if we already have a key for this ID or if it has expired
                saved_fingerprint, verified = contacts.get_fingerprint(from_user, encryption_name)
                crypto_fingerprint, expiration = key_crypto.get_fingerprint(from_user)
                
                if HeaderKeys.DEBUGGING:
                    self._log.write("{} {} saved fingerprint {}".format(from_user, encryption_name, saved_fingerprint))
                    self._log.write("{} {} crypto fingerprint {} expires {}".format(
                        from_user, encryption_name, crypto_fingerprint, expiration))
        
                if crypto_fingerprint is None:
                    if saved_fingerprint is None:
                        tag = self._import_new_key(from_user, encryption_name, key_block, user_ids)
                    else:
                        dropped = crypto_message.get_email_message().is_probably_pgp()
                        key_ok, new_fingerprint = self._key_matches(
                            encryption_name, key_block, saved_fingerprint)
                        tag = self._report_missing_key(from_user, key_ok, new_fingerprint, crypto_message)
                        self._log.write(tag)
                else:
                    if saved_fingerprint is None:
                        # remember the fingerprint for the future
                        saved_fingerprint = crypto_fingerprint
        
                    if crypto_fingerprint == saved_fingerprint:
                        key_ok, new_fingerprint = self._key_matches(
                            encryption_name, key_block, crypto_fingerprint)
                        if key_ok:
                            if key_crypto.fingerprint_expired(expiration):
                                dropped = crypto_message.get_email_message().is_probably_pgp()
                                tag = self._report_expired_key(from_user, encryption_name, expiration, crypto_message)
                            else:
                                self._log.write('  same fingerprint: {}'.format(saved_fingerprint))
                                # warn user if unable to save the fingerprint, but proceed
                                if not contacts.update_fingerprint(from_user, encryption_name, crypto_fingerprint):
                                    tag = self._report_db_error(from_user, encryption_name)
                        else:
                            if self.DEBUGGING:
                                self._log.write('{} key block\n{}'.format(
                                  from_user, key_crypto.export_public(from_user)))
                            dropped = crypto_message.get_email_message().is_probably_pgp()
                            tag = self._report_replacement_key(from_user, encryption_name, crypto_message)
                            self._log.write(tag)
        
                    else:
                        dropped = crypto_message.get_email_message().is_probably_pgp()
                        tag = self._report_mismatched_keys(from_user, encryption_name, crypto_message)
                        self._log.write(tag)
            else:
                if len(user_ids) <= 0:
                    self._log.write('no importable keys found\n{}'.format(key_block))
                else:
                    tag = self._report_bad_header_key(from_user, user_ids, encryption_name, crypto_message)
                    dropped = crypto_message.get_email_message().is_probably_pgp()
                    
        self._log.write('tag: {}'.format(tag))
        self._log.write('dropped: {}'.format(dropped))
        
        return tag, dropped

    def _import_new_key(self, from_user, encryption_name, key_block, user_ids):
        '''
            Import a new key.
        '''
    
        def import_key_add_contacts():
            
            result_ok = False

            key_crypto = KeyFactory.get_crypto(
              encryption_name, crypto_software.get_key_classname(encryption_name))
            fingerprints = key_crypto.import_public(key_block)
            if len(fingerprints) > 0:
                imported_fingerprint = fingerprints[0]
                tag = "\n{}{}\n    {}: {}".format(
                    international_strings.NEW_KEY_TAGLINE, 
                    international_strings.VERIFY_NEW_KEY_TAGLINE,
                    from_user, format_fingerprint(imported_fingerprint))
                self._log.write('imported key successfully: {}'.format(imported_fingerprint))
                self._notify_recipient(international_strings.NEW_KEY_TAGLINE.strip(':'), tag)
                
                result_ok = True
                self._log.write('adding/updating contacts for user ids')
                for user_id in user_ids:
                    if user_id is not None and len(user_id.strip()) > 0:
                        self._log.write(
                            'adding contact for {} with {} fingerprint'.format(user_id, imported_fingerprint))
                        contact = contacts.add(user_id, encryption_name, fingerprint=imported_fingerprint)
                        if contact is None:
                            result_ok = False
                            self._log.write('unable to add contact')
                        else:
                            self._log.write('successfully added contact')

            return result_ok, tag

        tag = None
        result_ok = False
        if encryption_name is None:
            encryption_name = ''

        try:
            self._log.write("starting to import new {} key for {}".format(encryption_name, from_user))
            if from_user is None or len(encryption_name) == 0 or user_ids is None:
                self._log.write('missing key data so unable to import new key')
            else:
                key_crypto = KeyFactory.get_crypto(
                    encryption_name, crypto_software.get_key_classname(encryption_name))

                # make sure that we don't have a key for any of the user ids included with this key
                result_ok = True
                for user_id in user_ids:
                    crypto_fingerprint, expiration = key_crypto.get_fingerprint(user_id)
                    if crypto_fingerprint is not None:
                        result_ok = False
                        self._log.write('key exists for {} so unable to import key for {}'.format(user_id, from_user))
                        break

                if result_ok:
                    result_ok, tag = import_key_add_contacts()
                    self._log.write('result after adding keys and contacts: {}'.format(result_ok))

            if not result_ok:
                tag = '{} {}\n'.format(SERIOUS_ERROR_PREFIX, translate('Could not import new {} key for {}'.format(encryption_name, from_user)))
                self._log.write('WARNING: Unable to import new public key for {}'.format(from_user))
        except:
            self._log.write(format_exc())
            ExceptionLog.log_message(format_exc())
            tag = '{} {}\n'.format(SERIOUS_ERROR_PREFIX, translate('Could not import new {} key for {}'.format(encryption_name, from_user)))
    
        self._log.write('import new key ok: {}'.format(result_ok))
    
        return tag
    
    def _key_matches(self, encryption_name, key_block, old_fingerprint):
        ''' 
            Does the new key's fingerprint match the old fingerprint?
        '''
    
        matches = False
        new_fingerprint = None
        
        if encryption_name is None or key_block is None:
            self._log.write('unable to compare fingerprints because basic data is missing')
        else:
            try:
                key_crypto = KeyFactory.get_crypto(
                  encryption_name, crypto_software.get_key_classname(encryption_name))
                fingerprints = key_crypto.import_temporarily(key_block)
                if fingerprints and len(fingerprints) > 0:
                    new_fingerprint = fingerprints[0]
                    if new_fingerprint is None or old_fingerprint is None:
                        matches = False
                        self._log.write('unable to get fingerprint from key block')
                    else:
                        matches = new_fingerprint == old_fingerprint.replace(' ', '')
                else:
                    self._log.write('unable to get fingerprint for key block\n{}'.format(key_block))

                if self.DEBUGGING:
                    self._log.write('key block fingerprint: {}'.format(new_fingerprint))
                    self._log.write('existing fingerprint : {}'.format(old_fingerprint))
            except:
                self._log.write(format_exc())
                ExceptionLog.log_message(format_exc())
                matches = False
            
        return matches, new_fingerprint
    
    def _import_accepted_crypto_software(self, from_user, crypto_message):
        ''' 
            Import the encryption software the contact can use.
        '''
        
        accepted_crypto_packages = crypto_message.get_accepted_crypto_software()
        contacts.update_accepted_crypto(from_user, accepted_crypto_packages)
        
        return accepted_crypto_packages
    
    def _report_replacement_key(self, from_user, encryption_name, crypto_message):
        '''
            Report that they key in the header doesn't match an existing key.
        '''
    
        subject = translate('A new {} key arrived for {} that is not the same as the current key'.format(
            encryption_name, from_user))
        tag = subject
    
        message_lines = []
        message_lines.append(tag)
        message_lines.append('\n')
    
        message_lines.append(translate(
          "Contact the sender and verify if they've changed their {} key.".format(encryption_name)))
        message_lines.append(translate('If they *do* have a new key, then use your GoodCrypto server to delete the contact and ask them to resend the message.'))
        message_lines.append('\n')
        
        message_lines.append(translate(
          'If the sender has *not* replaced their key, then reconfirm the fingerprint in your GoodCrypto server.'.format(from_user)))
        message_lines.append('\n')
        
        message_lines.append(translate(
          'Remember, never use email for the verification of fingerprints and header_keys.'.format(from_user)))
    
        self._notify_recipient(subject, message_lines, crypto_message=crypto_message)

        return tag
    
    def _report_missing_key(self, from_user, key_ok, new_fingerprint, crypto_message):
        ''' 
            Report a key is missing for the user.
        '''
        subject = translate('Missing the key for {}'.format(from_user))
        tag = subject
        
        message_lines = []
        if key_ok:
            message_lines.append(translate('The message arrived with a key that matches the fingerprint in your GoodCrypto server, but that key is missing.'))
        else:
            message_lines.append(translate('The message arrived with a key that does not match the fingerprint in your GoodCrypto server and the key is missing.'))
        message_lines.append(translate('This should never happen so you need to communicate with the user *without* using email.'))
        message_lines.append('\n')
    
        message_lines.append(translate('*After* you verify that the following fingerprint is correct'))
        message_lines.append(translate('    fingerprint: {}'.format(new_fingerprint)))
        message_lines.append(translate(
          'then, use your GoodCrypto server to delete the {} contact.'.format(from_user)))
        message_lines.append(translate('Next, ask {} to resend the message.'.format(from_user)))
        message_lines.append(translate(
          'Finally, verify the new fingerprint with {}. Remember not to use email for the verification or someone could insert a bad key.'.format(from_user)))
    
        self._notify_recipient(subject, message_lines, crypto_message=crypto_message)
        
        return tag
    
    def _report_expired_key(self, from_user, encryption_name, expiration, crypto_message):
        '''
            Report a key expired.
        '''
    
        tag = translate("The {} key for {} expired on {}.".format(encryption_name, from_user, expiration))
        subject = translate('Received a message from {} with a {} key that expired on {}'.format(
          from_user, encryption_name, expiration))
        
        message_lines = []
        message_lines.append(tag)
        message_lines.append('\n')
        message_lines.append(translate(
          'First, use your GoodCrypto server to delete the {} contact.'.format(from_user)))
        message_lines.append(translate('Next, ask {} to create a new key and resend the message.'.format(from_user)))
        message_lines.append(translate(
          'Finally, verify the new fingerprint with {}. Do not use email for the verification or someone could insert a bad key.'.format(from_user)))
    
        self._notify_recipient(subject, message_lines, crypto_message=crypto_message)
        
        return tag
    
    def _report_mismatched_keys(self, from_user, encryption_name, crypto_message):
        '''
            Report the keys don't match.
        '''
        subject = translate("Keys do not match {}".format(from_user))
        tag = subject
    
        message_lines = []
        message_lines.append(translate(
           "You received a message from {} that has a key which is different than the existing key in the {} database.".format(from_user, encryption_name)))
        message_lines.append('\n\n')

        message_lines.append(translate(
          'First, contact {} and see if they have changed their key. If they have use your GoodCrypto server to delete their contact.'.format(from_user)))
        message_lines.append(translate('Next, ask {} to create a new key and resend the message.'.format(from_user)))
        message_lines.append(translate(
          'Finally, verify the new fingerprint with {}. Do not use email for the verification or someone could insert a bad key.'.format(from_user)))
        message_lines.append('\n\n')
    
        message_lines.append(translate(
          'Of course, if they have not changed their key, then future messages with the bad key will continue to be saved as attachment and not decrypted.'))
    
        self._notify_recipient(subject, message_lines, crypto_message=crypto_message)
        
        return tag
    
    def _report_bad_header_key(self, from_user, user_ids, encryption_name, crypto_message):
        '''
            Report the header's key doesn't match the sender.
        '''
        subject = translate("Message contained a bad {} key in header".format(encryption_name))
    
        if len(user_ids) == 1:
            tag = translate('Message included a {} key for {} when the message was sent from {}.'.format(
               encryption_name, user_ids[0], from_user))
        else:
            tag = translate('Message included multiple {} keys for "{}", but only a key from the sender, {}, can be imported.'.format(
                encryption_name, ', '.join(user_ids), from_user))

        message_lines = []
        message_lines.append(tag)
        
        self._notify_recipient(subject, message_lines, crypto_message=crypto_message)
        
        return tag

    
    def _report_db_error(self, from_user, encryption_name):
        '''
            Report a database error to the user.
        '''
    
        subject = translate('Unable to save the {} fingerprint in the database.'.format(encryption_name))
        tag = translate('The {} fingerprint for {} could not be saved.'.format(
                      encryption_name, from_user))
        
        message_lines = []
        message_lines.append(tag)
        message_lines.append('\n')
        message_lines.append(translate('Forward this email message to your system or mail administrator immediately.'))
        
        self._notify_recipient(subject, message_lines)
        
        return tag
    
    def _notify_recipient(self, subject, body, crypto_message=None):
        '''
            Send a message to the recipient.
        '''
    
        if self._recipient is None or body is None:
            self._log.write('unable to send notice because missing data')
            self._log.write('self._recipient: {}'.format(self._recipient))
            self._log.write('subject: {}'.format(subject))
            self._log.write('body: {}'.format(body))
        else:
            self._log.write('notifying {} about "{}"'.format(self._recipient, subject))
            if crypto_message is None:
                notify_user(self._recipient, subject, body)
            else:
                ORIGINAL_MESSAGE_ATTACHED = ' The original message is attached.'
                if type(body) is list:
                    body = ''.join(body)
                body += ORIGINAL_MESSAGE_ATTACHED
                self._log.write(' including original message as an attachment')
                attachment = crypto_message.get_email_message().to_string()
                filename = '{}.txt'.format(get_hashcode(attachment))
                notify_user(self._recipient, subject, body, attachment=attachment, filename=filename)

