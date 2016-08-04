'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-11-30

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import os

from goodcrypto.mail import contacts, crypto_software
from goodcrypto.mail.message.constants import PUBLIC_KEY_HEADER
from goodcrypto.mail.message.inspect_utils import get_multientry_header
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.metadata import is_metadata_address
from goodcrypto.mail.message.utils import get_public_key_header_name
from goodcrypto.mail.utils import get_sysadmin_email
from goodcrypto.mail.utils import notices
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import strip_fingerprint
from goodcrypto.utils import i18n, parse_address
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile


class HeaderKeys(object):
    '''
        Manage keys from a message's header.

        It's important that we only import a key if we don't have a key
        for this user. If we already do, then we must be very careful
        deciding whether to use the key or not.

        The following table shows the conditions that we must handle if there's a key in the header.
        If we decide not to use a key, then a message is sent to the recipient explaining our reason
        for not processing the message. The original offending message is included as an attachment.

        Received key in header so check db and crypto package.
        | saved in db  | crypto package | action     | unit test                             |
        |--------------|----------------|------------|---------------------------------------|
        | match        | match          | use        | test_all_matching_keys                |
        | match        | no match       | do not use | test_db_fingerprint_bad_crypto_key    |
        | match        | missing        | do not use | test_db_fingerprint_no_crypto_key     |
        | no match     | match          | do not use | test_bad_fingerprint_matching_crypto  |
        | no match     | no match       | do not use | test_bad_fingerprint_bad_crypto       |
        | no match     | missing        | do not use | test_bad_fingerprint_missing_crypto   |
        | missing      | match          | add to db  | test_crypto_key_no_db_fingerprint     |
        | missing      | no match       | do not use | test_bad_crypto_key_no_db_fingerprint |
        | missing      | missing        | import     | test_no_existing_keys                 |
    '''

    DEBUGGING = False

    def __init__(self):
        '''
            >>> header_keys = HeaderKeys()
            >>> header_keys != None
            True
        '''

        self.log = LogFile()

        self.recipient_to_notify = None
        self.new_key_imported = False

    def manage_keys_in_header(self, crypto_message):
        '''
            Manage all the public keys in the message's header.
        '''
        header_contains_key_info = False
        try:
            from_user = crypto_message.smtp_sender()
            self.recipient_to_notify = crypto_message.smtp_recipient()
            # all notices about a metadata address goes to the sysadmin
            if is_metadata_address(self.recipient_to_notify):
                self.recipient_to_notify = get_sysadmin_email()

            name, address = parse_address(from_user)
            if address is None or crypto_message is None or crypto_message.get_email_message() is None:
                self.log_message('missing data so cannot import key')
                self.log_message('   from user: {}'.format(from_user))
                self.log_message('   address: {}'.format(address))
                self.log_message('   crypto message: {}'.format(crypto_message))
                if crypto_message is not None: self.log_message('   email message: {}'.format(crypto_message.get_email_message()))
            else:
                accepted_crypto_packages = self._import_accepted_crypto_software(from_user, crypto_message)
                if accepted_crypto_packages is None or len(accepted_crypto_packages) <= 0:
                    self.log_message("checking for default key for {} <{}>".format(name, address))
                    tag = self._manage_key_header(address, crypto_message,
                       KeyFactory.get_default_encryption_name(), PUBLIC_KEY_HEADER)
                else:
                    self.log_message("checking for {} keys".format(accepted_crypto_packages))
                    for encryption_name in accepted_crypto_packages:
                        # see if there's a the key block for this encryption program
                        header_name = get_public_key_header_name(encryption_name)
                        key_block = get_multientry_header(
                          crypto_message.get_email_message().get_message(), header_name)
                        # see if there's a plain key block
                        if ((key_block is None or len(key_block) <= 0) and
                            len(accepted_crypto_packages) == 1):
                            self.log_message("no {} public key in header so trying generic header".format(encryption_name))
                            key_block = get_multientry_header(
                              crypto_message.get_email_message().get_message(), PUBLIC_KEY_HEADER)

                        tag = self._manage_key_header(
                          address, crypto_message, encryption_name, key_block)
                    header_contains_key_info = True

        except MessageException as message_exception:
            raise MessageException(value=message_exception.value)

        except:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            if crypto_message is not None:
                crypto_message.add_tag_once(i18n('An unexpected error ocurred while processing this message'))

        self.log_message('header_contains_key_info: {}'.format(header_contains_key_info))

        return header_contains_key_info

    def keys_in_header(self, crypto_message):
        '''
            Return true if there are public keys in the message's header.
        '''
        header_contains_key_info = False
        try:
            from_user = crypto_message.smtp_sender()
            accepted_crypto_packages = self._import_accepted_crypto_software(from_user, crypto_message)
            if accepted_crypto_packages is not None and len(accepted_crypto_packages) > 0:
                self.log_message("checking for {} keys".format(accepted_crypto_packages))
                for encryption_name in accepted_crypto_packages:
                    # see if there's a the key block for this encryption program
                    header_name = get_public_key_header_name(encryption_name)
                    key_block = get_multientry_header(
                      crypto_message.get_email_message().get_message(), header_name)
                    # see if there's a plain key block
                    if ((key_block is None or len(key_block) <= 0) and
                        len(accepted_crypto_packages) == 1):
                        self.log_message("no {} public key in header so trying generic header".format(encryption_name))
                        key_block = get_multientry_header(
                          crypto_message.get_email_message().get_message(), PUBLIC_KEY_HEADER)
                    if key_block is not None and len(key_block) > 0:
                        header_contains_key_info = True
                        break

        except MessageException as message_exception:
            raise MessageException(value=message_exception.value)

        except:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
            if crypto_message is not None:
                crypto_message.add_tag_once(i18n('An unexpected error ocurred while processing this message'))

        return header_contains_key_info

    def new_key_imported_from_header(self):
        '''
            Return true if a new key was imported from the header.
        '''

        return self.new_key_imported

    def _manage_key_header(self, from_user, crypto_message, encryption_name, key_block):
        '''
            Manage a key in the header for the encryption software (internal use only).
        '''

        tag = None

        try:
            if key_block == None or len(key_block.strip()) <= 0:
                self.log_message("no {} public key in header".format(encryption_name))
            else:
                if self.DEBUGGING:
                    self.log_message("{} key from message:\n{}".format(encryption_name, key_block))

                key_crypto = KeyFactory.get_crypto(
                  encryption_name, crypto_software.get_key_classname(encryption_name))
                if key_crypto is None:
                    id_fingerprint_pairs = None
                    self.log_message('no key crypto for {}'.format(encryption_name))
                else:
                    id_fingerprint_pairs = key_crypto.get_id_fingerprint_pairs(key_block)

                if id_fingerprint_pairs is None or len(id_fingerprint_pairs) <= 0:
                    tag = None
                    self.log_message('no user keys in key block')
                else:
                    tag = self._manage_public_key(
                        from_user, crypto_message, key_crypto, key_block, id_fingerprint_pairs)

                if tag is not None and len(tag.strip()) > 0:
                    crypto_message.add_tag_once(tag)

        except MessageException as message_exception:
            raise MessageException(value=message_exception.value)

        except:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return tag

    def _manage_public_key(self, from_user, crypto_message, key_crypto, key_block, id_fingerprint_pairs):
        '''
            Manage a public key for the encryption software (internal use only).
        '''

        tag = None
        drop = False

        encryption_name = key_crypto.get_name()
        user_ids= []
        for (user_id, __) in id_fingerprint_pairs:
            user_ids.append(user_id)
        self.log_message("key block includes key for {}".format(user_ids))

        if from_user in user_ids:
            #  see if we already have a key for this ID or if it has expired
            saved_fingerprint, verified, __ = contacts.get_fingerprint(from_user, encryption_name)
            crypto_fingerprint, expiration = key_crypto.get_fingerprint(from_user)

            self.log_message("{} {} saved fingerprint {}".format(from_user, encryption_name, saved_fingerprint))
            self.log_message("{} {} crypto fingerprint {} expires {}".format(
                from_user, encryption_name, crypto_fingerprint, expiration))
            self.log_message("{} {} id fingerprint pairs {}".format(from_user, encryption_name, id_fingerprint_pairs))

            if crypto_fingerprint is None:
                if saved_fingerprint is None:
                    self.log_message("importing new key")
                    tag = self._import_new_key(
                        from_user, encryption_name, key_block, id_fingerprint_pairs)
                else:
                    self.log_message("checking if key matches")
                    drop = crypto_message.get_email_message().is_probably_pgp()
                    key_matches, key_error = self._key_matches(
                        encryption_name, saved_fingerprint, id_fingerprint_pairs)
                    self.log_message("key matches: {} / key error: {}".format(key_matches, key_error))
                    if key_error:
                        tag = notices.report_error_verifying_key(
                            self.recipient_to_notify, from_user, encryption_name, crypto_message)
                    else:
                        tag = notices.report_missing_key(self.recipient_to_notify,
                            from_user, key_matches, id_fingerprint_pairs, crypto_message)
            else:
                if saved_fingerprint is None:
                    # remember the fingerprint for the future
                    saved_fingerprint = crypto_fingerprint

                if (strip_fingerprint(crypto_fingerprint).lower() ==
                    strip_fingerprint(saved_fingerprint).lower()):
                    key_matches, key_error = self._key_matches(
                        encryption_name, crypto_fingerprint, id_fingerprint_pairs)
                    if key_error:
                        tag = notices.report_error_verifying_key(
                           self.recipient_to_notify, from_user, encryption_name, crypto_message)
                    elif key_matches:
                        if key_crypto.fingerprint_expired(expiration):
                            drop = crypto_message.get_email_message().is_probably_pgp()
                            tag = notices.report_expired_key(self.recipient_to_notify,
                                from_user, encryption_name, expiration, crypto_message)
                        else:
                            self.log_message('  same fingerprint: {}'.format(saved_fingerprint))
                            # warn user if unable to save the fingerprint, but proceed
                            if not contacts.update_fingerprint(from_user, encryption_name, crypto_fingerprint):
                                tag = notices.report_db_error(
                                    self.recipient_to_notify, from_user, encryption_name, crypto_message)
                    else:
                        if self.DEBUGGING:
                            self.log_message('{} key block\n{}'.format(
                              from_user, key_crypto.export_public(from_user)))
                        drop = crypto_message.get_email_message().is_probably_pgp()
                        tag = notices.report_replacement_key(self.recipient_to_notify,
                            from_user, encryption_name, id_fingerprint_pairs, crypto_message)
                else:
                    drop = crypto_message.get_email_message().is_probably_pgp()
                    tag = notices.report_mismatched_keys(
                        self.recipient_to_notify, from_user, encryption_name, crypto_message)
        else:
            if len(user_ids) > 0:
                drop = crypto_message.get_email_message().is_probably_pgp()
                tag = notices.report_bad_header_key(
                    self.recipient_to_notify, from_user, user_ids, encryption_name, crypto_message)
            else:
                self.log_message('no importable keys found\n{}'.format(key_block))

        self.log_message('tag: {}'.format(tag))

        if drop:
            crypto_message.drop(dropped=True)
            self.log_message('serious error in header so original message sent as attchment')
            raise MessageException(value=i18n(tag))

        return tag

    def _import_new_key(self, from_user, encryption_name, key_block, id_fingerprint_pairs):
        '''
            Import a new key (internal use only).
        '''

        tag = None
        result_ok = False
        if encryption_name is None:
            encryption_name = ''

        self.new_key_imported = False
        try:
            self.log_message("starting to import new {} key for {}".format(encryption_name, from_user))
            if from_user is None or len(encryption_name) == 0 or id_fingerprint_pairs is None:
                self.log_message('missing key data so unable to import new key')
            else:
                key_crypto = KeyFactory.get_crypto(
                    encryption_name, crypto_software.get_key_classname(encryption_name))

                # make sure that we don't have a key for any of the user ids included with this key
                result_ok = True
                if id_fingerprint_pairs is None or len(id_fingerprint_pairs) <= 0:
                    result_ok = False

                elif len(id_fingerprint_pairs) > 1:
                    for (user_id, __) in id_fingerprint_pairs:
                        crypto_fingerprint, expiration = key_crypto.get_fingerprint(user_id)
                        if crypto_fingerprint is not None:
                            result_ok = False
                            self.log_message('key exists for {} so unable to import key for {}'.format(user_id, from_user))
                            break

                if result_ok:
                    result_ok = key_crypto.import_public(key_block, id_fingerprint_pairs=id_fingerprint_pairs)
                    self.log_message('imported key: {}'.format(result_ok))

                if result_ok:
                    self.new_key_imported = True
                    result_ok = self._add_contacts_and_notify(encryption_name, id_fingerprint_pairs)
                    self.log_message('added contacts: {}'.format(result_ok))

            if not result_ok:
                self.log_message('Unable to import new public key for {}; probably taking longer than expected; check Contacts later'.format(from_user))
        except:
            record_exception()
            self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        self.log_message('import new key ok: {}'.format(result_ok))

        return tag

    def _add_contacts_and_notify(self, encryption_name, id_fingerprint_pairs):

        result_ok = True

        # use the first email address from the imported key
        email, __ = id_fingerprint_pairs[0]

        for (user_id, fingerprint) in id_fingerprint_pairs:
            self.log_message(
                'adding contact for {} with {} fingerprint'.format(user_id, fingerprint))
            contact = contacts.add(user_id, encryption_name, fingerprint=fingerprint)
            if contact is None:
                result_ok = False
                self.log_message('unable to add contact while trying to import key for {}'.format(email))
            else:
                self.log_message('successfully added contact after importing key for {}'.format(email))

        if result_ok:
            notices.notify_new_key_arrived(self.recipient_to_notify, id_fingerprint_pairs)

        return result_ok

    def _key_matches(self, encryption_name, old_fingerprint, id_fingerprint_pairs):
        '''
            Does the new key's fingerprint match the old fingerprint? (internal use only)
        '''

        matches = error = False

        if encryption_name is None:
            error = True
            self.log_message('unable to compare fingerprints because basic data is missing')
        else:
            try:
                if id_fingerprint_pairs is None or old_fingerprint is None:
                    error = True
                    self.log_message('missing fingerprint for comparison')
                    self.log_message('old fingerprint: {}'.format(old_fingerprint))
                    self.log_message('id fingerprint pairs: {}'.format(id_fingerprint_pairs))
                else:
                    fingerprints = []
                    for (__, fingerprint) in id_fingerprint_pairs:
                        fingerprints.append(fingerprint.replace(' ', ''))
                    matches = old_fingerprint.replace(' ', '') in fingerprints
            except:
                error = True
                matches = False
                record_exception()
                self.log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        return matches, error

    def _import_accepted_crypto_software(self, from_user, crypto_message):
        '''
            Import the encryption software the contact can use (internal use only).
        '''

        accepted_crypto_packages = crypto_message.get_accepted_crypto_software()
        contacts.update_accepted_crypto(from_user, accepted_crypto_packages)

        return accepted_crypto_packages

    def log_message(self, message):
        '''
            Log the message to the local log.
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

