'''
    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-08-03

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from email.mime.nonmultipart import MIMENonMultipart

from goodcrypto.mail import contacts, crypto_software, options
from goodcrypto.mail.message import constants, inspect_utils, utils
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.history import is_sig_verified
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.utils import add_private_key
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.crypto_factory import CryptoFactory
from goodcrypto.oce.utils import format_fingerprint
from goodcrypto.utils import get_email
from goodcrypto.utils.log_file import LogFile
from syr import mime_constants
from syr.exception import record_exception
from syr.python import is_string


class CryptoMessage(object):
    '''
        Crypto email_message.

        This class does not extend EmailMessage because we want a copy of the original
        EmailMessage so we can change it without impacting the original.

        See unittests for most of the functions.
    '''

    DEBUGGING = False

    SEPARATOR = ': '

    def __init__(self, email_message=None, sender=None, recipient=None):
        '''
            >>> crypto_message = CryptoMessage()
            >>> crypto_message != None
            True

            >>> crypto_message = CryptoMessage(email_message=EmailMessage())
            >>> crypto_message != None
            True
        '''

        super(CryptoMessage, self).__init__()
        self.log = LogFile()

        if email_message is None:
            self.email_message = EmailMessage()
            self.log_message('starting crypto message with a blank email message')
        else:
            self.email_message = email_message
            self.log_message('starting crypto message with an existing email message')

        # initialize a few key elements
        self.set_smtp_sender(sender)
        self.set_smtp_recipient(recipient)
        self.set_filtered(False)
        self.set_crypted(False)
        self.set_crypted_with([])
        self.set_metadata_crypted(False)
        self.set_metadata_crypted_with([])
        self.drop(False)
        self.set_processed(False)
        self.set_tag('')
        self.set_error_tag('')
        self.set_private_signed(False)
        self.set_private_signers([])
        self.set_clear_signed(False)
        self.set_clear_signers([])
        self.set_dkim_signed(False)
        self.set_dkim_sig_verified(False)


    def get_email_message(self):
        '''
            Returns the email message.

            >>> crypto_message = CryptoMessage(email_message=EmailMessage())
            >>> crypto_message.get_email_message() is not None
            True
        '''

        return self.email_message


    def set_email_message(self, email_message):
        '''
            Sets the email_message.

            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_email_message(get_basic_email_message())
            >>> crypto_message.get_email_message().get_message() is not None
            True
        '''

        self.email_message = email_message

    def smtp_sender(self):
        '''
            Returns the SMTP sender.

            >>> crypto_message = CryptoMessage(email_message=EmailMessage())
            >>> crypto_message.smtp_sender() is None
            True
        '''

        return self.sender

    def set_smtp_sender(self, email_address):
        '''
            Sets the SMTP sender email address. If a message had its metadata
            protected, then we'll set the "smtp sender" as the inner, protected
            messages are set. This address is never derived from the "header"
            section of a message.

            # In honor of Sister Megan Rice, an anti-nuclear activist who was
            # initially sentenced for breaking into a US nuclear facility as a protest.
            # Fortunately, she was finally released when federal appeals court acknowledged a
            # little old lady had embarrassed the gov't, not threatened them.
            >>> from goodcrypto_tests.mail.message_utils import get_basic_email_message
            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_smtp_sender('megan@goodcrypto.local')
            >>> sender = crypto_message.smtp_sender()
            >>> sender == 'megan@goodcrypto.local'
            True
        '''

        self.sender = get_email(email_address)
        if self.DEBUGGING: self.log_message('set sender: {}'.format(self.sender))

    def smtp_recipient(self):
        '''
            Returns the SMTP recipient.

            >>> crypto_message = CryptoMessage(email_message=EmailMessage())
            >>> crypto_message.smtp_recipient() is None
            True
        '''

        return self.recipient

    def set_smtp_recipient(self, email_address):
        '''
            Sets the SMTP recipient email address. If a message had its metadata
            protected, then we'll set the "smtp recipient" as the inner, protected
            messages are set. This address is never derived from the "header"
            section of a message.

            >>> # In honor of the Navy nurse who refused to torture prisoners
            >>> # in Guantanamo by force feeding them.
            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_smtp_recipient('nurse@goodcrypto.local')
            >>> recipient = crypto_message.smtp_recipient()
            >>> recipient == 'nurse@goodcrypto.local'
            True
        '''

        self.recipient = get_email(email_address)
        if self.DEBUGGING: self.log_message('set recipient: {}'.format(self.recipient))

    def get_public_key_header(self, from_user):
        '''
            Get the public key header lines.

            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
            >>> from goodcrypto.oce.test_constants import EDWARD_LOCAL_USER
            >>> auto_exchange = options.auto_exchange_keys()
            >>> options.set_auto_exchange_keys(True)
            >>> filename = get_plain_message_name('basic.txt')
            >>> with open(filename) as input_file:
            ...     crypto_message = CryptoMessage(email_message=EmailMessage(input_file))
            ...     key_block = crypto_message.get_public_key_header(EDWARD_LOCAL_USER)
            ...     key_block is not None
            ...     len(key_block) > 0
            True
            True
            >>> options.set_auto_exchange_keys(auto_exchange)
        '''

        header_lines = []
        if options.auto_exchange_keys():
            encryption_software_list = contacts.get_encryption_names(from_user)

            # if no crypto and we're creating keys, then do so now
            if (len(encryption_software_list) <= 0 and
                email_in_domain(from_user) and
                options.create_private_keys()):

                add_private_key(from_user)
                self.log_message("started to create a new key for {}".format(from_user))
                encryption_software_list = contacts.get_encryption_names(from_user)

            if len(encryption_software_list) > 0:
                self.log_message("getting header with public keys for {}: {}".format(
                   from_user, encryption_software_list))

                for encryption_software in encryption_software_list:
                    key_block = self.create_public_key_block(encryption_software, from_user)
                    if len(key_block) > 0:
                        header_lines += key_block
        else:
            self.log_message("Warning: auto-exchange of keys is not active")

        return header_lines


    def create_public_key_block(self, encryption_software, from_user):
        '''
            Create a public key block for the user if the header doesn't already have one.
        '''

        key_block = []
        try:
            if from_user is None or encryption_software is None or self.has_public_key_header(encryption_software):
                self.log_message('public {} key block already exists'.format(encryption_software))
            else:
                key_block = utils.make_public_key_block(from_user, encryption_software=encryption_software)
        except MessageException:
            record_exception()
            self.log_message('EXCEPTION - see syr.exception.log for details')
            self.log_exception("Unable to get {} public key header for {}".format(encryption_software, from_user))

        return key_block


    def extract_public_key_block(self, encryption_software):
        '''
            Extract a public key block from the header, if there is one.
        '''

        key_block = None
        try:
            if self.has_public_key_header(encryption_software):
                header_name = utils.get_public_key_header_name(encryption_software)
                self.log_message("getting {} public key header block using header {}".format(
                   encryption_software, header_name))
                key_block = inspect_utils.get_multientry_header(
                   self.get_email_message().get_message(), header_name)
                if key_block:
                    self.log_message("len key_block: {}".format(len(key_block)))
                else:
                    self.log_exception("No valid key {} block in header".format(encryption_software))
        except MessageException:
            record_exception()
            self.log_exception("Unable to get {} public key block".format(encryption_software))
            self.log_message('EXCEPTION - see syr.exception.log for details')

        return key_block


    def add_public_key_to_header(self, from_user):
        '''
            Add public key and accepted crypto to header if automatically exchanging keys.
        '''

        if options.auto_exchange_keys():
            header_lines = self.get_public_key_header(from_user)
            if header_lines and len(header_lines) > 0:
                for line in header_lines:
                    # we can't just use split() because some lines have no value
                    index = line.find(CryptoMessage.SEPARATOR)
                    if index > 0:
                        header_name = line[0:index]

                        value_index = index + len(CryptoMessage.SEPARATOR)
                        if len(line) > value_index:
                            value = line[value_index:]
                        else:
                            value = ''
                    else:
                        header_name = line
                        value = ''

                    self.email_message.add_header(header_name, value)

                self.add_accepted_crypto_software(from_user)
                self.add_fingerprint(from_user)
                self.log_message("added key for {} to header".format(from_user))
            else:
                encryption_name = CryptoFactory.DEFAULT_ENCRYPTION_NAME
                if options.create_private_keys():
                    add_private_key(from_user, encryption_software=encryption_name)
                    self.log_message("creating a new {} key for {}".format(encryption_name, from_user))
                else:
                    self.log_message("not creating a new {} key for {} because auto-create disabled".format(
                        encryption_name, from_user_id))
        else:
            self.log_message("not adding key for {} to header because auto-exchange disabled".format(from_user))

    def add_accepted_crypto_software(self, from_user):
        '''
            Add accepted encryption software to email message header.
        '''

        #  check whether we've already added them
        existing_crypto_software = self.get_accepted_crypto_software()
        if len(existing_crypto_software) > 0:
            self.log_message("attempted to add accepted encryption software to email_message that already has them")
        else:
            encryption_software_list = contacts.get_encryption_names(from_user)
            if len(encryption_software_list) <= 0:
                self.log_message("No encryption software for {}".format(from_user))
            else:
                self.email_message.add_header(
                  constants.ACCEPTED_CRYPTO_SOFTWARE_HEADER, ','.join(encryption_software_list))

    def get_accepted_crypto_software(self):
        '''
            Gets list of accepted encryption software from email message header.
            Crypto services are comma delimited.
        '''

        encryption_software_list = []
        try:
            #  !!!! the accepted services list is unsigned! fix this!
            encryption_software_header = inspect_utils.get_first_header(
                self.email_message.get_message(), constants.ACCEPTED_CRYPTO_SOFTWARE_HEADER)
            if encryption_software_header != None and len(encryption_software_header) > 0:
                self.log_message("accepted encryption software from email_message: {}".format(encryption_software_header))
                encryption_software_list = encryption_software_header.split(',')
        except Exception as exception:
            self.log_message(exception)

        return encryption_software_list

    def add_fingerprint(self, from_user):
        '''
            Add the fingerprint for each type of crypto used to the email message header.
        '''

        try:
            encryption_software_list = contacts.get_encryption_names(from_user)
            if len(encryption_software_list) <= 0:
                self.log_message("Not adding fingerprint for {} because no crypto software".format(from_user))
            else:
                for encryption_name in encryption_software_list:
                    fingerprint, __, active = contacts.get_fingerprint(from_user, encryption_name)
                    if active and fingerprint is not None and len(fingerprint.strip()) > 0:
                        self.email_message.add_header(constants.PUBLIC_FINGERPRINT_HEADER.format(
                            encryption_name.upper()), format_fingerprint(fingerprint))
                        self.log_message('added {} fingerprint'.format(encryption_name))
        except:
            record_exception()
            self.log_message('EXCEPTION - see syr.exception.log for details')

    def get_default_key_from_header(self):
        '''
             Gets the default public key from the email_message header.
        '''

        return self.get_public_key_from_header(constants.PUBLIC_KEY_HEADER)


    def get_public_key_from_header(self, header_name):
        '''
            Gets the public key from the email_message header.
        '''

        key = None
        try:
            key = inspect_utils.get_multientry_header(self.email_message.get_message(), header_name)
            if key is not None and len(key.strip()) <= 0:
                key = None
        except Exception:
            self.log_message("No public key found in email message")

        return key


    def has_public_key_header(self, encryption_name):
        ''' Return true if a public key header exists for the encryption software. '''

        has_key = False
        try:
            header_name = utils.get_public_key_header_name(encryption_name)
            email_message_key = inspect_utils.get_multientry_header(self.email_message.get_message(), header_name)
            has_key = email_message_key != None and len(email_message_key) > 0
        except Exception as exception:
            #  whatever the error, the point is we didn't get a public key header
            self.log_message(exception)

        if has_key:
            self.log_message("email_message already has public key header for encryption program {}".format(encryption_name))

        return has_key


    def set_filtered(self, filtered):
        '''
            Sets whether this email_message has been changed by a filter.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_filtered(True)
            >>> crypto_message.is_filtered()
            True
        '''

        if self.DEBUGGING: self.log_message("set filtered: {}".format(filtered))
        self.filtered = filtered


    def is_filtered(self):
        '''
            Gets whether this email_message has been changed by a filter.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_filtered()
            False
        '''

        return self.filtered


    def set_crypted(self, crypted):
        '''
            Sets whether this email_message has been encrypted or decrypted,
            even partially. You can check whether an inner email_message is still
            encrypted with email_email_message.is_probably_pgp().

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_crypted(True)
            >>> crypto_message.is_crypted()
            True
        '''

        if self.DEBUGGING: self.log_message("set crypted: {}".format(crypted))
        self.crypted = crypted


    def is_crypted(self):
        '''
            Returns whether this email_message has been encrypted or decrypted,
            even partially. You can check whether an inner email_message is still
            encrypted with email_email_message.is_probably_pgp().

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_crypted()
            False
        '''

        return self.crypted

    def set_metadata_crypted(self, crypted):
        '''
            Sets whether this email_message has its metadata encrypted or decrypted.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_metadata_crypted(True)
            >>> crypto_message.is_metadata_crypted()
            True
        '''

        if self.DEBUGGING: self.log_message("set metadata crypted: {}".format(crypted))
        self.metadata_crypted = crypted

    def is_metadata_crypted(self):
        '''
            Returns whether this email_message has been encrypted or decrypted,
            even partially. You can check whether an inner email_message is still
            encrypted with email_email_message.is_probably_pgp().

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_metadata_crypted()
            False
        '''

        return self.metadata_crypted


    def is_signed(self):
        '''
            Returns whether this email_message has any type of signature.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_signed()
            False
        '''

        return self.is_private_signed() or self.is_clear_signed() or self.is_dkim_signed()

    def set_private_signed(self, signed):
        '''
            Sets whether this email_message has been signed when encrypted.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_private_signed(True)
            >>> crypto_message.is_private_signed()
            True
        '''

        if self.DEBUGGING: self.log_message("set private signed: {}".format(signed))
        self.private_signed = signed


    def is_private_signed(self):
        '''
            Returns whether this email_message has been signed when encrypted.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_private_signed()
            False
        '''

        return self.private_signed

    def is_private_sig_verified(self):
        '''
            Returns whether this email_message's signature has been verified.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_private_sig_verified()
            False
        '''

        return is_sig_verified(self.private_signers_list())

    def set_private_signers(self, signers):
        '''
            Set who signed this email_message when encrypted.

            >>> private_signers = [{'signer': 'edward@goodcrypto.local', 'verified': True}]
            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_private_signers(
            ...    [{u'signer': u'edward@goodcrypto.local', u'verified': True}])
            >>> signers = crypto_message.private_signers_list()
            >>> signers == private_signers
            True
        '''

        self.private_signers = signers


    def add_private_signer(self, signer):
        '''
            Add who signed this email_message when encrypted.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.add_private_signer(
            ...   {constants.SIGNER: 'edward@goodcrypto.local', constants.SIGNER_VERIFIED: True})
            >>> signers = crypto_message.private_signers_list()
            >>> signers == [{'signer': 'edward@goodcrypto.local', 'verified': True}]
            True
        '''

        self.add_signer(signer, self.private_signers_list())


    def private_signers_list(self):
        '''
            Returns a list of signers when encrypted.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.private_signers_list()
            []
        '''

        if self.private_signers is None:
            self.set_private_signers([])

        return self.private_signers


    def set_clear_signed(self, signed):
        '''
            Sets whether this email_message has been clear signed.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_clear_signed(True)
            >>> crypto_message.is_clear_signed()
            True
        '''

        if self.DEBUGGING: self.log_message("set clear signed: {}".format(signed))
        self.clear_signed = signed


    def is_clear_signed(self):
        '''
            Returns whether this email_message has been clear signed.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_clear_signed()
            False
        '''

        return self.clear_signed

    def is_clear_sig_verified(self):
        '''
            Returns whether this email_message's clear signature has been verified.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_clear_sig_verified()
            False
        '''

        return is_sig_verified(self.clear_signers_list())

    def set_clear_signers(self, signers):
        '''
            Set who clear signed this email_message.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_clear_signers(
            ...    [{'signer': 'edward@goodcrypto.local', 'verified': True}])
            >>> signers = crypto_message.clear_signers_list()
            >>> signers == [{'signer': 'edward@goodcrypto.local', 'verified': True}]
            True
        '''

        self.clear_signers = signers


    def add_clear_signer(self, signer_dict):
        '''
            Add who clear signed this email_message.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.add_clear_signer({'signer': 'edward@goodcrypto.local', 'verified': True})
            >>> signers = crypto_message.clear_signers_list()
            >>> signers == [{'signer': 'edward@goodcrypto.local', 'verified': True}]
            True
        '''

        self.add_signer(signer_dict, self.clear_signers_list())

    def clear_signers_list(self):
        '''
            Returns a list of clear signers.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.clear_signers_list()
            []
        '''

        if self.clear_signers is None:
            self.set_clear_signers([])

        return self.clear_signers


    def set_dkim_signed(self, signed):
        '''
            Sets whether this email_message has been signed using DKIM.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_dkim_signed(True)
            >>> crypto_message.is_dkim_signed()
            True
        '''

        if self.DEBUGGING: self.log_message("set dkim signed: {}".format(signed))
        self.dkim_signed = signed


    def is_dkim_signed(self):
        '''
            Returns whether this email_message has been signed using DKIM.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_dkim_signed()
            False
        '''

        return self.dkim_signed

    def set_dkim_sig_verified(self, verified):
        '''
            Sets whether this email_message's DKIM sig has been verified.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_dkim_sig_verified(True)
            >>> crypto_message.is_dkim_sig_verified()
            True
        '''

        if self.DEBUGGING: self.log_message("set dkim sig verified: {}".format(verified))
        self.dkim_verified = verified


    def is_dkim_sig_verified(self):
        '''
            Returns whether this email_message's DKIM sig has been verified.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_dkim_sig_verified()
            False
        '''

        return self.dkim_verified

    def add_signer(self, signer_dict, signer_list):
        '''
            Add who signed this email_message.

            >>> crypto_message = CryptoMessage()
            >>> clear_signers = crypto_message.clear_signers_list()
            >>> crypto_message.add_signer({'signer': 'edward@goodcrypto.local', 'verified': True}, clear_signers)
        '''

        if signer_dict is not None:
            signer = signer_dict[constants.SIGNER]
            if signer is not None:
                signer = get_email(signer)
            # now make the signer readable if unknown
            if signer == None:
                signer = 'unknown user'

            signer_dict[constants.SIGNER] = signer
            if signer_dict not in signer_list:
                if self.DEBUGGING: self.log_message("add signer: {}".format(signer_dict))
                signer_list.append(signer_dict)


    def drop(self, dropped=True):
        '''
            Sets whether this email_message has been dropped by a filter.
            If the message is dropped, then it's never returned to postfix.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.drop()
            >>> crypto_message.is_dropped()
            True
        '''

        if self.DEBUGGING: self.log_message("set dropped: {}".format(dropped))
        self.dropped = dropped


    def is_dropped(self):
        '''
            Gets whether this email_message has been dropped by a filter.
            If the message is dropped, then it's never returned to postfix.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_dropped()
            False
        '''

        return self.dropped


    def set_processed(self, processed):
        '''
            Sets whether this email message has been processed by a filter.
            A processed message does not need any further processing by the caller.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_processed(True)
            >>> crypto_message.is_processed()
            True
        '''

        if self.DEBUGGING: self.log_message("set processed: {}".format(processed))
        self.processed = processed


    def is_processed(self):
        '''
            Gets whether this email_message has been processed by a filter.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_processed()
            False
        '''

        return self.processed


    def set_crypted_with(self, crypted_with):
        '''
            Sets the encryption programs message was crypted..

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_crypted_with(['GPG'])
            >>> crypted_with = crypto_message.get_crypted_with()
            >>> crypted_with == ['GPG']
            True
        '''

        self.crypted_with = crypted_with
        if self.DEBUGGING: self.log_message("set crypted_with: {}".format(self.get_crypted_with()))


    def get_crypted_with(self):
        '''
            Returns the encryption programs message was crypted.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.get_crypted_with()
            []
        '''

        return self.crypted_with


    def set_metadata_crypted_with(self, crypted_with):
        '''
            Sets whether this email_message has its metadata encrypted or decrypted.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_metadata_crypted_with(['GPG'])
            >>> crypted_with = crypto_message.get_metadata_crypted_with()
            >>> crypted_with == ['GPG']
            True
        '''

        self.metadata_crypted_with = crypted_with
        if self.DEBUGGING: self.log_message("set metadata crypted_with: {}".format(self.get_metadata_crypted_with()))


    def get_metadata_crypted_with(self):
        '''
            Returns the encryption programs the metadata was encrypted.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.get_metadata_crypted_with()
            []
        '''

        return self.metadata_crypted_with


    def is_create_private_keys_active(self):
        '''
            Gets whether creating private keys on the fly is active.

            >>> crypto_message = CryptoMessage()
            >>> current_setting = options.create_private_keys()
            >>> options.set_create_private_keys(True)
            >>> crypto_message.is_create_private_keys_active()
            True
            >>> options.set_create_private_keys(False)
            >>> crypto_message.is_create_private_keys_active()
            False
            >>> options.set_create_private_keys(current_setting)
        '''

        active = options.create_private_keys()
        if self.DEBUGGING: self.log_message("Create private keys: {}".format(active))

        return active

    def add_tags_to_message(self, tags):
        '''
            Add tag to a message.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.add_tags_to_message('')
            False
        '''

        def add_tags_to_text(content, tags):
            ''' Add the tag to the text content. '''

            text_content = content
            text_content = '{}\n\n\n{}\n'.format(text_content, str(tags))
            self.log_message('added tags to text content')

            return text_content

        def add_tags_to_html(content, tags):
            ''' Add the tag to the html content. '''

            for tag in tags:
                tag = tag.replace('\n', '<br/>')
                tag = tag.replace(' ', '&nbsp;')

            html_content = content
            index = html_content.lower().find('</body>')
            if index < 0:
                index = html_content.lower().find('</html>')
            if index < 0:
                html_content = '{}<div><hr>\n{}<br/></div>'.format(html_content, str(tags))
            else:
                html_content = '{}<div><hr>\n{}<br/></div>\n{}'.format(html_content[0:index], str(tags), html_content[:index])
            self.log_message('added tags to html content')

            return html_content

        tags_added = False
        if tags is None or len(tags.strip()) <= 0:
            self.log_message('no tags need to be added to message')
        elif self.get_email_message() is None or self.get_email_message().get_message() is None:
            self.log_message('email message not formed correctly')
        else:
            msg_charset, self._last_charset = inspect_utils.get_charset(self.get_email_message())
            content_type = self.get_email_message().get_message().get_content_type()
            self.log_message("content type: {}".format(content_type))
            if content_type is None:
                pass
            elif (content_type == mime_constants.TEXT_PLAIN_TYPE or
                  content_type == mime_constants.TEXT_HTML_TYPE):
                content = self.get_email_message().get_content()
                if content is None:
                    self.get_email_message().set_content(tags, content_type, charset=msg_charset)
                    tags_added = True
                else:
                    if content.lower().find('<html>') > 0:
                        content = add_tags_to_html(content, tags)
                    else:
                        content = add_tags_to_text(self.get_email_message().get_content(), tags)
                    self.get_email_message().set_content(content, content_type, charset=msg_charset)
                    tags_added = True

            elif content_type.startswith(mime_constants.MULTIPART_PRIMARY_TYPE):
                added_tags_to_text = False
                added_tags_to_html = False
                message = self.get_email_message().get_message()
                for part in message.get_payload():
                    part_content_type = part.get_content_type().lower()
                    self.log_message('part_content_type: {}'.format(part_content_type)) #DEBUG
                    if part_content_type == mime_constants.TEXT_PLAIN_TYPE and not added_tags_to_text:
                        content = add_tags_to_text(part.get_payload(), tags)
                        charset, __ = inspect_utils.get_charset(content)
                        if charset.lower() == msg_charset.lower():
                            part.set_payload(content)
                        else:
                            part.set_payload(content, charset=charset)
                        added_tags_to_text = True

                    elif part_content_type == mime_constants.TEXT_HTML_TYPE and not added_tags_to_html:
                        content = add_tags_to_html(part.get_payload(), tags)
                        charset, __ = inspect_utils.get_charset(content)
                        part.set_payload(content, charset=charset)
                        added_tags_to_html = True

                    # no need to keep getting payloads if we've added the tags
                    if added_tags_to_text and added_tags_to_html:
                        break

                tags_added = added_tags_to_text or added_tags_to_html
                if not tags_added:
                    msg = MIMENonMultipart(mime_constants.TEXT_PRIMARY_TYPE, mime_constants.PLAIN_SUB_TYPE)
                    msg.set_payload(tags)
                    self.get_email_message().get_message().attach(msg)
                    self.log_message('attached new payload\n{}'.format(msg))
                    tags_added = True

                self.log_message('added tags to multipart message: {}'.format(tags_added))

            else:
                self.log_message('unable to add tags to message with {} content type'.format(content_type))

        return tags_added

    def get_tags(self):
        '''
            Returns the list of tags to be added to the email_message text.

            >>> regular_tags = ['test tag']
            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_tag('test tag')
            >>> tags = crypto_message.get_tags()
            >>> crypto_message.log_message('tags: {}'.format(tags))
            >>> tags == regular_tags
            True
        '''

        if self.DEBUGGING: self.log_message("tags:\n{}".format(self.tags))

        return self.tags

    def get_tag(self):
        '''
            Returns the tags as a string to be added to the email_message text.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_tag('test tag')
            >>> tags = crypto_message.get_tag()
            >>> tags == 'test tag'
            True
        '''

        if self.tags is None:
            tag = ''
        else:
            tag = '\n'.join(self.tags)
            if self.DEBUGGING: self.log_message("tag:\n{}".format(tag))

        return tag

    def set_tag(self, new_tag):
        '''
            Sets the tag to be added to the email_message text.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_tag(None)
            >>> tag = crypto_message.get_tag()
            >>> tag == ''
            True
        '''

        if new_tag is None:
            if self.DEBUGGING: self.log_message("tried to set blank tag")
        elif new_tag == '':
            self.tags = []
            if self.DEBUGGING: self.log_message("reset tags")
        else:
            if is_string(new_tag):
                new_tag = new_tag.strip('\n')
                self.tags = [new_tag]
            else:
                self.tags = new_tag
            if self.DEBUGGING: self.log_message("new tag:\n{}".format(new_tag))


    def add_tag(self, new_tag):
        '''
            Add new tag to the existing tag.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.add_tag(None)
            >>> tag = crypto_message.get_tag()
            >>> tag == ''
            True
        '''

        if new_tag is None or len(new_tag) <= 0:
            if self.DEBUGGING: self.log_message("tried to add empty tag")
        else:
            new_tag = new_tag.strip('\n')
            if self.tags == None or len(self.tags) <= 0:
                if self.DEBUGGING: self.log_message("adding to an empty tag:\n{}".format(new_tag))
                self.tags = [new_tag]
            else:
                if self.DEBUGGING: self.log_message("adding to tag:\n{}".format(new_tag))
                if new_tag.startswith('.'):
                    self.tags[len(self.tags) - 1] += new_tag
                else:
                    self.tags.append(new_tag)

    def add_tag_once(self, new_tag):
        '''
            Add new tag only if it isn't already in the tag.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.add_tag_once(None)
            >>> tag = crypto_message.get_tag().strip()
            >>> tag == ''
            True
        '''
        if new_tag is None:
            pass
        elif self.tags is None or new_tag not in self.tags:
            self.add_tag(new_tag)

    def add_prefix_to_tag_once(self, new_tag):
        '''
            Add new tag prefix only if it isn't already in the tag.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.add_prefix_to_tag_once(None)
            >>> tag = crypto_message.get_tag()
            >>> tag == ''
            True
        '''

        if new_tag is None:
            pass
        elif self.tags is None or new_tag not in self.tags:
            new_tag = new_tag.strip('\n')
            if self.DEBUGGING: self.log_message("adding prefix to tag:\n{}".format(new_tag))
            if self.tags == None or len(self.tags) <= 0:
                self.tags = [new_tag]
            else:
                old_tags = self.tags
                self.tags = [new_tag]
                for tag in old_tags:
                    self.tags.append(tag)

    def get_error_tags(self):
        '''
            Returns the list of error tags to be added to the email_message text.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_error_tag('test error tag')
            >>> tags = crypto_message.get_error_tags()
            >>> tags == ['test error tag']
            True
        '''

        if self.DEBUGGING: self.log_message("error tags:\n{}".format(self.error_tags))

        return self.error_tags

    def get_error_tag(self):
        '''
            Returns the error tags as a string to be added to the email_message text.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_error_tag('test error tag')
            >>> tag = crypto_message.get_error_tag()
            >>> tag == 'test error tag'
            True
        '''

        if self.error_tags is None:
            error_tag = ''
        else:
            error_tag = '\n'.join(self.error_tags)
            if self.DEBUGGING: self.log_message("error tag:\n{}".format(error_tag))

        return error_tag

    def set_error_tag(self, new_tag):
        '''
            Sets the error tag to be added to the email_message text.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_error_tag(None)
            >>> tag = crypto_message.get_error_tag()
            >>> tag == ''
            True
        '''

        if new_tag is None:
            if self.DEBUGGING: self.log_message("tried to set blank error tag")
        elif new_tag == '':
            self.error_tags = []
            if self.DEBUGGING: self.log_message("reset error tags")
        else:
            if is_string(new_tag):
                new_tag = new_tag.strip('\n')
                self.error_tags = [new_tag]
            else:
                self.error_tags = new_tag
            if self.DEBUGGING: self.log_message("new tag:\n{}".format(self.error_tags))


    def add_error_tag_once(self, new_tag):
        '''
            Add new error tag only if it isn't already in the error tag.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.add_error_tag_once(None)
            >>> tag = crypto_message.get_error_tag().strip()
            >>> tag == ''
            True
        '''
        if new_tag is None:
            pass
        elif self.error_tags is None or new_tag not in self.error_tags:
            new_tag = new_tag.strip('\n')
            if len(self.error_tags) <= 0:
                if self.DEBUGGING: self.log_message("adding to an empty error tag:\n{}".format(new_tag))
                self.error_tags = [new_tag]
            else:
                self.log_message("adding to error tag:\n{}".format(new_tag))
                if new_tag.startswith('.'):
                    self.error_tags[len(self.tags) - 1] += new_tag
                else:
                    self.error_tags.append(new_tag)

    def log_exception(self, exception):
        '''
            Log the message to the local and Exception logs.

            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> CryptoMessage().log_exception('test message')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.crypto_message.log'))
            True
        '''

        self.log_message(exception)
        record_exception(message=exception)

    def log_message(self, message):
        '''
            Log the message to the local log.

            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> CryptoMessage().log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.crypto_message.log'))
            True
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

