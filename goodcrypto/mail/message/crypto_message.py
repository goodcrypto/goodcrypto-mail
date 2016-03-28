'''
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-04-15

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from email.mime.nonmultipart import MIMENonMultipart
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail import contacts, contacts_passcodes, crypto_software, options
from goodcrypto.mail.message import utils
from goodcrypto.mail.message.constants import ACCEPTED_CRYPTO_SOFTWARE_HEADER, PUBLIC_KEY_HEADER, PUBLIC_FINGERPRINT_HEADER
from goodcrypto.mail.message.crypto_filter import CryptoFilter
from goodcrypto.mail.message.email_message import EmailMessage
from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.mail.message.utils import add_private_key
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.mail.utils.exception_log import ExceptionLog
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.oce.utils import format_fingerprint
from syr import mime_constants


class CryptoMessage(object):
    '''
        Crypto email_message.
        
        This class does not extend EmailMessage because we want a copy of the original
        EmailMessage so we can change it without impacting the original.
        
        See unittests for most of the functions.
    '''
    
    DEBUGGING = False
    
    SEPARATOR = ': '
    
    def __init__(self, email_message=None):
        ''' 
            >>> crypto_message = CryptoMessage()
            >>> crypto_message != None
            True
            
            >>> crypto_message = CryptoMessage(EmailMessage())
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

        self.tag = ''
        self.set_filtered(False)
        self.set_crypted(False)
        self.set_dropped(False)
 

    def get_email_message(self):
        ''' 
            Returns the email message.
        
            >>> crypto_message = CryptoMessage(EmailMessage())
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


    def get_public_key_header(self, from_user):
        ''' 
            Get the public key header lines.

            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
            >>> from goodcrypto.oce.constants import EDWARD_LOCAL_USER
            >>> auto_exchange = options.auto_exchange_keys()
            >>> options.set_auto_exchange_keys(True)
            >>> filename = get_plain_message_name('basic.txt')
            >>> with open(filename) as input_file:
            ...     crypto_message = CryptoMessage(EmailMessage(input_file))
            ...     key_block = crypto_message.get_public_key_header(EDWARD_LOCAL_USER)
            ...     key_block is not None
            ...     len(key_block) > 0
            True
            True
            >>> options.set_auto_exchange_keys(auto_exchange)
        '''

        header_lines = []
        if options.auto_exchange_keys():
            encryption_software_list = utils.get_encryption_software(from_user)
            
            # if no crypto and we're creating keys, then do so now
            if ((encryption_software_list is None or len(encryption_software_list) <= 0) and 
                email_in_domain(from_user) and 
                options.create_private_keys()):

                add_private_key(from_user)
                self.log_message("started to create a new key for {}".format(from_user))
                encryption_software_list = utils.get_encryption_software(from_user)
                
            if encryption_software_list is not None and len(encryption_software_list) > 0:
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
                pub_key = None
                try:
                    key_ok, __, __ = contacts.is_key_ok(from_user, encryption_software)
                    if key_ok:
                        key_crypto = KeyFactory.get_crypto(encryption_software)
                        pub_key = key_crypto.export_public(from_user)
                    else:
                        self.log_message('{} key is not valid for {}'.format(encryption_software, from_user))
                except CryptoException as crypto_exception:
                    self.log_message(crypto_exception.value)
                    
                if pub_key is None:
                    self.log_message('no {} public key for {}'.format(encryption_software, from_user))
                else:
                    # if there is a public key, then save it in the header
                    header_name = utils.get_public_key_header_name(encryption_software)
                    self.log_message("getting {} public key header block for {} using header {}".format(
                        encryption_software, from_user, header_name))

                    count = 0
                    for value in pub_key.split('\n'):
                        count += 1
                        key_block.append('{}-{}{}{}'.format(header_name, count, CryptoMessage.SEPARATOR, value))
                    if self.DEBUGGING:
                        self.log_message("key_block:\n{}".format(key_block))
        except MessageException as exception:
            self.log_message(format_exc())
            self.log_exception("Unable to get {} public key header for {}".format(encryption_software, from_user))
            self.log_exception(exception)

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
                key_block = utils.get_multientry_header(
                   self.get_email_message().get_message(), header_name)
                if key_block:
                    self.log_message("len key_block: {}".format(len(key_block)))
                else:
                    self.log_exception("No valid key {} block in header".format(encryption_software))
        except MessageException as exception:
            self.log_message(format_exc())
            self.log_exception("Unable to get {} public key block".format(encryption_software))
            self.log_exception(exception)
            
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
                encryption_name = KeyFactory.DEFAULT_ENCRYPTION_NAME
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
            encryption_software_list = utils.get_encryption_software(from_user)
            if encryption_software_list == None or len(encryption_software_list) <= 0:
                self.log_message("No encryption software for {}".format(from_user))
            else:
                self.email_message.add_header(
                    ACCEPTED_CRYPTO_SOFTWARE_HEADER, ','.join(encryption_software_list))

    def get_accepted_crypto_software(self):
        ''' 
            Gets list of accepted encryption software from email message header.
            Crypto services are comma delimited.
        '''

        encryption_software_list = []
        try:
            #  !!!! the accepted services list is unsigned! fix this!
            encryption_software_header = utils.get_first_header(
                self.email_message.get_message(), ACCEPTED_CRYPTO_SOFTWARE_HEADER)
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
            encryption_software_list = utils.get_encryption_software(from_user)
            if encryption_software_list == None or len(encryption_software_list) <= 0:
                self.log_message("Not adding fingerprint for {} because no crypto software".format(from_user))
            else:
                for encryption_name in encryption_software_list:
                    fingerprint, __, active = contacts.get_fingerprint(from_user, encryption_name)
                    if active and fingerprint is not None and len(fingerprint.strip()) > 0:
                        self.email_message.add_header(
                            PUBLIC_FINGERPRINT_HEADER.format(encryption_name.upper()), format_fingerprint(fingerprint))
                        self.log_message('added {} fingerprint'.format(encryption_name))
        except:
            self.log_message(format_exc())

    def get_default_key_from_header(self):
        ''' 
             Gets the default public key from the email_message header.
        '''

        return self.get_public_key_from_header(PUBLIC_KEY_HEADER)


    def get_public_key_from_header(self, header_name):
        ''' 
            Gets the public key from the email_message header.
        '''

        key = None
        try:
            key = utils.get_multientry_header(self.email_message.get_message(), header_name)
            if key is not None and len(key.strip()) <= 0:
                key = None
        except Exception:
            self.log_message("No public key found in email message")

        return key


    def has_public_key_header(self, encryption_name):
        ''' Return true if a public key header exists for the encryption software. '''

        has_key = False
        try:
            header_name = utils.get_public_key_header_name(encryption_name);
            email_message_key = utils.get_multientry_header(self.email_message.get_message(), header_name);
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

        self.log_message("set filtered: {}".format(filtered))
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

        self.log_message("set crypted: {}".format(crypted))
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


    def set_dropped(self, dropped):
        ''' 
            Sets whether this email_message has been dropped by a filter.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.set_dropped(True)
            >>> crypto_message.is_dropped()
            True
        '''

        self.log_message("set dropped: {}".format(dropped))
        self.dropped = dropped


    def is_dropped(self):
        ''' 
            Gets whether this email_message has been dropped by a filter.

            >>> crypto_message = CryptoMessage()
            >>> crypto_message.is_dropped()
            False
        '''

        return self.dropped


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
        self.log_message("Create private keys: {}".format(active))
    
        return active

    def add_tag_to_message(self):
        '''
            Add tag to a message.
            
            >>> from goodcrypto_tests.mail.message_utils import get_plain_message_name
            >>> with open(get_plain_message_name('basic.txt')) as input_file:
            ...    crypto_message = CryptoMessage(EmailMessage(input_file))
            ...    crypto_message.set_tag('Test tag')
            ...    crypto_message.add_tag_to_message()
            ...    final_message_string = crypto_message.get_email_message().to_string()
            ...    final_message_string.strip().find('Test tag') >= 0
            True
            True
            
            >>> crypto_message = CryptoMessage()
            >>> crypto_message.add_tag_to_message()
            False
        '''

        def add_tags_to_text(content, tags):
            ''' Add the tag to the text content. '''
            
            text_content = content
            text_content = '{}\n\n{}'.format(text_content, tags)
            self.log_message('added tags to text content')
            
            return text_content

        def add_tags_to_html(content, tags):
            ''' Add the tag to the html content. '''
            
            html_content = content
            index = html_content.lower().find('</body>')
            if index < 0:
                index = html_content.lower().find('</html>')
            if index < 0:
                html_content = '{}<div><hr>\n{}</div>'.format(html_content, tags)
            else:
                html_content = '{}<div><hr>\n{}</div>\n{}'.format(html_content[0:index], tags, html_content[:index])
            self.log_message('added tags to html content')

            return html_content

        tags_added = False
        tags = self.get_tag()
        if tags is None or len(tags.strip()) <= 0:
            self.log_message('No tags need to be added to message')
        else:
            content_type = self.get_email_message().get_message().get_content_type()
            self.log_message("message type is {}".format(content_type))
            if (content_type == mime_constants.TEXT_PLAIN_TYPE or 
                content_type == mime_constants.TEXT_HTML_TYPE):
                content = self.get_email_message().get_content()
                charset, self._last_charset = utils.get_charset(self.get_email_message().get_message())
                if content is None:
                    self.get_email_message().set_content(tags, content_type, charset=charset)
                    tags_added = True
                else:
                    if content.lower().find('<html>') > 0:
                        content = add_tags_to_html(content, tags)
                    else:
                        content = add_tags_to_text(self.get_email_message().get_content(), tags)
                    self.get_email_message().set_content(content, content_type, charset=charset)
                    tags_added = True
                
            elif content_type.startswith(mime_constants.MULTIPART_PRIMARY_TYPE):
                added_tags_to_text = False
                added_tags_to_html = False
                message = self.get_email_message().get_message()
                for part in message.get_payload():
                    part_content_type = part.get_content_type().lower()
                    if part_content_type == mime_constants.TEXT_PLAIN_TYPE and not added_tags_to_text:
                        content = add_tags_to_text(part.get_payload(), tags)
                        part.set_payload(content)
                        added_tags_to_text = True
                        
                    elif part_content_type == mime_constants.TEXT_HTML_TYPE and not added_tags_to_html:
                        content = add_tags_to_html(part.get_payload(), tags)
                        part.set_payload(content)
                        added_tags_to_html = True
                        
                    # no need to keep getting payloads if we've added the tags
                    if added_tags_to_text and added_tags_to_html:
                        break;

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

    def get_tag(self):
        ''' 
            Returns the tag to be added to the email_message text.

            >>> crypto_message = CryptoMessage()
            >>> tag = crypto_message.get_tag()
            >>> crypto_message.set_tag('test tag')
            >>> crypto_message.get_tag()
            'test tag'
            >>> crypto_message.set_tag(tag)
        '''

        if self.tag is None:
            tag = ''
        else:
            self.log_message("tag:\n{}".format(self.tag))
            tag = self.tag

        return tag

    def set_tag(self, new_tag):
        ''' 
            Sets the tag to be added to the email_message text.

            >>> crypto_message = CryptoMessage()
            >>> tag = crypto_message.get_tag()
            >>> crypto_message.set_tag(None)
            >>> crypto_message.get_tag()
            ''
            >>> crypto_message.set_tag('test tag')
            >>> crypto_message.get_tag()
            'test tag'
            >>> crypto_message.set_tag(tag)
        '''

        if new_tag is None or len(str(new_tag)) <= 0:
            self.log_message("tried to set blank tag")
        else:
            new_tag = str(new_tag)
            self.log_message("new tag:\n{}".format(new_tag))
            self.tag = new_tag


    def add_tag(self, new_tag):
        ''' 
            Add new tag to the existing tag.
        '''

        if new_tag is None or len(new_tag) <= 0:
            self.log_message("tried to add empty tag")
        else:
            if self.tag == None or len(self.tag) <= 0:
                self.log_message("adding to an empty tag:\n{}".format(new_tag))
                self.tag = new_tag
            else:
                self.log_message("adding to tag:\n{}".format(new_tag))
                if new_tag.startswith('.'):
                    self.tag += new_tag
                else:
                    self.tag = '{}\n{}'.format(self.tag, new_tag)
    
    def add_prefix_to_tag(self, new_tag):
        ''' 
            Add prefix to email_message tag.

            >>> crypto_message = CryptoMessage()
            >>> tag = crypto_message.get_tag()
            >>> crypto_message.set_tag('test tag')
            >>> crypto_message.add_prefix_to_tag(None)
            >>> crypto_message.get_tag()
            'test tag'
            >>> crypto_message.add_prefix_to_tag('prefix')
            >>> crypto_message.get_tag().startswith('prefix')
            True
            >>> crypto_message.set_tag(tag)
        '''

        if new_tag is None or len(new_tag) <= 0:
            self.log_message("tried to add empty prefix tag")
        else:
            self.log_message("adding prefix to tag:\n{}".format(new_tag))
            if self.tag == None or len(self.tag) <= 0:
                self.tag = '{}\n'.format(new_tag)
            else:
                self.tag = '{}\n{}'.format(new_tag, self.tag)


    def add_tag_once(self, new_tag):
        ''' 
            Add new tag only if it isn't already in the tag.

            >>> crypto_message = CryptoMessage()
            >>> tag = crypto_message.get_tag()
            >>> crypto_message.add_tag_once('test tag')
            >>> crypto_message.get_tag().strip()
            'test tag'
            >>> crypto_message.add_tag_once('test tag')
            >>> crypto_message.get_tag().strip()
            'test tag'
            >>> crypto_message.add_tag_once(None)
            >>> crypto_message.get_tag().strip()
            'test tag'
            >>> crypto_message.set_tag(tag)
        '''
        if new_tag is None:
            pass
        elif self.tag is None or self.tag.find(new_tag) < 0:
            self.add_tag(new_tag)


    def add_prefix_to_tag_once(self, new_tag):
        ''' 
            Add new tag prefix only if it isn't already in the tag.

            >>> crypto_message = CryptoMessage()
            >>> tag = crypto_message.get_tag()
            >>> crypto_message.set_tag('test tag')
            >>> crypto_message.add_prefix_to_tag_once('test tag')
            >>> crypto_message.get_tag().strip()
            'test tag'
            >>> crypto_message.add_prefix_to_tag_once(None)
            >>> crypto_message.get_tag().strip()
            'test tag'
            >>> crypto_message.add_prefix_to_tag_once('prefix')
            >>> crypto_message.get_tag().startswith('prefix')
            True
            >>> crypto_message.set_tag(tag)
        '''

        if new_tag is None:
            pass
        elif self.tag == None or self.tag.find(new_tag) < 0:
            self.add_prefix_to_tag(new_tag)


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
        ExceptionLog.log_message(exception)

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

