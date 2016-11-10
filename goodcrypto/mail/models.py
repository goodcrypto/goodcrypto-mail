'''
    Models for Mail app.

    Better to use the goodcrypto.mail classes (e.g., contacts, crypto_software)
    to access data than access it directly via the Models. Using those classes will increase
    the probability of future compatibility in case GoodCrypto uses another way to store data
    or moves to another framework which doesn't interface with databases the same way as django.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-02-19

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from django.core import validators
from django.db import models
from django.db.models.signals import pre_delete, post_save

from goodcrypto.mail import constants, model_signals
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.utils import format_fingerprint
from goodcrypto.utils import i18n
# do not use LogFile because it references models.Options
from syr.log import get_log

_log = get_log()

HOURS = i18n('Hours')
DAYS = i18n('Days')
WEEKS = i18n('Weeks')
MONTHS = i18n('Months')
YEARS = i18n('Years')


class EncryptionSoftware(models.Model):
    '''
        The encryption software available to goodcrypto.

        Create some encryption software
        >>> test_gpg = EncryptionSoftware.objects.create(
        ... name='TestAnotherGPG', active=True, classname='goodcrypto.oce.gpg_plugin.GPGPlugin')
        >>> str(test_gpg)
        'TestAnotherGPG'
        >>> test_gpg.__unicode__()
        'TestAnotherGPG'
        >>> test_gpg.delete()
    '''

    name = models.CharField(i18n('Name'),
       max_length=100, unique=True, blank=False, null=False,
       help_text=i18n('Name of the encryption software (e.g., GPG).'))

    active = models.BooleanField(i18n('Active?'), default=True,
       help_text=i18n('Is encryption software installed and available?'))

    classname = models.CharField(i18n('Classname'),
       max_length=100, blank=True, null=True,
       help_text=i18n("Leave blank unless you are using encryption software not supplied by GoodCrypto."))

    def __unicode__(self):
        return '{}'.format(self.name)

    class Meta:
        verbose_name = i18n('encryption software')
        verbose_name_plural = verbose_name


class Keyserver(models.Model):
    '''
        List of keyservers to obtain public keys.

    '''

    name = models.CharField(i18n('Name'),max_length=100,
       help_text=i18n('Name of keyserver.'))

    encryption_software = models.ForeignKey(EncryptionSoftware, default=1,
       help_text=i18n('Type of encryption software for this keyserver.'))

    active = models.BooleanField(i18n('Active?'), default=True,
       help_text=i18n('Should this keyserver be used to find keys?'))

    last_date = models.DateField(i18n('Last attempt'), blank=True, null=True,
       help_text=i18n('The last date attempted to use this keyserver.'))

    last_status = models.CharField(i18n('Status'),max_length=50,
       default=constants.DEFAULT_KEYSERVER_STATUS,
       help_text=i18n('The status of the last contact to this keyserver.'))

    def __unicode__(self):
        return '{}'.format(self.name)

class Contact(models.Model):
    '''
        Email addresses that use encryption.

        Contains both users whose email goodcrypto encrypt/decrypts and their correspondents.

        >>> # In honor of Arlo Breault, a developer for the Tor project.
        >>> # Create a contact with a full user name and email address
        >>> email = 'arlo@goodcrypto.remote'
        >>> contact = Contact.objects.create(email=email, user_name='Arlo')
        >>> contact.email
        'arlo@goodcrypto.remote'
        >>> contact.user_name
        'Arlo'
        >>> str(contact)
        'Arlo <arlo@goodcrypto.remote>'
        >>> contact.__unicode__()
        'Arlo <arlo@goodcrypto.remote>'
        >>> contact.delete()

        >>> # In honor of Andrea Shepard, a core Tor developer.
        >>> # Create a contact with only an email address
        >>> contact = Contact.objects.create(email='andrea@GoodCrypto.remote')
        >>> str(contact)
        'andrea@goodcrypto.remote'
        >>> contact.delete()

        >>> # In honor of Paul Syverson, one of the original designers of Tor.
        >>> # Create a contact with a mixed case email address
        >>> contact = Contact.objects.create(email='Paul@GoodCrypto.Remote')
        >>> contact.__unicode__()
        'paul@goodcrypto.remote'
        >>> contact.delete()

    '''

    Outbound_Encrypt_Policies = [
        (constants.USE_GLOBAL_OUTBOUND_SETTING, i18n('Use global setting')),
        (constants.ALWAYS_ENCRYPT_OUTBOUND, i18n('Always')),
        (constants.NEVER_ENCRYPT_OUTBOUND, i18n('Never')),
    ]

    email = models.EmailField(i18n('Email'), blank=False, null=False,
       unique=True, help_text=i18n('Email address of someone that uses encryption software.'))

    user_name = models.CharField(i18n('User name'),
       max_length=100, blank=True, null=True,
       help_text=i18n('Printable name for the contact. Strongly recommended.'))

    outbound_encrypt_policy = models.CharField(i18n('Encrypt to contact'), max_length=10,
       choices=Outbound_Encrypt_Policies, default=constants.DEFAULT_OUTBOUND_ENCRYPT_POLICY,
       help_text=i18n('<br/>"Always" means encrypt or bounce. "Never" means plain text only. See <a href="/admin/mail/options/">Mail Protection</a> for the global setting.'))

    def save(self, *args, **kwargs):
        # maintain all addresses in lower case
        if self.email:
            self.email = self.email.lower()
        super(Contact, self).save(*args, **kwargs)

    def __unicode__(self):
        if self.user_name and len(self.user_name.strip()) > 0:
            return '{} <{}>'.format(self.user_name, self.email)
        else:
            return '{}'.format(self.email)

    class Meta:
        verbose_name = i18n('contact')
        verbose_name_plural = i18n('contacts')


class ContactsCrypto(models.Model):
    '''
        The encryption software used by contacts.

        There can be multiple records for each contact because
        ideally, each contact can handle encrypting messages with
        multiple encryption programs.

        Contacts include the local users as well as those people they correspond.

        >>> # In honor of William Binney, a whistleblower about Trailblazer, a NSA mass surveillance project.
        >>> from django.db import IntegrityError
        >>> contact = Contact.objects.create(email='william@goodcrypto.remote')
        >>> gpg = EncryptionSoftware.objects.create(
        ... name='TestWilliamGPG', active=True, classname='goodcrypto.oce.gpg_plugin.GPGPlugin')
        >>> contacts_crypto = ContactsCrypto.objects.create(contact=contact, encryption_software=gpg)
        >>> str(contacts_crypto)
        'william@goodcrypto.remote: TestWilliamGPG'
        >>> contacts_crypto.__unicode__()
        'william@goodcrypto.remote: TestWilliamGPG'
        >>> contact.user_name = 'William'
        >>> contact.save()
        >>> contacts_crypto.__unicode__()
        'William <william@goodcrypto.remote>: TestWilliamGPG'
        >>> try:
        ...     ContactsCrypto.objects.create(contact=contact, encryption_software=gpg)
        ... except IntegrityError as error:
        ...     str(error).strip().startswith('duplicate key value violates unique constraint "mail_contactscrypto_contact_id_encryption_software_id_key"')
        True
        >>> contacts_crypto.delete()
        >>> contact.delete()
        >>> gpg.delete()
    '''

    KEY_SOURCES = [
        (constants.AUTO_GENERATED, i18n('Automatically generated')),
        (constants.MESSAGE_HEADER, i18n('Message header')),
        (constants.KEYSERVER, i18n('Keyserver')),
        (constants.MANUALLY_IMPORTED, i18n('Manually imported')),
    ]

    contact = models.ForeignKey(Contact,
       help_text=i18n('Email address.'))

    encryption_software = models.ForeignKey(EncryptionSoftware, blank=True, null=True,
       help_text=i18n('Encryption software used by this contact.'))

    fingerprint = models.CharField(i18n('Fingerprint'),
       max_length=100, blank=True, null=True,
       help_text=i18n("The fingerprint for the contact's public key."))

    verified = models.BooleanField(i18n('Verified?'), default=False,
       help_text=i18n('We strongly recommend that you verify this fingerprint in a secure manner, not via email.'))

    source = models.CharField(i18n('Source'),max_length=10,
       choices=KEY_SOURCES, blank=True, null=True,
       help_text=i18n('The way that the key was introduced into your GoodCrypto private server.'))

    def save(self, *args, **kwargs):
        # maintain all addresses in lower case
        if not self.encryption_software or self.encryption_software is None:
            self.encryption_software = EnryptionSoftware.objects.all()[0]
        if self.fingerprint is not None:
            self.fingerprint = format_fingerprint(self.fingerprint)
        super(ContactsCrypto, self).save(*args, **kwargs)

    def __unicode__(self):
        return '{}: {}'.format(self.contact, self.encryption_software)

    class Meta:
        verbose_name = i18n("contact's encryption software")
        verbose_name_plural = verbose_name

        unique_together = ('contact', 'encryption_software')
post_save.connect(model_signals.post_save_contacts_crypto, sender=ContactsCrypto)
pre_delete.connect(model_signals.post_delete_contacts_crypto, sender=ContactsCrypto)

class UserKey(models.Model):
    '''
        Extra details about local users' keys.

        We'd prefer to keep salted hashes, but the underlying crypto software wants the
        passphrase in plain text. It's important that the goodcrypto server is kept behind
        a strong firewall.

        This table contains all the passcodes for contacts whose email goodcrypto manages.
        Most contacts will not have a record in this table because GoodCrypto only manages
        email for local users.

        There is one record in this table for each contact's encryption software
        *if* goodcrypto encrypts and decrypts messages for that contact.

        >>> # In honor of Professional Academic Officer H, who co-signed letter and refused to serve in operations
        >>> # involving the occupied Palestinian territories because of the widespread surveillance of innocent residents.
        >>> from django.core.exceptions import ValidationError
        >>> from goodcrypto.mail.model_signals import TESTS_RUNNING
        >>> TESTS_RUNNING = True
        >>> gpg = EncryptionSoftware.objects.create(
        ...   name='TestHGPG', active=True, classname='goodcrypto.oce.gpg_plugin.GPGPlugin')
        >>> contact = Contact.objects.create(email='officer_h@goodcrypto.local')
        >>> contacts_crypto = ContactsCrypto.objects.create(contact=contact, encryption_software=gpg)
        >>> user_key = UserKey.objects.create(contacts_encryption=contacts_crypto,
        ...  passcode='secret', auto_generated=False)
        >>> user_key is not None
        True
        >>> contact.delete()
        >>> gpg.delete()
        >>> TESTS_RUNNING = False
    '''

    EXPIRE_IN_DAYS = constants.DAYS_CODE
    EXPIRE_IN_WEEKS = constants.WEEKS_CODE
    EXPIRE_IN_MONTHS = constants.MONTHS_CODE
    EXPIRE_IN_YEARS = constants.YEARS_CODE
    EXPIRATION_CHOICES = (
      (EXPIRE_IN_DAYS, i18n('Days')),
      (EXPIRE_IN_WEEKS, i18n('Weeks')),
      (EXPIRE_IN_MONTHS, i18n('Months')),
      (EXPIRE_IN_YEARS, i18n('Years')),
    )

    # default time until key expires: 2 years
    DEFAULT_EXPIRATION_TIME = 2
    DEFAULT_EXPIRATION_PERIOD = EXPIRE_IN_YEARS

    contacts_encryption = models.OneToOneField(ContactsCrypto,
       help_text=i18n('Encryption software used by a contact.'))

    passcode = models.CharField(i18n('Passcode'),
       max_length=constants.PASSCODE_MAX_LENGTH, blank=True, null=True,
       help_text=i18n(
         'Secret passcode, also known as a passphrase, used with this encryption software. It is recommended that you allow GoodCrypto to create the passcode because it should be long and difficult to remember.'))

    auto_generated = models.BooleanField(i18n('Auto generate?'), default=True,
       help_text=i18n('Add a check mark if you want GoodCrypto to generate a private passcode.'))

    expires_in = models.PositiveSmallIntegerField(i18n('Expires in'), default=DEFAULT_EXPIRATION_TIME,
       help_text=i18n('The quantity of time the key is valid. If set to 0, it never expires which is not recommended.'))

    expiration_unit = models.CharField(max_length=1,
        default=DEFAULT_EXPIRATION_PERIOD, choices=EXPIRATION_CHOICES,
       help_text=i18n('The unit of time the key is valid.'))

    def __unicode__(self):
        return '{}'.format(self.contacts_encryption)

    class Meta:
        verbose_name = i18n('user key')
        verbose_name_plural = i18n('user keys')

class MessageHistory(models.Model):
    '''
        Log of messages that were encrypted or decrypted.

        Each user can verify a message was encrypted before it was sent or it
        was decrypted by the GoodCrypto server. Users can only see details about
        messages they sent or received. This eliminates concerns about a message's
        tag being spoofed by a third party.
    '''

    INBOUND_MESSAGE = '1'
    OUTBOUND_MESSAGE = '2'
    MESSAGE_DIRECTIONS = (
      (INBOUND_MESSAGE, i18n('Inbound')),
      (OUTBOUND_MESSAGE, i18n('Outbound')),
    )
    MAX_ENCRYPTION_PROGRAMS = 50
    MAX_MESSAGE_DATE = 50
    MAX_SUBJECT = 130  # this is the default for Outlook, Thunderbird, and gmail
    MAX_MESSAGE_ID = 100
    MAX_VERIFICATION_CODE = 25

    sender = models.EmailField(i18n('Sender email'), blank=False, unique=False,
              help_text=i18n('From user email address.'))

    recipient = models.EmailField(i18n('Recipient email'), blank=False,  unique=False,
                  help_text=i18n('To user email address.'))

    direction = models.CharField(max_length=1, choices=MESSAGE_DIRECTIONS, blank=True, null=True,
       help_text=i18n('Shows whether the message was inbound or outbound.'))

    content_protected = models.BooleanField(default=False,
        help_text=i18n('True if the content was protected with a personal key.'))

    metadata_protected = models.BooleanField(default=False,
        help_text=i18n('True if the metadata was protected during transit.'))

    private_signers = models.TextField(blank=True, null=True,
        help_text=i18n('The signers of an encrypted message, if any. Also, shows whether the signer was digitally verified or not.'))

    clear_signers = models.TextField(blank=True, null=True,
        help_text=i18n('The clear signers of a message, if any. Also, shows whether the signer was digitally verified or not.'))

    dkim_signed = models.BooleanField(default=False,
        help_text=i18n('True if the message had a DKIM signature.'))

    dkim_sig_verified = models.BooleanField(default=False,
        help_text=i18n('True if the DKIM signature was verified.'))

    encryption_programs = models.CharField(max_length=MAX_ENCRYPTION_PROGRAMS,
       help_text=i18n('List of encryption software programs used with this message.'))

    message_date = models.CharField(max_length=MAX_MESSAGE_DATE,
       help_text=i18n("The date from the message header or if there isn't one, then the date when message processed."))

    subject = models.CharField(max_length=MAX_SUBJECT, help_text=i18n("The subject from the message header."))

    message_id = models.CharField(i18n('Message ID'), max_length=MAX_MESSAGE_ID,
       help_text=i18n("The ID for the message from the header."))

    verification_code = models.CharField(i18n('Verification code'), max_length=MAX_VERIFICATION_CODE,
       help_text=i18n("The special code generated when the message is encrypted/decrypted."))

    def __unicode__(self):
        return '{}: {} at {}'.format(self.sender, self.recipient, self.message_date)

    class Meta:
        verbose_name = i18n('message history')
        verbose_name_plural = i18n('message history')

class InternalSettings(models.Model):
    '''
        Internal settings, only changeable by code.

        >>> internal_settings = InternalSettings.objects.all()
        >>> internal_settings is not None
        True
        >>> len(internal_settings) == 1
        True
    '''

    domain = models.CharField(max_length=100, blank=True, null=True)

    date_queue_last_active = models.DateTimeField(blank=True, null=True)

    def __unicode__(self):
        return self.domain

    class Meta:
        verbose_name = i18n('internal settings')
        verbose_name_plural = i18n('internal settings')
post_save.connect(model_signals.post_save_internal_settings, sender=InternalSettings)

class Options(models.Model):
    '''
        GoodCrypto Mail settings controled by the admin.

        >>> options = Options.objects.all()
        >>> options is not None
        True
        >>> len(options) == 1
        True
    '''

    DEFAULT_GOODCRYPTO_LISTEN_PORT = 10027
    DEFAULT_MTA_LISTEN_PORT = 10028

    DEFAULT_PADDING_MESSAGE_KB = 1024

    DEFAULT_FREQUENCY_PERIOD = constants.HOURS_CODE
    FREQUENCY_CHOICES = (
      (constants.HOURS_CODE, i18n('Hourly')),
      (constants.DAYS_CODE, i18n('Daily')),
      (constants.WEEKS_CODE, i18n('Weekly')),
    )

    CLEAR_SIGN_POLICY_CHOICES = (
      (constants.CLEAR_SIGN_WITH_DOMAIN_KEY, i18n("domain's key")),
      (constants.CLEAR_SIGN_WITH_SENDER_KEY, i18n("sender's key if there is one")),
      (constants.CLEAR_SIGN_WITH_SENDER_OR_DOMAIN, i18n("sender's key if there is one, otherwise domain's key")),
    )

    DKIM_POLICY_CHOICES = (
      (constants.DKIM_WARN_POLICY, i18n('warn')),
      (constants.DKIM_DROP_POLICY, i18n('drop')),
    )

    mail_server_address = models.CharField(i18n('Mail server address'),
       max_length=100, blank=True, null=True,
       help_text=i18n("The address for the domain's mail transport agent (e.g., postfix, exim)."))

    goodcrypto_listen_port = models.PositiveSmallIntegerField(i18n('MTA inbound port'),
       default=DEFAULT_GOODCRYPTO_LISTEN_PORT,
       help_text=i18n("The port where the goodcrypto mail server listens for messages FROM the MTA."))

    mta_listen_port = models.PositiveSmallIntegerField(i18n('MTA outbound port'),
       default=DEFAULT_MTA_LISTEN_PORT,
       help_text=i18n("The port where the MTA listens for messages FROM the the goodcrypto mail server."))

    auto_exchange = models.BooleanField(i18n('Exchange public keys P2P'), default=True,
       help_text=i18n("Automatically exchange public keys P2P. Always include the sender's public key in the header."))

    create_private_keys = models.BooleanField(i18n('Create keys'), default=True,
       help_text=i18n("Generate keys for users who don't have one."))

    clear_sign = models.BooleanField(i18n('Clear sign mail'), default=False,
       help_text=i18n("Outbound mail will include an encrypted signature."))

    clear_sign_policy = models.CharField(i18n('Clear sign policy'), max_length=10,
       blank=True, null=True,
       default=constants.DEFAULT_CLEAR_SIGN_POLICY, choices=CLEAR_SIGN_POLICY_CHOICES,
       help_text=i18n("What key to use to clear sign a message. The most private is the domain key."))

    filter_html = models.BooleanField(i18n('Filter HTML'), default=True,
       help_text=i18n("Remove dangerous HTML that may compromise end users' computers."))

    debugging_enabled = models.BooleanField(i18n('Enable diagnostic logs'), default=True,
       help_text=i18n('Activate logs to help debug unexpected behavior.'))

    require_outbound_encryption = models.BooleanField(i18n('Require outbound encryption'), default=False,
       help_text=i18n("All outbound messages will be encrypted or bounced. You can override by Contact."))

    require_key_verified = models.BooleanField(i18n('Require verify new keys'), default=False,
       help_text=i18n("Do not use a new public key until it is flagged as verified in the database."))

    # we default to false to make it easier for the user to verify fingerprints, but for security
    # it's much better to restrict access to logged in users so if a non-authorized user accesses
    # the site, they can't determine whether someone in the company is communicating with someone else
    login_to_view_fingerprints = models.BooleanField(i18n('Require login to view fingerprints'), default=False,
       help_text=i18n("Require that a user login to view any fingerprints."))

    # see comment above about login_to_view_fingerprints
    login_to_export_keys = models.BooleanField(i18n('Require login to export keys'), default=False,
       help_text=i18n("Require that a user login to export any public keys."))

    goodcrypto_server_url = models.CharField(i18n('GoodCrypto server url'),
        max_length=100, blank=True, null=True,
        help_text=i18n("The full url to reach your GoodCrypto server's website, including the port. For example, http://194.10.34.1:8080 or https://194.10.34.1:8443"))

    encrypt_metadata = models.BooleanField(i18n('Encrypt metadata'), default=True,
       help_text=i18n("Of course, until other packages implement this open source protocol for metadata protection, you may need GoodCrypto on both ends."))

    bundle_and_pad = models.BooleanField(i18n('Padding and packetization'), default=True,
       help_text=i18n("Bundle and pad messages by domain. You may encounter performance issues. Of course, until other packages implement this open source protocol for metadata protection, you may need GoodCrypto on both ends."))

    bundle_frequency = models.CharField(i18n('Frequency'), max_length=1,
       blank=True, null=True,
       default=DEFAULT_FREQUENCY_PERIOD, choices=FREQUENCY_CHOICES,
       help_text=i18n("How often to send padded and packetized messages."))

    bundle_message_kb = models.PositiveIntegerField(i18n('Packet size'),
       blank=True, null=True, default=DEFAULT_PADDING_MESSAGE_KB,
       help_text=i18n('The size of a message bundle in Kbytes. Messages larger than this will be returned.'))

    add_dkim_sig = models.BooleanField(i18n('Add DKIM signature'), default=False,
       help_text=i18n("All outbound mail will include the domain's DKIM signature."))

    verify_dkim_sig = models.BooleanField(i18n('Verify DKIM signatures'), default=False,
       help_text=i18n("All inbound mail with a DKIM signature will be verified."))

    dkim_delivery_policy = models.CharField(i18n('DKIM delivery policy'), max_length=10,
       blank=True, null=True,
       default=constants.DEFAULT_DKIM_POLICY, choices=DKIM_POLICY_CHOICES,
       help_text=i18n("What to do with an inbound message that contains a bad DKIM signature."))

    dkim_public_key = models.CharField(i18n('DKIM public key'),
       max_length=1000, blank=True, null=True,
       help_text=i18n("The public key for DKIM. Enter this key into a TXT record for your DNS. <a href=\"https://goodcrypto.com/qna/knowledge-base/crypt-options#DkimPublicKey\">Learn more</a>"))

    use_keyservers = models.BooleanField(i18n('Use keyservers'), default=True,
       help_text=i18n("Use keyservers to find keys for contacts without keys."))

    add_long_tags = models.BooleanField(i18n('Add long tags'), default=False,
       help_text=i18n("Add detailed tags describing the security features of the message."))

    def __unicode__(self):
        if self.mail_server_address is not None and len(self.mail_server_address) > 0:
            return self.mail_server_address
        else:
            return ''

    class Meta:
        verbose_name = i18n('global options')
        verbose_name_plural = i18n('global options')
post_save.connect(model_signals.post_save_options, sender=Options)


