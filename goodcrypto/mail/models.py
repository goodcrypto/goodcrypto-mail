'''
    Models for Mail app.
    
    Better to use the goodcrypto.mail classes (e.g., Contacts, ContactsPasscodes) 
    to access data than access it directly via the Models. Using these classes will increase 
    the probability of future compatibility in case GoodCrypto uses another way to store data
    or moves to another framework which doesn't interface with databases the same way as django.

    Copyright 2014 GoodCrypto
    Last modified: 2014-10-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from django.core import validators
from django.db import models
from django.db.models.signals import post_delete, post_save

from goodcrypto.mail import constants, international_strings
from goodcrypto.mail.model_signals import post_save_contacts_crypto, post_delete_contacts_crypto, post_save_options
from goodcrypto.mail.options import get_domain
from goodcrypto.mail.utils import email_in_domain, gen_passcode
from goodcrypto.utils.internationalize import translate
# do not use LogFile because it references models.System
from syr.log import get_log

_log = get_log()

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
    
    name = models.CharField(translate('Name'),
       max_length=100, unique=True, blank=False,
       help_text=translate('Name of the encryption software (e.g., GPG).'))

    active = models.BooleanField(translate('Active?'), default=True,
       help_text=translate('Is encryption software installed and available?'))
    
    classname = models.CharField(translate('Classname'),
       max_length=100, blank=True, null=True,
       help_text=translate("Leave blank unless you are using encryption software not supplied by GoodCrypto. See GoodCrypto's OCE docs for more details."))

    def __unicode__(self):
        return '{}'.format(self.name)

    class Meta:
        verbose_name = translate('encryption software')
        verbose_name_plural = translate('encryption software')
        
    
class LongEmailField(models.CharField):
    ''' A RFC3696/5321 compatible email address. 
    
        Django's default EmailField limits the max length to 75 characters.
    '''
    default_validators = [validators.validate_email]
    description = translate("Email address")

    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = kwargs.get('max_length', 254)
        models.CharField.__init__(self, *args, **kwargs)

    def formfield(self, **kwargs):
        from django import forms
        
        # As with CharField, this will cause email validation to be performed twice.
        defaults = {
            'form_class': forms.EmailField,
        }
        defaults.update(kwargs)
        return super(LongEmailField, self).formfield(**defaults)


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
    
    email = LongEmailField(translate('Email'), blank=False,
       unique=True, help_text=translate('Email address of someone that uses encryption software.'))

    user_name = models.CharField(translate('User name'),
       max_length=100, blank=True, null=True,
       help_text=translate('Printable name for the contact. It is not required, but strongly recommended as encryption software often requires it.'))

    def save(self, *args, **kwargs):
        # maintain all addresses in lower case
        if self.email:
            self.email = self.email.lower()
        super(Contact, self).save(*args, **kwargs)
        # OperationalError: database is locked

    def __unicode__(self):
        if self.user_name and len(self.user_name.strip()) > 0:
            return '{} <{}>'.format(self.user_name, self.email)
        else:
            return '{}'.format(self.email)

    class Meta:
        verbose_name = translate('contact')
        verbose_name_plural = translate('contacts')


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
    
    contact = models.ForeignKey(Contact,
       help_text=translate('Email address.'))
    
    encryption_software = models.ForeignKey(EncryptionSoftware,
       help_text=translate('Encryption software used by this contact.'))

    fingerprint = models.CharField(translate('Fingerprint'),
       max_length=100, blank=True, null=True,
       help_text=translate("The fingerprint for the contact's public key."))

    verified = models.BooleanField(translate('Verified?'), default=False,
       help_text=translate('You should verify this fingerprint in a secure manner, not via email.'))
    
    def __unicode__(self):
        return '{}: {}'.format(self.contact, self.encryption_software)

    class Meta:
        verbose_name = translate("contact's encryption software")
        verbose_name_plural = translate("contacts' encryption software")

        unique_together = ('contact', 'encryption_software')
post_save.connect(post_save_contacts_crypto, sender=ContactsCrypto)
post_delete.connect(post_delete_contacts_crypto, sender=ContactsCrypto)

class ContactsPasscode(models.Model):
    '''
        Private passcodes, also known as passphrases, for contacts.
        
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
        >>> contacts_passcode = ContactsPasscode.objects.create(contacts_encryption=contacts_crypto, 
        ...  passcode='secret', auto_generated=False)
        >>> contacts_passcode is not None
        True
        >>> contact.delete()
        >>> gpg.delete()
        >>> TESTS_RUNNING = False
    '''
    
    EXPIRE_IN_DAYS = 'd'
    EXPIRE_IN_WEEKS = 'w'
    EXPIRE_IN_MONTHS = 'm'
    EXPIRE_IN_YEARS = 'y'
    EXPIRATION_CHOICES = (
    (EXPIRE_IN_DAYS, 'Days'),
    (EXPIRE_IN_WEEKS, 'Weeks'),
    (EXPIRE_IN_MONTHS, 'Months'),
    (EXPIRE_IN_YEARS, 'Years'),)

    # default time until key expires: 1 year
    DEFAULT_EXPIRATION_TIME = 1
    DEFAULT_EXPIRATION_PERIOD = EXPIRE_IN_YEARS

    contacts_encryption = models.OneToOneField(ContactsCrypto,
       help_text=translate('Encryption software used by a contact.'))

    passcode = models.CharField(translate('Passcode'),
       max_length=constants.PASSCODE_MAX_LENGTH, blank=True, null=True,
       help_text=translate(
         'Secret passcode, also known as a passphrase, used with this encryption software. It is recommended that you allow GoodCrypto to create the passcode because it should be long and difficult to remember.'))

    auto_generated = models.BooleanField(translate('Auto generate?'), default=True,
       help_text=translate('Add a check mark if you want GoodCrypto to generate a private passcode.'))
    
    expires_in = models.PositiveSmallIntegerField(translate('Expires in'), default=DEFAULT_EXPIRATION_TIME,
       help_text=translate('The quantity of time the key is valid. If set to 0, it never expires which is not recommended.'))
    
    expiration_unit = models.CharField(max_length=1, default=DEFAULT_EXPIRATION_PERIOD, choices=EXPIRATION_CHOICES,
       help_text=translate('The unit of time the key is valid.'))
    
    last_notified = models.DateTimeField(translate('Last notified'), blank=True, null=True,
       help_text=translate('Last date a notice about this key was sent to the user.'))
    
    def __unicode__(self):
        return '{}'.format(self.contacts_encryption)

    class Meta:
        verbose_name = translate('passcode')
        verbose_name_plural = translate('passcodes')

class Options(models.Model):
    ''' 
        GoodCrypto Mail settings. 
    
        >>> options = Options.objects.all()
        >>> options is not None
        True
        >>> len(options) == 1
        True
    '''

    DEFAULT_GOODCRYPTO_LISTEN_PORT = 10025
    DEFAULT_MTA_LISTEN_PORT = 10026
    
    mail_server_address = models.CharField(translate('Mail server address'),
       max_length=100, blank=True, null=True,
       help_text=translate("The address for the domain's mail transport agent (e.g., postfix, sendmail)."))
    
    goodcrypto_listen_port = models.PositiveSmallIntegerField(translate('MTA inbound port'),
       default=DEFAULT_GOODCRYPTO_LISTEN_PORT,
       help_text=translate("The port where the goodcrypto mail server listens for messages FROM the MTA."))
    
    mta_listen_port = models.PositiveSmallIntegerField(translate('MTA outbound port'),
       default=DEFAULT_MTA_LISTEN_PORT,
       help_text=translate("The port where the MTA listens for messages FROM the the goodcrypto mail server."))
    
    auto_exchange = models.BooleanField(translate('Auto exchange keys'), default=True,
       help_text=translate("Automatically exchange keys and always include the sender's key in the header."))
    
    validation_code = models.CharField(translate('Validation code'),
       max_length=100, blank=True, null=True,
       help_text=translate('A secret code added to all decrypted messages so you have increased confidence the message was decrypted by GoodCrypto.'))
    
    accept_self_signed_certs = models.BooleanField(translate('Accept self signed certs'), default=True,
       help_text=translate('Recognize self signed certificates.'))
    
    create_private_keys = models.BooleanField(translate('Create private keys'), default=True,
       help_text=translate("Generate private keys for users who don't have any keys automatically."))
    
    days_between_key_alerts = models.PositiveSmallIntegerField(translate('Days between key alerts'),  default=1,
       help_text=translate("GoodCrypto sends alerts about errors with keys. How many days between notices would you like to users to receive those notices?."))
    
    clear_sign = models.BooleanField(translate('Clear sign mail'), default=False,
       help_text=translate("If you elect to clear sign, then all outbound encrypted mail will include the sender's encrypted signature."))
    
    filter_html = models.BooleanField(translate('Filter HTML'), default=True,
       help_text=translate("GoodCrypto can remove HTML that may harm your system."))

    use_encrypted_content_type = models.BooleanField(translate('Encrypt entire message'), default=False,
       help_text=translate("Select this option if you want the entire message, not just the body and attachments, encrypted. You should only use this if you know your only exchange encrypted mail with contacts support the special 'EncryptedContentType'."))
    
    encrypted_subject = models.CharField(translate('Subject for encrypted messages'), default='Message',
       max_length=100, blank=True, null=True,
       help_text=translate("If you opt to encrypt the entire messages, then whatever you enter in this field will be the subject for your encrypted message."))

    max_message_length = models.PositiveSmallIntegerField(translate('Max kilobytes of a message'), default=5120,
       help_text=translate('The maximum size, in K, of messages, including attachments, accepted. This helps prevent your mail system from being DOSed.'))

    use_us_standards = models.BooleanField(translate('Use US standards'), default=False,
       help_text=translate("Use the standards supported by US government. We strongly recommend you set this to False."))
    
    domain = models.CharField(max_length=100, blank=True, null=True)

    subscription = models.CharField(max_length=100, blank=True, null=True)
    
    debugging_enabled = models.BooleanField(international_strings.ENABLE_DEBUGGING_FIELD, default=True,
       help_text=international_strings.ENABLE_DEBUGGING_HELP)
    
    def __unicode__(self):
        return '{}'.format(self.mail_server_address)

    class Meta:
        verbose_name = translate('options')
        verbose_name_plural = translate('options')
post_save.connect(post_save_options, sender=Options)

