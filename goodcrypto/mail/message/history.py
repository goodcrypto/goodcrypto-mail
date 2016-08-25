'''
    Copyright 2015-2016 GoodCrypto.
    Last modified: 2016-02-04

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.

    Manage logging messages encrypted and decrypted by the GoodCrypto server to
    prevent others spoofing the security of a message.
'''
import os, re, urllib
from datetime import datetime
from time import gmtime, strftime

from django.db.models import Q

from goodcrypto.mail.models import MessageHistory
from goodcrypto.mail.utils import gen_password
from goodcrypto.mail.message.constants import SIGNER_VERIFIED
from goodcrypto.mail.message.inspect_utils import get_message_id
from goodcrypto.utils import get_email
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr.mime_constants import DATE_KEYWORD, SUBJECT_KEYWORD

_log = None
DEBUGGING = False

def add_outbound_record(crypto_message, verification_code):
    '''
        Add a history record so the user can verify what security measures were made to an outbound message.
    '''
    try:
        add_record(crypto_message, MessageHistory.OUTBOUND_MESSAGE, verification_code=verification_code)
        log_message('added outbound history record from {}'.format(crypto_message.smtp_sender()))
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

def add_inbound_record(crypto_message, verification_code):
    '''
        Add a history record so the user can verify what security measures were made to an inbound message.
    '''
    try:
        add_record(crypto_message, MessageHistory.INBOUND_MESSAGE, verification_code=verification_code)
        log_message('added inbound history record to {}'.format(crypto_message.smtp_recipient()))
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

def add_record(crypto_message, direction, verification_code=None):
    ''' Add the message's summary details about its security measures. '''

    ok = False
    try:
        sender = get_email(crypto_message.smtp_sender())
        recipient = get_email(crypto_message.smtp_recipient())
        message_id = get_message_id(crypto_message.get_email_message())
        message_date = crypto_message.get_email_message().get_header(DATE_KEYWORD)
        subject = crypto_message.get_email_message().get_header(SUBJECT_KEYWORD)
        crypted_with = crypto_message.get_crypted_with()
        crypted = crypted_with is not None and len(crypted_with) > 0
        metadata_crypted_with = crypto_message.get_metadata_crypted_with()
        metadata_crypted = metadata_crypted_with is not None and len(metadata_crypted_with) > 0

        # use the encryption for the inner message if possible
        if crypted_with is not None and len(crypted_with) > 0:
            encryption_programs = crypto_message.get_crypted_with()
        else:
            encryption_programs = crypto_message.get_metadata_crypted_with()

        timestamp = get_isoformat(message_date)
        sender_email = get_email(sender)
        recipient_email = get_email(recipient)
        if sender is None:
            log_message(
              "unable to record {} message because there's no contact record for {}".format(direction, sender))
        elif recipient is None:
            log_message(
              "unable to record {} message because there's no contact record for {}".format(direction, recipient))
        else:
            if message_id is None:
                message_id = ''

            programs = ''
            if encryption_programs is not None:
                for encryption_program in encryption_programs:
                    if len(programs) > 0:
                        programs += ', '
                    programs += str(encryption_program)

            if subject is None:
                subject = ''
            if timestamp is None:
                timestamp = ''
            if message_id is None:
                message_id = ''
            if verification_code is None:
                verification_code = gen_verification_code()
            if type(verification_code) is list:
                verification_code = ' '.join(verification_code)

            if DEBUGGING:
                log_message("sender: {}".format(sender))
                log_message("recipient: {}".format(recipient))
                log_message("direction: {}".format(direction))
                log_message("timestamp: {}".format(timestamp))
                log_message("subject: {}".format(subject))
                log_message("message_id: {}".format(message_id))
                log_message("verification_code: {}".format(verification_code))
                log_message("crypted: {}".format(crypted))
                log_message("metadata_crypted: {}".format(metadata_crypted))
                if encryption_programs: log_message("encryption_programs: {}".format(encryption_programs))
                if crypto_message is not None:
                    log_message("is_private_signed: {}".format(crypto_message.is_private_signed()))
                    log_message("private_sig_verified: {}".format(crypto_message.is_private_sig_verified()))
                    log_message("is_clear_signed: {}".format(crypto_message.is_clear_signed()))
                    log_message("clear_sig_verified: {}".format(crypto_message.is_clear_sig_verified()))
                    log_message("is_dkim_signed: {}".format(crypto_message.is_dkim_signed()))
                    log_message("is_dkim_sig_verified: {}".format(crypto_message.is_dkim_sig_verified()))

            MessageHistory.objects.create(sender=sender_email,
                                          recipient=recipient_email,
                                          direction=direction[:1],
                                          encryption_programs=programs[:MessageHistory.MAX_ENCRYPTION_PROGRAMS],
                                          message_date=timestamp[:MessageHistory.MAX_MESSAGE_DATE],
                                          subject=subject[:MessageHistory.MAX_SUBJECT],
                                          message_id=message_id[:MessageHistory.MAX_MESSAGE_ID],
                                          verification_code=verification_code[:MessageHistory.MAX_VERIFICATION_CODE],
                                          content_protected=crypted,
                                          metadata_protected=metadata_crypted,
                                          private_signed=crypto_message.is_private_signed(),
                                          private_sig_verified=crypto_message.is_private_sig_verified(),
                                          clear_signed=crypto_message.is_clear_signed(),
                                          clear_sig_verified=crypto_message.is_clear_sig_verified(),
                                          dkim_signed=crypto_message.is_dkim_signed(),
                                          dkim_sig_verified=crypto_message.is_dkim_sig_verified(),
                                          )
            log_message('created {} history record for {} with {} verification code'.format(
                get_direction(direction), sender, verification_code))
            ok = True
    except:
        ok = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        if sender: log_message("sender: {}".format(sender))
        if recipient: log_message("recipient: {}".format(recipient))
        if direction: log_message("direction: {}".format(direction))
        if encryption_programs: log_message("encryption_programs: {}".format(encryption_programs))
        if timestamp: log_message("timestamp: {}".format(timestamp))
        if subject: log_message("subject: {}".format(subject))
        if message_id: log_message("message_id: {}".format(message_id))
        if verification_code: log_message("verification_code: {}".format(verification_code))
        if crypted: log_message("crypted: {}".format(crypted))
        if metadata_crypted: log_message("metadata_crypted: {}".format(metadata_crypted))
        if crypto_message is not None:
            log_message("is_private_signed: {}".format(crypto_message.is_private_signed()))
            log_message("is_clear_signed: {}".format(crypto_message.is_clear_signed()))
            log_message("is_dkim_signed: {}".format(crypto_message.is_dkim_signed()))
            log_message("private_sig_verified: {}".format(crypto_message.is_private_sig_verified()))
            log_message("clear_sig_verified: {}".format(crypto_message.is_clear_sig_verified()))
            log_message("is_dkim_sig_verified: {}".format(crypto_message.is_dkim_sig_verified()))

    return ok

def sig_verified(signed, signers):
    ''' Returns true if at least one signer was verified. '''

    verified_sig = False
    try:
        if signed and len(signers) > 0:
            for signer in signers:
                if signer[SIGNER_VERIFIED]:
                    verified_sig = True
    except:
        record_exception()

    return verified_sig

def get_outbound_messages(email):
    ''' Get the encrypted messages when the email address was the sender. '''

    records = []

    if email is not None:
        address = get_email(email)
        try:
            sender_records = MessageHistory.objects.filter(sender=address)
            records = sender_records.filter(
              Q(direction=MessageHistory.OUTBOUND_MESSAGE) )
        except MessageHistory.DoesNotExist:
            records = []
        except Exception:
            records = []
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
    else:
        address = email

    log_message("{} has {} encrypted messages".format(address, len(records)))

    return records

def get_inbound_messages(email):
    ''' Get the decrypted messages when the email address was the recipient. '''

    records = []

    if email is not None:
        address = get_email(email)
        try:
            recipient_records = MessageHistory.objects.filter(recipient=address)
            records = recipient_records.filter(Q(direction=MessageHistory.INBOUND_MESSAGE))
        except MessageHistory.DoesNotExist:
            records = []
        except Exception:
            records = []
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
    else:
        address = email

    log_message("{} has {} decrypted messages".format(address, len(records)))

    return records

def get_validated_messages(email, verification_code):
    '''
        Get the messages with a matching verification code for the email address.

        Theoretically, this should just be one message, but we'll remain flexible.
    '''

    records = []

    if email is not None and verification_code is not None:
        address = get_email(email)
        try:
            validated_records = MessageHistory.objects.filter(verification_code=urllib.unquote(verification_code))
            records = validated_records.filter(Q(sender=address) | Q(recipient=address) )
        except MessageHistory.DoesNotExist:
            records = []
        except Exception:
            records = []
            record_exception()
            log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

        if len(records) <= 0:
            try:
                validated_records = MessageHistory.objects.filter(verification_code=verification_code)
                records = validated_records.filter(Q(sender=address) | Q(recipient=address) )
            except MessageHistory.DoesNotExist:
                records = []
            except Exception:
                records = []
                record_exception()
                log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    log_message("{} has {} crypted messages".format(email, len(records)))

    return records

def gen_verification_code():
    '''
        Generate a verification code.

        >>> verification_code = gen_verification_code()
        >>> len(verification_code)
        24
        >>> ' ' not in verification_code
        True
    '''

    verification_code = gen_password(
        max_length=MessageHistory.MAX_VERIFICATION_CODE - 1, punctuation_chars='-_.')

    return verification_code

def get_direction(direction_code):
    '''
        Get the direction in words.

        >>> get_direction(1)
        'Inbound'
    '''
    try:
        code = int(direction_code)
        if code > 0 and code <= len(MessageHistory.MESSAGE_DIRECTIONS):
            __, direction = MessageHistory.MESSAGE_DIRECTIONS[code-1]
        else:
            direction = ''
    except:
        direction = ''

    return direction

def get_isoformat(message_date):
    ''' Get the timestamp in iso format. '''

    def get_year(yr):
        ''' Get the year as a 4 digit number. '''
        if len(yr) < 4:
            if yr.startswith('7') or yr.startswith('8') or yr.startswith('9'):
                yr = '19' + yr
            else:
                yr = '20' + yr
        year = int(yr)
        return year

    # map month abbrevs to numeric equivalent
    MONTH_MAP = {'Jan': 1,
                 'Feb': 2,
                 'Mar': 3,
                 'Apr': 4,
                 'May': 5,
                 'Jun': 6,
                 'Jul': 7,
                 'Aug': 8,
                 'Sep': 9,
                 'Oct': 10,
                 'Nov': 11,
                 'Dec': 12}

    if message_date is None:
        message_date = strftime("%a, %d %b %Y %H:%M:%S", gmtime())

    try:
        Date_Format = re.compile(r'''(?P<wk_day>.*,)?\s+(?P<day>\d*) (?P<month>.*) (?P<year>\d*) (?P<hour>\d*):(?P<min>\d*):(?P<sec>\d*)\s+(?P<gmt_offset>.*)''')
        m = Date_Format.search(message_date)
        if not m:
            Date_Format = re.compile(r'''(?P<day>\d*) (?P<month>.*) (?P<year>\d*) (?P<hour>\d*):(?P<min>\d*):(?P<sec>\d*)\s+(?P<gmt_offset>.*)''')
            m = Date_Format.search(message_date)

        if m:
            day = int(m.group('day'))
            month = MONTH_MAP[m.group('month')]
            year = get_year(m.group('year'))
            hour = int(m.group('hour'))
            minutes = int(m.group('min'))
            seconds = int(m.group('sec'))
            timestamp = datetime(year, month, day, hour, minutes, seconds).isoformat(' ')
            if m.group('gmt_offset'):
                gmt_offset = m.group('gmt_offset')
                if gmt_offset.lower() == 'gmt' or gmt_offset.lower() == 'utc':
                    gmt_offset = '+0000'
                timestamp += ' {}'.format(gmt_offset)
        else:
            timestamp = message_date
            log_message('unable to format date: {}'.format(timestamp))
    except:
        timestamp = message_date

    return timestamp

def log_message(message):
    '''
        Log a message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.message.history.log'))
        True
    '''

    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

