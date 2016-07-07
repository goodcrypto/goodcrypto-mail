'''
    Copyright 2015 GoodCrypto.
    Last modified: 2015-07-27

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
from goodcrypto.mail.message.inspect_utils import get_message_id
from goodcrypto.utils import get_email
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from syr.mime_constants import DATE_KEYWORD, SUBJECT_KEYWORD

_log = None

def add_encrypted_record(crypto_message, verification_code):
    '''
        Add a history record so the user can verify the message was encrypted.
    '''
    try:
        sender = crypto_message.smtp_sender()
        crypted_with = crypto_message.is_crypted_with()
        metadata_crypted_with = crypto_message.is_metadata_crypted_with()
        if crypted_with is None:
            crypted_with = []
        if metadata_crypted_with is None:
            metadata_crypted_with = []
        
        if len(crypted_with) > 0 and len(metadata_crypted_with) > 0:
            add_record(crypto_message, MessageHistory.DOUBLE_ENCRYPTED_MESSAGE_STATUS,
                      verification_code=verification_code)
            log_message('added double encrypted history record from {}'.format(sender))
        elif len(crypted_with) > 0:
            add_record(crypto_message, MessageHistory.ENCRYPTED_MESSAGE_STATUS,
                       verification_code=verification_code)
            log_message('added encrypted history record from {}'.format(sender))
        else:
            add_record(crypto_message, MessageHistory.ENCRYPTED_METADATA_MESSAGE_STATUS,
                      verification_code=verification_code)
            log_message('added encrypted metadata history record from {}'.format(sender))
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

def add_decrypted_record(crypto_message, verification_code):
    '''
        Add a history record so the user can verify the message was decrypted by GoodCrypto.
    '''
    try:
        recipient = crypto_message.smtp_recipient()
        crypted_with = crypto_message.is_crypted_with()
        metadata_crypted_with = crypto_message.is_metadata_crypted_with()

        if len(crypted_with) > 0 and len(metadata_crypted_with) > 0:
            add_record(crypto_message, MessageHistory.DOUBLE_DECRYPTED_MESSAGE_STATUS, 
                      verification_code=verification_code)
            log_message('added double decrypted history record to {}'.format(recipient))
        elif len(crypted_with) > 0:
            add_record(crypto_message, MessageHistory.DECRYPTED_MESSAGE_STATUS, 
                       verification_code=verification_code)
            log_message('added decrypted history record to {}'.format(recipient))
        else:
            add_record(crypto_message, MessageHistory.DECRYPTED_METADATA_MESSAGE_STATUS, 
                       verification_code=verification_code)
            log_message('added decrypted metadata history record to {}'.format(recipient))
    except:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

def add_record(crypto_message, status, verification_code=None):
    ''' Add the message's summary details. '''

    ok = False
    try:
        sender = get_email(crypto_message.smtp_sender())
        recipient = get_email(crypto_message.smtp_recipient())
        message_id = get_message_id(crypto_message.get_email_message())
        message_date = crypto_message.get_email_message().get_header(DATE_KEYWORD)
        subject = crypto_message.get_email_message().get_header(SUBJECT_KEYWORD)
        crypted_with = crypto_message.is_crypted_with()

        # use the encryption for the inner message if possible
        if crypted_with is not None and len(crypted_with) > 0:
            encryption_programs = crypto_message.is_crypted_with()
        else:
            encryption_programs = crypto_message.is_metadata_crypted_with()

        timestamp = get_isoformat(message_date)
        sender_email = get_email(sender)
        recipient_email = get_email(recipient)
        if sender is None:
            log_message(
              "unable to record {} message because there's no contact record for {}".format(status, sender))
        elif recipient is None:
            log_message(
              "unable to record {} message because there's no contact record for {}".format(status, recipient))
        else:
            if message_id is None:
                message_id = ''

            programs = ''
            if encryption_programs is not None:
                for encryption_program in encryption_programs:
                    if len(programs) > 0:
                        programs += ', '
                    programs += str(encryption_program)

            log_message("encryption programs: {}".format(programs))

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

            MessageHistory.objects.create(sender=sender,
                                          recipient=recipient,
                                          encryption_programs=programs[:MessageHistory.MAX_ENCRYPTION_PROGRAMS],
                                          message_date=timestamp[:MessageHistory.MAX_MESSAGE_DATE],
                                          subject=subject[:MessageHistory.MAX_SUBJECT],
                                          message_id=message_id[:MessageHistory.MAX_MESSAGE_ID],
                                          verification_code=verification_code[:MessageHistory.MAX_VERIFICATION_CODE],
                                          status=status[:1])
            log_message('created {} history record for {} with {} verification code'.format(
                get_status(status), sender, verification_code))
            ok = True
    except:
        ok = False
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        if sender: log_message("sender: {}".format(sender))
        if recipient: log_message("recipient: {}".format(recipient))
        if encryption_programs: log_message("encryption_programs: {}".format(encryption_programs))
        if timestamp: log_message("timestamp: {}".format(timestamp))
        if subject: log_message("subject: {}".format(subject))
        if message_id: log_message("message_id: {}".format(message_id))
        if verification_code: log_message("verification_code: {}".format(verification_code))
        if status: log_message("status: {}".format(status))
        
    return ok

def get_encrypted_messages(email):
    ''' Get the encrypted messages when the email address was the sender. '''

    records = []

    if email is not None:
        address = get_email(email)
        try:
            sender_records = MessageHistory.objects.filter(sender=address)
            records = sender_records.filter(
              Q(status=MessageHistory.ENCRYPTED_MESSAGE_STATUS) |
              Q(status=MessageHistory.ENCRYPTED_METADATA_MESSAGE_STATUS) |
              Q(status=MessageHistory.DOUBLE_ENCRYPTED_MESSAGE_STATUS) )
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

def get_decrypted_messages(email):
    ''' Get the decrypted messages when the email address was the recipient. '''

    records = []

    if email is not None:
        address = get_email(email)
        try:
            recipient_records = MessageHistory.objects.filter(recipient=address)
            records = recipient_records.filter(
              Q(status=MessageHistory.DECRYPTED_MESSAGE_STATUS) |
              Q(status=MessageHistory.DECRYPTED_METADATA_MESSAGE_STATUS) |
              Q(status=MessageHistory.DOUBLE_DECRYPTED_MESSAGE_STATUS) )
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

def get_status(status_code):
    ''' 
        Get the status code in words.
        
        >>> get_status(1)
        'Content only'
    '''
    try:
        code = int(status_code)
        if code > 0 and code <= len(MessageHistory.MESSAGE_STATUS):
            __, status = MessageHistory.MESSAGE_STATUS[code-1]
        else:
            status = ''
    except:
        status = ''

    return status

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
        Date_Format = re.compile(r'''(?P<wk_day>.*,)? (?P<day>\d*) (?P<month>.*) (?P<year>\d*) (?P<hour>\d*):(?P<min>\d*):(?P<sec>\d*) *(?P<gmt_offset>.*)''')
        m = Date_Format.search(message_date)
        if not m:
            Date_Format = re.compile(r'''(?P<day>\d*) (?P<month>.*) (?P<year>\d*) (?P<hour>\d*):(?P<min>\d*):(?P<sec>\d*) *(?P<gmt_offset>.*)''')
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
            log_message('formatted date: {}'.format(timestamp))
        else:
            timestamp = message_date
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

