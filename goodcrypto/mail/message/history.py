#!/usr/bin/env python
'''
    Copyright 2015 GoodCrypto.
    Last modified: 2015-02-16

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.

    Manage logging messages encrypted and decrypted by the GoodCrypto server to
    prevent others spoofing the security of a message. 
'''
import os
from time import gmtime, strftime
from traceback import format_exc
from django.db.models.query import QuerySet

from goodcrypto.mail.models import MessageHistory
from goodcrypto.mail.utils import gen_password
from goodcrypto.oce.utils import parse_address
from goodcrypto.utils.log_file import LogFile

_log = None

def get_decrypted_message_status():
    ''' 
        Get the decrypted message status.

        >>> get_decrypted_message_status()
        'decrypted'
    '''
    
    __, description = MessageHistory.MESSAGE_STATUS[0]
    
    return description


def get_encrypted_message_status():
    '''
        Get the encrypted message status.

        >>> get_encrypted_message_status()
        'encrypted'
    '''
    
    __, description = MessageHistory.MESSAGE_STATUS[1]
    
    return description


def add_encrypted_record(sender, recipient, encryption_programs, message_id, message_date=None):
    ''' Add the encrypted message's record. '''
    
    return add_record(sender, recipient, encryption_programs, 
                      message_id, message_date, MessageHistory.ENCRYPTED_MESSAGE_STATUS)

def add_decrypted_record(sender, recipient, encryption_programs, message_id, validation_code, message_date=None):
    ''' Add the decrypted message's summary details. '''
    
    return add_record(sender, recipient, encryption_programs, 
                      message_id, message_date, MessageHistory.DECRYPTED_MESSAGE_STATUS, 
                      validation_code=validation_code)

def add_record(sender, recipient, encryption_programs, message_id, message_date, status, validation_code=None):
    ''' Add the message's summary details. '''
    
    ok = False
    try:
        if message_date is None:
            message_date = strftime("%a, %d %b %Y %H:%M:%S", gmtime())

        __, sender_email = parse_address(sender)
        __, recipient_email = parse_address(recipient)
        if sender_email is None:
            log_message(
              "unable to record {} message because there's no contact record for {}".format(status, sender))
        elif recipient_email is None:
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

            if validation_code is None:
                validation_code = gen_validation_code()

            MessageHistory.objects.create(sender=sender_email,
                                          recipient=recipient_email,
                                          encryption_programs=programs[:MessageHistory.MAX_ENCRYPTION_PROGRAMS],
                                          message_date=message_date[:MessageHistory.MAX_MESSAGE_DATE],
                                          message_id=message_id[:MessageHistory.MAX_MESSAGE_ID],
                                          validation_code=validation_code,
                                          status=status)
            ok = True
    except:
        ok = False
        log_message(format_exc())
        
    return ok

def get_encrypted_messages(email):
    ''' Get the encrypted messages when the email address was the sender. '''

    records = []

    if email is not None:
        __, address = parse_address(email)
        try:
            records = MessageHistory.objects.filter(
               sender=address, status=MessageHistory.ENCRYPTED_MESSAGE_STATUS)
        except MessageHistory.DoesNotExist:
            records = []
        except Exception:
            records = []
            log_message(format_exc())

    log_message("got {} encrypted messages".format(len(records)))

    return records

def get_decrypted_messages(email):
    ''' Get the decrypted messages when the email address was the recipient. '''

    records = []

    if email is not None:
        __, address = parse_address(email)
        try:
            records = MessageHistory.objects.filter(
               recipient=address, status=MessageHistory.DECRYPTED_MESSAGE_STATUS)
        except MessageHistory.DoesNotExist:
            records = []
        except Exception:
            records = []
            log_message(format_exc())

    log_message("got {} decrypted messages".format(len(records)))

    return records

def gen_validation_code():
    ''' 
        Generate a validation code.
        
        >>> password = gen_password()
        >>> len(password)
        25
    '''
    
    validation_code = gen_password(max_length=MessageHistory.MAX_VALIDATION_CODE)
          
    return validation_code
    
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

