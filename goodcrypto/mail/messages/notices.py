#!/usr/bin/env python
'''
    Send notices from the GoodCrypto Server daemon.
    
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-24

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

import os, sh, smtplib
from email.Encoders import encode_base64
from email.mime.text import MIMEText
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.utils import formataddr
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.mail.messages import mime_constants
from goodcrypto.mail.options import get_domain
from goodcrypto.mail.utils.dirs import get_notices_directory
from goodcrypto.mail.utils.exception_log import ExceptionLog
from goodcrypto.oce.utils import parse_address


USE_SMTP = False

#  Notices From: address. 
NOTICE_FROM_NAME = 'GoodCrypto Daemon'
NOTICE_FROM_EMAIL = 'mailer-daemon@{}'.format(get_domain())
NOTICE_FROM_ADDRESS = (NOTICE_FROM_NAME, NOTICE_FROM_EMAIL)
NOTICE_FROM_ADDR = formataddr(NOTICE_FROM_ADDRESS)

_log = None


def create_notice_message(to_address, subject, text=None, attachment=None, filename=None):
    '''
        Creates a notice message.
        
        >>> # In honor of Sukhbir Singh, developed and maintains TorBirdy.
        >>> message = create_notice_message('sukhbir@goodcrypto.remote', 'test notice')
        >>> message.find('To: sukhbir@goodcrypto.remote') >= 0
        True
        >>> message.find('From: GoodCrypto Daemon <mailer-daemon@goodcrypto.local>') >= 0
        True
        >>> message.find('Subject: test notice') >= 0
        True
    '''

    message = None
    if to_address is None or (subject is None and text is None):
        log_message('unable to send notice without to address plus subject or text')
    else:
        from goodcrypto.mail.messages.utils import get_current_timestamp
        
        if text is None:
            text = subject
        elif type(text) == list:
            text = '\n'.join(text)
    
        try:
            if attachment is None:
                msg = MIMEText(text)
            else:
                msg = MIMEMultipart()
                log_message('adding attachment')

            if subject is not None:
                msg[mime_constants.SUBJECT_KEYWORD] = subject
            msg[mime_constants.FROM_KEYWORD] = NOTICE_FROM_ADDR
            msg[mime_constants.TO_KEYWORD] = to_address
            msg[mime_constants.DATE_KEYWORD] = get_current_timestamp()

            if attachment is not None:
                msg.attach(MIMEText(text))
    
                payload = MIMEBase('application', "octet-stream")
                payload.set_payload(attachment)
                encode_base64(payload)
                payload.add_header(
                  'Content-Disposition', 'attachment; filename="%s"' % os.path.basename(filename))
                if payload is not None:
                    msg.attach(payload)

            message = msg.as_string()
        except Exception:
            log_message(format_exc())

    return message


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
        message = create_notice_message(
            to_address, subject, text=text, attachment=attachment, filename=filename)
        if message is None:
            result_ok = False
        else:
            log_message('starting to send notice to {}'.format(to_address))
            
            from_addr = NOTICE_FROM_EMAIL
            _, to_addr = parse_address(to_address)
            
            if to_addr is None or message is None:
                result_ok = False
                log_message('no to address to send notice')
            else:
                if USE_SMTP:
                    smtp = smtplib.SMTP()
                    smtp.connect()
                    smtp.sendmail(from_addr, to_addr, message)
                    smtp.quit()
                else:
                    sendmail = sh.Command('/usr/sbin/sendmail')
                    sendmail('-B', '8BITMIME', '-f', from_addr, to_addr, _in=message)

                log_message('sent notice to {}'.format(to_address))
                result_ok = True
    except:
        result_ok = False
        log_message(format_exc())
        
    if not result_ok and message is not None:
        _save(message)

    log_message('final result: {}'.format(result_ok))
    
    return result_ok
        
    
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
            from goodcrypto.mail.messages.utils import write_message
        
            log_message('saving: {}'.format(message))
            notice_filename = write_message(get_notices_directory(), message)
    except Exception as exception:
        notice_filename = None
        log_message(exception)
        log_message(format_exc())

    return notice_filename


def log_message(message):
    ''' 
        Record debugging messages. 
        
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.messages.notices.log'))
        True
    '''

    global _log
    
    if _log is None:
        _log = LogFile()
        
    _log.write(message)

