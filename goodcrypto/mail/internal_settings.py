'''
    Manage Mail's internal settings.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-10-26

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from datetime import datetime

from goodcrypto.utils.log_file import LogFile
from reinhardt.singleton import get_singleton, save_singleton
from syr.exception import record_exception
from syr.lock import locked

_log = None

def get_date_queue_last_active():
    ''' Get the date the bundling/padding queue was last active. '''

    date_queue_last_active = get_internal_settings().date_queue_last_active
    if not date_queue_last_active or date_queue_last_active is None:
        date_queue_last_active = datetime.utcnow()
        set_date_queue_last_active(date_queue_last_active)

    return date_queue_last_active

def set_date_queue_last_active(new_date_queue_last_active):
    ''' Set date the bundling/padding queue was last active. '''

    record = get_internal_settings()
    try:
        record.date_queue_last_active = new_date_queue_last_active
        save_internal_settings(record)
    except:
        record_exception()
        log_message('EXCEPTION - see syr.exception.log for details')

def get_domain():
    ''' Get the domain that GoodCrypto private server manages. '''

    domain = get_internal_settings().domain
    if not domain:
        domain = ''

    return domain

def set_domain(new_domain):
    ''' Set the domain for local crypto users. '''

    record = get_internal_settings()
    record.domain = new_domain
    save_internal_settings(record)

def get_internal_settings():
    '''
        Get the mail internal settings.

        >>> get_internal_settings() is not None
        True
    '''

    from goodcrypto.mail.models import InternalSettings

    try:
        record = get_singleton(InternalSettings)
    except InternalSettings.DoesNotExist:
        with locked():
            record = InternalSettings.objects.create(
                domain=None,
                date_queue_last_active=datetime.utcnow())
            record.save()

    return record


def save_internal_settings(record):
    '''
        Save the mail options.

        >>> save_internal_settings(get_internal_settings())
    '''
    from goodcrypto.mail.models import InternalSettings

    save_singleton(InternalSettings, record)


def log_message(message):
    '''
        Log a message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.internal_settings.log'))
        True
    '''

    global _log

    if _log is None:
        _log = LogFile()

    _log.write_and_flush(message)

