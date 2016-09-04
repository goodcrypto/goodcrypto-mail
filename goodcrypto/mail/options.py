'''
    Manage Mail options.

    Mail options are in a singleton Django Admin record.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-02-19

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from goodcrypto.mail.constants import HOURS_CODE, DAYS_CODE, WEEKS_CODE, DEFAULT_DKIM_POLICY
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile
from reinhardt.singleton import get_singleton, save_singleton
from syr.lock import locked

log = LogFile()


def goodcrypto_server_url():
    ''' Get the url for the goodcrypto server. '''

    goodcrypto_server_url = get_options().goodcrypto_server_url
    if goodcrypto_server_url and len(goodcrypto_server_url.strip()) > 0:
        goodcrypto_server_url = goodcrypto_server_url.strip()
        if not goodcrypto_server_url.startswith('http'):
            if ':8443' in goodcrypto_server_url:
                goodcrypto_server_url = 'https://{}'.format(goodcrypto_server_url)
            else:
                goodcrypto_server_url = 'http://{}'.format(goodcrypto_server_url)
        if not goodcrypto_server_url.endswith('/'):
            goodcrypto_server_url += '/'

    return goodcrypto_server_url


def set_goodcrypto_server_url(new_goodcrypto_server_url):
    ''' Set the url for the goodcrypto server. '''

    record = get_options()
    record.goodcrypto_server_url = new_goodcrypto_server_url
    save_options(record)

def mail_server_address():
    ''' Get the IP address or domain for the MTA. '''

    mail_server_address = get_options().mail_server_address
    if not mail_server_address:
        mail_server_address = ''

    return mail_server_address


def set_mail_server_address(new_mail_server_address):
    ''' Set the IP address or domain for the MTA. '''

    record = get_options()
    record.mail_server_address = new_mail_server_address
    save_options(record)


def goodcrypto_listen_port():
    '''
       Get the port where the goodcrypto mail server listens for messages FROM the MTA.
       The MTA sends messages TO this port on the goodcrypto mail server.
    '''

    goodcrypto_listen_port = get_options().goodcrypto_listen_port
    if goodcrypto_listen_port is None:
        from goodcrypto.mail.models import Options

        goodcrypto_listen_port = Options.DEFAULT_GOODCRYPTO_LISTEN_PORT

    return goodcrypto_listen_port


def set_goodcrypto_listen_port(new_goodcrypto_listen_port):
    ''' Set the port where the goodcrypto mail server listens for messages FROM the MTA. '''

    record = get_options()
    record.goodcrypto_listen_port = new_goodcrypto_listen_port
    save_options(record)


def mta_listen_port():
    '''
       Get the port where the MTA listens for messages FROM the the goodcrypto mail server.
       The goodcrypto mail server sends "crypted" messages TO this port on the MTA.
    '''

    mta_listen_port = get_options().mta_listen_port
    if mta_listen_port is None:
        from goodcrypto.mail.models import Options

        mta_listen_port = Options.DEFAULT_MTA_LISTEN_PORT

    return mta_listen_port


def set_mta_listen_port(new_mta_listen_port):
    ''' Set the port where the MTA listens for messages FROM the the goodcrypto mail server. '''

    record = get_options()
    record.mta_listen_port = new_mta_listen_port
    save_options(record)


def auto_exchange_keys():
    ''' Get whether to auto exchange keys. '''

    return get_options().auto_exchange


def set_auto_exchange_keys(auto):
    ''' Set the user's preference to exchange keys automatically. '''

    record = get_options()
    record.auto_exchange = auto
    save_options(record)

def create_private_keys():
    ''' Get whether to automatically create private keys. '''

    return get_options().create_private_keys


def set_create_private_keys(auto):
    ''' Set the user's preference to create private keys automatically. '''

    record = get_options()
    record.create_private_keys = auto
    save_options(record)

def clear_sign_email():
    ''' Get whether to clear sign outbound encrypted mail. '''

    return get_options().clear_sign

def set_clear_sign_email(sign):
    ''' Set the user's preference to clear sign encrypted outbound mail. '''

    record = get_options()
    record.clear_sign = sign
    save_options(record)

def clear_sign_policy():
    ''' Get the policy to clear sign a message. '''

    return get_options().clear_sign_policy

def set_clear_sign_policy(policy):
    ''' Set the user's preference to clear sign encrypted outbound mail. '''

    record = get_options()
    record.clear_sign_policy = policy
    save_options(record)

def filter_html():
    ''' Get whether to filter html from inbound email messages. '''

    return get_options().filter_html


def set_filter_html(preference):
    ''' Set the user's preference to filter html in inbound email messages. '''

    record = get_options()
    record.filter_html = preference
    save_options(record)

def encrypt_metadata():
    ''' Get whether to encrypt metadata. '''

    return get_options().encrypt_metadata

def set_encrypt_metadata(encrypt):
    ''' Set the user's preference to encrypt metadata. '''

    record = get_options()
    record.encrypt_metadata = encrypt
    save_options(record)

def bundle_and_pad():
    ''' Get whether to bundle and pad messages. '''

    return get_options().bundle_and_pad


def set_bundle_and_pad(bundle):
    ''' Set the user's preference to bundle and pad messages. '''

    record = get_options()
    record.bundle_and_pad = bundle
    save_options(record)

def bundle_frequency():
    ''' Get how frequently to send bundled messages. '''

    return get_options().bundle_frequency

def set_bundle_frequency(frequency):
    ''' Set the user's preference to send bundled messages. '''

    record = get_options()
    record.bundle_frequency = frequency
    save_options(record)

def bundled_message_max_size():
    ''' Get the max size for bundled messages. '''

    return bundle_message_kb() * 1024

def bundle_message_kb():
    ''' Get the kb for bundled messages. '''

    bundle_message_kb = get_options().bundle_message_kb
    if bundle_message_kb is None:
        bundle_message_kb = 0

    return bundle_message_kb

def set_bundle_message_kb(kb):
    ''' Set the kb for bundled messages. '''

    record = get_options()
    record.bundle_message_kb = kb
    save_options(record)

def login_to_view_fingerprints():
    ''' Get whether to require logging in before viewing fingerprints. '''

    try:
        return get_options().login_to_view_fingerprints
    except:
        return False

def set_login_to_view_fingerprints(require):
    ''' Set the user's preference to require logging in before viewing fingerprints. '''

    record = get_options()
    try:
        record.login_to_view_fingerprints = require
        save_options(record)
    except:
        pass

def login_to_export_keys():
    ''' Get whether to require logging in before exporting keys. '''

    try:
        return get_options().login_to_export_keys
    except:
        return False

def set_login_to_export_keys(require):
    ''' Set the user's preference to require logging in before exporting keys. '''

    record = get_options()
    try:
        record.login_to_export_keys = require
        save_options(record)
    except:
        pass

def require_outbound_encryption():
    ''' Get whether to require all outbound mail is encrypted. '''

    try:
        return get_options().require_outbound_encryption
    except:
        return False

def set_require_outbound_encryption(require):
    ''' Set whether to require all outbound mail is encrypted. '''

    record = get_options()
    try:
        record.require_outbound_encryption = require
        save_options(record)
    except:
        pass

def require_key_verified():
    ''' Get whether to require key verified before using a new key. '''

    try:
        return get_options().require_key_verified
    except:
        return False

def set_require_key_verified(require):
    ''' Set the user's preference to require key verified before using a new key. '''

    record = get_options()
    try:
        record.require_key_verified = require
        save_options(record)
    except:
        pass

def add_dkim_sig():
    ''' Get whether to add the domain's DKIM signature to outbound messages. '''

    try:
        return get_options().add_dkim_sig
    except:
        return False

def set_add_dkim_sig(add):
    ''' Set the user's preference to add the domain's DKIM signature to outbound messages. '''

    record = get_options()
    try:
        record.add_dkim_sig = add
        save_options(record)
    except:
        pass

def verify_dkim_sig():
    ''' Get whether to verify DKIM signatures on inbound messages. '''

    try:
        return get_options().verify_dkim_sig
    except:
        return False

def set_verify_dkim_sig(verify):
    ''' Set the user's preference to verify DKIM signatures on inbound messages. '''

    record = get_options()
    try:
        record.verify_dkim_sig = verify
        save_options(record)
    except:
        pass

def dkim_delivery_policy():
    ''' Get the delivery policy if DKIM verification fails. '''

    try:
        return get_options().dkim_delivery_policy
    except:
        return DEFAULT_DKIM_POLICY

def set_dkim_delivery_policy(policy):
    ''' Set the domain's DKIM signature. '''

    record = get_options()
    try:
        record.dkim_delivery_policy = policy
        save_options(record)
    except:
        pass

def dkim_public_key():
    ''' Get the domain's DKIM signature. '''

    try:
        return get_options().dkim_public_key
    except:
        return False

def set_dkim_public_key(key):
    ''' Set the domain's DKIM signature. '''

    record = get_options()
    try:
        record.dkim_public_key = key
        save_options(record)
    except:
        pass

def use_keyservers():
    ''' Get whether to use keyservers to find keys for contacts. '''

    try:
        return get_options().use_keyservers
    except:
        return False

def set_use_keyservers(use):
    ''' Set whether to use keyservers to find keys for contacts. '''

    record = get_options()
    try:
        record.use_keyservers = use
        save_options(record)
    except:
        pass

def add_long_tags():
    ''' Get whether to add long tags to messages or not. '''

    try:
        return get_options().add_long_tags
    except:
        return True

def set_use_keyservers(add):
    ''' Set whether to add long tags to messages. '''

    record = get_options()
    try:
        record.add_long_tags = add
        save_options(record)
    except:
        pass

def debug_logs_enabled():
    ''' Get whether to enable debug logs. '''

    return get_options().debugging_enabled

def set_debug_logs_enabled(enable):
    ''' Set the user's preference to enable debug logs.'''

    record = get_options()
    record.debugging_enabled = enable
    save_options(record)

def bundle_hourly():
    ''' Return the code for bundling and padding messages hourly. '''

    return HOURS_CODE

def bundle_daily():
    ''' Return the code for bundling and padding messages daily. '''

    return DAYS_CODE

def bundle_weekly():
    ''' Return the code for bundling and padding messages weekly. '''

    return WEEKS_CODE

def get_options():
    '''
        Get the mail options.

        >>> get_options() is not None
        True
    '''

    from goodcrypto.mail.models import Options

    try:
        record = get_singleton(Options)
    except Options.DoesNotExist:
        with locked():
            record = Options.objects.create(
                goodcrypto_listen_port=Options.DEFAULT_GOODCRYPTO_LISTEN_PORT,
                mta_listen_port=Options.DEFAULT_MTA_LISTEN_PORT)
            record.save()

    return record


def save_options(record):
    '''
        Save the mail options.

        >>> save_options(get_options())
    '''
    from goodcrypto.mail.models import Options

    save_singleton(Options, record)

def log_message(message):
    '''
        Log a message to the local log.

        >>> import os.path
        >>> from syr.log import BASE_LOG_DIR
        >>> from syr.user import whoami
        >>> log_message('test')
        >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.options.log'))
        True
    '''

    global log

    if log is None:
        log = LogFile()

    log.write_and_flush(message)




