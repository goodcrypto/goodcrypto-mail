'''
    Manage GoodCrypto Mail's options.
    
    Copyright 2014-2015 GoodCrypto
    Last modified: 2015-01-10

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from traceback import format_exc


def get_mail_server_address():
    '''
       Get the IP address or domain for the MTA.
    
       >>> get_mail_server_address() is not None
       True
    '''

    mail_server_address = get_options().mail_server_address
    if not mail_server_address:
        mail_server_address = ''

    return mail_server_address
    

def set_mail_server_address(new_mail_server_address):
    '''
       Set the IP address or domain for the MTA.
    
       >>> current_mail_server_address = get_mail_server_address()
       >>> set_mail_server_address('123.12.12.124')
       >>> get_mail_server_address()
       u'123.12.12.124'
       >>> set_mail_server_address(current_mail_server_address)
    '''

    record = get_options()
    record.mail_server_address = new_mail_server_address
    save_options(record)


def get_goodcrypto_listen_port():
    '''
       Get the port where the goodcrypto mail server listens for messages FROM the MTA.
       The MTA sends messages TO this port on the goodcrypto mail server.
    
       >>> get_goodcrypto_listen_port()
       10025
    '''

    goodcrypto_listen_port = get_options().goodcrypto_listen_port

    return goodcrypto_listen_port
    

def set_goodcrypto_listen_port(new_goodcrypto_listen_port):
    '''
       Set the port where the goodcrypto mail server listens for messages FROM the MTA.
    
       >>> current_goodcrypto_listen_port = get_goodcrypto_listen_port()
       >>> set_goodcrypto_listen_port(10027)
       >>> get_goodcrypto_listen_port()
       10027
       >>> set_goodcrypto_listen_port(current_goodcrypto_listen_port)
    '''

    record = get_options()
    record.goodcrypto_listen_port = new_goodcrypto_listen_port
    save_options(record)


def get_mta_listen_port():
    '''
       Get the port where the MTA listens for messages FROM the the goodcrypto mail server.
       The goodcrypto mail server sends "crypted" messages TO this port on the MTA.
       
       >>> get_mta_listen_port()
       10026
    '''

    mta_listen_port = get_options().mta_listen_port

    return mta_listen_port
    

def set_mta_listen_port(new_mta_listen_port):
    '''
       Set the port where the MTA listens for messages FROM the the goodcrypto mail server.
    
       >>> current_mta_listen_port = get_mta_listen_port()
       >>> set_mta_listen_port(10028)
       >>> get_mta_listen_port()
       10028
       >>> set_mta_listen_port(current_mta_listen_port)
    '''

    record = get_options()
    record.mta_listen_port = new_mta_listen_port
    save_options(record)


def auto_exchange_keys():
    '''
       Get whether to auto exchange keys.
    
       >>> current_setting = auto_exchange_keys()
       >>> set_auto_exchange_keys(True)
       >>> auto_exchange_keys()
       True
       >>> set_auto_exchange_keys(current_setting)
    '''

    return get_options().auto_exchange


def set_auto_exchange_keys(auto):
    '''
       Set the user's preference to exchange keys automatically.
    
       >>> current_setting = auto_exchange_keys()
       >>> set_auto_exchange_keys(True)
       >>> auto_exchange_keys()
       True
       >>> set_auto_exchange_keys(False)
       >>> auto_exchange_keys()
       False
       >>> set_auto_exchange_keys(current_setting)
    '''

    record = get_options()
    record.auto_exchange = auto
    save_options(record)

def create_private_keys():
    '''
       Get whether to automatically create private keys.
   
       >>> current_setting = create_private_keys()
       >>> set_create_private_keys(True)
       >>> create_private_keys()
       True
       >>> set_create_private_keys(False)
       >>> create_private_keys()
       False
       >>> set_create_private_keys(current_setting)
    '''

    return get_options().create_private_keys


def set_create_private_keys(auto):
    '''
       Set the user's preference to create private keys automatically.
    
       >>> current_setting = create_private_keys()
       >>> set_create_private_keys(True)
       >>> create_private_keys()
       True
       >>> set_create_private_keys(current_setting)
    '''

    record = get_options()
    record.create_private_keys = auto
    save_options(record)

def get_domain():
    '''
       Get the domain that GoodCrypto is managing.
    
       >>> get_domain() is not None
       True
    '''

    domain = get_options().domain
    if not domain:
        domain = ''

    return domain
    

def set_domain(new_domain):
    '''
       Set the domain for local crypto users.
    
       >>> current_domain = get_domain()
       >>> set_domain('new_domain.com')
       >>> get_domain()
       u'new_domain.com'
       >>> set_domain(current_domain)
    '''

    record = get_options()
    record.domain = new_domain
    save_options(record)


def clear_sign_email():
    '''
       Get whether to clear sign outbound encrypted mail.
  
       >>> current_setting = clear_sign_email()
       >>> set_clear_sign_email(True)
       >>> clear_sign_email()
       True
       >>> set_clear_sign_email(current_setting)
    '''

    return get_options().clear_sign


def set_clear_sign_email(sign):
    '''
       Set the user's preference to clear sign encrypted outbound mail.
    
       >>> current_setting = clear_sign_email()
       >>> set_clear_sign_email(True)
       >>> clear_sign_email()
       True
       >>> set_clear_sign_email(False)
       >>> clear_sign_email()
       False
       >>> set_clear_sign_email(current_setting)
    '''

    record = get_options()
    record.clear_sign = sign
    save_options(record)

def filter_html():
    '''
       Get whether to filter html from inbound email messages.
  
       >>> current_setting = filter_html()
       >>> set_filter_html(True)
       >>> filter_html()
       True
       >>> set_filter_html(current_setting)
    '''

    return get_options().filter_html


def set_filter_html(preference):
    '''
       Set the user's preference to filter html in inbound email messages.
    
       >>> current_setting = filter_html()
       >>> set_filter_html(True)
       >>> filter_html()
       True
       >>> set_filter_html(False)
       >>> filter_html()
       False
       >>> set_filter_html(current_setting)
    '''

    record = get_options()
    record.filter_html = preference
    save_options(record)

def max_message_length():
    '''
       Get the maximum message length, including attachments that are accepted.
  
       >>> current_setting = max_message_length()
       >>> set_max_message_length(10)
       >>> max_message_length()
       10
       >>> set_max_message_length(current_setting)
    '''

    return get_options().max_message_length


def set_max_message_length(max_length):
    '''
       Set the user's preference for the subject of entire encrypted messages.
    
       >>> current_setting = max_message_length()
       >>> set_max_message_length(20)
       >>> max_message_length()
       20
       >>> set_max_message_length(current_setting)
    '''

    record = get_options()
    record.max_message_length = max_length
    save_options(record)

def debug_logs_enabled():
    '''
       Get whether to enable debug logs.
    
       >>> enabled = debug_logs_enabled()
       >>> set_debug_logs_enabled(False)
       >>> debug_logs_enabled()
       False
       >>> set_debug_logs_enabled(enabled)
    '''

    return get_options().debugging_enabled

def set_debug_logs_enabled(enable):
    '''
       Set the user's preference to enable debug logs.
    
       >>> enabled = debug_logs_enabled()
       >>> set_debug_logs_enabled(False)
       >>> debug_logs_enabled()
       False
       >>> set_debug_logs_enabled(enabled)
    '''

    record = get_options()
    record.debugging_enabled = enable
    save_options(record)

def login_to_view_fingerprints():
    '''
       Get whether to require logging in before viewing fingerprints.
  
       >>> current_setting = login_to_view_fingerprints()
       >>> set_login_to_view_fingerprints(False)
       >>> login_to_view_fingerprints()
       False
       >>> set_login_to_view_fingerprints(current_setting)
    '''

    try:
        return get_options().login_to_view_fingerprints
    except:
        return False


def set_login_to_view_fingerprints(require):
    '''
       Set the user's preference to require logging in before viewing fingerprints.
    
       >>> current_setting = login_to_view_fingerprints()
       >>> set_login_to_view_fingerprints(True)
       >>> login_to_view_fingerprints()
       True
       >>> set_login_to_view_fingerprints(False)
       >>> login_to_view_fingerprints()
       False
       >>> set_login_to_view_fingerprints(current_setting)
    '''

    record = get_options()
    try:
        record.login_to_view_fingerprints = require
        save_options(record)
    except:
        pass

def login_to_export_keys():
    '''
       Get whether to require logging in before exporting keys.
  
       >>> current_setting = login_to_export_keys()
       >>> set_login_to_export_keys(False)
       >>> login_to_export_keys()
       False
       >>> set_login_to_export_keys(current_setting)
    '''

    try:
        return get_options().login_to_export_keys
    except:
        return False


def set_login_to_export_keys(require):
    '''
       Set the user's preference to require logging in before exporting keys.
    
       >>> current_setting = login_to_export_keys()
       >>> set_login_to_export_keys(True)
       >>> login_to_export_keys()
       True
       >>> set_login_to_export_keys(False)
       >>> login_to_export_keys()
       False
       >>> set_login_to_export_keys(current_setting)
    '''

    record = get_options()
    try:
        record.login_to_export_keys = require
        save_options(record)
    except:
        pass

def require_key_verified():
    '''
       Get whether to require key verified before using a new key.
  
       >>> current_setting = require_key_verified()
       >>> set_require_key_verified(False)
       >>> require_key_verified()
       False
       >>> set_require_key_verified(current_setting)
    '''

    try:
        return get_options().require_key_verified
    except:
        return False


def set_require_key_verified(require):
    '''
       Set the user's preference to require key verified before using a new key.
    
       >>> current_setting = require_key_verified()
       >>> set_require_key_verified(True)
       >>> require_key_verified()
       True
       >>> set_require_key_verified(False)
       >>> require_key_verified()
       False
       >>> set_require_key_verified(current_setting)
    '''

    record = get_options()
    try:
        record.require_key_verified = require
        save_options(record)
    except:
        pass

def add_keys_to_keyservers():
    '''
       Get whether to add generated keys to keyservers.
  
       >>> current_setting = add_keys_to_keyservers()
       >>> set_add_keys_to_keyservers(False)
       >>> add_keys_to_keyservers()
       False
       >>> set_add_keys_to_keyservers(current_setting)
    '''

    try:
        return get_options().add_keys_to_keyservers
    except:
        return False


def set_add_keys_to_keyservers(add):
    '''
       Set the user's preference to add generated keys to keyservers.
    
       >>> current_setting = add_keys_to_keyservers()
       >>> set_add_keys_to_keyservers(True)
       >>> add_keys_to_keyservers()
       True
       >>> set_add_keys_to_keyservers(False)
       >>> add_keys_to_keyservers()
       False
       >>> set_add_keys_to_keyservers(current_setting)
    '''

    record = get_options()
    try:
        record.add_keys_to_keyservers = add
        save_options(record)
    except:
        pass

def verify_new_keys_with_keyservers():
    '''
       Get whether to verify new keys with keyservers.
  
       >>> current_setting = verify_new_keys_with_keyservers()
       >>> set_verify_new_keys_with_keyservers(False)
       >>> verify_new_keys_with_keyservers()
       False
       >>> set_verify_new_keys_with_keyservers(current_setting)
    '''

    try:
        return get_options().verify_new_keys_with_keyservers
    except:
        return False


def set_verify_new_keys_with_keyservers(verify):
    '''
       Set the user's preference to verify new keys with keyservers.
    
       >>> current_setting = verify_new_keys_with_keyservers()
       >>> set_verify_new_keys_with_keyservers(True)
       >>> verify_new_keys_with_keyservers()
       True
       >>> set_verify_new_keys_with_keyservers(False)
       >>> verify_new_keys_with_keyservers()
       False
       >>> set_verify_new_keys_with_keyservers(current_setting)
    '''

    record = get_options()
    try:
        record.verify_new_keys_with_keyservers = verify
        save_options(record)
    except:
        pass

def get_options():
    '''
        Get the mail options.
        
        >>> get_options() is not None
        True
    '''
    
    from goodcrypto.mail.models import Options
    try:
        records = Options.objects.all()
        if records and len(records) > 0:
            record = records[0]
        else:
            record = None
    except Exception:
        record = None
    
    if record is None:
        record = Options.objects.create(
            domain=None, 
            goodcrypto_listen_port=Options.DEFAULT_GOODCRYPTO_LISTEN_PORT,
            mta_listen_port=Options.DEFAULT_MTA_LISTEN_PORT)

    return record
    

def save_options(record):
    '''
        Save the mail options.
        
        >>> save_options(get_options())
    '''
    try:
        record.save()
    except:
        from syr.log import get_log
        
        log = get_log()
        log(format_exc())
        


