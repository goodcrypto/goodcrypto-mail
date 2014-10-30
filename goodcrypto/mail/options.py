'''
    Manage GoodCrypto Mail's options.
    
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-13

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

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
    record.save()


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
    record.save()


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
    record.save()


def get_validation_code():
    ''' 
        Get the validation code or None if there isn't one.
        
        >>> current_code = get_validation_code()
        >>> set_validation_code('test code')
        >>> get_validation_code()
        u'test code'
        >>> set_validation_code(current_code)
    '''

    return get_options().validation_code


def set_validation_code(new_code):
    ''' 
        Set a new validation code.
        
        >>> current_code = get_validation_code()
        >>> set_validation_code('test code')
        >>> get_validation_code()
        u'test code'
        >>> set_validation_code(current_code)
    '''

    record = get_options()
    record.validation_code = new_code
    record.save()


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
    record.save()

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
    record.save()

def self_signed_certs_ok():
    '''
       Get whether to accept self signed certs.
  
       >>> current_setting = self_signed_certs_ok()
       >>> set_self_signed_certs_ok(True)
       >>> self_signed_certs_ok()
       True
       >>> set_self_signed_certs_ok(False)
       >>> self_signed_certs_ok()
       False
       >>> set_self_signed_certs_ok(current_setting)
    '''

    return get_options().accept_self_signed_certs


def set_self_signed_certs_ok(ok):
    '''
       Set the user's preference to accept self signed certs.
    
       >>> current_setting = self_signed_certs_ok()
       >>> set_self_signed_certs_ok(True)
       >>> self_signed_certs_ok()
       True
       >>> set_self_signed_certs_ok(False)
       >>> self_signed_certs_ok()
       False
       >>> set_self_signed_certs_ok(current_setting)
    '''

    record = get_options()
    record.accept_self_signed_certs = ok
    record.save()


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
    record.save()


def days_between_key_alerts():
    '''
       Get how frequently to send alerts about keys.
  
       >>> current_setting = days_between_key_alerts()
       >>> set_days_between_key_alerts(10)
       >>> days_between_key_alerts()
       10
       >>> set_days_between_key_alerts(current_setting)
    '''

    return get_options().days_between_key_alerts


def set_days_between_key_alerts(days):
    '''
       Set the user's preference as to how frequently alerts are sent.
    
       >>> current_setting = days_between_key_alerts()
       >>> set_days_between_key_alerts(5)
       >>> days_between_key_alerts()
       5
       >>> set_days_between_key_alerts(current_setting)
    '''

    record = get_options()
    record.days_between_key_alerts = days
    record.save()

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
    record.save()

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


def set_filter_html(filter):
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
    record.filter_html = filter
    record.save()

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
    record.save()

def use_encrypted_content_type():
    '''
       Get whether to encrypt the entire message instead of just the body.
  
       >>> current_setting = use_encrypted_content_type()
       >>> set_use_encrypted_content_type(True)
       >>> use_encrypted_content_type()
       True
       >>> set_use_encrypted_content_type(current_setting)
    '''

    return get_options().use_encrypted_content_type


def set_use_encrypted_content_type(use):
    '''
       Set the user's preference to encrypt the entire message instead of just the body.
    
       >>> current_setting = use_encrypted_content_type()
       >>> set_use_encrypted_content_type(True)
       >>> use_encrypted_content_type()
       True
       >>> set_use_encrypted_content_type(False)
       >>> use_encrypted_content_type()
       False
       >>> set_use_encrypted_content_type(current_setting)
    '''

    record = get_options()
    record.use_encrypted_content_type = use
    record.save()

def get_encrypted_subject():
    '''
       Get the encrypted subject when the entire message is encrypted.
  
       >>> current_setting = get_encrypted_subject()
       >>> set_encrypted_subject('Test subject')
       >>> get_encrypted_subject()
       u'Test subject'
       >>> set_encrypted_subject(current_setting)
    '''

    return get_options().encrypted_subject


def set_encrypted_subject(subject):
    '''
       Set the user's preference for the subject of entire encrypted messages.
    
       >>> current_setting = get_encrypted_subject()
       >>> set_encrypted_subject('Test subject')
       >>> get_encrypted_subject()
       u'Test subject'
       >>> set_encrypted_subject(current_setting)
    '''

    record = get_options()
    record.encrypted_subject = subject
    record.save()

def use_us_standards():
    '''
       Get whether to use US standards.
  
       >>> current_setting = use_us_standards()
       >>> set_use_us_standards(True)
       >>> use_us_standards()
       True
       >>> set_use_us_standards(current_setting)
    '''

    return get_options().use_us_standards


def set_use_us_standards(use):
    '''
       Set the user's preference to use US standards.
    
       >>> current_setting = use_us_standards()
       >>> set_use_us_standards(True)
       >>> use_us_standards()
       True
       >>> set_use_us_standards(current_setting)
    '''

    record = get_options()
    record.use_us_standards = use
    record.save()

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
    record.save()

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
    


