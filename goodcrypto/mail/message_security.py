'''
    Show the user the security protection for messages they've sent or received..

    Copyright 2016 GoodCrypto
    Last modified: 2016-02-07

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import urllib
from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect
from django.template import RequestContext

from goodcrypto.mail.forms import VerifyMessageForm
from goodcrypto.mail.message import history
from goodcrypto.utils import i18n
from goodcrypto.utils.exception import record_exception
from goodcrypto.utils.log_file import LogFile

ENCRYPTED_STATUS = i18n('encrypted')
DECRYPTED_STATUS = i18n('decrypted')
SIGNED_STATUS = i18n('signed')
NOT_SENT_PRIVATELY = i18n('GoodCrypto did <font color="red">not</font> send message privately from <strong>{email}</strong> (verification code: {verification_code}).')
TAMPERED_SENT_WARNING = i18n("If the message has a tag which states it was sent privately from {email} and you're double checked the verification code, then someone probably tampered with the message.")
NOT_RECEIVED_PRIVATELY = i18n('GoodCrypto did <font color="red">not</font> receive a message for <strong>{email}</strong> with the verification code: <strong>{verification_code}</strong>')
TAMPERED_RECEIVED_WARNING = i18n("If the message has a tag which states it was received privately and you're double checked the verification code, then someone probably tampered with the message.")
NOT_EXCHANGED_PRIVATELY = i18n('GoodCrypto did <font color="red">not</font> exchange a message for <strong>{email}</strong> with the verification code: <strong>{verification_code}</strong>')
TAMPERED_EXCHANGED_WARNING = i18n("If the message has a tag which states it was exchanged privately or signed and you're double checked the verification code, then someone probably tampered with the message.")


log = None

def prompt_for_code(request):
    ''' Prompt user for the verification code for the message user wants to verify.'''

    response = None
    form = VerifyMessageForm()
    form_template = 'mail/verify_message.html'
    if request.method == 'POST':
        form = VerifyMessageForm(request.POST)
        if form.is_valid():
            template = 'mail/verified_decrypted.html'
            log_message('verification code: {}'.format(form.cleaned_data['verification_code']))
            params, status = get_crypted_params(
               request.user.email, form.cleaned_data['verification_code'])
            if 'error_message' in params and params['error_message'] is not None:
                log_message('retry verification code: {}'.format(urllib.quote(form.cleaned_data['verification_code'])))
                retry_params, __ = get_crypted_params(
                   request.user.email, urllib.quote(form.cleaned_data['verification_code']))
                if 'error_message' in retry_params and retry_params['error_message'] is None:
                    params = retry_params
                log_message('retry params: {}'.format(retry_params))
            elif status == ENCRYPTED_STATUS:
                template = 'mail/verified_encrypted.html'
                log_message('using encrypted verification page')

            response = render_to_response(
                template, params, context_instance=RequestContext(request))
        else:
            log_message('form not valid')

        if response is None:
            log_message('post: {}'.format(request.POST))

    if response is None:
        log_message('no response for verifying message crypted so redisplaying main page')
        params = {'form': form,
                  'main_headline': 'Verify Message',
                  'url': 'verify_crypted'}
        response = render_to_response(
            form_template, params, context_instance=RequestContext(request))

    return response

def show_outbound_msg(request, verification_code):
    '''Show the outbound message with the verification code.'''

    try:
        template = 'mail/verified_encrypted.html'
        result_headers = []
        results = []
        error_message = None

        email = request.user.email
        records = history.get_outbound_messages(email)
        if records:
            # narrow the messages to those matching the verification_code
            records = records.filter(verification_code=urllib.unquote(verification_code))
        if not records:
            try:
                # use the verification_code without unquoting it in case they pasted it into a url field
                records = records.filter(verification_code=verification_code)
            except:
                pass

        if records:
            results, private, private_signed, clear_signed, dkim_signed = summarize_outbound_messages(
                records)
            main_headline, subheadline = get_verify_msg_headlines(
                'sent', private, private_signed, clear_signed, dkim_signed)
        else:
            main_headline = i18n('<font color="red">Not</font> Verified')
            subheadline = i18n('Message not sent privately from {}'.format(email))
            error1 = NOT_SENT_PRIVATELY.format(email=email, verification_code=verification_code)
            error2 = TAMPERED_SENT_WARNING.format(email=email)
            error_message = '{} {}'.format(error1, error2)
            log_message(error_message)

        params = {'email': email,
                  'main_headline': main_headline,
                  'results': results,
                  'error_message': error_message}
        response = render_to_response(
            template, params, context_instance=RequestContext(request))
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        response = HttpResponseRedirect('/mail/show_encrypted_history/')

    return response

def show_all_outbound(request):
    '''Show all outbound messages with security protection for logged in user.'''

    try:
        result_headers = []
        results = []
        error_message = None

        template = 'mail/encrypted_history.html'
        records = history.get_outbound_messages(request.user.email)
        if records:
            for record in records:
                verification_link = get_formatted_verification_link(
                    record.verification_code, 'msg-encrypted')
                results.append({
                  'email': record.recipient,
                  'private_signed': len(history.unpickle_signers(record.private_signers)) > 0,
                  'clear_signed': len(history.unpickle_signers(record.clear_signers)) > 0,
                  'verification_link': verification_link,
                  'record': record,
                  })

        params = {'email': request.user.email,
                  'results': results,
                  'error_message': error_message}
        response = render_to_response(
            template, params, context_instance=RequestContext(request))
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        response = HttpResponseRedirect('/mail/show_encrypted_history/')

    return response

def show_inbound_msg(request, verification_code):
    '''Show the inbound message with the verification code.'''

    try:
        template = 'mail/verified_decrypted.html'
        result_headers = []
        results = []
        error_message = None

        email = request.user.email
        records = history.get_inbound_messages(email)
        if records:
            # narrow the messages to those matching the verification_code
            records = records.filter(verification_code=urllib.unquote(verification_code))

        if records:
            results, private, private_signed, clear_signed, dkim_signed = summarize_inbound_messages(
                records)
            main_headline, subheadline = get_verify_msg_headlines(
                'received', private, private_signed, clear_signed, dkim_signed)
        else:
            main_headline = i18n('<font color="red">Not</font> Verified')
            subheadline = i18n('Message not received privately for {}'.format(email))
            error1 = NOT_RECEIVED_PRIVATELY.format(email=email, verification_code=verification_code)
            error2 = TAMPERED_RECEIVED_WARNING
            error_message = '{} {}'.format(error1, error2)
            log_message(error_message)

        params = {'email': request.user.email,
                  'main_headline': main_headline,
                  'subheadline': subheadline,
                  'results': results,
                  'error_message': error_message}
        response = render_to_response(
            template, params, context_instance=RequestContext(request))
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        response = HttpResponseRedirect('/mail/verify_crypted/')

    return response

def show_all_inbound(request):
    '''Show all inbound messages with security protection for the logged in user.'''

    try:
        template = 'mail/decrypted_history.html'
        result_headers = []
        results = []
        error_message = None


        records = history.get_inbound_messages(request.user.email)
        if records:
            for record in records:
                verification_link = get_formatted_verification_link(record.verification_code, 'msg-decrypted')
                results.append({
                  'email': record.sender,
                  'private_signed': len(history.unpickle_signers(record.private_signers)) > 0,
                  'clear_signed': len(history.unpickle_signers(record.clear_signers)) > 0,
                  'verification_link': verification_link,
                  'record': record,
                })
        params = {'email': request.user.email,
                  'results': results,
                  'error_message': error_message}
        response = render_to_response(
            template, params, context_instance=RequestContext(request))
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')
        response = HttpResponseRedirect('/mail/show_decrypted_history/')

    return response

def summarize_inbound_messages(records):
    ''' Summarize which, if any, signatures the outbound messages used. '''

    results = []
    private = private_signed = clear_signed = dkim_signed = False
    for record in records:

        record_result = summarize_message(record, record.recipient)

        if record_result['private']:
            private = True

        if record_result['private_signed']:
            private_signed = True

        if record_result['clear_signed']:
            clear_signed = True

        if record_result['dkim_signed']:
            dkim_signed = True

        results.append(record_result)

    return results, private, private_signed, clear_signed, dkim_signed

def summarize_outbound_messages(records):
    ''' Summarize which, if any, signatures the outbound messages used. '''

    results = []
    private = private_signed = clear_signed = dkim_signed = False
    for record in records:

        record_result = summarize_message(record, record.sender)

        if record_result['private']:
            private = True

        if record_result['private_signed']:
            private_signed = True

        if record_result['clear_signed']:
            clear_signed = True

        if record_result['dkim_signed']:
            dkim_signed = True

        results.append(record_result)

    return results, private, private_signed, clear_signed, dkim_signed

def summarize_message(record, email):
    ''' Summarize which, if any, signatures the message used. '''

    private = private_signed = clear_signed = dkim_signed = False
    if record is None:
        record_result = {'email': email}
    else:
        record_result = {'email': email, 'record': record}
        if record.content_protected or record.metadata_protected:
            private = True
        record_result['private'] = private
    
        private_signers = history.unpickle_signers(record.private_signers)
        if len(private_signers) > 0:
            private_signed = True
            record_result['private_signed'] = True
            record_result['private_sig_verified'] = history.is_sig_verified(private_signers)
        else:
            record_result['private_signed'] = False
            record_result['private_sig_verified'] = False
    
        clear_signers = history.unpickle_signers(record.clear_signers)
        if len(clear_signers) > 0:
            clear_signed = True
            record_result['clear_signed'] = True
            record_result['clear_sig_verified'] = history.is_sig_verified(clear_signers)
        else:
            record_result['clear_signed'] = False
            record_result['clear_sig_verified'] = False
    
        if record.dkim_signed:
            dkim_signed = True
            record_result['dkim_signed'] = True
            record_result['dkim_sig_verified']= record.dkim_sig_verified
        else:
            record_result['dkim_signed'] = False
            record_result['dkim_sig_verified'] = False

    return record_result

def get_verify_msg_headlines(direction, private, private_signed, clear_signed, dkim_signed):
    ''' Get the headlines for a verified message. '''

    main_headline = i18n('<font color="green">Verified</font>')
    if private and (private_signed or clear_signed or dkim_signed):
        subheadline = i18n('Message {} privately and signed'.format(direction))
    elif private:
        subheadline = i18n('Message {} privately'.format(direction))
    elif (private_signed or clear_signed or dkim_signed):
        subheadline = i18n('Message {} signed'.format(direction))

    return main_headline, subheadline

def get_crypted_params(email, verification_code):
    '''Get the params for a response to verify a message was crypted by GoodCrypto.'''

    params = {}
    results = []
    status = DECRYPTED_STATUS
    error_message = None

    try:
        records = history.get_validated_messages(email, verification_code)
        if records:
            if len(records) == 1:
                record = records[0]
                if record.sender == email:
                    main_headline = i18n('Verified')
                    if record.content_protected or record.metadata_protected:
                        subheadline = i18n('Message sent privately')
                        status = ENCRYPTED_STATUS
                    else:
                        subheadline = i18n('Message sent with signature')
                        status = SIGNED_STATUS
                    for record in records:
                        results.append({'email': record.sender, 'record': record})
                else:
                    main_headline = i18n('Verified')
                    if record.content_protected or record.metadata_protected:
                        subheadline = i18n('Message received privately')
                        status = DECRYPTED_STATUS
                    else:
                        subheadline = i18n('Message received with signature')
                        status = SIGNED_STATUS
                    for record in records:
                        results.append({'email': record.sender, 'record': record})
            else:
                main_headline = i18n('Verified')
                subheadline = i18n('Exchanged the messages privately')
                for record in records:
                    results.append({'email': record.sender, 'record': record})
        else:
            main_headline = i18n('<font color="red">Not</font> Verified')
            subheadline = i18n('Message with verification code not exchanged with {}'.format(email))
            error1 = NOT_EXCHANGED_PRIVATELY.format(email=email, verification_code=verification_code)
            error2 = TAMPERED_EXCHANGED_WARNING
            error_message = '{} {}'.format(error1, error2)
            log_message(error_message)

        params = {'email': email,
                  'main_headline': main_headline,
                  'subheadline': subheadline,
                  'results': results,
                  'error_message': error_message,}
        log_message('params:\n{}'.format(params))
    except Exception:
        record_exception()
        log_message('EXCEPTION - see goodcrypto.utils.exception.log for details')

    return params, status

def get_formatted_verification_link(verification_code, partial_link):
    ''' Create a link for the verification code. '''

    try:
        code = verification_code
        quoted_code = urllib.quote(code)
        link = '/mail/{}/{}'.format(partial_link, quoted_code, code)
    except:
        link = code

    return link

def log_message(message):
    ''' Log a message to the local log. '''

    global log

    if log is None:
        log = LogFile()

    log.write_and_flush(message)


