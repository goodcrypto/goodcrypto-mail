'''
    Mail crypto.

    Copyright 2014-2016 GoodCrypto
    Last modified: 2016-06-10

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import email, os
from threading import Thread
from io import StringIO

from goodcrypto.mail.message.message_exception import MessageException
from goodcrypto.oce.otp import OTPFile

def encrypt(mailfrom, mailto, message):
    ''' Return encrypted message.

        If error raises MessageException.
    '''

    otp_file = OTPFile(otp_filename(mailfrom, mailto))
    with otp_file:
        with StringIO() as encrypted_message:
            encrypted_message.write('...')
        otp_file.write()

    return message


def otp_filename(mailfrom, mailto):
    ''' Returns One Time Pad filename for email_addr.

        If there is no otp for email_addr, starts process to create one. '''

    # just use the email address part, the string with '@'
    __, mailfrom = email.utils.parseaddr(mailfrom)
    __, mailto = email.utils.parseaddr(mailto)

    users_dir = 'something unknown'
    user_dir = os.path.join(users_dir, mailfrom)
    if not os.path.exists(user_dir):
        raise MessageException('No directory for user: {0}'.format(mailfrom))

    peer_dir = os.path.join(users_dir, mailto)
    if not os.path.exists(peer_dir):
        raise MessageException('No directory for user, peer: {0}, {1}'.
            format(mailfrom, mailto))

    filename = os.path.join(users_dir, 'otp')
    if not os.path.exists(filename):

        thread = Thread(target=create_otp, args=(filename))
        thread.start()
        raise MessageException('Creating otp file for user, peer: {0}, {1}'.
            format(mailfrom, mailto))

    return filename

def create_otp(filename):
    ''' Create a pad file. '''

    # !! we need make this function atomic to avoid races
    #    lock based on otp_filename

    if not os.path.exists(filename):

        temp_filename = filename + '.temp'
        otp_file = OTPFile(temp_filename)
        otp_file.create()
        os.rename(temp_filename, filename)

