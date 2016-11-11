'''
    Retrieve a key from a keyserver.

    Copyright 2016 GoodCrypto.
    Last modified: 2016-10-31

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from rq.queue import Queue

from goodcrypto.mail import contacts, crypto_software
from goodcrypto.mail.constants import UNKNOWN_EMAIL
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception

class RetrieveKey(object):
    '''
        Retrieve a key from a keyserver.
    '''

    def __init__(self, email, encryption_name, keyserver, key_id, user_initiated_search):
        '''
            >>> # In honor of Werner Koch, developer of gpg.
            >>> email = 'wk@gnupg.org'
            >>> crypto_name = 'GPG'
            >>> srk_class = RetrieveKey(email, crypto_name, 'pgp.mit.edu', 'F2AD85AC1E42B367', 'chelsea@goodcrypto.local')
            >>> srk_class = RetrieveKey(None, crypto_name, 'pgp.mit.edu', 'F2AD85AC1E42B367', 'chelsea@goodcrypto.local')
            >>> srk_class = RetrieveKey(email, None, 'pgp.mit.edu', 'F2AD85AC1E42B367', 'chelsea@goodcrypto.local')
            >>> srk_class = RetrieveKey(email, crypto_name, None, 'F2AD85AC1E42B367', 'chelsea@goodcrypto.local')
            >>> srk_class = RetrieveKey(None, None, None, None, None)
        '''

        self.log = LogFile()
        self.email = email
        self.encryption_name = encryption_name
        self.keyserver = keyserver
        self.key_id = key_id
        self.user_initiated_search = user_initiated_search

        self.key_plugin = None

    def start_retrieval(self):
        '''
            Queue retrieving key from the keyserver. When the job finishes, associated
            database entries will be made from another queued job which is dependent on
            the key retrieval's job.

            Test extreme case.
            >>> rk = RetrieveKey(None, None, None, None, None)
            >>> rk.start_retrieval()
            False
        '''

        if self.email == UNKNOWN_EMAIL:
            email_or_fingerprint = self.key_id
        else:
            email_or_fingerprint = self.email

        try:
            result_ok = (self.email is not None and
                         self.encryption_name is not None and
                         self.keyserver is not None and
                         self.key_id is not None and
                         self.user_initiated_search is not None)

            if result_ok:
                self.key_plugin = KeyFactory.get_crypto(
                   self.encryption_name, crypto_software.get_key_classname(self.encryption_name))
                result_ok = self.key_plugin is not None

            if result_ok:
                from goodcrypto.mail.keyserver_utils import add_contact_records

                self.key_plugin.retrieve_key(self.key_id, self.keyserver)

                retrieve_job = self.key_plugin.get_job()
                queue = self.key_plugin.get_queue()
                if queue is None or retrieve_job is None:
                    self.log_message('unable to queue job to add contact recs for {}'.format(
                       self.key_id))
                    result_ok = False
                else:
                    self.log_message('starting to add contact records for {} (after job: {})'.format(
                        self.key_id, retrieve_job.get_id()))
                    add_contact_records(email_or_fingerprint,
                                        self.encryption_name,
                                        self.user_initiated_search,
                                        retrieve_job.get_id(), queue.key)
                    result_ok = True
            else:
                result_ok = False
                self.log_message('unable to queue retrieving {} key for {}'.format(
                    self.encryption_name, self.key_id))

        except Exception as exception:
            result_ok = False
            record_exception()
            self.log_message('EXCEPTION - see syr.exception.log for details')

        self.log_message('finished queueing retreival for {} ok: {}'.format(email_or_fingerprint, result_ok))

        return result_ok

    def log_message(self, message):
        '''
            Log the message to the local log.

            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> RetrieveKey(None, None, None, None, None).log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.retrieve_key.log'))
            True
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)


