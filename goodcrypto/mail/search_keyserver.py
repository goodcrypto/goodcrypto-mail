'''
    Search for a key on a keyserver.

    Copyright 2016 GoodCrypto.
    Last modified: 2016-08-03

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from goodcrypto.mail import contacts, crypto_software
from goodcrypto.mail.utils import email_in_domain
from goodcrypto.oce.key.key_factory import KeyFactory
from goodcrypto.utils.log_file import LogFile
from syr.exception import record_exception

class SearchKeyserver(object):
    '''
        Search for a key from keyserver.
    '''

    def __init__(self, email, encryption_name, keyserver, user_initiated_search):
        '''
            >>> # In honor of Werner Koch, developer of gpg.
            >>> email = 'wk@gnupg.org'
            >>> crypto_name = 'GPG'
            >>> srk_class = SearchKeyserver(email, crypto_name, 'pgp.mit.edu', 'julian@goodcrypto.local')
            >>> srk_class != None
            True
            >>> srk_class = SearchKeyserver(None, crypto_name, 'pgp.mit.edu', 'julian@goodcrypto.local')
            >>> srk_class != None
            True
            >>> srk_class = SearchKeyserver(email, None, 'pgp.mit.edu', 'julian@goodcrypto.local')
            >>> srk_class != None
            True
            >>> srk_class = SearchKeyserver(email, crypto_name, None, 'julian@goodcrypto.local')
            >>> srk_class != None
            True
            >>> srk_class = SearchKeyserver(None, None, None, None)
            >>> srk_class != None
            True
        '''

        self.log = LogFile()
        self.email = email
        self.encryption_name = encryption_name
        self.keyserver = keyserver
        self.user_initiated_search = user_initiated_search
        self.key_plugin = None

    def start_search(self):
        '''
            Queue searching the keyserver. When the job finishes, the key
            will be retrieved from another queued job which is dependent
            on the search's job.

            Test extreme case.
            >>> srk_class = SearchKeyserver(None, None, None, None)
            >>> srk_class.start_search()
            False
        '''

        try:
            if self._is_ready_for_search():
                result_ok = True

                # start the search, but don't wait for the results
                self.key_plugin.search_for_key(self.email, self.keyserver)
                search_job = self.key_plugin.get_job()
                queue = self.key_plugin.get_queue()

                # if the search job or queue are done, then retrieve the key
                if queue is None or search_job is None:
                    get_key(self.email, self.encryption_name, self.keyserver,
                            self.user_initiated_search, search_job, queue)
                else:
                    from goodcrypto.mail.keyserver_utils import get_key

                    ONE_MINUTE = 60 #  one minute, in seconds
                    DEFAULT_TIMEOUT = 10 * ONE_MINUTE

                    # otherwise, set up another job in the queue to retrieve the
                    # key as soon as the search for the key id is finished
                    result_ok = get_key(self.email,
                                        self.encryption_name,
                                        self.keyserver,
                                        self.user_initiated_search,
                                        search_job.get_id(), queue.key)
                    self.log_message('retrieving {} key for {}: {}'.format(
                          self.encryption_name, self.email, result_ok))
            else:
                result_ok = False

        except Exception as exception:
            result_ok = False
            record_exception()
            self.log_message('EXCEPTION - see syr.exception.log for details')

        self.log_message('finished starting search on {} for {} ok: {}'.format(
            self.keyserver, self.email, result_ok))

        return result_ok

    def _is_ready_for_search(self):
        '''
            Verify that we're ready to search for this key.

            Test extreme case.
            >>> srk_class = SearchKeyserver(None, None, None, None)
            >>> srk_class._is_ready_for_search()
            False
        '''

        ready = False
        try:
            ready = (self.email is not None and
                     self.encryption_name is not None and
                     self.keyserver is not None and
                     self.user_initiated_search is not None and
                     not email_in_domain(self.email))

            if ready:
                self.key_plugin = KeyFactory.get_crypto(
                   self.encryption_name, crypto_software.get_key_classname(self.encryption_name))
                ready = self.key_plugin is not None

            if ready:
                # make sure we don't already have crypto defined for this user
                contacts_crypto = contacts.get_contacts_crypto(self.email, self.encryption_name)
                if contacts_crypto is None or contacts_crypto.fingerprint is None:
                    fingerprint, expiration = self.key_plugin.get_fingerprint(self.email)
                    if fingerprint is not None:
                        ready = False
                        self.log_message('{} public key exists for {}: {}'.format(
                            self.encryption_name, self.email, fingerprint))
                else:
                    ready = False
                    self.log_message('crypto for {} already defined'.format(self.email))

        except Exception as exception:
            record_exception()
            self.log_message('EXCEPTION - see syr.exception.log for details')
            ready = False

        return ready

    def log_message(self, message):
        '''
            Log the message to the local log.

            >>> import os.path
            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> SearchKeyserver(None, None, None, None).log_message('test')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'goodcrypto.mail.search_keyserver.log'))
            True
        '''

        if self.log is None:
            self.log = LogFile()

        self.log.write_and_flush(message)

