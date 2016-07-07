'''
    Mail database router.

    Copyright 2015 GoodCrypto
    Last modified: 2015-06-06

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
from goodcrypto.constants import MAIL_DB

class MailRouter(object):
    """
    A router to control all database operations on models in the mail app.
    """
    def db_for_read(self, model, **hints):
        ''' Attempts to read mail models go to Mail db. '''
        if self.is_mail_db(model):
            return MAIL_DB
        else:
            return None

    def db_for_write(self, model, **hints):
        ''' Attempts to write mail models go to Mail db. '''
        if self.is_mail_db(model):
            return MAIL_DB
        else:
            return None

    def allow_relation(self, obj1, obj2, **hints):
        ''' Allow relations if a model in the mail app is involved. '''
        if (self.is_mail_db(obj1) or
            self.is_mail_db(obj2)):
            return True
        else:
            return None

    def allow_migrate(self, db, app_label, model=None, **hints):
        ''' Make sure the mail apps only appears in the Mail database. '''

        if (app_label == 'auth' or
            app_label == 'django' or
            app_label == 'group' or
            app_label == 'mail'):
            return db == MAIL_DB
        else:
            return None

    def is_mail_db(self, obj):
        ''' Return True if the table is part of the Mail database. '''
        return (obj._meta.app_label == 'auth' or
                obj._meta.app_label == 'django' or
                obj._meta.app_label == 'group' or
                obj._meta.app_label == 'mail')

