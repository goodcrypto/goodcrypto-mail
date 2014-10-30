#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-10-22

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''
import sys
from traceback import format_exc

from goodcrypto.utils.log_file import LogFile
from goodcrypto.oce.crypto_exception import CryptoException
from goodcrypto.oce.key.key_factory import KeyFactory


class CommandLineUtility(object):
    ''' Key command line utility program. '''

    ListCommand = "list"
    CreateCommand = "create"
    DeleteCommand = "delete"

    def __init__(self):
        '''
            >>> clu = CommandLineUtility()
            >>> clu is not None
            True
        '''

        self.log = LogFile()


    def show(self, service_name):
        '''
            Show the user ids.
            
            The results are unknown so we redirect them.
            >>> from StringIO import StringIO
            >>> output = StringIO()
            ... clu = CommandLineUtility()
            ... clu.show('GPG')
        '''

        try:
            key_plugin = KeyFactory.get_crypto(service_name)
            user_ids = key_plugin.get_user_ids()
            for user_id in user_ids:
                print(user_id)
        except Exception as exception:
            print(exception)
            self.log.write(exception)


    def create(self, service_name, args):
        '''
            Create a key pair.
            
            >>> # In honor of Usha Narayane, who inspired other women in her community to take action against a rapist.
            >>> args = ['narayane@goodcrypto.local', 'command line passphrase']
            >>> clu = CommandLineUtility()
            >>> clu.create('GPG', args)
            created key for narayane@goodcrypto.local: (True, False)
            >>> args = ['narayane@goodcrypto.local']
            >>> clu.delete('GPG', args)
            deleted key for narayane@goodcrypto.local
        '''

        arg_index = 0
        key_id = args[arg_index]
        arg_index += 1
        passphrase = args[arg_index]

        try:
            key_plugin = KeyFactory.get_crypto(service_name)
            result_ok = key_plugin.create(key_id, passphrase, wait_for_results=True)
            print("created key for {}: {}".format(key_id, result_ok))
        except CryptoException as crypto_exception:
            print(crypto_exception.value)
            self.log.write(crypto_exception.value)


    def delete(self, service_name, args):
        '''
            Delete a key pair.
            
            >>> clu = CommandLineUtility()
            >>> args = ['command_line@goodcrypto.local']
            >>> clu.delete('GPG', args)
            deleted key for command_line@goodcrypto.local
        '''

        key_id = args[0]
        try:
            key_plugin = KeyFactory.get_crypto(service_name)
            key_plugin.delete(key_id)
            print("deleted key for {}".format(key_id))
        except CryptoException as crypto_exception:
            print(crypto_exception.value)
            self.log.write(crypto_exception.value)


    def help(self):
        '''
            >>> clu = CommandLineUtility()
            >>> clu.help()
            usage: python command_line_utility.py <crypto name> <command>
                crypto name:
                     BC, GPG, etc.
                command:
                    list
                    create <email address> <passphrase>
                    delete <email address>
        '''

        print("usage: python command_line_utility.py <crypto name> <command>")
        print("    crypto name:")
        print("         BC, GPG, etc.")
        print("    command:")
        print("        {}".format(CommandLineUtility.ListCommand))
        print("        {}".format(CommandLineUtility.CreateCommand + " <email address> <passphrase>"))
        print("        {}".format(CommandLineUtility.DeleteCommand + " <email address>"))


    @staticmethod
    def main(args):
        ''' The main program for the CommandLineUtility class. '''

        try:
            command_utility = CommandLineUtility()
            if len(args) > 2:
                service_name = args[1].upper()
                command = args[2]
                if command == CommandLineUtility.ListCommand:
                    command_utility.show(service_name)
                elif command == CommandLineUtility.CreateCommand and len(args) > 3:
                    command_utility.create(service_name, args[3:])
                elif command == CommandLineUtility.DeleteCommand and len(args) > 3:
                    command_utility.delete(service_name, args[3:])
                else:
                    print("unexpected command: {}".format(command))
                    command_utility.help()
            else:
                command_utility.help()
        except Exception:
            print(format_exc())


if __name__ == '__main__':
    CommandLineUtility.main(sys.argv)

