#!/usr/bin/env python
'''
    Copyright 2014 GoodCrypto
    Last modified: 2014-09-20

    This file is open source, licensed under GPLv3 <http://www.gnu.org/licenses/>.
'''

from abc import ABCMeta, abstractmethod
from traceback import format_exc


class AbstractCrypto(object):
    """
        Cryptographic service provided by the Open Crypto Engine.
        
        AbstractCrypto is the superclass for one or more AbstractPlugins.
        AbstractCrypto describes the crypto algorithm, such as PGP.
        AbstractPlugin is an API for a specific implemention of the algorithm,
        such as the GPG program.
        
        To avoid race conditions operations we use queues.
        
        We would prefer to set the passphrase once because
        different cryptos need it at different times, and
        because sending it more often than needed would be
        a security risk. But since there is generally
        only one active instance of each OCE service, then
        one process' encrypt() could end up using another
        process' passphrase.
        
        Colin Percival recommends (as of mid-June 2014):
         * verify authenticity of encrypted data before decrypting it
         * generate a random key and apply symmetric encryption to your message, then apply 
           asymmetric encryption to your symmetric encryption key.
         * be especially careful to avoid timing side channels in RSAES-OAEP
         * do not use same RSA key for encryption and authentication
         * avoid using passwords whenever possible.
         * use a key derivation function to convert passwords into keys as soon as possible; use
           PBKDF2 if you want to be buzzword-compliant; use scrypt if you want to be approximately
           2 to the 8th times more secure against serious attackers.
 
         * hashing:
           * good: SHA-256; (consider SHA-3 in the future, if validated)
           * bad: MD2, MD4, MD5, SHA-1, RIPEMD
         * symmetric authentication:
           * good: HMAC-SHA256
           * bad: CBC-MAC, Poly1305
         * block ciphers:
           * good: AES-256 (AES-128 theoretically good, but 256, better)
           * bad: blowfish, DES, Triple-DES, block cipher raw
         * block cipher mode of operation:
           * good: CTR, MAC (e.g., HMAC-SHA256); uses modes that both encrypt and authenticate
           * bad: ECB
         * asymmetric authentication:
           * good: RSASSA-PSS, 2048-bit RSA,
           * bad: PKCS v1.5 padding, RSA without message padding
           * probably avoid: DSA, Elliptic Curve signature schemes
         * asymmetric encryption:
           * good: RSAES-OAEP (RSA encryption with Optimal Asymmetric Encryption Padding), 2048-bit RSA key, 
                   a public exponent of 65537, SHA256, and MGF1-SHA256
           * bad: PKCS v1.5 padding, RSA without message padding
         * passwords:
           * good: PBKDF2
           * bad: store passwords on server, even if encrypted; in the case of gpg, goodcrypto is the 
             'user' and the gpg database is stored on the same server as the server with the passphrases
         * ssl
            * SSL is a horrible system.
            * SSL is far too complex to be implemented securely.
            * SSL gives attackers far too many options for where to attack.
            * SSL requires that you decide which certificate authorities you want to trust.
            * Do you trust the Chinese government?
            * Unfortunately, SSL is often the only option available.
            * DO: Distribute an asymmetric signature verification key (or a
              hash thereof) with the client side of client-server software, and
              use that to bootstrap your cryptography.
            * DO: Use SSL to secure your website, email, and other public
              standard Internet-facing servers.
            * DO: Think very carefully about which certificate authorities
              you want to trust.
    """

    __metaclass__ = ABCMeta


    @abstractmethod
    def get_name(self):
        '''
            Get the crypto's short name.

            @return name of the crypto
        '''
        
    @abstractmethod
    def get_crypto_version(self):
        '''
            Get the version of the underlying crypto crypto.

            @return Crypto version
        '''
        
    @abstractmethod
    def is_available(self):
        '''
            Determine if the crypto app is installed.

            @return                      true if backend app is installed.
        '''
        
    @abstractmethod
    def get_user_ids(self):
        '''
            Get list of user IDs with a public key.
            
            Some crypto engines require an exact match to an existing user ID, no matter
            what their docs say.
        '''
        
    @abstractmethod
    def get_private_user_ids(self):
        ''' 
            Get list of user IDs with a private key.
    
            @return            List of user IDs with a private key
        '''

    @abstractmethod
    def encrypt_and_armor(self, data, toUserID, charset=None):
        '''
            Encrypt and then armor with the public key indicated by toUserID.
            
            @param data Data to encrypt
            @param toUserID ID indicating which public key to use. This is typically an email address.

            @return Encrypted data
        '''
        
    @abstractmethod
    def sign_and_encrypt(self, data, fromUserID, toUserID, passphrase, clear_sign=False, charset=None):
        '''
            Sign data with the secret key indicated by fromUserID, then encrypt with
            the public key indicated by toUserID.
            
            To avoid a security bug in OpenPGP we must sign before encrypting.

            @param data Data to encrypt
            @param fromUserID ID indicating which secret key to use. This is typically your own email address.
            @param toUserID ID indicating which public key to use. This is typically an email address.
            @param passphrase Passphrase

            @return Encrypted data
        '''
        
    @abstractmethod
    def sign_encrypt_and_armor(self, data, fromUserID, toUserID, passphrase, clear_sign=False, charset=None):
        '''
            Sign data with the secret key indicated by fromUserID, then encrypt with
            the public key indicated by toUserID, then ASCII armor.

            To avoid a security bug in OpenPGP we must sign before encrypting.

            @param data Data to encrypt
            @param fromUserID ID indicating which secret key to use. This is typically your own email address.
            @param toUserID ID indicating which public key to use. This is typically an email address.
            @param passphrase Passphrase

            @return Encrypted data
        '''
        
    @abstractmethod
    def decrypt(self, data, passphrase):
        '''
            Decrypt data.

            @param data Data to decrypt
            @param passphrase Passphrase

            @return Decrypted data
        '''
        
    @abstractmethod
    def sign(self, data, userID, passphrase):
        '''
            Sign data with the private key indicated by userID.

            @param data Data to sign
            @param userID ID indicating which private key to use. This is typically an email address.
            @param passphrase Passphrase

            @return Signed data
        '''
        
    @abstractmethod
    def verify(self, data, userID):
        '''
            Verify data was signed by userID.

            @return Whether data was signed by this user ID

            @param userID user ID
            @param data Data to verify
        '''
        
    @abstractmethod
    def get_signer(self, data):
        '''
            Get signer of data.

            @param data Signed data

            @return ID of the apparent signer, or null if none.
        '''
        
    @abstractmethod
    def log_message(self, message):
        ''' Log a message. '''      

    def log_data(self, data, message="data"):
        ''' Log data. '''

        self.log_message("{} {}:\n".format(message, data))
    	    
    #@synchronized
    def log_error(self, message, result_code=None):
        '''
            Log an error.

            >>> from syr.log import BASE_LOG_DIR
            >>> from syr.user import whoami
            >>> from goodcrypto.oce.crypto_factory import CryptoFactory
            >>> plugin = CryptoFactory.get_crypto(ENCRYPTION_NAME)
            >>> plugin.log_error('error message')
            >>> os.path.exists(os.path.join(BASE_LOG_DIR, whoami(), 'gpg_plugin.log'))
            True
            >>> plugin.log_error('error message', result_code=-1)
        '''

        try:
            errorMsg = []
            errorMsg.append("Error: ")
            errorMsg.append(message)

            if result_code is not None:
                errorMsg.append('\nResult code: {}'.format(result_code))
    
            self.log_message(format_exc())
            self.log_message(str(errorMsg))
        except Exception:
            pass

    def handle_unexpected_exception(self, t):
        ''' 
            Handle any unexpected exception.
            
            Conventional wisdom says that in a crypto program unexpected exceptions
            should terminate the program. That doesn't work in the real world.
            Users are extremely intolerant of program crashes, and should be.
            We log the exception and the higher level should return empty data 
            so caller knows there was a problem.

            >>> from goodcrypto.oce.crypto_factory import CryptoFactory
            >>> plugin = CryptoFactory.get_crypto(ENCRYPTION_NAME)
            >>> plugin.handle_unexpected_exception(Exception)
            >>> os.path.exists(os.path.join(OCE_LOGDIR, 'gpg_plugin.log'))
            True
        '''

        self.log_message('Unexpected error: {}'.format(t))
        self.log_message(format_exc())


