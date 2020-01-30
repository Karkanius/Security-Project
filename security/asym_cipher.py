"""
=====================================================================================

         Module:  Security - Asymmetric Keys Operations
                  RSA algorith mwith PKCS #1 OAEP Padding

        Version:  1.0 January 2020
       Revision:  1

        Authors:  Paulo Vasconcelos, Pedro Teixeira
   Organization:  University of Aveiro

=====================================================================================
"""
from Crypto.PublicKey import ECC
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class AsymCipher:
    def __init__(self, pwd, key_size=1024):
        """
        Create a RSA Asymmetric Cipher
        :param pwd: password
        :param key_size: key size (1024, 2048, ...). Default is 1024
        """
        self.key_size = key_size
        self.pwd = pwd
        self.createKeys()

    def getPubKey(self):
        return self.pub_key

    def getPrivKey(self):
        return self.priv_key

    def createKeys(self):
        """
        Generate a pair of asymmetric keys to be used with the RSA algorithm.
        Based on https://8gwifi.org/docs/python-rsa.jsp
        """
        self.priv_key = rsa.generate_private_key(65537, self.key_size, default_backend())
        self.pub_key = self.priv_key.public_key()

        # any need to save to file?

    def cipher(self, plaintext, pub_key=None):
        if pub_key is None:
            pub_key = self.pub_key

        # Calculate the maximum amount of data we can encrypt with OAEP + SHA256
        maxLen = (pub_key.key_size // 8) - 2 * hashes.SHA256.digest_size - 2

        # Read for plaintext no more than maxLen bytes from the input file

        # Encrypt the plaintext using OAEP + MGF1 ( SHA256 ) + SHA256
        ciphertext = pub_key.encrypt(plaintext.encode('utf-8'),
                                     padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

        # Write ciphertext in the ouput file
        return ciphertext

    def decipher(self, ciphertext, priv_key=None):
        if priv_key is None:
            priv_key = self.priv_key

        plaintext = priv_key.decrypt(ciphertext,
                                     padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
        return plaintext.decode('utf-8')

    def sign(self, plaintext, priv_key=None):
        if priv_key is None:
            priv_key = self.priv_key

        if type(plaintext) is not bytes:
            plaintext = bytes(plaintext, 'utf-8')

        signature = priv_key.sign(plaintext,
                                  padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH),
                                  hashes.SHA256())
        return signature

    def valid_signature(self, signature, plaintext, pub_key=None):
        try:
            if pub_key is None:
                pub_key = self.pub_key

            if type(plaintext) is not bytes:
                plaintext = bytes(plaintext, 'utf-8')

            pub_key.verify(signature, plaintext,
                           padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def valid_signature2(signature, plaintext, pub_key):
        try:
            if type(plaintext) is not bytes:
                plaintext = bytes(plaintext, 'utf-8')

            pub_key.verify(signature, plaintext,
                           padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except InvalidSignature:
            return False

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

class ECCCipher:
    def __init__(self, pwd):
        """
        Create a ECC Asymmetric Cipher
        :param pwd: password
        """
        self.pwd = pwd
        self.createKeys()

    def getPubKey(self):
        return self.pub_key

    def getPrivKey(self):
        return self.priv_key

    def createKeys(self):
        """
        Generate a pair of asymmetric keys
        """
        self.priv_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.pub_key = self.priv_key.public_key()

    def cipher(self, plaintext, pub_key=None):
        if pub_key is None:
            pub_key = self.pub_key

        # Encrypt the plaintext using OAEP + MGF1 ( SHA256 ) + SHA256

        ciphertext = pub_key.encrypt(plaintext.encode('utf-8'),
                                     padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))

        # Write ciphertext in the ouput file
        return ciphertext

    def decipher(self, ciphertext, priv_key=None):
        if priv_key is None:
            priv_key = self.priv_key

        plaintext = priv_key.decrypt(ciphertext,
                                     padding.OAEP(padding.MGF1(hashes.SHA256()), hashes.SHA256(), None))
        return plaintext.decode('utf-8')

    def sign(self, plaintext, priv_key=None):
        if priv_key is None:
            priv_key = self.priv_key

        plaintext = bytes(plaintext, 'utf-8')
        signature = priv_key.sign(plaintext,
                                  ec.ECDSA(hashes.SHA256()))
        return signature

    def valid_signature(self, signature, plaintext, pub_key=None):
        try:
            if pub_key is None:
                pub_key = self.pub_key

            plaintext = bytes(plaintext, 'utf-8')
            pub_key.verify(signature, plaintext,
                           ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False
