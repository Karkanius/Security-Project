"""
=====================================================================================

         Module:  Security - Symmetric Keys Operations
                  AES Algorithm, CBC Mode, Key generated from a password

        Version:  1.0 January 2020
       Revision:  1

        Authors:  Paulo Vasconcelos, Pedro Teixeira
   Organization:  University of Aveiro

=====================================================================================
"""
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from security import logger


class SymCipher:

    def __init__(self, pwd):
        self.pwd = pwd
        self.createKey()

    def getKey(self):
        return self.secretKey

    def getPwd(self):
        return self.pwd

    def createKey(self):
        # The PBKDF2 generator of Python receives as input the number of byes to generate, instead of bits
        salt = b'\x00'
        kdf = PBKDF2HMAC(hashes.SHA1(), 16, salt, 1000, default_backend())
        self.secretKey = kdf.derive(bytes(self.pwd, 'UTF -8 '))

    def cipher(self, plaintext, secretKey=None):
        """
        Ciphers text with a secret key
        :param plaintext:
        :return: ciphered text
        """
        if secretKey is None:
            secretKey = self.secretKey

        # Read key from key file and setup secretKey with the key to encrypt
        # Setup cipher : AES in CBC mode , w/ a random IV and PKCS #7 padding ( similar to PKCS #5)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(secretKey), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        # TypeError: data must be bytes
        if not isinstance(plaintext, bytes):
            plaintext = bytes(plaintext, 'utf-8')

        #cipherText = encryptor.update(padder.update(plaintext) + padder.finalize()) + encryptor.finalize()
        padded = padder.update(plaintext) + padder.finalize()
        cipherText = encryptor.update(padded) + encryptor.finalize()

        #logger.log("Security", "At Cecipher\nKey {}\nIV {}\nCipher text {}".format(secretKey, iv, cipherText), 'blue')

        return iv + cipherText

    def decipher(self, cipheredtext, sk=None):
        """
        Deciphers text with a secret key
        :param cipheredtext:
        :return: deciphered text
        """
        if sk is None:
            sk = self.secretKey

        iv, ciphertext_text = cipheredtext[:16], cipheredtext[16:]
        cipher = Cipher(algorithms.AES(sk), modes.CBC(iv),default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        #logger.log("Security", "At decipher\nKey {}\nIV {}\nCipher text {}".format(sk, iv, ciphertext_text), 'blue')

        plaintext = decryptor.update(ciphertext_text) + decryptor.finalize()
        paddedText = unpadder.update(plaintext) + unpadder.finalize()

        return paddedText

    @staticmethod
    def decipher2(cipheredtext, sk):
        """
        Deciphers text with a secret key
        :param cipheredtext:
        :return: deciphered text
        """

        iv, ciphertext_text = cipheredtext[:16], cipheredtext[16:]
        cipher = Cipher(algorithms.AES(sk), modes.CBC(iv),default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        #logger.log("Security", "At decipher\nKey {}\nIV {}\nCipher text {}".format(sk, iv, ciphertext_text), 'blue')

        plaintext = decryptor.update(ciphertext_text) + decryptor.finalize()
        paddedText = unpadder.update(plaintext) + unpadder.finalize()

        return paddedText
