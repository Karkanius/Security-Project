"""
=====================================================================================

         Module:  Security - Diffie Hellman Operations
                  AES Algorithm, CBC Mode, Key generated from a password

        Version:  1.0 January 2020
       Revision:  1

        Authors:  Paulo Vasconcelos, Pedro Teixeira
   Organization:  University of Aveiro

=====================================================================================
"""
import os
import random
import socket

from security.asym_cipher import AsymCipher
from security.sym_cipher import SymCipher


class DiffieHellman:

    #sharedPrime = 877
    #sharedBase = 513
    sharedPrime = 23
    sharedBase = 5
    

    @staticmethod
    def getDHKey(sock,address=None):
        secretValue = random.randint(1,16)
        valueToSend = (DiffieHellman.sharedBase ** secretValue) % DiffieHellman.sharedPrime
        if(address == None):    # No address means it's supose to receove first
            data, address = sock.recvfrom(4096)
            sock.sendto("{0:b}".format(valueToSend).encode(), address)
        else:
            sock.sendto("{0:b}".format(valueToSend).encode(), address)
            data, address = sock.recvfrom(4096)
        data = int(data.decode(),2)
        sharedKey = (data ** secretValue) % DiffieHellman.sharedPrime
        return (secretValue,sharedKey,address)

    @staticmethod
    def saveDHKey(keysDict,address,secretValue,sharedKey):
        keysDict[address] = [secretValue,sharedKey,SymCipher(str(sharedKey)),AsymCipher(str(sharedKey))]

    @staticmethod
    def getSharedPrime():
        return DiffieHellman.sharedPrime

    @staticmethod
    def getSharedBase():
        return DiffieHellman.sharedBase
