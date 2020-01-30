"""
=====================================================================================

         Module:  Server

        Version:  1.0 January 2020
       Revision:  1

        Authors:  Paulo Vasconcelos, Pedro Teixeira
   Organization:  University of Aveiro

=====================================================================================
"""


import socket
import sys
import argparse
import random
import threading
import logger
import os
import math
from tinyec import registry
import secrets
from table import TableThread

sys.path.append(os.path.abspath(os.getcwd()))	# solve import issues
from security.citizen_card import CitizenCard
from security.asym_cipher import AsymCipher
from security.sym_cipher import SymCipher
from security.diffie_hellman import DiffieHellman
from security import pem_utils

"""
===============
= Cards logic =
===============

CardValue = CardSuit*16 + CardNumberOrSymbol

» Suits «
  Hearts = 0
  Spades = 1
Diamonds = 2
   Clubs = 3

» Number or Symbol «
number = number
  jack = 11
 queen = 12
  king = 13
   ace = 14
"""

verbose = False
serverIP = socket.gethostbyname(socket.gethostname())
serverPort = 10000
tableCredentials = {}	# id = [password,port,thread]
registeredUsers = {}	# username = ((ip,port),publicKey)
threads = []



# ======================
# === Diffie Hellman ===
# ======================
dh_sharedPrime = 23
dh_sharedBase = 5
#dh_sharedPrime = 23
#dh_sharedBase = 5
dh_keys = {} # address = [selfSecret,key,SymCipherInstance,AsymCipherInstance]


def symCipherAndSend(message,address):
	print(dh_keys)
	print(dh_keys[address])
	print(dh_keys[address][1])
	logger.log('Server', 'Key is {}'.format(dh_keys[address][1]), 'yellow')
	cipheredMessage = dh_keys[address][2].cipher(message)
	sock.sendto(cipheredMessage, address)


def symDecipher(data,address):
	print(dh_keys)
	print(dh_keys[address])
	print(dh_keys[address][1])
	logger.log('Server', 'Key is {}'.format(dh_keys[address][1]), 'yellow')
	return dh_keys[address][2].decipher(data)


def asymCipherAndSend(message,address):
	cipheredMessage = dh_keys[address][3].cipher(message)
	sock.sendto(cipheredMessage, address)


def asymDecipher(data,address):
	return dh_keys[address][3].decipher(data)
	

def dh_keyToString(pubKey):
	return str(pubKey.x//math.pow(10,64))[:-2]+'?'+str(pubKey.y//math.pow(10,64))[:-2]


def dh_stringToKey(pubKey):
	x = int(pubKey[:pubKey.index('?')])
	y = int(pubKey[pubKey.index('?')+1:])
	return (x,y)



def decodeSignedMessage(data,pubKey,ccFlag):
	middleIndex = 1
	signature = None
	while True:
		try:
			data[:middleIndex].decode('utf-8').index('\v')
			decodedMessage = data[:middleIndex-1].decode('utf-8')
			signature = data[middleIndex:]
			break
		except:
			middleIndex += 1
	verifySignature(signature,decodedMessage,pubKey,ccFlag)
	return decodedMessage,signature


def isAddressRegistered(address):
	for username in registeredUsers: 
		if(registeredUsers[username]==address):
			return True
	return False


def isTableIDInUse(tid):
	for tableID in tableCredentials: 
		if(tableID==tid):
			return True
	return False


def isTablePortInUse(port):
	for tableID in tableCredentials: 
		if(tableCredentials[tableID][1]==port):
			return True
	return False


def getTablePort(tid):
	for tableID in tableCredentials: 
		if(tableID==tid):
			return tableCredentials[tableID][1]
	return -1


def handleMessage(message,address):
	decodedMessage = message.decode()
	if(decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='Handshake'):
		if(isAddressRegistered(address)):
			refuseHandshake(address)
			return
		handleHandshake(message,address)


def refuseHandshake(address):
	sock.sendto(("[401]Address already in use.").encode(),address)
	if(verbose):
		logger.log('Server','Handshake refused - Address {} already in use.'.format(address),'yellow')


def verifySignature(signature,data,publicKey,ccFlag=False):
	if(ccFlag):
		if(CitizenCard.valid_signature2(signature,data,publicKey)):
			logger.log('Server', 'Valid signature with CC on message: {}.'.format(data), 'blue')
			return
	else:
		if AsymCipher.valid_signature2(signature,data,publicKey):
			logger.log('Server', 'Valid signature with RSA cipher on message: {}.'.format(data), 'blue')
			return
	logger.log('Server','Invalid signature on message: {}.'.format(data),'red')
	logger.log('Server','Pentesting, are we?','red')
	sys.exit(3)


def handleHandshake(message,address):	# Handshake message format: "[Handshake]name?ccFlag?pubKey"
	decodedMessage = message.decode('utf-8')
	username = decodedMessage[decodedMessage.index(']')+1:decodedMessage.index('?')]
	ccFlag = decodedMessage[decodedMessage.index('?')+1:decodedMessage.rindex('?')]=='1'
	pubKey = pem_utils.get_publicKey_From_Pem(decodedMessage[decodedMessage.rindex('?')+1:].encode())
	registeredUsers[username] = (address,pubKey)
	sock.sendto(("[202]").encode(),address)
	if(verbose):
		logger.log('Server','Handshake accepted - User {}.'.format(username),'green')

	# Diffie-Hellman - Client (2)
	secretValue, sharedKey, address = DiffieHellman.getDHKey(sock)
	DiffieHellman.saveDHKey(dh_keys,address,secretValue,sharedKey)

	data, address = sock.recvfrom(4096)
	data = symDecipher(data,address)
	decodedMessage,signature = decodeSignedMessage(data,pubKey,ccFlag)
	if(decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='TableCreationRequest'):
		print("Going to add player creating the table!")
		tableID = handleTableCreationRequest(decodedMessage[decodedMessage.index(']')+1:])
		print("Next step")
		tableCredentials[tableID][2].addPlayer([username,address[0],address[1],0,None,[]])
	elif(decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='TableJoinRequest'):
		print("Going to add player!")
		tableID = decodedMessage[decodedMessage.index(']')+1:decodedMessage.index('?')]
		password = decodedMessage[decodedMessage.index('?')+1:]
		errorCode = handleTableJoinRequest(tableID,password)
		if(errorCode==0):	# All good
			tableCredentials[tableID][2].addPlayer([username,address[0],address[1],0,None,[]])
		elif(errorCode==1):	# No matching tableID
			sock.sendto(("[404]").encode(),address)
		elif(errorCode==2):	# Wrong password
			sock.sendto(("[401]").encode(),address)
	else:
		logger.log('Server','Unexpected message. Protocol breach detected. Shutting down.','red')
		sys.exit(1)


def handleTableCreationRequest(password):
	# Create table
	tableID = ''.join(random.choices(['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'],k=8))
	while(isTableIDInUse(tableID)):
		tableID = ''.join(random.choices(['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'],k=8))
	tablePort = serverPort+1
	while(isTablePortInUse(tablePort)):
		tablePort += 1
	tableThread = TableThread(serverIP,tablePort,tableID,password,verbose)
	tableCredentials[tableID] = [password,tablePort,tableThread]
	tableThread.start()
	if(verbose):
		logger.log('Server','New table created ({},{}).'.format(tableID,password),'green')
	return tableID


def handleTableJoinRequest(tid,password):
	for tableID in tableCredentials: 
		if(tableID==tid):
			if(tableCredentials[tableID][0]==password):
				return 0	# All good
			return 2		# Wrong password
	return 1				# No matching tableID


# Main
if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('-v','--verbose',default=False,help='Print logs',action='store_true')
	args = parser.parse_args()
	verbose=args.verbose

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	server_address = (serverIP,serverPort)
	sock.bind(server_address)
	if(verbose):
		logger.log('Server','Table management running on {} port {}.'.format(*server_address),'green')

	while True:
		data, address = sock.recvfrom(4096)
		if(verbose):
			logger.log('Server','Received {} bytes from {}.'.format(len(data),address),'green')
#		threading.Thread(target = handleMessage, args = (data,address)).start()
		handleMessage(data,address)
