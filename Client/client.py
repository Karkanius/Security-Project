"""
=====================================================================================

		 Module:  Client

		Version:  1.0 January 2020
	   Revision:  1

		Authors:  Paulo Vasconcelos, Pedro Teixeira
   Organization:  University of Aveiro

=====================================================================================
"""
import signal
import base64
import socket
import sys
import argparse
import random
import threading
import time
import json
import math
from datetime import datetime
import os
from tinyec import registry
import secrets
import logger



sys.path.append(os.path.abspath(os.getcwd()))	# solve import issues
from security import pem_utils
from security.citizen_card import CitizenCard
from security.asym_cipher import AsymCipher
from security.sym_cipher import SymCipher
from security.diffie_hellman import DiffieHellman

CARD_BIT_SIZE = 64

verbose = False
name = "NewUser"
hand = []
myIP = socket.gethostbyname(socket.gethostname())
myPort = random.randint(20000,30000)
serverIP = 0
serverPort = 0
otherPlayers = {}
selfPosition = None
citizen_card: CitizenCard = None
asym_cipher: AsymCipher = None
sym_cipher: SymCipher = None

privateKey = '0'
publicKey = '0'	# Keys must be strings or be converted to strings so they be encoded in order to be send via UDP

battlecryList = [	'Bring it, bitch!',
					'tyler1 has joined the chat',
					'*Pizza music stops*',
					'This is not okie dokie.',
					'I must have faith in my cards!',
					'Keep the change, you filthy animal!',
					'Meatballs, lasagna!',
					'Let\'s duel!',
					'Pull the lever, Kronk!',
					'A wild RNM appears',
					'I\'m just getting warmed up',
					'I\'ve got this!',
					'Time to show my skills',
					'Sandwich and I are coming for you',
					'Here I come',
					'Last one alive, lock the door',
					'Let\'s do it!',
					'Blinds nulls']

def serializeBytes(binMsg):
	return base64.encodebytes(binMsg).decode('ascii')


def deserializeBytes(strMsg):
	return base64.decodebytes(strMsg.encode('ascii'))


def serializeDeck(deck):
	for i in range(len(deck['validCards'])):
		deck['validCards'][i] = serializeBytes(deck['validCards'][i])
	for i in range(len(deck['removedCards'])):
		deck['removedCards'][i] = serializeBytes(deck['removedCards'][i])
	return deck


def deserializeDeck(deck):
	for i in range(len(deck['validCards'])):
		deck['validCards'][i] = deserializeBytes(deck['validCards'][i])
	for i in range(len(deck['removedCards'])):
		deck['removedCards'][i] = deserializeBytes(deck['removedCards'][i])
	return deck


def serializeHand(hand):
	for i in range(len(hand)):
		hand[i] = serializeBytes(hand[i])
	return hand


def deserializeHand(hand):
	for i in range(len(hand)):
		hand[i] = deserializeBytes(hand[i])
	return hand



# ======================
# === Diffie Hellman ===
# ======================
dh_sharedPrime = 23
dh_sharedBase = 5
#dh_sharedPrime = 23
#dh_sharedBase = 5
dh_keys = {} # address = [selfSecret,key,SymCipherInstance,AsymCipherInstance]

deckSymCipherKey = str(random.randint(1,64))
deckSymCipher = SymCipher(deckSymCipherKey)


def symCipherAndSend(message,address):
	cipheredMessage = dh_keys[address][2].cipher(message)
	sock.sendto(cipheredMessage, address)


def symDecipher(data,address):
	print("--------" + str(len(data)))
	return dh_keys[address][2].decipher(data)


def asymCipherAndSend(message,address):
	cipheredMessage = dh_keys[address][3].cipher(message)
	sock.sendto(cipheredMessage, address)


def asymDecipher(data,address):
	return dh_keys[address][3].decipher(data)


def signMessage(msg):
	if citizen_card is None:
		# sign with RSA
		signature = asym_cipher.sign(msg)
	else:
		# sign with citizen card
		signature = citizen_card.sign(msg)
	return signature


def sendBytesToServer(bytes):
	sock.sendto(b"".join([bytes]), (serverIP,serverPort))


def sendSignedBytesToServer(bytes,signature):
	sock.sendto(b"".join([bytes,'\v'.encode(),signature]), (serverIP,serverPort))


def createTable():
	password = input("Set table password\n> ")
	msg = "[TableCreationRequest]{}".format(password)
	msg = msg.encode()
	signature = signMessage(msg)
	msg = b"".join([msg,'\v'.encode(),signature])
	symCipherAndSend(msg,(serverIP,serverPort))


def joinTable():
	global tableID
	tableID = input("Table ID\n> ")
	tablePassword = input("Table password\n> ")
	msg = ("[TableJoinRequest]"+tableID+"?"+tablePassword)
	msg = msg.encode()
	signature = signMessage(msg)
	msg = b"".join([msg,'\v'.encode(),signature])
	symCipherAndSend(msg,(serverIP,serverPort))


def getRandomBattleCry():
	return random.choice(battlecryList)


def cardToString(cardDecimalValue):
	retVal = ''
	symbol = cardDecimalValue%16
	if(symbol>1 and symbol<11):
		retVal += str(symbol)
	elif(symbol==11):
		retVal += 'Jack'
	elif(symbol==12):
		retVal += 'Queen'
	elif(symbol==13):
		retVal += 'King'
	elif(symbol==14):
		retVal += 'Ace'
	else:
		logger.log('Client','Invalid card value - symbol. Shutting down.','red')
		sys.exit(2)
	retVal += ' of '
	suit = cardDecimalValue//16
	if(suit==0):
		retVal += 'Hearts'
	elif(suit==1):
		retVal += 'Spades'
	elif(suit==2):
		retVal += 'Diamonds'
	elif(suit==3):
		retVal += 'Clubs'
	else:
		logger.log('Client','Invalid card value - suit. Shutting down.','red')
		sys.exit(2)
	return retVal


def stringToCard(cardString):
	lst = cardString.split(' of ')
	symbol = lst[0]
	suit = lst[1]
	symbolList = [None,None,'2','3','4','5','6','7','8','9','10','Jack','Queen','King','Ace']
	suitList = ['Hearts','Spades','Diamonds','Clubs']
	if(symbol in symbolList and suit in suitList):
		return suitList.index(suit)*16+symbolList.index(symbol)
	return 0


def getUsername(self,address):
		for position in otherPlayers:
			if(otherPlayers[position][1]==address[0] and self.players[position][2]==address[1]):
				return self.players[position][0]
		return None



# ==================================
# === Ciphered Deck Interactions ===
# ==================================
def cipherDeck(deck):
	cipheredDeck = {}
	cipheredDeck['validCards'] = []
	cipheredDeck['removedCards'] = []
	for c in deck['validCards']:
		cipheredDeck['validCards'].append(deckSymCipher.cipher(c))
	for c in deck['removedCards']:
		cipheredDeck['removedCards'].append(deckSymCipher.cipher(c))
	return cipheredDeck



def encryptedRemoveCard(deck):
	# Shuffle
	random.shuffle(deck['validCards'])
	random.shuffle(deck['removedCards'])
	# Remove a card
	removedCard = deck['validCards'].pop()
	deck['removedCards'].append(removedCard)
	hand.append(removedCard)
	if(verbose):
		logger.log('Client','Card removed.','green')
	return deck


def encryptedExchangeCard(deck):
	# Shuffle
	random.shuffle(deck["validCards"])
	random.shuffle(deck['removedCards'])

	# Exchange a card
	cardFromHand = random.choice(hand)
	if cardFromHand in deck['removedCards']:
		cardToBeExchanged = random.choice(deck["validCards"])
		hIndex = hand.index(cardFromHand)
		rIndex = deck['removedCards'].index(cardFromHand)
		vIndex = deck["validCards"].index(cardToBeExchanged)
		hand[hIndex] = cardToBeExchanged
		deck['removedCards'][rIndex] = cardToBeExchanged
		deck["validCards"][vIndex] = cardFromHand

	if(verbose):
		logger.log('Client','Card exchanged.','green')
	return deck


def encryptedShuffle(deck):
	# Shuffle
	random.shuffle(deck["validCards"])
	random.shuffle(deck["removedCards"])
	if(verbose):
		logger.log('Client','Deck shuffled.','green')
	return deck


def encryptedCheckIfEmpty(deck):
	return len(deck['validCards'])==0


def getPreviousPlayer(player):
	if(player=='North'):
		return 'West'
	if(player=='West'):
		return 'South'
	if(player=='South'):
		return 'East'
	if(player=='East'):
		return 'North'
	else:
		logger.log('Client','Invalid player related request. Shutting down.','red')
		sys.exit(2)


def getInitialSuitDecimal(playedCards):
	if(sum(list(playedCards.values()))==0):	# Case no Card Played
		return None
	currentPlayer = getPreviousPlayer(selfPosition)
	if(playedCards[currentPlayer]==0):
		logger.log('Client','No card played before. Shutting down.','red')
		sys.exit(2)
	while playedCards[getPreviousPlayer(currentPlayer)]!=0:
		currentPlayer = getPreviousPlayer(currentPlayer)
	if(verbose):
		suits = ['Hearts','Spades','Diamonds','Clubs']
		logger.log('Client','Initial suit: {}'.format(suits[playedCards[currentPlayer]//16]),'green')
	return playedCards[currentPlayer]//16


def printTable(playedCards):
	printPlayedCardFromPlayer('North',playedCards)
	printPlayedCardFromPlayer('East',playedCards)
	printPlayedCardFromPlayer('South',playedCards)
	printPlayedCardFromPlayer('West',playedCards)


def printPlayedCardFromPlayer(player, playedCards):
	if(playedCards[player]==0):
		print('\033[94m{}: \033[0m-'.format(player))
	else:
		print('\033[94m{}: \033[0m{}'.format(player,cardToString(playedCards[player])))


def printScore(score):
	print('\033[94mNorth: \033[0m{} points'.format(score["North"]))
	print('\033[94mEast : \033[0m{} points'.format(score["East"]))
	print('\033[94mSouth: \033[0m{} points'.format(score["South"]))
	print('\033[94mWest : \033[0m{} points'.format(score["West"]))


def play(suitDecimal, brokenHearts, firstPlay=False):
	cardToPlay = 0
	while cardToPlay==0:
		logger.log('Client','Cards in hand:','violet')
		for i in range(len(hand)):
			logger.log('Client','[{}] {}'.format(i+1,cardToString(hand[i])),'violet')
		op = input('> ')
		if(op=='\\cheat'):
			cardToPlay = cheatPlay()
			break
		cardToPlay = hand[int(op)-1]
		if(not isValidPlay(cardToPlay,suitDecimal,brokenHearts,firstPlay)):
			if(not(input('\033[93mWARNING: You are about to play an invalid card. Do you wish to play it anyway? (yes/NO)\033[0m\n> ').lower() in ['y','yes'])):
				cardToPlay = 0
			else:
				hand.pop(int(op)-1)
		else:
			hand.pop(int(op)-1)
	symCipherAndSend(str(cardToPlay).encode(),(serverIP,serverPort))
	if(verbose):
		logger.log('Client','Played {}.'.format(cardToString(cardToPlay)),'green')


def isValidPlay(cardDecimalValue, suitDecimal, brokenHearts, firstPlay=False):
	if(firstPlay):											# First play of the game
		return cardDecimalValue==50							# 2 of Clubs
	if suitDecimal==None:									# First card of the round
		return brokenHearts or cardDecimalValue//16!=0
	if handHasSuit(suitDecimal):							# Have to assist
		return suitDecimal==cardDecimalValue//16			# Card has to be same suit
	return True												# Can't assist


def handHasSuit(suit):
	for card in hand:
		if card//16==suit:
			return True
	return False


def showHand():
	sendContent = {}
	sendContent['key']=publicKey
	sendContent['cards']=hand
	symCipherAndSend('{}'.format(json.dumps(sendContent)).encode(),(serverIP,serverPort))
	sys.exit(0)


def cheatPlay():
	print('\033[91m',end='')
	print('! =======================================')
	print('! ============ CHEATING MODE ============')
	print('! =======================================')
	print('! Choose a card to remove from your hand:\033[0m')
	for i in range(len(hand)):
		print('\033[91m! [{}] {}\033[0m'.format(i+1,cardToString(hand[i])))
	index = int(input('\033[91m! \033[93m> \033[0m'))
	while(index<1 or index>len(hand)):
		print('\033[91m! ERROR: Invalid card.\033[0m')
		print('! Choose a card to remove from your hand:\033[0m')
		index = int(input('\033[91m! \033[93m> \033[0m'))
	hand.pop(index-1)
	print('\033[91m! \033[93mType the card you wish to play:\033[0m')
	cardVal = stringToCard(input('\033[91m! \033[93m> \033[0m'))
	while(cardVal==0):
		print('\033[91m! ERROR: Invalid card.\033[0m')
		print('\033[91m! \033[93mType the card you wish to play:\033[0m')
		cardVal = stringToCard(input('\033[91m! \033[93m> \033[0m'))
	return cardVal



def accounting(score, myTableID):
	ccid = name

	date = datetime.now()
	dateForDetails = date.strftime("%d-%b-%Y, %H:%M:%S:%f")
	dateForFileName = date.strftime("%d%b%Y_%H_%M_%S_%f")

	accountingDetails = {	"MyID" 	: ccid,
				  "Date" 	: dateForDetails,
				  "TableID"  : myTableID,
				  "North" 	: score["North"],		# TODO get rest of info from players
				  "East" 	: score["East"],
				  "South"	: score["North"],
				  "West" 	: score["North"]
				  }

	# Sign over score
	accountingDetailsBytes = json.dumps(accountingDetails).encode('utf-8')

	if citizen_card is None:
		signedAccoutingDetails = asym_cipher.sign(accountingDetailsBytes)
	else:
		signedAccoutingDetails = citizen_card.sign(accountingDetailsBytes)

	print(signedAccoutingDetails)
	print(type(signedAccoutingDetails))

	# Write to file
	f = open("accounting/{}-{}-{}.txt".format(ccid, tableID, dateForFileName), "w")
	f.write(str(accountingDetails))
	f.write("\n")
	f.close()
	f = open("accounting/{}-{}-{}.txt".format(ccid, tableID, dateForFileName), "ab")
	f.write(signedAccoutingDetails)
	f.close()

class SIGINT_handler():
	def __init__(self):
		self.SIGINT = False

	def signal_handler(self, signal, frame):
		print('Going to exit')
		self.SIGINT = True

		# free up slot
		if citizen_card is not None:
			citizen_card.signOut()
		sys.exit(0)

# Main
if __name__ == "__main__":
	handler = SIGINT_handler()
	signal.signal(signal.SIGINT, handler.signal_handler)

	parser = argparse.ArgumentParser()
	parser.add_argument('-v','--verbose',default=False,help='Print logs',action='store_true')
	parser.add_argument('-u','--username',default="NewUser",help='Username')
	parser.add_argument('-i', '--ip-address', type=str, help='Server IP address', required=True)
	parser.add_argument('-p', '--port', type=int, help='Server port', required=True)
	args = parser.parse_args()
	verbose=args.verbose

	# Create Citizen Card instance
	try:
		citizen_card = CitizenCard("PIN - NOT USED")
		name = citizen_card.get_name()
		logger.log('Client', 'Using Citizen Card with name {} and id {}'.format(name, citizen_card.get_number()), 'green')
	except Exception as e:
		logger.log('Client', e, 'red')
		logger.log('Client', 'Not using Citizen Card - no available cards. Using name on arguments', 'red')
		name = args.username
		exception_happened = True

	# Create RSA and AES ciphers
	asym_cipher = AsymCipher(name)
	sym_cipher = SymCipher(name)

	# Get Public Keys
	if citizen_card is None:												# no citizen card
		publicKey = asym_cipher.getPubKey()
		publicKeyPem = pem_utils.get_publicKey_To_Pem(publicKey)
	else:
		publicKey = citizen_card.get_pubKey()							# use citizen card
		publicKeyPem = pem_utils.get_publicKey_To_Pem(publicKey)

	serverIP = args.ip_address
	serverPort = args.port
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((myIP,myPort))

	ccFlag = int(citizen_card is not None)
	sock.sendto(b"".join(["[Handshake]{}?{}?".format(name, ccFlag).encode(), publicKeyPem]),(serverIP,serverPort))
	if(verbose):
		logger.log('Client','Handshake sent to {}.'.format((serverIP,serverPort)),'green')
	data, address = sock.recvfrom(1048576)
	responseCode = int(data.decode()[data.decode().index('[')+1:data.decode().index(']')])
	while(responseCode!=202):
		if(verbose):
			logger.log('Client',data.decode(),'yellow')
		if(responseCode==401):
			if(data.decode()[data.decode().index(']')+1:]=="Address already in use."):
				myPort+=1
				sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
				sock.bind((myIP,myPort))
				sock.sendto(("[Handshake]"+name).encode(),(serverIP,serverPort))
				data, address = sock.recvfrom(1048576)
				responseCode = int(data.decode()[data.decode().index('[')+1:data.decode().index(']')])
	if(verbose):
		logger.log('Client',data.decode(),'green')

	# Diffie-Hellman - Server (1)
	secretValue, sharedKey, address = DiffieHellman.getDHKey(sock,(serverIP,serverPort))
	DiffieHellman.saveDHKey(dh_keys,address,secretValue,sharedKey)

	choice = int(input("Do you want to create a new table or join an existing one?\n1 - New table\n2 - Join table\n> "))
	while(choice!=1 and choice!=2):
		print("Warning: Invalid choice")
		choice = int(input("Do you want to create a new table or join an existing one?\n1 - New table\n2 - Join table\n> "))
	if(choice==1):
		createTable()
		data, address = sock.recvfrom(1048576)
		# Mandatory log, not dependent on verbose
		tableID = data.decode()[data.decode().index(']')+1:data.decode().index('?')]
		logger.log('Client','TableID is {}.'.format(data.decode()[data.decode().index(']')+1:data.decode().index('?')]),'green')
		if(verbose):
			logger.log('Client',data.decode(),'green')
	elif(choice==2):
		joinTable()
		data, address = sock.recvfrom(1048576)
		responseCode = int(data.decode()[data.decode().index('[')+1:data.decode().index(']')])
		while(responseCode!=200):
			# Mandatory log, not dependent on verbose
			logger.log('Client','[{}]Error joining table.'.format(responseCode),'yellow')
			joinTable()
			data, address = sock.recvfrom(1048576)
			responseCode = int(data.decode()[data.decode().index('[')+1:data.decode().index(']')])
		if(verbose):
			logger.log('Client',data.decode(),'green')
	selfPosition = data.decode()[data.decode().index('?')+1:data.decode().rindex('?')]
	serverPort = int(data.decode()[data.decode().rindex('?')+1:])

	# Diffie-Hellman - Table (1)
	secretValue, sharedKey, address = DiffieHellman.getDHKey(sock,(serverIP,serverPort))
	DiffieHellman.saveDHKey(dh_keys,address,secretValue,sharedKey)

	# Full Table, Game Starting
	data, address = sock.recvfrom(1048576)
	data = symDecipher(data,address)
	decodedMessage = data.decode()
	if(decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='GameOn'):
		if(verbose):
			logger.log('Client','Table is full. Game is beggining.','green')
		battlecry = input("Battle cry\n> ")
		if(battlecry=="\\random"):
			battlecry = getRandomBattleCry()
		#sock.sendto(('[GameOn]{}'.format(battlecry)).encode(),(serverIP,serverPort))
		symCipherAndSend(('[GameOn]{}'.format(battlecry)).encode(),(serverIP,serverPort))
	else:
		logger.log('Client','Unexpected message. Protocol breach detected. Shutting down.','red')
		sys.exit(1)

	# Receive Deck, Shuffle and Return Deck to Table
	data, address = sock.recvfrom(1048576)
	data = symDecipher(data,address)
	decodedMessage = deserializeDeck(json.loads(data))
	if(verbose):
		logger.log('Client','Deck received, shuffling.','green')
	decodedMessage = encryptedShuffle(decodedMessage)	
	if(verbose):
		logger.log('Client','Deck shuffled, encrypting.','green')
	decodedMessage = cipherDeck(decodedMessage)
	if(verbose):
		logger.log('Client','Deck encrypted, returning deck to table.','green')
	symCipherAndSend(json.dumps(serializeDeck(decodedMessage)),(serverIP,serverPort))

	# Receive Other Players Information
	data, address = sock.recvfrom(1048576)
	data = symDecipher(data,address)
	decodedMessage = data.decode()
	if(decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='PlayersInfo'):
		otherPlayers = json.loads(decodedMessage[decodedMessage.index(']')+1:])
		if(verbose):
			logger.log('Client',otherPlayers,'violet')
	else:
		logger.log('Client','Unexpected message. Protocol breach detected. Shutting down.','red')
		sys.exit(1)

	# Diffie-Hellman - Clients (1 or 2)
	myIPLst = myIP.split('.')
	toSendLst = []
	toReceiveLst = []
	print(otherPlayers)
	for pl in otherPlayers:
		plIPLst = otherPlayers[pl][1].split('.')
		if(int(myIPLst[0])>int(plIPLst[0])):
			toSendLst.append(pl)
		elif(int(myIPLst[0])<int(plIPLst[0])):
			toReceiveLst.append(pl)
		else:
			if(int(myIPLst[1])>int(plIPLst[1])):
				toSendLst.append(pl)
			elif(int(myIPLst[1])<int(plIPLst[1])):
				toReceiveLst.append(pl)
			else:
				if(int(myIPLst[2])>int(plIPLst[2])):
					toSendLst.append(pl)
				elif(int(myIPLst[2])<int(plIPLst[2])):
					toReceiveLst.append(pl)
				else:
					if(int(myIPLst[3])>int(plIPLst[3])):
						toSendLst.append(pl)
					elif(int(myIPLst[3])<int(plIPLst[3])):
						toReceiveLst.append(pl)
					else:
						if(myPort>otherPlayers[pl][2]):
							toSendLst.append(pl)
						else:
							toReceiveLst.append(pl)
	# Send to those that need to be sent
	for pl in toSendLst:
		address = (otherPlayers[pl][1],otherPlayers[pl][2])
		dh_keys[address] = [random.randint(1,16),None,None,None]	# [selfSecret, key, SymCipherInstance, AsymCipherInstance]
		valueToSend = (DiffieHellman.getSharedBase() ** dh_keys[address][0]) % DiffieHellman.getSharedPrime()
		msg = "{0:b}".format(valueToSend)
		sock.sendto(msg.encode(),address)
	# Listen to all
	for _ in range(len(otherPlayers)):
		data, address = sock.recvfrom(1048576)
		# Answer to the rest
		if(address not in dh_keys.keys()):
			dh_keys[address] = [random.randint(1,16),None,None,None]	# [selfSecret, key, SymCipherInstance, AsymCipherInstance]
			valueToSend = (DiffieHellman.getSharedBase() ** dh_keys[address][0]) % DiffieHellman.getSharedPrime()
			msg = "{0:b}".format(valueToSend)
			sock.sendto(msg.encode(),address)
		try:
			sharedKey = (int(data.decode(),2) ** dh_keys[address][0]) % DiffieHellman.getSharedPrime()
		except:
			logger.log('Client',data,'red')
		dh_keys[address][1] = sharedKey
		dh_keys[address][2] = SymCipher(str(sharedKey))
		dh_keys[address][3] = AsymCipher(str(sharedKey))

	# Deck Will Now Be Passed Around The Players
	data, address = sock.recvfrom(1048576)
	data = symDecipher(data,address)
	data = json.loads(data)
	# While Deck Not Empty
	while(data!={}):
		data = deserializeDeck(data)
		# Decide What to Do With Deck
		validActions = [encryptedShuffle]				# Shuffling Is Always An Option
		if(len(hand)>0):
			validActions.append(encryptedExchangeCard)	# If Hand Empty, Unable to Exchange Cards
		if(len(hand)<13):
			validActions.append(encryptedRemoveCard)	# If Hand Full, Unable to Remove Cards
		action = random.choice(validActions)
		# Perform Action
		data = action(data)
		if(encryptedCheckIfEmpty(data)):
			newDic = {}
			symCipherAndSend(json.dumps(newDic),(serverIP,serverPort))
			# Wait for Information Broadcast
		else:
			# Send Deck to Random Player
			target = random.choice(list(otherPlayers.keys()))
			symCipherAndSend(json.dumps(serializeDeck(data)),(otherPlayers[target][1],otherPlayers[target][2]))
			# Wait for Deck
		data, address = sock.recvfrom(1048576)
		data = json.loads(symDecipher(data,address))
	if(verbose):
		logger.log('Client','Deck empty.','green')
	time.sleep(1)

	# Send Signed Hand to Table
	symCipherAndSend((b''.join([(b''.join(hand)),'\v'.encode(),signMessage(b''.join(hand))])),(serverIP,serverPort))
	if(verbose):
		logger.log('Client','Hand signed and sent.','green')

	# Send Public Key to Other Players
	for p in otherPlayers.values():
		symCipherAndSend(str(deckSymCipherKey).encode(),(p[1],p[2]))
	if(verbose):
		logger.log('Client','Public key broadcasted.','green')

	# Receive and Store Public Keys
	for i in range(3):
		data, address = sock.recvfrom(1048576)
		data = symDecipher(data,address)
		for p in otherPlayers:
			if(address == (otherPlayers[p][1],otherPlayers[p][2])):
				otherPlayers[p].append(int(data.decode()))
				if(verbose):
					logger.log('Client','Public key received from {}({}). Number of public keys received: {}.'.format(p,p[0],i+1),'green')

	# Decrypt Hand (and Convert to Decimal)
	decipheringLst = []
	orderLst = ['West','South','East','North']
	for i in range(len(orderLst)):
		if orderLst[i]==selfPosition:
			for j in range(len(hand)):
				hand[j] = deckSymCipher.decipher(hand[j])
		else:
			symInstance = SymCipher(str(otherPlayers[orderLst[i]][3]))
			for j in range(len(hand)):
				hand[j] = symInstance.decipher(hand[j])
	for i in range(len(hand)):
		hand[i] = int(hand[i].decode())
	hand.sort()
	if(verbose):
		logger.log('Client','Hand decrypted.','green')

	# Play
	playFirst = 50 in hand	# Whether the player will make the first play of the round
	brokenHearts = False
	firstPlay = 50 in hand	# Whether the player will make the first play of the game
	while(len(hand)>12):
		initialSuitDecimal = None
		if(playFirst and 50 in hand):	# 2 of Clubs => 3*16+2 = 50
			firstPlay = True
		elif(not playFirst):
			data, address = sock.recvfrom(1048576)
			data = symDecipher(data,address)
			decodedMessage = data.decode() # decodedMessage: '[True/False]{"North":cardDecimalValue,"East":cardDecimalValue,"South":cardDecimalValue,"West":cardDecimalValue}'
			if decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='ShowHand':
				showHand()
			playedCards = json.loads(decodedMessage[decodedMessage.index(']')+1:])
			initialSuitDecimal = getInitialSuitDecimal(playedCards)
			printTable(playedCards)
			brokenHearts = decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='True'
		play(initialSuitDecimal, brokenHearts, firstPlay)
		firstPlay = False
		# Wait Round End
		data, address = sock.recvfrom(1048576)
		print("----------->" + str(data))
		data = symDecipher(data,address)
		decodedMessage = data.decode()
		if decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='ShowHand':
			showHand()
		playFirst = decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='Taken'
		playedCards = json.loads(decodedMessage[decodedMessage.index(']')+1:])
		printTable(playedCards)


	# 13 Rounds Over
	# Cheating Protest Phase
	if(input('Do you want to protest (cheating)? (yes/NO)\n> ').lower() in ['y','yes']):
		symCipherAndSend('[Protest]'.encode(),(serverIP,serverPort))
	else:
		symCipherAndSend('[NoProtest]'.encode(),(serverIP,serverPort))

	# Print Scores
	data, address = sock.recvfrom(1048576)
	data = symDecipher(data,address)
	decodedMessage = json.loads(data.decode())

	# TODO verify server signature?
	# TODO Check if server score equals client accounting
	printScore(decodedMessage)

	# Accouting
	accounting(decodedMessage, tableID)

	# Exit
	if citizen_card is not None:
		citizen_card.signOut()






