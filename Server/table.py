"""
=====================================================================================

         Module:  Table

        Version:  1.0 January 2020
       Revision:  1

        Authors:  Paulo Vasconcelos, Pedro Teixeira
   Organization:  University of Aveiro

=====================================================================================
"""
import math
import os
import base64
import socket
import sys
import threading
import json
import time
import random
import logger

sys.path.append(os.path.abspath(os.getcwd()))	# solve import issues
from Client.client import sendBytesToServer
from security.asym_cipher import AsymCipher
from security.sym_cipher import SymCipher
from security.diffie_hellman import DiffieHellman


CARD_BIT_SIZE = 64



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


# ======================
# === Diffie Hellman ===
# ======================
dh_sharedPrime = 877
dh_sharedBase = 513
#dh_sharedPrime = 23
#dh_sharedBase = 5
dh_keys = {} # address = [selfSecret,key,SymCipherInstance,AsymCipherInstance]


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



class TableThread(threading.Thread):
	
	def __init__(self, ip, port, tid, password, v=False):
		threading.Thread.__init__(self)
		self.cards = self.generatePlainDeck()
		self.ip = ip
		self.port = port
		self.tableID = tid
		self.password = password
		self.players = {'North':None,'East':None,'South':None,'West':None} # player = [username,ip,port,pointsToMoment,signedHand,listOfPlayedCards]
		self.verbose = v
		if(self.verbose):
			logger.log('Table','New TableThread created ({},{},{}).'.format(self.port,self.tableID,self.password),'green')
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.bind((self.ip,self.port))


	def symCipherAndSend(self,message,address):
		cipheredMessage = dh_keys[address][2].cipher(message)
		self.sock.sendto(cipheredMessage, address)


	def symDecipher(self,data,address):
		return dh_keys[address][2].decipher(data)


	def asymCipherAndSend(self,message,address):
		cipheredMessage = dh_keys[address][3].cipher(message)
		self.sock.sendto(cipheredMessage, address)


	def asymDecipher(self,data,address):
		return dh_keys[address][3].decipher(data)


	def generatePlainDeck(self):
		deck = [] # 52 = deck size
		for i in range(4):
			for j in range(2,15):
				deck.append(str(i*16+j).encode())
		dic = {}
		dic['validCards'] = deck
		dic['removedCards'] = []
		return dic


	def run(self):
		if(self.verbose):
			logger.log('Table','TableThread ({},{},{}) is now listening.'.format(self.port,self.tableID,self.password),'green')
		
		# Diffie-Hellman
		for _ in range(4):
			# Diffie-Hellman - Client (2)
			secretValue, sharedKey, address = DiffieHellman.getDHKey(self.sock)
			DiffieHellman.saveDHKey(dh_keys,address,secretValue,sharedKey)


		# Table is full
		if(self.verbose):
			logger.log('Table','Table full, game starting.','green')
		self.startGame()

		# Receive GameOn replies		
		for _ in range(4):
			data, address = self.sock.recvfrom(1048576)
			data = self.symDecipher(data,address)
			decodedMessage = data.decode()
			if(decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='GameOn'):
				player = self.getUsername(address)
				if(self.verbose):
					logger.log('Table','Player {} is ready to play.'.format(player),'green')
				if(len(decodedMessage[decodedMessage.index(']')+1:])>0):
					logger.log('Table','Player {} says: \033[91m\"{}\"'.format(player,decodedMessage[decodedMessage.index(']')+1:]),'violet')
			else:
				logger.log('Table','Unexpected message. Protocol breach detected. Shutting down.','red')
				sys.exit(1)

		# Send deck to be shuffled and encrypted
		for player in self.players:
			if(self.verbose):
				logger.log('Table','Deck sent to player {}({}).'.format(player, self.players[player][0]),'green')
			self.shuffleAndEncrypt(player)
			if(self.verbose):
				logger.log('Table','Player {}({}) returned deck after shuffling and encrypting.'.format(player, self.players[player][0]),'green')

		# Broadcast addresses info
		self.broadcastPlayersInfo()

		# Wait for players to get Diffie Hellman all over the place
		waitTime = 2
		if(self.verbose):
			logger.log('Table','Waiting for players to get to know each other.','green')
		for i in range(waitTime,0,-1):
			if(self.verbose):
				logger.log('Table','{}'.format(i),'green')
			time.sleep(1)

		# Give deck to North to begin deck distribution
		self.symCipherAndSend(json.dumps(serializeDeck(self.cards)),(self.players['North'][1],self.players['North'][2]))

		# Players are distributing the deck
		# Wait for signal that deck is empty
		data, address = self.sock.recvfrom(1048576)
		data = self.symDecipher(data,address)
		decodedMessage = json.loads(data)
		newDic = {}
		if(decodedMessage!=newDic):
			logger.log('Table','Unexpected message.','red')
			logger.log('Table','{} - {}'.format(decodedMessage,address),'red')

		# Send signal to players notifying the deck is empty
		newDic = {}
		for position in self.players:
			self.symCipherAndSend(json.dumps(newDic),(self.players[position][1],self.players[position][2]))

		# Receive encrypted and signed hands
		for _ in range(4):
			data, address = self.sock.recvfrom(1048576)
			data = self.symDecipher(data,address)
			for position in self.players:
				if(self.players[position][1]==address[0] and self.players[position][2]==address[1]):
					self.players[position][4] = data
					if(self.verbose):
						logger.log('Table','Stored signed hand from player {}({}).'.format(position, self.players[position][0]),'green')
					break

		# Play
		brokenHearts = False
		for playRound in range(1):
			roundSuit = None
			playedCards = {"North":0,"East":0,"South":0,"West":0}	# This is cardDecimalValue, not the amount of cards played (0 is an invalid cardDecimalValue)
			for play in range(4):
				data, address = self.sock.recvfrom(1048576)
				data = self.symDecipher(data,address)
				cardDecimalValue = int(data.decode())
				self.addCardToHistory(cardDecimalValue,self.getPlayerFromAddress(address))
				if play==0:
					roundSuit = cardDecimalValue//16
				if(cardDecimalValue//16==0):
					brokenHearts = True
				for position in self.players:
					if(self.players[position][1]==address[0] and self.players[position][2]==address[1]):
						if(self.verbose):
							logger.log('Table','{} played by {}({}).'.format(self.cardToString(cardDecimalValue), position, self.players[position][0]),'green')
						playedCards[position] = cardDecimalValue
						if(play<3):
							nextPlayer = self.getNextPlayer(position)
							self.symCipherAndSend('[{}]{}'.format(str(brokenHearts),json.dumps(playedCards)).encode(),(self.players[nextPlayer][1],self.players[nextPlayer][2]))
						break
			# Determine round winner
			roundWinner = self.getRoundWinner(roundSuit, playedCards)
			roundPoints = self.getRoundPoints(playedCards)
			self.players[roundWinner][3] += roundPoints
			# Broadcast cards played after every player played one
			for position in self.players:
				if(position==roundWinner):
					message='[Taken]'
				else:
					message='[NotTaken]'
				self.symCipherAndSend('{}{}'.format(message,json.dumps(playedCards)).encode(),(self.players[position][1],self.players[position][2]))
				#if(self.verbose):
				#	logger.log('Table','{} - {}'.format(position,message),'green')

		# End of 13 Rounds
		# Cheating Protest
		for _ in range(4):
			data, address = self.sock.recvfrom(1048576)
			data = self.symDecipher(data,address)
			decodedMessage = data.decode()
			if(decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='NoProtest'):
				player = self.getUsername(address)
				if(self.verbose):
					logger.log('Table','Player {} did not protest.'.format(player),'green')
			elif(decodedMessage[decodedMessage.index('[')+1:decodedMessage.index(']')]=='Protest'):
				player = self.getUsername(address)
				logger.log('Table','Player {} protested for cheating.'.format(player),'yellow')
			else:
				logger.log('Table','Unexpected message. Protocol breach detected. Shutting down.','red')
				sys.exit(1)

		# Scores
		pointsDic = {"North": self.players['North'][3],"East": self.players['East'][3],"South": self.players['South'][3],"West": self.players['West'][3]}
		for position in pointsDic:
			if(pointsDic[position]==26):
				pointsDic = {"North": 26,"East": 26,"South": 26,"West": 26}
				pointsDic[position] = 0
				break
		logger.log('Table','Player scores:','violet')
		for position in self.players:
			self.symCipherAndSend(json.dumps(pointsDic).encode(),(self.players[position][1],self.players[position][2]))
			logger.log('Table','Player {}: {}'.format(position,str(pointsDic[position])),'violet')


	def getUsername(self,address):
		for position in self.players:
			if(self.players[position][1]==address[0] and self.players[position][2]==address[1]):
				return self.players[position][0]
		return None


	def getPlayerFromAddress(self,address):
		for position in self.players:
			if(self.players[position][1]==address[0] and self.players[position][2]==address[1]):
				return position
		return None


	def cardAlreadyPlayed(self,cardDecimalValue):
		for position in self.players:
			if(cardDecimalValue in self.players[position][5]):
				return True
		return False


	def addCardToHistory(self,cardDecimalValue,player):
		if(self.cardAlreadyPlayed(cardDecimalValue)):
			self.players[player][5].append(cardDecimalValue)
			self.forcePlayersToShowHand()
			sys.exit(2)
		self.players[player][5].append(cardDecimalValue)


	def forcePlayersToShowHand(self):
		publicKeys = []
		for position in self.players:
			self.symCipherAndSend('[ShowHand]'.encode(),(self.players[position][1],self.players[position][2]))
		for _ in range(4):
			data, address = self.sock.recvfrom(1048576)
			data = self.symDecipher(data,address)
			player = self.getPlayerFromAddress(address)
			decodedMessage = json.loads(data.decode())	# decodedMessage = { key=playerKeyToDecrypt, cards=listOfTheCards[] }
			publicKeys.append(decodedMessage['key'])
			self.players[player][5].extend(decodedMessage['cards'])
		for _ in range(4):
			for key in publicKeys:
				pass
				# aplicar key à mão cifrada self.players[player][4]
				# self.players[player][4] = decifrar(self.players[player][4],key)
			# convert result to list of cardDecimalValue
			if(self.players[player][4].sort()!=self.players[player][5].sort()):	# In case signed hand differs from played hand
				logger.log('Table','Played hand differs from signed hand. Player {} cheated.'.format(self.players[player][1]),'red')
			sys.exit(2)


	def getNextPlayer(self,player):
		if(player=='North'):
			return 'East'
		if(player=='East'):
			return 'South'
		if(player=='South'):
			return 'West'
		if(player=='West'):
			return 'North'
		else:
			logger.log('Table','Invalid player related request. Shutting down.','red')
			sys.exit(2)


	def getRoundWinner(self,suit,cards):
		cardValues = list(cards.values())
		winner = None
		for v in cardValues:
			# Cheating
			if cardValues.count(v) > 1:
				logger.log('Table','Same cards played by more than one player. Shutting down.','red')
				sys.exit(2)
			if(v//16==suit and (winner==None or winner<v)):
				winner = v
		for c in cards:
			if(cards[c]==winner):
				if(self.verbose):
					logger.log('Table','Round winner: {}'.format(c),'green')		
				return c
		logger.log('Table','Round with no winner. Shutting down.','red')
		sys.exit(2)


	def getRoundPoints(self,cards):
		cardValues = list(cards.values())
		points = 0
		for v in cardValues:
			if cardValues.count(v) > 1:
				logger.log('Table','Same cards played by more than one player. Shutting down.','red')
				for position in self.players:
					self.sock.sendto('[ShowHand]'.encode(),(self.players[position][1],self.players[position][2]))
				sys.exit(2)
			if v//16==0:	# Hearts
				points += 1
			elif v==28:		# Queen of Spades
				points += 13
		return points


	def getNumberOfPlayers(self):
		retVal = 0
		for position in self.players:
			if(self.players[position]!=None):
				retVal+=1
		return retVal


	def addPlayer(self,player):
		address = (player[1],player[2])
		for position in self.players:
			if(self.players[position]==None):
				self.players[position] = player
				self.sock.sendto('[200]{}?{}?{}'.format(self.tableID,position,str(self.port)).encode(),address)
				if(self.verbose):
					logger.log('Table','Player {} added. Total players: {}.'.format(player,self.getNumberOfPlayers()),'green')
				return True
		if(self.verbose):
			logger.log('Table','Unable to add player {}.'.format(player),'yellow')
		return False


#	def playersKeepAlive():
#		for position in self.players:
#			self.sock.sendto("[KeepAlive]",(self.players[position][1],self.players[position][2]))
#		threading.Timer(1,playersKeepAlive).start()
	

	def startGame(self):
		for position in self.players:
			self.symCipherAndSend('[GameOn]'.encode(),(self.players[position][1],self.players[position][2]))


	def broadcastPlayersInfo(self):
		self.sendPlayersInfoTo('North')
		self.sendPlayersInfoTo('East')
		self.sendPlayersInfoTo('South')
		self.sendPlayersInfoTo('West')
		if(self.verbose):
			logger.log('Table','Players information broadcasted.','green')


	def sendPlayersInfoTo(self,target):
		content = {}
		for position in self.players:
			if(position!=target):
				content[position] = (self.players[position][0],self.players[position][1],self.players[position][2])
		#self.sock.sendto('[PlayersInfo]{}'.format(json.dumps(content)).encode(),(self.players[target][1],self.players[target][2]))
		self.symCipherAndSend('[PlayersInfo]{}'.format(json.dumps(content)).encode(),(self.players[target][1],self.players[target][2]))


	def shuffleAndEncrypt(self,target):
		self.symCipherAndSend(json.dumps(serializeDeck(self.cards)),(self.players[target][1],self.players[target][2]))
		data, address = self.sock.recvfrom(1048576)
		data = json.loads(self.symDecipher(data,address))
		data = deserializeDeck(data)
		self.cards = data


	def cardToString(self,cardDecimalValue):
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
			logger.log('Table','Invalid card value - symbol. Shutting down.','red')
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
			logger.log('Table','Invalid card value - suit. Shutting down.','red')
			sys.exit(2)
		return retVal


