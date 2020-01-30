"""
=====================================================================================

         Module:  UDP Connection Tests

        Version:  1.0 January 2020
       Revision:  1

        Authors:  Paulo Vasconcelos, Pedro Teixeira
   Organization:  University of Aveiro

=====================================================================================
"""


import socket
import threading
import random

server_address = (socket.gethostbyname(socket.gethostname()),10000)

def echoServer():
	global server_address
	serverSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	serverSock.bind(server_address)
	messageNumber = 0
	while True:
		data, address = serverSock.recvfrom(4096)
		print("[EchoServer][{}] Data received from: {}".format(messageNumber,address))
		print("[EchoServer][{}] Data length: {}/{} bytes".format(messageNumber,len(data),len(data.decode())))
		print("[EchoServer][{}] Data: {}\n".format(messageNumber,data.decode()))
		messageNumber += 1

def send(message):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sock.sendto(message,server_address)
	except:
		try:
			print("[Client] ERROR_0: Unable to send message {}".format(message))
		except:
			print("[Client] ERROR_1: Unable to send message.")




threading.Thread(target = echoServer).start()

send(["H02","H03","H04","H05","H06","H07","H08","H09","H10","H11"].encode())
send("H02H03H04H05H06H07H08H09H10H11".encode())

send("PlainText".encode())
send(b"PlainText")
send(bin(1).encode())
send("{:b}".format(1).encode())
send("{:8b}".format(1).encode())
send("{:08b}".format(1).encode())
send(bin(37).encode())
send("{:b}".format(37).encode())
send("{:8b}".format(37).encode())
send("{:08b}".format(37).encode())
send(bin(420).encode())
send("{:b}".format(420).encode())
send("{:8b}".format(420).encode())
send("{:08b}".format(420).encode())
"""
CARD_BIT_SIZE = 64

myHand = []

# Create deck
deck = ["{:064b}".format(52)] # 52 = deck size
for i in range(4):
	for j in range(13):
		# Each card will have a size of 8 bytes (64 bits)
		deck.append("{:064b}".format(i*16+j+2))
deck="".join(deck)


 
# === Remove Card ===
# Receive and handle deck
nValidCards = int("".join(deck[0:CARD_BIT_SIZE]),2)
validCards = []
removedCards = []
for offset in range(CARD_BIT_SIZE,(nValidCards+1)*CARD_BIT_SIZE,CARD_BIT_SIZE):
	validCards.append(deck[offset:offset+CARD_BIT_SIZE])
for offset in range((nValidCards+1)*CARD_BIT_SIZE,53*CARD_BIT_SIZE,CARD_BIT_SIZE):
	removedCards.append(deck[offset:offset+CARD_BIT_SIZE])

# Shuffle
random.shuffle(validCards)
random.shuffle(removedCards)

# Remove a card
myHand.append(validCards[len(validCards)-1])
nValidCards -= 1

# Put everything back together
deck = ["{:064b}".format(nValidCards)]
deck.extend(validCards)
deck.extend(removedCards)
deck="".join(deck)
print('Deck: {}'.format(deck))
print('Hand: {}'.format(myHand))


# === Exchange Card ===
# Receive and handle deck
nValidCards = int("".join(deck[0:CARD_BIT_SIZE]),2)
validCards = []
removedCards = []
for offset in range(CARD_BIT_SIZE,(nValidCards+1)*CARD_BIT_SIZE,CARD_BIT_SIZE):
	validCards.append(deck[offset:offset+CARD_BIT_SIZE])
for offset in range((nValidCards+1)*CARD_BIT_SIZE,53*CARD_BIT_SIZE,CARD_BIT_SIZE):
	removedCards.append(deck[offset:offset+CARD_BIT_SIZE])

# Shuffle
random.shuffle(validCards)
random.shuffle(removedCards)

# Exchange a card
#cardFromHand = selecionar carta da mão
cardFromHand = random.choice(myHand)
if cardFromHand in removedCards:
	#cardToBeExchanged = selecionar carta das disponíveis
	cardToBeExchanged = random.choice(validCards)
	hIndex = myHand.index(cardFromHand)
	rIndex = removedCards.index(cardFromHand)
	vIndex = validCards.index(cardToBeExchanged)
	myHand[hIndex] = cardToBeExchanged
	removedCards[rIndex] = cardToBeExchanged
	validCards[vIndex] = cardFromHand


# Put everything back together
deck = ["{:064b}".format(nValidCards)]
deck.extend(validCards)
deck.extend(removedCards)
deck="".join(deck)
print('Deck: {}'.format(deck))
print('Hand: {}'.format(myHand))
"""