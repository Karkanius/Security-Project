"""
=====================================================================================

         Module:  Security - Elliptic Curve Diffie-Hellman Key Agreement
                  Based on https://cryptobook.nakov.com/asymmetric-key-ciphers/ecdh-key-exchange-examples

        Version:  1.0 January 2020
       Revision:  1

        Authors:  Paulo Vasconcelos, Pedro Teixeira
   Organization:  University of Aveiro

=====================================================================================
"""

from tinyec import registry
import secrets


def compress(pubKey):
    return hex(pubKey.x) + hex(pubKey.y % 2)[2:]


def getSharedKey(sock, destinationIP, destinationPort, debug=False):
    curve = registry.get_curve('brainpoolP256r1')

    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g
    print("My private key {} {}:".format(privKey, type(privKey)))

    # Now exchange the public keys (e.g. through Internet)
    if not debug:
        sock.sendto(("[Key]" + pubKey).encode(), (destinationIP, destinationPort))
        data = sock.recvfrom(4096)
        decodedMessage = data.decode()
        pairPubKey = decodedMessage
    else:
        pairPrivKey = secrets.randbelow(curve.field.n)
        pairPubKey = pairPrivKey * curve.g

    mySharedKey = privKey * pairPubKey
    print("My shared key to {} {}:".format(compress(mySharedKey), destinationPort), compress(mySharedKey))

    if debug:
        pairSharedKey = pairPrivKey * pubKey
        print("Pair shared key to {} {}:".format(destinationIP, destinationPort), compress(mySharedKey))

        assert mySharedKey == pairSharedKey

    return compress(mySharedKey)
