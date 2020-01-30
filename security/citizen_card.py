"""
=====================================================================================

         Module:  Security - Citizen Card Operations

        Version:  1.0 January 2020
       Revision:  1

        Authors:  Paulo Vasconcelos, Pedro Teixeira
   Organization:  University of Aveiro

=====================================================================================
"""

import OpenSSL
from os import listdir
from OpenSSL import crypto
from OpenSSL.crypto import X509StoreFlags, load_certificate, FILETYPE_PEM, FILETYPE_ASN1
from PyKCS11 import *
from PyKCS11.LowLevel import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (padding)
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate

class CitizenCard:

    used_slots = []

    def __init__(self, pin):
        self.pin = pin  # PIN to be used on operations with Citizen Card

        # Obtain slot where card is
        lib = '/usr/local/lib/libpteidpkcs11.so'
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)
        slots = self.pkcs11.getSlotList()

        self.slot = None

        for slot in slots:
            if 'CARTAO DE CIDADAO' in self.pkcs11.getTokenInfo(slot).label:
                if slot not in CitizenCard.used_slots:
                    CitizenCard.used_slots.append(slot)
                    try:
                        f = open("slots/slot_{}.txt".format(slot), 'x')
                    except FileExistsError as e:
                        # Used slot, go to next
                        print("Used slot {}, exception {}".format(slot, e))
                        continue
                    except Exception as e:
                        self.slot = slot
                        break
                    else:
                        # Free slot
                        #print("Free slot {}".format(slot))
                        self.slot = slot
                        break

        if self.slot is None:
            raise Exception('No free slots')

        # Get public and private key
        session = self.pkcs11.openSession(self.slot)

        self.privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]

        pubKeyHandle = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
        pubKeyDer = session.getAttributeValue(pubKeyHandle, [CKA_VALUE], True)[0]
        self.pubKey = load_der_public_key(bytes(pubKeyDer), default_backend())

        session.closeSession()

        # Create store
        self._init_store()
        self._init_certs()

    def signOut(self):
        CitizenCard.used_slots.remove(self.slot)
        try:
            os.remove("slots/slot_{}.txt".format(self.slot))
        except Exception as e:
            pass

    # Getters
    def get_pubKey(self):
        """
        :return: public key
        """
        return self.pubKey

    def get_privkey(self):
        """
        Should not be used, private key is private
        :return: private key
        """
        return self.privKey

    def get_cert(self):
        return self.cert

    def get_name(self):
        if self.name is None:
            return "Unknown Name"
        return self.name

    def get_number(self):
        if self.number is None:
            return -1
        return self.number

    # Signature
    def sign(self, data):
        """
        :param data:
        :return: signed data
        """
        if self.slot is not None:
            if type(data) is not bytes:
                data = data.encode()

            session = self.pkcs11.openSession(self.slot)
            # session.login(self.pin)     # should work?
            signature = bytes(session.sign(self.privKey, data, Mechanism(CKM_SHA1_RSA_PKCS)))
            session.closeSession

            return signature

        return None

    def valid_signature(self, signature, data):
        """
        :param signature:
        :param data:
        :return: True if signature is valid, False is it is not, else None
        """
        if self.slot is not None:
            data = bytes(data, 'utf-8')

            try:
                self.pubKey.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
                return True
            except:
                return False

        return None

    @staticmethod
    def valid_signature2(signature, data, pubKey):
        """
        :param signature:
        :param data:
        :return: True if signature is valid, False is it is not, else None
        """
        data = data.encode()

        try:
            pubKey.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
            return True
        except:
            return False

    # The following functions are based on
    # http://aviadas.com/blog/2015/06/18/verifying-x509-certificate-chain-of-trust-in-python/
    def verify_certificate_chain(self, cert):
        """
        :param cert:
        :return: True if certificate is valid, False if is not, else None (error situation)
        """
        if cert is None:
            return None

        # certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        certificate = cert

        # Create a certificate store and add your trusted certs
        try:
            # Create a certificate context using the store and the certificate
            store_ctx = crypto.X509StoreContext(self.store, certificate)

            # Verify the certificate, returns None if it can validate the certificate
            store_ctx.verify_certificate()

            return True

        except Exception as e:
            print(e)
            return False

    # Auxiliar functions
    def _init_certs(self):
        session = self.pkcs11.openSession(self.slot)

        try:
            info = session.findObjects(
                ([(CKA_CLASS, CKO_CERTIFICATE), (CKA_LABEL, "CITIZEN AUTHENTICATION CERTIFICATE")]))
        except PyKCS11Error:
            print("Problem with finding certificates")
            return None
        else:
            try:
                der = bytes([c.to_dict()['CKA_VALUE'] for c in info][0])
            except:
                print("Problem 2 with finding certificates")
                return None
            else:
                # converting DER format to X509 certificate
                try:
                    cert = load_der_x509_certificate(der, default_backend()).public_bytes(Encoding.PEM)
                except:
                    print("Problem 2 with finding certificates")
                    return None
                else:
                    self.cert = load_pem_x509_certificate(cert, default_backend())
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

                    # components = x509.get_subject().get_components()        # get components of the subject, ie. the owner of the CC Card
                    # for component in components:
                    # Decode components from bytes to UTF-8
                    # new_component = (component[0].decode('utf-8'), component[1].decode('utf-8'))
                    # print("Component {:s}".format(str(new_component)))
                    # print("Tests {:s} {:s}".format(str(new_component[0] == "serialNumber"), str(new_component[0] == "CN")))
                    # if new_component[0] == "serialNumber":              # number of CC
                    #    #print("Number detected")
                    #    self.number = int(new_component[1][2:])
                    # elif new_component[0] == "CN":                      # name of CC owner
                    # print("CN detected")
                    #    self.name = new_component[1]

                    self.name = x509.get_subject().commonName
                    self.number = int(x509.get_subject().serialNumber[2:])

    def _init_store(self):
        dirname = os.path.dirname(__file__)
        path = os.path.join(dirname, "certs/")
        self.store = crypto.X509Store()
        self.store.set_flags(X509StoreFlags.CRL_CHECK | X509StoreFlags.IGNORE_CRITICAL)

        for filename in listdir(path):
            filepath = path + filename
            try:
                cert_info_file = open(filepath, 'rb')
                cert_info = cert_info_file.read()
            except IOError:
                print("IO Exception while reading file : {:s}".format(filepath))
                exit(-1)
            else:
                if ".cer" in filename:
                    try:
                        cert = None
                        # thanks to our colleague Andre Mourato for this part
                        if "0012" in filename or "0013" in filename or "0015" in filename:
                            cert = load_certificate(FILETYPE_PEM, cert_info)
                        elif "Raiz" in filename:
                            cert = load_certificate(FILETYPE_ASN1, cert_info)
                        else:
                            cert = load_certificate(FILETYPE_ASN1, cert_info)
                        # end of part ---

                        if cert is not None:
                            self.store.add_cert(cert)

                    except Exception as e:
                        print("Exception while loading certificate from file {:s} : {:s}".format(filepath, e))
                        exit(-1)

                elif ".crt" in filename:
                    try:
                        if "ca_ecc" in filename:
                            root = load_certificate(FILETYPE_PEM, cert_info)
                        elif "-self" in filename:
                            root = load_certificate(FILETYPE_PEM, cert_info)
                        else:
                            root = load_certificate(FILETYPE_ASN1, cert_info)

                        if root is not None:
                            self.store.add_cert(root)

                    except Exception as e:
                        print("Exception while loading certificate from file {:s} : {:s}".format(filepath, e))
                        exit(-1)
                cert_info_file.close()

