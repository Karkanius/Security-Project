from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def get_publicKey_To_Pem(public_key):
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem


def get_publicKey_From_Pem(public_key):
    return serialization.load_pem_public_key(public_key, backend=default_backend())


def get_privateKey_To_Pem(private_key, passw):
    pem = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.BestAvailableEncryption(bytes(passw, "utf-8")))
    return pem


def get_privateKey_From_Pem(private_key, passw):
    return serialization.load_pem_private_key(private_key, backend=default_backend(), password=passw)
