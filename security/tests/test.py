import unittest

from security import pem_utils
from security.asym_cipher import AsymCipher, ECCCipher
from security.citizen_card import CitizenCard
from security.sym_cipher import SymCipher


class CitizenCardTests(unittest.TestCase):
    pin = ""

    def test_signature_equal(self):
        # Sign the data
        citizen_card = CitizenCard(self.pin)

        data = "Hello World"
        signature = citizen_card.sign(data)

        is_valid = citizen_card.valid_signature(signature, data)
        citizen_card.signOut()
        self.assertTrue(is_valid, msg="Signature should be valid")

    def test_signature_not_equal(self):
        # Sign the data
        citizen_card = CitizenCard(self.pin)

        data1 = "Hello World"
        signature = citizen_card.sign(data1)

        data2 = "Hello world, again"
        is_valid = citizen_card.valid_signature(signature, data2)
        citizen_card.signOut()
        self.assertFalse(is_valid, msg="Signature should be not valid")

    def test_validate_cert(self):
        citizen_card = CitizenCard(self.pin)

        cert = citizen_card.get_cert()
        is_valid = citizen_card.verify_certificate_chain(cert)
        citizen_card.signOut()
        self.assertTrue(is_valid, msg="Cert chain should be valid")

    def test_name_id(self):
        citizen_card = CitizenCard(self.pin)

        name = citizen_card.get_name()
        num = citizen_card.get_number()

        print("Name {:s}, Number {:s}".format(name, str(num)))
        citizen_card.signOut()
        self.assertTrue(True, msg="")  # dummy test

    def test_several_users(self):
        citizen_card = CitizenCard(self.pin)
        citizen_card.signOut()
        exception_happened = False

        try:
            citizen_card_2 = CitizenCard(self.pin)
            citizen_card_2.signOut()

        except Exception as e:
            print(e)
            exception_happened = True

        self.assertTrue(exception_happened, "Should have raised an exception (if only 1 card is connected)")


class SymCipherTests(unittest.TestCase):
    passwd = "pass"

    def test_sym_cipher_equal(self):
        # Sign the data
        sym_cipher = SymCipher(self.passwd)

        data = "Hello Worlds"
        ciphered_text = sym_cipher.cipher(data)

        deciphered_text = sym_cipher.decipher(ciphered_text)
        self.assertEqual(data, deciphered_text, msg="Result should be the same")

    def test_sym_ciphers_equal(self):
        # Sign the data
        sym_cipher = SymCipher(self.passwd)
        sym_cipher2 = SymCipher(self.passwd)

        data = "Hello Worlds"
        ciphered_text = sym_cipher.cipher(data)

        deciphered_text = sym_cipher2.decipher(ciphered_text)
        self.assertEqual(data, deciphered_text.decode(), msg="Result should be the same")

    def test_sym_cipher_not_equal(self):
        # Sign the data
        sym_cipher = SymCipher(self.passwd)

        data1 = "Hello World"
        data2 = "Hello World, again"

        ciphered_text = sym_cipher.cipher(data2)
        deciphered_text = sym_cipher.decipher(ciphered_text)

        self.assertNotEqual(data1, deciphered_text.decode(), msg="Result should not be the same")

    def test_sym_cipher_length(self):

        # Sign the data
        sym_cipher = SymCipher(self.passwd)

        data = "123"
        data2 = "345"
        data3 = "3455"

        ciphered_text_1 = sym_cipher.cipher(data)
        ciphered_text_2 = sym_cipher.cipher(data2)
        ciphered_text_3 = sym_cipher.cipher(data3)
        print("Len {} {} {}".format(type(ciphered_text_1), len(ciphered_text_2), len(ciphered_text_3)))

        self.assertEqual(len(ciphered_text_1), len(ciphered_text_2), msg="Result should be the same")

class AsymCipherTests(unittest.TestCase):
    passwd = "pass"

    def test_asym_cipher_equal(self):
        asym_cipher = AsymCipher(self.passwd)

        data = "Hello Worlds"
        ciphered_text = asym_cipher.cipher(data)

        deciphered_text = asym_cipher.decipher(ciphered_text)
        self.assertEqual(data, deciphered_text, msg="Result should be the same")

    def test_asym_cipher_not_equal(self):
        asym_cipher = AsymCipher(self.passwd)

        data1 = "Hello World"
        data2 = "Hello World, again"

        ciphered_text = asym_cipher.cipher(data2)
        deciphered_text = asym_cipher.decipher(ciphered_text)

        self.assertNotEqual(data1, deciphered_text, msg="Result should not be the same")

    def test_signature_valid(self):
        asym_cipher = AsymCipher(self.passwd)

        data = "Hello World"
        signature = asym_cipher.sign(data)

        is_valid = asym_cipher.valid_signature(signature, data)
        self.assertTrue(is_valid, msg="Signature should be valid")

    def test_signature_not_valid(self):
        asym_cipher = AsymCipher(self.passwd)

        data1 = "Hello World"
        signature = asym_cipher.sign(data1)

        data2 = "Hello World, again"
        is_valid = asym_cipher.valid_signature(signature, data2)

        self.assertFalse(is_valid, msg="Signature should be not valid")


class AsymCipherECCTests(unittest.TestCase):
    passwd = "pass"

    def test_asym_cipher_ecc_equal(self):
        asym_cipher = ECCCipher(self.passwd)

        data = "Hello Worlds"
        ciphered_text = asym_cipher.cipher(data)

        deciphered_text = asym_cipher.decipher(ciphered_text)
        self.assertEqual(data, deciphered_text, msg="Result should be the same")

    def test_asym_cipher_ecc_not_equal(self):
        asym_cipher = ECCCipher(self.passwd)

        data1 = "Hello World"
        data2 = "Hello World, again"

        ciphered_text = asym_cipher.cipher(data2)
        deciphered_text = asym_cipher.decipher(ciphered_text)

        self.assertNotEqual(data1, deciphered_text, msg="Result should not be the same")

    def test_signature_ecc_valid(self):
        asym_cipher = ECCCipher(self.passwd)

        data = "Hello World"
        signature = asym_cipher.sign(data)

        is_valid = asym_cipher.valid_signature(signature, data)
        self.assertTrue(is_valid, msg="Signature should be valid")

    def test_signature_ecc_not_valid(self):
        asym_cipher = ECCCipher(self.passwd)

        data1 = "Hello World"
        signature = asym_cipher.sign(data1)

        data2 = "Hello World, again"
        is_valid = asym_cipher.valid_signature(signature, data2)

        self.assertFalse(is_valid, msg="Signature should be not valid")


class PEMUtilsTests(unittest.TestCase):
    def test_pem_public(self):
        cipher = CitizenCard("a")
        pubKey = cipher.get_pubKey()

        pem = pem_utils.get_publicKey_To_Pem(pubKey)
        result = pem_utils.get_publicKey_From_Pem(pem)

        pem2 = pem_utils.get_publicKey_To_Pem(result)

        print("PRIVATE KEY {}".format(pubKey))
        print("RESULT KEY 1{}\n\n\n".format(pem))
        print("RESULT KEY 2{}".format(pem2))
        self.assertEqual(pem, pem2, "Should be the same")

if __name__ == '__main__':
    unittest.main()
