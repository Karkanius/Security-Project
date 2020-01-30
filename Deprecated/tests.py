class DHTests(unittest.TestCase):

    def test_sym_cipher_equal(self):
        # Sign the data
        secret_key = diffie_hellman.getSharedKey("", "", "", debug=True)
        sym_cipher = SymCipher(secret_key)

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
        self.assertEqual(data, deciphered_text, msg="Result should be the same")

    def test_sym_cipher_not_equal(self):
        # Sign the data
        sym_cipher = SymCipher(self.passwd)

        data1 = "Hello World"
        data2 = "Hello World, again"

        ciphered_text = sym_cipher.cipher(data2)
        deciphered_text = sym_cipher.decipher(ciphered_text)

        self.assertNotEqual(data1, deciphered_text, msg="Result should not be the same")
