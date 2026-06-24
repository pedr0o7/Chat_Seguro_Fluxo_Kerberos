import unittest

from src.crypto.feistel import decrypt_cbc, encrypt_cbc
from src.crypto.kdf import derive_key


class TestCrypto(unittest.TestCase):
    def test_feistel_cbc_roundtrip(self) -> None:
        key = b"K" * 16
        iv = b"I" * 8
        plaintext = b"Kerberos educational test message"

        ciphertext = encrypt_cbc(plaintext, key, iv)
        recovered = decrypt_cbc(ciphertext, key, iv)

        self.assertEqual(recovered, plaintext)

    def test_pbkdf2_is_deterministic(self) -> None:
        salt = b"same-salt"
        k1 = derive_key("password", salt, 120000)
        k2 = derive_key("password", salt, 120000)
        self.assertEqual(k1, k2)
        self.assertEqual(len(k1), 16)


if __name__ == "__main__":
    unittest.main()
