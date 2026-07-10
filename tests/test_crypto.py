import unittest
from unittest.mock import patch

from src.common import ReplayCache, decrypt_envelope, encrypt_envelope
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

    def test_envelope_detects_tampering(self) -> None:
        key = b"K" * 16
        envelope = encrypt_envelope({"x": "value"}, key)

        tampered = dict(envelope)
        tampered["mac"] = "0" * len(str(envelope["mac"]))
        with self.assertRaises(ValueError):
            decrypt_envelope(tampered, key)

    def test_replay_cache_expires_entries(self) -> None:
        cache = ReplayCache(ttl_seconds=10)

        with patch("src.common.now_ts", side_effect=[100, 100, 111]):
            self.assertFalse(cache.seen_or_store("nonce-1"))
            self.assertTrue(cache.seen_or_store("nonce-1"))
            self.assertFalse(cache.seen_or_store("nonce-1"))


if __name__ == "__main__":
    unittest.main()
