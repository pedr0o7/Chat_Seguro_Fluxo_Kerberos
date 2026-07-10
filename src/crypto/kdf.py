#Rotinas de derivação de chave baseadas em PBKDF2-HMAC-SHA256.#

from __future__ import annotations

import hashlib


def derive_key(password: str, salt: bytes, iterations: int, key_size: int = 16) -> bytes:
    #Deriva uma chave simétrica a partir da senha do usuário.#
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=key_size,
    )


def stretch_key_material(base_key: bytes) -> tuple[bytes, bytes]:
    #Expande a chave base em (enc_key, mac_key).#
    enc_key = hashlib.sha256(base_key + b"|enc").digest()[:16]
    mac_key = hashlib.sha256(base_key + b"|mac").digest()
    return enc_key, mac_key
