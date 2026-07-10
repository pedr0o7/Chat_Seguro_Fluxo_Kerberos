#Cifra de bloco Feistel didática com modo CBC.

#Implementação acadêmica para estudo.


from __future__ import annotations

import hashlib

BLOCK_SIZE = 8
DEFAULT_ROUNDS = 1000


def _normalize_rounds(rounds: int) -> int:
    return max(rounds, DEFAULT_ROUNDS)


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _round_function(half_block: bytes, round_key: bytes) -> bytes:
    return hashlib.sha256(half_block + round_key).digest()[:4]


def _expand_round_keys(key: bytes, rounds: int) -> list[bytes]:
    keys: list[bytes] = []
    seed = key
    for i in range(rounds):
        seed = hashlib.sha256(seed + i.to_bytes(2, "big")).digest()
        keys.append(seed[:8])
    return keys


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("tamanho de dado com padding inválido")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("tamanho de padding inválido")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("bytes de padding inválidos")
    return data[:-pad_len]


def encrypt_block(block8: bytes, key: bytes, rounds: int = DEFAULT_ROUNDS) -> bytes:
    if len(block8) != BLOCK_SIZE:
        raise ValueError("o bloco deve ter exatamente 8 bytes")
    if len(key) < 16:
        raise ValueError("a chave deve ter ao menos 16 bytes")

    left = block8[:4]
    right = block8[4:]
    round_keys = _expand_round_keys(key, _normalize_rounds(rounds))

    for round_key in round_keys:
        f_out = _round_function(right, round_key)
        left, right = right, _xor_bytes(left, f_out)

    return left + right


def decrypt_block(block8: bytes, key: bytes, rounds: int = DEFAULT_ROUNDS) -> bytes:
    if len(block8) != BLOCK_SIZE:
        raise ValueError("o bloco deve ter exatamente 8 bytes")
    if len(key) < 16:
        raise ValueError("a chave deve ter ao menos 16 bytes")

    left = block8[:4]
    right = block8[4:]
    round_keys = _expand_round_keys(key, _normalize_rounds(rounds))

    for round_key in reversed(round_keys):
        new_right = left
        f_out = _round_function(new_right, round_key)
        new_left = _xor_bytes(right, f_out)
        left, right = new_left, new_right

    return left + right


def encrypt_cbc(plaintext: bytes, key: bytes, iv: bytes, rounds: int = DEFAULT_ROUNDS) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("o IV deve ter 8 bytes")

    padded = _pkcs7_pad(plaintext, BLOCK_SIZE)
    prev = iv
    out = bytearray()

    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i : i + BLOCK_SIZE]
        xored = _xor_bytes(block, prev)
        cblock = encrypt_block(xored, key, rounds)
        out.extend(cblock)
        prev = cblock

    return bytes(out)


def decrypt_cbc(ciphertext: bytes, key: bytes, iv: bytes, rounds: int = DEFAULT_ROUNDS) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("o IV deve ter 8 bytes")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("o tamanho do texto cifrado deve ser múltiplo de 8")

    prev = iv
    out = bytearray()

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        cblock = ciphertext[i : i + BLOCK_SIZE]
        dblock = decrypt_block(cblock, key, rounds)
        pblock = _xor_bytes(dblock, prev)
        out.extend(pblock)
        prev = cblock

    return _pkcs7_unpad(bytes(out), BLOCK_SIZE)
