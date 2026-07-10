#Estruturas comuns de protocolo e utilitários de envelope seguro.#

from __future__ import annotations

import threading
from typing import Any

from src.config import MAX_CLOCK_SKEW_SECONDS, REPLAY_CACHE_TTL_SECONDS
from src.crypto.feistel import decrypt_cbc, encrypt_cbc
from src.crypto.kdf import stretch_key_material
from src.crypto.utils import (
    b64d,
    b64e,
    hmac_sha256_hex,
    json_dumps_canonical,
    json_loads_bytes,
    now_ts,
    random_bytes,
    secure_compare,
)


def is_timestamp_fresh(ts: int, skew: int = MAX_CLOCK_SKEW_SECONDS) -> bool:
    return abs(now_ts() - ts) <= skew


def make_ticket(
    ticket_type: str,
    username: str,
    session_key: bytes,
    service: str,
    issued_at: int,
    expires_at: int,
) -> dict[str, Any]:
    return {
        "ticket_type": ticket_type,
        "username": username,
        "service": service,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "session_key": b64e(session_key),
    }


def encrypt_envelope(obj: dict[str, Any], base_key: bytes) -> dict[str, str]:
    enc_key, mac_key = stretch_key_material(base_key)
    iv = random_bytes(8)
    plaintext = json_dumps_canonical(obj)
    ciphertext = encrypt_cbc(plaintext, enc_key, iv)
    body = iv + ciphertext
    mac = hmac_sha256_hex(mac_key, body)
    return {"body": b64e(body), "mac": mac}


def decrypt_envelope(envelope: dict[str, str], base_key: bytes) -> dict[str, Any]:
    enc_key, mac_key = stretch_key_material(base_key)
    body = b64d(envelope["body"])
    mac = envelope["mac"]

    expected = hmac_sha256_hex(mac_key, body)
    if not secure_compare(mac, expected):
        raise ValueError("MAC do envelope inválido")

    iv = body[:8]
    ciphertext = body[8:]
    plaintext = decrypt_cbc(ciphertext, enc_key, iv)
    return json_loads_bytes(plaintext)


def ticket_valid(ticket: dict[str, Any]) -> bool:
    current = now_ts()
    return ticket["issued_at"] <= current <= ticket["expires_at"]


class ReplayCache:
    #Cache simples com TTL para detectar replay de nonces/message ids.#

    def __init__(self, ttl_seconds: int = REPLAY_CACHE_TTL_SECONDS):
        self.ttl_seconds = ttl_seconds
        self._entries: dict[str, int] = {}
        self._lock = threading.Lock()

    def seen_or_store(self, key: str) -> bool:
        #Retorna True se a chave já foi vista (replay); caso contrário, armazena e retorna False.#
        current = now_ts()
        expires_before = current - self.ttl_seconds
        with self._lock:
            self._entries = {
                existing_key: ts for existing_key, ts in self._entries.items() if ts > expires_before
            }
            if key in self._entries:
                return True
            self._entries[key] = current
            return False
