"""Kerberos client and CLI helper."""

from __future__ import annotations

from dataclasses import dataclass

from src.common import decrypt_envelope, encrypt_envelope
from src.config import PBKDF2_ITERATIONS
from src.crypto.kdf import derive_key
from src.crypto.utils import now_ts, random_nonce_hex


@dataclass
class ClientCache:
    tgt: dict | None = None
    c_tgs_session_key: bytes | None = None
    service_ticket: dict | None = None
    c_s_session_key: bytes | None = None


class KerberosClient:
    def __init__(self, username: str, password: str, salt: bytes):
        self.username = username
        self.password = password
        self.salt = salt
        self.long_term_key = derive_key(password, salt, PBKDF2_ITERATIONS)
        self.cache = ClientCache()

    def make_as_req(self) -> dict:
        return {
            "msg_type": "AS_REQ",
            "username": self.username,
            "timestamp": now_ts(),
            "nonce": random_nonce_hex(),
        }

    def process_as_rep(self, response: dict) -> None:
        if response.get("msg_type") != "AS_REP":
            raise ValueError(response.get("error", "invalid as response"))

        payload = decrypt_envelope(response["payload"], self.long_term_key)
        self.cache.c_tgs_session_key = bytes.fromhex(payload["c_tgs_session_key"])
        self.cache.tgt = payload["tgt"]

    def make_tgs_req(self, service: str) -> dict:
        if self.cache.tgt is None or self.cache.c_tgs_session_key is None:
            raise ValueError("AS authentication required")

        authenticator_payload = {
            "username": self.username,
            "timestamp": now_ts(),
            "nonce": random_nonce_hex(),
        }
        authenticator = encrypt_envelope(authenticator_payload, self.cache.c_tgs_session_key)

        return {
            "msg_type": "TGS_REQ",
            "service": service,
            "tgt": self.cache.tgt,
            "authenticator": authenticator,
        }

    def process_tgs_rep(self, response: dict) -> None:
        if response.get("msg_type") != "TGS_REP":
            raise ValueError(response.get("error", "invalid tgs response"))

        if self.cache.c_tgs_session_key is None:
            raise ValueError("missing c_tgs session key")

        payload = decrypt_envelope(response["payload"], self.cache.c_tgs_session_key)
        self.cache.c_s_session_key = bytes.fromhex(payload["c_s_session_key"])
        self.cache.service_ticket = payload["service_ticket"]

    def make_ap_req(self) -> dict:
        if self.cache.service_ticket is None or self.cache.c_s_session_key is None:
            raise ValueError("service ticket required")

        authenticator_payload = {
            "username": self.username,
            "timestamp": now_ts(),
            "nonce": random_nonce_hex(),
        }
        authenticator = encrypt_envelope(authenticator_payload, self.cache.c_s_session_key)

        return {
            "msg_type": "AP_REQ",
            "service_ticket": self.cache.service_ticket,
            "authenticator": authenticator,
        }

    def process_ap_rep(self, response: dict) -> None:
        if response.get("msg_type") != "AP_REP":
            raise ValueError(response.get("error", "invalid ap response"))

        if self.cache.c_s_session_key is None:
            raise ValueError("missing c_s session key")

        payload = decrypt_envelope(response["payload"], self.cache.c_s_session_key)
        if payload.get("timestamp_plus_one") is None:
            raise ValueError("missing mutual auth evidence")

    def make_chat_message(self, text: str) -> dict:
        if self.cache.service_ticket is None or self.cache.c_s_session_key is None:
            raise ValueError("chat session key unavailable")

        payload = {"text": text, "timestamp": now_ts()}
        encrypted_message = encrypt_envelope(payload, self.cache.c_s_session_key)

        return {
            "msg_type": "CHAT_MSG",
            "service_ticket": self.cache.service_ticket,
            "message": encrypted_message,
        }
