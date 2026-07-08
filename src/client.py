"""Kerberos client and CLI helper."""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass

from src.common import decrypt_envelope, encrypt_envelope
from src.config import PBKDF2_ITERATIONS
from src.crypto.kdf import derive_key
from src.crypto.utils import now_ts, random_nonce_hex


def _send_json(sock: socket.socket, payload: dict) -> None:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    sock.sendall(data)


def _recv_json(reader) -> dict | None:
    line = reader.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


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
        self._pending_as_nonce: str | None = None
        self._pending_tgs_nonce: str | None = None
        self._pending_service: str | None = None
        self._last_ap_req_ts: int | None = None
        self._active_service: str | None = None

    def make_as_req(self) -> dict:
        nonce = random_nonce_hex()
        timestamp = now_ts()
        self._pending_as_nonce = nonce
        preauth = encrypt_envelope(
            {
                "username": self.username,
                "timestamp": timestamp,
                "nonce": nonce,
            },
            self.long_term_key,
        )
        return {
            "msg_type": "AS_REQ",
            "username": self.username,
            "timestamp": timestamp,
            "nonce": nonce,
            "preauth": preauth,
        }

    def process_as_rep(self, response: dict) -> None:
        if response.get("msg_type") != "AS_REP":
            raise ValueError(response.get("error", "invalid as response"))

        payload = decrypt_envelope(response["payload"], self.long_term_key)
        if payload.get("username") != self.username:
            raise ValueError("AS_REP username mismatch")
        if self._pending_as_nonce is None or payload.get("nonce") != self._pending_as_nonce:
            raise ValueError("AS_REP nonce mismatch")
        self._pending_as_nonce = None
        self.cache.c_tgs_session_key = bytes.fromhex(payload["c_tgs_session_key"])
        self.cache.tgt = payload["tgt"]

    def make_tgs_req(self, service: str) -> dict:
        if self.cache.tgt is None or self.cache.c_tgs_session_key is None:
            raise ValueError("AS authentication required")

        nonce = random_nonce_hex()
        timestamp = now_ts()
        self._pending_tgs_nonce = nonce
        self._pending_service = service
        authenticator_payload = {
            "username": self.username,
            "timestamp": timestamp,
            "nonce": nonce,
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
        if self._pending_tgs_nonce is None or payload.get("nonce") != self._pending_tgs_nonce:
            raise ValueError("TGS_REP nonce mismatch")
        if self._pending_service is None or payload.get("service") != self._pending_service:
            raise ValueError("TGS_REP service mismatch")
        self._pending_tgs_nonce = None
        self._active_service = self._pending_service
        self._pending_service = None
        self.cache.c_s_session_key = bytes.fromhex(payload["c_s_session_key"])
        self.cache.service_ticket = payload["service_ticket"]

    def make_ap_req(self) -> dict:
        if self.cache.service_ticket is None or self.cache.c_s_session_key is None:
            raise ValueError("service ticket required")

        timestamp = now_ts()
        self._last_ap_req_ts = timestamp
        authenticator_payload = {
            "username": self.username,
            "timestamp": timestamp,
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
        ts_plus_one = payload.get("timestamp_plus_one")
        if not isinstance(ts_plus_one, int) or self._last_ap_req_ts is None:
            raise ValueError("missing mutual auth evidence")
        if ts_plus_one != self._last_ap_req_ts + 1:
            raise ValueError("invalid mutual auth evidence")
        if payload.get("username") != self.username:
            raise ValueError("AP_REP username mismatch")
        if self._active_service is not None and payload.get("service") != self._active_service:
            raise ValueError("AP_REP service mismatch")

    def process_chat_rep(self, response: dict) -> dict:
        if response.get("msg_type") != "CHAT_OK":
            raise ValueError(response.get("error", "invalid chat response"))
        if self.cache.c_s_session_key is None:
            raise ValueError("missing c_s session key")

        payload = decrypt_envelope(response["payload"], self.cache.c_s_session_key)
        if payload.get("status") != "ok":
            raise ValueError("invalid chat ack")
        return payload

    def make_chat_message(self, text: str) -> dict:
        if self.cache.service_ticket is None or self.cache.c_s_session_key is None:
            raise ValueError("chat session key unavailable")

        payload = {
            "text": text,
            "timestamp": now_ts(),
            "message_id": random_nonce_hex(),
        }
        encrypted_message = encrypt_envelope(payload, self.cache.c_s_session_key)

        return {
            "msg_type": "CHAT_MSG",
            "service_ticket": self.cache.service_ticket,
            "message": encrypted_message,
        }

    # ------------------------------------------------------------------
    # Métodos de rede: conectam via TCP aos servidores reais
    # ------------------------------------------------------------------

    def do_as_exchange(self, host: str, port: int) -> tuple[dict, dict]:
        """Envia AS_REQ via TCP e processa AS_REP. Retorna (req, rep)."""
        req = self.make_as_req()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))
            _send_json(sock, req)
            reader = sock.makefile("r", encoding="utf-8")
            response = _recv_json(reader)
        if response is None:
            raise RuntimeError("sem resposta do AS")
        self.process_as_rep(response)
        return req, response

    def do_tgs_exchange(self, host: str, port: int, service: str) -> tuple[dict, dict]:
        """Envia TGS_REQ via TCP e processa TGS_REP. Retorna (req, rep)."""
        req = self.make_tgs_req(service)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))
            _send_json(sock, req)
            reader = sock.makefile("r", encoding="utf-8")
            response = _recv_json(reader)
        if response is None:
            raise RuntimeError("sem resposta do TGS")
        self.process_tgs_rep(response)
        return req, response

    def connect_to_service(self, host: str, port: int) -> tuple[socket.socket, object, dict, dict]:
        """Abre conexão TCP persistente com o ChatServiceServer e realiza AP_REQ/AP_REP.

        Retorna (sock, reader, ap_req, ap_rep). O chamador é responsável por fechar sock.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        reader = sock.makefile("r", encoding="utf-8")
        ap_req = self.make_ap_req()
        _send_json(sock, ap_req)
        response = _recv_json(reader)
        if response is None:
            sock.close()
            raise RuntimeError("sem resposta AP_REP")
        self.process_ap_rep(response)
        return sock, reader, ap_req, response

    def send_chat_message_tcp(self, sock: socket.socket, reader, text: str) -> tuple[dict, dict]:
        """Envia CHAT_MSG pelo socket já aberto e retorna (msg, rep)."""
        msg = self.make_chat_message(text)
        _send_json(sock, msg)
        response = _recv_json(reader)
        if response is None:
            raise RuntimeError("sem resposta do servidor de chat")
        self.process_chat_rep(response)
        return msg, response
