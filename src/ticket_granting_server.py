"""Ticket Granting Server (TGS) for the educational Kerberos flow."""

from __future__ import annotations

from collections.abc import Mapping

from src.common import decrypt_envelope, encrypt_envelope, is_timestamp_fresh, make_ticket, ticket_valid
from src.config import KEY_SIZE_BYTES, SERVICE_TTL_SECONDS
from src.crypto.utils import b64d, now_ts, random_bytes


class TicketGrantingServer:
    def __init__(self, key_tgs: bytes, service_keys: Mapping[str, bytes]):
        self.key_tgs = key_tgs
        self.service_keys = dict(service_keys)
        self.used_nonces: set[str] = set()

    def handle_tgs_req(self, request: dict) -> dict:
        if request.get("msg_type") != "TGS_REQ":
            return {"msg_type": "ERROR", "error": "invalid message type"}

        service = request.get("service")
        tgt_envelope = request.get("tgt")
        authenticator = request.get("authenticator")

        if not isinstance(service, str) or not isinstance(tgt_envelope, dict) or not isinstance(authenticator, dict):
            return {"msg_type": "ERROR", "error": "invalid request format"}

        if service not in self.service_keys:
            return {"msg_type": "ERROR", "error": "unknown service"}

        try:
            tgt = decrypt_envelope(tgt_envelope, self.key_tgs)
        except Exception:
            return {"msg_type": "ERROR", "error": "invalid tgt"}

        if not ticket_valid(tgt):
            return {"msg_type": "ERROR", "error": "expired tgt"}

        if tgt.get("service") != "tgs@local":
            return {"msg_type": "ERROR", "error": "tgt not intended for tgs"}

        c_tgs_session_key = b64d(tgt["session_key"])

        try:
            auth_data = decrypt_envelope(authenticator, c_tgs_session_key)
        except Exception:
            return {"msg_type": "ERROR", "error": "invalid authenticator"}

        username = auth_data.get("username")
        timestamp = auth_data.get("timestamp")
        nonce = auth_data.get("nonce")

        if not isinstance(username, str) or not isinstance(timestamp, int) or not isinstance(nonce, str):
            return {"msg_type": "ERROR", "error": "invalid authenticator format"}

        if username != tgt.get("username"):
            return {"msg_type": "ERROR", "error": "username mismatch"}

        if not is_timestamp_fresh(timestamp):
            return {"msg_type": "ERROR", "error": "stale authenticator"}

        if nonce in self.used_nonces:
            return {"msg_type": "ERROR", "error": "replay detected"}
        self.used_nonces.add(nonce)

        issued = now_ts()
        expires = issued + SERVICE_TTL_SECONDS
        c_s_session_key = random_bytes(KEY_SIZE_BYTES)

        service_ticket = make_ticket(
            ticket_type="SERVICE",
            username=username,
            session_key=c_s_session_key,
            service=service,
            issued_at=issued,
            expires_at=expires,
        )

        encrypted_service_ticket = encrypt_envelope(service_ticket, self.service_keys[service])

        rep_payload = {
            "service": service,
            "nonce": nonce,
            "issued_at": issued,
            "expires_at": expires,
            "c_s_session_key": c_s_session_key.hex(),
            "service_ticket": encrypted_service_ticket,
        }

        encrypted_payload = encrypt_envelope(rep_payload, c_tgs_session_key)
        return {"msg_type": "TGS_REP", "payload": encrypted_payload}
