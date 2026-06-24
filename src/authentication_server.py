"""Authentication Server (AS) for the educational Kerberos flow."""

from __future__ import annotations

from dataclasses import dataclass

from src.common import encrypt_envelope, is_timestamp_fresh, make_ticket
from src.config import KEY_SIZE_BYTES, TGS_PRINCIPAL, TGT_TTL_SECONDS
from src.crypto.utils import now_ts, random_bytes


@dataclass
class UserRecord:
    username: str
    long_term_key: bytes


class AuthenticationServer:
    def __init__(self, users: dict[str, UserRecord], key_tgs: bytes):
        self.users = users
        self.key_tgs = key_tgs

    def handle_as_req(self, request: dict) -> dict:
        if request.get("msg_type") != "AS_REQ":
            return {"msg_type": "ERROR", "error": "invalid message type"}

        username = request.get("username")
        nonce = request.get("nonce")
        client_ts = request.get("timestamp")

        if not isinstance(username, str) or not isinstance(nonce, str) or not isinstance(client_ts, int):
            return {"msg_type": "ERROR", "error": "invalid request format"}

        if not is_timestamp_fresh(client_ts):
            return {"msg_type": "ERROR", "error": "stale timestamp"}

        user = self.users.get(username)
        if user is None:
            return {"msg_type": "ERROR", "error": "unknown user"}

        issued = now_ts()
        expires = issued + TGT_TTL_SECONDS
        c_tgs_session_key = random_bytes(KEY_SIZE_BYTES)

        tgt = make_ticket(
            ticket_type="TGT",
            username=username,
            session_key=c_tgs_session_key,
            service=TGS_PRINCIPAL,
            issued_at=issued,
            expires_at=expires,
        )

        encrypted_tgt = encrypt_envelope(tgt, self.key_tgs)

        rep_payload = {
            "username": username,
            "tgs": TGS_PRINCIPAL,
            "nonce": nonce,
            "issued_at": issued,
            "expires_at": expires,
            "c_tgs_session_key": c_tgs_session_key.hex(),
            "tgt": encrypted_tgt,
        }

        encrypted_payload = encrypt_envelope(rep_payload, user.long_term_key)

        return {
            "msg_type": "AS_REP",
            "username": username,
            "payload": encrypted_payload,
        }
