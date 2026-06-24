"""Protected chat service that validates Kerberos service tickets."""

from __future__ import annotations

from src.common import decrypt_envelope, encrypt_envelope, is_timestamp_fresh, ticket_valid
from src.crypto.utils import b64d


class ChatService:
    def __init__(self, service_name: str, service_key: bytes):
        self.service_name = service_name
        self.service_key = service_key
        self.messages: list[dict[str, str]] = []
        self.used_nonces: set[str] = set()

    def handle_ap_req(self, request: dict) -> dict:
        if request.get("msg_type") != "AP_REQ":
            return {"msg_type": "ERROR", "error": "invalid message type"}

        ticket_envelope = request.get("service_ticket")
        authenticator = request.get("authenticator")

        if not isinstance(ticket_envelope, dict) or not isinstance(authenticator, dict):
            return {"msg_type": "ERROR", "error": "invalid request format"}

        try:
            ticket = decrypt_envelope(ticket_envelope, self.service_key)
        except Exception:
            return {"msg_type": "ERROR", "error": "invalid service ticket"}

        if not ticket_valid(ticket):
            return {"msg_type": "ERROR", "error": "service ticket expired"}

        if ticket.get("service") != self.service_name:
            return {"msg_type": "ERROR", "error": "wrong service ticket"}

        c_s_session_key = b64d(ticket["session_key"])

        try:
            auth_data = decrypt_envelope(authenticator, c_s_session_key)
        except Exception:
            return {"msg_type": "ERROR", "error": "invalid authenticator"}

        username = auth_data.get("username")
        timestamp = auth_data.get("timestamp")
        nonce = auth_data.get("nonce")

        if not isinstance(username, str) or not isinstance(timestamp, int) or not isinstance(nonce, str):
            return {"msg_type": "ERROR", "error": "invalid authenticator format"}

        if username != ticket.get("username"):
            return {"msg_type": "ERROR", "error": "username mismatch"}

        if nonce in self.used_nonces:
            return {"msg_type": "ERROR", "error": "replay detected"}
        self.used_nonces.add(nonce)

        if not is_timestamp_fresh(timestamp):
            return {"msg_type": "ERROR", "error": "stale authenticator"}

        ap_rep_payload = {
            "username": username,
            "service": self.service_name,
            "timestamp_plus_one": timestamp + 1,
        }
        ap_rep = encrypt_envelope(ap_rep_payload, c_s_session_key)

        return {
            "msg_type": "AP_REP",
            "payload": ap_rep,
            "username": username,
        }

    def handle_chat_msg(self, request: dict) -> dict:
        ticket_envelope = request.get("service_ticket")
        msg_envelope = request.get("message")

        if not isinstance(ticket_envelope, dict) or not isinstance(msg_envelope, dict):
            return {"msg_type": "ERROR", "error": "invalid chat request"}

        try:
            ticket = decrypt_envelope(ticket_envelope, self.service_key)
        except Exception:
            return {"msg_type": "ERROR", "error": "invalid service ticket"}

        if not ticket_valid(ticket):
            return {"msg_type": "ERROR", "error": "service ticket expired"}

        c_s_session_key = b64d(ticket["session_key"])

        try:
            message_data = decrypt_envelope(msg_envelope, c_s_session_key)
        except Exception:
            return {"msg_type": "ERROR", "error": "invalid encrypted message"}

        username = ticket.get("username")
        plaintext = message_data.get("text")
        if not isinstance(username, str) or not isinstance(plaintext, str):
            return {"msg_type": "ERROR", "error": "invalid message payload"}

        self.messages.append({"username": username, "text": plaintext})
        return {"msg_type": "CHAT_OK", "from": username, "echo": plaintext}
