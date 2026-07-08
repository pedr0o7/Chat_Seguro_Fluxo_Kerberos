"""Ticket Granting Server (TGS) for the educational Kerberos flow."""

from __future__ import annotations

import json
import socket
import threading
from collections.abc import Mapping

from src.common import ReplayCache, decrypt_envelope, encrypt_envelope, is_timestamp_fresh, make_ticket, ticket_valid
from src.config import KEY_SIZE_BYTES, SERVICE_TTL_SECONDS, TGS_HOST, TGS_PORT, TGS_PRINCIPAL
from src.crypto.utils import b64d, now_ts, random_bytes


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


class TicketGrantingServer:
    def __init__(self, key_tgs: bytes, service_keys: Mapping[str, bytes]):
        self.key_tgs = key_tgs
        self.service_keys = dict(service_keys)
        self.replay_cache = ReplayCache()

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

        if tgt.get("service") != TGS_PRINCIPAL:
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

        replay_key = f"{username}:{nonce}"
        if self.replay_cache.seen_or_store(replay_key):
            return {"msg_type": "ERROR", "error": "replay detected"}

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


class TGSServer(TicketGrantingServer):
    """TCP server wrapper for the Ticket Granting Server."""

    def __init__(self, key_tgs: bytes, service_keys: Mapping[str, bytes], host: str = TGS_HOST, port: int = TGS_PORT):
        super().__init__(key_tgs=key_tgs, service_keys=service_keys)
        self.host = host
        self.port = port
        self._server_socket: socket.socket | None = None
        self._running = threading.Event()

    def start_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, daemon=True)
        thread.start()
        return thread

    def serve_forever(self) -> None:
        self._running.set()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                server_socket.bind((self.host, self.port))
            except OSError as exc:
                raise RuntimeError(f"porta {self.host}:{self.port} indisponivel") from exc
            server_socket.listen()
            self._server_socket = server_socket
            while self._running.is_set():
                try:
                    client_sock, _ = server_socket.accept()
                except OSError:
                    break
                thread = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                thread.start()

    def shutdown(self) -> None:
        self._running.clear()
        if self._server_socket is not None:
            try:
                self._server_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self._server_socket.close()
            except OSError:
                pass

    def _handle_client(self, sock: socket.socket) -> None:
        try:
            reader = sock.makefile("r", encoding="utf-8")
            request = _recv_json(reader)
            if request is None:
                return
            response = self.handle_tgs_req(request)
            _send_json(sock, response)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
