"""Authentication Server (AS) for the educational Kerberos flow."""

from __future__ import annotations

import json
import socket
import threading
from dataclasses import dataclass

from src.common import encrypt_envelope, is_timestamp_fresh, make_ticket
from src.config import AS_HOST, AS_PORT, KEY_SIZE_BYTES, TGS_PRINCIPAL, TGT_TTL_SECONDS
from src.crypto.utils import now_ts, random_bytes


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


class ASServer(AuthenticationServer):
    """TCP server wrapper for the Authentication Server."""

    def __init__(self, users: dict[str, UserRecord], key_tgs: bytes, host: str = AS_HOST, port: int = AS_PORT):
        super().__init__(users=users, key_tgs=key_tgs)
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
            response = self.handle_as_req(request)
            _send_json(sock, response)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
