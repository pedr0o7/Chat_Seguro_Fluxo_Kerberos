#Serviço de chat protegido que valida tickets de serviço Kerberos.

from __future__ import annotations

import json
import socket
import threading

from src.common import ReplayCache, decrypt_envelope, encrypt_envelope, is_timestamp_fresh, ticket_valid
from src.config import CHAT_HOST, CHAT_MESSAGE_MAX_SKEW_SECONDS, CHAT_PORT
from src.crypto.utils import b64d, now_ts


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


class ChatService:
    def __init__(self, service_name: str, service_key: bytes):
        self.service_name = service_name
        self.service_key = service_key
        self.messages: list[dict[str, str]] = []
        self.auth_replay_cache = ReplayCache()
        self.chat_replay_cache = ReplayCache()

    def handle_ap_req(self, request: dict) -> dict:
        if request.get("msg_type") != "AP_REQ":
            return {"msg_type": "ERROR", "error": "tipo de mensagem inválido"}

        ticket_envelope = request.get("service_ticket")
        authenticator = request.get("authenticator")

        if not isinstance(ticket_envelope, dict) or not isinstance(authenticator, dict):
            return {"msg_type": "ERROR", "error": "formato de requisição inválido"}

        try:
            ticket = decrypt_envelope(ticket_envelope, self.service_key)
        except Exception:
            return {"msg_type": "ERROR", "error": "ticket de serviço inválido"}

        if not ticket_valid(ticket):
            return {"msg_type": "ERROR", "error": "ticket de serviço expirado"}

        if ticket.get("service") != self.service_name:
            return {"msg_type": "ERROR", "error": "ticket de serviço incorreto"}

        c_s_session_key = b64d(ticket["session_key"])

        try:
            auth_data = decrypt_envelope(authenticator, c_s_session_key)
        except Exception:
            return {"msg_type": "ERROR", "error": "autenticador inválido"}

        username = auth_data.get("username")
        timestamp = auth_data.get("timestamp")
        nonce = auth_data.get("nonce")

        if not isinstance(username, str) or not isinstance(timestamp, int) or not isinstance(nonce, str):
            return {"msg_type": "ERROR", "error": "formato de autenticador inválido"}

        if username != ticket.get("username"):
            return {"msg_type": "ERROR", "error": "usuário não confere"}

        replay_key = f"{username}:{nonce}"
        if self.auth_replay_cache.seen_or_store(replay_key):
            return {"msg_type": "ERROR", "error": "replay detectado"}

        if not is_timestamp_fresh(timestamp):
            return {"msg_type": "ERROR", "error": "autenticador fora da janela temporal"}

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
        if request.get("msg_type") != "CHAT_MSG":
            return {"msg_type": "ERROR", "error": "tipo de mensagem inválido"}

        ticket_envelope = request.get("service_ticket")
        msg_envelope = request.get("message")

        if not isinstance(ticket_envelope, dict) or not isinstance(msg_envelope, dict):
            return {"msg_type": "ERROR", "error": "requisição de chat inválida"}

        try:
            ticket = decrypt_envelope(ticket_envelope, self.service_key)
        except Exception:
            return {"msg_type": "ERROR", "error": "ticket de serviço inválido"}

        if not ticket_valid(ticket):
            return {"msg_type": "ERROR", "error": "ticket de serviço expirado"}

        if ticket.get("service") != self.service_name:
            return {"msg_type": "ERROR", "error": "ticket de serviço incorreto"}

        c_s_session_key = b64d(ticket["session_key"])

        try:
            message_data = decrypt_envelope(msg_envelope, c_s_session_key)
        except Exception:
            return {"msg_type": "ERROR", "error": "mensagem criptografada inválida"}

        username = ticket.get("username")
        plaintext = message_data.get("text")
        message_ts = message_data.get("timestamp")
        message_id = message_data.get("message_id")
        if (
            not isinstance(username, str)
            or not isinstance(plaintext, str)
            or not isinstance(message_ts, int)
            or not isinstance(message_id, str)
        ):
            return {"msg_type": "ERROR", "error": "payload de mensagem inválido"}

        if not is_timestamp_fresh(message_ts, CHAT_MESSAGE_MAX_SKEW_SECONDS):
            return {"msg_type": "ERROR", "error": "mensagem fora da janela temporal"}

        replay_key = f"{username}:{message_id}"
        if self.chat_replay_cache.seen_or_store(replay_key):
            return {"msg_type": "ERROR", "error": "replay de mensagem detectado"}

        self.messages.append({"username": username, "text": plaintext})
        ack_payload = {
            "status": "sucesso",
            "message_id": message_id,
            "received_at": now_ts(),
        }
        encrypted_ack = encrypt_envelope(ack_payload, c_s_session_key)
        return {"msg_type": "CHAT_OK", "from": username, "payload": encrypted_ack}


class ChatServiceServer(ChatService):
    # Encapsulador TCP para o serviço de chat autenticado por Kerberos.

    def __init__(self, service_name: str, service_key: bytes, host: str = CHAT_HOST, port: int = CHAT_PORT):
        super().__init__(service_name=service_name, service_key=service_key)
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
            # Negociação AP_REQ / AP_REP
            request = _recv_json(reader)
            if request is None:
                return
            if request.get("msg_type") != "AP_REQ":
                _send_json(sock, {"msg_type": "ERROR", "error": "AP_REQ esperado"})
                return
            response = self.handle_ap_req(request)
            _send_json(sock, response)
            if response.get("msg_type") != "AP_REP":
                return
            while True:
                msg = _recv_json(reader)
                if msg is None:
                    break
                rep = self.handle_chat_msg(msg)
                _send_json(sock, rep)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
