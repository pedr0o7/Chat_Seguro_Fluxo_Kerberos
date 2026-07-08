"""Secure interactive chat using Kerberos authentication and protected channels."""

from __future__ import annotations

import json
import os
import queue
import socket
import threading
from dataclasses import dataclass, field
from typing import Any

from src.common import decrypt_envelope, encrypt_envelope, is_timestamp_fresh, ticket_valid
from src.config import CHAT_HOST, CHAT_PORT, CHAT_SERVICE_PRINCIPAL, PBKDF2_ITERATIONS
from src.client import KerberosClient
from src.crypto.kdf import derive_key
from src.crypto.utils import b64d, b64e, now_ts, random_bytes, random_nonce_hex


def _send_json(sock: socket.socket, payload: dict[str, Any], lock: threading.Lock | None = None) -> None:
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if lock is None:
        sock.sendall(data)
        return

    with lock:
        sock.sendall(data)


def _recv_json(reader) -> dict[str, Any] | None:
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
    salt: bytes
    long_term_key: bytes


@dataclass
class ChannelRecord:
    channel_id: str
    user_a: str
    user_b: str
    channel_key: bytes


@dataclass
class ConnectionState:
    sock: socket.socket
    send_lock: threading.Lock = field(default_factory=threading.Lock)
    username: str | None = None
    c_s_session_key: bytes | None = None

    def send(self, payload: dict[str, Any]) -> None:
        _send_json(self.sock, payload, self.send_lock)


class SecureChatServer:
    def __init__(
        self,
        users: dict[str, UserRecord],
        service_name: str,
        service_key: bytes,
        host: str = CHAT_HOST,
        port: int = CHAT_PORT,
    ):
        self.users = users
        self.service_name = service_name
        self.service_key = service_key
        self.host = host
        self.port = port
        self._server_socket: socket.socket | None = None
        self._running = threading.Event()
        self._lock = threading.Lock()
        self._sessions: dict[str, ConnectionState] = {}
        self._channels: dict[str, ChannelRecord] = {}
        self._used_auth_nonces: set[str] = set()

    @classmethod
    def build_demo(
        cls,
        service_key: bytes,
        service_name: str = CHAT_SERVICE_PRINCIPAL,
        host: str = CHAT_HOST,
        port: int = CHAT_PORT,
    ) -> "SecureChatServer":
        demo_users = {
            "alice": _make_user("alice", "alice123"),
            "bob": _make_user("bob", "bob123"),
            "carol": _make_user("carol", "carol123"),
        }
        return cls(
            demo_users,
            service_name=service_name,
            service_key=service_key,
            host=host,
            port=port,
        )

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
        state = ConnectionState(sock=sock)
        try:
            reader = sock.makefile("r", encoding="utf-8")

            ap_req = _recv_json(reader)
            if ap_req is None:
                return

            if ap_req.get("msg_type") != "AP_REQ":
                state.send({"type": "ERROR", "error": "AP_REQ required"})
                return

            auth = self._authenticate_ap_req(ap_req)
            if auth is None:
                state.send({"type": "ERROR", "error": "invalid kerberos authentication"})
                return

            state.username = str(auth["username"])
            state.c_s_session_key = bytes(auth["c_s_session_key"])
            with self._lock:
                self._sessions[state.username] = state

            ap_rep = dict(auth["ap_rep"])
            ap_rep["participants"] = self._participants_snapshot()
            state.send(ap_rep)

            while True:
                message = _recv_json(reader)
                if message is None:
                    break
                self._dispatch_message(state, message)
        finally:
            with self._lock:
                if state.username:
                    if self._sessions.get(state.username) is state:
                        del self._sessions[state.username]
                    self._invalidate_user_channels(state.username)
            try:
                sock.close()
            except OSError:
                pass

    def _authenticate_ap_req(self, request: dict[str, Any]) -> dict[str, Any] | None:
        ticket_envelope = request.get("service_ticket")
        authenticator = request.get("authenticator")

        if not isinstance(ticket_envelope, dict) or not isinstance(authenticator, dict):
            return None

        try:
            ticket = decrypt_envelope(ticket_envelope, self.service_key)
        except Exception:
            return None

        if not ticket_valid(ticket):
            return None

        if ticket.get("service") != self.service_name:
            return None

        c_s_session_key = b64d(str(ticket["session_key"]))

        try:
            auth_data = decrypt_envelope(authenticator, c_s_session_key)
        except Exception:
            return None

        username = auth_data.get("username")
        timestamp = auth_data.get("timestamp")
        nonce = auth_data.get("nonce")

        if not isinstance(username, str) or not isinstance(timestamp, int) or not isinstance(nonce, str):
            return None

        if username != ticket.get("username"):
            return None

        if not is_timestamp_fresh(timestamp):
            return None

        with self._lock:
            if nonce in self._used_auth_nonces:
                return None
            self._used_auth_nonces.add(nonce)

        if username not in self.users:
            return None

        payload = {
            "username": username,
            "service": self.service_name,
            "timestamp_plus_one": timestamp + 1,
        }
        ap_rep = {
            "msg_type": "AP_REP",
            "payload": encrypt_envelope(payload, c_s_session_key),
            "username": username,
        }

        return {
            "username": username,
            "c_s_session_key": c_s_session_key,
            "ap_rep": ap_rep,
        }

    def _invalidate_user_channels(self, username: str) -> None:
        to_remove = [
            channel_id for channel_id, channel in self._channels.items()
            if username in (channel.user_a, channel.user_b)
        ]
        for channel_id in to_remove:
            del self._channels[channel_id]

    def _participants_snapshot(self) -> list[dict[str, Any]]:
        with self._lock:
            online = set(self._sessions)
        return [
            {"username": username, "online": username in online}
            for username in sorted(self.users)
        ]

    def _dispatch_message(self, state: ConnectionState, message: dict[str, Any]) -> None:
        message_type = message.get("type")

        if message_type == "LIST_USERS":
            state.send({"type": "LIST_USERS_OK", "participants": self._participants_snapshot()})
            return

        if message_type == "OPEN_CHANNEL":
            self._open_channel(state, message)
            return

        if message_type == "SEND_MESSAGE":
            self._relay_message(state, message)
            return

        if message_type == "LOGOUT":
            state.send({"type": "LOGOUT_OK"})
            with self._lock:
                self._invalidate_user_channels(state.username)
            raise SystemExit

        state.send({"type": "ERROR", "error": "unknown command"})

    def _open_channel(self, state: ConnectionState, message: dict[str, Any]) -> None:
        username = state.username
        peer = message.get("peer")
        if username is None or not isinstance(peer, str):
            state.send({"type": "ERROR", "error": "login required"})
            return

        if peer == username:
            state.send({"type": "ERROR", "error": "cannot open channel with yourself"})
            return

        with self._lock:
            peer_session = self._sessions.get(peer)
        if peer_session is None:
            state.send({"type": "ERROR", "error": "peer is offline"})
            return

        channel_id = random_nonce_hex(12)
        channel_key = random_bytes(32)
        record = ChannelRecord(channel_id=channel_id, user_a=username, user_b=peer, channel_key=channel_key)

        with self._lock:
            self._channels[channel_id] = record

        state.send({"type": "OPEN_CHANNEL_OK", "channel_id": channel_id, "peer": peer})
        self._send_channel_ready(username, state, peer, channel_id, channel_key)
        self._send_channel_ready(peer, peer_session, username, channel_id, channel_key)

    def _send_channel_ready(
        self,
        username: str,
        session: ConnectionState,
        peer: str,
        channel_id: str,
        channel_key: bytes,
    ) -> None:
        if session.c_s_session_key is None:
            return

        payload = {
            "channel_id": channel_id,
            "peer": peer,
            "channel_key": b64e(channel_key),
            "issued_at": now_ts(),
        }
        encrypted = encrypt_envelope(payload, session.c_s_session_key)
        session.send({"type": "CHANNEL_READY", "for": username, "payload": encrypted})

    def _relay_message(self, state: ConnectionState, message: dict[str, Any]) -> None:
        username = state.username
        channel_id = message.get("channel_id")
        payload = message.get("payload")

        if username is None or not isinstance(channel_id, str) or not isinstance(payload, dict):
            state.send({"type": "ERROR", "error": "invalid message format"})
            return

        with self._lock:
            channel = self._channels.get(channel_id)

        if channel is None:
            state.send({"type": "ERROR", "error": "canal expirado, abra novo canal"})
            return

        if username not in (channel.user_a, channel.user_b):
            state.send({"type": "ERROR", "error": "sender not in channel"})
            return

        peer = channel.user_b if username == channel.user_a else channel.user_a
        with self._lock:
            peer_session = self._sessions.get(peer)

        if peer_session is None:
            state.send({"type": "ERROR", "error": "usuario nao esta mais online"})
            return

        peer_session.send({
            "type": "INCOMING_MESSAGE",
            "channel_id": channel_id,
            "peer": username,
            "payload": payload,
        })
        state.send({"type": "SEND_MESSAGE_OK", "channel_id": channel_id, "to": peer})


class SecureChatClient:
    def __init__(self, host: str = CHAT_HOST, port: int = CHAT_PORT):
        self.host = host
        self.port = port
        self.sock: socket.socket | None = None
        self.reader = None
        self.writer_lock = threading.Lock()
        self.response_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.receiver_thread: threading.Thread | None = None
        self.running = threading.Event()
        self.username: str | None = None
        self.c_s_session_key: bytes | None = None
        self.channels: dict[str, dict[str, Any]] = {}
        self.channel_history: dict[str, list[str]] = {}
        self.active_channel_id: str | None = None

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port))
        self.reader = self.sock.makefile("r", encoding="utf-8")

    def close(self) -> None:
        self.running.clear()
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.sock.close()
            except OSError:
                pass

    @staticmethod
    def _print_flow_packet(title: str, payload: dict[str, Any]) -> None:
        print(title)
        print(json.dumps(payload, indent=2, ensure_ascii=True))

    def login_with_kerberos(
        self,
        kerberos_client: KerberosClient,
        as_host: str,
        as_port: int,
        tgs_host: str,
        tgs_port: int,
        service: str,
        verbose: bool = False,
    ) -> list[dict[str, Any]]:
        if self.sock is None or self.reader is None:
            raise RuntimeError("client not connected")

        if verbose:
            print("\n[Etapa 1] Cliente envia AS_REQ")
        as_req, as_rep = kerberos_client.do_as_exchange(as_host, as_port)
        if verbose:
            self._print_flow_packet("AS_REQ:", as_req)
            self._print_flow_packet("AS_REP:", as_rep)

        if verbose:
            print("\n[Etapa 2] Cliente envia TGS_REQ")
        tgs_req, tgs_rep = kerberos_client.do_tgs_exchange(tgs_host, tgs_port, service)
        if verbose:
            self._print_flow_packet("TGS_REQ:", tgs_req)
            self._print_flow_packet("TGS_REP:", tgs_rep)

        if verbose:
            print("\n[Etapa 3] Cliente envia AP_REQ no chat interativo")
        ap_req = kerberos_client.make_ap_req()
        _send_json(self.sock, ap_req, self.writer_lock)
        response = _recv_json(self.reader)
        if response is None:
            raise RuntimeError("server closed connection")
        if response.get("type") == "ERROR":
            raise RuntimeError(str(response.get("error", "kerberos auth failed")))
        if response.get("msg_type") != "AP_REP":
            raise RuntimeError(str(response.get("error", "invalid AP_REP")))
        kerberos_client.process_ap_rep(response)

        if verbose:
            self._print_flow_packet("AP_REQ:", ap_req)
            self._print_flow_packet("AP_REP:", response)
            print("\n[Etapa 4] Autenticacao Kerberos concluida; menu interativo liberado")

        self.username = kerberos_client.username
        self.c_s_session_key = kerberos_client.cache.c_s_session_key
        self.running.set()
        self._start_receiver_thread()
        return list(response.get("participants", []))

    def _start_receiver_thread(self) -> None:
        if self.receiver_thread is not None:
            return

        self.receiver_thread = threading.Thread(target=self._receiver_loop, daemon=True)
        self.receiver_thread.start()

    def _receiver_loop(self) -> None:
        if self.reader is None:
            return

        while self.running.is_set():
            try:
                message = _recv_json(self.reader)
            except Exception:
                break

            if message is None:
                break

            message_type = message.get("type")
            if message_type == "CHANNEL_READY":
                self._handle_channel_ready(message)
                continue

            if message_type == "INCOMING_MESSAGE":
                self._handle_incoming_message(message)
                continue

            if message_type in {"ERROR", "LIST_USERS_OK", "OPEN_CHANNEL_OK", "SEND_MESSAGE_OK", "LOGOUT_OK"}:
                self.response_queue.put(message)
                continue

            print(f"[servidor] {message}")

    def _handle_channel_ready(self, message: dict[str, Any]) -> None:
        payload = message.get("payload")
        if not isinstance(payload, dict) or self.c_s_session_key is None:
            print("[ALERTA] falha ao receber informacoes do canal seguro")
            return

        try:
            data = decrypt_envelope(payload, self.c_s_session_key)
        except Exception:
            print("[ALERTA] nao foi possivel validar a autenticidade do canal")
            return

        channel_id = str(data["channel_id"])
        peer = str(data["peer"])
        channel_key = b64d(str(data["channel_key"]))
        self.channels[channel_id] = {"peer": peer, "channel_key": channel_key}
        self.channel_history.setdefault(channel_id, [])
        self.active_channel_id = channel_id
        print(f"[canal seguro] aberto com {peer} (id {channel_id})")

    def _append_channel_history(self, channel_id: str, speaker: str, text: str) -> None:
        entries = self.channel_history.setdefault(channel_id, [])
        entries.append(f"{speaker}: {text}")

    def _print_channel_history(self, channel_id: str, limit: int = 20) -> None:
        channel = self.channels.get(channel_id)
        if channel is None:
            print("Historico indisponivel: canal nao encontrado.")
            return

        peer = str(channel.get("peer", "desconhecido"))
        print(f"Conversa com {peer} (canal {channel_id}):")
        entries = self.channel_history.get(channel_id, [])
        if not entries:
            print("- Sem mensagens anteriores.")
            return

        for item in entries[-limit:]:
            print(f"- {item}")

    def _handle_incoming_message(self, message: dict[str, Any]) -> None:
        channel_id = str(message.get("channel_id", ""))
        sender = str(message.get("peer", ""))
        payload = message.get("payload")
        channel = self.channels.get(channel_id)

        if channel is None:
            print(f"[ALERTA] mensagem recebida em canal desconhecido ({channel_id})")
            return

        if sender != channel["peer"]:
            print(f"[ALERTA] autenticidade comprometida: interlocutor esperado {channel['peer']}, recebido {sender}")
            return

        try:
            data = decrypt_envelope(payload, channel["channel_key"])
        except Exception:
            print(f"[ALERTA] integridade comprometida na mensagem de {sender}")
            return

        if str(data.get("sender")) != sender:
            print(f"[ALERTA] autenticidade do interlocutor nao e valida para {sender}")
            return

        text = str(data.get("text"))
        self._append_channel_history(channel_id, sender, text)
        print(f"[{sender}] {data.get('text')}")

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self.sock is None:
            raise RuntimeError("client not connected")

        _send_json(self.sock, payload, self.writer_lock)
        response = self.response_queue.get()
        if response.get("type") == "ERROR":
            raise RuntimeError(str(response.get("error", "request failed")))
        return response

    def list_users(self) -> list[dict[str, Any]]:
        response = self.request({"type": "LIST_USERS"})
        return list(response.get("participants", []))

    def open_channel(self, peer: str) -> str:
        response = self.request({"type": "OPEN_CHANNEL", "peer": peer})
        return str(response.get("channel_id"))

    def send_message(self, text: str, channel_id: str | None = None, tamper: bool = False) -> None:
        if self.username is None:
            raise RuntimeError("login required")

        channel_id = channel_id or self.active_channel_id
        if not channel_id:
            raise RuntimeError("no active channel")

        channel = self.channels.get(channel_id)
        if channel is None:
            raise RuntimeError("channel not ready yet")

        payload = encrypt_envelope({"sender": self.username, "text": text, "timestamp": now_ts()}, channel["channel_key"])
        if tamper:
            payload = dict(payload)
            body = b64d(payload["body"])
            body = body[:-1] + bytes([body[-1] ^ 0x01])
            payload["body"] = b64e(body)

        try:
            self.request({"type": "SEND_MESSAGE", "channel_id": channel_id, "payload": payload})
        except RuntimeError as exc:
            error_text = str(exc)
            if error_text in {"usuario nao esta mais online", "canal expirado, abra novo canal", "sender not in channel"}:
                raise RuntimeError("o usuario nao esta mais no canal ou nao esta mais online") from exc
            raise
        self._append_channel_history(channel_id, self.username, text)

    def logout(self) -> None:
        try:
            self.request({"type": "LOGOUT"})
        finally:
            self.close()

    def interactive_menu(self) -> None:
        while True:
            print("\nMenu:")
            print("1 - Listar usuarios")
            print("2 - Abrir canal seguro")
            print("3 - Enviar mensagem")
            print("4 - Sair")
            option = input("Opcao: ").strip()
            os.system("cls" if os.name == "nt" else "clear")

            try:
                if option == "1":
                    self._print_participants(self.list_users())
                elif option == "2":
                    peer = input("Usuario destinatario: ").strip()
                    channel_id = self.open_channel(peer)
                    print(f"Canal solicitado com {peer}. Aguarde o aviso de canal seguro (id {channel_id}).")
                elif option == "3":
                    if not self.active_channel_id:
                        raise RuntimeError("nenhum canal ativo. Abra um canal seguro primeiro")
                    self._print_channel_history(self.active_channel_id)
                    text = input("Mensagem: ").strip()
                    self.send_message(text, channel_id=self.active_channel_id)
                    print("Mensagem enviada e adicionada ao historico local.")
                elif option == "4":
                    self.logout()
                    print("Sessao encerrada.")
                    break
                else:
                    print("Opcao invalida.")
            except Exception as exc:
                print(f"Erro: {exc}")

    @staticmethod
    def _print_participants(participants: list[dict[str, Any]]) -> None:
        print("Participantes:")
        for participant in participants:
            status = "online" if participant.get("online") else "offline"
            print(f"- {participant.get('username')} ({status})")


def _make_user(username: str, password: str) -> UserRecord:
    salt = f"{username}-salt".encode("utf-8")
    return UserRecord(username=username, salt=salt, long_term_key=derive_key(password, salt, PBKDF2_ITERATIONS))
