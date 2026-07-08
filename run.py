"""Interactive entrypoint for the security project.

Provides three modes:
- secure chat server
- secure chat client
- Kerberos interactive flow with step-by-step output
"""

from __future__ import annotations

from getpass import getpass
import json
import socket
import threading

import time

from src.authentication_server import ASServer, UserRecord
from src.chat_server import ChatServiceServer
from src.client import KerberosClient
from src.config import (
    AS_HOST,
    AS_PORT,
    CHAT_HOST,
    CHAT_PORT,
    CHAT_SERVICE_PRINCIPAL,
    KEY_SIZE_BYTES,
    KERBEROS_CHAT_PORT,
    PBKDF2_ITERATIONS,
    TGS_HOST,
    TGS_PORT,
)
from src.crypto.kdf import derive_key
from src.crypto.utils import random_bytes
from src.secure_chat import SecureChatClient, SecureChatServer
from src.ticket_granting_server import TGSServer


def _build_demo_users() -> dict[str, tuple[str, bytes]]:
    return {
        "alice": ("alice123", b"alice-static-salt"),
        "bob": ("bob123", b"bob-static-salt"),
        "carol": ("carol123", b"carol-static-salt"),
    }


def _summarize_envelope(envelope: dict | None) -> dict:
    if not isinstance(envelope, dict):
        return {"type": "invalid-envelope"}

    body = str(envelope.get("body", ""))
    mac = str(envelope.get("mac", ""))
    return {
        "body_preview": f"{body[:24]}..." if len(body) > 24 else body,
        "body_length": len(body),
        "mac_preview": f"{mac[:12]}..." if len(mac) > 12 else mac,
    }


def _print_packet(title: str, packet: dict) -> None:
    redacted = dict(packet)
    if "payload" in redacted:
        redacted["payload"] = _summarize_envelope(redacted.get("payload"))
    if "tgt" in redacted:
        redacted["tgt"] = _summarize_envelope(redacted.get("tgt"))
    if "authenticator" in redacted:
        redacted["authenticator"] = _summarize_envelope(redacted.get("authenticator"))
    if "service_ticket" in redacted:
        redacted["service_ticket"] = _summarize_envelope(redacted.get("service_ticket"))
    if "message" in redacted:
        redacted["message"] = _summarize_envelope(redacted.get("message"))

    print(title)
    print(json.dumps(redacted, indent=2, ensure_ascii=True))


def _print_cache_state(client: KerberosClient) -> None:
    cache = client.cache
    print("Estado atual do cache Kerberos:")
    print(f"- TGT presente: {cache.tgt is not None}")
    print(f"- Chave cliente-TGS presente: {cache.c_tgs_session_key is not None}")
    print(f"- Service Ticket presente: {cache.service_ticket is not None}")
    print(f"- Chave cliente-servico presente: {cache.c_s_session_key is not None}")


def _build_users() -> dict[str, UserRecord]:
    users: dict[str, UserRecord] = {}
    for user, (plain_password, salt) in _build_demo_users().items():
        users[user] = UserRecord(
            username=user,
            long_term_key=derive_key(plain_password, salt, PBKDF2_ITERATIONS),
        )
    return users


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _wait_for_listener(host: str, port: int, timeout_s: float = 2.5) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.2)
            try:
                probe.connect((host, port))
                return
            except OSError:
                time.sleep(0.05)
    raise RuntimeError(f"falha ao iniciar listener em {host}:{port}")


def build_tcp_environment(
    username: str = "alice",
    password: str = "alice123",
    as_port: int = AS_PORT,
    tgs_port: int = TGS_PORT,
    chat_port: int = KERBEROS_CHAT_PORT,
) -> tuple[KerberosClient, ASServer, TGSServer, ChatServiceServer]:
    """Cria servidores TCP reais (AS, TGS, Chat) e um cliente Kerberos."""
    demo_users = _build_demo_users()
    if username not in demo_users:
        raise ValueError("usuario desconhecido")

    _, user_salt = demo_users[username]
    key_tgs = random_bytes(KEY_SIZE_BYTES)
    key_chat = random_bytes(KEY_SIZE_BYTES)

    as_server = ASServer(users=_build_users(), key_tgs=key_tgs, host=AS_HOST, port=as_port)
    tgs_server = TGSServer(
        key_tgs=key_tgs,
        service_keys={CHAT_SERVICE_PRINCIPAL: key_chat},
        host=TGS_HOST,
        port=tgs_port,
    )
    chat_server = ChatServiceServer(
        service_name=CHAT_SERVICE_PRINCIPAL,
        service_key=key_chat,
        host=CHAT_HOST,
        port=chat_port,
    )

    client = KerberosClient(username=username, password=password, salt=user_salt)
    return client, as_server, tgs_server, chat_server


# Alias mantido para compatibilidade com testes existentes
build_demo_environment = build_tcp_environment


def build_kdc_stack() -> tuple[ASServer, TGSServer, ChatServiceServer, bytes]:
    key_tgs = random_bytes(KEY_SIZE_BYTES)
    key_chat = random_bytes(KEY_SIZE_BYTES)

    as_server = ASServer(users=_build_users(), key_tgs=key_tgs)
    tgs_server = TGSServer(key_tgs=key_tgs, service_keys={CHAT_SERVICE_PRINCIPAL: key_chat})
    app_server = ChatServiceServer(
        service_name=CHAT_SERVICE_PRINCIPAL,
        service_key=key_chat,
        host=CHAT_HOST,
        port=KERBEROS_CHAT_PORT,
    )
    return as_server, tgs_server, app_server, key_chat


def _build_kerberos_client(username: str, password: str) -> KerberosClient:
    demo_users = _build_demo_users()
    if username not in demo_users:
        raise ValueError("usuario desconhecido")
    _, user_salt = demo_users[username]
    return KerberosClient(username=username, password=password, salt=user_salt)


def run_kerberos_demo() -> None:
    print("=== Fluxo Kerberos passo a passo (modo geral) ===")
    print("Usuarios demo: alice/alice123, bob/bob123, carol/carol123")
    username = input("Login: ").strip() or "alice"
    password = getpass("Senha: ")

    print("\n[Etapa 1] Usuario informou login e senha no cliente")
    print(f"- Login informado: {username}")
    print("- Senha informada: ********")

    as_port = _find_free_port()
    tgs_port = _find_free_port()
    chat_port = _find_free_port()

    client, as_server, tgs_server, chat_server = build_tcp_environment(
        username=username,
        password=password,
        as_port=as_port,
        tgs_port=tgs_port,
        chat_port=chat_port,
    )

    print(f"\nIniciando servidores TCP...")
    as_server.start_background()
    tgs_server.start_background()
    chat_server.start_background()
    time.sleep(0.3)  # aguarda os sockets ficarem prontos
    print(f"[OK] AS  ouvindo em {AS_HOST}:{as_port}")
    print(f"[OK] TGS ouvindo em {TGS_HOST}:{tgs_port}")
    print(f"[OK] Chat (Kerberos) ouvindo em {CHAT_HOST}:{chat_port}")

    print("\n[Etapa 2] Cliente envia AS_REQ para o AS via TCP")
    try:
        as_req, as_rep = client.do_as_exchange(AS_HOST, as_port)
    except Exception as exc:
        print("Falha na autenticacao inicial. Credenciais invalidas.")
        raise RuntimeError("autenticacao inicial falhou") from exc
    _print_packet("AS_REQ:", as_req)
    print("\n[Etapa 3] AS validou principal e devolveu AS_REP com TGT")
    _print_packet("AS_REP:", as_rep)
    print("- Cliente decriptou AS_REP com chave derivada da senha")
    print("- TGT e chave de sessao cliente-TGS armazenados no cache")

    print("\n[Etapa 4] Cliente envia TGS_REQ para o TGS via TCP")
    tgs_req, tgs_rep = client.do_tgs_exchange(TGS_HOST, tgs_port, CHAT_SERVICE_PRINCIPAL)
    _print_packet("TGS_REQ:", tgs_req)
    print("\n[Etapa 5] TGS validou TGT/Auth e retornou TGS_REP")
    _print_packet("TGS_REP:", tgs_rep)
    print("- Cliente obteve Service Ticket e chave de sessao cliente-servico")

    print("\n[Etapa 6] Cliente abre conexao com o ChatServiceServer e envia AP_REQ")
    chat_sock, chat_reader, ap_req, ap_rep = client.connect_to_service(CHAT_HOST, chat_port)
    _print_packet("AP_REQ:", ap_req)
    print("\n[Etapa 7] Servidor validou Service Ticket/Auth e respondeu AP_REP")
    _print_packet("AP_REP:", ap_rep)
    print("- AP_REP validado: autenticacao mutua concluida")

    print("\nAutenticacao Kerberos concluida. Cliente logado.")

    try:
        while True:
            print("\nMenu do cliente Kerberos:")
            print("1 - Enviar mensagem protegida")
            print("2 - Mostrar estado do cache de tickets")
            print("3 - Renovar ticket de servico (nova conexao TGS + AP)")
            print("4 - Encerrar sessao")
            option = input("Opcao: ").strip()

            if option == "1":
                print("\n[Etapa 8] Cliente envia mensagem protegida sem reenviar senha")
                chat_text = input("Mensagem: ").strip() or "mensagem segura de teste"
                chat_msg, chat_rep = client.send_chat_message_tcp(chat_sock, chat_reader, chat_text)
                _print_packet("CHAT_MSG:", chat_msg)
                _print_packet("CHAT_REP:", chat_rep)
                if chat_rep.get("msg_type") != "CHAT_OK":
                    print(f"Falha no chat: {chat_rep}")
                else:
                    ack = client.process_chat_rep(chat_rep)
                    print(f"Mensagem entregue com sucesso (id {ack['message_id']}).")
            elif option == "2":
                _print_cache_state(client)
            elif option == "3":
                print("\n[Renovacao] Cliente solicita novo ticket ao TGS")
                tgs_req, tgs_rep = client.do_tgs_exchange(TGS_HOST, tgs_port, CHAT_SERVICE_PRINCIPAL)
                _print_packet("TGS_REQ:", tgs_req)
                _print_packet("TGS_REP:", tgs_rep)
                chat_sock.close()
                chat_sock, chat_reader, ap_req, ap_rep = client.connect_to_service(
                    CHAT_HOST,
                    chat_port,
                )
                _print_packet("AP_REQ:", ap_req)
                _print_packet("AP_REP:", ap_rep)
                print("Novo ticket validado e sessao de servico renovada.")
            elif option == "4":
                print("Sessao Kerberos encerrada.")
                break
            else:
                print("Opcao invalida.")
    finally:
        try:
            chat_sock.close()
        except OSError:
            pass


def run_server_mode() -> None:
    print("=== Servidor de chat seguro ===")
    as_server, tgs_server, app_server, key_chat = build_kdc_stack()

    print("Inicializando ecossistema Kerberos (KDC + servico)...")
    as_server.start_background()
    tgs_server.start_background()
    app_server.start_background()
    _wait_for_listener(AS_HOST, AS_PORT)
    _wait_for_listener(TGS_HOST, TGS_PORT)
    _wait_for_listener(CHAT_HOST, KERBEROS_CHAT_PORT)

    server = SecureChatServer.build_demo(
        service_key=key_chat,
        service_name=CHAT_SERVICE_PRINCIPAL,
        host=CHAT_HOST,
        port=CHAT_PORT,
    )
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    _wait_for_listener(CHAT_HOST, CHAT_PORT)

    print(f"[OK] AS (Authentication Server) ouvindo em {AS_HOST}:{AS_PORT}")
    print(f"[OK] TGS (Ticket Granting Server) ouvindo em {TGS_HOST}:{TGS_PORT}")
    print(f"[OK] Servidor de Aplicacao Kerberos pronto em {CHAT_HOST}:{KERBEROS_CHAT_PORT}")
    print("[OK] Validacao de principals e emissao de tickets habilitadas")
    print(f"Servidor de chat seguro ouvindo em {server.host}:{server.port}")
    print("Usuarios demo: alice/alice123, bob/bob123, carol/carol123")
    print("Ctrl+C para encerrar.")
    while True:
        time.sleep(1)


def run_client_mode() -> None:
    print("=== Cliente de chat seguro (usa servidores da opcao 1) ===")
    print("Usuarios demo: alice/alice123, bob/bob123, carol/carol123")
    username = input("Login: ").strip() or "alice"
    password = getpass("Senha: ")

    kerberos_client = _build_kerberos_client(username, password)
    client = SecureChatClient(host=CHAT_HOST, port=CHAT_PORT)

    try:
        client.connect()
        participants = client.login_with_kerberos(
            kerberos_client=kerberos_client,
            as_host=AS_HOST,
            as_port=AS_PORT,
            tgs_host=TGS_HOST,
            tgs_port=TGS_PORT,
            service=CHAT_SERVICE_PRINCIPAL,
            verbose=True,
        )
        print("Autenticacao Kerberos concluida com sucesso.")
        client._print_participants(participants)
        client.interactive_menu()
    finally:
        client.close()


def main() -> None:
    print("=== Aplicacao de seguranca ===")
    print("1 - Chat seguro: servidor")
    print("2 - Chat seguro: cliente (usa servidores da opcao 1)")
    print("3 - Kerberos: fluxo completo + menu do cliente")

    option = input("Escolha uma opcao: ").strip()

    try:
        if option == "1":
            run_server_mode()
        elif option == "2":
            run_client_mode()
        elif option == "3":
            run_kerberos_demo()
        else:
            print("Opcao invalida.")
    except KeyboardInterrupt:
        print("\nExecucao interrompida pelo usuario.")
    except Exception as exc:
        print(f"Erro: {exc}")


if __name__ == "__main__":
    main()