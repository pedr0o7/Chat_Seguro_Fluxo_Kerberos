"""Interactive entrypoint for the security project.

Provides three modes:
- secure chat server
- secure chat client
- original Kerberos educational flow
"""

from __future__ import annotations

from getpass import getpass

from src.authentication_server import AuthenticationServer, UserRecord
from src.chat_server import ChatService
from src.client import KerberosClient
from src.config import CHAT_SERVICE_PRINCIPAL, KEY_SIZE_BYTES, PBKDF2_ITERATIONS
from src.crypto.kdf import derive_key
from src.crypto.utils import random_bytes
from src.secure_chat import SecureChatClient, SecureChatServer
from src.ticket_granting_server import TicketGrantingServer


def build_demo_environment() -> tuple[KerberosClient, AuthenticationServer, TicketGrantingServer, ChatService]:
    salt = b"alice-static-salt"
    user_password = "alice123"
    user_key = derive_key(user_password, salt, PBKDF2_ITERATIONS)

    key_tgs = random_bytes(KEY_SIZE_BYTES)
    key_chat = random_bytes(KEY_SIZE_BYTES)

    users = {
        "alice": UserRecord(username="alice", long_term_key=user_key),
    }

    as_server = AuthenticationServer(users=users, key_tgs=key_tgs)
    tgs_server = TicketGrantingServer(key_tgs=key_tgs, service_keys={CHAT_SERVICE_PRINCIPAL: key_chat})
    chat_service = ChatService(service_name=CHAT_SERVICE_PRINCIPAL, service_key=key_chat)

    client = KerberosClient(username="alice", password=user_password, salt=salt)
    return client, as_server, tgs_server, chat_service


def run_kerberos_demo() -> None:
    client, as_server, tgs_server, chat_service = build_demo_environment()

    print("[1/4] Cliente -> AS_REQ")
    as_req = client.make_as_req()
    as_rep = as_server.handle_as_req(as_req)
    client.process_as_rep(as_rep)
    print("      AS_REP recebido e decriptado com chave derivada da senha")

    print("[2/4] Cliente -> TGS_REQ")
    tgs_req = client.make_tgs_req(service=CHAT_SERVICE_PRINCIPAL)
    tgs_rep = tgs_server.handle_tgs_req(tgs_req)
    client.process_tgs_rep(tgs_rep)
    print("      TGS_REP recebido com service ticket")

    print("[3/4] Cliente -> AP_REQ (servico)")
    ap_req = client.make_ap_req()
    ap_rep = chat_service.handle_ap_req(ap_req)
    client.process_ap_rep(ap_rep)
    print("      AP_REP validado (autenticacao mutua OK)")

    print("[4/4] CHAT_MSG")
    chat_text = input("Mensagem de teste: ").strip() or "mensagem segura de teste"
    chat_msg = client.make_chat_message(chat_text)
    chat_rep = chat_service.handle_chat_msg(chat_msg)
    if chat_rep.get("msg_type") != "CHAT_OK":
        raise RuntimeError(f"Falha no chat: {chat_rep}")

    print("      Mensagem entregue com sucesso:", chat_rep["echo"])
    print("\nFluxo Kerberos educacional executado com sucesso.")


def run_server_mode() -> None:
    print("=== Servidor de chat seguro ===")
    server = SecureChatServer.build_demo()
    print(f"Servidor ouvindo em {server.host}:{server.port}")
    print("Usuarios demo: alice/alice123, bob/bob123, carol/carol123")
    print("Ctrl+C para encerrar.")
    server.serve_forever()


def run_client_mode() -> None:
    client = SecureChatClient()
    client.interactive_shell()


def main() -> None:
    print("=== Aplicacao de seguranca ===")
    print("1 - Chat seguro: servidor")
    print("2 - Chat seguro: cliente")
    print("3 - Demonstacao Kerberos educacional")

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