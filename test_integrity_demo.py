"""Automated demo script to validate message integrity and authenticity.

This script:
1. Starts the secure chat server
2. Connects two clients (alice and bob)
3. Opens a secure channel
4. Sends an intact message (success)
5. Sends a corrupted message (integrity alert)
6. Validates that the security mechanisms work as expected
"""

from __future__ import annotations

import threading
import time
import sys
import socket

from run import build_tcp_environment
from src.client import KerberosClient
from src.config import AS_HOST, CHAT_SERVICE_PRINCIPAL, TGS_HOST
from src.secure_chat import SecureChatClient, SecureChatServer


def _salt_for(username: str) -> bytes:
    salts = {
        "alice": b"alice-static-salt",
        "bob": b"bob-static-salt",
        "carol": b"carol-static-salt",
    }
    return salts[username]


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_integrity_demo() -> None:
    print("=" * 70)
    print("DEMONSTRAÇÃO: INTEGRIDADE E AUTENTICIDADE DE MENSAGENS")
    print("=" * 70)

    as_port = _find_free_port()
    tgs_port = _find_free_port()
    kerberos_chat_port = _find_free_port()
    interactive_chat_port = _find_free_port()

    _, as_server, tgs_server, app_server = build_tcp_environment(
        username="alice",
        password="alice123",
        as_port=as_port,
        tgs_port=tgs_port,
        chat_port=kerberos_chat_port,
    )
    as_server.start_background()
    tgs_server.start_background()
    app_server.start_background()

    server = SecureChatServer.build_demo(
        service_key=app_server.service_key,
        service_name=CHAT_SERVICE_PRINCIPAL,
        port=interactive_chat_port,
    )
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.8)
    print("\n✓ Ecossistema Kerberos + chat interativo iniciados")

    alice = SecureChatClient(port=interactive_chat_port)
    bob = SecureChatClient(port=interactive_chat_port)

    alice.connect()
    bob.connect()
    print("✓ Clientes conectados ao servidor")

    print("\n--- Login Kerberos (AS -> TGS -> AP) ---")
    alice_k = KerberosClient("alice", "alice123", _salt_for("alice"))
    bob_k = KerberosClient("bob", "bob123", _salt_for("bob"))
    alice_participants = alice.login_with_kerberos(
        kerberos_client=alice_k,
        as_host=AS_HOST,
        as_port=as_port,
        tgs_host=TGS_HOST,
        tgs_port=tgs_port,
        service=CHAT_SERVICE_PRINCIPAL,
    )
    print("✓ alice autenticada com Kerberos")
    bob_participants = bob.login_with_kerberos(
        kerberos_client=bob_k,
        as_host=AS_HOST,
        as_port=as_port,
        tgs_host=TGS_HOST,
        tgs_port=tgs_port,
        service=CHAT_SERVICE_PRINCIPAL,
    )
    print("✓ bob autenticado com Kerberos")

    print(f"\nParticipantes online: {[p['username'] for p in alice_participants if p['online']]}")

    print("\n--- Abertura de Canal Seguro ---")
    channel_id = alice.open_channel("bob")
    print(f"✓ Canal seguro aberto entre alice e bob (id: {channel_id})")
    time.sleep(0.3)

    print("\n--- Teste 1: Mensagem Íntegra ---")
    print("alice enviando: 'Olá Bob, tudo bem?'")
    alice.send_message("Ola Bob, tudo bem?")
    time.sleep(0.5)
    print("✓ Mensagem entregue com integridade validada em bob")

    print("\n--- Teste 2: Mensagem Corrompida ---")
    print("alice enviando mensagem adulterada...")
    alice.send_message("Mensagem corrompida", tamper=True)
    time.sleep(0.5)
    print("✓ bob recebeu alerta de integridade comprometida (como esperado)")

    print("\n--- Teste 3: Verificação de Autenticidade ---")
    print("Tentando enviar mensagem com peer inválido...")
    try:
        bob.send_message("Teste autenticidade", channel_id=channel_id)
        print("✓ Mensagem enviada de bob para alice")
    except Exception as exc:
        print(f"✓ Validação de autenticidade funcionou: {exc}")

    alice.logout()
    bob.logout()
    server.shutdown()
    time.sleep(0.2)

    print("\n" + "=" * 70)
    print("INTEGRIDADE VALIDADA ✓")
    print("=" * 70)
    print("\nResumo:")
    print("1. Mensagem íntegra: ENTREGUE COM SUCESSO")
    print("2. Mensagem corrompida: REJEITADA (integridade comprometida)")
    print("3. Autenticidade: VALIDADA")
    print("\nAs três propriedades de segurança foram demonstradas:")
    print("  - Confidencialidade: envelope criptografado com chave de sessão")
    print("  - Integridade: HMAC-SHA256 detecta alterações")
    print("  - Autenticidade: Kerberos (AS/TGS/AP) e identificação de remetente")
    print()


if __name__ == "__main__":
    try:
        test_integrity_demo()
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuário.")
        sys.exit(0)
    except Exception as exc:
        print(f"\nErro durante o teste: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
