import unittest

from run import build_demo_environment
from src.common import decrypt_envelope, encrypt_envelope
from src.config import CHAT_SERVICE_PRINCIPAL


class TestKerberosFlow(unittest.TestCase):
    def test_end_to_end_flow(self) -> None:
        client, as_server, tgs_server, chat_service = build_demo_environment()

        as_rep = as_server.handle_as_req(client.make_as_req())
        client.process_as_rep(as_rep)

        tgs_rep = tgs_server.handle_tgs_req(client.make_tgs_req(CHAT_SERVICE_PRINCIPAL))
        client.process_tgs_rep(tgs_rep)

        ap_rep = chat_service.handle_ap_req(client.make_ap_req())
        client.process_ap_rep(ap_rep)

        chat_rep = chat_service.handle_chat_msg(client.make_chat_message("hello"))
        self.assertEqual(chat_rep["msg_type"], "CHAT_OK")
        ack = client.process_chat_rep(chat_rep)
        self.assertEqual(ack["status"], "ok")

    def test_as_req_requires_preauth(self) -> None:
        client, as_server, _, _ = build_demo_environment()
        as_req = client.make_as_req()
        del as_req["preauth"]

        rep = as_server.handle_as_req(as_req)
        self.assertEqual(rep["msg_type"], "ERROR")
        self.assertEqual(rep["error"], "authentication failed")

    def test_client_rejects_nonce_mismatch_in_as_rep(self) -> None:
        client, as_server, _, _ = build_demo_environment()

        as_rep = as_server.handle_as_req(client.make_as_req())
        payload = decrypt_envelope(as_rep["payload"], client.long_term_key)
        payload["nonce"] = "tampered-nonce"
        as_rep["payload"] = encrypt_envelope(payload, client.long_term_key)

        with self.assertRaises(ValueError):
            client.process_as_rep(as_rep)

    def test_client_rejects_invalid_ap_rep_timestamp(self) -> None:
        client, as_server, tgs_server, chat_service = build_demo_environment()

        client.process_as_rep(as_server.handle_as_req(client.make_as_req()))
        client.process_tgs_rep(tgs_server.handle_tgs_req(client.make_tgs_req(CHAT_SERVICE_PRINCIPAL)))
        ap_rep = chat_service.handle_ap_req(client.make_ap_req())

        payload = decrypt_envelope(ap_rep["payload"], client.cache.c_s_session_key)
        payload["timestamp_plus_one"] = int(payload["timestamp_plus_one"]) + 7
        ap_rep["payload"] = encrypt_envelope(payload, client.cache.c_s_session_key)

        with self.assertRaises(ValueError):
            client.process_ap_rep(ap_rep)

    def test_client_rejects_nonce_mismatch_in_tgs_rep(self) -> None:
        client, as_server, tgs_server, _ = build_demo_environment()

        client.process_as_rep(as_server.handle_as_req(client.make_as_req()))
        tgs_rep = tgs_server.handle_tgs_req(client.make_tgs_req(CHAT_SERVICE_PRINCIPAL))
        payload = decrypt_envelope(tgs_rep["payload"], client.cache.c_tgs_session_key)
        payload["nonce"] = "tampered-nonce"
        tgs_rep["payload"] = encrypt_envelope(payload, client.cache.c_tgs_session_key)

        with self.assertRaises(ValueError):
            client.process_tgs_rep(tgs_rep)

    def test_chat_message_replay_is_rejected(self) -> None:
        client, as_server, tgs_server, chat_service = build_demo_environment()

        client.process_as_rep(as_server.handle_as_req(client.make_as_req()))
        client.process_tgs_rep(tgs_server.handle_tgs_req(client.make_tgs_req(CHAT_SERVICE_PRINCIPAL)))
        client.process_ap_rep(chat_service.handle_ap_req(client.make_ap_req()))

        msg = client.make_chat_message("hello")
        first = chat_service.handle_chat_msg(msg)
        second = chat_service.handle_chat_msg(msg)

        self.assertEqual(first["msg_type"], "CHAT_OK")
        self.assertEqual(second["msg_type"], "ERROR")
        self.assertEqual(second["error"], "chat replay detected")

    def test_chat_rejects_wrong_service_ticket(self) -> None:
        client, as_server, tgs_server, chat_service = build_demo_environment()

        client.process_as_rep(as_server.handle_as_req(client.make_as_req()))
        client.process_tgs_rep(tgs_server.handle_tgs_req(client.make_tgs_req(CHAT_SERVICE_PRINCIPAL)))
        client.process_ap_rep(chat_service.handle_ap_req(client.make_ap_req()))

        msg = client.make_chat_message("hello")
        ticket = decrypt_envelope(msg["service_ticket"], chat_service.service_key)
        ticket["service"] = "another-service@local"
        msg["service_ticket"] = encrypt_envelope(ticket, chat_service.service_key)

        rep = chat_service.handle_chat_msg(msg)
        self.assertEqual(rep["msg_type"], "ERROR")
        self.assertEqual(rep["error"], "wrong service ticket")

    def test_chat_rejects_stale_message_timestamp(self) -> None:
        client, as_server, tgs_server, chat_service = build_demo_environment()

        client.process_as_rep(as_server.handle_as_req(client.make_as_req()))
        client.process_tgs_rep(tgs_server.handle_tgs_req(client.make_tgs_req(CHAT_SERVICE_PRINCIPAL)))
        client.process_ap_rep(chat_service.handle_ap_req(client.make_ap_req()))

        msg = client.make_chat_message("hello")
        payload = decrypt_envelope(msg["message"], client.cache.c_s_session_key)
        payload["timestamp"] = 0
        msg["message"] = encrypt_envelope(payload, client.cache.c_s_session_key)

        rep = chat_service.handle_chat_msg(msg)
        self.assertEqual(rep["msg_type"], "ERROR")
        self.assertEqual(rep["error"], "stale chat message")


if __name__ == "__main__":
    unittest.main()
