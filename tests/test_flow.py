import unittest

from run import build_demo_environment
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
        self.assertEqual(chat_rep["echo"], "hello")


if __name__ == "__main__":
    unittest.main()
