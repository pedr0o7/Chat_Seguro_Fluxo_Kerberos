import unittest

from src.crypto.utils import now_ts
from src.secure_chat import ChannelRecord, SecureChatServer
from src.common import encrypt_envelope


class _DummyState:
    def __init__(self, username: str):
        self.username = username
        self.sent: list[dict] = []

    def send(self, payload: dict) -> None:
        self.sent.append(payload)


class TestSecureChatRelay(unittest.TestCase):
    def test_relay_rejects_replay_message_id(self) -> None:
        server = SecureChatServer(users={}, service_name="chat@local", service_key=b"K" * 16)
        channel = ChannelRecord("ch1", "alice", "bob", b"C" * 32)
        sender = _DummyState("alice")
        peer = _DummyState("bob")

        server._channels[channel.channel_id] = channel
        server._sessions["bob"] = peer

        payload = encrypt_envelope(
            {
                "sender": "alice",
                "text": "hello",
                "timestamp": now_ts(),
                "message_id": "m1",
            },
            channel.channel_key,
        )
        msg = {"channel_id": channel.channel_id, "payload": payload}

        server._relay_message(sender, msg)
        server._relay_message(sender, msg)

        self.assertEqual(peer.sent[0]["type"], "INCOMING_MESSAGE")
        self.assertEqual(sender.sent[0]["type"], "SEND_MESSAGE_OK")
        self.assertEqual(sender.sent[1]["type"], "ERROR")
        self.assertEqual(sender.sent[1]["error"], "replay de mensagem detectado")

    def test_relay_rejects_stale_timestamp(self) -> None:
        server = SecureChatServer(users={}, service_name="chat@local", service_key=b"K" * 16)
        channel = ChannelRecord("ch2", "alice", "bob", b"D" * 32)
        sender = _DummyState("alice")
        peer = _DummyState("bob")

        server._channels[channel.channel_id] = channel
        server._sessions["bob"] = peer

        payload = encrypt_envelope(
            {
                "sender": "alice",
                "text": "hello",
                "timestamp": 0,
                "message_id": "m2",
            },
            channel.channel_key,
        )
        msg = {"channel_id": channel.channel_id, "payload": payload}

        server._relay_message(sender, msg)

        self.assertEqual(sender.sent[0]["type"], "ERROR")
        self.assertEqual(sender.sent[0]["error"], "mensagem fora da janela temporal")
        self.assertEqual(len(peer.sent), 0)


if __name__ == "__main__":
    unittest.main()