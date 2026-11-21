"""Keepalive uses only a previously approved CDP socket; never bypasses Chrome approval."""
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"))
from cua_owner_chrome_secondary import _BrowserCDPClient


class _FakeSocket:
    def __init__(self, observed):
        self.observed = observed
        self.last_id = None
        self.closed = False

    def set_deadline(self, deadline):
        pass

    def send(self, raw):
        import json
        packet = json.loads(raw)
        self.last_id = packet["id"]
        self.observed.append(packet["method"])

    def recv(self):
        import json
        return json.dumps({"id": self.last_id, "result": {"product": "Chrome/158"}})

    def close(self):
        self.closed = True


class CDPApprovedKeepaliveTests(unittest.TestCase):
    def test_idle_heartbeat_uses_only_existing_socket(self):
        observed = []
        client = _BrowserCDPClient()
        sock = _FakeSocket(observed)
        client.socket = sock
        client.endpoint = "ws://127.0.0.1:1/devtools/browser/existing"
        client.generation = 1
        with patch.object(client, "KEEPALIVE_INTERVAL_S", 0.02), patch.object(
            client, "connect", side_effect=AssertionError("must not reconnect")
        ):
            try:
                client.start_keepalive()
                deadline = threading.Event()
                for _ in range(80):
                    if observed:
                        break
                    deadline.wait(0.01)
                self.assertIn("Browser.getVersion", observed)
                self.assertIs(client.socket, sock)
            finally:
                client.reset()
        self.assertTrue(sock.closed)

    def test_reset_stops_heartbeat_and_does_not_open_socket(self):
        observed = []
        client = _BrowserCDPClient()
        client.socket = _FakeSocket(observed)
        client.generation = 1
        with patch.object(client, "KEEPALIVE_INTERVAL_S", 0.02):
            client.start_keepalive()
            client.reset()
            threading.Event().wait(0.06)
        self.assertEqual(observed, [])
        self.assertFalse(client.connected())

    def test_no_socket_no_heartbeat_or_implicit_approval(self):
        client = _BrowserCDPClient()
        client.start_keepalive()
        self.assertFalse(client.connected())
        self.assertIsNone(client._keepalive_stop)


if __name__ == "__main__":
    unittest.main()
