"""Safety checks for the Windows-only, same-socket handover protocol."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime/bridge-v3"))
import ff_win_v3_agent as agent


class WindowsSocketHandoffGuards(unittest.TestCase):
    def test_listener_adoption_requires_standby(self):
        with patch.object(agent.STATE, "standby_waiting", False):
            with self.assertRaises(agent.RPCError) as caught:
                agent.op_adopt_listener({})
        self.assertEqual(caught.exception.code, "HANDOVER_NOT_WAITING")

    def test_listener_adoption_refuses_self_or_unverified_process(self):
        server = SimpleNamespace(server_address=("127.0.0.1", 44001),
                                 socket=Mock())
        with (patch.object(agent.STATE, "standby_waiting", True),
              patch.object(agent.STATE, "accept_ready", threading.Event()),
              patch.object(agent.STATE, "server", server)):
            for pid, token in ((os.getpid(), "self"), (1, "fake")):
                with self.subTest(pid=pid):
                    with self.assertRaises(agent.RPCError) as caught:
                        agent.op_adopt_listener({"source_pid": pid, "source_token": token})
                    self.assertEqual(caught.exception.code, "HANDOVER_SOURCE_INVALID")
            self.assertFalse(agent.STATE.accept_ready.is_set())

    @unittest.skipUnless(os.name == "nt", "WinSock socket.fromshare is Windows only")
    def test_malformed_windows_socket_share_does_not_activate(self):
        server = SimpleNamespace(server_address=("127.0.0.1", 44001),
                                 socket=Mock())
        event = threading.Event()
        with (patch.object(agent.STATE, "standby_waiting", True),
              patch.object(agent.STATE, "accept_ready", event),
              patch.object(agent.STATE, "server", server),
              patch.object(agent, "process_identity_matches", return_value=True)):
            with self.assertRaises(agent.RPCError) as caught:
                agent.op_adopt_listener({"source_pid": 123456,
                                         "source_token": "trusted-test-token",
                                         "listener_share": "***invalid***"})
            self.assertEqual(caught.exception.code, "HANDOVER_SOCKET_INVALID")
            self.assertFalse(event.is_set())
            server.socket.close.assert_not_called()

    def test_public_rpc_refuses_raw_socket_adoption(self):
        h = object.__new__(agent.Handler)
        h.path = "/rpc"
        h.server = object()
        h.send_json = Mock()
        with (patch.object(agent.STATE, "check_servers", []),
              patch.object(agent, "dispatch") as dispatch):
            h._handle_rpc(json.dumps({"op": "adopt_listener", "args": {}}).encode())
            dispatch.assert_not_called()
            h.send_json.assert_called_once_with(
                403, {"ok": False, "error_code": "HANDOVER_CHECK_PORT_REQUIRED"})

    def test_raw_winsock_share_is_never_written_to_audit(self):
        self.assertEqual(agent.redact({"listener_share": "sensitive-descriptor"}),
                         {"listener_share": "<redacted>"})

    def test_concurrent_drain_fails_before_contacting_standby(self):
        with (patch.object(agent.STATE, "drain_lock") as lock,
              patch.object(agent, "client_request") as peer):
            lock.acquire.return_value = False
            with self.assertRaises(agent.RPCError) as caught:
                agent.op_drain({"standby_port": 39099})
            self.assertEqual(caught.exception.code, "DRAIN_ALREADY_REQUESTED")
            peer.assert_not_called()
            lock.release.assert_not_called()

    def test_drain_refuses_unbound_or_unverified_standby(self):
        server = SimpleNamespace(socket=Mock())
        server.socket.share = Mock()
        with (patch.object(agent.STATE, "server", server),
              patch.object(agent.STATE, "draining", False),
              patch.object(agent.STATE, "drain_requested", False),
              patch.object(agent, "client_request", return_value={
                  "ok": True,
                  "result": {"pid": os.getpid() + 1, "standby_waiting": False,
                             "socket_handover_v1": True}
              })):
            if os.name == "nt":
                with self.assertRaises(agent.RPCError) as caught:
                    agent.op_drain({"standby_port": 39099})
                self.assertEqual(caught.exception.code, "DRAIN_STANDBY_NOT_READY")
                server.socket.share.assert_not_called()


if __name__ == "__main__":
    unittest.main()
