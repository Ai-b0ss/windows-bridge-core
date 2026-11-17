"""Verify the feature boundary and transparent error/key propagation."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime/bridge-v3"))
from ff_hub_rpc import HubGateway, HubGatewayError


class TestHubGateway(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.started, self.requests = [], []
        self.reply = {"ok": True, "result": {"state": "completed"}}
        outer = self

        class Client:
            def __init__(self, state):
                self.state = state

            def raw(self, request):
                outer.requests.append(request)
                return outer.reply

        self.gateway = HubGateway(Path(self.temp.name), client_factory=Client, starter=self.started.append)

    def enable(self, content=None):
        self.gateway.config_path.parent.mkdir(exist_ok=True)
        self.gateway.config_path.write_text(json.dumps({"version": 1, "enabled": True} if content is None else content), encoding="utf-8")

    def test_default_discovery_and_disabled_calls_have_no_effects(self):
        self.assertFalse(self.gateway.discovery()["enabled"])
        self.assertFalse(self.gateway.config_path.exists())
        with self.assertRaises(HubGatewayError) as ctx:
            self.gateway.call({"op": "capabilities"})
        self.assertEqual(ctx.exception.code, "HUB_FEATURE_DISABLED")
        self.assertEqual(self.started, [])
        self.assertEqual(self.requests, [])

    def test_malformed_config_fails_closed(self):
        for config in ({"version": True, "enabled": True}, {"version": 1, "enabled": "true"}, []):
            self.enable(config)
            self.assertEqual(self.gateway.discovery()["status"], "invalid_config")
            self.assertFalse(self.gateway.discovery()["enabled"])
        self.gateway.config_path.write_text("{", encoding="utf-8")
        self.assertEqual(self.gateway.discovery()["status"], "invalid_config")
        self.assertEqual(self.started, [])

    def test_forwards_exact_session_and_stable_request_key_without_replay(self):
        self.enable()
        request = {"op": "browser", "args": {"command": "act"}, "session_id": "session-a",
                   "session_secret": "test-secret", "request_key": "fixed-key"}
        self.assertEqual(self.gateway.call(request), {"state": "completed"})
        self.assertEqual(self.requests, [request])
        self.assertEqual(len(self.started), 1)
        self.assertIsNot(self.requests[0], request)

    def test_rejects_endpoint_injection_and_malformed_requests_before_start(self):
        self.enable()
        for request in ({"op": "capabilities", "state_dir": "foreign"}, {"op": "x", "args": []}, {"op": ""}, []):
            with self.assertRaises(HubGatewayError) as ctx:
                self.gateway.call(request)
            self.assertEqual(ctx.exception.code, "HUB_REQUEST_INVALID")
        self.assertEqual(self.started, [])

    def test_unknown_outcome_is_propagated_once(self):
        self.enable()
        self.reply = {"ok": False, "error_code": "REQUEST_OUTCOME_UNKNOWN",
                      "details": {"retry_safe": False, "execution_started": True}}
        with self.assertRaises(HubGatewayError) as ctx:
            self.gateway.call({"op": "browser", "args": {}, "request_key": "same-key"})
        self.assertEqual(ctx.exception.code, "REQUEST_OUTCOME_UNKNOWN")
        self.assertFalse(ctx.exception.details["retry_safe"])
        self.assertEqual(len(self.requests), 1)

    def test_bad_upstream_reply_does_not_report_success(self):
        self.enable()
        for reply in ({"result": "unconfirmed"}, {"ok": True}, {"ok": True, "result": "unconfirmed"},
                      {"ok": False, "details": ["invalid"]}):
            self.reply = reply
            with self.assertRaises(HubGatewayError) as ctx:
                self.gateway.call({"op": "capabilities"})
            self.assertEqual(ctx.exception.code, "HUB_REPLY_INVALID")


if __name__ == "__main__":
    unittest.main()
