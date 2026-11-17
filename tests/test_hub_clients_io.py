"""Contracts at the MCP/Hub boundary, ownership and durable external effects."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime/bridge-v3"))
from ff_hub import Hub
from ff_hub_io import MAX_OUTPUT_BYTES
from ff_hub_mcp import Adapter, handle
from ff_hub_permissions import PermissionError_
from ff_hub_store import HubError


class NoBrowser:
    def running(self):
        return False


class InProcessClient:
    def __init__(self, hub):
        self.hub = hub

    def raw(self, request):
        try:
            return {"ok": True, "result": self.hub.dispatch(request)}
        except HubError as exc:
            return {"ok": False, "error_code": exc.code, "details": exc.details}


class ClientIOTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.hub = Hub(self.root, browser=NoBrowser())
        self.client = InProcessClient(self.hub)
        self.a = Adapter(self.root, "client-a", client=self.client)
        self.b = Adapter(self.root, "client-b", client=self.client)
        self.a.call({"op": "session_open", "task_id": "task"})
        self.b.call({"op": "session_open", "task_id": "task"})

    def tearDown(self):
        for adapter in (self.a, self.b):
            try:
                adapter.call({"op": "session_close", "task_id": "task"})
            except HubError:
                pass
        self.hub.shutdown()
        self.hub.store.close()
        self.temporary.cleanup()

    def call(self, op, args, key=None, adapter=None):
        return (adapter or self.a).call({"op": op, "args": args, "task_id": "task", "request_key": "test-" + key if key else None})

    def error(self, code, callback):
        with self.assertRaises(HubError) as caught:
            callback()
        self.assertEqual(code, caught.exception.code)

    def grant(self):
        self.hub.policy.add_grant(["terminal_execute"], agents=["client-a"],
                                 paths=[str(self.root)], apps=[sys.executable], ttl_seconds=60)
        return self.hub.policy.add_grant(["project_write"], agents=["client-a"], paths=[str(self.root)], ttl_seconds=60)

    def wait(self, terminal_id):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            value = self.call("terminal", {"command": "status", "terminal_id": terminal_id})
            if value["state"] not in {"prepared", "running"}:
                return value
            time.sleep(.05)
        self.fail("terminal did not finish")

    def test_mcp_discovery_and_errors_never_leak_session_secrets(self):
        response = handle(self.a, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
        self.assertEqual("2024-11-05", response["result"]["protocolVersion"])
        tools = handle(self.a, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual("hub", tools["result"]["tools"][0]["name"])
        reply = handle(self.a, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
            "name": "hub", "arguments": {"op": "session_open", "task_id": "task"}}})
        self.assertNotIn("session_secret", json.dumps(reply))
        self.assertNotIn("resume_token", json.dumps(reply))
        self.assertIsNone(handle(self.a, {"jsonrpc": "2.0", "method": "notifications/initialized"}))
        self.assertEqual(-32601, handle(self.a, {"jsonrpc": "2.0", "id": 4, "method": "unsupported"})["error"]["code"])

    def test_restart_adapter_reuses_checkpoint_explicit_resume_revokes_old_secret(self):
        old = json.loads(next(self.a.checkpoints.glob("*.json")).read_text())
        fresh = Adapter(self.root, "client-a", client=self.client)
        self.assertTrue(fresh.call({"op": "session_open", "task_id": "task"})["checkpoint_reused"])
        resumed = fresh.call({"op": "session_resume", "task_id": "task"})
        self.assertNotEqual(old["session_id"], resumed["session_id"])
        self.assertFalse(self.client.raw({"op": "session_status", "session_id": old["session_id"],
                                          "session_secret": old["session_secret"]})["ok"])

    def test_files_policy_cas_dedupe_foreign_lock_and_revocation(self):
        path = self.root / "result.txt"
        args = {"command": "write", "path": str(path), "text": "one", "expected_sha256": None}
        self.error("PERMISSION_REQUIRED", lambda: self.call("files", args, "write-1"))
        grant = self.grant()
        first = self.call("files", args, "write-1")
        self.assertEqual(hashlib.sha256(b"one").hexdigest(), first["sha256"])
        self.assertTrue(self.call("files", args, "write-1")["deduplicated"])
        self.error("RESOURCE_BUSY", lambda: self.call("files", {"command": "read", "path": str(path)}, adapter=self.b))
        self.error("FILE_PRECONDITION_FAILED", lambda: self.call("files", {**args, "text": "wrong"}, "write-2"))
        self.assertEqual("one", path.read_text())
        self.hub.policy.revoke(grant["grant_id"])
        self.error("PERMISSION_REQUIRED", lambda: self.call("files", {**args, "expected_sha256": first["sha256"]}, "write-3"))
        self.assertEqual("one", path.read_text())

    def test_terminal_scopes_managed_ids_and_no_execution_on_denial(self):
        args = {"command": "start", "argv": [sys.executable, "-c", "print('ok')"], "cwd": str(self.root)}
        self.error("PERMISSION_REQUIRED", lambda: self.call("terminal", args, "terminal-1"))
        self.assertFalse((self.root / "terminal").exists())
        self.grant()
        self.error("PERMISSION_REQUIRED", lambda: self.call("terminal", {**args, "cwd": str(self.root.parent)}, "outside"))
        with self.assertRaises(PermissionError_):
            self.hub.policy.add_grant(["terminal_execute"], paths=[str(self.root)])
        self.error("RESOURCE_KIND_MANAGED", lambda: self.call("resource_claim", {"kind": "terminal", "key": "../../other"}, "bad"))

    def test_real_terminal_effect_once_foreign_denied_and_result_survives_hub_reopen(self):
        self.grant()
        path = self.root / "effect.txt"
        code = "from pathlib import Path;p=Path('effect.txt');p.write_text(p.read_text()+'x' if p.exists() else 'x');print('done')"
        args = {"command": "start", "argv": [sys.executable, "-c", code], "cwd": str(self.root)}
        job = self.call("terminal", args, "terminal-1")
        again = self.call("terminal", args, "terminal-1")
        self.assertEqual(job["terminal_id"], again["terminal_id"])
        self.error("RESOURCE_NOT_OWNED", lambda: self.call("terminal", {"command": "cancel", "terminal_id": job["terminal_id"]}, "bad-cancel", self.b))
        done = self.wait(job["terminal_id"])
        self.assertEqual("completed", done["state"])
        self.assertEqual(0, done["exit_code"])
        self.assertTrue(done["cleanup_verified"])
        self.assertEqual("x", path.read_text())
        self.hub.shutdown()
        self.hub.store.close()
        self.hub = Hub(self.root, browser=NoBrowser())
        self.client.hub = self.hub
        restored = self.call("terminal", {"command": "status", "terminal_id": job["terminal_id"]})
        self.assertEqual("completed", restored["state"])
        self.assertEqual("x", path.read_text())

    def test_hung_terminal_timeout_cancel_and_output_quota(self):
        self.grant()
        job = self.call("terminal", {"command": "start", "argv": [sys.executable, "-c", "import time;time.sleep(30)"],
                                     "cwd": str(self.root), "timeout_seconds": .15}, "timeout-1")
        self.assertEqual("timed_out", self.wait(job["terminal_id"])["state"])
        job = self.call("terminal", {"command": "start", "argv": [sys.executable, "-c", "import time;time.sleep(30)"],
                                     "cwd": str(self.root)}, "cancel-1")
        self.call("terminal", {"command": "cancel", "terminal_id": job["terminal_id"]}, "cancel-2")
        self.assertEqual("cancelled", self.wait(job["terminal_id"])["state"])
        job = self.call("terminal", {"command": "start", "argv": [sys.executable, "-c", "print('x'*2000000)"],
                                     "cwd": str(self.root)}, "quota-1")
        self.assertEqual("output_limit", self.wait(job["terminal_id"])["state"])
        self.assertLessEqual((self.root / "terminal" / job["terminal_id"] / "output.log").stat().st_size, MAX_OUTPUT_BYTES)


if __name__ == "__main__":
    unittest.main()
