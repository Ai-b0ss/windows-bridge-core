"""Contracts at the MCP/Hub boundary, ownership and durable external effects."""
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime/bridge-v3"))
from ff_hub import BrowserManager, Hub
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
            adapter.close()
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

    def test_stdio_entrypoint_bootstraps_with_an_isolated_python_import_path(self):
        script = Path(__file__).resolve().parents[1] / "runtime/bridge-v3/ff_hub_mcp.py"
        requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "isolated-python", "version": "1"}}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
        result = subprocess.run([sys.executable, "-I", "-S", str(script), "--agent", "portable-probe"],
                                input="".join(json.dumps(item) + "\n" for item in requests), cwd=self.root,
                                capture_output=True, text=True, encoding="utf-8", timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)
        replies = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual("hub", replies[1]["result"]["tools"][0]["name"])

    def test_terminal_worker_bootstraps_with_an_isolated_python_import_path(self):
        script = Path(__file__).resolve().parents[1] / "runtime/bridge-v3/ff_hub_io.py"
        directory = self.root / "isolated-worker"
        directory.mkdir()
        spec = {"terminal_id": "portable-worker", "job_token": uuid.uuid4().hex[:16],
                "argv": [sys.executable, "-I", "-S", "-c", "print('portable-worker-proof')"],
                "cwd": str(directory), "timeout_seconds": 5, "output_limit": 1024}
        (directory / "spec.json").write_text(json.dumps(spec), encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", "-S", str(script), "--worker", str(directory)],
                                cwd=self.root, capture_output=True, text=True, encoding="utf-8", timeout=15)
        self.assertEqual(0, result.returncode, result.stderr)
        status = json.loads((directory / "status.json").read_text())
        self.assertEqual("completed", status["state"])
        self.assertEqual(0, status["exit_code"])
        self.assertTrue(status["cleanup_verified"])
        self.assertIn("portable-worker-proof", (directory / "output.log").read_text())

    def test_owner_opt_in_start_never_enables_feature_and_never_replays_failed_call(self):
        adapter = Adapter(self.root / "hub", "owner-start", client=self.client, start_if_stopped=True)
        flag = self.root / "universal-agent-runtime.json"
        with patch("ff_hub_mcp.ensure_running") as starter:
            for content in (None, '{"version":true,"enabled":true}', '{"version":1,"enabled":false}', '{}'):
                if content is not None:
                    flag.write_text(content)
                self.error("HUB_FEATURE_DISABLED", lambda: adapter.call({"op": "capabilities"}))
                starter.assert_not_called()
            flag.write_text('{"version":1,"enabled":true}')
            self.assertIn("operations", adapter.call({"op": "capabilities"}))
            starter.assert_called_once_with(self.root / "hub")
        with patch("ff_hub_mcp.ensure_running"), patch.object(self.client, "raw", side_effect=HubError("HUB_UNREACHABLE")) as raw:
            self.error("HUB_UNREACHABLE", lambda: adapter.call({"op": "capabilities"}))
            raw.assert_called_once()

    @unittest.skipUnless(os.name == "nt", "Windows process incarnation")
    def test_browser_start_waits_for_prior_manager_without_killing_or_reusing_a_pid(self):
        from ff_win_process_identity import process_creation_token
        manager = BrowserManager(self.root)
        manager.state_dir.mkdir()
        token = process_creation_token(os.getpid())
        endpoint = manager.state_dir / "endpoint.json"
        endpoint.write_text(json.dumps({"pid": os.getpid(), "create_time": token, "port": 1}))
        self.error("BROWSER_MANAGER_RETIRING", lambda: manager._wait_for_prior_manager(timeout=.05))
        self.assertEqual(token, process_creation_token(os.getpid()))
        # A recycled PID is not the old manager. Never terminate or wait on it.
        endpoint.write_text(json.dumps({"pid": os.getpid(), "create_time": token + 1, "port": 1}))
        manager._wait_for_prior_manager(timeout=.05)

    def test_restart_adapter_reuses_checkpoint_explicit_resume_revokes_old_secret(self):
        old = json.loads(next(self.a.checkpoints.glob("*.json")).read_text())
        # While self.a is still live, another adapter instance must fail closed instead of hijacking.
        competing = Adapter(self.root, "client-a", client=self.client)
        try:
            self.error("CHECKPOINT_OWNED_BY_LIVE_PROCESS", lambda: competing.call({"op": "session_open", "task_id": "task"}))
        finally:
            competing.close()
        # After prior adapter exits cleanly, a restarted adapter recovers its checkpoint and can resume explicitly.
        self.a.close()
        fresh = Adapter(self.root, "client-a", client=self.client)
        try:
            self.assertTrue(fresh.call({"op": "session_open", "task_id": "task"})["checkpoint_reused"])
            resumed = fresh.call({"op": "session_resume", "task_id": "task"})
            self.assertNotEqual(old["session_id"], resumed["session_id"])
            self.assertFalse(self.client.raw({"op": "session_status", "session_id": old["session_id"],
                                              "session_secret": old["session_secret"]})["ok"])
        finally:
            fresh.close()

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

    @unittest.skipUnless(os.name == "nt", "Windows exact process/Job identity")
    def test_supervisor_crash_reports_unknown_and_cancel_reconciles_exact_job(self):
        from ff_win_process_identity import ProcessReference
        self.grant()
        job = self.call("terminal", {"command": "start", "argv": [sys.executable, "-c", "import time;time.sleep(30)"],
                                     "cwd": str(self.root)}, "supervisor-crash-1")
        deadline = time.monotonic() + 10
        while True:
            status = self.call("terminal", {"command": "status", "terminal_id": job["terminal_id"]})
            if status["state"] == "running":
                break
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.05)
        reference = ProcessReference(status["supervisor_pid"], status["supervisor_create_time"])
        try:
            reference.terminate()
        finally:
            reference.close()
        deadline = time.monotonic() + 5
        while True:
            status = self.call("terminal", {"command": "status", "terminal_id": job["terminal_id"]})
            if status["state"] == "unknown":
                break
            self.assertLess(time.monotonic(), deadline)
            time.sleep(.05)
        self.assertFalse(status["automatic_replay"])
        cancelled = self.call("terminal", {"command": "cancel", "terminal_id": job["terminal_id"]}, "supervisor-cancel-1")
        self.assertEqual("cancelled", cancelled["state"])
        self.assertTrue(cancelled["cleanup_verified"])


if __name__ == "__main__":
    unittest.main()
