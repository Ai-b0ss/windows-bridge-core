"""P0 Track C Hub / MCP / Agent Entry lifecycle, concurrency, crash-recovery & fail-closed tests.

Runs REAL isolated Hub HTTP servers (`ff_hub.py serve --port 0`), REAL `ff_hub_mcp.py` stdio
subprocesses, and REAL `/agent/v1` HTTP calls against temporary state directories.
Never touches production state, live Hub ports, or owner Chrome.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "runtime" / "bridge-v3"
sys.path.insert(0, str(PACKAGE))

from cua_agent_workflows import agent_workflows  # noqa: E402
from ff_agent_entry import EntryAuthority  # noqa: E402
from ff_hub import Hub, HubClient  # noqa: E402
from ff_hub_mcp import Adapter, MCP_ADAPTER_VERSION, credential_lock, handle  # noqa: E402
from ff_hub_permissions import PermissionError_, Policy  # noqa: E402
from ff_hub_rpc import HubGateway  # noqa: E402
from ff_hub_store import HubError, HubStore  # noqa: E402


def _loopback_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


class _LiveHubServer:
    """Manages an isolated `ff_hub.py serve --port 0` subprocess on a temporary state dir."""

    def __init__(self, state_dir: Path):
        self.state_dir = Path(state_dir)
        self.proc: subprocess.Popen | None = None
        self.endpoint: dict | None = None

    def start(self, timeout: float = 15.0) -> dict:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        argv = [
            sys.executable,
            str(PACKAGE / "ff_hub.py"),
            "serve",
            "--state-dir",
            str(self.state_dir),
            "--port",
            "0",
        ]
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(PACKAGE),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        client = HubClient(self.state_dir, timeout=3.0)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                out, err = self.proc.communicate(timeout=3)
                raise RuntimeError(f"Hub exited early ({self.proc.returncode}): {out!r} {err!r}")
            try:
                ep = client.endpoint()
                st = client.call("hub_status")
                if st.get("pid") == self.proc.pid and ep.get("pid") == self.proc.pid:
                    self.endpoint = ep
                    return ep
            except HubError:
                pass
            time.sleep(0.05)
        self.stop(force=True)
        raise TimeoutError("Isolated Hub did not become ready in time")

    def stop(self, *, force: bool = False) -> None:
        if self.proc is None:
            return
        try:
            if self.proc.poll() is None:
                if not force:
                    try:
                        HubClient(self.state_dir, timeout=2.0).call("hub_shutdown_idle")
                        self.proc.wait(timeout=6.0)
                    except Exception:
                        pass
                if self.proc.poll() is None:
                    self.proc.terminate()
                    try:
                        self.proc.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:
                        self.proc.kill()
                        self.proc.wait(timeout=3.0)
        finally:
            for stream in (self.proc.stdout, self.proc.stderr):
                if stream:
                    try:
                        stream.close()
                    except OSError:
                        pass
            self.proc = None


class _LiveMcpClient:
    """Real `ff_hub_mcp.py` stdio JSON-RPC subprocess client."""

    def __init__(self, state_dir: Path, agent: str, *, heartbeat_seconds: float = 0.0):
        argv = [
            sys.executable,
            str(PACKAGE / "ff_hub_mcp.py"),
            "--state-dir",
            str(state_dir),
            "--agent",
            agent,
        ]
        if heartbeat_seconds > 0:
            argv += ["--heartbeat-seconds", str(heartbeat_seconds)]
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(PACKAGE),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self._id = 0
        self._responses: dict[int, dict] = {}
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._closed = False
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    @property
    def pid(self) -> int:
        return self.proc.pid

    def _read_loop(self) -> None:
        assert self.proc.stdout is not None
        try:
            for raw in self.proc.stdout:
                line = raw.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                msg = json.loads(line)
                msg_id = msg.get("id")
                with self._cond:
                    if msg_id is not None:
                        self._responses[msg_id] = msg
                        self._cond.notify_all()
        finally:
            with self._cond:
                self._closed = True
                self._cond.notify_all()

    def send_raw(self, payload: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        self.proc.stdin.flush()

    def request(self, method: str, params: dict | None = None, *, timeout: float = 15.0) -> dict:
        with self._lock:
            self._id += 1
            req_id = self._id
        payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
        self.send_raw(payload)
        deadline = time.monotonic() + timeout
        with self._cond:
            while req_id not in self._responses:
                if self._closed:
                    raise RuntimeError("MCP subprocess stdout closed before reply")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"Timed out waiting for MCP response id={req_id}")
                self._cond.wait(timeout=remaining)
            return self._responses.pop(req_id)

    def initialize(self) -> dict:
        init = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "p0-test-client", "version": "1.0"},
            },
        )
        self.send_raw({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return init

    def call_hub(self, arguments: dict, *, timeout: float = 15.0) -> tuple[bool, dict]:
        resp = self.request("tools/call", {"name": "hub", "arguments": arguments}, timeout=timeout)
        res = resp["result"]
        body = json.loads(res["content"][0]["text"])
        return (not res["isError"]), body

    def close(self) -> int:
        try:
            if self.proc.stdin and not self.proc.stdin.closed:
                self.proc.stdin.close()
        except OSError:
            pass
        try:
            rc = self.proc.wait(timeout=8.0)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            rc = self.proc.wait(timeout=3.0)
        self._reader.join(timeout=2.0)
        for stream in (self.proc.stdout, self.proc.stderr):
            if stream:
                try:
                    stream.close()
                except OSError:
                    pass
        return rc


class RealIsolatedHubMcpTests(unittest.TestCase):
    """End-to-end tests using real Hub HTTP servers and real MCP stdio subprocesses."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.state = self.root / "hub-state"
        self.hub_srv = _LiveHubServer(self.state)
        self.clients: list[_LiveMcpClient] = []

    def tearDown(self) -> None:
        for client in self.clients:
            try:
                client.close()
            except Exception:
                pass
        self.hub_srv.stop(force=True)
        self.tmp.cleanup()

    def _spawn_mcp(self, agent: str, *, heartbeat_seconds: float = 0.0) -> _LiveMcpClient:
        client = _LiveMcpClient(self.state, agent, heartbeat_seconds=heartbeat_seconds)
        self.clients.append(client)
        return client

    def test_dual_parallel_sessions_receipts_and_zero_cross_session_cleanup(self) -> None:
        self.hub_srv.start()
        work_dir = self.root / "work"
        work_dir.mkdir()
        Policy(self.state / "policy.json").add_grant(
            ["project_write"], agents=["agent-1", "agent-2"], paths=[str(work_dir)], ttl_seconds=300
        )

        c1 = self._spawn_mcp("agent-1")
        c2 = self._spawn_mcp("agent-2")
        init1 = c1.initialize()
        init2 = c2.initialize()
        self.assertEqual(init1["result"]["serverInfo"]["version"], MCP_ADAPTER_VERSION)
        self.assertEqual(init2["result"]["serverInfo"]["version"], MCP_ADAPTER_VERSION)

        # Typed inputSchema verification
        tools = c1.request("tools/list")["result"]["tools"]
        self.assertEqual(tools[0]["name"], "hub")
        schema_props = tools[0]["inputSchema"]["properties"]
        self.assertIn("args", schema_props)
        self.assertIn("profile_id", schema_props["args"]["properties"])
        self.assertIn("route_plan", schema_props["op"]["enum"])
        self.assertIn("managed_browser", schema_props["op"]["enum"])

        ok1, s1 = c1.call_hub({"op": "session_open", "task_id": "task-1"})
        ok2, s2 = c2.call_hub({"op": "session_open", "task_id": "task-2"})
        self.assertTrue(ok1 and ok2)
        self.assertNotIn("session_secret", json.dumps(s1))
        self.assertNotIn("resume_token", json.dumps(s1))
        self.assertNotIn("_mcp_owner", json.dumps(s1))
        self.assertNotEqual(s1["session_id"], s2["session_id"])

        # Each agent claims its own exclusive lock and writes its own file
        ok, lock1 = c1.call_hub({
            "op": "resource_claim",
            "task_id": "task-1",
            "request_key": "a1-claim-lock-001",
            "args": {"kind": "custom", "key": "lease-alpha"},
        })
        self.assertTrue(ok, lock1)
        ok, lock2 = c2.call_hub({
            "op": "resource_claim",
            "task_id": "task-2",
            "request_key": "a2-claim-lock-001",
            "args": {"kind": "custom", "key": "lease-beta"},
        })
        self.assertTrue(ok, lock2)

        # Cross-session conflict must fail closed
        ok, busy = c2.call_hub({
            "op": "resource_claim",
            "task_id": "task-2",
            "request_key": "a2-steal-alpha-001",
            "args": {"kind": "custom", "key": "lease-alpha"},
        })
        self.assertFalse(ok)
        self.assertEqual(busy["error_code"], "RESOURCE_BUSY")

        f1 = work_dir / "a1.txt"
        ok, w1 = c1.call_hub({
            "op": "files",
            "task_id": "task-1",
            "request_key": "a1-write-file-001",
            "args": {"command": "write", "path": str(f1), "text": "hello-1", "expected_sha256": None},
        })
        self.assertTrue(ok, w1)
        self.assertEqual(f1.read_text(encoding="utf-8"), "hello-1")

        # Close agent-1/task-1 with request_key -> verified receipt, checkpoint removed, agent-2 untouched!
        cp1_dir = self.state / "clients" / hashlib.sha256(b"agent-1").hexdigest()[:24]
        cp1_file = cp1_dir / (hashlib.sha256(b"task-1").hexdigest() + ".json")
        self.assertTrue(cp1_file.is_file())

        ok, closed1 = c1.call_hub({
            "op": "session_close",
            "task_id": "task-1",
            "request_key": "a1-close-session-001",
        })
        self.assertTrue(ok, closed1)
        self.assertTrue(closed1["closed"])
        self.assertTrue(closed1["cleanup_verified"])
        self.assertEqual(closed1["resources_retained"], 0)
        self.assertEqual(closed1["locks_released"], 2)  # custom lock + file lock
        self.assertFalse(cp1_file.exists(), "checkpoint should be cleanly removed on verified session_close")

        # Verify agent-2/task-2 is completely untouched (zero cross-session cleanup)
        ok, st2 = c2.call_hub({"op": "session_status", "task_id": "task-2"})
        self.assertTrue(ok, st2)
        self.assertEqual([r["key"] for r in st2["resources"]], ["lease-beta"])

        # Now close agent-2/task-2
        ok, closed2 = c2.call_hub({
            "op": "session_close",
            "task_id": "task-2",
            "request_key": "a2-close-session-001",
        })
        self.assertTrue(ok, closed2)
        self.assertTrue(closed2["closed"])
        self.assertTrue(closed2["cleanup_verified"])
        self.assertEqual(closed2["resources_retained"], 0)
        self.assertEqual(closed2["locks_released"], 1)

        # Clean idle shutdown of the real Hub
        ok, status = c1.call_hub({"op": "hub_status"})
        self.assertTrue(ok)
        self.assertEqual(status["sessions"], [])
        self.assertEqual(status["resources"], [])
        self.assertEqual(c1.close(), 0)
        self.assertEqual(c2.close(), 0)
        shutdown_reply = HubClient(self.state, timeout=5.0).call("hub_shutdown_idle")
        self.assertTrue(shutdown_reply["idle_verified"])

    def test_concurrent_same_agent_same_task_mcp_fails_closed_no_hijack_no_winerror33(self) -> None:
        self.hub_srv.start()
        p1 = self._spawn_mcp("shared-agent")
        p2 = self._spawn_mcp("shared-agent")
        p1.initialize()
        p2.initialize()
        self.assertNotEqual(p1.pid, p2.pid)

        ok, opened = p1.call_hub({"op": "session_open", "task_id": "same-task"})
        self.assertTrue(ok, opened)
        ok, claimed = p1.call_hub({
            "op": "resource_claim",
            "task_id": "same-task",
            "request_key": "p1-claim-shared-001",
            "args": {"kind": "custom", "key": "p1-owned-lock"},
        })
        self.assertTrue(ok, claimed)

        # Process 2 (different live PID!) attempts to open, inspect, resume (without token), or close same-task
        for attempt in (
            {"op": "session_open", "task_id": "same-task"},
            {"op": "session_status", "task_id": "same-task"},
            {"op": "session_resume", "task_id": "same-task"},
            {"op": "session_resume", "task_id": "same-task", "args": {"resume_token": "wrong-token"}},
            {"op": "session_close", "task_id": "same-task", "request_key": "p2-steal-close-001"},
        ):
            ok, err = p2.call_hub(attempt)
            self.assertFalse(ok, f"Process 2 must fail closed for {attempt}: got {err}")
            self.assertEqual(err["error_code"], "CHECKPOINT_OWNED_BY_LIVE_PROCESS", err)
            self.assertTrue(err["details"]["session_active_elsewhere"])
            self.assertEqual(err["details"]["owner_pid"], p1.pid)

        # Process 1's session and lock remain completely intact!
        ok, st1 = p1.call_hub({"op": "session_status", "task_id": "same-task"})
        self.assertTrue(ok, st1)
        self.assertEqual([r["key"] for r in st1["resources"]], ["p1-owned-lock"])

        # Explicit takeover while Process 1 IS live succeeds ONLY when the valid resume_token is supplied
        cp_dir = self.state / "clients" / hashlib.sha256(b"shared-agent").hexdigest()[:24]
        cp_file = cp_dir / (hashlib.sha256(b"same-task").hexdigest() + ".json")
        saved_token = json.loads(cp_file.read_text(encoding="utf-8"))["resume_token"]
        ok, taken_over = p2.call_hub({
            "op": "session_resume",
            "task_id": "same-task",
            "args": {"resume_token": saved_token},
        })
        self.assertTrue(ok, taken_over)
        self.assertTrue(taken_over["resumed"])
        self.assertEqual(taken_over["adopted_resources"], 1)
        self.assertNotEqual(taken_over["session_id"], opened["session_id"])

        # Now Process 2 owns the live checkpoint -> Process 1 fails closed!
        ok, p1_denied = p1.call_hub({"op": "session_status", "task_id": "same-task"})
        self.assertFalse(ok)
        self.assertEqual(p1_denied["error_code"], "CHECKPOINT_OWNED_BY_LIVE_PROCESS")
        self.assertEqual(p1_denied["details"]["owner_pid"], p2.pid)

        # Stop Process 2 cleanly (disconnect without session_close) -> Process 3 can recover without manual token!
        self.assertEqual(p1.close(), 0)
        self.assertEqual(p2.close(), 0)
        p3 = self._spawn_mcp("shared-agent")
        p3.initialize()
        ok, resumed = p3.call_hub({"op": "session_resume", "task_id": "same-task"})
        self.assertTrue(ok, resumed)
        self.assertTrue(resumed["resumed"])
        self.assertEqual(resumed["adopted_resources"], 1)
        self.assertNotEqual(resumed["session_id"], taken_over["session_id"])

        ok, closed = p3.call_hub({
            "op": "session_close",
            "task_id": "same-task",
            "request_key": "p3-final-close-001",
        })
        self.assertTrue(ok, closed)
        self.assertTrue(closed["cleanup_verified"])
        self.assertEqual(closed["resources_retained"], 0)
        self.assertEqual(p3.close(), 0)

    def test_windows_credential_lock_multi_process_contention_zero_winerror33(self) -> None:
        lock_path = self.root / "contended-task.lock"
        script = "\n".join([
            "import sys, time",
            "from pathlib import Path",
            f"sys.path.insert(0, {str(PACKAGE)!r})",
            "from ff_hub_mcp import credential_lock",
            f"p = Path({str(lock_path)!r})",
            "with credential_lock(p, timeout=15):",
            "    time.sleep(0.1)",
            "    print('LOCK_OK')",
        ])
        procs: list[subprocess.Popen] = []
        try:
            with credential_lock(lock_path, timeout=15):
                for _ in range(3):
                    procs.append(subprocess.Popen(
                        [sys.executable, "-c", script],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    ))
                time.sleep(0.25)
                for p in procs:
                    self.assertIsNone(p.poll(), "Competing process should wait on lock, not fail with WinError 33")
            for p in procs:
                out, err = p.communicate(timeout=15)
                self.assertEqual(p.returncode, 0, f"stderr={err!r} stdout={out!r}")
                self.assertIn("LOCK_OK", out)
        finally:
            for p in procs:
                if p.poll() is None:
                    p.kill()
                    p.wait(timeout=3)
                for s in (p.stdout, p.stderr):
                    if s:
                        s.close()

    def test_negative_without_grants_cross_task_audit_and_agent_entry_http(self) -> None:
        ep = self.hub_srv.start()
        port = ep["port"]
        # 1. MCP negative tests WITHOUT any owner grants
        c = self._spawn_mcp("unprivileged-agent")
        c.initialize()
        ok, _ = c.call_hub({"op": "session_open", "task_id": "task-alpha"})
        self.assertTrue(ok)
        ok, _ = c.call_hub({"op": "session_open", "task_id": "task-beta"})
        self.assertTrue(ok)

        target_file = self.root / "forbidden.txt"
        ok, denied_write = c.call_hub({
            "op": "files",
            "task_id": "task-alpha",
            "request_key": "deny-write-0001",
            "args": {"command": "write", "path": str(target_file), "text": "nope", "expected_sha256": None},
        })
        self.assertFalse(ok)
        self.assertEqual(denied_write["error_code"], "PERMISSION_REQUIRED")
        self.assertFalse(target_file.exists())

        # request_status reports execution_started=False for pre-execution permission denial
        ok, rs = c.call_hub({
            "op": "request_status",
            "task_id": "task-alpha",
            "args": {"request_key": "deny-write-0001"},
        })
        self.assertTrue(ok, rs)
        self.assertEqual(rs["state"], "failed")
        self.assertFalse(rs["execution_started"])

        ok, denied_term = c.call_hub({
            "op": "terminal",
            "task_id": "task-alpha",
            "request_key": "deny-term-0001",
            "args": {"command": "start", "argv": [sys.executable, "-c", "print(1)"], "cwd": str(self.root)},
        })
        self.assertFalse(ok)
        self.assertEqual(denied_term["error_code"], "PERMISSION_REQUIRED")
        self.assertFalse((self.state / "terminal").exists())

        ok, denied_pb = c.call_hub({
            "op": "private_browser",
            "task_id": "task-alpha",
            "request_key": "deny-pb-0001",
            "args": {"command": "open"},
        })
        self.assertFalse(ok)
        self.assertEqual(denied_pb["error_code"], "PERMISSION_REQUIRED")

        ok, denied_fg = c.call_hub({
            "op": "browser",
            "task_id": "task-alpha",
            "request_key": "deny-fg-0001",
            "args": {"command": "act", "foreground": True, "tab_id": "tab-none"},
        })
        self.assertFalse(ok)
        self.assertEqual(denied_fg["error_code"], "FOREGROUND_ROUTE_REQUIRED")

        # Cross-task audit_read isolation
        ok, denied_audit = c.call_hub({
            "op": "audit_read",
            "task_id": "task-alpha",
            "args": {"task_id": "task-beta"},
        })
        self.assertFalse(ok)
        self.assertEqual(denied_audit["error_code"], "RESOURCE_NOT_OWNED")

        ok, own_audit = c.call_hub({"op": "audit_read", "task_id": "task-alpha"})
        self.assertTrue(ok)
        self.assertTrue(own_audit["records"])
        self.assertEqual({row["task_id"] for row in own_audit["records"]}, {"task-alpha"})

        # 2. REAL HTTP /agent/v1 Entry negative & positive contract tests
        auth = EntryAuthority(self.state)
        _, token = auth.issue(
            client_id="cli-entry",
            agent_id="entry-agent",
            task_id="entry-task",
            scopes=["private_browser", "locks"],
            apps=[],
            ttl=120,
        )

        def post_entry(body: dict, *, headers: dict | None = None) -> tuple[int, dict]:
            req_headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
            if headers:
                req_headers.update(headers)
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/agent/v1",
                method="POST",
                data=json.dumps(body).encode("utf-8"),
                headers=req_headers,
            )
            try:
                with _loopback_opener().open(req, timeout=5.0) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as exc:
                return exc.code, json.loads(exc.read())

        status, bad_origin = post_entry({"op": "capabilities"}, headers={"Origin": "https://evil.invalid"})
        self.assertEqual(status, 403)
        self.assertEqual(bad_origin["error_code"], "ENTRY_ORIGIN_DENIED")

        status, bad_auth = post_entry({"op": "capabilities"}, headers={"Authorization": "Bearer eg-bad"})
        self.assertEqual(status, 401)
        self.assertEqual(bad_auth["error_code"], "ENTRY_UNAUTHORIZED")

        status, caps = post_entry({"op": "capabilities"})
        self.assertEqual(status, 200)
        self.assertTrue(caps["ok"])
        self.assertEqual(caps["result"]["default_browser_route"], "isolated_hidden_browser")
        self.assertFalse(caps["result"]["owner_chrome_available"])
        self.assertFalse(caps["result"]["silent_playwright_fallback"])
        self.assertIn("session_close", caps["result"]["operations"])
        self.assertEqual(caps["result"]["managed_browser_profile_args"], ["profile_id", "profile_name", "persistent_profile"])

        status, entry_sess = post_entry({"op": "session_open"})
        self.assertEqual(status, 200)
        sid = entry_sess["result"]["session_id"]

        # Unscoped owner-chrome `browser` denied at /agent/v1
        status, unscoped = post_entry({"op": "browser", "session_id": sid, "args": {"command": "open"}, "request_key": "entry-unscoped-01"})
        self.assertFalse(unscoped["ok"])
        self.assertEqual(unscoped["error_code"], "ENTRY_SCOPE_DENIED")

        # Forbidden overrides (foreground, headless, route, raw profile_dir) denied fail-closed
        for forbidden_args in (
            {"command": "open", "foreground": True},
            {"command": "open", "headless": False},
            {"command": "open", "route": "owner_chrome_extension"},
            {"command": "open", "profile_dir": str(self.root / "raw-dir")},
        ):
            status, denied = post_entry({
                "op": "managed_browser",
                "session_id": sid,
                "request_key": "entry-forbid-001",
                "args": forbidden_args,
            })
            self.assertFalse(denied["ok"], forbidden_args)
            self.assertEqual(denied["error_code"], "ENTRY_BROWSER_COMMAND_DENIED")

        # session_close via /agent/v1 requires request_key, deduplicates on replay
        status, no_key = post_entry({"op": "session_close", "session_id": sid})
        self.assertFalse(no_key["ok"])
        self.assertEqual(no_key["error_code"], "REQUEST_KEY_REQUIRED")

        status, cls1 = post_entry({"op": "session_close", "session_id": sid, "request_key": "entry-close-0001"})
        self.assertTrue(cls1["ok"], cls1)
        self.assertTrue(cls1["result"]["closed"])
        self.assertTrue(cls1["result"]["cleanup_verified"])
        self.assertEqual(cls1["result"]["resources_retained"], 0)
        self.assertFalse(cls1["result"]["deduplicated"])

        status, cls2 = post_entry({"op": "session_close", "session_id": sid, "request_key": "entry-close-0001"})
        self.assertTrue(cls2["ok"], cls2)
        self.assertTrue(cls2["result"]["deduplicated"])
        self.assertEqual(cls2["result"]["resources_retained"], 0)

        # Verify unified route metadata across workflows & gateway has zero silent visible Playwright fallback
        wf = agent_workflows()
        self.assertEqual(wf["browser_workflow"]["preferred_route"], "shared_hub.isolated_hidden_browser")
        self.assertTrue(wf["browser_workflow"]["legacy_fallback"]["never_silently_fallback"])
        gw = HubGateway(self.root).discovery()
        self.assertEqual(gw["default_browser_route"], "isolated_hidden_browser")
        self.assertFalse(gw["silent_playwright_fallback"])

    def test_deduplication_mismatched_payload_and_hub_restart_recovery(self) -> None:
        self.hub_srv.start()
        work_dir = self.root / "restart-work"
        work_dir.mkdir()
        Policy(self.state / "policy.json").add_grant(
            ["terminal_execute"], agents=["recover-agent"], paths=[str(work_dir)], apps=[sys.executable], ttl_seconds=300
        )

        client = HubClient(self.state, timeout=10.0)
        sess = client.call("session_open", {"agent_id": "recover-agent", "task_id": "recover-task"})

        # Deduplication & payload mismatch rejection
        c1 = client.call("resource_claim", {"kind": "custom", "key": "durable-lock"}, request_key="dedupe-claim-001")
        c2 = client.call("resource_claim", {"kind": "custom", "key": "durable-lock"}, request_key="dedupe-claim-001")
        self.assertFalse(c1["deduplicated"])
        self.assertTrue(c2["deduplicated"])
        self.assertEqual(c1["resource_id"], c2["resource_id"])
        with self.assertRaises(HubError) as mismatch:
            client.call("resource_claim", {"kind": "custom", "key": "different-lock"}, request_key="dedupe-claim-001")
        self.assertEqual(mismatch.exception.code, "REQUEST_KEY_REUSED")

        # Start a real terminal job whose result survives Hub crash/restart
        job = client.call(
            "terminal",
            {"command": "start", "argv": [sys.executable, "-c", "print('survived-hub-restart')"], "cwd": str(work_dir)},
            request_key="term-survive-001",
        )
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            st = client.call("terminal", {"command": "status", "terminal_id": job["terminal_id"]})
            if st["state"] == "completed":
                break
            time.sleep(0.05)
        self.assertEqual(st["state"], "completed")

        # Simulate Hub restart on the exact same state dir
        self.hub_srv.stop(force=True)
        self.hub_srv.start()

        # Verify session, held lock, journal receipt, and terminal output survived restart
        after_status = client.call("session_status")
        keys = {r["key"] for r in after_status["resources"]}
        self.assertIn("durable-lock", keys)
        self.assertIn(job["terminal_id"], keys)
        term_after = client.call("terminal", {"command": "status", "terminal_id": job["terminal_id"]})
        self.assertIn("survived-hub-restart", term_after.get("output", ""))
        replay = client.call("resource_claim", {"kind": "custom", "key": "durable-lock"}, request_key="dedupe-claim-001")
        self.assertTrue(replay["deduplicated"])

        # Keyed session_close works and replays cleanly after close
        cls1 = client.call("session_close", request_key="close-after-restart-001")
        self.assertTrue(cls1["closed"])
        self.assertTrue(cls1["cleanup_verified"])
        self.assertEqual(cls1["resources_retained"], 0)
        self.assertFalse(cls1["deduplicated"])
        cls2 = client.call("session_close", request_key="close-after-restart-001")
        self.assertTrue(cls2["deduplicated"])
        self.assertEqual(cls2["resources_retained"], 0)

        with self.assertRaises(HubError) as closed_err:
            client.call("session_status")
        self.assertEqual(closed_err.exception.code, "SESSION_CLOSED")

    def test_short_orphan_ttl_auto_reaps_abandoned_while_heartbeat_keeps_active_alive(self) -> None:
        self.state.mkdir(parents=True, exist_ok=True)
        (self.state / "config.json").write_text(
            json.dumps({
                "session_ttl_seconds": 0.4,
                "orphan_ttl_seconds": 0.4,
                "maintain_interval_seconds": 0.15,
            }),
            encoding="utf-8",
        )
        self.hub_srv.start()

        # Verify capabilities advertises configured short TTLs
        client = HubClient(self.state, timeout=5.0)
        caps = client.call("capabilities")
        self.assertAlmostEqual(caps["session_timeouts"]["session_ttl_seconds"], 0.4)
        self.assertAlmostEqual(caps["session_timeouts"]["orphan_ttl_seconds"], 0.4)

        # Active MCP client WITH heartbeat stays alive across orphan window
        alive_mcp = self._spawn_mcp("hb-agent", heartbeat_seconds=0.2)
        alive_mcp.initialize()
        ok, alive_sess = alive_mcp.call_hub({"op": "session_open", "task_id": "hb-task"})
        self.assertTrue(ok, alive_sess)
        ok, _ = alive_mcp.call_hub({
            "op": "resource_claim",
            "task_id": "hb-task",
            "request_key": "hb-claim-0001",
            "args": {"kind": "custom", "key": "hb-lock"},
        })
        self.assertTrue(ok)

        # Abandoned client WITHOUT heartbeat holds a custom lock and goes silent
        orphan_client = HubClient(self.state, timeout=5.0)
        orphan_sess = orphan_client.call("session_open", {"agent_id": "orphan-agent", "task_id": "orphan-task"})
        orphan_client.call("resource_claim", {"kind": "custom", "key": "orphan-lock"}, request_key="orphan-claim-001")

        # Wait for Hub maintenance loop to reap the abandoned session while hb-agent stays alive
        deadline = time.monotonic() + 5.0
        reaped = False
        while time.monotonic() < deadline:
            st = client.call("hub_status")
            active_ids = {s["session_id"] for s in st["sessions"]}
            held_keys = {r["key"] for r in st["resources"]}
            if orphan_sess["session_id"] not in active_ids and "orphan-lock" not in held_keys:
                reaped = True
                break
            time.sleep(0.1)
        self.assertTrue(reaped, "Abandoned session should have been reaped promptly by short orphan TTL")

        # Heartbeat-backed MCP session MUST still be alive and hold its lock
        ok, alive_st = alive_mcp.call_hub({"op": "session_status", "task_id": "hb-task"})
        self.assertTrue(ok, alive_st)
        self.assertEqual([r["key"] for r in alive_st["resources"]], ["hb-lock"])

        # Verify session_expired_cleanup audit was written for the orphan session
        store = HubStore(self.state / "hub.db")
        try:
            audit_rows = store.read_audit(agent_id="orphan-agent", task_id="orphan-task")
            expired_cleanups = [r for r in audit_rows if r["event"] == "session_expired_cleanup"]
            self.assertEqual(len(expired_cleanups), 1)
            self.assertTrue(expired_cleanups[0]["detail"]["cleanup_verified"])
            self.assertEqual(expired_cleanups[0]["detail"]["resources_retained"], 0)
        finally:
            store.close()

        ok, closed = alive_mcp.call_hub({"op": "session_close", "task_id": "hb-task", "request_key": "hb-close-0001"})
        self.assertTrue(ok and closed["cleanup_verified"])


class TwoPhaseRetentionAndShutdownTests(unittest.TestCase):
    """Focused tests for two-phase retention, Hub.shutdown consistency, _mcp_pending & policy validation."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_two_phase_retains_unconfirmed_browser_tab_and_managed_browser_fail_closed(self) -> None:
        class _UnconfirmedBrowser:
            def __init__(self) -> None:
                self.is_running = True
                self.calls: list[tuple[str, dict | None]] = []
                self.confirm_close = False
                self.stop_calls: list[bool] = []

            def running(self) -> bool:
                return self.is_running

            def stop(self, *, close_tabs: bool = True) -> None:
                self.stop_calls.append(close_tabs)
                self.is_running = False

            def call(self, op: str, args: dict | None = None) -> dict:
                self.calls.append((op, args))
                if op == "tab_open":
                    return {"tab_id": "tab-unconfirmed-1", "url": args["url"]}
                if op == "tab_list":
                    return {"tabs": [{"tab_id": "tab-unconfirmed-1"}]}
                if op == "tab_close_owner":
                    if self.confirm_close:
                        return {"closed": 1, "unconfirmed": [], "errors": []}
                    return {"closed": 0, "unconfirmed": ["tab-unconfirmed-1"], "errors": []}
                return {"ok": True}

        class _UnconfirmedManaged:
            def __init__(self) -> None:
                self.is_running = True
                self.calls: list[tuple[str, dict | None]] = []
                self.confirm_close = False

            def running(self) -> bool:
                return self.is_running

            def stop(self, *, close_contexts: bool = True) -> None:
                self.is_running = False

            def call(self, op: str, args: dict | None = None) -> dict:
                self.calls.append((op, args))
                if op == "open":
                    return {
                        "browser_id": "pw-retained-1",
                        "route": "persistent_playwright",
                        "headless": True,
                        "isolated_profile": True,
                        "persistent_profile": True,
                        "profile_id": args.get("profile_id"),
                        "tab_id": "pwtab-1",
                        "target_id": "TGT-1",
                        "url": args.get("url") or "about:blank",
                    }
                if op == "close_owner":
                    if self.confirm_close:
                        return {"closed": 1, "unconfirmed": [], "errors": [], "preserved_profiles": ["agent-prof-1"]}
                    return {"closed": 0, "unconfirmed": ["pw-retained-1"], "errors": [{"code": "CHILD_STILL_RUNNING"}]}
                return {"ok": True}

        browser = _UnconfirmedBrowser()
        managed = _UnconfirmedManaged()
        hub = Hub(self.root / "retain", browser=browser, managed_browser=managed)
        try:
            sess = hub.dispatch({"op": "session_open", "args": {"agent_id": "ret-agent", "task_id": "ret-task"}})
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}

            hub.dispatch({**auth, "op": "browser", "args": {"command": "open", "url": "https://example.invalid/"}, "request_key": "open-tab-0001"})
            opened_pw = hub.dispatch({
                **auth,
                "op": "managed_browser",
                "args": {"command": "open", "url": "http://127.0.0.1:8080/", "profile_id": "agent-prof-1", "persistent_profile": True},
                "request_key": "open-pw-0001",
            })
            self.assertEqual(opened_pw["profile_id"], "agent-prof-1")
            hub.dispatch({**auth, "op": "resource_claim", "args": {"kind": "custom", "key": "plain-lock"}, "request_key": "open-lock-0001"})

            # Close while both browser_tab and managed_browser fail to confirm cleanup:
            # - forget_unconfirmed MUST be False!
            # - plain-lock IS released, while browser_tab & managed_browser STAY held in SQLite!
            first_close = hub.dispatch({**auth, "op": "session_close", "request_key": "close-unconfirmed-001"})
            self.assertTrue(first_close["closed"])
            self.assertFalse(first_close["cleanup_verified"])
            self.assertEqual(first_close["resources_retained"], 2)
            self.assertEqual(first_close["locks_released"], 1)
            close_owner_call = next(args for op, args in browser.calls if op == "tab_close_owner")
            self.assertIs(close_owner_call["forget_unconfirmed"], False)

            retained = hub.store.resources(session_id=sess["session_id"])
            self.assertEqual({r["key"] for r in retained}, {"tab-unconfirmed-1", "pw-retained-1"})

            # Explicit session_resume adopts BOTH retained resources
            resumed = hub.dispatch({
                "op": "session_open",
                "args": {"agent_id": "ret-agent", "task_id": "ret-task", "resume_token": sess["resume_token"]},
            })
            self.assertEqual(resumed["adopted_resources"], 2)
            auth2 = {"session_id": resumed["session_id"], "session_secret": resumed["session_secret"]}

            # Simulate browser manager NOT running during close -> STILL retained fail-closed!
            browser.is_running = False
            managed.is_running = False
            second_close = hub.dispatch({**auth2, "op": "session_close", "request_key": "close-offline-002"})
            self.assertFalse(second_close["cleanup_verified"])
            self.assertEqual(second_close["resources_retained"], 2)
            self.assertEqual({e["code"] for e in second_close["errors"]}, {"BROWSER_MANAGER_NOT_RUNNING", "MANAGED_BROWSER_NOT_RUNNING"})

            # Resume again, bring managers back with confirmed cleanup -> clean release!
            resumed2 = hub.dispatch({
                "op": "session_open",
                "args": {"agent_id": "ret-agent", "task_id": "ret-task", "resume_token": resumed["resume_token"]},
            })
            self.assertEqual(resumed2["adopted_resources"], 2)
            browser.is_running = True
            browser.confirm_close = True
            managed.is_running = True
            managed.confirm_close = True
            final_close = hub.dispatch({
                "session_id": resumed2["session_id"],
                "session_secret": resumed2["session_secret"],
                "op": "session_close",
                "request_key": "close-verified-003",
            })
            self.assertTrue(final_close["cleanup_verified"])
            self.assertEqual(final_close["resources_retained"], 0)
            self.assertEqual(final_close["preserved_profiles"], ["agent-prof-1"])
            self.assertEqual(hub.store.resources(), [])
        finally:
            hub.shutdown()
            hub.store.close()

    def test_hub_shutdown_preserves_tabs_when_sqlite_holds_browser_tabs(self) -> None:
        class _TrackingBrowser:
            def __init__(self) -> None:
                self.stop_close_tabs: list[bool] = []

            def running(self) -> bool:
                return True

            def call(self, op: str, args: dict | None = None) -> dict:
                if op == "tab_open":
                    return {"tab_id": "tab-live-1", "url": args["url"]}
                if op == "tab_list":
                    return {"tabs": [{"tab_id": "tab-live-1"}]}
                if op == "tab_close_owner":
                    return {"closed": 1, "unconfirmed": []}
                return {"ok": True}

            def stop(self, *, close_tabs: bool = True) -> None:
                self.stop_close_tabs.append(close_tabs)

        # Case 1: active browser_tab held in SQLite -> shutdown must pass close_tabs=False
        b1 = _TrackingBrowser()
        h1 = Hub(self.root / "sd-held", browser=b1)
        try:
            s1 = h1.dispatch({"op": "session_open", "args": {"agent_id": "a", "task_id": "t"}})
            h1.dispatch({
                "op": "browser",
                "args": {"command": "open", "url": "https://example.invalid/"},
                "session_id": s1["session_id"],
                "session_secret": s1["session_secret"],
                "request_key": "open-sd-0001",
            })
            h1.shutdown()
            self.assertEqual(b1.stop_close_tabs, [False])
        finally:
            h1.store.close()

        # Case 2: no browser_tab held -> shutdown passes close_tabs=True
        b2 = _TrackingBrowser()
        h2 = Hub(self.root / "sd-empty", browser=b2)
        try:
            h2.shutdown()
            self.assertEqual(b2.stop_close_tabs, [True])
        finally:
            h2.store.close()

    def test_mcp_pending_crash_intent_and_unconfirmed_close_keeps_checkpoint(self) -> None:
        class _Client:
            def __init__(self, hub: Hub):
                self.hub = hub
                self.fail_once = False

            def raw(self, request: dict) -> dict:
                if self.fail_once:
                    self.fail_once = False
                    raise HubError("HUB_UNREACHABLE", retry_safe=False)
                try:
                    return {"ok": True, "result": self.hub.dispatch(request)}
                except HubError as exc:
                    return {"ok": False, "error_code": exc.code, "message": exc.message, "details": exc.details}

        class _OfflineBrowser:
            def running(self) -> bool:
                return False

            def call(self, op: str, args: dict | None = None) -> dict:
                if op == "tab_open":
                    return {"tab_id": "tab-stuck", "url": args["url"]}
                return {"ok": True}

        hub = Hub(self.root / "mcp-crash", browser=_OfflineBrowser())
        client = _Client(hub)
        adapter = Adapter(self.root / "mcp-crash", "mcp-agent", client=client)
        try:
            # 1. Interrupted session_open leaves _mcp_pending -> fail closed MCP_SESSION_OUTCOME_UNKNOWN
            client.fail_once = True
            with self.assertRaises(HubError) as e1:
                adapter.call({"op": "session_open", "task_id": "interrupted-task"})
            self.assertEqual(e1.exception.code, "HUB_UNREACHABLE")
            with self.assertRaises(HubError) as e2:
                adapter.call({"op": "session_open", "task_id": "interrupted-task"})
            self.assertEqual(e2.exception.code, "MCP_SESSION_OUTCOME_UNKNOWN")
            self.assertFalse(e2.exception.details["automatic_replay"])

            # 2. Unconfirmed session_close MUST preserve checkpoint so explicit resume remains possible
            adapter.call({"op": "session_open", "task_id": "retained-task"})
            adapter.call({
                "op": "browser",
                "task_id": "retained-task",
                "request_key": "open-stuck-0001",
                "args": {"command": "open", "url": "https://example.invalid/"},
            })
            res = adapter.call({"op": "session_close", "task_id": "retained-task", "request_key": "close-stuck-0001"})
            self.assertFalse(res["cleanup_verified"])
            self.assertEqual(res["resources_retained"], 1)
            cp = adapter.checkpoints / (hashlib.sha256(b"retained-task").hexdigest() + ".json")
            self.assertTrue(cp.is_file(), "checkpoint must be preserved when resources_retained > 0")
        finally:
            adapter.close()
            hub.shutdown()
            hub.store.close()

    def test_store_shared_require_owned_mode_upgrade_and_policy_hardening(self) -> None:
        store = HubStore(self.root / "store.db")
        try:
            s1 = store.open_session("a", "t1")
            s2 = store.open_session("b", "t2")
            # Shared ownership: BOTH holders pass require_owned
            r1 = store.claim(s1, "custom", "shared-k", mode="shared")
            r2 = store.claim(s2, "custom", "shared-k", mode="shared")
            self.assertEqual(store.require_owned(s1, "custom", "shared-k")["resource_id"], r1["resource_id"])
            self.assertEqual(store.require_owned(s2, "custom", "shared-k")["resource_id"], r2["resource_id"])
            store.release(s2, resource_id=r2["resource_id"])
            # Mode upgrade updates existing row in place without duplicate
            upgraded = store.claim(s1, "custom", "shared-k", mode="exclusive")
            self.assertEqual(upgraded["resource_id"], r1["resource_id"])
            self.assertEqual(upgraded["mode"], "exclusive")
            self.assertEqual(len(store.resources(session_id=s1["session_id"])), 1)
            # Permission request reopens after approval and is isolated per task_id
            p1 = store.record_permission_request(s1, "app_launch", {"app": "notepad.exe"}, "app_open")
            s1_other = store.open_session("a", "t-other")
            p_other = store.record_permission_request(s1_other, "app_launch", {"app": "notepad.exe"}, "app_open")
            self.assertNotEqual(p1["request_id"], p_other["request_id"])
            store.resolve_permission_request(p1["request_id"], "approved")
            reopened = store.record_permission_request(s1, "app_launch", {"app": "notepad.exe"}, "app_open")
            self.assertEqual(reopened["request_id"], p1["request_id"])
            self.assertFalse(reopened["repeated"])
        finally:
            store.close()

        # Policy validation: empty agents, non-finite TTL, relative path all fail closed
        pfile = self.root / "policy.json"
        pol = Policy(pfile)
        pfile.write_text(json.dumps({
            "version": 1,
            "defaults": {},
            "grants": [{"grant_id": "g1", "classes": ["project_write"], "agents": [], "paths": [str(self.root)], "revoked": False}],
        }), encoding="utf-8")
        self.assertEqual(pol.decide("a", "project_write", {"path": str(self.root / "x.txt")})["reason"], "POLICY_FILE_INVALID")
        self.assertEqual(pol.describe()["classes"]["browser_own_tabs"]["default"], "ask")
        pfile.unlink()
        for bad_ttl in (float("nan"), float("inf"), -1, True):
            with self.assertRaises(PermissionError_) as err:
                pol.add_grant(["browser_script"], ttl_seconds=bad_ttl)
            self.assertEqual(err.exception.code, "GRANT_TTL_INVALID")
        with self.assertRaises(PermissionError_):
            pol.add_grant(["project_write"], paths=["relative/path"])
        self.assertEqual(pol.describe()["classes"]["terminal_execute"]["grant_must_name"], ["paths", "apps"])

    def test_protocol_hardening_falsy_args_secret_dedupe_terminal_recovery_and_cancel_retention(self) -> None:
        class _Browser:
            def __init__(self) -> None:
                self.is_running = False
                self.calls: list[tuple[str, dict | None]] = []

            def running(self) -> bool:
                return self.is_running

            def call(self, op: str, args: dict | None = None) -> dict:
                self.calls.append((op, args))
                if op == "tab_open":
                    return {"tab_id": "tab-1", "url": args["url"]}
                if op == "tab_restore":
                    return {"tab_id": "tab-1", "url": "https://after.invalid/", "reattached": True}
                return {"ok": True}

        browser = _Browser()
        hub = Hub(self.root / "harden", browser=browser)
        try:
            sess = hub.dispatch({"op": "session_open", "args": {"agent_id": "h", "task_id": "t"}})
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}

            # Falsy non-dict args & empty file key rejected
            for bad in ([], "", 0, False):
                with self.assertRaises(HubError) as ctx:
                    hub.dispatch({"op": "capabilities", "args": bad})
                self.assertEqual(ctx.exception.code, "ARGS_INVALID")
            for bad_key in ("", "   ", None, 123):
                with self.assertRaises(HubError) as ctx:
                    hub.dispatch({**auth, "op": "resource_claim", "args": {"kind": "file", "key": bad_key}, "request_key": "bad-file-key-01"})
                self.assertEqual(ctx.exception.code, "RESOURCE_KEY_INVALID")

            # browser restore in-place updates stored url for expected_host check
            hub.dispatch({**auth, "op": "browser", "args": {"command": "open", "url": "https://before.invalid/"}, "request_key": "open-b-0001"})
            hub.dispatch({**auth, "op": "browser", "args": {"command": "restore", "tab_id": "tab-1"}, "request_key": "rest-b-0001"})
            hub.dispatch({**auth, "op": "browser", "args": {"command": "act", "tab_id": "tab-1", "action": "click"}, "request_key": "act-b-0001"})
            self.assertEqual(browser.calls[-1][1]["expected_host"], "after.invalid")

            # secret_use journals before permission check and dedupes even after grant revoke
            s_args = {"name": "demo", "use": "http", "request": {"url": "https://api.invalid/", "headers": {"Authorization": "{{secret}}"}}}
            with self.assertRaises(HubError) as rk_err:
                hub.dispatch({**auth, "op": "secret_use", "args": s_args})
            self.assertEqual(rk_err.exception.code, "REQUEST_KEY_REQUIRED")
            self.assertEqual(hub.store.permission_requests(), [])
            grant = hub.policy.add_grant(["secret_use"], agents=["h"], secrets=["demo"], hosts=["api.invalid"])
            with patch.object(hub.vault, "use_http", return_value={"status": 200, "secret_value_returned": False}) as mock_http:
                r1 = hub.dispatch({**auth, "op": "secret_use", "args": s_args, "request_key": "sec-dedupe-0001"})
                hub.policy.revoke(grant["grant_id"])
                r2 = hub.dispatch({**auth, "op": "secret_use", "args": s_args, "request_key": "sec-dedupe-0001"})
                mock_http.assert_called_once()
            self.assertFalse(r1["deduplicated"])
            self.assertTrue(r2["deduplicated"])

            # task_cancel retains unconfirmed browser_tab fail-closed when browser manager is not running
            cancel = hub.dispatch({**auth, "op": "task_cancel", "request_key": "cancel-ret-0001"})
            self.assertTrue(cancel["closed"])
            self.assertFalse(cancel["cleanup_verified"])
            self.assertEqual(cancel["resources_retained"], 1)
            self.assertEqual(len(hub.store.resources(session_id=sess["session_id"])), 1)
        finally:
            hub.shutdown()
            hub.store.close()


if __name__ == "__main__":
    unittest.main()
