"""P0 verification tests for Playwright ABI, retry non-doubling, ownership/TTL,
graceful teardown, Bridge shutdown wiring, and coreBundle.js integrity guard.

Never touches owner Chrome, live production dirs, live ports, or real tokens.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
BRIDGE_DIR = REPO_ROOT / "runtime" / "bridge-v3"
sys.path.insert(0, str(BRIDGE_DIR))

import cua_bridge_v3  # noqa: E402
from cua_bridge_v3 import CuaBridgeControlPlane, CuaBridgeError  # noqa: E402
import cua_playwright_integrity as pw_integrity  # noqa: E402
from cua_playwright_integrity import (  # noqa: E402
    PlaywrightIntegrityError,
    assert_playwright_integrity,
    scan_core_bundle,
    scan_playwright_root,
)
from cua_sidecar_supervisor import JsonLineSidecarSupervisor  # noqa: E402
import ff_win_v3_agent as agent  # noqa: E402
import owner_chrome_session  # noqa: E402

def _discover_playwright_root() -> Path | None:
    for raw in (
        os.environ.get("FF_TEST_PW165_ROOT"),
        os.environ.get("FF_PLAYWRIGHT_ROOT"),
        str(BRIDGE_DIR),
    ):
        if not raw:
            continue
        candidate = Path(raw)
        if (candidate / "node_modules" / "playwright-core" / "lib" / "coreBundle.js").is_file():
            return candidate
    return None


PW165_ROOT = _discover_playwright_root()


class _FakeBrowserSupervisor:
    def __init__(self, *responses: dict):
        self.responses = list(responses)
        self.calls: list[tuple[str, dict]] = []
        self.restarts = 0
        self.stops = 0
        self._seq = 0

    def request(self, op: str, payload: dict):
        self.calls.append((op, dict(payload)))
        if op == "identity":
            return {"ok": True, "result": {"url": "https://example.invalid/"}}
        if op == "close":
            return {"ok": True, "result": {"ok": True, "cleanup": {"detached": True, "owned_pages_closed": 1}}}
        if self.responses:
            return self.responses.pop(0)
        self._seq += 1
        transport = "extension" if payload.get("ownerTransport") == "extension" else "isolated"
        return {
            "ok": True,
            "result": {
                "surface_id": f"surface-{transport}-{self._seq}",
                "route": "BROWSER_PLAYWRIGHT",
                "capabilities": {
                    "owner_browser": transport == "extension",
                    "isolated_profile": transport != "extension",
                    "owner_transport": "extension" if transport == "extension" else None,
                    "background": True,
                },
            },
        }

    def restart(self):
        self.restarts += 1

    def stop(self):
        self.stops += 1

    def health(self):
        return {"name": "fake", "running": True}


def _make_plane(supervisor_by_transport: dict[str, _FakeBrowserSupervisor], **kwargs) -> CuaBridgeControlPlane:
    plane = CuaBridgeControlPlane.__new__(CuaBridgeControlPlane)
    plane._surfaces = {}
    plane._browser = dict(supervisor_by_transport)
    plane._native = {}
    plane._vision = None
    plane._physical = None
    plane._browser_profiles = None
    plane._browser_idle_ttl_s = kwargs.get("browser_idle_ttl_s", cua_bridge_v3.DEFAULT_BROWSER_SURFACE_IDLE_TTL_S)
    plane._require_explicit_owner_chrome = kwargs.get("require_explicit_owner_chrome", False)
    plane._resources = SimpleNamespace(
        write=lambda _key: contextlib.nullcontext(),
        read=lambda _key: contextlib.nullcontext(),
        write_many=lambda _keys: contextlib.nullcontext(),
        read_many=lambda _keys: contextlib.nullcontext(),
    )
    plane._browser_supervisor = lambda transport: supervisor_by_transport[transport]
    return plane


class P0BridgeOwnershipRetryTests(unittest.TestCase):
    def test_no_blind_retry_on_extension_attach_failure(self):
        ext = _FakeBrowserSupervisor({"ok": False, "error_code": "OWNER_BROWSER_EXTENSION_ATTACH_FAILED"})
        plane = _make_plane({"extension": ext})
        with self.assertRaises(CuaBridgeError) as ctx:
            plane._attach({"surface_kind": "browser", "transport": "extension"})
        self.assertEqual(ctx.exception.code, "OWNER_CHROME_ATTACH_FAILED")
        self.assertEqual(ctx.exception.details["retry"], "disabled_no_blind_retry")
        self.assertFalse(ctx.exception.details["retry_safe"])
        self.assertFalse(ctx.exception.details["isolated_fallback"])
        self.assertTrue(ctx.exception.details["tab_spawned_possible"])
        self.assertEqual(ext.restarts, 0)
        self.assertEqual([op for op, _ in ext.calls], ["attach"])

    def test_default_transport_is_isolated_and_hub_mode_refuses_owner_chrome(self):
        iso = _FakeBrowserSupervisor()
        ext = _FakeBrowserSupervisor()
        plane = _make_plane({"isolated": iso, "extension": ext})

        # Omitting transport MUST pick isolated hidden browser, never direct owner Chrome.
        attached = plane._attach({"surface_kind": "browser", "agent_id": "a1", "task_id": "t1"})
        self.assertTrue(attached["surface_id"].startswith("surface-isolated-"))
        self.assertEqual(len(iso.calls), 1)
        self.assertEqual(len(ext.calls), 0)

        # Hub/hidden route expectation rejects direct owner Chrome extension attach fail-closed.
        for extra in (
            {"prefer_hub": True},
            {"hidden_only": True},
            {"route_mode": "hub"},
            {"browser_mode": "hidden"},
            {"owner_chrome_explicit": False},
        ):
            with self.assertRaises(CuaBridgeError) as ctx:
                plane._attach({"surface_kind": "browser", "transport": "extension", **extra})
            self.assertEqual(ctx.exception.code, "OWNER_CHROME_EXPLICIT_ROUTE_REQUIRED")
            self.assertFalse(ctx.exception.details["owner_chrome_fallback"])
        self.assertEqual(len(ext.calls), 0)

        # require_explicit_owner_chrome=True demands explicit owner_chrome_explicit=True
        strict_plane = _make_plane({"extension": ext}, require_explicit_owner_chrome=True)
        with self.assertRaises(CuaBridgeError) as ctx2:
            strict_plane._attach({"surface_kind": "browser", "transport": "extension"})
        self.assertEqual(ctx2.exception.code, "OWNER_CHROME_EXPLICIT_ROUTE_REQUIRED")
        ok_res = strict_plane._attach({
            "surface_kind": "browser",
            "transport": "extension",
            "owner_chrome_explicit": True,
            "agent_id": "a1",
            "task_id": "t1",
        })
        self.assertTrue(ok_res["surface_id"].startswith("surface-extension-"))
        self.assertEqual(ext.calls[-1][1].get("background"), True)

    def test_surface_ownership_prevents_cross_agent_sharing_and_enforces_ttl_reaping(self):
        ext = _FakeBrowserSupervisor()
        plane = _make_plane({"extension": ext}, browser_idle_ttl_s=0.1)

        # Agent A / Task 1 attaches
        s_a1 = plane._attach({
            "surface_kind": "browser", "transport": "extension",
            "agent_id": "agent-a", "task_id": "task-1",
        })
        self.assertFalse(s_a1["reused"])
        meta = plane._surfaces[s_a1["surface_id"]]
        self.assertEqual(meta["agent_id"], "agent-a")
        self.assertEqual(meta["task_id"], "task-1")
        self.assertAlmostEqual(meta["idle_ttl_s"], 0.1)
        self.assertIsInstance(meta["created_at"], float)
        self.assertIsInstance(meta["last_used_at"], float)

        # Same agent + same task reuses its own surface
        reused = plane._attach({
            "surface_kind": "browser", "transport": "extension",
            "agent_id": "agent-a", "task_id": "task-1",
        })
        self.assertTrue(reused["reused"])
        self.assertEqual(reused["surface_id"], s_a1["surface_id"])

        # Agent B with force_new_connection=False MUST NOT share Agent A's surface
        s_b1 = plane._attach({
            "surface_kind": "browser", "transport": "extension",
            "agent_id": "agent-b", "task_id": "task-1",
            "force_new_connection": False,
        })
        self.assertFalse(s_b1["reused"])
        self.assertNotEqual(s_b1["surface_id"], s_a1["surface_id"])

        # Same Agent A with different task_id MUST NOT share task-1's surface
        s_a2 = plane._attach({
            "surface_kind": "browser", "transport": "extension",
            "agent_id": "agent-a", "task_id": "task-2",
        })
        self.assertFalse(s_a2["reused"])
        self.assertNotEqual(s_a2["surface_id"], s_a1["surface_id"])

        # Cross-agent access to Agent A's surface fails closed
        with self.assertRaises(CuaBridgeError) as owned_exc:
            plane._surface({"surface_id": s_a1["surface_id"], "agent_id": "agent-b", "task_id": "task-1"})
        self.assertEqual(owned_exc.exception.code, "SURFACE_NOT_OWNED")

        # Idle TTL reaper closes expired surfaces only
        plane._surfaces[s_a1["surface_id"]]["last_used_at"] -= 1.0
        reaped = plane.reap_idle_browser_surfaces()
        self.assertEqual(reaped, [s_a1["surface_id"]])
        self.assertNotIn(s_a1["surface_id"], plane._surfaces)
        self.assertIn(s_b1["surface_id"], plane._surfaces)
        self.assertTrue(any(op == "close" and args.get("surface_id") == s_a1["surface_id"] for op, args in ext.calls))

    def test_task_preflight_recommends_shared_hub_and_hidden_browser(self):
        class _PreflightPlane(CuaBridgeControlPlane):
            def __init__(self):
                pass

            def dispatch(self, args):
                if args["command"] == "programmatic_plan":
                    return {"candidates": [], "task_compatibility": "unknown", "preferred_task_route": None}
                raise AssertionError(f"unexpected dispatch {args}")

        plane = _PreflightPlane()
        res = plane._task_preflight({"app": "Chrome", "task": "open dashboard"})
        self.assertEqual(res["browser_routing"]["recommended_route"], "shared_hub_hidden_browser")
        self.assertFalse(res["browser_routing"]["direct_owner_chrome_fallback_allowed"])
        self.assertTrue(res["browser_routing"]["requires_explicit_owner_chrome_opt_in"])
        self.assertEqual(res["next_step"], "use_shared_hub_or_hidden_browser_before_explicit_owner_chrome")


class P0GracefulTeardownAndShutdownTests(unittest.TestCase):
    def test_sidecar_supervisor_closes_stdin_and_waits_grace_before_kill(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "eof-cleanup-ran.txt"
            child_script = Path(tmp) / "graceful_child.py"
            child_script.write_text(
                "import json, pathlib, sys, time\n"
                "marker = pathlib.Path(sys.argv[1])\n"
                "try:\n"
                "    for line in sys.stdin:\n"
                "        req = json.loads(line)\n"
                "        sys.stdout.write(json.dumps({'id': req['id'], 'ok': True, 'result': {'pong': True}}) + '\\n')\n"
                "        sys.stdout.flush()\n"
                "finally:\n"
                "    time.sleep(0.15)\n"
                "    marker.write_text('CLEANUP_VIA_STDIN_EOF', encoding='utf-8')\n",
                encoding="utf-8",
            )
            sup = JsonLineSidecarSupervisor(
                "graceful-test",
                [sys.executable, str(child_script), str(marker)],
                shutdown_grace_seconds=2.5,
            )
            try:
                reply = sup.request("ping", {})
                self.assertTrue(reply["ok"])
                self.assertFalse(marker.exists())
                sup.stop()
                self.assertTrue(marker.is_file(), "child finally block MUST run on stdin EOF before job/taskkill")
                self.assertEqual(marker.read_text(encoding="utf-8"), "CLEANUP_VIA_STDIN_EOF")
            finally:
                sup.stop()

    def test_sidecar_supervisor_kills_stubborn_child_after_bounded_grace(self):
        with tempfile.TemporaryDirectory() as tmp:
            child_script = Path(tmp) / "stubborn_child.py"
            child_script.write_text(
                "import json, sys, time\n"
                "for line in sys.stdin:\n"
                "    req = json.loads(line)\n"
                "    sys.stdout.write(json.dumps({'id': req['id'], 'ok': True, 'result': {}}) + '\\n')\n"
                "    sys.stdout.flush()\n"
                "    break\n"
                "time.sleep(30)\n",
                encoding="utf-8",
            )
            sup = JsonLineSidecarSupervisor(
                "stubborn-test",
                [sys.executable, str(child_script)],
                shutdown_grace_seconds=0.3,
            )
            sup.request("ping", {})
            proc = sup.process
            assert proc is not None
            t0 = time.monotonic()
            sup.stop()
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 4.0)
            self.assertIsNotNone(proc.poll(), "stubborn child must be killed after bounded grace")

    def test_bridge_shutdown_and_serve_finally_close_cua_control_plane(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            v3_root = tmp_root / "bridge-v3"
            v3_root.mkdir(parents=True, exist_ok=True)
            secret = "test-shutdown-secret-" + ("x" * 24)
            (v3_root / "secret").write_text(secret, encoding="ascii")

            close_events: list[str] = []

            class _TrackedPlane:
                def close(self):
                    close_events.append("closed")

            tracked = _TrackedPlane()

            def _hook():
                tracked.close()

            _hook._plane_id = id(tracked)  # type: ignore[attr-defined]
            fake_main = SimpleNamespace(_CUA_CONTROL_PLANE=tracked)

            # Use isolated paths and synthetic secret so live user state/PID/secrets are NEVER touched.
            with mock.patch.object(agent, "BRIDGE_ROOT", tmp_root), \
                 mock.patch.object(agent, "V3_ROOT", v3_root), \
                 mock.patch.object(agent, "SECRET_PATH", v3_root / "secret"), \
                 mock.patch.object(agent, "CONFIG_PATH", v3_root / "config.json"), \
                 mock.patch.object(agent, "AUDIT_PATH", v3_root / "audit.jsonl"), \
                 mock.patch.object(agent, "PID_PATH", v3_root / "agent.pid"), \
                 mock.patch.object(agent.STATE, "secret", secret), \
                 mock.patch.dict(sys.modules, {"ff_win_v3_main": fake_main}):
                agent.register_shutdown_hook(_hook)
                server_holder: list[int] = []
                err_holder: list[BaseException] = []

                def run_server():
                    try:
                        # Capture bound ephemeral port via STATE.server
                        agent.serve("127.0.0.1", 0)
                    except BaseException as exc:
                        err_holder.append(exc)

                thread = threading.Thread(target=run_server, daemon=True)
                thread.start()
                try:
                    deadline = time.monotonic() + 5.0
                    while time.monotonic() < deadline:
                        srv = agent.STATE.server
                        if srv is not None and srv.server_port:
                            server_holder.append(srv.server_port)
                            break
                        time.sleep(0.05)
                    self.assertTrue(server_holder, "ephemeral bridge server failed to bind")
                    port = server_holder[0]
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{port}/shutdown",
                        data=b"{}",
                        headers={"Content-Type": "application/json", "X-FF3-Key": secret},
                        method="POST",
                    )
                    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                    with opener.open(req, timeout=5) as resp:
                        body = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(body["ok"])
                    # /shutdown closes runtime resources BEFORE responding
                    self.assertGreaterEqual(len(close_events), 1)
                    thread.join(timeout=5.0)
                    self.assertFalse(thread.is_alive())
                    self.assertEqual(err_holder, [])
                finally:
                    with agent._SHUTDOWN_HOOKS_LOCK:
                        if _hook in agent._SHUTDOWN_HOOKS:
                            agent._SHUTDOWN_HOOKS.remove(_hook)
                    if agent.STATE.server is not None:
                        try:
                            agent.STATE.server.shutdown()
                        except Exception:
                            pass
                        agent.STATE.server = None

    def test_real_node_sidecar_eof_graceful_cleanup_with_isolated_headless_browser(self):
        node = shutil.which("node.exe") or shutil.which("node")
        if not node or PW165_ROOT is None or not PW165_ROOT.is_dir():
            self.skipTest("node or pinned Playwright root unavailable")
        chrome_candidates = [
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Google" / "Chrome" / "Application" / "chrome.exe",
            Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        ]
        if not any(p.is_file() for p in chrome_candidates):
            self.skipTest("no Chromium/Chrome/Edge executable available")

        with tempfile.TemporaryDirectory() as tmp:
            profile_root = Path(tmp) / "isolated-profiles"
            profile_root.mkdir()
            env = {
                "FF_PLAYWRIGHT_ROOT": str(PW165_ROOT),
                "FF_ISOLATED_BROWSER_PROFILE_ROOT": str(profile_root),
            }
            sup = JsonLineSidecarSupervisor(
                "real-browser-eof-test",
                [node, str(BRIDGE_DIR / "cua_browser_rpc.mjs"), "--isolated-only", "--playwright-root", str(PW165_ROOT)],
                cwd=BRIDGE_DIR,
                env=env,
                timeout_seconds=30.0,
                shutdown_grace_seconds=5.0,
                multiplex=True,
            )
            try:
                attached = sup.request("attach", {"headless": True})
                self.assertTrue(attached["ok"], attached)
                sid = attached["result"]["surface_id"]
                nav = sup.request("navigate", {"surface_id": sid, "url": "data:text/html,<title>EOFTest</title><h1>OK</h1>"})
                self.assertTrue(nav["ok"], nav)
                self.assertEqual(len(list(profile_root.iterdir())), 1)

                # Stop supervisor WITHOUT calling 'close' RPC first: stdin EOF must trigger
                # cua_browser_rpc.mjs finally cleanup -> closes browser & deletes temp profile!
                sup.stop()
                self.assertEqual(
                    list(profile_root.iterdir()),
                    [],
                    "graceful stdin-EOF teardown must close isolated browser and remove temporary profile",
                )
            finally:
                sup.stop()


class P0PlaywrightIntegrityTests(unittest.TestCase):
    def test_clean_pw165_passes_api_and_cli(self):
        if PW165_ROOT is None or not PW165_ROOT.is_dir():
            self.skipTest("pinned Playwright root not present")
        result = assert_playwright_integrity(PW165_ROOT)
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "clean")
        self.assertIsNone(result["error_code"])
        self.assertEqual(result["playwright_core_version"], "1.65.1")
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["findings"], [])
        self.assertEqual(len(result["sha256"]), 64)

        proc = subprocess.run(
            [sys.executable, str(BRIDGE_DIR / "cua_playwright_integrity.py"), "--playwright-root", str(PW165_ROOT), "--json"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        parsed = json.loads(proc.stdout)
        self.assertTrue(parsed["ok"])
        self.assertEqual(parsed["status"], "clean")

    def test_tampered_core_bundle_caught_fail_closed_api_cli_and_owner_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "fake-pw"
            bundle = root / "node_modules" / "playwright-core" / "lib" / "coreBundle.js"
            bundle.parent.mkdir(parents=True, exist_ok=True)
            (root / "node_modules" / "playwright-core" / "package.json").write_text(
                json.dumps({"name": "playwright-core", "version": "1.65.1"}),
                encoding="utf-8",
            )
            secret_marker = "SYNTHETIC_SECRET_TOKEN_SHOULD_NOT_ECHO"
            bundle.write_text(
                "function ok() { return 1; }\n"
                f"// debug patch: {secret_marker}\n"
                "require('fs').writeFileSync('C:/Users/demo/ChatGPT_Conversation_Audit/pw_connect_url.txt', connectUrl);\n",
                encoding="utf-8",
            )

            res = scan_core_bundle(bundle)
            self.assertFalse(res["ok"])
            self.assertEqual(res["status"], "tampered")
            self.assertEqual(res["error_code"], "PLAYWRIGHT_CORE_BUNDLE_TAMPERED")
            rules = {item["rule"] for item in res["findings"]}
            self.assertIn("FORBIDDEN_DEBUG_ARTIFACT_NAME", rules)
            self.assertIn("FORBIDDEN_AUDIT_PATH_LITERAL", rules)
            self.assertIn("HARDCODED_WINDOWS_USER_PATH", rules)
            self.assertIn("RAW_REQUIRE_FS_WRITE", rules)
            self.assertIn("SUSPICIOUS_FS_WRITE_CONNECT_OR_TOKEN", rules)
            self.assertNotIn(secret_marker, json.dumps(res), "scanner must never echo raw matched content/secrets")

            with self.assertRaises(PlaywrightIntegrityError) as exc:
                assert_playwright_integrity(root)
            self.assertEqual(exc.exception.code, "PLAYWRIGHT_CORE_BUNDLE_TAMPERED")

            proc = subprocess.run(
                [sys.executable, str(BRIDGE_DIR / "cua_playwright_integrity.py"), "--playwright-root", str(root)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            self.assertEqual(proc.returncode, 2)
            cli_data = json.loads(proc.stdout)
            self.assertFalse(cli_data["ok"])
            self.assertEqual(cli_data["error_code"], "PLAYWRIGHT_CORE_BUNDLE_TAMPERED")

            # Missing root fails closed with exit 3 unless --allow-missing is passed
            empty_root = Path(tmp) / "empty-pw"
            empty_root.mkdir()
            missing = scan_playwright_root(empty_root, require_present=True)
            self.assertFalse(missing["ok"])
            self.assertEqual(missing["error_code"], "PLAYWRIGHT_CORE_BUNDLE_MISSING")
            allowed = scan_playwright_root(empty_root, require_present=False)
            self.assertTrue(allowed["ok"])
            self.assertEqual(allowed["status"], "not_installed")

            # OwnerChromeSession fails closed before spawning PowerShell when tampered
            fake_rpc = root / "cua_browser_extension_rpc.ps1"
            fake_rpc.write_text("# stub\n", encoding="utf-8")
            with mock.patch.object(owner_chrome_session, "BRIDGE_ROOT", root), \
                 mock.patch.object(owner_chrome_session, "RPC_SCRIPT", fake_rpc), \
                 mock.patch.object(owner_chrome_session.subprocess, "Popen") as popen_mock:
                with self.assertRaises(owner_chrome_session.OwnerChromeError) as octx:
                    owner_chrome_session.OwnerChromeSession().__enter__()
                self.assertEqual(str(octx.exception), "PLAYWRIGHT_CORE_BUNDLE_TAMPERED")
                popen_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
