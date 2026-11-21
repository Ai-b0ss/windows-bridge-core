"""P0 Track B: Hidden Chrome, Persistent Isolated Profiles & Route Separation Tests.

Includes deterministic unit/contract tests plus real isolated Windows live tests
against an ephemeral 127.0.0.1 HTTP server (zero external network, zero owner
Chrome User Data access).
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as wt
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "runtime" / "bridge-v3"
sys.path.insert(0, str(RUNTIME))

import cua_browser_profiles as profiles  # noqa: E402
import cua_hidden_chrome as hidden_chrome  # noqa: E402
import cua_private_browser as private_browser  # noqa: E402
import ff_browser_routes as routes_mod  # noqa: E402
from ff_win_process_identity import process_creation_token, process_identity_matches  # noqa: E402


# ---- Helpers for real isolated Windows live verification ---------------------

def _has_interactive_desktop() -> bool:
    if os.name != "nt":
        return False
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.OpenInputDesktop.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        user32.OpenInputDesktop.restype = wt.HANDLE
        user32.CloseDesktop.argtypes = [wt.HANDLE]
        handle = user32.OpenInputDesktop(0, False, 1)
        if not handle:
            return False
        user32.CloseDesktop(handle)
        return True
    except Exception:
        return False


def _discover_playwright_root() -> Path | None:
    candidates: list[Path] = []
    env_root = os.environ.get("FF_PLAYWRIGHT_ROOT")
    if env_root:
        candidates.append(Path(env_root))
    candidates.append(RUNTIME)
    for cand in candidates:
        if (cand / "node_modules" / "playwright").is_dir():
            return cand
    return None


def _snapshot_owner_desktop() -> dict:
    """Read-only snapshot of owner's visible Chrome HWNDs and foreground window."""
    if os.name != "nt":
        return {"visible_chrome_hwnds": [], "foreground_hwnd": None}
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.EnumWindows.argtypes = [ctypes.c_void_p, wt.LPARAM]
    user32.EnumWindows.restype = wt.BOOL
    user32.IsWindowVisible.argtypes = [wt.HWND]
    user32.IsWindowVisible.restype = wt.BOOL
    user32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
    user32.GetWindowThreadProcessId.restype = wt.DWORD
    user32.GetForegroundWindow.restype = wt.HWND

    chrome_windows: list[dict] = []
    cb_type = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

    @cb_type
    def callback(hwnd, _):
        if user32.IsWindowVisible(hwnd):
            cls = ctypes.create_unicode_buffer(128)
            user32.GetClassNameW(hwnd, cls, len(cls))
            if cls.value == "Chrome_WidgetWin_1":
                pid = wt.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                chrome_windows.append({"hwnd": int(hwnd), "pid": int(pid.value)})
        return True

    user32.EnumWindows(callback, 0)
    fg = int(user32.GetForegroundWindow() or 0)
    pt = wt.POINT()
    cursor = (int(pt.x), int(pt.y)) if user32.GetCursorPos(ctypes.byref(pt)) else None
    return {
        "visible_chrome_hwnds": sorted(item["hwnd"] for item in chrome_windows),
        "visible_chrome_windows": chrome_windows,
        "foreground_hwnd": fg,
        "cursor_pos": list(cursor) if cursor is not None else None,
    }


def _pid_alive(pid: int | None) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    if os.name == "nt":
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        k32.OpenProcess.restype = wt.HANDLE
        k32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
        k32.GetExitCodeProcess.restype = wt.BOOL
        k32.CloseHandle.argtypes = [wt.HANDLE]
        handle = k32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = wt.DWORD()
            return bool(k32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _start_local_fixture_server() -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    """Start an ephemeral 127.0.0.1 HTTP server for synthetic cookie/localStorage persistence tests."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_GET(self):
            if self.path == "/api/echo-cookie":
                cookie_header = self.headers.get("Cookie", "")
                self.server.observed_cookie_headers.append(cookie_header)
                body = json.dumps({"cookie_header": cookie_header}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return

            cookie_header = self.headers.get("Cookie", "")
            self.server.observed_cookie_headers.append(cookie_header)
            cookie_json = json.dumps(cookie_header)
            html = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>P0 Hidden Browser Fixture</title></head>
<body>
  <h1>P0 Hidden Browser Persistence Stand</h1>
  <label for="note-input">Synthetic Note</label>
  <input id="note-input" name="note" type="text" value="" />
  <button id="save-btn" type="button">Save State</button>
  <div id="result-box">IDLE</div>
  <pre id="persisted-box"></pre>
  <script>
    const serverCookie = {cookie_json};
    function renderPersisted() {{
      const snapshot = {{
        server_cookie_header: serverCookie,
        document_cookie: document.cookie,
        ls_note: localStorage.getItem('ff_p0_synth_note'),
        ls_token: localStorage.getItem('ff_p0_synth_token'),
      }};
      document.getElementById('persisted-box').textContent = JSON.stringify(snapshot);
    }}
    renderPersisted();
    document.getElementById('save-btn').addEventListener('click', async () => {{
      const note = document.getElementById('note-input').value;
      const resp = await fetch('/api/session', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{note}}),
      }});
      const data = await resp.json();
      localStorage.setItem('ff_p0_synth_note', data.note);
      localStorage.setItem('ff_p0_synth_token', data.token);
      document.getElementById('result-box').textContent = 'SAVED:' + data.note + ':' + data.token;
      renderPersisted();
    }});
  </script>
</body>
</html>""".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)

        def do_POST(self):
            if self.path != "/api/session":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))
            note = str(payload.get("note") or "")
            token = "synth-" + secrets.token_hex(8)
            self.server.issued_tokens.append({"note": note, "token": token})
            body = json.dumps({"saved": True, "note": note, "token": token}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header(
                "Set-Cookie",
                f"ff_p0_synth_session={token}; Path=/; Max-Age=3600; SameSite=Lax",
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class _QuietHTTPServer(ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            exc = sys.exc_info()[1]
            if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
                return
            super().handle_error(request, client_address)

    server = _QuietHTTPServer(("127.0.0.1", 0), Handler)
    server.issued_tokens = []  # type: ignore[attr-defined]
    server.observed_cookie_headers = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, f"http://127.0.0.1:{server.server_port}/"


class _ManagedPlaywrightProcess:
    """Test harness controller for a real isolated ff_playwright_managed.mjs sidecar."""

    def __init__(self, state_dir: Path, playwright_root: Path, persistent_profiles_root: Path):
        self.state_dir = state_dir
        self.playwright_root = playwright_root
        self.persistent_profiles_root = persistent_profiles_root
        self.endpoint_file = state_dir / "endpoint.json"
        self.key = secrets.token_urlsafe(32)
        self.proc: subprocess.Popen | None = None
        self.port: int | None = None
        self.pid: int | None = None
        self.create_time: int | None = None

    def start(self) -> dict:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.endpoint_file.unlink(missing_ok=True)
        node = shutil.which("node")
        if not node:
            raise RuntimeError("node not found")
        argv = [
            node,
            str(RUNTIME / "ff_playwright_managed.mjs"),
            "--state-dir",
            str(self.state_dir),
            "--endpoint-file",
            str(self.endpoint_file),
            "--playwright-root",
            str(self.playwright_root),
            "--persistent-profiles-root",
            str(self.persistent_profiles_root),
        ]
        env = {**os.environ, "FF_MANAGED_PW_KEY": self.key}
        self.proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(RUNTIME),
            env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        self.pid = self.proc.pid
        self.create_time = process_creation_token(self.pid) if os.name == "nt" else None
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                err = self.proc.stderr.read().decode("utf-8", "replace") if self.proc.stderr else ""
                raise RuntimeError(f"ff_playwright_managed exited early: {err}")
            if self.endpoint_file.is_file():
                try:
                    data = json.loads(self.endpoint_file.read_text(encoding="utf-8"))
                    self.port = int(data["port"])
                    return data
                except (OSError, ValueError, KeyError):
                    pass
            time.sleep(0.05)
        raise TimeoutError("ff_playwright_managed endpoint startup timed out")

    def rpc(self, op: str, args: dict | None = None, *, timeout: float = 30.0) -> dict:
        assert self.port is not None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/rpc",
            method="POST",
            data=json.dumps({"op": op, "args": args or {}}).encode("utf-8"),
            headers={"Content-Type": "application/json", "x-ff-managed-key": self.key},
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def stop(self, *, graceful: bool = True) -> dict:
        if self.proc is None:
            return {"exited": True}
        try:
            if graceful and self.proc.poll() is None and self.port is not None:
                try:
                    self.rpc("shutdown", {}, timeout=5.0)
                except Exception:
                    pass
            if self.proc.stdin:
                try:
                    self.proc.stdin.close()
                except OSError:
                    pass
            try:
                self.proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5.0)
        finally:
            for stream in (self.proc.stdout, self.proc.stderr):
                if stream:
                    try:
                        stream.close()
                    except OSError:
                        pass
        return {"exited": self.proc.poll() is not None, "returncode": self.proc.returncode}


# ---- Part 1: Deterministic Unit & Security Contract Tests --------------------

class ProfileIsolationContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ff-p0-profile-unit-")
        self.addCleanup(self.tmp.cleanup)
        self.isolated_root = Path(self.tmp.name) / "isolated-profiles"
        self.isolated_root.mkdir()

    def test_owner_chrome_and_other_browser_profiles_rejected_fail_closed(self):
        local_app = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        roaming_app = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        forbidden_paths = [
            Path(local_app) / "Google" / "Chrome" / "User Data",
            Path(local_app) / "Google" / "Chrome" / "User Data" / "Default",
            Path(local_app) / "Google" / "Chrome" / "User Data" / "Profile 1",
            Path(local_app) / "Google" / "Chrome",
            Path(local_app),
            Path(local_app) / "Chromium" / "User Data",
            Path(local_app) / "Microsoft" / "Edge" / "User Data",
            Path(local_app) / "BraveSoftware" / "Brave-Browser" / "User Data",
            Path(roaming_app) / "Mozilla" / "Firefox",
            Path.home(),
        ]
        for bad in forbidden_paths:
            with self.subTest(bad=str(bad)):
                self.assertTrue(profiles.is_owner_browser_profile_path(bad))
                with self.assertRaises(profiles.ProfileIsolationError) as exc:
                    profiles.resolve_isolated_profile_dir(self.isolated_root, profile_dir=bad)
                self.assertEqual(exc.exception.code, "OWNER_BROWSER_PROFILE_FORBIDDEN")

    def test_path_traversal_outside_root_and_invalid_ids_rejected(self):
        for bad_id in ("", "../escape", "a/b", "a\\b", "CON", "NUL", "COM1", "LPT1", "bad id", ".hidden", "x" * 65):
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(profiles.ProfileIsolationError) as exc:
                    profiles.resolve_isolated_profile_dir(self.isolated_root, profile_id=bad_id)
                self.assertEqual(exc.exception.code, "PROFILE_ID_INVALID")

        traversal = str(self.isolated_root / "sub" / ".." / ".." / "escape")
        with self.assertRaises(profiles.ProfileIsolationError) as exc:
            profiles.resolve_isolated_profile_dir(self.isolated_root, profile_dir=traversal)
        self.assertEqual(exc.exception.code, "PROFILE_PATH_TRAVERSAL")

        outside = Path(self.tmp.name) / "outside-dir"
        outside.mkdir()
        with self.assertRaises(profiles.ProfileIsolationError) as exc:
            profiles.resolve_isolated_profile_dir(self.isolated_root, profile_dir=outside)
        self.assertEqual(exc.exception.code, "PROFILE_OUTSIDE_ISOLATED_ROOT")

        with self.assertRaises(profiles.ProfileIsolationError) as exc:
            profiles.resolve_isolated_profile_dir(self.isolated_root, profile_dir="relative/profile")
        self.assertEqual(exc.exception.code, "PROFILE_PATH_NOT_ABSOLUTE")

    def test_junction_or_symlink_inside_isolated_root_is_rejected(self):
        outside_target = Path(self.tmp.name) / "junction-target"
        outside_target.mkdir()
        link_path = self.isolated_root / "sneaky-link"
        created = False
        if os.name == "nt":
            res = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(link_path), str(outside_target)],
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            created = res.returncode == 0
        else:
            os.symlink(outside_target, link_path)
            created = True
        if not created:
            self.skipTest("Could not create test junction/symlink on this host")
        try:
            with self.assertRaises(profiles.ProfileIsolationError) as exc:
                profiles.resolve_isolated_profile_dir(self.isolated_root, profile_id="sneaky-link")
            self.assertIn(exc.exception.code, {"ISOLATED_PROFILE_LINK_FORBIDDEN", "OWNER_BROWSER_PROFILE_FORBIDDEN"})
        finally:
            if link_path.exists() or link_path.is_symlink():
                if os.name == "nt":
                    subprocess.run(["cmd", "/c", "rmdir", str(link_path)], capture_output=True)
                else:
                    link_path.unlink(missing_ok=True)

    def test_persistent_profile_lease_preserve_relaunch_and_stale_reclaim(self):
        lease1 = profiles.PersistentBrowserProfile(self.isolated_root, profile_id="agent-persist-1")
        self.assertTrue((lease1.path / "owner.json").is_file())
        lease1.chrome_profile_path.mkdir(parents=True, exist_ok=True)
        marker = lease1.chrome_profile_path / "synthetic-state.txt"
        marker.write_text("persisted-marker-v1", encoding="utf-8")

        # Second concurrent open of the same persistent profile must fail closed.
        with self.assertRaises(profiles.ProfileIsolationError) as conflict:
            profiles.PersistentBrowserProfile(self.isolated_root, profile_id="agent-persist-1")
        self.assertEqual(conflict.exception.code, "PERSISTENT_PROFILE_IN_USE")

        # Closing releases owner lease while preserving chrome-profile contents.
        closed = lease1.close()
        self.assertTrue(closed["released"])
        self.assertTrue(closed["preserved"])
        self.assertFalse((lease1.path / "owner.json").exists())
        self.assertTrue(marker.is_file())

        # Re-open cleanly preserves data.
        lease2 = profiles.PersistentBrowserProfile(self.isolated_root, profile_id="agent-persist-1")
        self.assertEqual(marker.read_text(encoding="utf-8"), "persisted-marker-v1")
        lease2.close()

        # Simulate crashed owner + stale Chrome lock files -> reclaimed while preserving profile.
        (lease1.path / "owner.json").write_text(json.dumps({
            "schema": 1,
            "kind": profiles.PERSISTENT_OWNER_KIND,
            "profile_id": "agent-persist-1",
            "persistent": True,
            "pid": 999999,
            "creation": "win:1",
            "nonce": "deadbeef",
        }), encoding="utf-8")
        stale_port = lease1.chrome_profile_path / "DevToolsActivePort"
        stale_port.write_text("9999\n/devtools/browser/stale\n", encoding="ascii")
        with patch.object(profiles, "process_is_same", return_value=False):
            lease3 = profiles.PersistentBrowserProfile(self.isolated_root, profile_id="agent-persist-1")
        self.assertTrue(lease3.stale_owner_reclaimed)
        self.assertFalse(stale_port.exists())
        self.assertEqual(marker.read_text(encoding="utf-8"), "persisted-marker-v1")
        lease3.close()

    def test_managed_browser_profiles_rejects_owner_chrome_state_dir(self):
        local_app = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        owner_chrome = Path(local_app) / "Google" / "Chrome" / "User Data"
        with self.assertRaises(profiles.ProfileIsolationError) as exc:
            profiles.ManagedBrowserProfiles(owner_chrome)
        self.assertEqual(exc.exception.code, "OWNER_BROWSER_PROFILE_FORBIDDEN")


class HiddenChromeAndPrivateBrowserUnitTests(unittest.TestCase):
    def test_launch_chrome_refuses_owner_profile_before_spawn(self):
        local_app = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        owner_chrome = Path(local_app) / "Google" / "Chrome" / "User Data"
        with patch.object(hidden_chrome, "desktop_identity", return_value={
            "current": "FFBridge-Agent-test", "input": "Default", "target": "FFBridge-Agent-test"
        }), patch.object(hidden_chrome, "chrome_path", return_value=Path("C:/chrome.exe")), \
             patch.object(hidden_chrome.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(hidden_chrome.HiddenChromeError, "HIDDEN_CHROME_OWNER_PROFILE_FORBIDDEN"):
                hidden_chrome.launch_chrome(
                    owner_chrome, {"command": "browser.launch"},
                    register=Mock(), windows=lambda pid: [], owns=Mock(return_value=True),
                    window_info=Mock(), desktop="FFBridge-Agent-test",
                )
            popen.assert_not_called()

    def test_browser_connection_reset_clears_state_even_on_socket_close_error(self):
        conn = private_browser._BrowserConnection()
        bad_sock = Mock()
        bad_sock.close.side_effect = OSError("already closed")
        conn.socket = bad_sock
        conn.endpoint = "ws://127.0.0.1:1234/devtools/browser/x"
        conn.sessions["tab-1"] = "sid-1"
        conn.reset()
        self.assertIsNone(conn.socket)
        self.assertIsNone(conn.endpoint)
        self.assertEqual(conn.sessions, {})

    def test_private_browser_close_sends_browser_close_and_resets(self):
        broker = private_browser.PrivateBrowser.__new__(private_browser.PrivateBrowser)
        broker.verified_chrome = Mock(return_value={
            "cdp_port": 1234, "browser_ws_endpoint": "ws://127.0.0.1:1234/devtools/browser/a"
        })
        broker.tabs = {"t1"}
        broker.snapshots = {"t1": "snap"}
        broker.cdp = private_browser._BrowserConnection()
        fake_sock = Mock()
        fake_sock.recv.return_value = json.dumps({"id": 1, "result": {}})
        with patch.object(private_browser, "_LocalWebSocket", return_value=fake_sock):
            res = broker.close(close_browser=True)
        self.assertTrue(res["closed"])
        self.assertTrue(res["browser_close_sent"])
        self.assertTrue(res["socket_closed"])
        self.assertEqual(broker.tabs, set())
        self.assertEqual(broker.snapshots, {})
        sent = json.loads(fake_sock.send.call_args.args[0])
        self.assertEqual(sent["method"], "Browser.close")


class RouteSeparationContractTests(unittest.TestCase):
    def test_choose_route_never_silently_falls_back_to_owner_chrome(self):
        owner_only = [
            {"route": "owner_chrome_extension", "state": "READY"},
            {"route": "persistent_playwright", "state": "UNAVAILABLE"},
            {"route": "private_cdp", "state": "UNAVAILABLE"},
        ]
        # Default DOM route MUST return None rather than silently using owner Chrome.
        self.assertIsNone(routes_mod.choose_route(owner_only, capability="dom"))
        # Explicit hidden preferences MUST fail closed (None), NEVER fall back to owner Chrome.
        self.assertIsNone(routes_mod.choose_route(owner_only, prefer="persistent_playwright"))
        self.assertIsNone(routes_mod.choose_route(owner_only, prefer="private_cdp"))
        # Stale sticky affinity to owner Chrome MUST NOT hijack a default DOM request.
        self.assertIsNone(routes_mod.choose_route(
            owner_only, capability="dom", sticky={"route": "owner_chrome_extension"}
        ))
        # Explicit owner Chrome selection succeeds when usable.
        self.assertEqual(routes_mod.choose_route(owner_only, capability="extension_bridge"), "owner_chrome_extension")
        self.assertEqual(routes_mod.choose_route(owner_only, prefer="owner_chrome_extension"), "owner_chrome_extension")

    def test_route_plan_refuses_owner_fallback_and_never_reads_owner_prefs_by_default(self):
        with patch.object(routes_mod, "probe_playwright", return_value={"ok": False, "running": False, "reason": "PLAYWRIGHT_UNAVAILABLE", "probe_ms": 1}), \
             patch.object(routes_mod.apps, "resolve", return_value={"found": False}), \
             patch.object(routes_mod, "probe_owner_chrome", return_value={"ok": True, "running": True, "probe_ms": 1}) as owner_probe:
            # Default unscoped browser route fails closed when hidden routes are down, without even probing owner Chrome!
            plan = routes_mod.route_plan({"agent_id": "a1", "task_id": "t1"}, surface="browser")
            self.assertIsNone(plan["selected"])
            self.assertFalse(plan["owner_chrome_fallback"])
            self.assertTrue(plan["owner_chrome_explicit_only"])
            self.assertEqual(plan["fallback_refused_reason"], "ISOLATED_HIDDEN_ROUTES_UNAVAILABLE_NO_OWNER_FALLBACK")
            owner_probe.assert_not_called()

            # Even if owner_chrome_authorized=True, default capability="dom" STILL refuses silent fallback!
            plan_auth = routes_mod.route_plan(
                {"agent_id": "a1", "task_id": "t1"}, surface="browser", owner_chrome_authorized=True
            )
            self.assertIsNone(plan_auth["selected"])
            self.assertEqual(plan_auth["fallback_refused_reason"], "ISOLATED_HIDDEN_ROUTES_UNAVAILABLE_NO_OWNER_FALLBACK")

            # Explicit owner Chrome route with authorization=False is refused.
            plan_denied = routes_mod.route_plan(
                {"agent_id": "a1", "task_id": "t1"},
                surface="browser",
                capability="extension_bridge",
                owner_chrome_authorized=False,
            )
            self.assertIsNone(plan_denied["selected"])
            self.assertEqual(plan_denied["fallback_refused_reason"], "OWNER_CHROME_NOT_AUTHORIZED")

            # Scoped entry token CANNOT select owner Chrome even when explicitly requested.
            scoped = routes_mod.route_plan(
                {"agent_id": "a1", "task_id": "t1", "scopes": {"private_browser"}},
                surface="browser",
                prefer="owner_chrome_extension",
                owner_chrome_authorized=True,
            )
            self.assertIsNone(scoped["selected"])

            # Explicit owner Chrome route for authorized Hub caller succeeds.
            explicit = routes_mod.route_plan(
                {"agent_id": "a1", "task_id": "t1"},
                surface="browser",
                capability="extension_bridge",
            )
            self.assertEqual(explicit["selected"], "owner_chrome_extension")

        diag = routes_mod.inspect_extensions_and_companion()
        self.assertFalse(diag["owner_chrome_prefs_inspected"])


# ---- Part 2: Real Isolated Windows Live Tests --------------------------------

class RealWindowsManagedPlaywrightLiveTests(unittest.TestCase):
    """Real Windows live verification of ff_playwright_managed.mjs persistent isolated profile."""

    @classmethod
    def setUpClass(cls):
        if os.name != "nt":
            raise unittest.SkipTest("Windows-only live browser test")
        cls.pw_root = _discover_playwright_root()
        if cls.pw_root is None:
            raise unittest.SkipTest("Playwright root not configured (set FF_PLAYWRIGHT_ROOT)")
        if not shutil.which("node"):
            raise unittest.SkipTest("Node.js not installed")
        cls.server, cls.server_thread, cls.base_url = _start_local_fixture_server()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server"):
            cls.server.shutdown()
            cls.server.server_close()

    def test_live_persistent_profile_isolation_persistence_negatives_and_teardown(self):
        env_profile_root = os.environ.get("FF_P0_PERSISTENT_PROFILE_ROOT")
        tmp_state = tempfile.TemporaryDirectory(prefix="ff-p0-pw-state-")
        self.addCleanup(tmp_state.cleanup)
        if env_profile_root:
            persistent_root = Path(env_profile_root).resolve()
            persistent_root.mkdir(parents=True, exist_ok=True)
            profile_id = f"pw-persist-{secrets.token_hex(4)}"
            self.addCleanup(lambda: shutil.rmtree(persistent_root / profile_id, ignore_errors=True))
        else:
            tmp_prof = tempfile.TemporaryDirectory(prefix="ff-p0-pw-prof-")
            self.addCleanup(tmp_prof.cleanup)
            persistent_root = Path(tmp_prof.name)
            profile_id = "pw-persist-live"

        before_desktop = _snapshot_owner_desktop()
        evidence: dict = {
            "engine": "managed_headless_playwright",
            "before_desktop": {
                "visible_chrome_count": len(before_desktop["visible_chrome_hwnds"]),
                "foreground_hwnd": before_desktop["foreground_hwnd"],
            },
            "profile_id": profile_id,
        }

        # --- Session 1: launch, negative checks, interact, persist synthetic cookie+localStorage, close ---
        mgr1 = _ManagedPlaywrightProcess(Path(tmp_state.name) / "run1", self.pw_root, persistent_root)
        mgr1.start()
        try:
            # (e) Negative tests: owner Chrome User Data, path traversal, outside root, foreground/headless=false
            local_app = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
            owner_chrome_dir = str(Path(local_app) / "Google" / "Chrome" / "User Data")
            neg_owner = mgr1.rpc("open", {"owner": "neg-agent", "profile_dir": owner_chrome_dir, "url": self.base_url})
            self.assertFalse(neg_owner["ok"])
            self.assertEqual(neg_owner["error_code"], "OWNER_BROWSER_PROFILE_FORBIDDEN")

            neg_trav = mgr1.rpc("open", {"owner": "neg-agent", "profile_dir": str(persistent_root / "x" / ".." / ".." / "escape")})
            self.assertFalse(neg_trav["ok"])
            self.assertEqual(neg_trav["error_code"], "PROFILE_PATH_TRAVERSAL")

            neg_out = mgr1.rpc("open", {"owner": "neg-agent", "profile_dir": str(Path(tmp_state.name) / "outside")})
            self.assertFalse(neg_out["ok"])
            self.assertEqual(neg_out["error_code"], "PROFILE_OUTSIDE_ISOLATED_ROOT")

            neg_fg = mgr1.rpc("open", {"owner": "neg-agent", "profile_id": profile_id, "headless": False})
            self.assertFalse(neg_fg["ok"])
            self.assertEqual(neg_fg["error_code"], "FOREGROUND_ROUTE_REQUIRED")

            status_after_neg = mgr1.rpc("status")
            self.assertEqual(status_after_neg["result"]["contexts"], 0)

            # (a) & (b) Launch isolated persistent profile and interact with 127.0.0.1 stand
            opened1 = mgr1.rpc("open", {
                "owner": "p0-track-b",
                "profile_id": profile_id,
                "url": self.base_url,
            })
            self.assertTrue(opened1["ok"], opened1)
            res1 = opened1["result"]
            browser_id1 = res1["browser_id"]
            tab_id1 = res1["tab_id"]
            child_pid1 = res1["child_pid"]
            self.assertTrue(res1["headless"])
            self.assertTrue(res1["isolated_profile"])
            self.assertTrue(res1["persistent_profile"])
            self.assertEqual(res1["profile_id"], profile_id)
            self.assertIsInstance(child_pid1, int)
            self.assertTrue(_pid_alive(child_pid1))

            # Verify zero new visible Chrome windows on owner desktop & unchanged foreground HWND
            during_desktop = _snapshot_owner_desktop()
            new_visible = set(during_desktop["visible_chrome_hwnds"]) - set(before_desktop["visible_chrome_hwnds"])
            self.assertEqual(new_visible, set(), f"Unexpected visible Chrome HWND appeared: {new_visible}")
            self.assertEqual(during_desktop["foreground_hwnd"], before_desktop["foreground_hwnd"])

            # Concurrent second open against the SAME persistent profile fails closed
            dup = mgr1.rpc("open", {"owner": "other-agent", "profile_id": profile_id, "url": self.base_url})
            self.assertFalse(dup["ok"])
            self.assertEqual(dup["error_code"], "PERSISTENT_PROFILE_IN_USE")

            # Fill input, click Save State button, verify postcondition + DOM readback
            synth_note = "neon-p0-persist-" + secrets.token_hex(4)
            fill_res = mgr1.rpc("act", {
                "owner": "p0-track-b",
                "browser_id": browser_id1,
                "tab_id": tab_id1,
                "action": "fill",
                "target": {"selector": "#note-input"},
                "value": synth_note,
                "postcondition": {"target": {"selector": "#note-input"}, "value": synth_note},
            })
            self.assertTrue(fill_res["ok"], fill_res)
            self.assertFalse(fill_res["result"]["physical_input_used"])

            click_res = mgr1.rpc("act", {
                "owner": "p0-track-b",
                "browser_id": browser_id1,
                "tab_id": tab_id1,
                "action": "click",
                "target": {"selector": "#save-btn"},
                "postcondition": {"text_present": f"SAVED:{synth_note}:synth-"},
            })
            self.assertTrue(click_res["ok"], click_res)

            read1 = mgr1.rpc("read", {
                "owner": "p0-track-b",
                "browser_id": browser_id1,
                "tab_id": tab_id1,
                "target": {"selector": "#result-box"},
            })
            self.assertTrue(read1["ok"], read1)
            result_text = read1["result"]["text"].strip()
            self.assertTrue(result_text.startswith(f"SAVED:{synth_note}:synth-"), result_text)
            issued_token = result_text.split(":")[-1]

            # (c) Clean close via close_owner verifies 0 leaked Chrome processes & 0 leaked pages while preserving profile
            closed1 = mgr1.rpc("close_owner", {"owner": "p0-track-b"})
            self.assertTrue(closed1["ok"], closed1)
            self.assertEqual(closed1["result"]["closed"], 1)
            self.assertEqual(closed1["result"]["unconfirmed"], [])
            self.assertEqual(closed1["result"]["errors"], [])
            self.assertIn(profile_id, closed1["result"]["preserved_profiles"])
            self.assertFalse(_pid_alive(child_pid1), f"Chromium child PID {child_pid1} still alive after close!")
            self.assertTrue((persistent_root / profile_id).is_dir())
        finally:
            stop1 = mgr1.stop(graceful=True)
            self.assertTrue(stop1["exited"])
            self.assertFalse(_pid_alive(mgr1.pid))

        # --- Session 2: brand-new Node manager & fresh Chromium against SAME persistent profile dir ---
        mgr2 = _ManagedPlaywrightProcess(Path(tmp_state.name) / "run2", self.pw_root, persistent_root)
        mgr2.start()
        try:
            opened2 = mgr2.rpc("open", {
                "owner": "p0-track-b-relaunch",
                "profile_dir": str(persistent_root / profile_id),
                "url": self.base_url,
            })
            self.assertTrue(opened2["ok"], opened2)
            res2 = opened2["result"]
            browser_id2 = res2["browser_id"]
            tab_id2 = res2["tab_id"]
            child_pid2 = res2["child_pid"]
            self.assertNotEqual(child_pid2, child_pid1)
            self.assertTrue(_pid_alive(child_pid2))

            persisted_read = mgr2.rpc("read", {
                "owner": "p0-track-b-relaunch",
                "browser_id": browser_id2,
                "tab_id": tab_id2,
                "target": {"selector": "#persisted-box"},
            })
            self.assertTrue(persisted_read["ok"], persisted_read)
            persisted = json.loads(persisted_read["result"]["text"])
            # (d) Prove BOTH synthetic HTTP cookie (received by 127.0.0.1 server!) AND localStorage persisted!
            self.assertIn(f"ff_p0_synth_session={issued_token}", persisted["server_cookie_header"])
            self.assertIn(f"ff_p0_synth_session={issued_token}", persisted["document_cookie"])
            self.assertEqual(persisted["ls_note"], synth_note)
            self.assertEqual(persisted["ls_token"], issued_token)

            closed2 = mgr2.rpc("close", {"owner": "p0-track-b-relaunch", "browser_id": browser_id2})
            self.assertTrue(closed2["ok"], closed2)
            self.assertTrue(closed2["result"]["profile_cleanup_verified"])
            self.assertTrue(closed2["result"]["profile_preserved"])
            self.assertTrue(closed2["result"]["child_exited"])
            self.assertEqual(closed2["result"]["leaked_pids"], [])
            self.assertFalse(_pid_alive(child_pid2))

            # (f) Error teardown: open with unreachable port fails navigation -> 0 leaked contexts / processes
            err_open = mgr2.rpc("open", {
                "owner": "p0-error-check",
                "url": "http://127.0.0.1:1/",
            })
            self.assertFalse(err_open["ok"])
            st_after_err = mgr2.rpc("status")
            self.assertEqual(st_after_err["result"]["contexts"], 0)

            # (f) Forced EOF/crash teardown: open a context, close stdin abruptly -> Node tears down Chromium cleanly
            crash_open = mgr2.rpc("open", {
                "owner": "p0-crash-check",
                "profile_id": profile_id,
                "url": self.base_url,
            })
            self.assertTrue(crash_open["ok"], crash_open)
            crash_child_pid = crash_open["result"]["child_pid"]
            self.assertTrue(_pid_alive(crash_child_pid))
        finally:
            # Close stdin without calling RPC shutdown to simulate abrupt parent hub disconnect.
            stop2 = mgr2.stop(graceful=False)
            self.assertTrue(stop2["exited"])

        # Wait briefly and verify abrupt disconnect left ZERO zombie Chromium or Node processes!
        deadline = time.monotonic() + 8.0
        while _pid_alive(crash_child_pid) and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertFalse(_pid_alive(crash_child_pid), f"Zombie Chromium PID {crash_child_pid} after abrupt shutdown!")
        self.assertFalse(_pid_alive(mgr2.pid))

        after_desktop = _snapshot_owner_desktop()
        self.assertEqual(
            set(after_desktop["visible_chrome_hwnds"]) - set(before_desktop["visible_chrome_hwnds"]),
            set(),
        )
        self.assertEqual(after_desktop["foreground_hwnd"], before_desktop["foreground_hwnd"])

        evidence.update({
            "negatives_rejected": {
                "owner_chrome_user_data": neg_owner["error_code"],
                "path_traversal": neg_trav["error_code"],
                "outside_root": neg_out["error_code"],
                "headless_false": neg_fg["error_code"],
                "concurrent_same_profile": dup["error_code"],
            },
            "session1": {"child_pid": child_pid1, "child_exited": not _pid_alive(child_pid1), "result_text": result_text},
            "session2_relaunch": {
                "child_pid": child_pid2,
                "child_exited": not _pid_alive(child_pid2),
                "server_cookie_persisted": f"ff_p0_synth_session={issued_token}" in persisted["server_cookie_header"],
                "localstorage_persisted": persisted["ls_note"] == synth_note and persisted["ls_token"] == issued_token,
            },
            "error_and_crash_teardown": {
                "error_open_contexts_remaining": st_after_err["result"]["contexts"],
                "abrupt_disconnect_child_pid": crash_child_pid,
                "abrupt_disconnect_child_exited": not _pid_alive(crash_child_pid),
            },
            "after_desktop": {
                "visible_chrome_count": len(after_desktop["visible_chrome_hwnds"]),
                "new_visible_chrome_hwnds": 0,
                "foreground_hwnd_unchanged": after_desktop["foreground_hwnd"] == before_desktop["foreground_hwnd"],
                "cursor_pos_before": before_desktop.get("cursor_pos"),
                "cursor_pos_after": after_desktop.get("cursor_pos"),
            },
            "pass": True,
        })
        _record_live_evidence("managed_playwright", evidence)


class RealWindowsPrivateDesktopChromeLiveTests(unittest.TestCase):
    """Real Windows live verification of Win32 Private Desktop Chrome (IsolatedHiddenChromeSession)."""

    @classmethod
    def setUpClass(cls):
        if not _has_interactive_desktop():
            raise unittest.SkipTest("Interactive Windows desktop unavailable")
        if hidden_chrome.chrome_path() is None:
            raise unittest.SkipTest("Chrome executable not installed")
        cls.server, cls.server_thread, cls.base_url = _start_local_fixture_server()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server"):
            cls.server.shutdown()
            cls.server.server_close()

    def test_live_private_desktop_chrome_persistent_profile_and_job_teardown(self):
        env_profile_root = os.environ.get("FF_P0_PERSISTENT_PROFILE_ROOT")
        if env_profile_root:
            isolated_root = Path(env_profile_root).resolve()
            isolated_root.mkdir(parents=True, exist_ok=True)
            profile_id = f"cdp-persist-{secrets.token_hex(4)}"
            self.addCleanup(lambda: shutil.rmtree(isolated_root / profile_id, ignore_errors=True))
        else:
            tmp = tempfile.TemporaryDirectory(prefix="ff-p0-cdp-prof-")
            self.addCleanup(tmp.cleanup)
            isolated_root = Path(tmp.name)
            profile_id = "cdp-persist-live"

        before_desktop = _snapshot_owner_desktop()

        # Negative test: owner Chrome User Data refused fail-closed before CreateDesktopW / CreateProcessW
        local_app = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        owner_chrome_dir = Path(local_app) / "Google" / "Chrome" / "User Data"
        with self.assertRaises(hidden_chrome.HiddenChromeError) as neg:
            hidden_chrome.IsolatedHiddenChromeSession(isolated_root, profile_dir=owner_chrome_dir)
        self.assertEqual(neg.exception.code, "HIDDEN_CHROME_OWNER_PROFILE_FORBIDDEN")

        synth_note = "cdp-private-persist-" + secrets.token_hex(4)

        # --- Session 1: Real Chrome on Win32 Private Desktop ---
        s1 = hidden_chrome.IsolatedHiddenChromeSession(isolated_root, profile_id=profile_id, persistent=True)
        pid1 = s1.info["pid"]
        ctime1 = s1.info["create_time"]
        hwnd1 = s1.info["hwnd"]
        try:
            self.assertTrue(s1.info["persistent_profile"])
            self.assertEqual(s1.info["profile_id"], profile_id)
            self.assertFalse(s1.info["owner_desktop_access_allowed"])
            self.assertTrue(s1.desktop_name.startswith("FFBridge-Agent-"))

            # Verify Chrome HWND is NOT on owner's visible desktop and foreground is unchanged
            during = _snapshot_owner_desktop()
            self.assertNotIn(hwnd1, during["visible_chrome_hwnds"])
            self.assertEqual(
                set(during["visible_chrome_hwnds"]) - set(before_desktop["visible_chrome_hwnds"]),
                set(),
            )
            self.assertEqual(during["foreground_hwnd"], before_desktop["foreground_hwnd"])

            tabs = s1.browser.dispatch({"command": "tabs"})["tabs"]
            self.assertGreaterEqual(len(tabs), 1)
            tab_id = tabs[0]["tab_id"]
            s1.browser.dispatch({"command": "navigate", "tab_id": tab_id, "url": self.base_url})

            # Wait until page loads and controls are observable
            obs = None
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                cand = s1.browser.dispatch({"command": "observe", "tab_id": tab_id})
                if any(c.get("id") == "note-input" for c in cand.get("controls", [])):
                    obs = cand
                    break
                time.sleep(0.1)
            self.assertIsNotNone(obs, "Fixture controls did not appear in PrivateBrowser observe")

            input_ref = next(c["ref"] for c in obs["controls"] if c.get("id") == "note-input")
            s1.browser.dispatch({
                "command": "act",
                "tab_id": tab_id,
                "snapshot": obs["snapshot"],
                "ref": input_ref,
                "operation": "fill",
                "value": synth_note,
                "postcondition": {"type": "value_equals", "selector": "#note-input", "value": synth_note},
            })

            obs2 = s1.browser.dispatch({"command": "observe", "tab_id": tab_id})
            btn_ref = next(c["ref"] for c in obs2["controls"] if c.get("id") == "save-btn")
            s1.browser.dispatch({
                "command": "act",
                "tab_id": tab_id,
                "snapshot": obs2["snapshot"],
                "ref": btn_ref,
                "operation": "click",
                "postcondition": {"type": "text_includes", "value": f"SAVED:{synth_note}:synth-"},
            })

            read_res = s1.browser.dispatch({"command": "read", "tab_id": tab_id})
            self.assertIn(f"SAVED:{synth_note}:synth-", read_res["text"])
            issued_token = self.server.issued_tokens[-1]["token"]  # type: ignore[attr-defined]
        finally:
            receipt1 = s1.close(graceful=True)

        self.assertTrue(receipt1["closed"])
        self.assertTrue(receipt1["job_cleanup_verified"], receipt1)
        self.assertEqual(receipt1["active_processes_remaining"], 0, receipt1)
        self.assertTrue(receipt1["profile"]["released"], receipt1)
        self.assertTrue(receipt1["profile"]["preserved"], receipt1)
        self.assertFalse(process_identity_matches(pid1, ctime1))

        # --- Session 2: Fresh Private Desktop + Chrome against SAME isolated persistent profile ---
        s2 = hidden_chrome.IsolatedHiddenChromeSession(isolated_root, profile_id=profile_id, persistent=True)
        pid2 = s2.info["pid"]
        ctime2 = s2.info["create_time"]
        try:
            self.assertNotEqual((pid2, ctime2), (pid1, ctime1))
            tab2 = s2.browser.dispatch({"command": "tabs"})["tabs"][0]["tab_id"]
            s2.browser.dispatch({"command": "navigate", "tab_id": tab2, "url": self.base_url})
            persisted = None
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                val = s2.browser.dispatch({
                    "command": "evaluate",
                    "tab_id": tab2,
                    "expression": "document.getElementById('persisted-box')?.textContent || ''",
                })["value"]
                if val and "server_cookie_header" in val:
                    persisted = json.loads(val)
                    break
                time.sleep(0.1)
            self.assertIsNotNone(persisted)
            self.assertIn(f"ff_p0_synth_session={issued_token}", persisted["server_cookie_header"])
            self.assertIn(f"ff_p0_synth_session={issued_token}", persisted["document_cookie"])
            self.assertEqual(persisted["ls_note"], synth_note)
            self.assertEqual(persisted["ls_token"], issued_token)
        finally:
            # Test forced/non-graceful Job Object teardown too!
            receipt2 = s2.close(graceful=False)

        self.assertTrue(receipt2["job_cleanup_verified"], receipt2)
        self.assertEqual(receipt2["active_processes_remaining"], 0, receipt2)
        self.assertFalse(process_identity_matches(pid2, ctime2))

        after_desktop = _snapshot_owner_desktop()
        self.assertEqual(
            set(after_desktop["visible_chrome_hwnds"]) - set(before_desktop["visible_chrome_hwnds"]),
            set(),
        )
        self.assertEqual(after_desktop["foreground_hwnd"], before_desktop["foreground_hwnd"])

        _record_live_evidence("win32_private_desktop_chrome", {
            "engine": "win32_private_desktop_chrome_cdp",
            "profile_id": profile_id,
            "negative_owner_profile_error": neg.exception.code,
            "session1": {
                "pid": pid1,
                "hwnd": hwnd1,
                "desktop": s1.desktop_name,
                "hwnd_hidden_from_owner": hwnd1 not in during["visible_chrome_hwnds"],
                "job_cleanup_verified": receipt1["job_cleanup_verified"],
                "active_processes_remaining": receipt1["active_processes_remaining"],
                "graceful_cdp_close": receipt1["graceful_close"]["graceful_cdp_close"],
                "process_gone": not process_identity_matches(pid1, ctime1),
            },
            "session2_relaunch": {
                "pid": pid2,
                "desktop": s2.desktop_name,
                "server_cookie_persisted": f"ff_p0_synth_session={issued_token}" in persisted["server_cookie_header"],
                "localstorage_persisted": persisted["ls_note"] == synth_note and persisted["ls_token"] == issued_token,
                "forced_job_cleanup_verified": receipt2["job_cleanup_verified"],
                "active_processes_remaining": receipt2["active_processes_remaining"],
                "process_gone": not process_identity_matches(pid2, ctime2),
            },
            "after_desktop": {
                "new_visible_chrome_hwnds": 0,
                "foreground_hwnd_unchanged": after_desktop["foreground_hwnd"] == before_desktop["foreground_hwnd"],
                "cursor_pos_before": before_desktop.get("cursor_pos"),
                "cursor_pos_after": after_desktop.get("cursor_pos"),
            },
            "pass": True,
        })


def _record_live_evidence(section: str, payload: dict) -> None:
    target = os.environ.get("FF_P0_EVIDENCE_JSON")
    if not target:
        return
    path = Path(target)
    path.parent.mkdir(parents=True, exist_ok=True)
    current = {}
    if path.is_file():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                current = loaded
        except (OSError, ValueError):
            current = {}
    current[section] = payload
    current["updated_at_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
