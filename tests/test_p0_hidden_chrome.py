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
import cua_owner_chrome_secondary as owner_secondary  # noqa: E402
import cua_private_browser as private_browser  # noqa: E402
import ff_browser_routes as routes_mod  # noqa: E402
from cua_sidecar_supervisor import _bind_windows_kill_on_close_job, _close_windows_job_handle  # noqa: E402
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

    @unittest.skipUnless(os.name == "nt", "Windows 8.3 short-path canonicalization vs junction rejection")
    def test_windows_83_short_path_accepted_while_short_junction_and_owner_profile_rejected(self):
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetShortPathNameW.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]
        k32.GetShortPathNameW.restype = wt.DWORD

        def _short_path(p: Path) -> str:
            buf = ctypes.create_unicode_buffer(1024)
            n = k32.GetShortPathNameW(str(p), buf, len(buf))
            return buf.value if n else str(p)

        long_root = Path(self.tmp.name) / "isolated-long-profile-root"
        long_root.mkdir()
        short_root_str = _short_path(long_root)
        if "~" not in short_root_str:
            self.skipTest("Volume does not generate Windows 8.3 short paths")
        short_root = Path(short_root_str)

        # Pure 8.3 short path is canonicalized to its long path without triggering link false positives.
        target, pid = profiles.resolve_isolated_profile_dir(short_root, profile_id="short-ok-1")
        self.assertEqual(pid, "short-ok-1")
        self.assertEqual(profiles._norm_key(target), profiles._norm_key(long_root.resolve() / "short-ok-1"))

        lease = profiles.PersistentBrowserProfile(short_root, profile_id="short-persist-1")
        try:
            self.assertTrue((lease.path / "owner.json").is_file())
        finally:
            lease.close()

        # NTFS junction accessed by EITHER long name OR 8.3 short name MUST still fail closed!
        outside = Path(self.tmp.name) / "outside-junction-target"
        outside.mkdir()
        junc = long_root / "sneaky-long-junction"
        mk = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junc), str(outside)],
            capture_output=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if mk.returncode != 0:
            self.skipTest("Could not create test NTFS junction on this host")
        try:
            short_junc = Path(_short_path(junc))
            for candidate in (junc, short_junc, short_junc / "nested"):
                with self.subTest(candidate=str(candidate)):
                    with self.assertRaises(profiles.ProfileIsolationError) as exc:
                        profiles.assert_not_owner_browser_profile(candidate)
                    self.assertEqual(exc.exception.code, "ISOLATED_PROFILE_LINK_FORBIDDEN")

            # Dangling/broken NTFS junction (target removed) MUST still fail closed!
            outside.rmdir()
            for candidate in (junc, short_junc, junc / "future-child"):
                with self.subTest(dangling_candidate=str(candidate)):
                    with self.assertRaises(profiles.ProfileIsolationError) as exc:
                        profiles.assert_not_owner_browser_profile(candidate)
                    self.assertEqual(exc.exception.code, "ISOLATED_PROFILE_LINK_FORBIDDEN")
        finally:
            subprocess.run(
                ["cmd", "/c", "rmdir", str(junc)],
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )

        # Lowercase \\?\unc\ extended UNC path must never be rewritten into a local CWD path.
        from cua_windows_paths import expand_windows_short_path
        unc_in = Path(r"\\?\unc\localhost\nonexistent-share-ff-test")
        unc_out = expand_windows_short_path(unc_in)
        self.assertTrue(str(unc_out).lower().startswith("\\\\?\\unc\\"), str(unc_out))

        # Owner Chrome profile accessed via 8.3 short path prefix MUST still fail closed!
        local_app = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        short_local = Path(_short_path(Path(local_app)))
        owner_short = short_local / "Google" / "Chrome" / "User Data"
        with self.assertRaises(profiles.ProfileIsolationError) as exc:
            profiles.resolve_isolated_profile_dir(short_root, profile_dir=owner_short)
        self.assertEqual(exc.exception.code, "OWNER_BROWSER_PROFILE_FORBIDDEN")

    @unittest.skipUnless(os.name == "nt", "Windows PE binary version helper")
    def test_chrome_binary_version_reads_pe_and_rejects_non_pe(self):
        non_pe = Path(self.tmp.name) / "not-a-pe.txt"
        non_pe.write_text("hello", encoding="utf-8")
        self.assertIsNone(hidden_chrome.chrome_binary_version(non_pe))
        self.assertIsNone(hidden_chrome.chrome_binary_version(Path(self.tmp.name) / "missing.exe"))

        py_ver = hidden_chrome.chrome_binary_version(sys.executable)
        self.assertIsInstance(py_ver, tuple)
        self.assertEqual(len(py_ver), 4)
        self.assertGreaterEqual(py_ver[0], 3)

        chrome_exe = hidden_chrome.chrome_path()
        if chrome_exe is not None:
            cver = hidden_chrome.chrome_binary_version(chrome_exe)
            self.assertIsInstance(cver, tuple)
            self.assertEqual(len(cver), 4)
            self.assertGreater(cver[0], 0)


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


# ---- Part 3: Gate 2A Primary P0 (Owner Chrome Profile 1 Hidden Secondary) ----

class OwnerChromeHiddenSecondaryUnitTests(unittest.TestCase):
    """Fail-closed unit & route separation tests for primary P0 owner Chrome Profile 1 route."""

    def test_fail_closed_refusals_for_new_window_minimized_spawn_copy_foreground(self):
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(profile_dir_name="Profile 1")
        with self.assertRaises(owner_secondary.OwnerChromeSecondaryError) as exc:
            owner_secondary.reject_second_chrome_process_same_profile("synthetic-udd", "Profile 1")
        self.assertEqual(exc.exception.code, "SECOND_CHROME_PROCESS_SAME_PROFILE_FORBIDDEN")

        for extra, expected_code in (
            ({"spawn_new_process": True}, "SECOND_CHROME_PROCESS_SAME_PROFILE_FORBIDDEN"),
            ({"copy_profile": True}, "OWNER_PROFILE_COPY_FORBIDDEN"),
            ({"foreground": True}, "FOREGROUND_ROUTE_REQUIRED"),
            ({"new_window": True}, "OWNER_CHROME_NEW_WINDOW_HIDDEN_UNSUPPORTED"),
            ({"window_state": "minimized"}, "OWNER_CHROME_MINIMIZED_VISIBLE_SIDE_EFFECT_FORBIDDEN"),
            ({"profile_dir_name": "../escape"}, "OWNER_CHROME_PROFILE_INVALID"),
        ):
            with self.subTest(extra=extra), self.assertRaises(owner_secondary.OwnerChromeSecondaryError) as raised:
                mgr.call("open", {"owner": "agent\x1ftask", **extra})
            self.assertEqual(raised.exception.code, expected_code)

    def test_fail_closed_missing_cdp_not_running_and_old_chrome_version(self):
        with tempfile.TemporaryDirectory(prefix="ff-p0-sec-nocdp-") as td:
            udd = Path(td)
            mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(
                profile_dir_name="Profile 1", user_data_dir=udd
            )
            with patch.object(owner_secondary, "_is_chrome_running_on_windows", return_value=False):
                pf_down = mgr.preflight()
            self.assertFalse(pf_down["ok"])
            self.assertEqual(pf_down["error_code"], "OWNER_CHROME_NOT_RUNNING")

            with patch.object(owner_secondary, "_is_chrome_running_on_windows", return_value=True):
                pf_nocdp = mgr.preflight()
            self.assertFalse(pf_nocdp["ok"])
            self.assertEqual(pf_nocdp["error_code"], "OWNER_CHROME_HIDDEN_SECONDARY_CDP_UNAVAILABLE")

            (udd / "DevToolsActivePort").write_text("54321\n/devtools/browser/old\n", encoding="ascii")
            with patch.object(owner_secondary, "_find_listener_pid_for_port", return_value=1234), \
                 patch.object(owner_secondary, "_loopback_json_version", return_value={
                     "Browser": "Chrome/157.0.0.1",
                     "webSocketDebuggerUrl": "ws://127.0.0.1:54321/devtools/browser/old",
                 }):
                pf_old = mgr.preflight()
            self.assertFalse(pf_old["ok"])
            self.assertEqual(pf_old["error_code"], "OWNER_CHROME_VERSION_UNSUPPORTED")

    def test_fail_closed_multi_profile_default_context_mismatch(self):
        with tempfile.TemporaryDirectory(prefix="ff-p0-sec-mp-") as td:
            udd = Path(td)
            (udd / "DevToolsActivePort").write_text("54321\n/devtools/browser/mp\n", encoding="ascii")
            mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(
                profile_dir_name="Profile 1", user_data_dir=udd
            )

            # Case 1: Chrome running single profile 'Default' when 'Profile 1' requested -> MISMATCH
            fake_cdp = Mock()
            fake_cdp.send.side_effect = [
                {"browserContextIds": [], "defaultBrowserContextId": "CTX-DEFAULT"},
                {"targetInfos": [{"type": "page", "targetId": "T1", "browserContextId": "CTX-DEFAULT"}]},
            ]
            mgr._cdp = fake_cdp
            with patch.object(owner_secondary, "_find_listener_pid_for_port", return_value=1234), \
                 patch.object(owner_secondary, "_loopback_json_version", return_value={
                     "Browser": "Chrome/158.0.8127.36",
                     "webSocketDebuggerUrl": "ws://127.0.0.1:54321/devtools/browser/mp",
                 }), \
                 patch.object(owner_secondary, "_query_process_cmdline_windows", return_value='"chrome.exe" --profile-directory=Default'):
                pf_default = mgr.preflight()
            self.assertFalse(pf_default["ok"])
            self.assertEqual(pf_default["error_code"], "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH")

            # Case 2: Multiple profile contexts open simultaneously -> ALWAYS MISMATCH (dynamic context shift)
            fake_cdp2 = Mock()
            fake_cdp2.send.side_effect = [
                {"browserContextIds": [], "defaultBrowserContextId": "CTX-DEFAULT"},
                {"targetInfos": [
                    {"type": "page", "targetId": "T1", "browserContextId": "CTX-DEFAULT"},
                    {"type": "page", "targetId": "T2", "browserContextId": "CTX-PROFILE1"},
                ]},
            ]
            mgr._cdp = fake_cdp2
            with patch.object(owner_secondary, "_find_listener_pid_for_port", return_value=1234), \
                 patch.object(owner_secondary, "_loopback_json_version", return_value={
                     "Browser": "Chrome/158.0.8127.36",
                     "webSocketDebuggerUrl": "ws://127.0.0.1:54321/devtools/browser/mp",
                 }), \
                 patch.object(owner_secondary, "_query_process_cmdline_windows", return_value='"chrome.exe" --profile-directory="Profile 1"'):
                pf_multi = mgr.preflight()
            self.assertFalse(pf_multi["ok"])
            self.assertEqual(pf_multi["error_code"], "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH")

    def test_route_plan_primary_owner_auth_never_substitutes_isolated_or_extension(self):
        with patch.object(routes_mod, "probe_playwright", return_value={"ok": True, "running": True, "playwright_version": "1.65.1", "probe_ms": 1}), \
             patch.object(routes_mod.apps, "resolve", return_value={"found": True}), \
             patch.object(routes_mod, "probe_owner_chrome", return_value={"ok": True, "running": True, "probe_ms": 1}), \
             patch.object(routes_mod, "probe_owner_chrome_hidden_secondary", return_value={
                 "ok": False, "available": False, "hidden_target_supported": False,
                 "error_code": "OWNER_CHROME_HIDDEN_SECONDARY_CDP_UNAVAILABLE",
                 "reason": "no loopback CDP", "probe_ms": 1,
             }):
            plan = routes_mod.route_plan(
                {"agent_id": "a1", "task_id": "t1"},
                surface="browser",
                capability="owner_profile_hidden",
            )
            self.assertIsNone(plan["selected"])
            self.assertTrue(plan["isolated_substitution_forbidden"])
            self.assertEqual(plan["primary_owner_auth_route"], routes_mod.OWNER_CHROME_HIDDEN_SECONDARY_ROUTE)
            self.assertEqual(plan["fallback_refused_reason"], "OWNER_CHROME_HIDDEN_SECONDARY_CDP_UNAVAILABLE")

            by_name = {r["route"]: r for r in plan["routes"]}
            self.assertEqual(by_name["persistent_playwright"]["mode"], "optional_isolated_mode")
            self.assertFalse(by_name["persistent_playwright"]["satisfies_owner_profile_auth"])
            self.assertEqual(by_name["private_cdp"]["mode"], "optional_isolated_mode")
            self.assertFalse(by_name["private_cdp"]["satisfies_owner_profile_auth"])
            self.assertFalse(by_name["owner_chrome_extension"]["hidden_secondary_window_supported"])
            self.assertTrue(by_name["owner_chrome_extension"]["visible_tab_strip"])

            # Scoped entry without owner_chrome_hidden scope fails closed
            scoped_denied = routes_mod.route_plan(
                {"agent_id": "a1", "task_id": "t1", "scopes": {"private_browser"}},
                surface="browser",
                capability="owner_profile_hidden",
            )
            self.assertIsNone(scoped_denied["selected"])

        # When primary owner_chrome_profile1_hidden_secondary IS READY -> selected cleanly
        with patch.object(routes_mod, "probe_playwright", return_value={"ok": True, "running": True, "playwright_version": "1.65.1", "probe_ms": 1}), \
             patch.object(routes_mod.apps, "resolve", return_value={"found": True}), \
             patch.object(routes_mod, "probe_owner_chrome_hidden_secondary", return_value={
                 "ok": True, "available": True, "hidden_target_supported": True,
                 "error_code": None, "reason": "ready", "probe_ms": 1,
             }):
            ready_plan = routes_mod.route_plan(
                {"agent_id": "a1", "task_id": "t1"},
                surface="browser",
                capability="owner_profile_hidden",
            )
            self.assertEqual(ready_plan["selected"], routes_mod.OWNER_CHROME_HIDDEN_SECONDARY_ROUTE)

            scoped_ok = routes_mod.route_plan(
                {"agent_id": "a1", "task_id": "t1", "scopes": {"owner_chrome_hidden"}},
                surface="browser",
                capability="owner_profile_hidden",
            )
            self.assertEqual(scoped_ok["selected"], routes_mod.OWNER_CHROME_HIDDEN_SECONDARY_ROUTE)

    def test_close_single_target_polls_async_chromium_teardown_and_still_fails_closed(self):
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(profile_dir_name="Profile 1")
        rec1 = {"tab_id": "hsec-1", "target_id": "TID-1", "owner": "a\x1ft"}
        mgr._targets["hsec-1"] = rec1
        # Simulate Chromium listing TID-1 on first 2 polls, then unregistering it on 3rd poll.
        cdp_ok = Mock()
        cdp_ok.send.side_effect = [
            {"success": True},
            {"targetInfos": [{"targetId": "TID-1"}]},
            {"targetInfos": [{"targetId": "TID-1"}]},
            {"targetInfos": []},
        ]
        mgr._cdp = cdp_ok
        res_ok = mgr.call("close_owner", {"owner": "a\x1ft", "forget_unconfirmed": False})
        self.assertEqual(res_ok["closed"], 1)
        self.assertEqual(res_ok["unconfirmed"], [])
        self.assertEqual(res_ok["errors"], [])
        self.assertNotIn("hsec-1", mgr._targets)

        # Simulate target stuck alive past bounded deadline -> still fails closed & retained!
        rec2 = {"tab_id": "hsec-2", "target_id": "TID-2", "owner": "a\x1ft"}
        mgr._targets["hsec-2"] = rec2
        cdp_stuck = Mock()
        cdp_stuck.send.side_effect = lambda method, params=None, **kw: (
            {"success": True} if method == "Target.closeTarget" else {"targetInfos": [{"targetId": "TID-2"}]}
        )
        mgr._cdp = cdp_stuck
        res_stuck = mgr.call("close_owner", {"owner": "a\x1ft", "forget_unconfirmed": False}, timeout=0.2)
        self.assertEqual(res_stuck["closed"], 0)
        self.assertEqual(res_stuck["unconfirmed"], ["hsec-2"])
        self.assertEqual(res_stuck["errors"][0]["code"], "TARGET_CLEANUP_UNCONFIRMED")
        self.assertIn("hsec-2", mgr._targets)

    def test_close_single_target_polls_boundedly_and_still_fails_closed_if_stuck(self):
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(profile_dir_name="Profile 1")
        rec1 = {"tab_id": "hsec-race-1", "target_id": "TGT-RACE-1", "owner": "agent\x1ftask"}
        mgr._targets[rec1["tab_id"]] = rec1
        fake_cdp = Mock()
        fake_cdp.send.side_effect = [
            {"success": True},
            {"targetInfos": [{"targetId": "TGT-RACE-1"}]},  # still closing on 1st poll
            {"targetInfos": [{"targetId": "TGT-RACE-1"}]},  # still closing on 2nd poll
            {"targetInfos": []},                            # gone on 3rd poll
        ]
        mgr._cdp = fake_cdp
        res_ok = mgr.call("close_owner", {"owner": "agent\x1ftask", "forget_unconfirmed": False})
        self.assertEqual(res_ok["closed"], 1)
        self.assertEqual(res_ok["unconfirmed"], [])
        self.assertEqual(res_ok["errors"], [])
        self.assertNotIn(rec1["tab_id"], mgr._targets)

        # Stuck target that never disappears still fails closed and stays retained!
        rec2 = {"tab_id": "hsec-stuck-2", "target_id": "TGT-STUCK-2", "owner": "agent\x1ftask"}
        mgr._targets[rec2["tab_id"]] = rec2
        fake_cdp2 = Mock()
        fake_cdp2.send.side_effect = lambda method, params=None, **kw: (
            {"success": True} if method == "Target.closeTarget" else {"targetInfos": [{"targetId": "TGT-STUCK-2"}]}
        )
        mgr._cdp = fake_cdp2
        res_stuck = mgr._close_single_target(rec2, timeout_s=0.25)
        self.assertFalse(res_stuck["target_closed_in_browser"])
        self.assertEqual(res_stuck["error_code"], "TARGET_CLEANUP_UNCONFIRMED")
        self.assertIn(rec2["tab_id"], mgr._targets)


class RealWindowsOwnerChromeProfile1Gate2ALiveTests(unittest.TestCase):
    """Real Chrome 158+ synthetic Profile 1 Gate 2A live test (disposable private desktop, zero owner touch)."""

    @classmethod
    def setUpClass(cls):
        if not _has_interactive_desktop():
            raise unittest.SkipTest("Interactive Windows desktop unavailable")
        cls.exe = hidden_chrome.chrome_path()
        if cls.exe is None:
            if os.environ.get("FF_REQUIRE_CHROME_158") == "1":
                raise AssertionError("FF_REQUIRE_CHROME_158=1 requires installed Google Chrome >= 158.0.8127.2")
            raise unittest.SkipTest("Chrome executable not installed")
        cls.chrome_ver = hidden_chrome.chrome_binary_version(cls.exe)
        if cls.chrome_ver is None:
            raise AssertionError(f"Could not read PE version metadata from {cls.exe}")
        if not owner_secondary._version_at_least(cls.chrome_ver, owner_secondary.MIN_HIDDEN_TARGET_CHROME):
            got = ".".join(str(x) for x in cls.chrome_ver)
            req = ".".join(str(x) for x in owner_secondary.MIN_HIDDEN_TARGET_CHROME)
            if os.environ.get("FF_REQUIRE_CHROME_158") == "1":
                raise AssertionError(f"FF_REQUIRE_CHROME_158=1 requires Chrome >= {req}, found {got} at {cls.exe}")
            raise unittest.SkipTest(f"Installed Chrome binary {got} < required {req}")
        cls.server, cls.server_thread, cls.base_url = _start_httponly_auth_server()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server"):
            cls.server.shutdown()
            cls.server.server_close()

    def test_gate2a_real_chrome158_profile1_hidden_secondary_auth_zero_visible_and_fail_closed(self):
        before_owner = _snapshot_owner_desktop()
        tmp_dir = tempfile.mkdtemp(prefix="ff-p0-gate2a-p1-")
        user_data = Path(tmp_dir) / "UserData"
        user_data.mkdir()

        u32 = ctypes.WinDLL("user32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        u32.CreateDesktopW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.c_void_p]
        u32.CreateDesktopW.restype = wt.HANDLE
        u32.CloseDesktop.argtypes = [wt.HANDLE]
        u32.EnumDesktopWindows.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.LPARAM]
        u32.EnumDesktopWindows.restype = wt.BOOL
        u32.IsWindowVisible.argtypes = [wt.HWND]
        u32.IsWindowVisible.restype = wt.BOOL
        u32.IsIconic.argtypes = [wt.HWND]
        u32.IsIconic.restype = wt.BOOL
        u32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
        u32.GetWindowThreadProcessId.restype = wt.DWORD
        u32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
        u32.GetClassNameW.restype = ctypes.c_int
        u32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
        u32.GetWindowRect.restype = wt.BOOL
        u32.GetWindowLongW.argtypes = [wt.HWND, ctypes.c_int]
        u32.GetWindowLongW.restype = ctypes.c_long
        u32.GetWindow.argtypes = [wt.HWND, wt.UINT]
        u32.GetWindow.restype = wt.HWND

        k32.CreateProcessW.argtypes = [
            wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wt.BOOL, wt.DWORD,
            ctypes.c_void_p, wt.LPCWSTR, ctypes.POINTER(hidden_chrome._WinStartupInfo),
            ctypes.POINTER(hidden_chrome._WinProcessInfo),
        ]
        k32.CreateProcessW.restype = wt.BOOL
        k32.ResumeThread.argtypes = [wt.HANDLE]
        k32.CloseHandle.argtypes = [wt.HANDLE]
        k32.TerminateJobObject.argtypes = [wt.HANDLE, wt.UINT]
        k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]

        def enum_desktop_chrome(desktop_handle, pid_filter: int) -> list[dict]:
            found: list[dict] = []
            cb_type = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

            @cb_type
            def cb(hwnd, _):
                cls_buf = ctypes.create_unicode_buffer(128)
                u32.GetClassNameW(hwnd, cls_buf, len(cls_buf))
                if cls_buf.value != "Chrome_WidgetWin_1":
                    return True
                pid = wt.DWORD()
                u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if int(pid.value) != pid_filter:
                    return True
                rect = wt.RECT()
                u32.GetWindowRect(hwnd, ctypes.byref(rect))
                ex = int(u32.GetWindowLongW(hwnd, -20))
                owner = int(u32.GetWindow(hwnd, 4) or 0)
                vis = bool(u32.IsWindowVisible(hwnd))
                ico = bool(u32.IsIconic(hwnd))
                width = int(rect.right - rect.left)
                taskbar = vis and (bool(ex & 0x00040000) or (owner == 0 and not (ex & 0x00000080))) and (width > 0 or ico)
                found.append({"hwnd": int(hwnd), "visible": vis, "iconic": ico, "taskbar": taskbar, "width": width})
                return True

            u32.EnumDesktopWindows(desktop_handle, cb, 0)
            return found

        desktop_name = "FFBridge-Gate2A-" + secrets.token_hex(8)
        desktop = u32.CreateDesktopW(desktop_name, None, None, 0, 0x01FF, None)
        self.assertTrue(bool(desktop), "CreateDesktopW failed")
        job = hproc = None
        mgr = None
        try:
            argv = [
                str(self.exe),
                "--user-data-dir=" + str(user_data),
                "--profile-directory=Profile 1",
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0",
                "--no-first-run",
                "--no-default-browser-check",
                self.base_url + "login",
            ]
            cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            si = hidden_chrome._WinStartupInfo()
            si.cb = ctypes.sizeof(hidden_chrome._WinStartupInfo)
            si.lpDesktop = "winsta0\\" + desktop_name
            si.dwFlags = 1
            si.wShowWindow = 4
            pi = hidden_chrome._WinProcessInfo()
            created = k32.CreateProcessW(
                None, cmdline, None, None, False, 0x08000004, None, str(user_data),
                ctypes.byref(si), ctypes.byref(pi),
            )
            self.assertTrue(bool(created), "CreateProcessW for synthetic Profile 1 Chrome failed")
            hproc = pi.hProcess
            chrome_pid = int(pi.pid)
            job = _bind_windows_kill_on_close_job(SimpleNamespace(pid=chrome_pid))
            k32.ResumeThread(pi.hThread)
            k32.CloseHandle(pi.hThread)

            # Wait for DevToolsActivePort + Primary Window #1 login cookie to land
            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline:
                if (user_data / "DevToolsActivePort").is_file() and getattr(self.server, "token", None):
                    break
                time.sleep(0.1)
            self.assertIsNotNone(getattr(self.server, "token", None), "Primary Profile 1 /login did not complete")
            # Brief settle for localStorage script in Primary Window #1
            time.sleep(0.6)
            auth_token = self.server.token  # type: ignore[attr-defined]
            baseline_windows = enum_desktop_chrome(desktop, chrome_pid)
            baseline_hwnds = {w["hwnd"] for w in baseline_windows}
            self.assertGreaterEqual(len(baseline_hwnds), 1)

            # Start 5ms Win32 observer on BOTH synthetic Chrome desktop & owner visible desktop
            stop_obs = threading.Event()
            obs_stats = {"samples": 0, "new_hwnds": [], "any_visible": False, "any_taskbar": False, "owner_leaks": []}

            def poll_windows():
                seen = set()
                while not stop_obs.is_set():
                    obs_stats["samples"] += 1
                    for item in enum_desktop_chrome(desktop, chrome_pid):
                        if item["hwnd"] not in baseline_hwnds:
                            if item["hwnd"] not in seen:
                                seen.add(item["hwnd"])
                                obs_stats["new_hwnds"].append(item)
                            if item["visible"] and (item["width"] > 0 or item["iconic"]):
                                obs_stats["any_visible"] = True
                            if item["taskbar"]:
                                obs_stats["any_taskbar"] = True
                    cur_owner = _snapshot_owner_desktop()
                    leaks = set(cur_owner["visible_chrome_hwnds"]) - set(before_owner["visible_chrome_hwnds"])
                    if leaks:
                        obs_stats["owner_leaks"].extend(sorted(leaks))
                    time.sleep(0.005)

            obs_thread = threading.Thread(target=poll_windows, daemon=True)
            obs_thread.start()
            try:
                mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(
                    profile_dir_name="Profile 1",
                    user_data_dir=user_data,
                    chrome_pid=chrome_pid,
                )
                pf = mgr.preflight()
                self.assertTrue(pf["ok"], pf)
                self.assertTrue(pf["profile_context_verified"])
                self.assertTrue(pf["visible_side_effect_free"])
                self.assertFalse(pf["screenshot_supported"])

                # Wrong profile request against the SAME live Chrome 158 fails closed!
                wrong_mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(
                    profile_dir_name="Default",
                    user_data_dir=user_data,
                    chrome_pid=chrome_pid,
                )
                wrong_pf = wrong_mgr.preflight()
                self.assertFalse(wrong_pf["ok"])
                self.assertEqual(wrong_pf["error_code"], "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH")

                # Open hidden managed secondary target on Profile 1 (zero visible windows/tabs!)
                opened = mgr.call("open", {"owner": "agent-a\x1ftask-2a", "url": self.base_url + "check"})
                tab_id = opened["tab_id"]
                self.assertTrue(opened["hidden"])
                self.assertTrue(opened["windowless"])
                self.assertTrue(opened["auth_inherited"])
                self.assertFalse(opened["profile_copied"])
                self.assertFalse(opened["visible_window_created"])
                self.assertFalse(opened["taskbar_window_created"])
                self.assertFalse(opened["owner_tab_strip_modified"])

                # Prove HttpOnly cookie + localStorage auth inheritance (ZERO cookie/profile copying!)
                auth_read = mgr.call("read", {"owner": "agent-a\x1ftask-2a", "tab_id": tab_id, "selector": "#auth"})
                auth_payload = json.loads(auth_read["text"])
                self.assertIn(f"p1_httponly={auth_token}", auth_payload["server_cookie"])
                self.assertNotIn(auth_token, auth_payload["doc_cookie"])
                self.assertEqual(auth_payload["ls_token"], auth_token)
                self.assertEqual(auth_payload["innerWidth"], 1280)
                self.assertEqual(auth_payload["innerHeight"], 800)

                # Real DOM observe + fill + click + read on the windowless hidden target
                obs = mgr.call("observe", {"owner": "agent-a\x1ftask-2a", "tab_id": tab_id})
                inp_ref = next(c["ref"] for c in obs["controls"] if c.get("id") == "inp")
                btn_ref = next(c["ref"] for c in obs["controls"] if c.get("id") == "btn")
                mgr.call("act", {
                    "owner": "agent-a\x1ftask-2a",
                    "tab_id": tab_id,
                    "operation": "fill",
                    "snapshot": obs["snapshot"],
                    "ref": inp_ref,
                    "value": "gate2a-verified",
                    "postcondition": {"type": "value_equals", "selector": "#inp", "value": "gate2a-verified"},
                })
                obs2 = mgr.call("observe", {"owner": "agent-a\x1ftask-2a", "tab_id": tab_id})
                btn_ref2 = next(c["ref"] for c in obs2["controls"] if c.get("id") == "btn")
                mgr.call("act", {
                    "owner": "agent-a\x1ftask-2a",
                    "tab_id": tab_id,
                    "operation": "click",
                    "snapshot": obs2["snapshot"],
                    "ref": btn_ref2,
                    "postcondition": {"type": "text_includes", "value": "DONE:gate2a-verified"},
                })

                # Cross-owner isolation: foreign agent cannot read or close target
                with self.assertRaises(owner_secondary.OwnerChromeSecondaryError) as foreign:
                    mgr.call("read", {"owner": "agent-b\x1ftask-other", "tab_id": tab_id})
                self.assertEqual(foreign.exception.code, "TARGET_NOT_OWNED")

                # Screenshot fails closed cleanly instead of hanging or opening a visible window
                with self.assertRaises(owner_secondary.OwnerChromeSecondaryError) as shot_err:
                    mgr.call("screenshot", {"owner": "agent-a\x1ftask-2a", "tab_id": tab_id})
                self.assertEqual(shot_err.exception.code, "HIDDEN_TARGET_SCREENSHOT_UNSUPPORTED")

                # Clean teardown via close_owner leaves Primary Window #1 completely intact!
                closed = mgr.call("close_owner", {"owner": "agent-a\x1ftask-2a", "forget_unconfirmed": False})
                self.assertEqual(closed["closed"], 1)
                self.assertEqual(closed["unconfirmed"], [])
                self.assertEqual(closed["errors"], [])
                self.assertTrue(closed["primary_window_untouched"])
                self.assertEqual(mgr.call("list", {"owner": "agent-a\x1ftask-2a"})["tabs"], [])
            finally:
                stop_obs.set()
                obs_thread.join(timeout=2.0)

            # Assert ZERO visible/taskbar/owner-desktop side effects across entire 5ms observation window!
            self.assertGreater(obs_stats["samples"], 20)
            self.assertEqual(obs_stats["new_hwnds"], [])
            self.assertFalse(obs_stats["any_visible"])
            self.assertFalse(obs_stats["any_taskbar"])
            self.assertEqual(obs_stats["owner_leaks"], [])
            # Primary Window #1 still alive on synthetic desktop
            after_primary_windows = enum_desktop_chrome(desktop, chrome_pid)
            self.assertTrue(baseline_hwnds.issubset({w["hwnd"] for w in after_primary_windows}))

            after_owner = _snapshot_owner_desktop()
            self.assertEqual(
                set(after_owner["visible_chrome_hwnds"]) - set(before_owner["visible_chrome_hwnds"]),
                set(),
            )
            self.assertEqual(after_owner["foreground_hwnd"], before_owner["foreground_hwnd"])

            _record_live_evidence("gate2a_owner_chrome_profile1_hidden_secondary", {
                "engine": "chrome158_owner_profile1_hidden_target_cdp",
                "chrome_version": pf["chrome_version"],
                "profile_dir_name": "Profile 1",
                "profile_verified_by": pf["profile_verified_by"],
                "httponly_cookie_inherited": True,
                "localstorage_inherited": True,
                "profile_copied": False,
                "observer_5ms_samples": obs_stats["samples"],
                "new_hwnds_count": len(obs_stats["new_hwnds"]),
                "any_new_visible_window": obs_stats["any_visible"],
                "any_new_taskbar_window": obs_stats["any_taskbar"],
                "owner_desktop_leaks": len(obs_stats["owner_leaks"]),
                "wrong_profile_mismatch_code": wrong_pf["error_code"],
                "screenshot_fail_closed_code": shot_err.exception.code,
                "close_owner_closed": closed["closed"],
                "close_owner_unconfirmed": closed["unconfirmed"],
                "primary_window_intact": True,
                "pass": True,
            })
        finally:
            if mgr is not None:
                mgr.shutdown(close_targets=True)
            if job:
                k32.TerminateJobObject(job, 1)
                if hproc:
                    k32.WaitForSingleObject(hproc, 5000)
                    k32.CloseHandle(hproc)
                _close_windows_job_handle(job)
            if desktop:
                u32.CloseDesktop(desktop)
            time.sleep(0.3)
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _start_httponly_auth_server() -> tuple[ThreadingHTTPServer, threading.Thread, str]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            return

        def do_GET(self):
            cookie = self.headers.get("Cookie", "")
            if self.path == "/login":
                token = "p1-httponly-" + secrets.token_hex(6)
                self.server.token = token  # type: ignore[attr-defined]
                html = f"""<!doctype html><title>Primary Profile 1</title><body>
<div id="status">LOGGED_IN:{token}</div>
<script>localStorage.setItem('p1_ls', {json.dumps(token)});</script></body>""".encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Set-Cookie", f"p1_httponly={token}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            if self.path.startswith("/check"):
                html = f"""<!doctype html><title>Gate 2A Hidden Check</title><body>
<input id="inp" type="text" value="" />
<button id="btn" onclick="document.getElementById('out').textContent='DONE:' + document.getElementById('inp').value">Submit</button>
<div id="out">WAIT</div>
<pre id="auth"></pre>
<script>
  document.getElementById('auth').textContent = JSON.stringify({{
    server_cookie: {json.dumps(cookie)},
    doc_cookie: document.cookie,
    ls_token: localStorage.getItem('p1_ls'),
    innerWidth: window.innerWidth,
    innerHeight: window.innerHeight,
  }});
</script></body>""".encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return
            self.send_response(404)
            self.end_headers()

    class QuietServer(ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            exc = sys.exc_info()[1]
            if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
                return
            super().handle_error(request, client_address)

    srv = QuietServer(("127.0.0.1", 0), Handler)
    srv.token = None  # type: ignore[attr-defined]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    return srv, thread, f"http://127.0.0.1:{srv.server_port}/"


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
