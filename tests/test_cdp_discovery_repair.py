"""Scoped regression tests for FF Shared Hub Chrome 158+ CDP discovery repair.

Verifies:
- HTTP /json/version 404 (Chrome 144+/158 chrome://inspect/#remote-debugging
  kWithApprovalOnly WebSocket-only mode) is recognized instead of misreported
  as OWNER_CHROME_HIDDEN_SECONDARY_CDP_UNAVAILABLE.
- Consent-respecting passive discovery (route_plan / default preflight) does
  not trigger unsolicited WebSocket handshakes or Chrome approval dialogs.
- Active discovery / connect classifies:
  * 404 + approved WebSocket (Browser.getVersion + profile context verification
    + single-approval connection retention),
  * 404 + pending Chrome confirmation timeout -> OWNER_CHROME_CDP_APPROVAL_REQUIRED,
  * 404 + denied sessions (HTTP 403, HTTP 500, immediate EOF, post-upgrade close)
    -> OWNER_CHROME_CDP_DENIED,
  * Connection refused (stale DevToolsActivePort / closed port)
    -> OWNER_CHROME_CDP_CONNECTION_REFUSED,
  * 404 + unsupported Chrome version (<158.0.8127.2) via Browser.getVersion
    -> OWNER_CHROME_VERSION_UNSUPPORTED.
- Connection secrets (/devtools/browser/<uuid>) are never leaked in responses,
  route plans, or error messages/details.
- Real controlled Chrome 158+ synthetic Profile 1 E2E through a loopback
  HTTP-404 /json/version + WebSocket-passthrough facade verifies same-context
  hidden page auth inheritance, zero focus/window/taskbar side effects, and
  verified Target.closeTarget cleanup via FF Shared Hub.
"""
from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes as wt
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))

import cua_hidden_chrome as hidden_chrome  # noqa: E402
import cua_owner_chrome_secondary as owner_secondary  # noqa: E402
import ff_browser_routes as routes_mod  # noqa: E402
from ff_agent_entry import EntryAuthority, entry_call  # noqa: E402
from ff_hub import Hub  # noqa: E402
from ff_hub_permissions import Policy  # noqa: E402
from ff_hub_store import HubError  # noqa: E402


_WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_send_text(conn: socket.socket, text: str) -> None:
    payload = text.encode("utf-8")
    n = len(payload)
    head = bytearray([0x81])
    if n < 126:
        head.append(n)
    elif n <= 0xFFFF:
        head.append(126)
        head.extend(struct.pack("!H", n))
    else:
        head.append(127)
        head.extend(struct.pack("!Q", n))
    conn.sendall(bytes(head) + payload)


def _ws_recv_exact(conn: socket.socket, buf: bytearray, n: int) -> bytes:
    out = buf[:n]
    del buf[:n]
    while len(out) < n:
        chunk = conn.recv(n - len(out))
        if not chunk:
            raise EOFError("peer closed")
        out.extend(chunk)
    return bytes(out)


def _ws_recv_text(conn: socket.socket, buf: bytearray) -> str:
    parts = bytearray()
    while True:
        b1, b2 = _ws_recv_exact(conn, buf, 2)
        fin, opcode = bool(b1 & 0x80), b1 & 0x0F
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack("!H", _ws_recv_exact(conn, buf, 2))[0]
        elif n == 127:
            n = struct.unpack("!Q", _ws_recv_exact(conn, buf, 8))[0]
        masked = bool(b2 & 0x80)
        mask = _ws_recv_exact(conn, buf, 4) if masked else b""
        payload = _ws_recv_exact(conn, buf, n)
        if masked:
            payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        if opcode == 0x8:
            raise EOFError("ws close")
        if opcode in (0x0, 0x1):
            parts.extend(payload)
            if fin:
                return parts.decode("utf-8")


class _ControlledCDPServer:
    """Controlled loopback HTTP+WebSocket server for Chrome 158 404/denied/pending/approved tests."""

    def __init__(
        self,
        *,
        ws_path: str,
        http_version_status: int = 404,
        ws_mode: str = "approve",
        product: str = "Chrome/158.0.8127.36",
        default_ctx: str = "CTX-P1",
        target_contexts: list[str] | None = None,
        hold_seconds: float = 2.0,
    ) -> None:
        self.ws_path = ws_path
        self.http_version_status = http_version_status
        self.ws_mode = ws_mode
        self.product = product
        self.default_ctx = default_ctx
        self.target_contexts = list(target_contexts) if target_contexts is not None else [default_ctx]
        self.hold_seconds = hold_seconds
        self.http_requests: list[str] = []
        self.ws_requests: list[str] = []
        self.cdp_methods: list[str] = []
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = int(self._sock.getsockname()[1])
        self._sock.listen(16)
        self._sock.settimeout(0.1)
        self._threads: list[threading.Thread] = []
        self._accept_thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "_ControlledCDPServer":
        self._accept_thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._accept_thread.join(timeout=2.0)
        for t in list(self._threads):
            t.join(timeout=1.0)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            self._threads.append(t)
            t.start()

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(2.0)
            raw = bytearray()
            while b"\r\n\r\n" not in raw and len(raw) < 16384:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                raw.extend(chunk)
            head_bytes, _, rest = raw.partition(b"\r\n\r\n")
            lines = head_bytes.decode("latin1", "replace").split("\r\n")
            if not lines:
                return
            parts = lines[0].split(" ")
            if len(parts) < 2:
                return
            req_path = parts[1]
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            is_ws = headers.get("upgrade", "").lower() == "websocket"
            if not is_ws:
                self.http_requests.append(req_path)
                if req_path == "/json/version" and self.http_version_status == 200:
                    body = json.dumps({
                        "Browser": self.product,
                        "Protocol-Version": "1.3",
                        "webSocketDebuggerUrl": f"ws://127.0.0.1:{self.port}{self.ws_path}",
                    }).encode("utf-8")
                    resp = (
                        f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                    ).encode("ascii") + body
                else:
                    code = self.http_version_status
                    reason = {404: "Not Found", 403: "Forbidden", 401: "Unauthorized"}.get(code, "Error")
                    resp = f"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii")
                conn.sendall(resp)
                return

            self.ws_requests.append(req_path)
            if req_path != self.ws_path:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            if self.ws_mode == "deny_403":
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            if self.ws_mode == "deny_500":
                conn.sendall(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            if self.ws_mode == "deny_eof":
                return
            if self.ws_mode == "pending_timeout":
                self._stop.wait(timeout=self.hold_seconds)
                return

            key = headers.get("sec-websocket-key", "")
            accept = base64.b64encode(hashlib.sha1((key + _WS_MAGIC).encode("ascii")).digest()).decode("ascii")
            conn.sendall(
                f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n".encode("ascii")
            )
            if self.ws_mode == "deny_after_upgrade":
                # Send WebSocket close frame immediately (simulates post-upgrade rejection)
                conn.sendall(bytes([0x88, 0x00]))
                return

            buf = bytearray(rest)
            conn.settimeout(0.2)
            while not self._stop.is_set():
                try:
                    msg = _ws_recv_text(conn, buf)
                except socket.timeout:
                    continue
                except (EOFError, OSError):
                    break
                pkt = json.loads(msg)
                rid = pkt.get("id")
                method = str(pkt.get("method") or "")
                self.cdp_methods.append(method)
                if method == "Browser.getVersion":
                    result = {"protocolVersion": "1.3", "product": self.product}
                elif method == "Target.getBrowserContexts":
                    result = {"browserContextIds": [], "defaultBrowserContextId": self.default_ctx}
                elif method == "Target.getTargets":
                    result = {
                        "targetInfos": [
                            {"type": "page", "targetId": f"T-{i}", "browserContextId": ctx}
                            for i, ctx in enumerate(self.target_contexts)
                        ]
                    }
                else:
                    result = {}
                _ws_send_text(conn, json.dumps({"id": rid, "result": result}))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


class _Http404WsPassthroughProxy:
    """Loopback facade: returns HTTP 404 for /json/* while forwarding WebSocket upgrades to real Chrome."""

    def __init__(self, target_port: int, allowed_ws_path: str) -> None:
        self.target_port = int(target_port)
        self.allowed_ws_path = allowed_ws_path
        self.http_404_count = 0
        self.ws_upgrade_count = 0
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = int(self._sock.getsockname()[1])
        self._sock.listen(16)
        self._sock.settimeout(0.1)
        self._threads: list[threading.Thread] = []
        self._accept_thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "_Http404WsPassthroughProxy":
        self._accept_thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._accept_thread.join(timeout=2.0)
        for t in list(self._threads):
            t.join(timeout=1.0)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            t = threading.Thread(target=self._handle_conn, args=(conn,), daemon=True)
            self._threads.append(t)
            t.start()

    @staticmethod
    def _pipe(src: socket.socket, dst: socket.socket, stop: threading.Event) -> None:
        try:
            while not stop.is_set():
                try:
                    data = src.recv(16384)
                except socket.timeout:
                    continue
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def _handle_conn(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            client.settimeout(3.0)
            raw = bytearray()
            while b"\r\n\r\n" not in raw and len(raw) < 16384:
                chunk = client.recv(4096)
                if not chunk:
                    return
                raw.extend(chunk)
            head_bytes, sep, rest = raw.partition(b"\r\n\r\n")
            if not sep:
                return
            lines = head_bytes.decode("latin1", "replace").split("\r\n")
            req_path = lines[0].split(" ")[1] if len(lines[0].split(" ")) >= 2 else ""
            is_ws = any(line.lower().startswith("upgrade:") and "websocket" in line.lower() for line in lines[1:])
            if not is_ws:
                self.http_404_count += 1
                client.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            if req_path != self.allowed_ws_path:
                client.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            self.ws_upgrade_count += 1
            upstream = socket.create_connection(("127.0.0.1", self.target_port), timeout=3.0)
            rebuilt_lines = [lines[0]]
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    rebuilt_lines.append(f"Host: 127.0.0.1:{self.target_port}")
                else:
                    rebuilt_lines.append(line)
            upstream.sendall(("\r\n".join(rebuilt_lines) + "\r\n\r\n").encode("latin1") + bytes(rest))
            client.settimeout(0.2)
            upstream.settimeout(0.2)
            t1 = threading.Thread(target=self._pipe, args=(client, upstream, self._stop), daemon=True)
            t2 = threading.Thread(target=self._pipe, args=(upstream, client, self._stop), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except OSError:
            pass
        finally:
            for s in (client, upstream):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass


def _write_profile_state(udd: Path, port: int, ws_path: str, *, active_profile: str = "Profile 1") -> None:
    (udd / "DevToolsActivePort").write_text(f"{port}\n{ws_path}\n", encoding="ascii")
    (udd / "Local State").write_text(
        json.dumps({"profile": {"last_used": active_profile, "last_active_profiles": [active_profile]}}),
        encoding="utf-8",
    )


class CdpDiscoveryRepairTests(unittest.TestCase):
    """Unit & loopback server verification for 404, refused, denied, and pending-approval sessions."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ff-cdp-repair-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_404_passive_discovery_respects_consent_and_reports_approval_required_without_secret_leak(self) -> None:
        ws_secret = "/devtools/browser/secret-uuid-404-passive-test"
        srv = _ControlledCDPServer(ws_path=ws_secret, http_version_status=404, ws_mode="approve").start()
        udd = self.root / "udd-404-passive"
        udd.mkdir()
        _write_profile_state(udd, srv.port, ws_secret, active_profile="Profile 1")
        hub_state = self.root / "hub-404-passive"
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(hub_state, profile_dir_name="Profile 1", user_data_dir=udd)
        hub = Hub(hub_state, owner_chrome_secondary=mgr)
        try:
            pf = mgr.preflight()
            self.assertFalse(pf["ok"])
            self.assertTrue(pf["cdp_discovered"])
            self.assertTrue(pf["approval_required"])
            self.assertTrue(pf["confirmation_required"])
            self.assertEqual(pf["discovery_mode"], "devtools_active_port_ws_only")
            self.assertEqual(pf["http_discovery_status"], 404)
            self.assertEqual(pf["error_code"], "OWNER_CHROME_CDP_APPROVAL_REQUIRED")
            self.assertEqual(pf["remedy"], "OWNER_CHROME_APPROVE_REMOTE_DEBUGGING_DIALOG")
            self.assertFalse(pf["automatic"])
            # Passive discovery MUST NOT open a WebSocket or trigger Chrome confirmation dialog
            self.assertEqual(srv.ws_requests, [])
            self.assertEqual(srv.http_requests, ["/json/version"])
            self.assertNotIn(ws_secret, json.dumps(pf))

            # Hub route_plan reflects APPROVAL_REQUIRED and never substitutes isolated routes
            with patch.object(routes_mod, "probe_playwright", return_value={"ok": True, "running": True, "playwright_version": "1.65.1", "probe_ms": 1}), \
                 patch.object(routes_mod.apps, "resolve", return_value={"found": True}):
                rp = hub.dispatch({
                    "op": "route_plan",
                    "args": {"surface": "browser", "capability": "owner_profile_hidden", "profile_dir_name": "Profile 1"},
                })
            self.assertIsNone(rp["selected"])
            self.assertTrue(rp["isolated_substitution_forbidden"])
            self.assertEqual(rp["fallback_refused_reason"], "OWNER_CHROME_CDP_APPROVAL_REQUIRED")
            owner_route = next(r for r in rp["routes"] if r["route"] == owner_secondary.ROUTE_NAME)
            self.assertEqual(owner_route["state"], "APPROVAL_REQUIRED")
            self.assertTrue(owner_route["cdp_discovered"])
            self.assertTrue(owner_route["approval_required"])
            self.assertEqual(owner_route["http_discovery_status"], 404)
            self.assertEqual(srv.ws_requests, [])
            self.assertNotIn(ws_secret, json.dumps(rp))

            # Passive discovery with mismatched profile fails closed BEFORE asking for confirmation
            pf_wrong = mgr.preflight(profile_dir_name="Default")
            self.assertFalse(pf_wrong["ok"])
            self.assertEqual(pf_wrong["error_code"], "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH")
            self.assertTrue(pf_wrong["cdp_discovered"])
            self.assertEqual(pf_wrong["http_discovery_status"], 404)
            self.assertEqual(srv.ws_requests, [])
            self.assertNotIn(ws_secret, json.dumps(pf_wrong))
        finally:
            hub.shutdown()
            hub.store.close()
            srv.close()

    def test_404_approved_ws_discovery_retains_single_session_and_enforces_hub_permission(self) -> None:
        ws_secret = "/devtools/browser/secret-uuid-404-approved-test"
        srv = _ControlledCDPServer(ws_path=ws_secret, http_version_status=404, ws_mode="approve").start()
        udd = self.root / "udd-404-approved"
        udd.mkdir()
        _write_profile_state(udd, srv.port, ws_secret, active_profile="Profile 1")
        hub_state = self.root / "hub-404-approved"
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(hub_state, profile_dir_name="Profile 1", user_data_dir=udd)
        hub = Hub(hub_state, owner_chrome_secondary=mgr)
        try:
            sess = hub.dispatch({"op": "session_open", "args": {"agent_id": "a404", "task_id": "t404"}})
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}

            # Without standing policy grant, connect_ws=True is refused fail-closed before touching WS
            with self.assertRaises(HubError) as perm_err:
                hub.dispatch({**auth, "op": "owner_chrome_hidden", "args": {"command": "preflight", "connect_ws": True}})
            self.assertEqual(perm_err.exception.code, "PERMISSION_REQUIRED")
            self.assertEqual(srv.ws_requests, [])

            # Grant owner_chrome_hidden_secondary -> active preflight connects via DevToolsActivePort WS + Browser.getVersion
            Policy(hub_state / "policy.json").add_grant(["owner_chrome_hidden_secondary"], agents=["a404"], ttl_seconds=300)
            pf = hub.dispatch({**auth, "op": "owner_chrome_hidden", "args": {"command": "preflight", "connect_ws": True}})
            self.assertTrue(pf["ok"], pf)
            self.assertTrue(pf["available"])
            self.assertTrue(pf["cdp_discovered"])
            self.assertFalse(pf["approval_required"])
            self.assertEqual(pf["discovery_mode"], "devtools_active_port_ws_only")
            self.assertEqual(pf["http_discovery_status"], 404)
            self.assertEqual(pf["chrome_version"], "158.0.8127.36")
            self.assertIn("Browser.getVersion", srv.cdp_methods)
            self.assertEqual(len(srv.ws_requests), 1)
            self.assertTrue(mgr._cdp.connected())
            self.assertNotIn(ws_secret, json.dumps(pf))

            # Subsequent passive route_plan reuses the single owner-approved WS connection without opening a 2nd socket
            rp = hub.dispatch({
                "op": "route_plan",
                "args": {"surface": "browser", "capability": "owner_profile_hidden", "profile_dir_name": "Profile 1"},
            })
            self.assertEqual(rp["selected"], owner_secondary.ROUTE_NAME)
            self.assertEqual(len(srv.ws_requests), 1)
            self.assertNotIn(ws_secret, json.dumps(rp))

            # Probing a wrong profile while connected fails closed WITHOUT dropping the healthy approved WS
            pf_wrong = mgr.preflight(profile_dir_name="Default")
            self.assertFalse(pf_wrong["ok"])
            self.assertEqual(pf_wrong["error_code"], "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH")
            self.assertTrue(mgr._cdp.connected())
            self.assertEqual(len(srv.ws_requests), 1)

            # Explicit http://127.0.0.1:<port> cdp_endpoint also recovers ws_path from matching DevToolsActivePort on 404
            mgr_http_ep = owner_secondary.OwnerChromeHiddenSecondaryManager(
                profile_dir_name="Profile 1",
                cdp_endpoint=f"http://127.0.0.1:{srv.port}",
                user_data_dir=udd,
            )
            pf_http_ep = mgr_http_ep.preflight(connect_ws=True)
            self.assertTrue(pf_http_ep["ok"], pf_http_ep)
            self.assertEqual(pf_http_ep["discovery_mode"], "devtools_active_port_ws_only")
            self.assertEqual(pf_http_ep["http_discovery_status"], 404)
            self.assertNotIn(ws_secret, json.dumps(pf_http_ep))
            mgr_http_ep.shutdown(close_targets=False)

            # If the cached approved WS dies remotely, passive preflight returns APPROVAL_REQUIRED without opening a new WS
            before_ws_count = len(srv.ws_requests)
            mgr._cdp.socket.close()  # simulate remote EOF while mgr still considers socket open
            pf_stale = mgr.preflight(connect_ws=False)
            self.assertFalse(pf_stale["ok"])
            self.assertEqual(pf_stale["error_code"], "OWNER_CHROME_CDP_APPROVAL_REQUIRED")
            self.assertTrue(pf_stale["approval_required"])
            self.assertFalse(mgr._cdp.connected())
            self.assertEqual(len(srv.ws_requests), before_ws_count)
        finally:
            hub.shutdown()
            hub.store.close()
            srv.close()

    def test_404_pending_timeout_and_denied_sessions_classified_accurately(self) -> None:
        # 1. Pending Chrome approval dialog (WS upgrade stalls until timeout)
        ws_pending = "/devtools/browser/secret-uuid-pending-test"
        srv_pending = _ControlledCDPServer(
            ws_path=ws_pending, http_version_status=404, ws_mode="pending_timeout", hold_seconds=3.0
        ).start()
        try:
            udd = self.root / "udd-pending"
            udd.mkdir()
            _write_profile_state(udd, srv_pending.port, ws_pending)
            mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(profile_dir_name="Profile 1", user_data_dir=udd)
            pf = mgr.preflight(connect_ws=True, timeout_s=0.35)
            self.assertFalse(pf["ok"])
            self.assertEqual(pf["error_code"], "OWNER_CHROME_CDP_APPROVAL_REQUIRED")
            self.assertTrue(pf["cdp_discovered"])
            self.assertTrue(pf["approval_required"])
            self.assertTrue(pf["confirmation_required"])
            self.assertEqual(pf["http_discovery_status"], 404)
            self.assertEqual(pf["remedy"], "OWNER_CHROME_APPROVE_REMOTE_DEBUGGING_DIALOG")
            self.assertFalse(pf["automatic"])
            self.assertNotIn(ws_pending, json.dumps(pf))
        finally:
            srv_pending.close()

        # 2. Denied WS sessions: HTTP 403, HTTP 500, immediate EOF, post-upgrade close
        for mode, expected_ws_status in (
            ("deny_403", 403),
            ("deny_500", 500),
            ("deny_eof", None),
            ("deny_after_upgrade", None),
        ):
            with self.subTest(ws_mode=mode):
                ws_denied = f"/devtools/browser/secret-uuid-{mode}"
                srv = _ControlledCDPServer(ws_path=ws_denied, http_version_status=404, ws_mode=mode).start()
                try:
                    udd = self.root / f"udd-{mode}"
                    udd.mkdir()
                    _write_profile_state(udd, srv.port, ws_denied)
                    mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(profile_dir_name="Profile 1", user_data_dir=udd)
                    pf = mgr.preflight(connect_ws=True, timeout_s=1.5)
                    self.assertFalse(pf["ok"], pf)
                    self.assertEqual(pf["error_code"], "OWNER_CHROME_CDP_DENIED", pf)
                    self.assertTrue(pf["denied"])
                    self.assertTrue(pf["cdp_discovered"])
                    self.assertFalse(pf["approval_required"])
                    self.assertEqual(pf["http_discovery_status"], 404)
                    if expected_ws_status is not None:
                        self.assertEqual(pf["details"].get("ws_http_status"), expected_ws_status)
                    self.assertNotIn(ws_denied, json.dumps(pf))
                finally:
                    srv.close()

        # 3. HTTP /json/version 403 itself -> OWNER_CHROME_CDP_DENIED
        ws_h403 = "/devtools/browser/secret-uuid-http-403"
        srv_h403 = _ControlledCDPServer(ws_path=ws_h403, http_version_status=403, ws_mode="approve").start()
        try:
            udd = self.root / "udd-http-403"
            udd.mkdir()
            _write_profile_state(udd, srv_h403.port, ws_h403)
            mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(profile_dir_name="Profile 1", user_data_dir=udd)
            pf = mgr.preflight()
            self.assertFalse(pf["ok"])
            self.assertEqual(pf["error_code"], "OWNER_CHROME_CDP_DENIED")
            self.assertTrue(pf["denied"])
            self.assertEqual(srv_h403.ws_requests, [])
            self.assertNotIn(ws_h403, json.dumps(pf))
        finally:
            srv_h403.close()

    def test_refused_session_and_404_old_chrome_version_fail_closed(self) -> None:
        # 1. Connection refused on closed loopback port (stale DevToolsActivePort)
        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe_sock.bind(("127.0.0.1", 0))
        closed_port = int(probe_sock.getsockname()[1])
        probe_sock.close()

        ws_stale = "/devtools/browser/secret-uuid-stale-refused"
        udd = self.root / "udd-refused"
        udd.mkdir()
        _write_profile_state(udd, closed_port, ws_stale)
        hub_state = self.root / "hub-refused"
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(hub_state, profile_dir_name="Profile 1", user_data_dir=udd)
        hub = Hub(hub_state, owner_chrome_secondary=mgr)
        try:
            pf = mgr.preflight()
            self.assertFalse(pf["ok"])
            self.assertEqual(pf["error_code"], "OWNER_CHROME_CDP_CONNECTION_REFUSED")
            self.assertTrue(pf["refused"])
            self.assertFalse(pf["cdp_discovered"])
            self.assertFalse(pf["approval_required"])
            self.assertNotIn(ws_stale, json.dumps(pf))

            rp = hub.dispatch({
                "op": "route_plan",
                "args": {"surface": "browser", "capability": "owner_profile_hidden", "profile_dir_name": "Profile 1"},
            })
            self.assertIsNone(rp["selected"])
            self.assertEqual(rp["fallback_refused_reason"], "OWNER_CHROME_CDP_CONNECTION_REFUSED")
            owner_route = next(r for r in rp["routes"] if r["route"] == owner_secondary.ROUTE_NAME)
            self.assertEqual(owner_route["state"], "UNAVAILABLE")
            self.assertTrue(owner_route["refused"])
            self.assertNotIn(ws_stale, json.dumps(rp))
        finally:
            hub.shutdown()
            hub.store.close()

        # 2. HTTP 404 + Browser.getVersion reports unsupported Chrome < 158.0.8127.2
        ws_old = "/devtools/browser/secret-uuid-404-old-chrome"
        srv_old = _ControlledCDPServer(
            ws_path=ws_old, http_version_status=404, ws_mode="approve", product="Chrome/157.0.0.1"
        ).start()
        try:
            udd_old = self.root / "udd-old"
            udd_old.mkdir()
            _write_profile_state(udd_old, srv_old.port, ws_old)
            mgr_old = owner_secondary.OwnerChromeHiddenSecondaryManager(profile_dir_name="Profile 1", user_data_dir=udd_old)
            pf_old = mgr_old.preflight(connect_ws=True)
            self.assertFalse(pf_old["ok"])
            self.assertEqual(pf_old["error_code"], "OWNER_CHROME_VERSION_UNSUPPORTED")
            self.assertFalse(mgr_old._cdp.connected())
            self.assertNotIn(ws_old, json.dumps(pf_old))
        finally:
            srv_old.close()


@unittest.skipUnless(os.name == "nt", "Controlled Chrome 158 live hidden-page verification requires Windows")
class ControlledChrome158Http404HiddenPageE2ETests(unittest.TestCase):
    """Real controlled Chrome 158 with synthetic data behind an HTTP-404 /json/version loopback facade."""

    def test_controlled_chrome158_404_discovery_same_context_hidden_page_focus_and_cleanup(self) -> None:
        from cua_sidecar_supervisor import _bind_windows_kill_on_close_job, _close_windows_job_handle

        chrome_exe = hidden_chrome.chrome_path()
        if not chrome_exe:
            self.skipTest("Chrome executable not installed")

        u32 = ctypes.WinDLL("user32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        u32.GetForegroundWindow.restype = wt.HWND
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

        auth_token = "synth-404-e2e-" + secrets.token_hex(6)
        posts: list[dict] = []
        login_served = threading.Event()

        class _AuthHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def do_GET(self):
                if self.path == "/login":
                    body = (
                        "<!doctype html><title>Synthetic Primary</title><body>"
                        f"<script>localStorage.setItem('cdp404_ls', {json.dumps(auth_token)});</script>"
                        "<div id='ok'>SIGNED_IN</div></body>"
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Set-Cookie", f"cdp404_http={auth_token}; HttpOnly; Path=/")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    login_served.set()
                    return
                cookie_ok = f"cdp404_http={auth_token}" in (self.headers.get("Cookie") or "")
                body = (
                    "<!doctype html><title>Hidden Check</title><body>"
                    f"<div id='cookie'>COOKIE={'YES' if cookie_ok else 'NO'}</div>"
                    "<div id='ls'></div>"
                    "<input id='msg' type='text' value=''>"
                    "<button id='go' onclick=\"fetch('/act',{method:'POST',body:document.getElementById('msg').value})"
                    ".then(r=>r.text()).then(t=>{document.getElementById('out').textContent=t;})\">Go</button>"
                    "<div id='out'>IDLE</div>"
                    "<script>document.getElementById('ls').textContent=localStorage.getItem('cdp404_ls')||'NONE';</script>"
                    "</body>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                val = self.rfile.read(length).decode("utf-8", "replace")
                cookie_ok = f"cdp404_http={auth_token}" in (self.headers.get("Cookie") or "")
                posts.append({"value": val, "cookie_ok": cookie_ok})
                reply = f"OK:{val}:AUTH={'YES' if cookie_ok else 'NO'}".encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                self.wfile.write(reply)

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _AuthHandler)
        app_port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()

        tmp_dir = Path(tempfile.mkdtemp(prefix="ff-cdp404-e2e-"))
        synth_ud = tmp_dir / "chrome-ud"
        proxy_ud = tmp_dir / "proxy-ud"
        hub_state = tmp_dir / "hub-state"
        synth_ud.mkdir()
        proxy_ud.mkdir()
        # Pre-seed Local State like an existing running Chrome Profile 1 user-data-dir
        (synth_ud / "Local State").write_text(
            json.dumps({"profile": {"last_used": "Profile 1", "last_active_profiles": ["Profile 1"]}}),
            encoding="utf-8",
        )

        fg_before = int(u32.GetForegroundWindow() or 0)
        desktop_name = "FFBridge-CDP404-" + secrets.token_hex(8)
        desktop = u32.CreateDesktopW(desktop_name, None, None, 0, 0x01FF, None)
        self.assertTrue(bool(desktop), "CreateDesktopW failed")

        job = hproc = proxy = hub = None
        try:
            argv = [
                str(chrome_exe),
                f"--user-data-dir={synth_ud}",
                "--profile-directory=Profile 1",
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0",
                "--no-first-run",
                "--no-default-browser-check",
                f"http://127.0.0.1:{app_port}/login",
            ]
            cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            si = hidden_chrome._WinStartupInfo()
            si.cb = ctypes.sizeof(hidden_chrome._WinStartupInfo)
            si.lpDesktop = "winsta0\\" + desktop_name
            si.dwFlags = 1
            si.wShowWindow = 4
            pi = hidden_chrome._WinProcessInfo()
            created = k32.CreateProcessW(
                None, cmdline, None, None, False, 0x08000004, None, str(synth_ud),
                ctypes.byref(si), ctypes.byref(pi),
            )
            self.assertTrue(bool(created), "CreateProcessW failed")
            hproc = pi.hProcess
            chrome_pid = int(pi.pid)
            job = _bind_windows_kill_on_close_job(SimpleNamespace(pid=chrome_pid))
            k32.ResumeThread(pi.hThread)
            k32.CloseHandle(pi.hThread)

            marker = synth_ud / "DevToolsActivePort"
            local_state = synth_ud / "Local State"
            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline and (
                not marker.is_file() or not local_state.is_file() or not login_served.is_set()
            ):
                time.sleep(0.05)
            self.assertTrue(marker.is_file(), "Controlled Chrome did not write DevToolsActivePort")
            self.assertTrue(login_served.is_set(), "Controlled Chrome did not complete /login")
            time.sleep(0.5)

            real_lines = marker.read_text(encoding="ascii").splitlines()
            real_port, real_ws_path = int(real_lines[0]), real_lines[1].strip()
            proxy = _Http404WsPassthroughProxy(real_port, real_ws_path).start()

            # Write ONLY DevToolsActivePort (pointing to 404 proxy) + non-secret profile metadata
            (proxy_ud / "DevToolsActivePort").write_text(f"{proxy.port}\n{real_ws_path}\n", encoding="ascii")
            ls_data = json.loads(local_state.read_text(encoding="utf-8"))
            prof_meta = ls_data.setdefault("profile", {})
            prof_meta.setdefault("last_used", "Profile 1")
            if not prof_meta.get("last_active_profiles"):
                prof_meta["last_active_profiles"] = ["Profile 1"]
            (proxy_ud / "Local State").write_text(json.dumps(ls_data), encoding="utf-8")

            baseline_windows = enum_desktop_chrome(desktop, chrome_pid)
            baseline_hwnds = {w["hwnd"] for w in baseline_windows}
            self.assertGreaterEqual(len(baseline_hwnds), 1)

            stop_obs = threading.Event()
            obs_stats = {"samples": 0, "new_hwnds": [], "any_visible": False, "any_taskbar": False, "fg_changed": False}

            def poll_focus_and_windows() -> None:
                seen: set[int] = set()
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
                    cur_fg = int(u32.GetForegroundWindow() or 0)
                    if fg_before and cur_fg != fg_before:
                        obs_stats["fg_changed"] = True
                    time.sleep(0.005)

            obs_thread = threading.Thread(target=poll_focus_and_windows, daemon=True)
            obs_thread.start()
            try:
                mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(
                    hub_state,
                    profile_dir_name="Profile 1",
                    user_data_dir=proxy_ud,
                )
                hub = Hub(hub_state, owner_chrome_secondary=mgr)
                Policy(hub_state / "policy.json").add_grant(
                    ["owner_chrome_hidden_secondary"], agents=["a-404-e2e"], hosts=["127.0.0.1"], ttl_seconds=180
                )
                ea = EntryAuthority(hub_state)
                _, token = ea.issue(
                    client_id="c-404", agent_id="a-404-e2e", task_id="t-404-e2e",
                    scopes=["owner_chrome_hidden"], apps=[], ttl=180,
                )
                bearer = f"Bearer {token}"

                # 1. Passive route_plan sees HTTP 404 -> APPROVAL_REQUIRED (zero WS upgrade yet!)
                rp_before = entry_call(hub, ea, bearer, {
                    "op": "route_plan",
                    "args": {"surface": "browser", "capability": "owner_profile_hidden", "profile_dir_name": "Profile 1"},
                })
                self.assertIsNone(rp_before["selected"])
                self.assertEqual(rp_before["fallback_refused_reason"], "OWNER_CHROME_CDP_APPROVAL_REQUIRED")
                self.assertGreaterEqual(proxy.http_404_count, 1)
                self.assertEqual(proxy.ws_upgrade_count, 0)
                self.assertNotIn(real_ws_path, json.dumps(rp_before))

                # 2. Authorized open connects directly via DevToolsActivePort WS + Browser.getVersion + hidden page!
                sid = entry_call(hub, ea, bearer, {"op": "session_open"})["session_id"]
                opened = entry_call(hub, ea, bearer, {
                    "op": "owner_chrome_hidden",
                    "session_id": sid,
                    "request_key": "cdp404-open-001",
                    "args": {"command": "open", "url": f"http://127.0.0.1:{app_port}/app"},
                })
                self.assertTrue(opened["hidden"])
                self.assertTrue(opened["windowless"])
                self.assertTrue(opened["auth_inherited"])
                self.assertFalse(opened["profile_copied"])
                self.assertFalse(opened["visible_window_created"])
                self.assertEqual(proxy.ws_upgrade_count, 1)
                self.assertNotIn(real_ws_path, json.dumps(opened))
                tab_id = opened["tab_id"]

                # 3. Subsequent route_plan reuses the approved WS and reports READY!
                rp_after = entry_call(hub, ea, bearer, {
                    "op": "route_plan",
                    "args": {"surface": "browser", "capability": "owner_profile_hidden", "profile_dir_name": "Profile 1"},
                })
                self.assertEqual(rp_after["selected"], owner_secondary.ROUTE_NAME)
                owner_after = next(r for r in rp_after["routes"] if r["route"] == owner_secondary.ROUTE_NAME)
                self.assertEqual(owner_after["state"], "READY")
                self.assertEqual(owner_after["discovery_mode"], "devtools_active_port_ws_only")
                self.assertEqual(owner_after["http_discovery_status"], 404)
                self.assertTrue(str(owner_after.get("chrome_version") or "").startswith("158."))
                self.assertEqual(proxy.ws_upgrade_count, 1)

                # 4. Verify same-context HttpOnly cookie + localStorage + authenticated DOM action
                read_res = entry_call(hub, ea, bearer, {
                    "op": "owner_chrome_hidden",
                    "session_id": sid,
                    "args": {"command": "read", "tab_id": tab_id},
                })
                self.assertIn("COOKIE=YES", read_res["text"])
                self.assertIn(auth_token, read_res["text"])

                entry_call(hub, ea, bearer, {
                    "op": "owner_chrome_hidden",
                    "session_id": sid,
                    "request_key": "cdp404-fill-001",
                    "args": {"command": "act", "tab_id": tab_id, "operation": "fill", "selector": "#msg", "value": "via-404-ws"},
                })
                entry_call(hub, ea, bearer, {
                    "op": "owner_chrome_hidden",
                    "session_id": sid,
                    "request_key": "cdp404-click-001",
                    "args": {
                        "command": "act",
                        "tab_id": tab_id,
                        "operation": "click",
                        "selector": "#go",
                        "postcondition": {"type": "text_includes", "value": "OK:via-404-ws:AUTH=YES"},
                    },
                })
                self.assertTrue(any(p["value"] == "via-404-ws" and p["cookie_ok"] for p in posts))

                # 5. Clean teardown leaves primary Chrome window intact
                closed = entry_call(hub, ea, bearer, {
                    "op": "session_close",
                    "session_id": sid,
                    "request_key": "cdp404-close-001",
                })
                self.assertTrue(closed["closed"])
                self.assertTrue(closed["cleanup_verified"])
                self.assertEqual(closed["resources_retained"], 0)
                self.assertEqual(closed["owner_chrome_hidden_targets_closed"], 1)
                self.assertEqual(hub.store.resources(), [])
            finally:
                stop_obs.set()
                obs_thread.join(timeout=2.0)

            self.assertGreater(obs_stats["samples"], 20)
            self.assertEqual(obs_stats["new_hwnds"], [])
            self.assertFalse(obs_stats["any_visible"])
            self.assertFalse(obs_stats["any_taskbar"])
            self.assertFalse(obs_stats["fg_changed"])
            after_primary = enum_desktop_chrome(desktop, chrome_pid)
            self.assertTrue(baseline_hwnds.issubset({w["hwnd"] for w in after_primary}))
        finally:
            if hub is not None:
                hub.shutdown()
                hub.store.close()
            if proxy is not None:
                proxy.close()
            if job is not None:
                k32.TerminateJobObject(job, 1)
                _close_windows_job_handle(job)
            if hproc is not None:
                k32.WaitForSingleObject(hproc, 5000)
                k32.CloseHandle(hproc)
            if desktop:
                u32.CloseDesktop(desktop)
            httpd.shutdown()
            httpd.server_close()
            time.sleep(0.3)
            shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
