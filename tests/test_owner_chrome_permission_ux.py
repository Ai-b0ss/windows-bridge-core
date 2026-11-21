"""Synthetic-fixture regression tests for owner_chrome_hidden permission UX & two-gate consent separation.

Verifies without touching live Hub state, live grants, or private Chrome data:
- Chrome Default + HTTP-404 /json/version passive discovery distinguishes Gate 2
  (chrome_remote_debugging_dialog) from Gate 1 (hub_policy).
- Smoke open of about:blank returns PERMISSION_REQUIRED / NO_MATCHING_GRANT before execution
  with target.host == "" and clear Gate 1 vs Gate 2 diagnostics.
- Owner CLI `requests`, `approve`, `reject`, `grant add/list/revoke` offer a site-scoped,
  revocable grant for an actual HTTPS site and refuse bare `approve` on empty target.host
  (preventing silent all-sites escalation).
- Both consent gates remain preserved: approving Gate 1 still enforces Gate 2 (Chrome native
  dialog timeout/denial) and allows clean retry with the same request_key once Gate 2 passes.
- Site-scoped grants work end-to-end across `preflight(connect_ws=True, url/host=...)`,
  `open`, `read`, `observe`, `act`, `navigate`, and immediate revocation via `grant revoke`,
  while refusing other hosts, host spoofing via args.url, about:blank, and invalid host specs.
"""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "runtime" / "bridge-v3"
sys.path.insert(0, str(PACKAGE))

import cua_owner_chrome_secondary as owner_secondary  # noqa: E402
import ff_browser_routes as routes_mod  # noqa: E402
from ff_agent_entry import EntryAuthority, entry_call  # noqa: E402
from ff_hub import Hub  # noqa: E402
from ff_hub_mcp import Adapter, handle as mcp_handle  # noqa: E402
from ff_hub_permissions import PermissionError_, Policy  # noqa: E402
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


class _FullSyntheticHttp404CDPServer:
    """Synthetic Chrome 158 HTTP-404 loopback CDP server supporting hidden targets and HTTPS pages."""

    def __init__(
        self,
        *,
        ws_path: str,
        ws_mode: str = "approve",
        product: str = "Chrome/158.0.8127.36",
        default_ctx: str = "CTX-DEFAULT",
        hold_seconds: float = 1.5,
        ready_state: str = "complete",
    ) -> None:
        self.ws_path = ws_path
        self.ws_mode = ws_mode
        self.product = product
        self.default_ctx = default_ctx
        self.hold_seconds = hold_seconds
        self.ready_state = ready_state
        self.http_requests: list[str] = []
        self.ws_requests: list[str] = []
        self.cdp_methods: list[str] = []
        self._targets: dict[str, dict] = {}
        self._sessions: dict[str, str] = {}
        self._seq = 0
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = int(self._sock.getsockname()[1])
        self._sock.listen(16)
        self._sock.settimeout(0.1)
        self._threads: list[threading.Thread] = []
        self._accept_thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "_FullSyntheticHttp404CDPServer":
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
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return

            self.ws_requests.append(req_path)
            if req_path != self.ws_path:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            if self.ws_mode == "deny_403":
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
                params = pkt.get("params") or {}
                sid = pkt.get("sessionId")
                self.cdp_methods.append(method)
                if method == "Browser.getVersion":
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"protocolVersion": "1.3", "product": self.product}}))
                elif method == "Target.getBrowserContexts":
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"browserContextIds": [], "defaultBrowserContextId": self.default_ctx}}))
                elif method == "Target.getTargets":
                    infos = [{"type": "page", "targetId": "PRIMARY-0", "browserContextId": self.default_ctx}]
                    for tid in self._targets:
                        infos.append({"type": "page", "targetId": tid, "browserContextId": self.default_ctx})
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"targetInfos": infos}}))
                elif method == "Target.createTarget":
                    self._seq += 1
                    tid = f"HIDDEN-{self._seq}"
                    self._targets[tid] = {"url": str(params.get("url") or "about:blank"), "title": ""}
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"targetId": tid}}))
                elif method == "Browser.getWindowForTarget":
                    # Hidden windowless target has no browser window.
                    _ws_send_text(conn, json.dumps({"id": rid, "error": {"code": -32000, "message": "Browser window not found"}}))
                elif method == "Target.attachToTarget":
                    tid = str(params.get("targetId") or "")
                    session_id = f"SES-{tid}"
                    self._sessions[session_id] = tid
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"sessionId": session_id}}))
                elif method == "Emulation.setDeviceMetricsOverride":
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {}}))
                elif method == "Page.navigate":
                    tid = self._sessions.get(sid or "", "")
                    url = str(params.get("url") or "about:blank")
                    if tid in self._targets:
                        self._targets[tid]["url"] = url
                        self._targets[tid]["title"] = f"Title for {url}"
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"frameId": "F1"}}))
                elif method == "Runtime.evaluate":
                    tid = self._sessions.get(sid or "", "")
                    rec = self._targets.get(tid, {"url": "about:blank", "title": ""})
                    expr = str(params.get("expression") or "")
                    if "document.readyState" in expr:
                        val = {"rs": self.ready_state, "url": rec["url"], "title": rec["title"]}
                    elif "window.__ffhsec=" in expr:
                        val = {
                            "url": rec["url"],
                            "title": rec["title"],
                            "text": f"Synthetic HTTPS content at {rec['url']}",
                            "controls": [{"ref": "0", "tag": "button", "type": "button", "id": "go", "name": "Go", "value": None, "disabled": False}],
                        }
                    elif "acted:true" in expr:
                        val = {"acted": True, "url": rec["url"], "title": rec["title"]}
                    else:
                        val = {"url": rec["url"], "title": rec["title"], "text": f"Synthetic HTTPS content at {rec['url']}"}
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"result": {"value": val}}}))
                elif method == "Target.closeTarget":
                    tid = str(params.get("targetId") or "")
                    removed = self._targets.pop(tid, None) is not None
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"success": removed}}))
                else:
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {}}))
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _write_default_profile(udd: Path, port: int, ws_path: str, *, active_profile: str = "Default") -> None:
    (udd / "DevToolsActivePort").write_text(f"{port}\n{ws_path}\n", encoding="ascii")
    (udd / "Local State").write_text(
        json.dumps({"profile": {"last_used": active_profile, "last_active_profiles": [active_profile]}}),
        encoding="utf-8",
    )


def _run_hub_cli(state_dir: Path, *args: str) -> tuple[int, dict | list | str]:
    proc = subprocess.run(
        [sys.executable, str(PACKAGE / "ff_hub.py"), "--state-dir", str(state_dir), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=20,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    out = (proc.stdout or "").strip()
    try:
        parsed = json.loads(out) if out else {}
    except ValueError:
        parsed = out
    return proc.returncode, parsed


class OwnerChromePermissionUXTests(unittest.TestCase):
    """Verify site-scoped revocable permission UX and two-gate separation using synthetic fixtures."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ff-perm-ux-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_about_blank_empty_host_refusal_fail_closed_approve_and_reject_cli(self) -> None:
        ws_secret = "/devtools/browser/secret-uuid-ux-blank-default"
        srv = _FullSyntheticHttp404CDPServer(ws_path=ws_secret, ws_mode="approve").start()
        udd = self.root / "udd-blank"
        udd.mkdir()
        _write_default_profile(udd, srv.port, ws_secret, active_profile="Default")
        hub_state = self.root / "hub-blank"
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(hub_state, profile_dir_name="Default", user_data_dir=udd)
        hub = Hub(hub_state, owner_chrome_secondary=mgr)
        try:
            # 1. Passive discovery detects Chrome Default despite HTTP 404 and labels Gate 2 clearly
            with patch.object(routes_mod, "probe_playwright", return_value={"ok": False, "probe_ms": 0, "reason": "NO_PW"}), \
                 patch.object(routes_mod.apps, "resolve", return_value={"found": False}):
                rp = hub.dispatch({
                    "op": "route_plan",
                    "args": {"surface": "browser", "capability": "owner_profile_hidden"},
                })
            self.assertIsNone(rp["selected"])
            self.assertEqual(rp["fallback_refused_reason"], "OWNER_CHROME_CDP_APPROVAL_REQUIRED")
            owner_route = next(r for r in rp["routes"] if r["route"] == owner_secondary.ROUTE_NAME)
            self.assertEqual(owner_route["profile_dir_name"], "Default")
            self.assertEqual(owner_route["state"], "APPROVAL_REQUIRED")
            self.assertEqual(owner_route["http_discovery_status"], 404)
            self.assertEqual(owner_route["consent_gate"], "chrome_remote_debugging_dialog")
            self.assertTrue(owner_route["hub_policy_separate"])
            self.assertEqual(owner_route["hub_risk_class"], "owner_chrome_hidden_secondary")
            self.assertTrue(owner_route["site_scoped_grants_supported"])
            self.assertEqual(srv.ws_requests, [])
            self.assertNotIn(ws_secret, json.dumps(rp))

            # 2. Smoke open of about:blank hits Gate 1 BEFORE execution with empty target.host and clear distinction
            sess = hub.dispatch({"op": "session_open", "args": {"agent_id": "smoke-agent", "task_id": "smoke-task"}})
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}
            with self.assertRaises(HubError) as ctx:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "request_key": "smoke-blank-0001",
                    "args": {"command": "open", "url": "about:blank"},
                })
            err = ctx.exception
            self.assertEqual(err.code, "PERMISSION_REQUIRED")
            self.assertEqual(err.details["reason"], "NO_MATCHING_GRANT")
            self.assertFalse(err.details["execution_started"])
            self.assertEqual(err.details["target"], {"host": ""})
            self.assertTrue(err.details["target_host_missing"])
            self.assertEqual(err.details["consent_gate"], "hub_policy")
            self.assertTrue(err.details["separate_chrome_dialog_may_apply"])
            self.assertTrue(err.details["site_scope_supported"])
            self.assertTrue(err.details["revocable"])
            self.assertIn("Gate 1", err.message)
            self.assertIn("Gate 2", err.details["chrome_dialog_note"])
            self.assertIn("--hosts <site-host>", err.details["owner_actions"]["approve_site_scoped"])
            self.assertIn("grant revoke", err.details["owner_actions"]["revoke_grant"])
            self.assertNotIn("the whole class runs without asking", err.details["next_step"])
            self.assertEqual(srv.ws_requests, [])
            blank_req_id = err.details["owner_request_id"]

            # 3. Owner CLI `requests` clearly marks Gate 1, empty target.host, and safe commands
            rc, reqs = _run_hub_cli(hub_state, "requests")
            self.assertEqual(rc, 0, reqs)
            self.assertEqual(len(reqs), 1)
            self.assertEqual(reqs[0]["request_id"], blank_req_id)
            self.assertEqual(reqs[0]["consent_gate"], "hub_policy")
            self.assertTrue(reqs[0]["target_host_missing"])
            self.assertTrue(reqs[0]["separate_chrome_dialog_may_apply"])
            self.assertIn("reject", reqs[0]["owner_actions"]["reject_pending"])

            # 4. Bare `ff_hub.py approve <blank_id>` MUST fail closed (never silently mint all-sites 30d grant!)
            rc_approve, out_approve = _run_hub_cli(hub_state, "approve", blank_req_id)
            self.assertNotEqual(rc_approve, 0)
            self.assertEqual(out_approve["error"], "APPROVE_HOST_SCOPE_REQUIRED")
            self.assertEqual(out_approve["consent_gate"], "hub_policy")
            self.assertIn("--hosts <site-host>", out_approve["site_scoped_approve_command"])
            self.assertEqual(Policy(hub_state / "policy.json").describe()["grants"], [])
            # Request must still be pending because approval was refused
            rc_reqs2, reqs2 = _run_hub_cli(hub_state, "requests")
            self.assertEqual(rc_reqs2, 0)
            self.assertEqual(len(reqs2), 1)

            # 5. Conflicting --hosts + --all-hosts also fails closed
            rc_conf, out_conf = _run_hub_cli(hub_state, "approve", blank_req_id, "--hosts", "app.example.test", "--all-hosts")
            self.assertNotEqual(rc_conf, 0)
            self.assertEqual(out_conf["error"], "GRANT_SCOPE_INVALID")
            self.assertEqual(out_conf["reason"], "CONFLICTING_HOST_FLAGS")

            # 6. Owner CLI `reject` dismisses the bogus about:blank request cleanly with zero grant created
            rc_rej, out_rej = _run_hub_cli(hub_state, "reject", blank_req_id)
            self.assertEqual(rc_rej, 0, out_rej)
            self.assertTrue(out_rej["rejected"])
            self.assertEqual(out_rej["consent_gate"], "hub_policy")
            rc_reqs3, reqs3 = _run_hub_cli(hub_state, "requests")
            self.assertEqual(rc_reqs3, 0)
            self.assertEqual(reqs3, [])
            self.assertEqual(Policy(hub_state / "policy.json").describe()["grants"], [])
            # Rejecting again returns PENDING_REQUEST_NOT_FOUND
            rc_rej2, out_rej2 = _run_hub_cli(hub_state, "reject", blank_req_id)
            self.assertNotEqual(rc_rej2, 0)
            self.assertEqual(out_rej2["error"], "PENDING_REQUEST_NOT_FOUND")

            # 7. Re-opening about:blank reopens the pending request; owner can narrow it with --hosts <site-host>
            with self.assertRaises(HubError):
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "request_key": "smoke-blank-0002",
                    "args": {"command": "open", "url": "about:blank"},
                })
            rc_narrow, out_narrow = _run_hub_cli(hub_state, "approve", blank_req_id, "--hosts", "scoped.example.test", "--ttl", "60s")
            self.assertEqual(rc_narrow, 0, out_narrow)
            self.assertEqual(out_narrow["hosts"], ["scoped.example.test"])
            self.assertTrue(out_narrow["site_scoped"])
            self.assertEqual(out_narrow["consent_gate"], "hub_policy")
            # Revoke before testing explicit --all-hosts opt-in
            rc_rev_n, _ = _run_hub_cli(hub_state, "grant", "revoke", out_narrow["grant_id"])
            self.assertEqual(rc_rev_n, 0)

            with self.assertRaises(HubError):
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "request_key": "smoke-blank-0003",
                    "args": {"command": "open", "url": "about:blank"},
                })
            rc_all, out_all = _run_hub_cli(hub_state, "approve", blank_req_id, "--all-hosts", "--ttl", "60s")
            self.assertEqual(rc_all, 0, out_all)
            self.assertEqual(out_all["hosts"], [])
            self.assertFalse(out_all["site_scoped"])
            self.assertEqual(out_all["consent_gate"], "hub_policy")
        finally:
            hub.shutdown()
            hub.store.close()
            srv.close()

    def test_https_site_scoped_revocable_flow_preserves_both_consent_gates_and_retries_cleanly(self) -> None:
        ws_secret = "/devtools/browser/secret-uuid-ux-https-e2e"
        srv = _FullSyntheticHttp404CDPServer(ws_path=ws_secret, ws_mode="pending_timeout", hold_seconds=2.5).start()
        udd = self.root / "udd-https"
        udd.mkdir()
        _write_default_profile(udd, srv.port, ws_secret, active_profile="Default")
        hub_state = self.root / "hub-https"

        class _FastTimeoutSecondary(owner_secondary.OwnerChromeHiddenSecondaryManager):
            def call(self, op, args=None, *, timeout=30.0):
                return super().call(op, args, timeout=min(timeout, 0.35) if srv.ws_mode == "pending_timeout" else timeout)

        mgr = _FastTimeoutSecondary(hub_state, profile_dir_name="Default", user_data_dir=udd)
        hub = Hub(hub_state, owner_chrome_secondary=mgr)
        try:
            sess = hub.dispatch({"op": "session_open", "args": {"agent_id": "site-agent", "task_id": "site-task"}})
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}
            https_url = "https://app.example.test/dashboard"
            req_key = "https-open-0001"

            # 1. Gate 1 blocks HTTPS open BEFORE touching Chrome WebSocket
            with self.assertRaises(HubError) as g1_err:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "request_key": req_key,
                    "args": {"command": "open", "url": https_url},
                })
            self.assertEqual(g1_err.exception.code, "PERMISSION_REQUIRED")
            self.assertEqual(g1_err.exception.details["reason"], "NO_MATCHING_GRANT")
            self.assertEqual(g1_err.exception.details["target"], {"host": "app.example.test"})
            self.assertFalse(g1_err.exception.details["target_host_missing"])
            self.assertEqual(g1_err.exception.details["consent_gate"], "hub_policy")
            self.assertTrue(g1_err.exception.details["separate_chrome_dialog_may_apply"])
            self.assertFalse(g1_err.exception.details["execution_started"])
            self.assertEqual(srv.ws_requests, [])
            https_req_id = g1_err.exception.details["owner_request_id"]

            # 2. Owner approves site-scoped, TTL-bounded, revocable grant via CLI `approve`
            rc_app, granted = _run_hub_cli(hub_state, "approve", https_req_id, "--ttl", "1h")
            self.assertEqual(rc_app, 0, granted)
            self.assertEqual(granted["classes"], ["owner_chrome_hidden_secondary"])
            self.assertEqual(granted["agents"], ["site-agent"])
            self.assertEqual(granted["hosts"], ["app.example.test"])
            self.assertTrue(granted["site_scoped"])
            self.assertEqual(granted["consent_gate"], "hub_policy")
            self.assertTrue(granted["separate_chrome_dialog_may_apply"])
            self.assertIn("grant revoke", granted["revoke_command"])
            self.assertIn("Gate 2", granted["separate_chrome_dialog_note"])
            grant_id = granted["grant_id"]

            # 3. Gate 2 STILL enforced after Gate 1 is approved: pending Chrome dialog times out cleanly & retry_safe=True
            with self.assertRaises(HubError) as g2_pending:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "request_key": req_key,
                    "args": {"command": "open", "url": https_url},
                })
            self.assertEqual(g2_pending.exception.code, "OWNER_CHROME_CDP_APPROVAL_REQUIRED")
            self.assertEqual(g2_pending.exception.details["consent_gate"], "chrome_remote_debugging_dialog")
            self.assertTrue(g2_pending.exception.details["hub_policy_separate"])
            self.assertTrue(g2_pending.exception.details["retry_safe"])
            self.assertFalse(g2_pending.exception.details["execution_started"])
            self.assertFalse(g2_pending.exception.details["automatic"])
            self.assertEqual(len(srv.ws_requests), 1)
            self.assertEqual(hub.store.resources(), [])

            # 4. Gate 2 denied in Chrome -> OWNER_CHROME_CDP_DENIED (still retry_safe=True, no target leaked)
            srv.ws_mode = "deny_403"
            with self.assertRaises(HubError) as g2_denied:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "request_key": req_key,
                    "args": {"command": "open", "url": https_url},
                })
            self.assertEqual(g2_denied.exception.code, "OWNER_CHROME_CDP_DENIED")
            self.assertEqual(g2_denied.exception.details["consent_gate"], "chrome_remote_debugging_dialog")
            self.assertTrue(g2_denied.exception.details["hub_policy_separate"])
            self.assertTrue(g2_denied.exception.details["retry_safe"])
            self.assertFalse(g2_denied.exception.details["execution_started"])

            # 5. Owner approves Chrome native dialog (Gate 2) -> retry with SAME request_key succeeds!
            srv.ws_mode = "approve"
            opened = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "request_key": req_key,
                "args": {"command": "open", "url": https_url},
            })
            self.assertFalse(opened["deduplicated"])
            self.assertEqual(opened["url"], https_url)
            self.assertEqual(opened["profile_dir_name"], "Default")
            self.assertTrue(opened["hidden"])
            self.assertTrue(opened["windowless"])
            self.assertNotIn(ws_secret, json.dumps(opened))
            tab_id = opened["tab_id"]

            # Deduplication still works for the completed key
            dedup = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "request_key": req_key,
                "args": {"command": "open", "url": https_url},
            })
            self.assertTrue(dedup["deduplicated"])
            self.assertEqual(dedup["tab_id"], tab_id)

            # 6. Site-scoped preflight(connect_ws=True) works with matching url or host, and refuses others/empty
            pf_url = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "args": {"command": "preflight", "connect_ws": True, "url": https_url},
            })
            self.assertTrue(pf_url["ok"], pf_url)
            self.assertEqual(pf_url["profile_dir_name"], "Default")

            pf_host = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "args": {"command": "preflight", "connect_ws": True, "host": "app.example.test"},
            })
            self.assertTrue(pf_host["ok"], pf_host)

            with self.assertRaises(HubError) as pf_other:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "args": {"command": "preflight", "connect_ws": True, "url": "https://other.example.test/"},
                })
            self.assertEqual(pf_other.exception.code, "PERMISSION_REQUIRED")
            self.assertEqual(pf_other.exception.details["reason"], "HOST_NOT_GRANTED")

            with self.assertRaises(HubError) as pf_empty:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "args": {"command": "preflight", "connect_ws": True},
                })
            self.assertEqual(pf_empty.exception.code, "PERMISSION_REQUIRED")
            self.assertEqual(pf_empty.exception.details["reason"], "HOST_NOT_GRANTED")
            self.assertTrue(pf_empty.exception.details["target_host_missing"])

            # 7. Same-site read/observe/act/navigate succeed; other-site & about:blank refused
            read_out = hub.dispatch({**auth, "op": "owner_chrome_hidden", "args": {"command": "read", "tab_id": tab_id}})
            self.assertIn(https_url, read_out["text"])

            obs_out = hub.dispatch({**auth, "op": "owner_chrome_hidden", "args": {"command": "observe", "tab_id": tab_id}})
            self.assertEqual(obs_out["url"], https_url)

            act_out = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "request_key": "https-act-0001",
                "args": {"command": "act", "tab_id": tab_id, "operation": "click", "selector": "#go"},
            })
            self.assertTrue(act_out["acted"])

            nav_same = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "request_key": "https-nav-same-001",
                "args": {"command": "navigate", "tab_id": tab_id, "url": "https://app.example.test/settings"},
            })
            self.assertTrue(nav_same["navigated"])

            for forbidden_url in ("https://other.example.test/", "about:blank"):
                with self.assertRaises(HubError) as denied_nav:
                    hub.dispatch({
                        **auth,
                        "op": "owner_chrome_hidden",
                        "request_key": f"https-deny-{len(forbidden_url):04d}",
                        "args": {"command": "navigate", "tab_id": tab_id, "url": forbidden_url},
                    })
                self.assertEqual(denied_nav.exception.code, "PERMISSION_REQUIRED")
                self.assertEqual(denied_nav.exception.details["reason"], "HOST_NOT_GRANTED")

            # 8. Host spoofing guard: if tab navigated to another host, passing args.url cannot bypass read check
            res_row = hub.store.resources(session_id=sess["session_id"], kind="owner_chrome_hidden_target")[0]
            hub.store.update_resource_meta(res_row["resource_id"], {**res_row["meta"], "url": "https://other.example.test/redirected"})
            with self.assertRaises(HubError) as spoof_err:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "args": {"command": "read", "tab_id": tab_id, "url": "https://app.example.test/"},
                })
            self.assertEqual(spoof_err.exception.code, "PERMISSION_REQUIRED")
            self.assertEqual(spoof_err.exception.details["reason"], "HOST_NOT_GRANTED")
            self.assertEqual(spoof_err.exception.details["target"], {"host": "other.example.test"})

            # 9. Immediate revocation via `ff_hub.py grant revoke` blocks access immediately while allowing clean close
            rc_rev, rev_out = _run_hub_cli(hub_state, "grant", "revoke", grant_id)
            self.assertEqual(rc_rev, 0, rev_out)
            self.assertTrue(rev_out["revoked"])
            self.assertEqual(rev_out["consent_gate"], "hub_policy")

            rc_list, list_out = _run_hub_cli(hub_state, "grant", "list")
            self.assertEqual(rc_list, 0)
            self.assertEqual(list_out, [])

            with self.assertRaises(HubError) as post_rev:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "request_key": "https-after-revoke-001",
                    "args": {"command": "open", "url": https_url},
                })
            self.assertEqual(post_rev.exception.code, "PERMISSION_REQUIRED")
            self.assertEqual(post_rev.exception.details["reason"], "NO_MATCHING_GRANT")

            # Session close still cleanly closes owned hidden target after grant revocation
            closed = hub.dispatch({**auth, "op": "session_close", "request_key": "https-close-0001"})
            self.assertTrue(closed["closed"])
            self.assertTrue(closed["cleanup_verified"])
            self.assertEqual(closed["resources_retained"], 0)
            self.assertEqual(closed["owner_chrome_hidden_targets_closed"], 1)
            self.assertEqual(hub.store.resources(), [])
        finally:
            hub.shutdown()
            hub.store.close()
            srv.close()

    def test_host_scope_validation_forbidden_schemes_slow_open_and_mcp_entry_surfaces(self) -> None:
        ws_secret = "/devtools/browser/secret-uuid-ux-mcp"
        srv = _FullSyntheticHttp404CDPServer(ws_path=ws_secret, ws_mode="approve", ready_state="loading").start()
        udd = self.root / "udd-mcp"
        udd.mkdir()
        _write_default_profile(udd, srv.port, ws_secret, active_profile="Default")
        hub_state = self.root / "hub-mcp"

        class _QuickOpenSecondary(owner_secondary.OwnerChromeHiddenSecondaryManager):
            def call(self, op, args=None, *, timeout=30.0):
                return super().call(op, args, timeout=min(timeout, 0.25) if op == "open" else timeout)

        mgr = _QuickOpenSecondary(hub_state, profile_dir_name="Default", user_data_dir=udd)
        hub = Hub(hub_state, owner_chrome_secondary=mgr)
        try:
            # 1. Host pattern validation refuses URLs, ports, about:blank, bare wildcards
            pol = Policy(hub_state / "policy.json")
            for bad_host in ("https://app.example.test", "https://app.example.test/x", "app.example.test:443",
                             "about:blank", "*", "*.", "*.*", "a.*.example.test", "bad host"):
                with self.subTest(bad_host=bad_host):
                    with self.assertRaises(PermissionError_) as herr:
                        pol.add_grant(["owner_chrome_hidden_secondary"], agents=["mcp-agent"], hosts=[bad_host], ttl_seconds=60)
                    self.assertEqual(herr.exception.code, "GRANT_SCOPE_INVALID")
                    self.assertEqual(herr.exception.details.get("reason"), "HOSTNAME_REQUIRED")

            # CLI `grant add` with URL-as-host also fails closed cleanly
            rc_bad, out_bad = _run_hub_cli(
                hub_state, "grant", "add",
                "--classes", "owner_chrome_hidden_secondary",
                "--agents", "mcp-agent",
                "--hosts", "https://app.example.test/path",
                "--ttl", "1h",
            )
            self.assertNotEqual(rc_bad, 0)
            self.assertEqual(out_bad["error"], "GRANT_SCOPE_INVALID")

            # Valid wildcard + trailing dot + uppercase normalize cleanly
            rc_ok, grant_out = _run_hub_cli(
                hub_state, "grant", "add",
                "--classes", "owner_chrome_hidden_secondary",
                "--agents", "mcp-agent",
                "--hosts", "*.EXAMPLE.TEST.",
                "--ttl", "1h",
                "--note", "synthetic wildcard",
            )
            self.assertEqual(rc_ok, 0, grant_out)
            self.assertEqual(grant_out["hosts"], ["*.example.test"])
            self.assertTrue(grant_out["site_scoped"])
            self.assertEqual(grant_out["consent_gate"], "hub_policy")
            self.assertTrue(grant_out["separate_chrome_dialog_may_apply"])

            # Policy describe advertises host-scoping and separate Chrome dialog
            desc = pol.describe()["classes"]["owner_chrome_hidden_secondary"]
            self.assertTrue(desc["supports_host_scope"])
            self.assertTrue(desc["separate_chrome_dialog_may_apply"])
            self.assertIn("separate from Chrome's native remote debugging confirmation dialog", desc["about"])

            # 2. Forbidden schemes & unsupported commands fail BEFORE _permit (zero bogus pending requests!)
            sess = hub.dispatch({"op": "session_open", "args": {"agent_id": "mcp-agent", "task_id": "t-check"}})
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}
            for bad_url in ("chrome://settings", "file:///C:/Windows/win.ini", "javascript:alert(1)"):
                with self.assertRaises(HubError) as serr:
                    hub.dispatch({
                        **auth,
                        "op": "owner_chrome_hidden",
                        "request_key": f"bad-scheme-{abs(hash(bad_url)) % 100000:05d}",
                        "args": {"command": "open", "url": bad_url},
                    })
                self.assertEqual(serr.exception.code, "URL_SCHEME_FORBIDDEN")
            with self.assertRaises(HubError) as pf_bad:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "args": {"command": "preflight", "connect_ws": True, "host": "*.example.test"},
                })
            self.assertEqual(pf_bad.exception.code, "ARGS_INVALID")
            with self.assertRaises(HubError) as pf_disagree:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "args": {"command": "preflight", "connect_ws": True, "url": "https://sub.example.test/", "host": "other.example.test"},
                })
            self.assertEqual(pf_disagree.exception.code, "ARGS_INVALID")
            self.assertEqual(hub.store.permission_requests(), [])

            # 3. Slow HTTPS open (readyState stays 'loading' until timeout) still records real URL so subsequent read passes host scope!
            slow_opened = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "request_key": "slow-open-0001",
                "args": {"command": "open", "url": "https://sub.example.test/slow"},
            })
            self.assertEqual(slow_opened["url"], "https://sub.example.test/slow")
            read_slow = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "args": {"command": "read", "tab_id": slow_opened["tab_id"]},
            })
            self.assertIn("https://sub.example.test/slow", read_slow["text"])
            # Unsupported command on owned tab fails BEFORE _permit
            with self.assertRaises(HubError) as unsup:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "args": {"command": "bogus_cmd", "tab_id": slow_opened["tab_id"]},
                })
            self.assertEqual(unsup.exception.code, "OWNER_CHROME_HIDDEN_COMMAND_UNSUPPORTED")
            self.assertEqual(hub.store.permission_requests(), [])
            hub.dispatch({**auth, "op": "session_close", "request_key": "slow-close-0001"})

            # 4. Wildcard refuses apex and unrelated host; works via MCP Adapter and /agent/v1 EntryAuthority
            class _DirectClient:
                def raw(self, req):
                    try:
                        return {"ok": True, "result": hub.dispatch(req)}
                    except HubError as exc:
                        return {"ok": False, "error_code": exc.code, "message": exc.message, "details": exc.details}

            adapter = Adapter(hub_state, "mcp-agent", client=_DirectClient())
            try:
                caps = adapter.call({"op": "capabilities"})
                gates = caps["operations"]["owner_chrome_hidden"]["consent_gates"]
                self.assertIn("hub_policy", gates)
                self.assertIn("chrome_remote_debugging_dialog", gates)
                tools = mcp_handle(adapter, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                arg_props = tools["result"]["tools"][0]["inputSchema"]["properties"]["args"]["properties"]
                self.assertIn("connect_ws", arg_props)
                self.assertIn("host", arg_props)

                adapter.call({"op": "session_open", "task_id": "mcp-ux-task"})
                # Apex domain is NOT matched by *.example.test
                with self.assertRaises(HubError) as apex_err:
                    adapter.call({
                        "op": "owner_chrome_hidden",
                        "task_id": "mcp-ux-task",
                        "request_key": "mcp-apex-0001",
                        "args": {"command": "open", "url": "https://example.test/"},
                    })
                self.assertEqual(apex_err.exception.code, "PERMISSION_REQUIRED")
                self.assertEqual(apex_err.exception.details["reason"], "HOST_NOT_GRANTED")
                self.assertEqual(apex_err.exception.details["consent_gate"], "hub_policy")

                # Subdomain matches *.example.test cleanly via MCP
                srv.ready_state = "complete"
                pf_mcp = adapter.call({
                    "op": "owner_chrome_hidden",
                    "task_id": "mcp-ux-task",
                    "args": {"command": "preflight", "connect_ws": True, "host": "portal.example.test"},
                })
                self.assertTrue(pf_mcp["ok"], pf_mcp)
                m_open = adapter.call({
                    "op": "owner_chrome_hidden",
                    "task_id": "mcp-ux-task",
                    "request_key": "mcp-sub-0001",
                    "args": {"command": "open", "url": "https://portal.example.test/home"},
                })
                self.assertEqual(m_open["url"], "https://portal.example.test/home")
                m_close = adapter.call({
                    "op": "session_close",
                    "task_id": "mcp-ux-task",
                    "request_key": "mcp-close-0001",
                })
                self.assertTrue(m_close["cleanup_verified"])
            finally:
                adapter.close()

            # /agent/v1 scoped entry also supports site-scoped preflight(connect_ws=True, host=...)
            ea = EntryAuthority(hub_state)
            _, token = ea.issue(
                client_id="c-ux", agent_id="mcp-agent", task_id="entry-ux-task",
                scopes=["owner_chrome_hidden"], apps=[], ttl=180,
            )
            bearer = f"Bearer {token}"
            sid = entry_call(hub, ea, bearer, {"op": "session_open"})["session_id"]
            pf_entry = entry_call(hub, ea, bearer, {
                "op": "owner_chrome_hidden",
                "session_id": sid,
                "args": {"command": "preflight", "connect_ws": True, "host": "portal.example.test"},
            })
            self.assertTrue(pf_entry["ok"], pf_entry)
            self.assertNotIn(ws_secret, json.dumps(pf_entry))
            entry_call(hub, ea, bearer, {"op": "session_close", "session_id": sid, "request_key": "entry-close-001"})
        finally:
            hub.shutdown()
            hub.store.close()
            srv.close()


if __name__ == "__main__":
    unittest.main()
