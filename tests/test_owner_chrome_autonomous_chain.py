"""Production-grade regression and multi-process handover tests for the autonomous owner-Chrome chain.

Covers without touching live owner Chrome, live Hub state, or live Bridge processes:
1. Dynamic `owner_chrome_profile` reload from `state/hub/config.json` without restarting Hub
   or dropping an already-approved CDP WebSocket (including capabilities/status visibility and
   fail-closed invalid profile rejection).
2. Approved CDP keepalive observability (`hub_status` / `owner_chrome_hidden(status)`),
   clean thread teardown on `OWNER_CHROME_CDP_REJECTED`, frame-safe `_LocalWebSocket`
   buffering, and preserving the approved CDP channel when a slow page-session command
   times out (`OWNER_CHROME_CDP_TIMEOUT`, `connection_preserved=True`).
3. Real-world navigation/postcondition race resilience: `navigate` waits for document
   commit marker (`window.__ffhsec_nav`) and tolerates transient execution-context destruction;
   `_check_postcondition` tolerates transient navigation errors and refreshes `url_after`.
4. Strict local-only boundary for WinSock CDP handover RPCs (blocked on Bridge `HubGateway`,
   MCP `Adapter`, and `/agent/v1` `EntryAuthority`).
5. Real two-process Windows `WSADuplicateSocket` (`socket.share` / `socket.fromshare`) Hub
   `handover_upgrade` over HTTP-404 WebSocket-only CDP: proves `new_pid != old_pid`,
   `cdp_handed_over=True`, `len(ws_requests) == 1` across the entire Hub replacement (zero
   new Chrome WebSocket handshake), zero secret leakage in audit/status, busy-Hub refusal,
   abort/rollback recovery, and full post-handover hidden-tab lifecycle + teardown.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "runtime" / "bridge-v3"
sys.path.insert(0, str(PACKAGE))

import cua_owner_chrome_secondary as owner_secondary  # noqa: E402
import ff_browser_routes as routes_mod  # noqa: E402
from cua_universal_fastpath import _LocalWebSocket  # noqa: E402
from ff_agent_entry import EntryAuthority, entry_call  # noqa: E402
from ff_hub import Hub, HubClient, handover_upgrade  # noqa: E402
from ff_hub_mcp import Adapter  # noqa: E402
from ff_hub_permissions import Policy  # noqa: E402
from ff_hub_rpc import HubGateway, HubGatewayError  # noqa: E402
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


class _AdvancedSyntheticHttp404CDPServer:
    """Controlled Chrome 158 HTTP-404 WS-only CDP server with programmable delays & nav races."""

    def __init__(
        self,
        *,
        ws_path: str,
        product: str = "Chrome/158.0.8127.36",
        default_ctx: str = "CTX-DEFAULT",
    ) -> None:
        self.ws_path = ws_path
        self.product = product
        self.default_ctx = default_ctx
        self.ws_requests: list[str] = []
        self.cdp_methods: list[str] = []
        self.targets: dict[str, dict] = {}
        self._sessions: dict[str, str] = {}
        self._seq = 0
        self.stall_eval_once_s = 0.0
        self.nav_stale_polls = 0
        self.nav_destroy_polls = 0
        self.postcond_destroy_polls = 0
        self.click_redirect_url: str | None = None
        self.eval_expressions: list[str] = []
        self._pending_nav: dict[str, dict] = {}
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self.port = int(self._sock.getsockname()[1])
        self._sock.listen(16)
        self._sock.settimeout(0.1)
        self._threads: list[threading.Thread] = []
        self._accept_thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> "_AdvancedSyntheticHttp404CDPServer":
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
            req_path = lines[0].split(" ")[1] if lines and len(lines[0].split(" ")) >= 2 else ""
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            if headers.get("upgrade", "").lower() != "websocket":
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            self.ws_requests.append(req_path)
            if req_path != self.ws_path:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
                    for tid in self.targets:
                        infos.append({"type": "page", "targetId": tid, "browserContextId": self.default_ctx})
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"targetInfos": infos}}))
                elif method == "Target.createTarget":
                    self._seq += 1
                    tid = f"HIDDEN-{self._seq}"
                    self.targets[tid] = {"url": str(params.get("url") or "about:blank"), "title": "", "text": ""}
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"targetId": tid}}))
                elif method == "Browser.getWindowForTarget":
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
                    next_url = str(params.get("url") or "about:blank")
                    if tid in self.targets:
                        if self.nav_stale_polls > 0 or self.nav_destroy_polls > 0:
                            self._pending_nav[tid] = {
                                "url": next_url,
                                "title": f"Title {next_url}",
                                "stale_left": self.nav_stale_polls,
                                "destroy_left": self.nav_destroy_polls,
                            }
                        else:
                            self.targets[tid]["url"] = next_url
                            if next_url.rstrip("/") == "https://example.com":
                                self.targets[tid]["title"] = "Example Domain"
                                self.targets[tid]["text"] = "Example Domain"
                            else:
                                self.targets[tid]["title"] = f"Title {next_url}"
                                self.targets[tid]["text"] = f"Body {next_url}"
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"frameId": "F1"}}))
                elif method == "Runtime.evaluate":
                    tid = self._sessions.get(sid or "", "")
                    rec = self.targets.get(tid, {"url": "about:blank", "title": "", "text": ""})
                    expr = str(params.get("expression") or "")
                    self.eval_expressions.append(expr)
                    if self.stall_eval_once_s > 0 and "STALL_PROBE" in expr:
                        delay = self.stall_eval_once_s
                        self.stall_eval_once_s = 0.0
                        self._stop.wait(delay)
                        _ws_send_text(conn, json.dumps({"id": rid, "result": {"result": {"value": "late"}}}))
                        continue
                    if "window.__ffhsec_nav=" in expr:
                        _ws_send_text(conn, json.dumps({"id": rid, "result": {"result": {"value": True}}}))
                        continue
                    if "document.readyState" in expr and "navigated:window.__ffhsec_nav" in expr:
                        pend = self._pending_nav.get(tid)
                        if pend is not None:
                            if pend["stale_left"] > 0:
                                pend["stale_left"] -= 1
                                val = {"rs": "complete", "url": rec["url"], "title": rec["title"], "navigated": False}
                                _ws_send_text(conn, json.dumps({"id": rid, "result": {"result": {"value": val}}}))
                                continue
                            if pend["destroy_left"] > 0:
                                pend["destroy_left"] -= 1
                                _ws_send_text(conn, json.dumps({"id": rid, "error": {"code": -32000, "message": "Execution context was destroyed."}}))
                                continue
                            rec["url"] = pend["url"]
                            rec["title"] = pend["title"]
                            rec["text"] = f"Body {pend['url']}"
                            self._pending_nav.pop(tid, None)
                        val = {"rs": "complete", "url": rec["url"], "title": rec["title"], "navigated": True}
                        _ws_send_text(conn, json.dumps({"id": rid, "result": {"result": {"value": val}}}))
                        continue
                    if "document.readyState" in expr:
                        val = {"rs": "complete", "url": rec["url"], "title": rec["title"]}
                    elif "acted:true" in expr:
                        old_url = rec["url"]
                        if self.click_redirect_url:
                            rec["url"] = self.click_redirect_url
                            rec["title"] = f"Title {self.click_redirect_url}"
                            rec["text"] = f"Body {self.click_redirect_url}"
                            self.click_redirect_url = None
                        val = {"acted": True, "url": old_url, "title": rec["title"], "detail": {"mode": "dom-click"}}
                    elif "location.href.includes(" in expr:
                        if self.postcond_destroy_polls > 0:
                            self.postcond_destroy_polls -= 1
                            _ws_send_text(conn, json.dumps({"id": rid, "error": {"code": -32000, "message": "Execution context was destroyed."}}))
                            continue
                        m_start = expr.find("location.href.includes(") + len("location.href.includes(")
                        needle = json.loads(expr[m_start:-1])
                        val = needle in rec["url"]
                    elif "({url:location.href,title:document.title})" in expr:
                        val = {"url": rec["url"], "title": rec["title"]}
                    elif "({url:location.href})" in expr:
                        val = {"url": rec["url"]}
                    elif "document.body" in expr and "Example Domain" in expr and ".includes(" in expr:
                        # The hidden target has textContent but no rendered innerText.
                        # Require the explicit textContent fallback; the old expression stays false.
                        val = "textContent" in expr and "visible.trim()" in expr
                    elif 'document.querySelector("h1")' in expr:
                        has_fallback = "textContent" in expr and "visible.trim()" in expr
                        val = {
                            "url": rec["url"],
                            "title": rec["title"],
                            "text": "Example Domain" if has_fallback else "",
                            "found": True,
                            "tag_name": "H1",
                            "text_source": "textContent" if has_fallback else "innerText",
                        }
                    else:
                        val = {"url": rec["url"], "title": rec["title"], "text": rec["text"]}
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"result": {"value": val}}}))
                elif method == "Target.closeTarget":
                    tid = str(params.get("targetId") or "")
                    removed = self.targets.pop(tid, None) is not None
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


def _write_profile_state(udd: Path, port: int, ws_path: str, *, active_profile: str = "Default") -> None:
    (udd / "DevToolsActivePort").write_text(f"{port}\n{ws_path}\n", encoding="ascii")
    (udd / "Local State").write_text(
        json.dumps({"profile": {"last_used": active_profile, "last_active_profiles": [active_profile]}}),
        encoding="utf-8",
    )


class OwnerChromeAutonomousChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ff-auto-chain-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_hidden_read_uses_text_content_when_inner_text_is_empty_and_cleans_up(self) -> None:
        ws_secret = "/devtools/browser/secret-hidden-read-text-fallback"
        srv = _AdvancedSyntheticHttp404CDPServer(ws_path=ws_secret).start()
        udd = self.root / "udd-read-text"
        udd.mkdir()
        _write_profile_state(udd, srv.port, ws_secret, active_profile="Default")
        hub_state = self.root / "hub-read-text"
        hub_state.mkdir()
        Policy(hub_state / "policy.json").add_grant(
            ["owner_chrome_hidden_secondary"],
            agents=["chatgpt-gpt6-owner-browser"],
            note="scoped owner browser read test",
        )
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(
            hub_state,
            profile_dir_name="Default",
            user_data_dir=udd,
        )
        hub = Hub(hub_state, owner_chrome_secondary=mgr)
        try:
            sess = hub.dispatch({
                "op": "session_open",
                "args": {"agent_id": "chatgpt-gpt6-owner-browser", "task_id": "read-text-fallback"},
            })
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}
            opened = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "request_key": "read-text-open-0001",
                "args": {"command": "open", "url": "https://example.com/"},
            })
            self.assertTrue(opened["hidden"])
            self.assertTrue(opened["windowless"])
            self.assertFalse(opened["visible_window_created"])
            self.assertEqual(opened["profile_dir_name"], "Default")
            self.assertEqual(opened["title"], "Example Domain")
            tab_id = opened["tab_id"]

            ready = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "args": {
                    "command": "wait_for",
                    "tab_id": tab_id,
                    "timeout_ms": 1000,
                    "condition": {"text_present": "Example Domain"},
                },
            })
            self.assertTrue(ready["satisfied"])

            read = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "args": {"command": "read", "tab_id": tab_id, "selector": "h1"},
            })
            self.assertEqual(read["text"], "Example Domain")
            self.assertTrue(read["found"])
            self.assertEqual(read["tag_name"], "H1")
            self.assertEqual(read["text_source"], "textContent")
            self.assertTrue(any(
                'document.querySelector("h1")' in expression
                and "visible.trim()" in expression
                and "textContent" in expression
                for expression in srv.eval_expressions
            ))

            closed = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "request_key": "read-text-close-0001",
                "args": {"command": "close", "tab_id": tab_id},
            })
            self.assertTrue(closed["target_closed_in_browser"])
            self.assertEqual(srv.targets, {})

            session_closed = hub.dispatch({
                **auth,
                "op": "session_close",
                "request_key": "read-text-session-close-0001",
            })
            self.assertTrue(session_closed["cleanup_verified"])
            self.assertEqual(session_closed["resources_retained"], 0)
        finally:
            hub.shutdown()
            hub.store.close()
            srv.close()

    def test_dynamic_config_profile_reload_preserves_approved_cdp_socket(self) -> None:
        ws_secret = "/devtools/browser/secret-dynamic-profile-reload"
        srv = _AdvancedSyntheticHttp404CDPServer(ws_path=ws_secret).start()
        udd = self.root / "udd-dyn"
        udd.mkdir()
        _write_profile_state(udd, srv.port, ws_secret, active_profile="Default")
        hub_state = self.root / "hub-dyn"
        hub_state.mkdir()
        Policy(hub_state / "policy.json").add_grant(
            ["owner_chrome_hidden_secondary", "browser_script"],
            agents=["chatgpt-gpt6-owner-browser"],
            note="standing owner delegation",
        )
        # Start Hub with Profile 1 (simulating live prod started before config.json edit)
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(
            hub_state,
            profile_dir_name="Profile 1",
            user_data_dir=udd,
        )
        hub = Hub(hub_state, owner_chrome_secondary=mgr)
        try:
            sess = hub.dispatch({"op": "session_open", "args": {"agent_id": "chatgpt-gpt6-owner-browser", "task_id": "dyn-task"}})
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}

            # Establish approved CDP channel explicitly on Default first
            pf0 = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "args": {"command": "preflight", "connect_ws": True, "profile_dir_name": "Default"},
            })
            self.assertTrue(pf0["ok"], pf0)
            self.assertEqual(len(srv.ws_requests), 1)

            # Before config.json update, implicit route_plan defaults to Profile 1 -> mismatch, socket preserved
            with patch.object(routes_mod, "probe_playwright", return_value={"ok": False, "probe_ms": 0, "reason": "NO_PW"}), \
                 patch.object(routes_mod.apps, "resolve", return_value={"found": False}):
                rp_before = hub.dispatch({
                    "op": "route_plan",
                    "args": {"surface": "browser", "capability": "owner_profile_hidden", "agent_id": "chatgpt-gpt6-owner-browser"},
                })
            self.assertIsNone(rp_before["selected"])
            self.assertEqual(rp_before["fallback_refused_reason"], "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH")
            self.assertTrue(mgr._cdp.connected())

            # Now owner updates state/hub/config.json to Default WITHOUT restarting Hub
            (hub_state / "config.json").write_text(json.dumps({"owner_chrome_profile": "Default"}), encoding="utf-8")

            caps = hub.dispatch({"op": "capabilities"})
            self.assertEqual(caps["browser_routes"]["owner_chrome_configured_profile"], "Default")
            self.assertEqual(caps["operations"]["owner_chrome_hidden"]["configured_profile"], "Default")
            st = hub.dispatch({"op": "hub_status"})
            self.assertEqual(st["owner_chrome_secondary"]["profile_dir_name"], "Default")
            self.assertTrue(st["owner_chrome_secondary"]["connected"])
            self.assertTrue(st["owner_chrome_secondary"]["keepalive_active"])
            self.assertNotIn(ws_secret, json.dumps(st))

            # Implicit route_plan, site_read, and owner_chrome_hidden open now automatically use Default!
            with patch.object(routes_mod, "probe_playwright", return_value={"ok": False, "probe_ms": 0, "reason": "NO_PW"}), \
                 patch.object(routes_mod.apps, "resolve", return_value={"found": False}):
                rp_after = hub.dispatch({
                    "op": "route_plan",
                    "args": {"surface": "browser", "capability": "owner_profile_hidden", "agent_id": "chatgpt-gpt6-owner-browser"},
                })
                rp_read = hub.dispatch({
                    "op": "route_plan",
                    "args": {
                        "surface": "browser",
                        "capability": "background_tab_read",
                        "agent_id": "chatgpt-gpt6-owner-browser",
                        "url": "https://portal.example.test/home",
                        "visibility": "strict_invisible",
                    },
                })
            self.assertEqual(rp_after["selected"], owner_secondary.ROUTE_NAME)
            self.assertEqual(rp_read["selected"], owner_secondary.ROUTE_NAME)

            opened = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "request_key": "dyn-open-default-0001",
                "args": {"command": "open", "url": "https://portal.example.test/home"},
            })
            self.assertEqual(opened["profile_dir_name"], "Default")
            self.assertEqual(len(srv.ws_requests), 1)

            closed = hub.dispatch({**auth, "op": "session_close", "request_key": "dyn-close-default-0001"})
            self.assertTrue(closed["cleanup_verified"])
            self.assertEqual(closed["resources_retained"], 0)
            self.assertEqual(len(srv.ws_requests), 1)

            # Fail-closed on invalid config.json profile
            (hub_state / "config.json").write_text(json.dumps({"owner_chrome_profile": "../escape"}), encoding="utf-8")
            with self.assertRaises(HubError) as bad_cfg:
                hub.configured_owner_chrome_profile()
            self.assertEqual(bad_cfg.exception.code, "OWNER_CHROME_PROFILE_INVALID")
        finally:
            hub.shutdown()
            hub.store.close()
            srv.close()

    def test_page_timeout_preserves_approved_cdp_and_nav_postcondition_races_recover(self) -> None:
        ws_secret = "/devtools/browser/secret-timeout-and-nav-race"
        srv = _AdvancedSyntheticHttp404CDPServer(ws_path=ws_secret).start()
        udd = self.root / "udd-race"
        udd.mkdir()
        _write_profile_state(udd, srv.port, ws_secret, active_profile="Default")
        hub_state = self.root / "hub-race"
        hub_state.mkdir()
        (hub_state / "config.json").write_text(json.dumps({"owner_chrome_profile": "Default"}), encoding="utf-8")
        Policy(hub_state / "policy.json").add_grant(
            ["owner_chrome_hidden_secondary", "browser_script"],
            agents=["chatgpt-gpt6-owner-browser"],
            note="standing owner delegation",
        )
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(hub_state, profile_dir_name="Default", user_data_dir=udd)
        hub = Hub(hub_state, owner_chrome_secondary=mgr)
        try:
            sess = hub.dispatch({"op": "session_open", "args": {"agent_id": "chatgpt-gpt6-owner-browser", "task_id": "race-task"}})
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}
            opened = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "request_key": "race-open-0001",
                "args": {"command": "open", "url": "https://app.example.test/page1"},
            })
            tab_id = opened["tab_id"]
            self.assertEqual(len(srv.ws_requests), 1)

            # 1. Slow page-level evaluate times out, but browser CDP socket MUST stay alive!
            srv.stall_eval_once_s = 1.2
            with self.assertRaises(HubError) as tout:
                hub.dispatch({
                    **auth,
                    "op": "owner_chrome_hidden",
                    "request_key": "race-eval-timeout-0001",
                    "args": {"command": "evaluate", "tab_id": tab_id, "expression": "'STALL_PROBE'", "timeout_s": 0.5},
                })
            self.assertEqual(tout.exception.code, "OWNER_CHROME_CDP_TIMEOUT")
            self.assertTrue(tout.exception.details.get("connection_preserved"))
            self.assertTrue(mgr._cdp.connected())
            self.assertEqual(len(srv.ws_requests), 1)

            # Subsequent command succeeds on the SAME approved socket without reconnect
            read_ok = hub.dispatch({**auth, "op": "owner_chrome_hidden", "args": {"command": "read", "tab_id": tab_id}})
            self.assertEqual(read_ok["url"], "https://app.example.test/page1")
            self.assertEqual(len(srv.ws_requests), 1)

            # 2. Navigate with 2 stale old-page polls + 2 execution-context-destroyed errors MUST wait for page2
            srv.nav_stale_polls = 2
            srv.nav_destroy_polls = 2
            nav = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "request_key": "race-nav-page2-0001",
                "args": {"command": "navigate", "tab_id": tab_id, "url": "https://app.example.test/page2"},
            })
            self.assertTrue(nav["navigated"])
            self.assertEqual(nav["url"], "https://app.example.test/page2")
            self.assertEqual(nav["title"], "Title https://app.example.test/page2")

            # 3. Click triggers navigation + 2 transient execution-context-destroyed errors during postcondition wait
            srv.click_redirect_url = "https://app.example.test/submitted"
            srv.postcond_destroy_polls = 2
            acted = hub.dispatch({
                **auth,
                "op": "owner_chrome_hidden",
                "request_key": "race-click-nav-0001",
                "args": {
                    "command": "act",
                    "tab_id": tab_id,
                    "operation": "click",
                    "selector": "#submit",
                    "postcondition": {"type": "url_contains", "value": "/submitted"},
                },
            })
            self.assertTrue(acted["acted"])
            self.assertTrue(acted["verified"])
            self.assertEqual(acted["url_after"], "https://app.example.test/submitted")
            self.assertTrue(acted["navigated"])
            self.assertEqual(len(srv.ws_requests), 1)

            closed = hub.dispatch({**auth, "op": "session_close", "request_key": "race-close-0001"})
            self.assertTrue(closed["cleanup_verified"])
            self.assertEqual(closed["resources_retained"], 0)
        finally:
            hub.shutdown()
            hub.store.close()
            srv.close()

    def test_keepalive_cleans_up_on_rejected_and_local_only_handover_blocked_remotely(self) -> None:
        # Keepalive thread must clear _keepalive_stop if Browser.getVersion is rejected without reset
        client = owner_secondary._BrowserCDPClient()
        class _DummyWS:
            frame_dirty = False
            def close(self):
                pass
        client.socket = _DummyWS()
        client.endpoint = "ws://127.0.0.1:1/devtools/browser/test"
        client.generation = 1
        with patch.object(client, "KEEPALIVE_INTERVAL_S", 0.02), patch.object(
            client, "send", side_effect=owner_secondary.OwnerChromeSecondaryError("OWNER_CHROME_CDP_REJECTED", "denied")
        ):
            client.start_keepalive()
            dl = time.monotonic() + 1.0
            while client._keepalive_stop is not None and time.monotonic() < dl:
                time.sleep(0.01)
            self.assertIsNone(client._keepalive_stop)
            self.assertEqual(client.last_keepalive_error, "OWNER_CHROME_CDP_REJECTED")
            client.reset()

        # Bridge HubGateway, MCP Adapter, and /agent/v1 MUST all block local-only handover ops
        bridge_root = self.root / "bridge-gw"
        (bridge_root / "state").mkdir(parents=True)
        (bridge_root / "state" / "universal-agent-runtime.json").write_text(
            json.dumps({"version": 1, "enabled": True}), encoding="utf-8"
        )
        gw = HubGateway(bridge_root, starter=lambda _s: None)
        for op in ("hub_cdp_handover_export", "hub_cdp_handover_adopt", "hub_cdp_handover_commit",
                   "hub_cdp_handover_abort", "hub_standby_activate", "hub_standby_status"):
            with self.subTest(gateway_op=op):
                with self.assertRaises(HubGatewayError) as exc:
                    gw.call({"op": op, "args": {}})
                self.assertEqual(exc.exception.code, "HUB_OP_LOCAL_ONLY")

        hub_state = self.root / "hub-sec"
        hub = Hub(hub_state)
        try:
            adapter = Adapter(hub_state, "test-mcp", client=object())
            with self.assertRaises(HubError) as m_err:
                adapter.call({"op": "hub_cdp_handover_export", "args": {}})
            self.assertEqual(m_err.exception.code, "MCP_ARGUMENTS_INVALID")
            adapter.close()

            auth_entry = EntryAuthority(hub_state)
            _, token = auth_entry.issue(
                client_id="c1", agent_id="a1", task_id="t1",
                scopes=["owner_chrome_hidden"], apps=[], ttl=300,
            )
            with self.assertRaises(HubError) as e_err:
                entry_call(hub, auth_entry, f"Bearer {token}", {"op": "hub_cdp_handover_export", "args": {}})
            self.assertEqual(e_err.exception.code, "ENTRY_SCOPE_DENIED")
        finally:
            hub.shutdown()
            hub.store.close()

    @unittest.skipUnless(os.name == "nt", "Windows WinSock WSADuplicateSocket handover")
    def test_real_two_process_windows_cdp_socket_handover_zero_reapproval(self) -> None:
        ws_secret = "/devtools/browser/secret-wsaduplicatesocket-handover"
        srv = _AdvancedSyntheticHttp404CDPServer(ws_path=ws_secret).start()
        udd = self.root / "udd-ho"
        udd.mkdir()
        _write_profile_state(udd, srv.port, ws_secret, active_profile="Default")
        hub_state = self.root / "hub-ho"
        hub_state.mkdir()

        # Find a free loopback port for our isolated Hub pair
        probe_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe_sock.bind(("127.0.0.1", 0))
        hub_port = int(probe_sock.getsockname()[1])
        probe_sock.close()

        (hub_state / "config.json").write_text(
            json.dumps({
                "port": hub_port,
                "owner_chrome_profile": "Default",
                "owner_chrome_user_data_dir": str(udd),
            }),
            encoding="utf-8",
        )
        Policy(hub_state / "policy.json").add_grant(
            ["owner_chrome_hidden_secondary", "browser_script"],
            agents=["chatgpt-gpt6-owner-browser"],
            note="standing owner delegation for handover test",
        )
        policy_sha_before = hashlib.sha256((hub_state / "policy.json").read_bytes()).hexdigest()

        hub_a = subprocess.Popen(
            [sys.executable, str(PACKAGE / "ff_hub.py"), "serve", "--state-dir", str(hub_state), "--port", str(hub_port)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(PACKAGE),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        client = HubClient(hub_state, timeout=15.0)
        try:
            dl = time.monotonic() + 15.0
            while time.monotonic() < dl:
                try:
                    st_a = client.call("hub_status")
                    if st_a.get("pid") == hub_a.pid:
                        break
                except HubError:
                    time.sleep(0.05)
            else:
                raise AssertionError("Hub A failed to start")

            # 1. Open, read, close hidden tab on Hub A -> 1 approved WS connection established
            sess1 = client.call("session_open", {"agent_id": "chatgpt-gpt6-owner-browser", "task_id": "pre-handover"})
            open1 = client.call(
                "owner_chrome_hidden",
                {"command": "open", "url": "https://portal.example.test/before"},
                request_key="ho-pre-open-0001",
            )
            self.assertEqual(open1["profile_dir_name"], "Default")
            self.assertEqual(len(srv.ws_requests), 1)

            # 2. Busy Hub MUST refuse handover_upgrade before spawning/breaking anything
            with self.assertRaises(HubError) as busy_err:
                handover_upgrade(hub_state, PACKAGE, port=hub_port, python=sys.executable)
            self.assertEqual(busy_err.exception.code, "HUB_BUSY")

            close1 = client.call("session_close", {}, request_key="ho-pre-close-0001")
            self.assertTrue(close1["cleanup_verified"])
            self.assertEqual(close1["resources_retained"], 0)
            client.session = None

            st_before = client.call("hub_status")
            self.assertTrue(st_before["owner_chrome_secondary"]["connected"])
            self.assertTrue(st_before["owner_chrome_secondary"]["keepalive_active"])

            # 3. Abort/rollback check: export + abort keeps Hub A connected with keepalive restored
            exp_bad = client.call("hub_cdp_handover_export", {"target_pid": os.getpid()})
            self.assertEqual(exp_bad["schema"], "ff-cdp-socket-handover-v1")
            aborted = client.call("hub_cdp_handover_abort", {})
            self.assertTrue(aborted["aborted"])
            self.assertTrue(aborted["connected"])
            self.assertTrue(aborted["keepalive_active"])

            # 4. Perform REAL two-process handover upgrade via CLI: Hub A -> Hub B!
            ho_proc = subprocess.run(
                [
                    sys.executable,
                    str(PACKAGE / "ff_hub.py"),
                    "--state-dir",
                    str(hub_state),
                    "handover-upgrade",
                    "--new-runtime",
                    str(PACKAGE),
                    "--port",
                    str(hub_port),
                    "--python",
                    sys.executable,
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.assertEqual(ho_proc.returncode, 0, f"stdout={ho_proc.stdout}\nstderr={ho_proc.stderr}")
            receipt = json.loads(ho_proc.stdout)
            new_hub_pid = int(receipt["new_pid"])
            self.assertTrue(receipt["upgraded"])
            self.assertEqual(receipt["old_pid"], hub_a.pid)
            self.assertNotEqual(new_hub_pid, hub_a.pid)
            self.assertEqual(receipt["port"], hub_port)
            self.assertTrue(receipt["cdp_handed_over"])
            self.assertTrue(receipt["owner_chrome_secondary"]["connected"])
            self.assertTrue(receipt["owner_chrome_secondary"]["keepalive_active"])
            self.assertEqual(receipt["owner_chrome_secondary"]["profile_dir_name"], "Default")
            self.assertNotIn(ws_secret, json.dumps(receipt))

            # CRITICAL INVARIANT: STILL ONLY 1 WEBSOCKET HANDSHAKE ACROSS BOTH HUB PROCESSES!
            self.assertEqual(len(srv.ws_requests), 1)

            # 5. Drive hidden tab on NEW Hub B without any new WebSocket handshake!
            client.call("session_open", {"agent_id": "chatgpt-gpt6-owner-browser", "task_id": "post-handover"})
            open2 = client.call(
                "owner_chrome_hidden",
                {"command": "open", "url": "https://portal.example.test/after"},
                request_key="ho-post-open-0001",
            )
            self.assertEqual(open2["url"], "https://portal.example.test/after")
            self.assertEqual(open2["profile_dir_name"], "Default")
            read2 = client.call("owner_chrome_hidden", {"command": "read", "tab_id": open2["tab_id"]})
            self.assertIn("https://portal.example.test/after", read2["text"])
            close2 = client.call("session_close", {}, request_key="ho-post-close-0001")
            self.assertTrue(close2["cleanup_verified"])
            self.assertEqual(close2["resources_retained"], 0)
            self.assertEqual(close2["owner_chrome_hidden_targets_closed"], 1)
            client.session = None

            # STILL ONLY 1 WEBSOCKET HANDSHAKE!
            self.assertEqual(len(srv.ws_requests), 1)

            # Policy untouched and audit never leaks ws_secret or raw socket share
            self.assertEqual(hashlib.sha256((hub_state / "policy.json").read_bytes()).hexdigest(), policy_sha_before)
            audit_raw = (hub_state / "hub.db").read_bytes()
            self.assertNotIn(ws_secret.encode("ascii"), audit_raw)
            self.assertNotIn(b"socket_share_b64", audit_raw)
        finally:
            active_pid = None
            try:
                active_pid = int(client.endpoint().get("pid") or 0)
            except Exception:
                pass
            try:
                client.session = None
                client.call("hub_shutdown_idle")
            except Exception:
                pass
            if active_pid:
                from ff_hub import _pid_alive
                wait_dl = time.monotonic() + 8.0
                while _pid_alive(active_pid) and time.monotonic() < wait_dl:
                    time.sleep(0.05)
            for proc in (hub_a,):
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
                for stream in (proc.stdout, proc.stderr):
                    if stream:
                        try:
                            stream.close()
                        except OSError:
                            pass
            srv.close()

    @unittest.skipUnless(os.name == "nt", "Windows real isolated Chrome 158 Default handover test")
    def test_real_isolated_chrome158_default_handover_and_full_form_chain(self) -> None:
        """Prove real Chrome 158 (Default profile) survives Hub-to-Hub WSADuplicateSocket handover + full form E2E."""
        import ctypes
        from ctypes import wintypes as wt
        import html as html_lib
        import http.server
        import cua_hidden_chrome as hidden_chrome
        from cua_sidecar_supervisor import _bind_windows_kill_on_close_job, _close_windows_job_handle
        from ff_hub import _pid_alive

        from types import SimpleNamespace
        chrome_exe = hidden_chrome.chrome_path()
        if not chrome_exe:
            if os.environ.get("FF_REQUIRE_CHROME_158") == "1":
                self.fail("FF_REQUIRE_CHROME_158=1 requires installed Google Chrome >= 158.0.8127.2")
            self.skipTest("Google Chrome executable not found")
        chrome_ver = hidden_chrome.chrome_binary_version(chrome_exe)
        if chrome_ver is None:
            self.fail(f"Could not read PE version metadata from {chrome_exe}")
        if not owner_secondary._version_at_least(chrome_ver, owner_secondary.MIN_HIDDEN_TARGET_CHROME):
            got = ".".join(str(x) for x in chrome_ver)
            req = ".".join(str(x) for x in owner_secondary.MIN_HIDDEN_TARGET_CHROME)
            if os.environ.get("FF_REQUIRE_CHROME_158") == "1":
                self.fail(f"FF_REQUIRE_CHROME_158=1 requires Chrome >= {req}, found {got} at {chrome_exe}")
            self.skipTest(f"Installed Chrome binary {got} < required {req}")

        # Ephemeral local form + page2 server
        form_state: dict = {"submissions": [], "stored": {"name": "", "role": "viewer", "agree": False, "tier": "basic"}}

        class FormHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def _send(self, code: int, ct: str, body: bytes) -> None:
                self.send_response(code)
                self.send_header("Content-Type", ct)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if self.path == "/form":
                    s = form_state["stored"]
                    page = f"""<!doctype html><html><head><meta charset="utf-8"><title>Isolated Default Form</title></head><body>
                    <form id="f">
                      <label for="name">Name</label><input id="name" type="text" value="{html_lib.escape(s['name'], quote=True)}"/>
                      <label for="role">Role</label><select id="role">
                        <option value="viewer"{' selected' if s['role']=='viewer' else ''}>Viewer</option>
                        <option value="engineer"{' selected' if s['role']=='engineer' else ''}>Engineer</option>
                      </select>
                      <input id="agree" type="checkbox"{' checked' if s['agree'] else ''}/>
                      <input id="tier-basic" name="tier" type="radio" value="basic"{' checked' if s['tier']=='basic' else ''}/>
                      <input id="tier-pro" name="tier" type="radio" value="pro"{' checked' if s['tier']=='pro' else ''}/>
                      <button id="save-btn" type="submit">Save</button>
                    </form>
                    <a id="p2" href="/page2">Page2</a>
                    <div id="banner">READY</div>
                    <script>
                      document.getElementById('f').addEventListener('submit', async (ev) => {{
                        ev.preventDefault();
                        const payload = {{
                          name: document.getElementById('name').value,
                          role: document.getElementById('role').value,
                          agree: document.getElementById('agree').checked,
                          tier: (document.querySelector('input[name="tier"]:checked')||{{}}).value || ''
                        }};
                        const r = await fetch('/api/save', {{method:'POST', headers:{{'Content-Type':'application/json'}}, body:JSON.stringify(payload)}});
                        const d = await r.json();
                        document.getElementById('banner').textContent = 'SAVED:' + d.count + ':' + d.stored.name + ':' + d.stored.role + ':' + d.stored.agree + ':' + d.stored.tier;
                      }});
                    </script></body></html>""".encode("utf-8")
                    self._send(200, "text/html; charset=utf-8", page)
                elif self.path == "/page2":
                    self._send(200, "text/html; charset=utf-8", b"<!doctype html><html><head><title>Page 2</title></head><body><h1>NAV_PAGE_TWO_OK</h1></body></html>")
                elif self.path == "/owner":
                    self._send(200, "text/html; charset=utf-8", b"<!doctype html><html><head><title>Owner Primary</title></head><body><h1>OWNER_TAB</h1></body></html>")
                else:
                    self._send(404, "text/plain", b"404")

            def do_POST(self) -> None:
                if self.path == "/api/save":
                    n = int(self.headers.get("Content-Length", "0"))
                    payload = json.loads(self.rfile.read(n).decode("utf-8"))
                    form_state["stored"] = payload
                    form_state["submissions"].append(payload)
                    body = json.dumps({"ok": True, "count": len(form_state["submissions"]), "stored": payload}).encode("utf-8")
                    self._send(200, "application/json", body)
                else:
                    self._send(404, "text/plain", b"404")

        form_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FormHandler)
        form_srv.daemon_threads = True
        threading.Thread(target=form_srv.serve_forever, daemon=True).start()
        base_url = f"http://127.0.0.1:{form_srv.server_port}"

        # HTTP-404 /json/version + WebSocket passthrough facade in front of real isolated Chrome 158
        class _Passthrough404Proxy:
            def __init__(self, target_port: int, ws_path: str) -> None:
                self.target_port = target_port
                self.ws_path = ws_path
                self.ws_upgrade_count = 0
                self._stop = threading.Event()
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._sock.bind(("127.0.0.1", 0))
                self.port = int(self._sock.getsockname()[1])
                self._sock.listen(16)
                self._sock.settimeout(0.1)
                self._conns: list[socket.socket] = []
                self._t = threading.Thread(target=self._serve, daemon=True)

            def start(self):
                self._t.start()
                return self

            def close(self):
                self._stop.set()
                try:
                    self._sock.close()
                except OSError:
                    pass
                for c in list(self._conns):
                    try:
                        c.close()
                    except OSError:
                        pass
                self._t.join(timeout=2.0)

            def _serve(self):
                while not self._stop.is_set():
                    try:
                        conn, _ = self._sock.accept()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
                    self._conns.append(conn)
                    threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

            def _handle(self, cli: socket.socket):
                up = None
                try:
                    cli.settimeout(5.0)
                    raw = bytearray()
                    while b"\r\n\r\n" not in raw and len(raw) < 16384:
                        chunk = cli.recv(4096)
                        if not chunk:
                            return
                        raw.extend(chunk)
                    head_b, _, rest = raw.partition(b"\r\n\r\n")
                    head_text = head_b.decode("latin1", "replace")
                    if "upgrade: websocket" not in head_text.lower():
                        cli.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        return
                    self.ws_upgrade_count += 1
                    up = socket.create_connection(("127.0.0.1", self.target_port), timeout=5.0)
                    self._conns.append(up)
                    # Rewrite Host header to target_port for Chrome DevTools validation
                    lines = head_text.split("\r\n")
                    rewritten = [lines[0]]
                    for ln in lines[1:]:
                        if ln.lower().startswith("host:"):
                            rewritten.append(f"Host: 127.0.0.1:{self.target_port}")
                        else:
                            rewritten.append(ln)
                    up.sendall(("\r\n".join(rewritten) + "\r\n\r\n").encode("latin1") + bytes(rest))
                    cli.settimeout(None)
                    up.settimeout(None)

                    def pipe(src: socket.socket, dst: socket.socket):
                        try:
                            while not self._stop.is_set():
                                data = src.recv(65536)
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

                    t1 = threading.Thread(target=pipe, args=(cli, up), daemon=True)
                    t2 = threading.Thread(target=pipe, args=(up, cli), daemon=True)
                    t1.start()
                    t2.start()
                    t1.join()
                    t2.join()
                except OSError:
                    pass
                finally:
                    for s in (cli, up):
                        if s is not None:
                            try:
                                s.close()
                            except OSError:
                                pass

        u32 = ctypes.WinDLL("user32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        u32.CreateDesktopW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.c_void_p]
        u32.CreateDesktopW.restype = wt.HANDLE
        u32.CloseDesktop.argtypes = [wt.HANDLE]
        u32.GetForegroundWindow.restype = wt.HWND
        desktop_name = f"FF_AutoHO_{secrets.token_hex(4)}"
        desktop = u32.CreateDesktopW(desktop_name, None, None, 0, 0x01FF, None)
        if not desktop:
            form_srv.shutdown()
            form_srv.server_close()
            self.skipTest("CreateDesktopW unavailable in this session")

        synth_ud = self.root / "real-c158-udd"
        proxy_ud = self.root / "real-c158-proxy-udd"
        hub_state = self.root / "real-c158-hub"
        bridge_root = self.root / "real-c158-bridge"
        synth_ud.mkdir()
        proxy_ud.mkdir()
        hub_state.mkdir()
        (bridge_root / "state").mkdir(parents=True)
        (bridge_root / "state" / "universal-agent-runtime.json").write_text(
            json.dumps({"version": 1, "enabled": True}), encoding="utf-8"
        )

        k32.CreateProcessW.argtypes = [
            wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wt.BOOL, wt.DWORD,
            ctypes.c_void_p, wt.LPCWSTR,
            ctypes.POINTER(hidden_chrome._WinStartupInfo),
            ctypes.POINTER(hidden_chrome._WinProcessInfo),
        ]
        k32.CreateProcessW.restype = wt.BOOL
        k32.ResumeThread.argtypes = [wt.HANDLE]
        k32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
        k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
        k32.CloseHandle.argtypes = [wt.HANDLE]

        si = hidden_chrome._WinStartupInfo()
        si.cb = ctypes.sizeof(hidden_chrome._WinStartupInfo)
        si.lpDesktop = "winsta0\\" + desktop_name
        si.dwFlags = 1
        si.wShowWindow = 4
        pi = hidden_chrome._WinProcessInfo()
        cmdline = subprocess.list2cmdline([
            str(chrome_exe),
            f"--user-data-dir={synth_ud}",
            "--profile-directory=Default",
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            f"{base_url}/owner",
        ])
        hproc = None
        job = None
        proxy = None
        hub_a = None
        client = HubClient(hub_state, timeout=20.0)
        try:
            fg_before = int(u32.GetForegroundWindow() or 0)
            ok = k32.CreateProcessW(
                None, ctypes.create_unicode_buffer(cmdline),
                None, None, False, 0x08000004, None, str(synth_ud),
                ctypes.byref(si), ctypes.byref(pi),
            )
            self.assertTrue(bool(ok), "CreateProcessW failed for isolated Chrome 158")
            hproc = pi.hProcess
            job = _bind_windows_kill_on_close_job(SimpleNamespace(pid=int(pi.pid)))
            k32.ResumeThread(pi.hThread)
            k32.CloseHandle(pi.hThread)

            marker = synth_ud / "DevToolsActivePort"
            local_state = synth_ud / "Local State"
            dl = time.monotonic() + 20.0
            while time.monotonic() < dl and (not marker.is_file() or not local_state.is_file()):
                time.sleep(0.05)
            self.assertTrue(marker.is_file(), "Isolated Chrome 158 did not write DevToolsActivePort")
            time.sleep(0.4)
            lines = marker.read_text(encoding="ascii").splitlines()
            real_port, real_ws_path = int(lines[0]), lines[1].strip()

            proxy = _Passthrough404Proxy(real_port, real_ws_path).start()
            (proxy_ud / "DevToolsActivePort").write_text(f"{proxy.port}\n{real_ws_path}\n", encoding="ascii")
            ls_data = json.loads(local_state.read_text(encoding="utf-8"))
            ls_data.setdefault("profile", {})["last_used"] = "Default"
            ls_data["profile"]["last_active_profiles"] = ["Default"]
            (proxy_ud / "Local State").write_text(json.dumps(ls_data), encoding="utf-8")

            probe_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            probe_s.bind(("127.0.0.1", 0))
            hub_port = int(probe_s.getsockname()[1])
            probe_s.close()

            (hub_state / "config.json").write_text(
                json.dumps({
                    "port": hub_port,
                    "owner_chrome_profile": "Default",
                    "owner_chrome_user_data_dir": str(proxy_ud),
                }),
                encoding="utf-8",
            )
            Policy(hub_state / "policy.json").add_grant(
                ["owner_chrome_hidden_secondary", "browser_script"],
                agents=["chatgpt-gpt6-owner-browser"],
                note="isolated Default standing delegation",
            )

            hub_a = subprocess.Popen(
                [sys.executable, str(PACKAGE / "ff_hub.py"), "serve", "--state-dir", str(hub_state), "--port", str(hub_port)],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(PACKAGE), creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            dl = time.monotonic() + 15.0
            while time.monotonic() < dl:
                try:
                    if client.call("hub_status").get("pid") == hub_a.pid:
                        break
                except HubError:
                    time.sleep(0.05)
            else:
                raise AssertionError("Hub A failed to start")

            # Establish ONE approved WebSocket to real Chrome 158 Default via Hub A
            client.call("session_open", {"agent_id": "chatgpt-gpt6-owner-browser", "task_id": "real-c158-boot"})
            pf = client.call("owner_chrome_hidden", {"command": "preflight", "connect_ws": True})
            self.assertTrue(pf["ok"], pf)
            self.assertEqual(pf["profile_dir_name"], "Default")
            self.assertEqual(proxy.ws_upgrade_count, 1)
            client.call("session_close", {}, request_key="real-c158-boot-close")
            client.session = None

            # Upgrade Hub A -> Hub B via real WSADuplicateSocket handover!
            ho = subprocess.run(
                [
                    sys.executable, str(PACKAGE / "ff_hub.py"), "--state-dir", str(hub_state),
                    "handover-upgrade", "--new-runtime", str(PACKAGE), "--port", str(hub_port), "--python", sys.executable,
                ],
                capture_output=True, text=True, encoding="utf-8", timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            self.assertEqual(ho.returncode, 0, f"stdout={ho.stdout}\nstderr={ho.stderr}")
            ho_res = json.loads(ho.stdout)
            self.assertTrue(ho_res["cdp_handed_over"])
            self.assertNotEqual(ho_res["new_pid"], hub_a.pid)
            self.assertEqual(proxy.ws_upgrade_count, 1)

            # Drive full form + navigation + reload + idempotency through Bridge HubGateway -> NEW Hub B -> REAL Chrome 158!
            gw = HubGateway(bridge_root, client_factory=lambda _s: HubClient(hub_state, timeout=20.0), starter=lambda _s: None)
            # This isolated fixture routes the gateway to a nonstandard Hub
            # state root. Signing and verifying must use the SAME state root;
            # the production Bridge always derives both from BRIDGE_ROOT/state/hub.
            gw.state_dir = hub_state
            sess = gw.call({"op": "session_open", "args": {"agent_id": "chatgpt-gpt6-owner-browser", "task_id": "real-c158-form"}})
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}
            opened = gw.call({
                **auth, "op": "owner_chrome_hidden", "request_key": "rc158-open-0001",
                "args": {"command": "open", "url": f"{base_url}/form"},
            })
            tab_id = opened["tab_id"]
            self.assertEqual(opened["profile_dir_name"], "Default")
            self.assertTrue(opened["hidden"] and opened["windowless"])
            self.assertFalse(opened["visible_window_created"])
            self.assertFalse(opened["owner_tab_strip_modified"])

            gw.call({**auth, "op": "owner_chrome_hidden", "request_key": "rc158-fill-0001",
                     "args": {"command": "act", "tab_id": tab_id, "operation": "fill", "selector": "#name", "value": "Autonomous Default"}})
            gw.call({**auth, "op": "owner_chrome_hidden", "request_key": "rc158-sel-0001",
                     "args": {"command": "act", "tab_id": tab_id, "operation": "select", "selector": "#role", "value": "engineer"}})
            gw.call({**auth, "op": "owner_chrome_hidden", "request_key": "rc158-chk-0001",
                     "args": {"command": "act", "tab_id": tab_id, "operation": "check", "selector": "#agree"}})
            gw.call({**auth, "op": "owner_chrome_hidden", "request_key": "rc158-rad-0001",
                     "args": {"command": "act", "tab_id": tab_id, "operation": "check", "selector": "#tier-pro"}})
            save_req = {
                **auth, "op": "owner_chrome_hidden", "request_key": "rc158-save-0001",
                "args": {
                    "command": "act", "tab_id": tab_id, "operation": "click", "selector": "#save-btn",
                    "postcondition": {"type": "text_includes", "value": "SAVED:1:Autonomous Default:engineer:true:pro"},
                },
            }
            s1 = gw.call(save_req)
            s2 = gw.call(save_req)
            self.assertFalse(s1["deduplicated"])
            self.assertTrue(s2["deduplicated"])
            self.assertEqual(len(form_state["submissions"]), 1)

            rel = gw.call({**auth, "op": "owner_chrome_hidden", "request_key": "rc158-rel-0001",
                           "args": {"command": "reload", "tab_id": tab_id}})
            self.assertTrue(rel["reloaded"])
            r_name = gw.call({**auth, "op": "owner_chrome_hidden", "args": {"command": "read", "tab_id": tab_id, "selector": "#name"}})
            self.assertEqual(r_name["value"], "Autonomous Default")

            # Click link navigation with postcondition (tests navigation race resilience on real Chrome 158!)
            lnk = gw.call({
                **auth, "op": "owner_chrome_hidden", "request_key": "rc158-link-0001",
                "args": {
                    "command": "act", "tab_id": tab_id, "operation": "click", "selector": "#p2",
                    "postcondition": {"type": "text_includes", "value": "NAV_PAGE_TWO_OK"},
                },
            })
            self.assertTrue(lnk["verified"])
            self.assertIn("/page2", lnk["url_after"])
            self.assertTrue(lnk["navigated"])

            # Navigate back to /form cleanly
            nav_back = gw.call({
                **auth, "op": "owner_chrome_hidden", "request_key": "rc158-nav-0001",
                "args": {"command": "navigate", "tab_id": tab_id, "url": f"{base_url}/form"},
            })
            self.assertIn("/form", nav_back["url"])

            closed = gw.call({**auth, "op": "session_close", "request_key": "rc158-close-0001"})
            self.assertTrue(closed["cleanup_verified"])
            self.assertEqual(closed["resources_retained"], 0)
            self.assertEqual(closed["owner_chrome_hidden_targets_closed"], 1)

            # STILL EXACTLY 1 WEBSOCKET HANDSHAKE ACROSS BOTH HUB PROCESSES ON REAL CHROME 158!
            self.assertEqual(proxy.ws_upgrade_count, 1)
            self.assertEqual(int(u32.GetForegroundWindow() or 0), fg_before)
        finally:
            active_pid = None
            try:
                active_pid = int(client.endpoint().get("pid") or 0)
            except Exception:
                pass
            try:
                client.session = None
                client.call("hub_shutdown_idle")
            except Exception:
                pass
            if active_pid:
                wait_dl = time.monotonic() + 8.0
                while _pid_alive(active_pid) and time.monotonic() < wait_dl:
                    time.sleep(0.05)
            if hub_a is not None:
                try:
                    hub_a.wait(timeout=5)
                except Exception:
                    hub_a.kill()
                for stream in (hub_a.stdout, hub_a.stderr):
                    if stream:
                        try:
                            stream.close()
                        except OSError:
                            pass
            if proxy is not None:
                proxy.close()
            if job is not None:
                _close_windows_job_handle(job)
            if hproc:
                k32.TerminateProcess(hproc, 1)
                k32.WaitForSingleObject(hproc, 5000)
                k32.CloseHandle(hproc)
            u32.CloseDesktop(desktop)
            form_srv.shutdown()
            form_srv.server_close()


if __name__ == "__main__":
    unittest.main()
