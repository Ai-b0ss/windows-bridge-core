"""Tests for the user-facing no-interruption read-only site workflow.

Covers without touching live Hub state, live Chrome, or live extension permissions:
1. Actual manifest audit: FF Browser Companion 0.1.1 declares only `downloads` and
   `nativeMessaging` and is never advertised or selected as a browser page reader.
2. Strict visibility distinction: ordinary background-tab requests (`visibility="background_tab"`)
   vs strict invisibility (`visibility="strict_invisible"` / `strict_invisibility=True`);
   never substitutes a visible tab (`owner_chrome_extension`) when strict invisibility is requested.
3. Strict provider verification: selects an existing supported provider ONLY when authorization,
   live connection, background open without activation, read access, and ownership are verified.
4. One actionable capability result before any UI, WebSocket connect, browser launch, or pending
   Hub permission request when no eligible provider exists; preserves all permissions and settings.
5. Two consecutive read-only tasks and verified teardown on real synthetic loopback HTTP pages via:
   - real Node.js `ff_browser_hub.mjs` (`BrowserHub` + `tab-ledger.json` -> `owner_chrome_extension`),
   - synthetic Chrome 158 HTTP-404 loopback CDP (`owner_chrome_profile1_hidden_secondary`),
   - MCP Adapter (`ff_hub_mcp.py`), `/agent/v1` scoped entry (`ff_agent_entry.py`), and
     user-facing CLI (`ff_hub.py site-read`).
"""
from __future__ import annotations

import base64
import hashlib
import html
import http.server
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "runtime" / "bridge-v3"
sys.path.insert(0, str(PACKAGE))

import cua_owner_chrome_secondary as owner_secondary  # noqa: E402
import ff_browser_routes as routes_mod  # noqa: E402
from cua_agent_workflows import agent_workflows  # noqa: E402
from cua_bridge_v3 import CuaBridgeControlPlane  # noqa: E402
from ff_agent_entry import EntryAuthority, entry_call  # noqa: E402
from ff_hub import Hub, HubHTTPServer, make_handler, process_creation_token  # noqa: E402
from ff_hub_mcp import Adapter, handle as mcp_handle  # noqa: E402
from ff_hub_permissions import Policy  # noqa: E402
from ff_hub_store import HubError  # noqa: E402

_WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _loopback_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _start_synthetic_site_server() -> tuple[http.server.ThreadingHTTPServer, threading.Thread, int]:
    """Serve two distinct synthetic HTML pages plus a cross-host redirect on loopback."""
    hits: list[str] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args) -> None:
            return

        def do_GET(self) -> None:
            hits.append(self.path)
            if self.path == "/site-alpha":
                body = (
                    "<!doctype html><html><head><title>Synthetic Alpha Page</title></head>"
                    "<body><h1>Alpha Report</h1><p id='payload'>ALPHA-PAYLOAD-42</p></body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/site-beta":
                body = (
                    "<!doctype html><html><head><title>Synthetic Beta Page</title></head>"
                    "<body><h1>Beta Report</h1><p id='payload'>BETA-PAYLOAD-99</p></body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/redirect-other":
                port = self.server.server_port
                self.send_response(302)
                self.send_header("Location", f"http://localhost:{port}/forbidden-secret")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/forbidden-secret":
                body = (
                    "<!doctype html><html><head><title>Unauthorized Host</title></head>"
                    "<body><p>UNAUTHORIZED-HOST-CONTENT-DO-NOT-LEAK</p></body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.hits = hits  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, int(server.server_port)


def _fetch_html_summary(url: str) -> tuple[str, str, str]:
    """Fetch a synthetic loopback page and extract (final_url, title, body_text)."""
    with _loopback_opener().open(url, timeout=5.0) as resp:
        final_url = resp.geturl()
        raw = resp.read(65536).decode("utf-8", "replace")
    m_title = re.search(r"<title>(.*?)</title>", raw, re.IGNORECASE | re.DOTALL)
    title = html.unescape(m_title.group(1)).strip() if m_title else ""
    text = html.unescape(re.sub(r"<[^>]+>", " ", re.sub(r"<head.*?</head>", "", raw, flags=re.IGNORECASE | re.DOTALL)))
    text = re.sub(r"\s+", " ", text).strip()
    return final_url, title, text


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


class _SyntheticCDPServer:
    """Loopback Chrome 158 CDP server that loads real synthetic loopback pages."""

    def __init__(
        self,
        *,
        ws_path: str,
        http_status: int = 404,
        product: str = "Chrome/158.0.8127.36",
        default_ctx: str = "CTX-DEFAULT",
    ) -> None:
        self.ws_path = ws_path
        self.http_status = http_status
        self.product = product
        self.default_ctx = default_ctx
        self.http_requests: list[str] = []
        self.ws_requests: list[str] = []
        self.cdp_methods: list[str] = []
        self.targets: dict[str, dict] = {}
        self.primary_targets: list[str] = ["PRIMARY-OWNER-0"]
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

    def start(self) -> "_SyntheticCDPServer":
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
            if not lines or len(lines[0].split(" ")) < 2:
                return
            req_path = lines[0].split(" ")[1]
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            if headers.get("upgrade", "").lower() != "websocket":
                self.http_requests.append(req_path)
                if self.http_status == 200 and req_path == "/json/version":
                    body = json.dumps({
                        "Browser": self.product,
                        "webSocketDebuggerUrl": f"ws://127.0.0.1:{self.port}{self.ws_path}",
                    }).encode("utf-8")
                    conn.sendall(
                        f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii") + body
                    )
                else:
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
                    infos = [{"type": "page", "targetId": pid, "browserContextId": self.default_ctx} for pid in self.primary_targets]
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
                    url = str(params.get("url") or "about:blank")
                    if tid in self.targets:
                        if url.startswith(("http://127.0.0.1:", "http://localhost:")):
                            final_url, title, text = _fetch_html_summary(url)
                        else:
                            final_url, title, text = url, f"Title {url}", f"Synthetic body {url}"
                        self.targets[tid] = {"url": final_url, "title": title, "text": text}
                    _ws_send_text(conn, json.dumps({"id": rid, "result": {"frameId": "F1"}}))
                elif method == "Runtime.evaluate":
                    tid = self._sessions.get(sid or "", "")
                    rec = self.targets.get(tid, {"url": "about:blank", "title": "", "text": ""})
                    expr = str(params.get("expression") or "")
                    if "document.readyState" in expr:
                        val = {"rs": "complete", "url": rec["url"], "title": rec["title"]}
                    elif "window.__ffhsec=" in expr:
                        val = {"url": rec["url"], "title": rec["title"], "text": rec["text"], "controls": []}
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


class _RealNodeBrowserHubHarness:
    """Runs the REAL ff_browser_hub.mjs BrowserHub HTTP server with a synthetic HTTP-fetching page adapter."""

    _SCRIPT = r"""
import {EventEmitter} from 'node:events';
import fs from 'node:fs';
import {pathToFileURL} from 'node:url';

const hubModUrl = pathToFileURL(process.argv[2]).href;
const ledgerFile = process.argv[3];
const key = process.env.SYNTH_HUB_KEY;
const {BrowserHub, serve} = await import(hubModUrl);

let targetSeq = 0;
let bringToFrontCalls = 0;
let disconnectOnNextClose = false;
const createdPages = [];

class SyntheticFetchPage extends EventEmitter {
  constructor(url = 'about:blank') {
    super();
    this._url = url;
    this._title = '';
    this._text = '';
    this._closed = false;
    this.targetId = `SYNTH-EXT-TARGET-${String(++targetSeq).padStart(4, '0')}`;
  }
  isClosed() { return this._closed; }
  url() { return this._url; }
  mainFrame() { return this; }
  async title() { return this._title; }
  async bringToFront() { bringToFrontCalls++; }
  async goto(targetUrl) {
    const resp = await fetch(targetUrl, {redirect: 'follow'});
    const raw = await resp.text();
    this._url = resp.url || targetUrl;
    const titleMatch = raw.match(/<title>([\s\S]*?)<\/title>/i);
    this._title = titleMatch ? titleMatch[1].trim() : '';
    const withoutHead = raw.replace(/<head[\s\S]*?<\/head>/i, '');
    this._text = withoutHead.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
    this.emit('framenavigated', this);
  }
  async close() {
    if (disconnectOnNextClose) {
      disconnectOnNextClose = false;
      browser.connected = false;
      browser.emit('disconnected');
      this._closed = true;
      this.emit('close');
      return;
    }
    this._closed = true;
    this.emit('close');
  }
  locator(selector) {
    const page = this;
    return {
      count: async () => 1,
      evaluate: async () => page._text,
      ariaSnapshot: async () => `- document "${page._title}":\n  - text: "${page._text}"`,
    };
  }
  async evaluate(fn) {
    const src = String(fn);
    if (src.includes('visibilityState')) return 'hidden';
    return this._text;
  }
}

class SyntheticBrowser extends EventEmitter {
  constructor() {
    super();
    this.connected = true;
  }
  isConnected() { return this.connected; }
  async close() { this.connected = false; this.emit('disconnected'); }
}

const foreignOwnerPage = new SyntheticFetchPage('https://owner-work.invalid/dashboard');
const browser = new SyntheticBrowser();
const context = new EventEmitter();
const livePages = [foreignOwnerPage];
context.pages = () => livePages.filter(p => !p.isClosed());
context.newPage = async () => {
  const page = new SyntheticFetchPage('about:blank');
  livePages.push(page);
  createdPages.push(page);
  context.emit('page', page);
  return page;
};
context.newCDPSession = async page => ({
  send: async () => ({targetInfo: {targetId: page.targetId}}),
  detach: async () => {},
});

const connector = {
  describe: () => ({
    transport: 'playwright-extension',
    extension_id: 'mmlmfjhmonkocbjadbfplnigmagldckm',
    extension_permissions: ['activeTab', 'debugger', 'storage', 'tabGroups', 'tabs'],
    playwright: '1.65.1',
    background: true,
    activates_tab: false,
    read_supported: true,
    ownership_supported: true,
    hidden_secondary_window_supported: false,
    visible_tab_strip: true,
    owner_profile: 'Default',
    profile_pinned: true,
    isolated_profile: false,
  }),
  async connect() {
    browser.connected = true;
    return {browser, context};
  },
};

const hub = new BrowserHub(connector, {ledgerFile});
await hub.connect();

const origDispatch = hub.dispatch.bind(hub);
hub.dispatch = (op, args) => {
  if (op === '__test_telemetry') {
    return {
      bring_to_front_calls: bringToFrontCalls,
      foreign_owner_page_closed: foreignOwnerPage.isClosed(),
      created_pages_total: createdPages.length,
      created_pages_open: createdPages.filter(p => !p.isClosed()).length,
    };
  }
  if (op === '__test_arm_disconnect_on_close') {
    disconnectOnNextClose = true;
    return {armed: true};
  }
  return origDispatch(op, args);
};

const server = await serve(hub, {key, port: 0, onShutdown: () => setTimeout(() => process.exit(0), 100)});
process.stdout.write(JSON.stringify({port: server.address().port, pid: process.pid}) + '\n');
"""

    def __init__(self, state_dir: Path) -> None:
        self.state_dir = state_dir
        self.ledger_file = state_dir / "tab-ledger.json"
        self.key = secrets.token_urlsafe(36)
        self.proc: subprocess.Popen[str] | None = None
        self.port: int | None = None

    def start(self) -> "_RealNodeBrowserHubHarness":
        node = shutil.which("node")
        if not node:
            raise unittest.SkipTest("Node.js not installed")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        script_file = self.state_dir / "run_synth_browser_hub.mjs"
        script_file.write_text(self._SCRIPT, encoding="utf-8")
        self.proc = subprocess.Popen(
            [node, str(script_file), str(PACKAGE / "ff_browser_hub.mjs"), str(self.ledger_file)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env={**os.environ, "SYNTH_HUB_KEY": self.key},
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"Synthetic BrowserHub failed to start: {err}")
        info = json.loads(line)
        self.port = int(info["port"])
        return self

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def call(self, op: str, args: dict | None = None, *, timeout: float = 15.0) -> dict:
        assert self.port is not None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/rpc",
            method="POST",
            data=json.dumps({"op": op, "args": args or {}}).encode("utf-8"),
            headers={"content-type": "application/json", "x-ff-browser-key": self.key},
        )
        with _loopback_opener().open(req, timeout=timeout) as resp:
            reply = json.loads(resp.read().decode("utf-8"))
        if reply.get("ok"):
            return reply["result"]
        raise HubError(reply.get("error_code") or "BROWSER_ERROR", reply.get("message"), **(reply.get("details") or {}))

    def stop(self, *, close_tabs: bool = True) -> None:
        proc = self.proc
        self.proc = None
        if proc is None:
            return
        if proc.poll() is None and self.port is not None:
            try:
                self.call("shutdown", {"close_tabs": close_tabs}, timeout=5.0)
            except Exception:
                pass
        try:
            proc.wait(timeout=5.0)
        except Exception:
            proc.kill()
            proc.wait(timeout=3.0)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream:
                    stream.close()
            except OSError:
                pass


class _StubExtensionBrowser:
    """Configurable in-memory browser manager for negative provider verification tests."""

    def __init__(self, *, running: bool = True, status_payload: dict | None = None) -> None:
        self._running = running
        self.status_payload = status_payload if status_payload is not None else {
            "connected": True,
            "stopping": False,
            "circuit_open": False,
            "route": {
                "transport": "playwright-extension",
                "extension_id": "mmlmfjhmonkocbjadbfplnigmagldckm",
                "extension_permissions": ["activeTab", "debugger", "storage", "tabGroups", "tabs"],
                "background": True,
                "activates_tab": False,
                "read_supported": True,
                "ownership_supported": True,
                "hidden_secondary_window_supported": False,
                "visible_tab_strip": True,
                "owner_profile": "Default",
                "isolated_profile": False,
            },
            "tab_ledger": {"enabled": True, "error": None},
            "limits": {"maxTabsPerOwner": 8, "maxTabs": 32},
        }
        self.calls: list[tuple[str, dict]] = []

    def running(self) -> bool:
        return self._running

    def stop(self, *, close_tabs: bool = True) -> None:
        self._running = False

    def call(self, op: str, args: dict | None = None, *, timeout: float = 15.0) -> dict:
        self.calls.append((op, dict(args or {})))
        if op == "status":
            return dict(self.status_payload)
        if op == "tab_list":
            return {"tabs": []}
        if op == "tab_close_owner":
            return {"closed": 0, "unconfirmed": [], "errors": []}
        raise AssertionError(f"Unexpected browser call {op!r} when provider should be ineligible")


class NoInterruptionSiteReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ff-site-read-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_actual_companion_manifest_never_advertised_as_page_reader(self) -> None:
        # Consult the actual checked-in manifest.json on disk.
        raw_manifest = json.loads((PACKAGE / "browser_companion" / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(raw_manifest["name"], "FF Browser Companion")
        self.assertEqual(raw_manifest["version"], "0.1.1")
        self.assertEqual(sorted(raw_manifest["permissions"]), ["downloads", "nativeMessaging"])
        self.assertNotIn("host_permissions", raw_manifest)

        comp = routes_mod.inspect_companion_manifest(PACKAGE)
        self.assertTrue(comp["manifest_valid"])
        self.assertEqual(comp["manifest_version"], "0.1.1")
        self.assertEqual(comp["permissions"], ["downloads", "nativeMessaging"])
        self.assertEqual(comp["host_permissions"], [])
        self.assertTrue(comp["downloads_only"])
        self.assertFalse(comp["browser_page_reader"])
        self.assertFalse(comp["page_read_supported"])
        self.assertFalse(comp["tab_open_supported"])
        self.assertFalse(comp["background_tab_supported"])

        diag = routes_mod.inspect_extensions_and_companion(PACKAGE, read_owner_chrome_prefs=False)
        self.assertFalse(diag["companion"]["browser_page_reader"])
        self.assertFalse(diag["companion"]["page_read_supported"])
        self.assertEqual(diag["companion"]["permissions"], ["downloads", "nativeMessaging"])

        wf = agent_workflows()
        self.assertEqual(wf["browser_workflow"]["companion_scope"]["version"], "0.1.1")
        self.assertFalse(wf["browser_workflow"]["companion_scope"]["browser_page_reader"])
        self.assertFalse(wf["browser_workflow"]["companion_scope"]["page_read_supported"])
        self.assertEqual(wf["browser_workflow"]["companion_scope"]["permissions"], ["downloads", "nativeMessaging"])
        self.assertTrue(wf["browser_workflow"]["no_interruption_site_read"]["strict_invisibility_forbids_visible_tab_substitution"])

        bridge = CuaBridgeControlPlane(PACKAGE, state_dir=self.root / "cua-state")
        try:
            health = bridge._companion_health()
        finally:
            bridge.close()
        self.assertFalse(health["browser_page_reader"])
        self.assertFalse(health["page_read_supported"])
        self.assertEqual(health["supported_capabilities"], ["downloads", "nativeMessaging"])

        # Hub capabilities and site_read plan both declare companion non-reader honestly.
        hub_state = self.root / "hub-comp"
        hub = Hub(hub_state, browser=_StubExtensionBrowser(running=False))
        try:
            caps = hub.capabilities()
            self.assertFalse(caps["browser_routes"]["companion_scope"]["browser_page_reader"])
            self.assertFalse(caps["browser_routes"]["companion_scope"]["page_read_supported"])
            self.assertEqual(caps["browser_routes"]["companion_scope"]["permissions"], ["downloads", "nativeMessaging"])

            plan = routes_mod.evaluate_no_interruption_site_read(
                {"agent_id": "reader-agent", "task_id": "t-comp"},
                "https://docs.example.test/page",
                hub=hub,
            )
            comp_excl = next(p for p in plan["excluded_providers"] if p["provider"] == "ff_browser_companion")
            self.assertEqual(comp_excl["manifest_version"], "0.1.1")
            self.assertEqual(comp_excl["permissions"], ["downloads", "nativeMessaging"])
            self.assertFalse(comp_excl["browser_page_reader"])
            self.assertEqual(comp_excl["reason_code"], "COMPANION_DOWNLOADS_AND_NATIVE_MESSAGING_ONLY")
        finally:
            hub.shutdown()
            hub.store.close()

    def test_visibility_distinction_strict_verification_and_single_actionable_result_before_ui_or_pending(self) -> None:
        ws_secret = "/devtools/browser/secret-uuid-no-interruption-check"
        cdp_srv = _SyntheticCDPServer(ws_path=ws_secret, http_status=404).start()
        udd = self.root / "udd-neg"
        udd.mkdir()
        _write_profile_state(udd, cdp_srv.port, ws_secret, active_profile="Default")

        hub_state = self.root / "hub-neg"
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(hub_state, profile_dir_name="Default", user_data_dir=udd)
        ext = _StubExtensionBrowser(running=False)
        hub = Hub(hub_state, browser=ext, owner_chrome_secondary=mgr)
        try:
            sess = hub.dispatch({"op": "session_open", "args": {"agent_id": "reader-agent", "task_id": "task-neg"}})
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}
            target_url = "https://portal.example.test/report"

            # 1. No eligible provider -> ONE actionable capability result, 0 UI, 0 WS, 0 pending requests!
            res = hub.dispatch({**auth, "op": "site_read", "args": {"command": "read", "url": target_url}})
            self.assertFalse(res["ok"])
            self.assertFalse(res["eligible"])
            self.assertFalse(res["executed"])
            self.assertFalse(res["execution_started"])
            self.assertFalse(res["ui_triggered"])
            self.assertFalse(res["prompts_triggered"])
            self.assertFalse(res["pending_request_created"])
            self.assertEqual(res["error_code"], "NO_ELIGIBLE_NO_INTERRUPTION_PROVIDER")
            self.assertEqual(res["visibility_requested"], "background_tab")
            self.assertFalse(res["strict_invisibility"])
            self.assertIsNone(res["selected_provider"])
            self.assertTrue(res["actionable_next_steps"])
            self.assertTrue(res["permissions_preserved"])
            self.assertFalse(res["chrome_settings_modified"])
            self.assertFalse(res["credentials_extracted"])
            self.assertEqual(cdp_srv.ws_requests, [])
            self.assertEqual(ext.calls, [])
            self.assertEqual(hub.store.permission_requests(), [])
            self.assertNotIn(ws_secret, json.dumps(res))

            # 2. When extension IS connected and eligible for background_tab, strict_invisibility STILL refuses substitution!
            ext._running = True
            plan_bg = hub.dispatch({**auth, "op": "site_read", "args": {"command": "plan", "url": target_url, "visibility": "background_tab"}})
            self.assertTrue(plan_bg["eligible"])
            self.assertEqual(plan_bg["selected_provider"], "owner_chrome_extension")
            self.assertTrue(plan_bg["visible_tab_strip"])

            for strict_args in (
                {"command": "read", "url": target_url, "visibility": "strict_invisible"},
                {"command": "read", "url": target_url, "strict_invisibility": True},
            ):
                with self.subTest(strict_args=strict_args):
                    strict_res = hub.dispatch({**auth, "op": "site_read", "args": strict_args})
                    self.assertFalse(strict_res["ok"])
                    self.assertFalse(strict_res["eligible"])
                    self.assertTrue(strict_res["strict_invisibility"])
                    self.assertIsNone(strict_res["selected_provider"])
                    self.assertEqual(strict_res["error_code"], "NO_ELIGIBLE_NO_INTERRUPTION_PROVIDER")
                    ext_info = next(p for p in strict_res["providers"] if p["provider"] == "owner_chrome_extension")
                    self.assertFalse(ext_info["eligible"])
                    self.assertEqual(ext_info["reason_code"], "VISIBLE_TAB_SUBSTITUTION_FORBIDDEN")
                    self.assertTrue(ext_info["visible_tab_strip"])
                    self.assertFalse(ext_info["strict_invisibility_supported"])
            self.assertFalse(any(op == "tab_open" for op, _ in ext.calls))
            self.assertEqual(cdp_srv.ws_requests, [])
            self.assertEqual(hub.store.permission_requests(), [])

            # 3. Every missing verification criterion on owner_chrome_extension fails closed!
            base_status = json.loads(json.dumps(ext.status_payload))
            neg_cases = [
                ("disconnected", lambda s: s.update({"connected": False}), "PROVIDER_NOT_CONNECTED"),
                ("background_false", lambda s: s["route"].update({"background": False}), "BACKGROUND_OPEN_WITHOUT_ACTIVATION_UNVERIFIED"),
                ("activates_tab_true", lambda s: s["route"].update({"activates_tab": True}), "BACKGROUND_OPEN_WITHOUT_ACTIVATION_UNVERIFIED"),
                ("isolated_profile_true", lambda s: s["route"].update({"isolated_profile": True}), "ISOLATED_PROFILE_SUBSTITUTION_FORBIDDEN"),
                ("companion_transport", lambda s: s["route"].update({"transport": "ff_browser_companion"}), "PROVIDER_MANIFEST_PAGE_READ_UNSUPPORTED"),
                ("companion_permissions", lambda s: s["route"].update({"extension_permissions": ["downloads", "nativeMessaging"]}), "PROVIDER_MANIFEST_PAGE_READ_UNSUPPORTED"),
                ("read_unsupported", lambda s: s["route"].update({"read_supported": False}), "READ_ACCESS_UNVERIFIED"),
                ("ledger_disabled", lambda s: s["tab_ledger"].update({"enabled": False}), "OWNERSHIP_UNVERIFIED"),
                ("ledger_error", lambda s: s["tab_ledger"].update({"error": "TAB_LEDGER_UNREADABLE"}), "OWNERSHIP_UNVERIFIED"),
            ]
            for label, mutate, expected_reason in neg_cases:
                with self.subTest(case=label):
                    payload = json.loads(json.dumps(base_status))
                    mutate(payload)
                    ext.status_payload = payload
                    out = hub.dispatch({**auth, "op": "site_read", "args": {"command": "read", "url": target_url}})
                    self.assertFalse(out["ok"])
                    self.assertIsNone(out["selected_provider"])
                    ext_p = next(p for p in out["providers"] if p["provider"] == "owner_chrome_extension")
                    self.assertEqual(ext_p["reason_code"], expected_reason)
            ext.status_payload = base_status

            # Explicit profile mismatch also fails closed
            mismatch = hub.dispatch({
                **auth, "op": "site_read",
                "args": {"command": "read", "url": target_url, "profile_dir_name": "Profile 1"},
            })
            self.assertFalse(mismatch["ok"])
            ext_m = next(p for p in mismatch["providers"] if p["provider"] == "owner_chrome_extension")
            self.assertEqual(ext_m["reason_code"], "OWNER_CHROME_PROFILE_MISMATCH")

            # 4. Policy default='ask' on browser_own_tabs or read_diagnose blocks WITHOUT pending requests!
            hub.policy.set_default("browser_own_tabs", "ask")
            denied_tab = hub.dispatch({**auth, "op": "site_read", "args": {"command": "read", "url": target_url}})
            self.assertFalse(denied_tab["ok"])
            self.assertFalse(denied_tab["pending_request_created"])
            ext_d = next(p for p in denied_tab["providers"] if p["provider"] == "owner_chrome_extension")
            self.assertEqual(ext_d["reason_code"], "NO_MATCHING_GRANT")
            self.assertEqual(ext_d["consent_gate"], "hub_policy")
            self.assertEqual(hub.store.permission_requests(), [])
            hub.policy.set_default("browser_own_tabs", "allow")

            hub.policy.set_default("read_diagnose", "ask")
            denied_read = hub.dispatch({**auth, "op": "site_read", "args": {"command": "read", "url": target_url}})
            self.assertFalse(denied_read["ok"])
            self.assertEqual(hub.store.permission_requests(), [])
            hub.policy.set_default("read_diagnose", "allow")

            # 5. Unconnected HTTP-200 CDP does NOT open a new WS under no-interruption site_read!
            cdp_srv.http_status = 200
            hub.policy.add_grant(["owner_chrome_hidden_secondary"], agents=["reader-agent"], hosts=["portal.example.test"], ttl_seconds=300)
            ext._running = False
            no_ws = hub.dispatch({**auth, "op": "site_read", "args": {"command": "read", "url": target_url, "strict_invisibility": True}})
            self.assertFalse(no_ws["ok"])
            hid_p = next(p for p in no_ws["providers"] if p["provider"] == "owner_chrome_profile1_hidden_secondary")
            self.assertEqual(hid_p["reason_code"], "OWNER_CHROME_CDP_NOT_CONNECTED")
            self.assertEqual(cdp_srv.ws_requests, [])

            # 6. Forbidden / mutating / malformed args fail closed before anything runs
            for bad_args, expected_code in (
                ({"url": ""}, "SITE_URL_REQUIRED"),
                ({"url": "about:blank"}, "URL_SCHEME_FORBIDDEN"),
                ({"url": "chrome://settings"}, "URL_SCHEME_FORBIDDEN"),
                ({"url": "file:///C:/Windows/win.ini"}, "URL_SCHEME_FORBIDDEN"),
                ({"url": "javascript:alert(1)"}, "URL_SCHEME_FORBIDDEN"),
                ({"url": "https://user:pass@portal.example.test/"}, "URL_INVALID"),
                ({"url": target_url, "visibility": "background_tab", "strict_invisibility": True}, "ARGS_INVALID"),
                ({"url": target_url, "visibility": "strict_invisible", "strict_invisibility": False}, "ARGS_INVALID"),
                ({"url": target_url, "foreground": True}, "SITE_READ_ARG_FORBIDDEN"),
                ({"url": target_url, "act": "click"}, "SITE_READ_ARG_FORBIDDEN"),
                ({"url": target_url, "evaluate": "document.cookie"}, "SITE_READ_ARG_FORBIDDEN"),
                ({"url": target_url, "auto_approve": True}, "SITE_READ_ARG_FORBIDDEN"),
                ({"url": target_url, "bypass_permissions": True}, "SITE_READ_ARG_FORBIDDEN"),
                ({"url": target_url, "stealth": True}, "SITE_READ_ARG_FORBIDDEN"),
                ({"url": target_url, "extract_cookies": True}, "SITE_READ_ARG_FORBIDDEN"),
                ({"url": target_url, "copy_profile": True}, "SITE_READ_ARG_FORBIDDEN"),
            ):
                with self.subTest(bad_args=bad_args), self.assertRaises(HubError) as herr:
                    hub.dispatch({**auth, "op": "site_read", "args": bad_args})
                self.assertEqual(herr.exception.code, expected_code)
            self.assertEqual(hub.store.permission_requests(), [])
        finally:
            hub.shutdown()
            hub.store.close()
            cdp_srv.close()

    def test_two_consecutive_tasks_and_teardown_via_real_browser_hub_mjs_extension_provider(self) -> None:
        site_srv, _site_thread, site_port = _start_synthetic_site_server()
        node_hub = _RealNodeBrowserHubHarness(self.root / "node-browser-hub").start()
        hub_state = self.root / "hub-ext-e2e"
        empty_udd = self.root / "empty-udd"
        empty_udd.mkdir()
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(hub_state, profile_dir_name="Default", user_data_dir=empty_udd)
        hub = Hub(hub_state, browser=node_hub, owner_chrome_secondary=mgr)
        try:
            # Scope browser_own_tabs + read_diagnose to 127.0.0.1 explicitly via standing grants
            hub.policy.set_default("browser_own_tabs", "ask")
            hub.policy.add_grant(["browser_own_tabs"], agents=["ext-reader"], hosts=["127.0.0.1"], ttl_seconds=600)

            url_alpha = f"http://127.0.0.1:{site_port}/site-alpha"
            url_beta = f"http://127.0.0.1:{site_port}/site-beta"
            url_redir = f"http://127.0.0.1:{site_port}/redirect-other"

            # Strict invisibility MUST refuse substituting the connected visible-tab extension!
            s_strict = hub.dispatch({"op": "session_open", "args": {"agent_id": "ext-reader", "task_id": "task-strict-refuse"}})
            strict_out = hub.dispatch({
                "session_id": s_strict["session_id"],
                "session_secret": s_strict["session_secret"],
                "op": "site_read",
                "args": {"command": "read", "url": url_alpha, "strict_invisibility": True},
            })
            self.assertFalse(strict_out["ok"])
            self.assertIsNone(strict_out["selected_provider"])
            self.assertEqual(node_hub.call("__test_telemetry")["created_pages_total"], 0)
            hub.dispatch({
                "session_id": s_strict["session_id"],
                "session_secret": s_strict["session_secret"],
                "op": "session_close",
                "request_key": "close-strict-refuse-01",
            })

            # --- Consecutive Task 1: synthetic page alpha (read mode) ---
            s1 = hub.dispatch({"op": "session_open", "args": {"agent_id": "ext-reader", "task_id": "task-ext-1"}})
            r1 = hub.dispatch({
                "session_id": s1["session_id"],
                "session_secret": s1["session_secret"],
                "op": "site_read",
                "request_key": "ext-site-read-task-01",
                "args": {"command": "read", "url": url_alpha, "visibility": "background_tab", "read_mode": "read"},
            })
            self.assertTrue(r1["ok"], r1)
            self.assertEqual(r1["provider"], "owner_chrome_extension")
            self.assertEqual(r1["actual_visibility"], "background_tab")
            self.assertTrue(r1["visible_tab_strip"])
            self.assertFalse(r1["tab_activated"])
            self.assertFalse(r1["prompts_triggered"])
            self.assertFalse(r1["pending_request_created"])
            self.assertEqual(r1["title"], "Synthetic Alpha Page")
            self.assertIn("ALPHA-PAYLOAD-42", r1["text"])
            self.assertTrue(r1["ownership"]["verified"])
            self.assertTrue(r1["ownership"]["durable_identity"])
            self.assertTrue(r1["teardown"]["closed"])
            self.assertTrue(r1["teardown"]["cleanup_verified"])
            self.assertTrue(r1["teardown"]["page_closed_in_browser"])
            self.assertEqual(r1["teardown"]["resources_retained"], 0)
            c1 = hub.dispatch({
                "session_id": s1["session_id"],
                "session_secret": s1["session_secret"],
                "op": "session_close",
                "request_key": "ext-session-close-01",
            })
            self.assertTrue(c1["closed"])
            self.assertTrue(c1["cleanup_verified"])
            self.assertEqual(c1["resources_retained"], 0)

            # --- Consecutive Task 2: synthetic page beta (snapshot mode) ---
            s2 = hub.dispatch({"op": "session_open", "args": {"agent_id": "ext-reader", "task_id": "task-ext-2"}})
            r2 = hub.dispatch({
                "session_id": s2["session_id"],
                "session_secret": s2["session_secret"],
                "op": "site_read",
                "request_key": "ext-site-read-task-02",
                "args": {"command": "read", "url": url_beta, "visibility": "background_tab", "read_mode": "snapshot"},
            })
            self.assertTrue(r2["ok"], r2)
            self.assertEqual(r2["provider"], "owner_chrome_extension")
            self.assertNotEqual(r2["ownership"]["tab_id"], r1["ownership"]["tab_id"])
            self.assertEqual(r2["title"], "Synthetic Beta Page")
            self.assertIn("BETA-PAYLOAD-99", r2["snapshot"])
            self.assertEqual(r2["document_visibility"], "hidden")
            self.assertTrue(r2["teardown"]["cleanup_verified"])
            self.assertEqual(r2["teardown"]["resources_retained"], 0)
            c2 = hub.dispatch({
                "session_id": s2["session_id"],
                "session_secret": s2["session_secret"],
                "op": "session_close",
                "request_key": "ext-session-close-02",
            })
            self.assertTrue(c2["closed"])
            self.assertTrue(c2["cleanup_verified"])
            self.assertEqual(c2["resources_retained"], 0)

            # --- Redirect to unauthorized host ('localhost') fails closed and tears down tab cleanly ---
            s3 = hub.dispatch({"op": "session_open", "args": {"agent_id": "ext-reader", "task_id": "task-ext-redir"}})
            r3 = hub.dispatch({
                "session_id": s3["session_id"],
                "session_secret": s3["session_secret"],
                "op": "site_read",
                "request_key": "ext-site-read-redir",
                "args": {"command": "read", "url": url_redir, "visibility": "background_tab"},
            })
            self.assertFalse(r3["ok"])
            self.assertEqual(r3["error_code"], "REDIRECT_HOST_NOT_GRANTED")
            self.assertTrue(r3["content_withheld"])
            self.assertNotIn("UNAUTHORIZED-HOST-CONTENT-DO-NOT-LEAK", json.dumps(r3))
            self.assertTrue(r3["teardown"]["cleanup_verified"])
            self.assertEqual(r3["teardown"]["resources_retained"], 0)
            hub.dispatch({
                "session_id": s3["session_id"],
                "session_secret": s3["session_secret"],
                "op": "session_close",
                "request_key": "ext-session-close-redir",
            })

            # Verify zero leaks in real tab-ledger.json, zero activations, and foreign owner tab untouched!
            telem = node_hub.call("__test_telemetry")
            self.assertEqual(telem["bring_to_front_calls"], 0)
            self.assertFalse(telem["foreign_owner_page_closed"])
            self.assertEqual(telem["created_pages_total"], 3)
            self.assertEqual(telem["created_pages_open"], 0)
            ledger = json.loads(node_hub.ledger_file.read_text(encoding="utf-8"))
            self.assertEqual(ledger["tabs"], [])
            self.assertEqual(hub.store.resources(), [])
            self.assertEqual(hub.store.permission_requests(), [])

            # --- Unconfirmed teardown (disconnect during close) retains resource fail-closed ---
            node_hub.call("__test_arm_disconnect_on_close")
            s4 = hub.dispatch({"op": "session_open", "args": {"agent_id": "ext-reader", "task_id": "task-ext-unconf"}})
            r4 = hub.dispatch({
                "session_id": s4["session_id"],
                "session_secret": s4["session_secret"],
                "op": "site_read",
                "request_key": "ext-site-read-unconf",
                "args": {"command": "read", "url": url_alpha, "visibility": "background_tab"},
            })
            self.assertTrue(r4["ok"])
            self.assertFalse(r4["teardown"]["closed"])
            self.assertFalse(r4["teardown"]["cleanup_verified"])
            self.assertEqual(r4["teardown"]["resources_retained"], 1)
            self.assertEqual(len(hub.store.resources(session_id=s4["session_id"], kind="browser_tab")), 1)
        finally:
            hub.shutdown()
            hub.store.close()
            node_hub.stop()
            site_srv.shutdown()
            site_srv.server_close()

    def test_two_consecutive_tasks_and_teardown_via_strict_invisible_cdp_provider(self) -> None:
        site_srv, _site_thread, site_port = _start_synthetic_site_server()
        ws_secret = "/devtools/browser/secret-uuid-hidden-e2e"
        cdp_srv = _SyntheticCDPServer(ws_path=ws_secret, http_status=404).start()
        udd = self.root / "udd-hidden"
        udd.mkdir()
        _write_profile_state(udd, cdp_srv.port, ws_secret, active_profile="Default")

        hub_state = self.root / "hub-hidden"
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(hub_state, profile_dir_name="Default", user_data_dir=udd)
        hub = Hub(hub_state, browser=_StubExtensionBrowser(running=False), owner_chrome_secondary=mgr)
        try:
            url_alpha = f"http://127.0.0.1:{site_port}/site-alpha"
            url_beta = f"http://127.0.0.1:{site_port}/site-beta"

            # Before owner grant & owner-approved WS connection: ineligible with 0 WS & 0 pending requests
            s0 = hub.dispatch({"op": "session_open", "args": {"agent_id": "hidden-reader", "task_id": "task-pre"}})
            pre = hub.dispatch({
                "session_id": s0["session_id"],
                "session_secret": s0["session_secret"],
                "op": "site_read",
                "args": {"command": "read", "url": url_alpha, "strict_invisibility": True},
            })
            self.assertFalse(pre["ok"])
            self.assertEqual(cdp_srv.ws_requests, [])
            self.assertEqual(hub.store.permission_requests(), [])

            # Owner grants site-scoped standing permission + connects once explicitly
            grant = hub.policy.add_grant(
                ["owner_chrome_hidden_secondary"],
                agents=["hidden-reader"],
                hosts=["127.0.0.1"],
                ttl_seconds=600,
            )
            pf = hub.dispatch({
                "session_id": s0["session_id"],
                "session_secret": s0["session_secret"],
                "op": "owner_chrome_hidden",
                "args": {"command": "preflight", "connect_ws": True, "host": "127.0.0.1"},
            })
            self.assertTrue(pf["ok"])
            self.assertEqual(len(cdp_srv.ws_requests), 1)
            hub.dispatch({
                "session_id": s0["session_id"],
                "session_secret": s0["session_secret"],
                "op": "session_close",
                "request_key": "close-pre-0001",
            })

            # --- Consecutive Task 1: strict_invisible read of page alpha ---
            s1 = hub.dispatch({"op": "session_open", "args": {"agent_id": "hidden-reader", "task_id": "task-hid-1"}})
            r1 = hub.dispatch({
                "session_id": s1["session_id"],
                "session_secret": s1["session_secret"],
                "op": "site_read",
                "request_key": "hid-site-read-01",
                "args": {"command": "read", "url": url_alpha, "visibility": "strict_invisible", "read_mode": "read"},
            })
            self.assertTrue(r1["ok"], r1)
            self.assertEqual(r1["provider"], "owner_chrome_profile1_hidden_secondary")
            self.assertTrue(r1["windowless"])
            self.assertFalse(r1["visible_tab_strip"])
            self.assertFalse(r1["tab_activated"])
            self.assertFalse(r1["prompts_triggered"])
            self.assertEqual(r1["title"], "Synthetic Alpha Page")
            self.assertIn("ALPHA-PAYLOAD-42", r1["text"])
            self.assertTrue(r1["teardown"]["cleanup_verified"])
            self.assertTrue(r1["teardown"]["target_closed_in_browser"])
            self.assertEqual(r1["teardown"]["resources_retained"], 0)
            self.assertNotIn(ws_secret, json.dumps(r1))
            c1 = hub.dispatch({
                "session_id": s1["session_id"],
                "session_secret": s1["session_secret"],
                "op": "session_close",
                "request_key": "hid-close-01",
            })
            self.assertTrue(c1["cleanup_verified"])
            self.assertEqual(c1["resources_retained"], 0)

            # --- Consecutive Task 2: strict_invisibility=True observe of page beta ---
            s2 = hub.dispatch({"op": "session_open", "args": {"agent_id": "hidden-reader", "task_id": "task-hid-2"}})
            r2 = hub.dispatch({
                "session_id": s2["session_id"],
                "session_secret": s2["session_secret"],
                "op": "site_read",
                "request_key": "hid-site-read-02",
                "args": {"command": "read", "url": url_beta, "strict_invisibility": True, "read_mode": "observe"},
            })
            self.assertTrue(r2["ok"], r2)
            self.assertEqual(r2["provider"], "owner_chrome_profile1_hidden_secondary")
            self.assertNotEqual(r2["ownership"]["tab_id"], r1["ownership"]["tab_id"])
            self.assertEqual(r2["title"], "Synthetic Beta Page")
            self.assertIn("BETA-PAYLOAD-99", r2["text"])
            self.assertTrue(r2["teardown"]["cleanup_verified"])
            self.assertEqual(r2["teardown"]["resources_retained"], 0)
            c2 = hub.dispatch({
                "session_id": s2["session_id"],
                "session_secret": s2["session_secret"],
                "op": "session_close",
                "request_key": "hid-close-02",
            })
            self.assertTrue(c2["cleanup_verified"])
            self.assertEqual(c2["resources_retained"], 0)

            # Single WS reused across both tasks (zero prompts/reconnects), zero leaked hidden targets, primary intact
            self.assertEqual(len(cdp_srv.ws_requests), 1)
            self.assertEqual(cdp_srv.targets, {})
            self.assertEqual(cdp_srv.primary_targets, ["PRIMARY-OWNER-0"])
            self.assertEqual(hub.store.resources(), [])
            self.assertEqual(hub.store.permission_requests(), [])

            # --- Immediate revocation stops Task 3 without creating pending requests or targets ---
            self.assertTrue(hub.policy.revoke(grant["grant_id"]))
            create_before = cdp_srv.cdp_methods.count("Target.createTarget")
            s3 = hub.dispatch({"op": "session_open", "args": {"agent_id": "hidden-reader", "task_id": "task-hid-3"}})
            r3 = hub.dispatch({
                "session_id": s3["session_id"],
                "session_secret": s3["session_secret"],
                "op": "site_read",
                "args": {"command": "read", "url": url_alpha, "strict_invisibility": True},
            })
            self.assertFalse(r3["ok"])
            self.assertEqual(r3["error_code"], "NO_ELIGIBLE_NO_INTERRUPTION_PROVIDER")
            self.assertFalse(r3["pending_request_created"])
            self.assertEqual(cdp_srv.cdp_methods.count("Target.createTarget"), create_before)
            self.assertEqual(hub.store.permission_requests(), [])
            hub.dispatch({
                "session_id": s3["session_id"],
                "session_secret": s3["session_secret"],
                "op": "session_close",
                "request_key": "hid-close-03",
            })
        finally:
            hub.shutdown()
            hub.store.close()
            cdp_srv.close()
            site_srv.shutdown()
            site_srv.server_close()

    def test_mcp_adapter_scoped_entry_and_user_facing_cli_site_read(self) -> None:
        site_srv, _site_thread, site_port = _start_synthetic_site_server()
        node_hub = _RealNodeBrowserHubHarness(self.root / "node-cli-hub").start()
        ws_secret = "/devtools/browser/secret-uuid-cli-entry"
        cdp_srv = _SyntheticCDPServer(ws_path=ws_secret, http_status=404).start()
        udd = self.root / "udd-cli"
        udd.mkdir()
        _write_profile_state(udd, cdp_srv.port, ws_secret, active_profile="Default")

        hub_state = self.root / "hub-cli"
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(hub_state, profile_dir_name="Default", user_data_dir=udd)
        hub = Hub(hub_state, browser=node_hub, owner_chrome_secondary=mgr)

        # Serve Hub over real loopback HTTP so user-facing `ff_hub.py site-read` CLI exercises real HubClient
        hub_key = secrets.token_urlsafe(36)
        (hub_state / "hub.key").write_text(hub_key, encoding="ascii")
        httpd = HubHTTPServer(("127.0.0.1", 0), make_handler(hub, hub_key))
        httpd.daemon_threads = True
        (hub_state / "endpoint.json").write_text(
            json.dumps({
                "version": 1,
                "pid": os.getpid(),
                "create_time": process_creation_token(os.getpid()),
                "port": httpd.server_address[1],
                "started_at": time.time(),
            }),
            encoding="utf-8",
        )
        http_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        http_thread.start()

        try:
            url_alpha = f"http://127.0.0.1:{site_port}/site-alpha"
            url_beta = f"http://127.0.0.1:{site_port}/site-beta"

            # 1. MCP Adapter schema + two consecutive tasks via owner_chrome_extension
            class _DirectClient:
                def raw(self, req):
                    try:
                        return {"ok": True, "result": hub.dispatch(req)}
                    except HubError as exc:
                        return {"ok": False, "error_code": exc.code, "message": exc.message, "details": exc.details}

            adapter = Adapter(hub_state, "mcp-reader", client=_DirectClient())
            try:
                tools = mcp_handle(adapter, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                schema = tools["result"]["tools"][0]["inputSchema"]["properties"]
                self.assertIn("site_read", schema["op"]["enum"])
                for arg_name in ("visibility", "strict_invisibility", "read_mode", "max_chars"):
                    self.assertIn(arg_name, schema["args"]["properties"])

                rp_mcp = adapter.call({
                    "op": "route_plan",
                    "args": {"surface": "browser", "capability": "background_tab_read", "url": url_alpha},
                })
                self.assertEqual(rp_mcp["selected"], "owner_chrome_extension")
                self.assertFalse(rp_mcp["companion"]["browser_page_reader"])

                for idx, (tid, target_url, expected) in enumerate(
                    (("mcp-sr-1", url_alpha, "ALPHA-PAYLOAD-42"), ("mcp-sr-2", url_beta, "BETA-PAYLOAD-99")),
                    start=1,
                ):
                    adapter.call({"op": "session_open", "task_id": tid})
                    out = adapter.call({
                        "op": "site_read",
                        "task_id": tid,
                        "request_key": f"mcp-sr-key-000{idx}",
                        "args": {"command": "read", "url": target_url, "visibility": "background_tab"},
                    })
                    self.assertTrue(out["ok"], out)
                    self.assertIn(expected, out["text"])
                    self.assertTrue(out["teardown"]["cleanup_verified"])
                    closed = adapter.call({"op": "session_close", "task_id": tid, "request_key": f"mcp-sr-cls-000{idx}"})
                    self.assertTrue(closed["cleanup_verified"])
            finally:
                adapter.close()

            # 2. Scoped /agent/v1 entry cannot use owner_chrome_extension even when connected!
            ea = EntryAuthority(hub_state)
            _, tok_hidden = ea.issue(
                client_id="c-sr", agent_id="entry-reader", task_id="entry-sr-1",
                scopes=["owner_chrome_hidden"], apps=[], ttl=300,
            )
            bearer = f"Bearer {tok_hidden}"
            entry_caps = entry_call(hub, ea, bearer, {"op": "capabilities"})
            self.assertIn("site_read", entry_caps["operations"])
            entry_sid = entry_call(hub, ea, bearer, {"op": "session_open"})["session_id"]

            entry_inelig = entry_call(hub, ea, bearer, {
                "op": "site_read", "session_id": entry_sid,
                "args": {"command": "read", "url": url_alpha, "visibility": "background_tab"},
            })
            self.assertFalse(entry_inelig["ok"])
            ext_p = next(p for p in entry_inelig["providers"] if p["provider"] == "owner_chrome_extension")
            self.assertEqual(ext_p["reason_code"], "ENTRY_OWNER_CHROME_FORBIDDEN")

            # After granting owner_chrome_hidden_secondary + connecting WS, scoped entry succeeds via hidden target!
            hub.policy.add_grant(["owner_chrome_hidden_secondary"], agents=["entry-reader"], hosts=["127.0.0.1"], ttl_seconds=300)
            entry_call(hub, ea, bearer, {
                "op": "owner_chrome_hidden", "session_id": entry_sid,
                "args": {"command": "preflight", "connect_ws": True, "host": "127.0.0.1"},
            })
            entry_ok = entry_call(hub, ea, bearer, {
                "op": "site_read", "session_id": entry_sid, "request_key": "entry-sr-ok-01",
                "args": {"command": "read", "url": url_alpha, "visibility": "background_tab"},
            })
            self.assertTrue(entry_ok["ok"], entry_ok)
            self.assertEqual(entry_ok["provider"], "owner_chrome_profile1_hidden_secondary")
            self.assertIn("ALPHA-PAYLOAD-42", entry_ok["text"])
            self.assertTrue(entry_ok["teardown"]["cleanup_verified"])
            entry_call(hub, ea, bearer, {"op": "session_close", "session_id": entry_sid, "request_key": "entry-sr-cls-01"})

            # 3. User-facing CLI `ff_hub.py site-read` (strict ineligible exit 2 vs two consecutive background_tab reads exit 0)
            def run_cli(*cli_args: str) -> tuple[int, dict]:
                proc = subprocess.run(
                    [sys.executable, str(PACKAGE / "ff_hub.py"), "--state-dir", str(hub_state), *cli_args],
                    capture_output=True, text=True, encoding="utf-8", timeout=20,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                return proc.returncode, json.loads((proc.stdout or "{}").strip())

            # Ineligible strict_invisible for cli-user -> exit 2, ONE actionable capability result, zero sessions/pending!
            sessions_before = len(hub.store.sessions(include_closed=True))
            rc_inelig, out_inelig = run_cli(
                "site-read", "--url", url_alpha, "--agent", "cli-user", "--strict-invisibility",
            )
            self.assertEqual(rc_inelig, 2, out_inelig)
            self.assertFalse(out_inelig["ok"])
            self.assertFalse(out_inelig["pending_request_created"])
            self.assertEqual(out_inelig["error_code"], "NO_ELIGIBLE_NO_INTERRUPTION_PROVIDER")
            self.assertEqual(len(hub.store.sessions(include_closed=True)), sessions_before)
            self.assertEqual(hub.store.permission_requests(), [])

            # Two consecutive CLI site-read runs for alpha & beta via connected owner_chrome_extension
            rc1, cli1 = run_cli("site-read", "--url", url_alpha, "--agent", "cli-user", "--visibility", "background_tab")
            self.assertEqual(rc1, 0, cli1)
            self.assertIn("ALPHA-PAYLOAD-42", cli1["text"])
            self.assertTrue(cli1["teardown"]["cleanup_verified"])
            self.assertTrue(cli1["session_cleanup"]["cleanup_verified"])

            rc2, cli2 = run_cli("site-read", "--url", url_beta, "--agent", "cli-user", "--visibility", "background_tab", "--mode", "snapshot")
            self.assertEqual(rc2, 0, cli2)
            self.assertIn("BETA-PAYLOAD-99", cli2["snapshot"])
            self.assertTrue(cli2["teardown"]["cleanup_verified"])
            self.assertTrue(cli2["session_cleanup"]["cleanup_verified"])

            # Verify clean teardown across everything
            self.assertEqual(hub.store.resources(), [])
            self.assertEqual(hub.store.permission_requests(), [])
            self.assertEqual(cdp_srv.targets, {})
            self.assertEqual(json.loads(node_hub.ledger_file.read_text(encoding="utf-8"))["tabs"], [])
            self.assertEqual(node_hub.call("__test_telemetry")["bring_to_front_calls"], 0)
        finally:
            httpd.shutdown()
            httpd.server_close()
            http_thread.join(timeout=5)
            hub.shutdown()
            hub.store.close()
            node_hub.stop()
            cdp_srv.close()
            site_srv.shutdown()
            site_srv.server_close()


if __name__ == "__main__":
    unittest.main()
