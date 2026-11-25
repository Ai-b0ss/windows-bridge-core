"""Form regression fixture & verification tests for supported background form operations.

Continues from the staged no-interruption background read changes and verifies:
1. Policy preservation & route planning (`route_plan(capability="background_tab_form")`),
   strict visibility separation (`background_tab` vs `strict_invisible`), FF Browser Companion
   0.1.1 exclusion, and `site_read` staying strictly read-only.
2. Ownership isolation, foreground refusal (`FOREGROUND_ROUTE_REQUIRED`), mandatory
   `request_key` journaling (`REQUEST_KEY_REQUIRED`), live host-change guard
   (`TAB_HOST_CHANGED`) on `act` and `reload`, and fail-closed form control validation
   (`TARGET_NOT_EDITABLE`, `TARGET_DISABLED`, `OPTION_NOT_FOUND`, `KEY_REQUIRED`).
3. Two consecutive fill/edit/save/reload workflows against a synthetic local loopback form
   via normal Hub APIs (`Hub.dispatch` + MCP `Adapter`) through the REAL Node.js
   `ff_browser_hub.mjs` (`op: "browser"`, `owner_chrome_extension`):
   - Workflow 1: fill text, textarea, select, check checkbox, check radio, save click,
     duplicate `request_key` replay (`deduplicated=True`), `request_status`, `REQUEST_KEY_REUSED`,
     `reload`, verify stored data, clean `session_close`.
   - Workflow 2: consecutive task via MCP `Adapter`, observe WF1 stored data, edit all fields,
     uncheck checkbox, switch radio, save via `press(key="Enter")`, deduplicated replay,
     `reload`, verify stored data, clean `session_close`.
   - Verifies exact 2 submissions (0 duplicates), 0 `bringToFront`, 0 native Playwright input,
     foreign owner tab focus retention (`blur_count=0`), empty `tab-ledger.json`, unchanged
     `policy.json` SHA-256.
4. Two consecutive fill/edit/save/reload workflows against the synthetic local form via
   REAL isolated Chrome 158 (ephemeral `user_data_dir` on a separate private Win32 desktop
   `CreateDesktopW` + HTTP-404 `DevToolsActivePort` WS passthrough proxy) through normal Hub
   APIs (`owner_chrome_hidden` via `Hub.dispatch`, MCP `Adapter`, and `/agent/v1` `entry_call`):
   - Real Chromium DOM/JS/fetch/`Page.reload`, exact 2 submissions (0 duplicates), live
     `TAB_HOST_CHANGED` guard, real Windows OS focus retention (`GetForegroundWindow()`
     unchanged, 0 new HWNDs, 0 visible/taskbar side effects), synthetic primary owner tab
     focus retention (`blur_count=0`, `visibility_change_count=0`), clean teardown, and
     unchanged `policy.json` SHA-256.

Zero live user accounts, zero live owner Chrome profile access, zero browser permission changes.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as wt
import hashlib
import html as html_lib
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "runtime" / "bridge-v3"
sys.path.insert(0, str(PACKAGE))

import cua_hidden_chrome as hidden_chrome  # noqa: E402
import cua_owner_chrome_secondary as owner_secondary  # noqa: E402
import ff_browser_routes as routes_mod  # noqa: E402
from cua_agent_workflows import agent_workflows  # noqa: E402
from cua_sidecar_supervisor import _bind_windows_kill_on_close_job, _close_windows_job_handle  # noqa: E402
from cua_universal_fastpath import _LocalWebSocket  # noqa: E402
from ff_agent_entry import EntryAuthority, entry_call  # noqa: E402
from ff_hub import Hub  # noqa: E402
from ff_hub_mcp import Adapter, handle as mcp_handle  # noqa: E402
from ff_hub_permissions import Policy  # noqa: E402
from ff_hub_store import HubError  # noqa: E402


def _loopback_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _sha256_or_none(path: Path) -> str | None:
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


class _SyntheticFormServer:
    """Loopback synthetic local form application with persistent server store & submission telemetry."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.stored: dict = {
            "revision": 0,
            "title": "",
            "notes": "",
            "priority": "medium",
            "notify": False,
            "mode": "draft",
        }
        self.submissions: list[dict] = []
        self.form_get_count = 0
        self.owner_get_count = 0
        self.owner_loaded = threading.Event()
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args) -> None:
                return

            def _send(self, status: int, content_type: str, body: bytes) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:
                if self.path == "/form":
                    with parent._lock:
                        parent.form_get_count += 1
                        rec = dict(parent.stored)
                    title_attr = html_lib.escape(str(rec["title"]), quote=True)
                    notes_text = html_lib.escape(str(rec["notes"]))
                    prio = str(rec["priority"])
                    notify_attr = " checked" if rec["notify"] else ""
                    draft_attr = " checked" if rec["mode"] == "draft" else ""
                    final_attr = " checked" if rec["mode"] == "final" else ""
                    rec_json_html = html_lib.escape(json.dumps(rec, sort_keys=True))
                    opts = "\n".join(
                        f'        <option value="{val}"{" selected" if prio == val else ""}>{val.title()}</option>'
                        for val in ("low", "medium", "high", "urgent")
                    )
                    page = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>Synthetic Form Regression Fixture</title></head>
<body>
  <h1>Synthetic Form Regression Fixture</h1>
  <form id="record-form">
    <label for="title-input">Title</label>
    <input id="title-input" name="title" type="text" value="{title_attr}" />

    <label for="notes-input">Notes</label>
    <textarea id="notes-input" name="notes">{notes_text}</textarea>

    <label for="priority-select">Priority</label>
    <select id="priority-select" name="priority">
{opts}
    </select>

    <label for="notify-check">Notify</label>
    <input id="notify-check" name="notify" type="checkbox"{notify_attr} />

    <fieldset>
      <label for="mode-draft">Draft Mode</label>
      <input id="mode-draft" name="mode" type="radio" value="draft"{draft_attr} />
      <label for="mode-final">Final Mode</label>
      <input id="mode-final" name="mode" type="radio" value="final"{final_attr} />
    </fieldset>

    <label for="readonly-code">Readonly Code</label>
    <input id="readonly-code" name="readonly_code" type="text" readonly value="LOCKED-CODE" />

    <label for="disabled-field">Disabled Field</label>
    <input id="disabled-field" name="disabled_field" type="text" disabled value="DISABLED-VAL" />

    <button id="save-btn" type="submit">Save Record</button>
    <button id="async-drift-btn" type="button">Async Host Drift</button>
  </form>
  <div id="status-banner">LOADED:rev={rec['revision']}</div>
  <div id="persisted-revision">rev={rec['revision']}</div>
  <div id="client-submit-count">0</div>
  <pre id="persisted-json">{rec_json_html}</pre>
  <script>
    let submitEvents = 0;
    document.getElementById('async-drift-btn').addEventListener('click', () => {{
      setTimeout(() => {{ location.assign('http://localhost:' + location.port + '/other-host'); }}, 30);
    }});
    document.getElementById('record-form').addEventListener('submit', async (ev) => {{
      ev.preventDefault();
      submitEvents += 1;
      document.getElementById('client-submit-count').textContent = String(submitEvents);
      const modeEl = document.querySelector('input[name="mode"]:checked');
      const payload = {{
        title: document.getElementById('title-input').value,
        notes: document.getElementById('notes-input').value,
        priority: document.getElementById('priority-select').value,
        notify: document.getElementById('notify-check').checked,
        mode: modeEl ? modeEl.value : 'draft',
      }};
      const resp = await fetch('/api/save', {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify(payload),
      }});
      const data = await resp.json();
      const rec = data.record;
      try {{ localStorage.setItem('ff_form_fixture_rev', String(rec.revision)); }} catch (e) {{}}
      document.getElementById('status-banner').textContent = 'SAVED:rev=' + rec.revision + ':title=' + rec.title;
      document.getElementById('persisted-revision').textContent = 'rev=' + rec.revision;
      document.getElementById('persisted-json').textContent = JSON.stringify(rec);
    }});
  </script>
</body>
</html>""".encode("utf-8")
                    self._send(200, "text/html; charset=utf-8", page)
                    return

                if self.path == "/owner-active":
                    with parent._lock:
                        parent.owner_get_count += 1
                    parent.owner_loaded.set()
                    page = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Owner Active Workspace</title></head>
<body>
  <h1>Owner Active Tab</h1>
  <input id="owner-draft" type="text" value="owner-typing-in-progress" autofocus />
  <script>
    window.__ownerFocusTelemetry = {blur_count: 0, visibility_change_count: 0};
    window.addEventListener('blur', () => { window.__ownerFocusTelemetry.blur_count += 1; });
    document.addEventListener('visibilitychange', () => { window.__ownerFocusTelemetry.visibility_change_count += 1; });
    document.getElementById('owner-draft').focus();
  </script>
</body>
</html>""".encode("utf-8")
                    self._send(200, "text/html; charset=utf-8", page)
                    return

                if self.path == "/api/state":
                    with parent._lock:
                        body = json.dumps({
                            "stored": dict(parent.stored),
                            "submission_count": len(parent.submissions),
                            "form_get_count": parent.form_get_count,
                        }).encode("utf-8")
                    self._send(200, "application/json", body)
                    return

                if self.path == "/redirect-other":
                    port = int(self.server.server_port)
                    self.send_response(302)
                    self.send_header("Location", f"http://localhost:{port}/other-host")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return

                if self.path == "/other-host":
                    self._send(200, "text/html; charset=utf-8", b"<!doctype html><html><body><h1>Other Host</h1></body></html>")
                    return

                self._send(404, "text/plain", b"not found")

            def do_POST(self) -> None:
                if self.path != "/api/save":
                    self._send(404, "text/plain", b"not found")
                    return
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                with parent._lock:
                    rev = int(parent.stored["revision"]) + 1
                    rec = {
                        "revision": rev,
                        "title": str(payload.get("title") or ""),
                        "notes": str(payload.get("notes") or ""),
                        "priority": str(payload.get("priority") or "medium"),
                        "notify": bool(payload.get("notify")),
                        "mode": str(payload.get("mode") or "draft"),
                    }
                    parent.stored = dict(rec)
                    parent.submissions.append(dict(rec))
                body = json.dumps({"ok": True, "record": rec}, sort_keys=True).encode("utf-8")
                self._send(200, "application/json", body)

        class _QuietServer(http.server.ThreadingHTTPServer):
            def handle_error(self, request, client_address) -> None:
                exc = sys.exc_info()[1]
                if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
                    return
                super().handle_error(request, client_address)

        self.server = _QuietServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = int(self.server.server_port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self) -> "_SyntheticFormServer":
        self.thread.start()
        return self

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    @property
    def form_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/form"

    @property
    def owner_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/owner-active"

    @property
    def other_host_url(self) -> str:
        return f"http://localhost:{self.port}/other-host"


class _Http404WsPassthroughProxy:
    """Loopback proxy matching Chrome 158 approval-gated mode (HTTP 404 + WS passthrough)."""

    def __init__(self, target_port: int, expected_ws_path: str) -> None:
        self.target_port = int(target_port)
        self.expected_ws_path = str(expected_ws_path)
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
            t = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            self._threads.append(t)
            t.start()

    @staticmethod
    def _pipe(src: socket.socket, dst: socket.socket, stop: threading.Event) -> None:
        src.settimeout(0.2)
        try:
            while not stop.is_set():
                try:
                    data = src.recv(16384)
                except socket.timeout:
                    continue
                except OSError:
                    break
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

    def _handle(self, client: socket.socket) -> None:
        upstream = None
        try:
            client.settimeout(3.0)
            raw = bytearray()
            while b"\r\n\r\n" not in raw and len(raw) < 32768:
                chunk = client.recv(4096)
                if not chunk:
                    return
                raw.extend(chunk)
            head_bytes, sep, rest = raw.partition(b"\r\n\r\n")
            if not sep:
                return
            lines = head_bytes.decode("latin1", "replace").split("\r\n")
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            if headers.get("upgrade", "").lower() != "websocket":
                self.http_404_count += 1
                client.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                return
            self.ws_upgrade_count += 1
            rebuilt = [lines[0]]
            for line in lines[1:]:
                if line.lower().startswith("host:"):
                    rebuilt.append(f"Host: 127.0.0.1:{self.target_port}")
                else:
                    rebuilt.append(line)
            forward = ("\r\n".join(rebuilt) + "\r\n\r\n").encode("latin1") + bytes(rest)
            upstream = socket.create_connection(("127.0.0.1", self.target_port), timeout=5.0)
            upstream.sendall(forward)
            t1 = threading.Thread(target=self._pipe, args=(client, upstream, self._stop), daemon=True)
            t2 = threading.Thread(target=self._pipe, args=(upstream, client, self._stop), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except OSError:
            pass
        finally:
            for s in (upstream, client):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass


class _RealDomNodeBrowserHubHarness:
    """Runs the REAL Node.js ff_browser_hub.mjs with a real-HTTP + real-DOM form Page adapter.

    Executes the actual `domClick`, `domFill`, `domSelect`, `domPress`, `read`, `reload`,
    `wait_for`, `snapshot`, and `tab-ledger.json` code in `ff_browser_hub.mjs` against the
    live loopback `_SyntheticFormServer`.
    """

    _SCRIPT = r"""
import {EventEmitter} from 'node:events';
import {pathToFileURL} from 'node:url';

const hubModUrl = pathToFileURL(process.argv[2]).href;
const ledgerFile = process.argv[3];
const key = process.env.SYNTH_FORM_HUB_KEY;
const {BrowserHub, serve} = await import(hubModUrl);

let targetSeq = 0;
let bringToFrontCalls = 0;
let nativeInputCalls = 0;
let reloadCalls = 0;
const createdPages = [];

function unescapeHtml(str) {
  return String(str || '')
    .replaceAll('&quot;', '"')
    .replaceAll('&#x27;', "'")
    .replaceAll('&#39;', "'")
    .replaceAll('&lt;', '<')
    .replaceAll('&gt;', '>')
    .replaceAll('&amp;', '&');
}

class DomEvent {
  constructor(type, init = {}) {
    this.type = type;
    this.bubbles = Boolean(init.bubbles);
    this.cancelable = Boolean(init.cancelable);
    this.composed = Boolean(init.composed);
    this.key = init.key;
    this.code = init.code;
    this.data = init.data;
    this.defaultPrevented = false;
  }
  preventDefault() { if (this.cancelable) this.defaultPrevented = true; }
}

class DomNode {
  constructor(page, tagName, attrs = {}) {
    this._page = page;
    this.tagName = tagName.toUpperCase();
    this.id = attrs.id || '';
    this.name = attrs.name || '';
    this.type = attrs.type || '';
    this.readOnly = Boolean(attrs.readOnly);
    this.disabled = Boolean(attrs.disabled);
    this.isContentEditable = Boolean(attrs.contentEditable);
    this._textContent = attrs.textContent || '';
    this._listeners = new Map();
    this.form = null;
    this.labels = [];
    this.ownerDocument = null;
  }
  get textContent() { return this._textContent; }
  set textContent(v) { this._textContent = String(v ?? ''); }
  get innerText() { return this._textContent; }
  set innerText(v) { this._textContent = String(v ?? ''); }
  getAttribute(k) {
    if (k === 'id') return this.id || null;
    if (k === 'name') return this.name || null;
    if (k === 'type') return this.type || null;
    return null;
  }
  addEventListener(type, fn) {
    if (!this._listeners.has(type)) this._listeners.set(type, []);
    this._listeners.get(type).push(fn);
  }
  dispatchEvent(ev) {
    for (const fn of (this._listeners.get(ev.type) || [])) fn(ev);
    return !ev.defaultPrevented;
  }
  focus() {
    this._page._activeElement = this;
  }
  scrollIntoView() {}
  getBoundingClientRect() { return {left: 0, top: 0, width: 120, height: 24}; }
  click() {
    this.dispatchEvent(new DomEvent('click', {bubbles: true, cancelable: true}));
    if (this.tagName === 'BUTTON' && (this.type || 'submit') === 'submit' && this.form) {
      this.form.requestSubmit(this);
    }
  }
}

class HTMLInputElement extends DomNode {
  constructor(page, attrs = {}) {
    super(page, 'INPUT', attrs);
    this._value = String(attrs.value ?? '');
    this.checked = Boolean(attrs.checked);
  }
  get value() { return this._value; }
  set value(v) { this._value = String(v ?? ''); }
  click() {
    if (this.type === 'checkbox') {
      this.checked = !this.checked;
    } else if (this.type === 'radio') {
      for (const node of this._page._elements) {
        if (node instanceof HTMLInputElement && node.type === 'radio' && node.name === this.name) {
          node.checked = (node === this);
        }
      }
    }
    super.click();
  }
}

class HTMLTextAreaElement extends DomNode {
  constructor(page, attrs = {}) {
    super(page, 'TEXTAREA', attrs);
    this._value = String(attrs.value ?? '');
  }
  get value() { return this._value; }
  set value(v) { this._value = String(v ?? ''); }
}

class HTMLSelectElement extends DomNode {
  constructor(page, attrs = {}, options = []) {
    super(page, 'SELECT', attrs);
    this.multiple = Boolean(attrs.multiple);
    this.options = options.map(opt => ({
      value: String(opt.value),
      textContent: String(opt.label),
      disabled: Boolean(opt.disabled),
      selected: Boolean(opt.selected),
    }));
    const firstSel = this.options.find(o => o.selected) || this.options[0];
    this.value = firstSel ? firstSel.value : '';
  }
  get selectedOptions() { return this.options.filter(o => o.selected); }
}

class HTMLFormElement extends DomNode {
  constructor(page, attrs = {}) {
    super(page, 'FORM', attrs);
  }
  requestSubmit() {
    const ev = new DomEvent('submit', {bubbles: true, cancelable: true});
    this.dispatchEvent(ev);
  }
}

class SyntheticDomPage extends EventEmitter {
  constructor(url = 'about:blank') {
    super();
    this._url = url;
    this._title = '';
    this._closed = false;
    this._elements = [];
    this._byId = new Map();
    this._activeElement = null;
    this._bodyText = '';
    this._pendingSaves = [];
    this.blurCount = 0;
    this.visibilityChangeCount = 0;
    this.targetId = `SYNTH-FORM-TARGET-${String(++targetSeq).padStart(4, '0')}`;
    this._view = {
      HTMLInputElement,
      HTMLTextAreaElement,
      HTMLSelectElement,
      Event: DomEvent,
      InputEvent: DomEvent,
      KeyboardEvent: DomEvent,
      MouseEvent: DomEvent,
      PointerEvent: DomEvent,
    };
    this._document = {
      defaultView: this._view,
      get activeElement() { return this._page._activeElement; },
      body: {
        get innerText() { return this._page._renderBodyText(); },
      },
    };
    this._document._page = this;
    this._document.body._page = this;
  }

  isClosed() { return this._closed; }
  url() { return this._url; }
  mainFrame() { return this; }
  async title() { return this._title; }
  async bringToFront() { bringToFrontCalls++; }

  _renderBodyText() {
    if (!this._elements.length) return this._bodyText;
    const parts = [this._title];
    for (const id of ['status-banner', 'persisted-revision', 'client-submit-count', 'persisted-json']) {
      const node = this._byId.get(id);
      if (node) parts.push(node.textContent);
    }
    return parts.join('\n');
  }

  _register(node) {
    node.ownerDocument = this._document;
    this._elements.push(node);
    if (node.id) this._byId.set(node.id, node);
    return node;
  }

  _loadFromHtml(rawHtml, resolvedUrl) {
    this._url = resolvedUrl;
    const titleMatch = rawHtml.match(/<title>([\s\S]*?)<\/title>/i);
    this._title = titleMatch ? unescapeHtml(titleMatch[1].trim()) : '';
    this._elements = [];
    this._byId = new Map();
    this._activeElement = null;
    this._bodyText = rawHtml.replace(/<head[\s\S]*?<\/head>/i, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();

    if (!rawHtml.includes('id="record-form"')) return;

    const form = this._register(new HTMLFormElement(this, {id: 'record-form'}));
    const attrVal = (id, attr) => {
      const m = rawHtml.match(new RegExp(`<input[^>]*id="${id}"[^>]*>`, 'i'));
      if (!m) return '';
      const v = m[0].match(new RegExp(`${attr}="([^"]*)"`, 'i'));
      return v ? unescapeHtml(v[1]) : '';
    };
    const hasFlag = (id, flag) => {
      const m = rawHtml.match(new RegExp(`<input[^>]*id="${id}"[^>]*>`, 'i'));
      return Boolean(m && new RegExp(`\\b${flag}\\b`, 'i').test(m[0]));
    };
    const tagText = id => {
      const m = rawHtml.match(new RegExp(`<[^>]*id="${id}"[^>]*>([\\s\\S]*?)<\\/`, 'i'));
      return m ? unescapeHtml(m[1]) : '';
    };

    const titleEl = this._register(new HTMLInputElement(this, {id: 'title-input', name: 'title', type: 'text', value: attrVal('title-input', 'value')}));
    const notesEl = this._register(new HTMLTextAreaElement(this, {id: 'notes-input', name: 'notes', value: tagText('notes-input')}));
    const optMatches = [...rawHtml.matchAll(/<option value="([^"]+)"([^>]*)>([^<]*)<\/option>/gi)];
    const selectEl = this._register(new HTMLSelectElement(this, {id: 'priority-select', name: 'priority'}, optMatches.map(m => ({
      value: unescapeHtml(m[1]),
      selected: /\bselected\b/i.test(m[2]),
      label: unescapeHtml(m[3]),
    }))));
    const notifyEl = this._register(new HTMLInputElement(this, {id: 'notify-check', name: 'notify', type: 'checkbox', value: 'on', checked: hasFlag('notify-check', 'checked')}));
    const draftEl = this._register(new HTMLInputElement(this, {id: 'mode-draft', name: 'mode', type: 'radio', value: 'draft', checked: hasFlag('mode-draft', 'checked')}));
    const finalEl = this._register(new HTMLInputElement(this, {id: 'mode-final', name: 'mode', type: 'radio', value: 'final', checked: hasFlag('mode-final', 'checked')}));
    const roEl = this._register(new HTMLInputElement(this, {id: 'readonly-code', name: 'readonly_code', type: 'text', value: attrVal('readonly-code', 'value'), readOnly: true}));
    const disEl = this._register(new HTMLInputElement(this, {id: 'disabled-field', name: 'disabled_field', type: 'text', value: attrVal('disabled-field', 'value'), disabled: true}));
    const saveBtn = this._register(new DomNode(this, 'BUTTON', {id: 'save-btn', type: 'submit', textContent: 'Save Record'}));

    const labelMap = {
      'title-input': 'Title', 'notes-input': 'Notes', 'priority-select': 'Priority',
      'notify-check': 'Notify', 'mode-draft': 'Draft Mode', 'mode-final': 'Final Mode',
    };
    for (const el of [titleEl, notesEl, selectEl, notifyEl, draftEl, finalEl, roEl, disEl, saveBtn]) {
      el.form = form;
      if (labelMap[el.id]) el.labels = [{innerText: labelMap[el.id]}];
    }

    const statusBanner = this._register(new DomNode(this, 'DIV', {id: 'status-banner', textContent: tagText('status-banner')}));
    const revEl = this._register(new DomNode(this, 'DIV', {id: 'persisted-revision', textContent: tagText('persisted-revision')}));
    const submitCounter = this._register(new DomNode(this, 'DIV', {id: 'client-submit-count', textContent: tagText('client-submit-count') || '0'}));
    const jsonEl = this._register(new DomNode(this, 'PRE', {id: 'persisted-json', textContent: tagText('persisted-json')}));

    let clientSubmits = 0;
    form.addEventListener('submit', ev => {
      ev.preventDefault();
      clientSubmits += 1;
      submitCounter.textContent = String(clientSubmits);
      const checkedMode = [draftEl, finalEl].find(r => r.checked);
      const payload = {
        title: titleEl.value,
        notes: notesEl.value,
        priority: selectEl.value,
        notify: notifyEl.checked,
        mode: checkedMode ? checkedMode.value : 'draft',
      };
      const saveUrl = new URL('/api/save', this._url).href;
      const p = fetch(saveUrl, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
      }).then(r => r.json()).then(data => {
        const rec = data.record;
        statusBanner.textContent = `SAVED:rev=${rec.revision}:title=${rec.title}`;
        revEl.textContent = `rev=${rec.revision}`;
        jsonEl.textContent = JSON.stringify(rec);
      });
      this._pendingSaves.push(p);
    });
  }

  async goto(targetUrl) {
    const resp = await fetch(targetUrl, {redirect: 'follow'});
    const raw = await resp.text();
    this._loadFromHtml(raw, resp.url || targetUrl);
    this.emit('framenavigated', this);
  }

  async reload() {
    reloadCalls += 1;
    await Promise.allSettled(this._pendingSaves);
    const resp = await fetch(this._url, {redirect: 'follow'});
    const raw = await resp.text();
    this._loadFromHtml(raw, resp.url || this._url);
    this.emit('framenavigated', this);
  }

  async close() {
    this._closed = true;
    this.emit('close');
  }

  _matchSelector(selector) {
    if (selector === 'body') return [this._document.body];
    if (selector.startsWith('#')) {
      const node = this._byId.get(selector.slice(1));
      return node ? [node] : [];
    }
    return [];
  }

  _locatorFor(nodes) {
    const page = this;
    return {
      count: async () => nodes.length,
      isVisible: async () => nodes.length === 1,
      isEnabled: async () => nodes.length === 1 && !nodes[0].disabled,
      isChecked: async () => Boolean(nodes[0]?.checked),
      inputValue: async () => String(nodes[0]?.value ?? ''),
      click: async () => { nativeInputCalls++; },
      fill: async () => { nativeInputCalls++; },
      selectOption: async () => { nativeInputCalls++; return []; },
      ariaSnapshot: async () => {
        await Promise.allSettled(page._pendingSaves);
        const lines = [`- document "${page._title}":`];
        for (const el of page._elements) {
          if (el.tagName === 'INPUT' && el.type === 'text') lines.push(`  - textbox "${el.id}": "${el.value}"`);
          else if (el.tagName === 'TEXTAREA') lines.push(`  - textbox "${el.id}": "${el.value}"`);
          else if (el.tagName === 'SELECT') lines.push(`  - combobox "${el.id}": "${el.value}"`);
          else if (el.tagName === 'INPUT' && (el.type === 'checkbox' || el.type === 'radio'))
            lines.push(`  - ${el.type} "${el.id}"${el.checked ? ' [checked]' : ''}`);
          else if (['status-banner', 'persisted-revision', 'persisted-json'].includes(el.id))
            lines.push(`  - text "${el.id}": "${el.textContent}"`);
        }
        return lines.join('\n');
      },
      evaluate: async (fn, arg) => {
        const prevWindow = globalThis.window;
        const prevDoc = globalThis.document;
        const prevKb = globalThis.KeyboardEvent;
        globalThis.window = page._view;
        globalThis.document = page._document;
        globalThis.KeyboardEvent = DomEvent;
        try {
          const out = fn(nodes[0], arg);
          await Promise.allSettled(page._pendingSaves);
          return out;
        } finally {
          if (prevWindow === undefined) delete globalThis.window; else globalThis.window = prevWindow;
          if (prevDoc === undefined) delete globalThis.document; else globalThis.document = prevDoc;
          if (prevKb === undefined) delete globalThis.KeyboardEvent; else globalThis.KeyboardEvent = prevKb;
        }
      },
    };
  }

  locator(selector) {
    return this._locatorFor(this._matchSelector(selector));
  }

  getByLabel(label) {
    const matched = this._elements.filter(el => el.labels.some(l => l.innerText === label));
    return this._locatorFor(matched);
  }

  async evaluate(fn, arg) {
    await Promise.allSettled(this._pendingSaves);
    const src = String(fn);
    if (src.includes('visibilityState')) return 'hidden';
    const prevWindow = globalThis.window;
    const prevDoc = globalThis.document;
    const prevKb = globalThis.KeyboardEvent;
    globalThis.window = this._view;
    globalThis.document = this._document;
    globalThis.KeyboardEvent = DomEvent;
    try {
      const out = fn(arg);
      await Promise.allSettled(this._pendingSaves);
      return out;
    } finally {
      if (prevWindow === undefined) delete globalThis.window; else globalThis.window = prevWindow;
      if (prevDoc === undefined) delete globalThis.document; else globalThis.document = prevDoc;
      if (prevKb === undefined) delete globalThis.KeyboardEvent; else globalThis.KeyboardEvent = prevKb;
    }
  }
}

class SyntheticBrowser extends EventEmitter {
  constructor() { super(); this.connected = true; }
  isConnected() { return this.connected; }
  async close() { this.connected = false; this.emit('disconnected'); }
}

const foreignOwnerPage = new SyntheticDomPage('https://owner-work.invalid/editor');
const browser = new SyntheticBrowser();
const context = new EventEmitter();
const livePages = [foreignOwnerPage];
context.pages = () => livePages.filter(p => !p.isClosed());
context.newPage = async () => {
  const page = new SyntheticDomPage('about:blank');
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
    form_operations_supported: true,
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
      native_input_calls: nativeInputCalls,
      reload_calls: reloadCalls,
      foreign_owner_page_closed: foreignOwnerPage.isClosed(),
      foreign_owner_blur_count: foreignOwnerPage.blurCount,
      foreign_owner_visibility_changes: foreignOwnerPage.visibilityChangeCount,
      created_pages_total: createdPages.length,
      created_pages_open: createdPages.filter(p => !p.isClosed()).length,
    };
  }
  if (op === '__test_force_page_url') {
    const tab = hub.tabs.get(args.tab_id);
    if (tab?.page) tab.page._url = args.url;
    return {ok: true};
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

    def start(self) -> "_RealDomNodeBrowserHubHarness":
        node = shutil.which("node")
        if not node:
            raise unittest.SkipTest("Node.js not installed")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        script_file = self.state_dir / "run_synth_form_browser_hub.mjs"
        script_file.write_text(self._SCRIPT, encoding="utf-8")
        self.proc = subprocess.Popen(
            [node, str(script_file), str(PACKAGE / "ff_browser_hub.mjs"), str(self.ledger_file)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env={**os.environ, "SYNTH_FORM_HUB_KEY": self.key},
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline()
        if not line:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"Synthetic form BrowserHub failed to start: {err}")
        self.port = int(json.loads(line)["port"])
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


def _make_direct_mcp_client(hub: Hub):
    class _DirectClient:
        def raw(self, req: dict) -> dict:
            try:
                return {"ok": True, "result": hub.dispatch(req)}
            except HubError as exc:
                return {"ok": False, "error_code": exc.code, "message": exc.message, "details": exc.details}

    return _DirectClient()


def _enum_desktop_chrome(desktop_handle, pid: int) -> list[dict]:
    u32 = ctypes.WinDLL("user32", use_last_error=True)
    cb_type = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
    u32.EnumDesktopWindows.argtypes = [wt.HANDLE, cb_type, wt.LPARAM]
    u32.EnumDesktopWindows.restype = wt.BOOL
    u32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
    u32.GetWindowThreadProcessId.restype = wt.DWORD
    u32.IsWindowVisible.argtypes = [wt.HWND]
    u32.IsWindowVisible.restype = wt.BOOL
    u32.IsIconic.argtypes = [wt.HWND]
    u32.IsIconic.restype = wt.BOOL
    u32.GetWindowLongW.argtypes = [wt.HWND, ctypes.c_int]
    u32.GetWindowLongW.restype = wt.LONG
    u32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
    u32.GetWindowRect.restype = wt.BOOL
    u32.GetClassNameW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
    u32.GetClassNameW.restype = ctypes.c_int

    out: list[dict] = []

    @cb_type
    def cb(hwnd, _lp):
        wpid = wt.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
        if int(wpid.value) != pid:
            return True
        cls = ctypes.create_unicode_buffer(128)
        u32.GetClassNameW(hwnd, cls, len(cls))
        if cls.value != "Chrome_WidgetWin_1":
            return True
        rect = wt.RECT()
        u32.GetWindowRect(hwnd, ctypes.byref(rect))
        ex = int(u32.GetWindowLongW(hwnd, -20))
        vis = bool(u32.IsWindowVisible(hwnd))
        out.append({
            "hwnd": int(hwnd),
            "visible": vis,
            "iconic": bool(u32.IsIconic(hwnd)),
            "taskbar": bool(vis and not (ex & 0x80)),
            "width": rect.right - rect.left,
            "height": rect.bottom - rect.top,
        })
        return True

    u32.EnumDesktopWindows(desktop_handle, cb, 0)
    return out


class BackgroundFormOperationsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="ff-form-reg-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_route_plan_background_form_policy_preservation_and_site_read_remains_read_only(self) -> None:
        hub_state = self.root / "hub-plan"
        empty_udd = self.root / "empty-udd"
        empty_udd.mkdir()
        node_hub = _RealDomNodeBrowserHubHarness(self.root / "node-plan").start()
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(hub_state, profile_dir_name="Default", user_data_dir=empty_udd)
        hub = Hub(hub_state, browser=node_hub, owner_chrome_secondary=mgr)
        try:
            policy_path = hub_state / "policy.json"
            hub.policy.set_default("browser_own_tabs", "ask")
            hub.policy.add_grant(["browser_own_tabs"], agents=["form-agent"], hosts=["127.0.0.1"], ttl_seconds=600)
            policy_hash_before = _sha256_or_none(policy_path)

            # Capabilities & workflows expose truthful background form metadata
            caps = hub.capabilities()
            bf = caps["browser_routes"]["background_form_operations"]
            self.assertEqual(bf["route_plan_capability"], "background_tab_form")
            self.assertEqual(bf["supported_actions"], ["fill", "click", "select", "check", "uncheck", "press"])
            self.assertTrue(bf["reload_supported"])
            self.assertTrue(bf["wait_for_supported"])
            self.assertTrue(bf["request_key_deduplication"])
            self.assertFalse(bf["foreground_fallback"])
            self.assertFalse(bf["policy_modified"])
            self.assertIn("reload", caps["operations"]["browser"]["commands"])
            self.assertIn("reload", caps["operations"]["owner_chrome_hidden"]["commands"])
            self.assertIn("wait_for", caps["operations"]["owner_chrome_hidden"]["commands"])

            wf = agent_workflows()
            self.assertIn("reload", wf["browser_workflow"]["commands"])
            self.assertIn("wait_for", wf["browser_workflow"]["commands"])
            self.assertEqual(wf["browser_workflow"]["background_form_operations"]["route_plan_capability"], "background_tab_form")

            # 1. background_tab_form selects connected authorized owner_chrome_extension for ordinary background_tab
            plan_bg = hub.dispatch({
                "op": "route_plan",
                "args": {
                    "surface": "browser",
                    "capability": "background_tab_form",
                    "agent_id": "form-agent",
                    "url": "http://127.0.0.1:8080/form",
                    "visibility": "background_tab",
                },
            })
            self.assertEqual(plan_bg["selected"], "owner_chrome_extension")
            self.assertFalse(plan_bg["pending_request_created"])
            self.assertFalse(plan_bg["ui_triggered"])
            self.assertFalse(plan_bg["foreground_fallback"])
            self.assertFalse(plan_bg["companion"]["browser_page_reader"])
            bf_plan = plan_bg["background_form_plan"]
            self.assertEqual(bf_plan["schema"], "ff-no-interruption-background-form-v1")
            self.assertEqual(bf_plan["supported_form_actions"], ["fill", "click", "select", "check", "uncheck", "press"])
            self.assertFalse(bf_plan["policy_modified"])
            self.assertFalse(bf_plan["browser_permissions_modified"])

            # 2. strict_invisibility NEVER substitutes visible-tab owner_chrome_extension
            plan_strict = hub.dispatch({
                "op": "route_plan",
                "args": {
                    "surface": "browser",
                    "capability": "background_tab_form",
                    "agent_id": "form-agent",
                    "url": "http://127.0.0.1:8080/form",
                    "strict_invisibility": True,
                },
            })
            self.assertIsNone(plan_strict["selected"])
            self.assertEqual(plan_strict["fallback_refused_reason"], "NO_ELIGIBLE_NO_INTERRUPTION_PROVIDER")
            ext_p = next(p for p in plan_strict["routes"] if p["provider"] == "owner_chrome_extension")
            self.assertEqual(ext_p["reason_code"], "VISIBLE_TAB_SUBSTITUTION_FORBIDDEN")

            # 3. Unauthorized host produces ONE actionable capability result, zero pending requests, unchanged policy
            plan_denied = hub.dispatch({
                "op": "route_plan",
                "args": {
                    "surface": "browser",
                    "capability": "background_tab_form",
                    "agent_id": "form-agent",
                    "url": "https://ungranted.example.test/form",
                },
            })
            self.assertIsNone(plan_denied["selected"])
            self.assertEqual(plan_denied["fallback_refused_reason"], "NO_ELIGIBLE_NO_INTERRUPTION_PROVIDER")
            self.assertEqual(hub.store.permission_requests(), [])
            self.assertEqual(_sha256_or_none(policy_path), policy_hash_before)

            # 4. site_read stays strictly read-only (mutating form args remain forbidden!)
            sess = hub.dispatch({"op": "session_open", "args": {"agent_id": "form-agent", "task_id": "t-sr-ro"}})
            auth = {"session_id": sess["session_id"], "session_secret": sess["session_secret"]}
            for bad_arg in ({"fill": "x"}, {"click": "#save-btn"}, {"act": "click"}):
                with self.assertRaises(HubError) as exc:
                    hub.dispatch({**auth, "op": "site_read", "args": {"url": "http://127.0.0.1:8080/form", **bad_arg}})
                self.assertEqual(exc.exception.code, "SITE_READ_ARG_FORBIDDEN")
            hub.dispatch({**auth, "op": "session_close", "request_key": "close-sr-ro-01"})
            self.assertEqual(_sha256_or_none(policy_path), policy_hash_before)
        finally:
            hub.shutdown()
            hub.store.close()
            node_hub.stop()

    def test_ownership_isolation_foreground_refusal_request_key_host_guard_and_control_validation(self) -> None:
        form_srv = _SyntheticFormServer().start()
        node_hub = _RealDomNodeBrowserHubHarness(self.root / "node-guards").start()
        hub_state = self.root / "hub-guards"
        hub = Hub(hub_state, browser=node_hub)
        try:
            policy_path = hub_state / "policy.json"
            hub.policy.set_default("browser_own_tabs", "ask")
            hub.policy.add_grant(["browser_own_tabs"], agents=["agent-a", "agent-b"], hosts=["127.0.0.1"], ttl_seconds=600)
            policy_hash_before = _sha256_or_none(policy_path)

            sa = hub.dispatch({"op": "session_open", "args": {"agent_id": "agent-a", "task_id": "task-a"}})
            sb = hub.dispatch({"op": "session_open", "args": {"agent_id": "agent-b", "task_id": "task-b"}})
            auth_a = {"session_id": sa["session_id"], "session_secret": sa["session_secret"]}
            auth_b = {"session_id": sb["session_id"], "session_secret": sb["session_secret"]}

            opened = hub.dispatch({
                **auth_a, "op": "browser", "request_key": "guard-open-001",
                "args": {"command": "open", "url": form_srv.form_url},
            })
            tab_id = opened["tab_id"]

            # 1. Cross-agent isolation: Agent B cannot read, act, reload, or close Agent A's owned tab
            for cmd, req_key, extra in (
                ("read", None, {}),
                ("act", "guard-b-act-01", {"action": "fill", "target": {"selector": "#title-input"}, "value": "hijack"}),
                ("reload", "guard-b-rel-01", {}),
                ("close", "guard-b-cls-01", {}),
            ):
                with self.subTest(cross_agent_cmd=cmd), self.assertRaises(HubError) as exc:
                    payload = {**auth_b, "op": "browser", "args": {"command": cmd, "tab_id": tab_id, **extra}}
                    if req_key:
                        payload["request_key"] = req_key
                    hub.dispatch(payload)
                self.assertEqual(exc.exception.code, "RESOURCE_NOT_OWNED")

            # 2. Foreground refusal before any DOM mutation
            with self.assertRaises(HubError) as fg_err:
                hub.dispatch({
                    **auth_a, "op": "browser", "request_key": "guard-fg-0001",
                    "args": {"command": "act", "tab_id": tab_id, "foreground": True, "action": "click", "target": {"selector": "#save-btn"}},
                })
            self.assertEqual(fg_err.exception.code, "FOREGROUND_ROUTE_REQUIRED")
            self.assertFalse(fg_err.exception.details.get("execution_started", True))

            # 3. Missing request_key rejected fail-closed on act and reload
            for cmd, extra in (
                ("act", {"action": "click", "target": {"selector": "#save-btn"}}),
                ("reload", {}),
            ):
                with self.subTest(missing_key=cmd), self.assertRaises(HubError) as rk_err:
                    hub.dispatch({**auth_a, "op": "browser", "args": {"command": cmd, "tab_id": tab_id, **extra}})
                self.assertEqual(rk_err.exception.code, "REQUEST_KEY_REQUIRED")

            # 4. Control validation (readOnly, disabled, missing option, uncheck radio, missing key)
            for idx, (extra, expected_code) in enumerate((
                ({"action": "fill", "target": {"selector": "#readonly-code"}, "value": "override"}, "TARGET_NOT_EDITABLE"),
                ({"action": "fill", "target": {"selector": "#disabled-field"}, "value": "override"}, "TARGET_DISABLED"),
                ({"action": "fill", "target": {"selector": "#notify-check"}, "value": "bad"}, "TARGET_NOT_EDITABLE"),
                ({"action": "select", "target": {"selector": "#priority-select"}, "value": "invalid-opt"}, "OPTION_NOT_FOUND"),
                ({"action": "uncheck", "target": {"selector": "#mode-draft"}}, "TARGET_NOT_EDITABLE"),
                ({"action": "press", "target": {"selector": "#title-input"}}, "KEY_REQUIRED"),
            ), start=1):
                with self.subTest(bad_action=expected_code), self.assertRaises(HubError) as act_err:
                    hub.dispatch({
                        **auth_a, "op": "browser", "request_key": f"guard-bad-{idx:04d}",
                        "args": {"command": "act", "tab_id": tab_id, **extra},
                    })
                self.assertEqual(act_err.exception.code, expected_code)

            # 5. Live host-change guard rejects both act and reload BEFORE touching DOM/server
            node_hub.call("__test_force_page_url", {"tab_id": tab_id, "url": form_srv.other_host_url})
            with self.assertRaises(HubError) as host_act:
                hub.dispatch({
                    **auth_a, "op": "browser", "request_key": "guard-host-act1",
                    "args": {"command": "act", "tab_id": tab_id, "action": "click", "target": {"selector": "#save-btn"}},
                })
            self.assertEqual(host_act.exception.code, "TAB_HOST_CHANGED")
            with self.assertRaises(HubError) as host_rel:
                hub.dispatch({
                    **auth_a, "op": "browser", "request_key": "guard-host-rel1",
                    "args": {"command": "reload", "tab_id": tab_id},
                })
            self.assertEqual(host_rel.exception.code, "TAB_HOST_CHANGED")

            self.assertEqual(form_srv.submissions, [])
            hub.dispatch({**auth_a, "op": "session_close", "request_key": "guard-cls-a-01"})
            hub.dispatch({**auth_b, "op": "session_close", "request_key": "guard-cls-b-01"})
            self.assertEqual(hub.store.resources(), [])
            self.assertEqual(hub.store.permission_requests(), [])
            self.assertEqual(_sha256_or_none(policy_path), policy_hash_before)
        finally:
            hub.shutdown()
            hub.store.close()
            node_hub.stop()
            form_srv.close()

    def test_two_consecutive_form_workflows_via_real_browser_hub_mjs_and_mcp(self) -> None:
        form_srv = _SyntheticFormServer().start()
        node_hub = _RealDomNodeBrowserHubHarness(self.root / "node-form-e2e").start()
        hub_state = self.root / "hub-form-ext"
        empty_udd = self.root / "empty-udd-ext"
        empty_udd.mkdir()
        mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(hub_state, profile_dir_name="Default", user_data_dir=empty_udd)
        hub = Hub(hub_state, browser=node_hub, owner_chrome_secondary=mgr)
        try:
            policy_path = hub_state / "policy.json"
            hub.policy.set_default("browser_own_tabs", "ask")
            hub.policy.add_grant(["browser_own_tabs"], agents=["ext-form-agent"], hosts=["127.0.0.1"], ttl_seconds=600)
            policy_hash_before = _sha256_or_none(policy_path)

            # --- Consecutive Workflow 1 via Hub.dispatch (`browser` op): fill -> save -> dedupe -> reload -> verify ---
            s1 = hub.dispatch({"op": "session_open", "args": {"agent_id": "ext-form-agent", "task_id": "form-ext-wf1"}})
            a1 = {"session_id": s1["session_id"], "session_secret": s1["session_secret"]}

            t1 = hub.dispatch({
                **a1, "op": "browser", "request_key": "ext-wf1-open-001",
                "args": {"command": "open", "url": form_srv.form_url},
            })
            tab1 = t1["tab_id"]
            self.assertTrue(t1["durable_identity"])

            hub.dispatch({
                **a1, "op": "browser", "request_key": "ext-wf1-fill-title",
                "args": {"command": "act", "tab_id": tab1, "action": "fill", "target": {"selector": "#title-input"}, "value": "Quarterly Plan v1"},
            })
            hub.dispatch({
                **a1, "op": "browser", "request_key": "ext-wf1-fill-notes",
                "args": {"command": "act", "tab_id": tab1, "action": "fill", "target": {"selector": "#notes-input"}, "value": "Drafted in background tab"},
            })
            sel1 = hub.dispatch({
                **a1, "op": "browser", "request_key": "ext-wf1-sel-prio",
                "args": {"command": "act", "tab_id": tab1, "action": "select", "target": {"selector": "#priority-select"}, "value": "high"},
            })
            self.assertEqual(sel1["detail"], {"mode": "dom-select", "selected": ["high"]})
            hub.dispatch({
                **a1, "op": "browser", "request_key": "ext-wf1-chk-notify",
                "args": {"command": "act", "tab_id": tab1, "action": "check", "target": {"selector": "#notify-check"}},
            })
            hub.dispatch({
                **a1, "op": "browser", "request_key": "ext-wf1-chk-draft",
                "args": {"command": "act", "tab_id": tab1, "action": "check", "target": {"selector": "#mode-draft"}},
            })

            save1_req = {
                **a1, "op": "browser", "request_key": "ext-wf1-save-001",
                "args": {
                    "command": "act", "tab_id": tab1, "action": "click",
                    "target": {"selector": "#save-btn"},
                    "postcondition": {"text_present": "SAVED:rev=1:title=Quarterly Plan v1"},
                },
            }
            save1 = hub.dispatch(save1_req)
            self.assertFalse(save1["deduplicated"])
            self.assertTrue(save1["verified"])
            self.assertEqual(save1["visibility"], "hidden")
            self.assertEqual(len(form_srv.submissions), 1)

            # No duplicate submission: exact replay returns deduplicated=True, server stays at 1
            save1_dup = hub.dispatch(save1_req)
            self.assertTrue(save1_dup["deduplicated"])
            self.assertEqual(len(form_srv.submissions), 1)

            st1 = hub.dispatch({**a1, "op": "request_status", "args": {"request_key": "ext-wf1-save-001"}})
            self.assertEqual(st1["state"], "completed")
            self.assertFalse(st1["automatic_replay"])
            self.assertEqual(len(form_srv.submissions), 1)

            # Reusing same request_key with modified payload fails closed without submitting
            with self.assertRaises(HubError) as reused1:
                hub.dispatch({
                    **a1, "op": "browser", "request_key": "ext-wf1-save-001",
                    "args": {"command": "act", "tab_id": tab1, "action": "click", "target": {"selector": "#save-btn"}},
                })
            self.assertEqual(reused1.exception.code, "REQUEST_KEY_REUSED")
            self.assertEqual(len(form_srv.submissions), 1)

            # Reload owned tab & verify stored data persisted on server (without duplicating submit)
            gets_before_rel1 = form_srv.form_get_count
            rel1 = hub.dispatch({**a1, "op": "browser", "request_key": "ext-wf1-reload-1", "args": {"command": "reload", "tab_id": tab1}})
            self.assertTrue(rel1["reloaded"])
            self.assertEqual(rel1["visibility"], "hidden")
            self.assertEqual(form_srv.form_get_count, gets_before_rel1 + 1)
            self.assertEqual(len(form_srv.submissions), 1)

            hub.dispatch({
                **a1, "op": "browser",
                "args": {"command": "wait_for", "tab_id": tab1, "condition": {"target": {"selector": "#title-input"}, "value": "Quarterly Plan v1"}},
            })
            read_title1 = hub.dispatch({**a1, "op": "browser", "args": {"command": "read", "tab_id": tab1, "target": {"selector": "#title-input"}}})
            read_notes1 = hub.dispatch({**a1, "op": "browser", "args": {"command": "read", "tab_id": tab1, "target": {"selector": "#notes-input"}}})
            read_prio1 = hub.dispatch({**a1, "op": "browser", "args": {"command": "read", "tab_id": tab1, "target": {"selector": "#priority-select"}}})
            read_chk1 = hub.dispatch({**a1, "op": "browser", "args": {"command": "read", "tab_id": tab1, "target": {"selector": "#notify-check"}}})
            snap1 = hub.dispatch({**a1, "op": "browser", "args": {"command": "snapshot", "tab_id": tab1}})
            self.assertEqual(read_title1["value"], "Quarterly Plan v1")
            self.assertEqual(read_notes1["value"], "Drafted in background tab")
            self.assertEqual(read_prio1["value"], "high")
            self.assertTrue(read_chk1["checked"])
            self.assertIn("LOADED:rev=1", snap1["snapshot"])
            self.assertEqual(snap1["visibility"], "hidden")

            c1 = hub.dispatch({**a1, "op": "session_close", "request_key": "ext-wf1-close-01"})
            self.assertTrue(c1["closed"])
            self.assertTrue(c1["cleanup_verified"])
            self.assertEqual(c1["resources_retained"], 0)
            self.assertEqual(c1["browser_tabs_closed"], 1)

            # --- Consecutive Workflow 2 via normal MCP Adapter: edit -> save (Enter) -> dedupe -> reload -> verify ---
            adapter = Adapter(hub_state, "ext-form-agent", client=_make_direct_mcp_client(hub))
            try:
                tools = mcp_handle(adapter, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                arg_props = tools["result"]["tools"][0]["inputSchema"]["properties"]["args"]["properties"]
                for field in ("key", "condition", "timeout_ms", "ignore_cache"):
                    self.assertIn(field, arg_props)

                rp = adapter.call({
                    "op": "route_plan",
                    "args": {"surface": "browser", "capability": "background_tab_form", "url": form_srv.form_url},
                })
                self.assertEqual(rp["selected"], "owner_chrome_extension")

                adapter.call({"op": "session_open", "task_id": "form-ext-wf2"})
                t2 = adapter.call({
                    "op": "browser", "task_id": "form-ext-wf2", "request_key": "ext-wf2-open-001",
                    "args": {"command": "open", "url": form_srv.form_url},
                })
                tab2 = t2["tab_id"]
                self.assertNotEqual(tab2, tab1)

                # Verify Workflow 1 stored data loaded into fresh Workflow 2 tab before editing
                pre2 = adapter.call({
                    "op": "browser", "task_id": "form-ext-wf2",
                    "args": {"command": "read", "tab_id": tab2, "target": {"selector": "#title-input"}},
                })
                self.assertEqual(pre2["value"], "Quarterly Plan v1")

                adapter.call({
                    "op": "browser", "task_id": "form-ext-wf2", "request_key": "ext-wf2-edit-title",
                    "args": {"command": "act", "tab_id": tab2, "action": "fill", "target": {"selector": "#title-input"}, "value": "Quarterly Plan v2 Final"},
                })
                adapter.call({
                    "op": "browser", "task_id": "form-ext-wf2", "request_key": "ext-wf2-edit-notes",
                    "args": {"command": "act", "tab_id": tab2, "action": "fill", "target": {"selector": "#notes-input"}, "value": "Edited and verified"},
                })
                adapter.call({
                    "op": "browser", "task_id": "form-ext-wf2", "request_key": "ext-wf2-edit-prio",
                    "args": {"command": "act", "tab_id": tab2, "action": "select", "target": {"selector": "#priority-select"}, "value": "urgent"},
                })
                adapter.call({
                    "op": "browser", "task_id": "form-ext-wf2", "request_key": "ext-wf2-unchk-notify",
                    "args": {"command": "act", "tab_id": tab2, "action": "uncheck", "target": {"selector": "#notify-check"}},
                })
                adapter.call({
                    "op": "browser", "task_id": "form-ext-wf2", "request_key": "ext-wf2-chk-final",
                    "args": {"command": "act", "tab_id": tab2, "action": "check", "target": {"selector": "#mode-final"}},
                })

                # Enter in textarea must NOT submit
                ta_enter = adapter.call({
                    "op": "browser", "task_id": "form-ext-wf2", "request_key": "ext-wf2-ta-enter",
                    "args": {"command": "act", "tab_id": tab2, "action": "press", "target": {"selector": "#notes-input"}, "key": "Enter"},
                })
                self.assertEqual(ta_enter["detail"], "dispatched")
                self.assertEqual(len(form_srv.submissions), 1)

                # Save Workflow 2 via Enter press on title input
                save2_call = {
                    "op": "browser", "task_id": "form-ext-wf2", "request_key": "ext-wf2-save-001",
                    "args": {
                        "command": "act", "tab_id": tab2, "action": "press",
                        "target": {"selector": "#title-input"}, "key": "Enter",
                        "postcondition": {"text_present": "SAVED:rev=2:title=Quarterly Plan v2 Final"},
                    },
                }
                save2 = adapter.call(save2_call)
                self.assertFalse(save2["deduplicated"])
                self.assertEqual(save2["detail"], "form_submitted")
                self.assertEqual(len(form_srv.submissions), 2)

                # Duplicate retry via MCP -> deduplicated, still 2 submissions
                save2_dup = adapter.call(save2_call)
                self.assertTrue(save2_dup["deduplicated"])
                self.assertEqual(len(form_srv.submissions), 2)

                # Reload owned tab & verify persisted revision 2 data
                gets_before_rel2 = form_srv.form_get_count
                rel2 = adapter.call({
                    "op": "browser", "task_id": "form-ext-wf2", "request_key": "ext-wf2-reload-1",
                    "args": {"command": "reload", "tab_id": tab2},
                })
                self.assertTrue(rel2["reloaded"])
                self.assertEqual(form_srv.form_get_count, gets_before_rel2 + 1)
                self.assertEqual(len(form_srv.submissions), 2)

                r2_title = adapter.call({"op": "browser", "task_id": "form-ext-wf2", "args": {"command": "read", "tab_id": tab2, "target": {"selector": "#title-input"}}})
                r2_notes = adapter.call({"op": "browser", "task_id": "form-ext-wf2", "args": {"command": "read", "tab_id": tab2, "target": {"selector": "#notes-input"}}})
                r2_prio = adapter.call({"op": "browser", "task_id": "form-ext-wf2", "args": {"command": "read", "tab_id": tab2, "target": {"selector": "#priority-select"}}})
                r2_notify = adapter.call({"op": "browser", "task_id": "form-ext-wf2", "args": {"command": "read", "tab_id": tab2, "target": {"selector": "#notify-check"}}})
                r2_final = adapter.call({"op": "browser", "task_id": "form-ext-wf2", "args": {"command": "read", "tab_id": tab2, "target": {"selector": "#mode-final"}}})
                r2_json = adapter.call({"op": "browser", "task_id": "form-ext-wf2", "args": {"command": "read", "tab_id": tab2, "target": {"selector": "#persisted-json"}}})
                self.assertEqual(r2_title["value"], "Quarterly Plan v2 Final")
                self.assertEqual(r2_notes["value"], "Edited and verified")
                self.assertEqual(r2_prio["value"], "urgent")
                self.assertFalse(r2_notify["checked"])
                self.assertTrue(r2_final["checked"])
                self.assertEqual(json.loads(r2_json["text"]), {
                    "mode": "final",
                    "notes": "Edited and verified",
                    "notify": False,
                    "priority": "urgent",
                    "revision": 2,
                    "title": "Quarterly Plan v2 Final",
                })

                c2 = adapter.call({"op": "session_close", "task_id": "form-ext-wf2", "request_key": "ext-wf2-close-01"})
                self.assertTrue(c2["closed"])
                self.assertTrue(c2["cleanup_verified"])
                self.assertEqual(c2["resources_retained"], 0)
                self.assertEqual(c2["browser_tabs_closed"], 1)
            finally:
                adapter.close()

            # Focus retention, zero native input, zero duplicate submissions, empty ledger, unchanged policy
            telem = node_hub.call("__test_telemetry")
            self.assertEqual(telem["bring_to_front_calls"], 0)
            self.assertEqual(telem["native_input_calls"], 0)
            self.assertEqual(telem["reload_calls"], 2)
            self.assertFalse(telem["foreign_owner_page_closed"])
            self.assertEqual(telem["foreign_owner_blur_count"], 0)
            self.assertEqual(telem["foreign_owner_visibility_changes"], 0)
            self.assertEqual(telem["created_pages_total"], 2)
            self.assertEqual(telem["created_pages_open"], 0)
            self.assertEqual(len(form_srv.submissions), 2)
            self.assertEqual(form_srv.submissions[0]["revision"], 1)
            self.assertEqual(form_srv.submissions[1]["revision"], 2)
            self.assertEqual(json.loads(node_hub.ledger_file.read_text(encoding="utf-8"))["tabs"], [])
            self.assertEqual(hub.store.resources(), [])
            self.assertEqual(hub.store.permission_requests(), [])
            self.assertEqual(_sha256_or_none(policy_path), policy_hash_before)
        finally:
            hub.shutdown()
            hub.store.close()
            node_hub.stop()
            form_srv.close()

    @unittest.skipUnless(os.name == "nt", "Windows private desktop & Chrome 158+ test")
    def test_two_consecutive_form_workflows_via_real_chrome158_owner_chrome_hidden_and_focus_retention(self) -> None:
        chrome_exe = hidden_chrome.chrome_path()
        if chrome_exe is None:
            if os.environ.get("FF_REQUIRE_CHROME_158") == "1":
                self.fail("FF_REQUIRE_CHROME_158=1 requires installed Google Chrome >= 158.0.8127.2")
            self.skipTest("Google Chrome not installed on this host")
        chrome_ver = hidden_chrome.chrome_binary_version(chrome_exe)
        if chrome_ver is None:
            self.fail(f"Could not read PE version metadata from {chrome_exe}")
        if not owner_secondary._version_at_least(chrome_ver, owner_secondary.MIN_HIDDEN_TARGET_CHROME):
            got = ".".join(str(x) for x in chrome_ver)
            req = ".".join(str(x) for x in owner_secondary.MIN_HIDDEN_TARGET_CHROME)
            if os.environ.get("FF_REQUIRE_CHROME_158") == "1":
                self.fail(f"FF_REQUIRE_CHROME_158=1 requires Chrome >= {req}, found {got} at {chrome_exe}")
            self.skipTest(f"Installed Chrome binary {got} < required {req}")

        form_srv = _SyntheticFormServer().start()
        u32 = ctypes.WinDLL("user32", use_last_error=True)
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        u32.CreateDesktopW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, ctypes.c_void_p, wt.DWORD, wt.DWORD, ctypes.c_void_p]
        u32.CreateDesktopW.restype = wt.HANDLE
        u32.CloseDesktop.argtypes = [wt.HANDLE]
        u32.CloseDesktop.restype = wt.BOOL
        u32.GetForegroundWindow.restype = wt.HWND
        u32.GetCursorPos.argtypes = [ctypes.POINTER(wt.POINT)]
        u32.GetCursorPos.restype = wt.BOOL
        k32.CreateProcessW.argtypes = [
            wt.LPCWSTR, wt.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, wt.BOOL,
            wt.DWORD, ctypes.c_void_p, wt.LPCWSTR,
            ctypes.POINTER(hidden_chrome._WinStartupInfo),
            ctypes.POINTER(hidden_chrome._WinProcessInfo),
        ]
        k32.CreateProcessW.restype = wt.BOOL
        k32.ResumeThread.argtypes = [wt.HANDLE]
        k32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
        k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
        k32.CloseHandle.argtypes = [wt.HANDLE]

        synth_ud = self.root / "chrome-ud"
        proxy_ud = self.root / "proxy-ud"
        hub_state = self.root / "hub-chrome158"
        synth_ud.mkdir()
        proxy_ud.mkdir()
        (synth_ud / "Local State").write_text(
            json.dumps({"profile": {"last_used": "Profile 1", "last_active_profiles": ["Profile 1"]}}),
            encoding="utf-8",
        )

        fg_before = int(u32.GetForegroundWindow() or 0)
        desktop_name = "FFBridge-FormReg-" + secrets.token_hex(8)
        desktop = u32.CreateDesktopW(desktop_name, None, None, 0, 0x01FF, None)
        if not desktop:
            form_srv.close()
            self.skipTest("CreateDesktopW unavailable in this session")

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
                form_srv.owner_url,
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
                not marker.is_file() or not local_state.is_file() or not form_srv.owner_loaded.is_set()
            ):
                time.sleep(0.05)
            self.assertTrue(marker.is_file(), "Controlled Chrome did not write DevToolsActivePort")
            self.assertTrue(form_srv.owner_loaded.is_set(), "Controlled Chrome did not load /owner-active")
            time.sleep(0.4)

            real_lines = marker.read_text(encoding="ascii").splitlines()
            real_port, real_ws_path = int(real_lines[0]), real_lines[1].strip()
            proxy = _Http404WsPassthroughProxy(real_port, real_ws_path).start()

            (proxy_ud / "DevToolsActivePort").write_text(f"{proxy.port}\n{real_ws_path}\n", encoding="ascii")
            ls_data = json.loads(local_state.read_text(encoding="utf-8"))
            prof_meta = ls_data.setdefault("profile", {})
            prof_meta.setdefault("last_used", "Profile 1")
            if not prof_meta.get("last_active_profiles"):
                prof_meta["last_active_profiles"] = ["Profile 1"]
            (proxy_ud / "Local State").write_text(json.dumps(ls_data), encoding="utf-8")

            baseline_windows = _enum_desktop_chrome(desktop, chrome_pid)
            baseline_hwnds = {w["hwnd"] for w in baseline_windows}
            self.assertGreaterEqual(len(baseline_hwnds), 1)

            mgr = owner_secondary.OwnerChromeHiddenSecondaryManager(
                hub_state, profile_dir_name="Profile 1", user_data_dir=proxy_ud,
            )
            hub = Hub(hub_state, owner_chrome_secondary=mgr)
            policy_path = hub_state / "policy.json"
            Policy(policy_path).add_grant(
                ["owner_chrome_hidden_secondary"], agents=["c158-form"], hosts=["127.0.0.1"], ttl_seconds=300,
            )
            policy_hash_before = _sha256_or_none(policy_path)

            # Establish ONE already-authorized connection before running the two form workflows
            s0 = hub.dispatch({"op": "session_open", "args": {"agent_id": "c158-form", "task_id": "bootstrap"}})
            a0 = {"session_id": s0["session_id"], "session_secret": s0["session_secret"]}
            pf = hub.dispatch({
                **a0, "op": "owner_chrome_hidden",
                "args": {"command": "preflight", "connect_ws": True, "host": "127.0.0.1"},
            })
            self.assertTrue(pf["ok"], pf)
            self.assertEqual(proxy.ws_upgrade_count, 1)
            hub.dispatch({**a0, "op": "session_close", "request_key": "c158-boot-cls-01"})

            # Monitor OS foreground focus & Chrome HWNDs across BOTH workflows
            stop_obs = threading.Event()
            obs_stats = {"samples": 0, "new_hwnds": [], "any_visible": False, "any_taskbar": False, "fg_changed": False}

            def poll_focus_and_windows() -> None:
                seen: set[int] = set()
                while not stop_obs.is_set():
                    obs_stats["samples"] += 1
                    for item in _enum_desktop_chrome(desktop, chrome_pid):
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
                # Plan with strict_invisibility -> selects already connected owner_chrome_profile1_hidden_secondary
                rp = hub.dispatch({
                    "op": "route_plan",
                    "args": {
                        "surface": "browser",
                        "capability": "background_tab_form",
                        "agent_id": "c158-form",
                        "url": form_srv.form_url,
                        "visibility": "strict_invisible",
                    },
                })
                self.assertEqual(rp["selected"], owner_secondary.ROUTE_NAME)
                self.assertEqual(proxy.ws_upgrade_count, 1)

                # --- Consecutive Workflow 1 via Hub.dispatch (`owner_chrome_hidden`): fill -> save -> dedupe -> reload -> verify ---
                s1 = hub.dispatch({"op": "session_open", "args": {"agent_id": "c158-form", "task_id": "c158-wf1"}})
                a1 = {"session_id": s1["session_id"], "session_secret": s1["session_secret"]}
                open1 = hub.dispatch({
                    **a1, "op": "owner_chrome_hidden", "request_key": "c158-wf1-open-01",
                    "args": {"command": "open", "url": form_srv.form_url},
                })
                self.assertTrue(open1["hidden"])
                self.assertTrue(open1["windowless"])
                self.assertFalse(open1["visible_window_created"])
                self.assertFalse(open1["owner_tab_strip_modified"])
                tab1 = open1["tab_id"]

                obs1 = hub.dispatch({**a1, "op": "owner_chrome_hidden", "args": {"command": "observe", "tab_id": tab1}})
                by_id1 = {c["id"]: c for c in obs1["controls"] if c.get("id")}
                self.assertFalse(by_id1["notify-check"]["checked"])
                self.assertTrue(by_id1["readonly-code"]["readonly"])
                self.assertTrue(by_id1["disabled-field"]["disabled"])

                # Cross-agent isolation on owner_chrome_hidden
                s_other = hub.dispatch({"op": "session_open", "args": {"agent_id": "other-hidden-agent", "task_id": "c158-other"}})
                a_other = {"session_id": s_other["session_id"], "session_secret": s_other["session_secret"]}
                for cmd, rk, extra in (
                    ("read", None, {}),
                    ("act", "c158-other-act1", {"operation": "click", "selector": "#save-btn"}),
                    ("reload", "c158-other-rel1", {}),
                    ("close", "c158-other-cls1", {}),
                ):
                    with self.assertRaises(HubError) as iso_err:
                        req = {**a_other, "op": "owner_chrome_hidden", "args": {"command": cmd, "tab_id": tab1, **extra}}
                        if rk:
                            req["request_key"] = rk
                        hub.dispatch(req)
                    self.assertEqual(iso_err.exception.code, "RESOURCE_NOT_OWNED")
                hub.dispatch({**a_other, "op": "session_close", "request_key": "c158-other-scls1"})

                # Negative guard checks on real Chrome DOM
                with self.assertRaises(HubError) as ro_err:
                    hub.dispatch({
                        **a1, "op": "owner_chrome_hidden", "request_key": "c158-wf1-bad-ro",
                        "args": {"command": "act", "tab_id": tab1, "operation": "fill", "selector": "#readonly-code", "value": "x"},
                    })
                self.assertEqual(ro_err.exception.code, "TARGET_NOT_EDITABLE")
                with self.assertRaises(HubError) as opt_err:
                    hub.dispatch({
                        **a1, "op": "owner_chrome_hidden", "request_key": "c158-wf1-bad-opt",
                        "args": {"command": "act", "tab_id": tab1, "operation": "select", "selector": "#priority-select", "value": "no-such-opt"},
                    })
                self.assertEqual(opt_err.exception.code, "OPTION_NOT_FOUND")

                # Re-observe after failed acts invalidated snapshot, then fill title using snapshot + ref!
                obs1_ref = hub.dispatch({**a1, "op": "owner_chrome_hidden", "args": {"command": "observe", "tab_id": tab1}})
                title_ref = next(c["ref"] for c in obs1_ref["controls"] if c.get("id") == "title-input")
                hub.dispatch({
                    **a1, "op": "owner_chrome_hidden", "request_key": "c158-wf1-fill-title",
                    "args": {
                        "command": "act", "tab_id": tab1, "operation": "fill",
                        "snapshot": obs1_ref["snapshot"], "ref": title_ref, "value": "Chrome158 Form v1",
                    },
                })
                hub.dispatch({
                    **a1, "op": "owner_chrome_hidden", "request_key": "c158-wf1-fill-notes",
                    "args": {"command": "act", "tab_id": tab1, "operation": "fill", "target": {"label": "Notes"}, "value": "Hidden CDP draft"},
                })
                sel1 = hub.dispatch({
                    **a1, "op": "owner_chrome_hidden", "request_key": "c158-wf1-sel-prio",
                    "args": {"command": "act", "tab_id": tab1, "operation": "select", "selector": "#priority-select", "value": "high"},
                })
                self.assertEqual(sel1["detail"], {"mode": "dom-select", "selected": ["high"]})
                hub.dispatch({
                    **a1, "op": "owner_chrome_hidden", "request_key": "c158-wf1-chk-notify",
                    "args": {
                        "command": "act", "tab_id": tab1, "operation": "check", "selector": "#notify-check",
                        "postcondition": {"type": "checked_equals", "selector": "#notify-check", "checked": True},
                    },
                })
                hub.dispatch({
                    **a1, "op": "owner_chrome_hidden", "request_key": "c158-wf1-chk-draft",
                    "args": {"command": "act", "tab_id": tab1, "operation": "check", "selector": "#mode-draft"},
                })

                save1_req = {
                    **a1, "op": "owner_chrome_hidden", "request_key": "c158-wf1-save-01",
                    "args": {
                        "command": "act", "tab_id": tab1, "operation": "click", "selector": "#save-btn",
                        "postcondition": {"type": "text_includes", "value": "SAVED:rev=1:title=Chrome158 Form v1"},
                    },
                }
                save1 = hub.dispatch(save1_req)
                self.assertFalse(save1["deduplicated"])
                self.assertTrue(save1["verified"])
                self.assertFalse(save1["physical_input_used"])
                self.assertEqual(len(form_srv.submissions), 1)

                # Replay exact save key -> deduplicated, 0 duplicate submissions
                save1_dup = hub.dispatch(save1_req)
                self.assertTrue(save1_dup["deduplicated"])
                self.assertEqual(len(form_srv.submissions), 1)
                st1 = hub.dispatch({**a1, "op": "request_status", "args": {"request_key": "c158-wf1-save-01"}})
                self.assertEqual(st1["state"], "completed")
                self.assertFalse(st1["automatic_replay"])

                # Real CDP Page.reload & verify persisted server state
                gets_before_rel1 = form_srv.form_get_count
                rel1 = hub.dispatch({
                    **a1, "op": "owner_chrome_hidden", "request_key": "c158-wf1-reload1",
                    "args": {"command": "reload", "tab_id": tab1},
                })
                self.assertTrue(rel1["reloaded"])
                self.assertFalse(rel1["physical_input_used"])
                self.assertEqual(form_srv.form_get_count, gets_before_rel1 + 1)
                self.assertEqual(len(form_srv.submissions), 1)

                hub.dispatch({
                    **a1, "op": "owner_chrome_hidden",
                    "args": {
                        "command": "wait_for", "tab_id": tab1,
                        "condition": {"target": {"selector": "#title-input"}, "value": "Chrome158 Form v1"},
                    },
                })
                obs1_after = hub.dispatch({**a1, "op": "owner_chrome_hidden", "args": {"command": "observe", "tab_id": tab1}})
                by_id1_after = {c["id"]: c for c in obs1_after["controls"] if c.get("id")}
                self.assertEqual(by_id1_after["title-input"]["value"], "Chrome158 Form v1")
                self.assertEqual(by_id1_after["notes-input"]["value"], "Hidden CDP draft")
                self.assertEqual(by_id1_after["priority-select"]["value"], "high")
                self.assertTrue(by_id1_after["notify-check"]["checked"])
                self.assertTrue(by_id1_after["mode-draft"]["checked"])
                self.assertIn("LOADED:rev=1", obs1_after["text"])

                r1_title = hub.dispatch({**a1, "op": "owner_chrome_hidden", "args": {"command": "read", "tab_id": tab1, "selector": "#title-input"}})
                self.assertEqual(r1_title["value"], "Chrome158 Form v1")

                c1 = hub.dispatch({**a1, "op": "session_close", "request_key": "c158-wf1-close1"})
                self.assertTrue(c1["closed"])
                self.assertTrue(c1["cleanup_verified"])
                self.assertEqual(c1["resources_retained"], 0)
                self.assertEqual(c1["owner_chrome_hidden_targets_closed"], 1)

                # --- Consecutive Workflow 2 via MCP Adapter + `/agent/v1` entry check: edit -> save (Enter) -> reload -> verify ---
                adapter = Adapter(hub_state, "c158-form", client=_make_direct_mcp_client(hub))
                try:
                    adapter.call({"op": "session_open", "task_id": "c158-wf2"})
                    open2 = adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2", "request_key": "c158-wf2-open-01",
                        "args": {"command": "open", "url": form_srv.form_url},
                    })
                    tab2 = open2["tab_id"]
                    self.assertNotEqual(tab2, tab1)

                    # Confirm WF1 state loaded in new tab
                    r2_pre = adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2",
                        "args": {"command": "read", "tab_id": tab2, "selector": "#title-input"},
                    })
                    self.assertEqual(r2_pre["value"], "Chrome158 Form v1")

                    adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2", "request_key": "c158-wf2-edit-title",
                        "args": {"command": "act", "tab_id": tab2, "operation": "fill", "selector": "#title-input", "value": "Chrome158 Form v2 Edited"},
                    })
                    adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2", "request_key": "c158-wf2-edit-notes",
                        "args": {"command": "act", "tab_id": tab2, "operation": "fill", "selector": "#notes-input", "value": "Second workflow saved cleanly"},
                    })
                    adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2", "request_key": "c158-wf2-edit-prio",
                        "args": {"command": "act", "tab_id": tab2, "operation": "select", "selector": "#priority-select", "value": "urgent"},
                    })
                    adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2", "request_key": "c158-wf2-unchk",
                        "args": {
                            "command": "act", "tab_id": tab2, "operation": "uncheck", "selector": "#notify-check",
                            "postcondition": {"target": {"selector": "#notify-check"}, "checked": False},
                        },
                    })
                    adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2", "request_key": "c158-wf2-chk-final",
                        "args": {"command": "act", "tab_id": tab2, "operation": "check", "selector": "#mode-final"},
                    })

                    # Enter on textarea does not submit
                    ta_p = adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2", "request_key": "c158-wf2-ta-enter",
                        "args": {"command": "act", "tab_id": tab2, "operation": "press", "selector": "#notes-input", "key": "Enter"},
                    })
                    self.assertEqual(ta_p["detail"], "dispatched")
                    self.assertEqual(len(form_srv.submissions), 1)

                    # Save WF2 via Enter on title input
                    save2_call = {
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2", "request_key": "c158-wf2-save-01",
                        "args": {
                            "command": "act", "tab_id": tab2, "operation": "press", "selector": "#title-input", "key": "Enter",
                            "postcondition": {"text_present": "SAVED:rev=2:title=Chrome158 Form v2 Edited"},
                        },
                    }
                    save2 = adapter.call(save2_call)
                    self.assertFalse(save2["deduplicated"])
                    self.assertEqual(save2["detail"], "form_submitted")
                    self.assertEqual(len(form_srv.submissions), 2)

                    # Replay exact save key -> deduplicated, still 2 submissions
                    save2_dup = adapter.call(save2_call)
                    self.assertTrue(save2_dup["deduplicated"])
                    self.assertEqual(len(form_srv.submissions), 2)

                    # Reload & verify stored data after reload
                    gets_before_rel2 = form_srv.form_get_count
                    rel2 = adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2", "request_key": "c158-wf2-reload1",
                        "args": {"command": "reload", "tab_id": tab2},
                    })
                    self.assertTrue(rel2["reloaded"])
                    self.assertEqual(form_srv.form_get_count, gets_before_rel2 + 1)
                    self.assertEqual(len(form_srv.submissions), 2)

                    adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2",
                        "args": {
                            "command": "wait_for", "tab_id": tab2,
                            "condition": {"target": {"selector": "#title-input"}, "value": "Chrome158 Form v2 Edited"},
                        },
                    })
                    obs2_after = adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2",
                        "args": {"command": "observe", "tab_id": tab2},
                    })
                    by_id2_after = {c["id"]: c for c in obs2_after["controls"] if c.get("id")}
                    self.assertEqual(by_id2_after["title-input"]["value"], "Chrome158 Form v2 Edited")
                    self.assertEqual(by_id2_after["notes-input"]["value"], "Second workflow saved cleanly")
                    self.assertEqual(by_id2_after["priority-select"]["value"], "urgent")
                    self.assertFalse(by_id2_after["notify-check"]["checked"])
                    self.assertTrue(by_id2_after["mode-final"]["checked"])
                    r2_json = adapter.call({
                        "op": "owner_chrome_hidden", "task_id": "c158-wf2",
                        "args": {"command": "read", "tab_id": tab2, "selector": "#persisted-json"},
                    })
                    self.assertEqual(json.loads(r2_json["text"]), {
                        "mode": "final",
                        "notes": "Second workflow saved cleanly",
                        "notify": False,
                        "priority": "urgent",
                        "revision": 2,
                        "title": "Chrome158 Form v2 Edited",
                    })

                    c2 = adapter.call({"op": "session_close", "task_id": "c158-wf2", "request_key": "c158-wf2-close1"})
                    self.assertTrue(c2["closed"])
                    self.assertTrue(c2["cleanup_verified"])
                    self.assertEqual(c2["resources_retained"], 0)
                    self.assertEqual(c2["owner_chrome_hidden_targets_closed"], 1)
                finally:
                    adapter.close()

                # Verify `/agent/v1` scoped entry advertises & supports `reload` (keyed) and `wait_for` (read-only)
                ea = EntryAuthority(hub_state)
                _, tok = ea.issue(
                    client_id="c-form-entry", agent_id="c158-form", task_id="c158-entry-check",
                    scopes=["owner_chrome_hidden"], apps=[], ttl=180,
                )
                bearer = f"Bearer {tok}"
                ecaps = entry_call(hub, ea, bearer, {"op": "capabilities"})
                self.assertIn("reload", ecaps["owner_chrome_hidden_commands"])
                self.assertIn("wait_for", ecaps["owner_chrome_hidden_commands"])
                esid = entry_call(hub, ea, bearer, {"op": "session_open"})["session_id"]
                etab = entry_call(hub, ea, bearer, {
                    "op": "owner_chrome_hidden", "session_id": esid, "request_key": "entry-open-0001",
                    "args": {"command": "open", "url": form_srv.form_url},
                })["tab_id"]
                # Unkeyed reload rejected fail-closed
                with self.assertRaises(HubError) as e_unkeyed:
                    entry_call(hub, ea, bearer, {
                        "op": "owner_chrome_hidden", "session_id": esid,
                        "args": {"command": "reload", "tab_id": etab},
                    })
                self.assertEqual(e_unkeyed.exception.code, "REQUEST_KEY_REQUIRED")
                erel = entry_call(hub, ea, bearer, {
                    "op": "owner_chrome_hidden", "session_id": esid, "request_key": "entry-rel-0001",
                    "args": {"command": "reload", "tab_id": etab},
                })
                self.assertTrue(erel["reloaded"])
                ewait = entry_call(hub, ea, bearer, {
                    "op": "owner_chrome_hidden", "session_id": esid,
                    "args": {"command": "wait_for", "tab_id": etab, "condition": {"text_present": "LOADED:rev=2"}},
                })
                self.assertTrue(ewait["satisfied"])

                # Live host-drift guard on real Chrome 158: client-side async navigation to `localhost`
                # must fail closed with TAB_HOST_CHANGED before any subsequent act or reload!
                entry_call(hub, ea, bearer, {
                    "op": "owner_chrome_hidden", "session_id": esid, "request_key": "entry-drift-001",
                    "args": {"command": "act", "tab_id": etab, "operation": "click", "selector": "#async-drift-btn"},
                })
                deadline_drift = time.monotonic() + 5.0
                while time.monotonic() < deadline_drift:
                    try:
                        entry_call(hub, ea, bearer, {
                            "op": "owner_chrome_hidden", "session_id": esid,
                            "args": {"command": "wait_for", "tab_id": etab, "condition": {"url_contains": "/other-host"}, "timeout_ms": 200},
                        })
                    except HubError as exc:
                        if exc.code == "TAB_HOST_CHANGED":
                            break
                    time.sleep(0.05)
                with self.assertRaises(HubError) as drift_act:
                    entry_call(hub, ea, bearer, {
                        "op": "owner_chrome_hidden", "session_id": esid, "request_key": "entry-drift-act1",
                        "args": {"command": "act", "tab_id": etab, "operation": "click", "selector": "#save-btn"},
                    })
                self.assertEqual(drift_act.exception.code, "TAB_HOST_CHANGED")
                with self.assertRaises(HubError) as drift_rel:
                    entry_call(hub, ea, bearer, {
                        "op": "owner_chrome_hidden", "session_id": esid, "request_key": "entry-drift-rel1",
                        "args": {"command": "reload", "tab_id": etab},
                    })
                self.assertEqual(drift_rel.exception.code, "TAB_HOST_CHANGED")

                eclose = entry_call(hub, ea, bearer, {
                    "op": "session_close", "session_id": esid, "request_key": "entry-cls-0001",
                })
                self.assertTrue(eclose["cleanup_verified"])
            finally:
                stop_obs.set()
                obs_thread.join(timeout=2.0)

            # Verify focus retention on BOTH Windows OS level AND primary Chrome owner tab
            self.assertGreater(obs_stats["samples"], 20)
            self.assertEqual(obs_stats["new_hwnds"], [])
            self.assertFalse(obs_stats["any_visible"])
            self.assertFalse(obs_stats["any_taskbar"])
            self.assertFalse(obs_stats["fg_changed"])
            self.assertEqual(proxy.ws_upgrade_count, 1)

            # Read-only CDP inspection of primary owner tab (`/owner-active`) proves zero blur/visibility changes
            ws = _LocalWebSocket(f"ws://127.0.0.1:{real_port}{real_ws_path}", timeout=5.0)
            try:
                ws.send(json.dumps({"id": 1, "method": "Target.getTargets", "params": {}}))
                targets = []
                while True:
                    msg = json.loads(ws.recv())
                    if msg.get("id") == 1:
                        targets = msg["result"]["targetInfos"]
                        break
                owner_pages = [t for t in targets if t.get("type") == "page" and "/owner-active" in str(t.get("url") or "")]
                self.assertEqual(len(owner_pages), 1)
                # Zero leaked hidden /form targets remaining in Chrome
                leaked_form = [t for t in targets if t.get("type") == "page" and "/form" in str(t.get("url") or "")]
                self.assertEqual(leaked_form, [])
                ws.send(json.dumps({"id": 2, "method": "Target.attachToTarget", "params": {"targetId": owner_pages[0]["targetId"], "flatten": True}}))
                owner_sid = None
                while True:
                    msg = json.loads(ws.recv())
                    if msg.get("id") == 2:
                        owner_sid = msg["result"]["sessionId"]
                        break
                ws.send(json.dumps({
                    "id": 3, "sessionId": owner_sid, "method": "Runtime.evaluate",
                    "params": {
                        "expression": "({draft: document.getElementById('owner-draft')?.value, activeId: document.activeElement?.id, telemetry: window.__ownerFocusTelemetry})",
                        "returnByValue": True,
                    },
                }))
                owner_eval = None
                while True:
                    msg = json.loads(ws.recv())
                    if msg.get("id") == 3:
                        owner_eval = msg["result"]["result"]["value"]
                        break
                self.assertEqual(owner_eval["draft"], "owner-typing-in-progress")
                self.assertEqual(owner_eval["activeId"], "owner-draft")
                self.assertEqual(owner_eval["telemetry"]["blur_count"], 0)
                self.assertEqual(owner_eval["telemetry"]["visibility_change_count"], 0)
            finally:
                ws.close()

            self.assertEqual(len(form_srv.submissions), 2)
            self.assertEqual(hub.store.resources(), [])
            self.assertEqual(hub.store.permission_requests(), [])
            self.assertEqual(_sha256_or_none(policy_path), policy_hash_before)
        finally:
            if hub is not None:
                hub.shutdown()
                hub.store.close()
            if proxy is not None:
                proxy.close()
            if job is not None:
                _close_windows_job_handle(job)
            if hproc:
                k32.TerminateProcess(hproc, 1)
                k32.WaitForSingleObject(hproc, 5000)
                k32.CloseHandle(hproc)
            u32.CloseDesktop(desktop)
            form_srv.close()


if __name__ == "__main__":
    unittest.main()
