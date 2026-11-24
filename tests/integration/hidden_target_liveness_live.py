"""Opt-in real Chrome 158 acceptance test for windowless hidden target scheduler liveness and Enter press.

Runs an isolated headless Chrome with a temporary User Data dir (ZERO touch on owner Chrome
or owner windows) and verifies against real `Target.createTarget({hidden: true})`:
1. Without the liveness shim, `requestIdleCallback` (with and without timeout) and
   `requestAnimationFrame` starve in Chrome 158 windowless hidden targets, deadlocking
   an Angular/Gemini-style idle-gated Send button.
2. With `OwnerChromeHiddenSecondaryManager.call("open")`, the preload liveness shim runs
   before document bootstrap so:
   - `requestIdleCallback` (with & without timeout) and `requestAnimationFrame` fire promptly,
   - `cancelIdleCallback` and `cancelAnimationFrame` cancel cleanly without firing,
   - an idle-gated Send button succeeds on first `act(click)` via hidden Chrome,
   - `act(press, key="Enter")` focuses a `contenteditable` editor and delivers
     `keyCode === 13` / `which === 13` (Quill-compatible),
   - `act(press, key="Shift+Enter")` sets `shiftKey: true` without triggering form submit.
"""
from __future__ import annotations

import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
from cua_owner_chrome_secondary import OwnerChromeHiddenSecondaryManager

OWNER = "isolated-liveness\x1ftest"

FIXTURE_HTML = """<!doctype html>
<html>
<head><meta charset="utf-8"><title>Hidden Liveness Fixture</title></head>
<body>
  <form id="f">
    <input id="inp" type="text" value="draft">
  </form>
  <div id="ed" class="ql-editor" contenteditable="true" role="textbox" aria-label="Prompt"></div>
  <button id="send" type="button" aria-label="Send message">Send</button>
  <script>
    window.__state = {
      ricNoTimeout: 0,
      ricWithTimeout: 0,
      ricCancelledFired: 0,
      rafFired: 0,
      rafCancelledFired: 0,
      sentPayloads: [],
      keyEvents: [],
      formSubmits: 0,
      editorFocusedOnEnter: false,
    };
    const cid = requestIdleCallback(() => { window.__state.ricCancelledFired++; });
    cancelIdleCallback(cid);
    const rid = requestAnimationFrame(() => { window.__state.rafCancelledFired++; });
    cancelAnimationFrame(rid);

    requestIdleCallback((d) => {
      if (d && typeof d.timeRemaining === 'function') window.__state.ricNoTimeout++;
    });
    requestIdleCallback((d) => {
      if (d && typeof d.timeRemaining === 'function') window.__state.ricWithTimeout++;
    }, { timeout: 200 });
    requestAnimationFrame((ts) => {
      if (typeof ts === 'number') window.__state.rafFired++;
    });

    // Reproduce Gemini Task mode _.HD(() => ... ) idle-gated send pipeline:
    let idleLoaderPromise = null;
    function getIdleGate() {
      if (!idleLoaderPromise) {
        idleLoaderPromise = new Promise((resolve) => {
          requestIdleCallback(() => resolve({ allowSend: true }));
        });
      }
      return idleLoaderPromise;
    }

    const ed = document.getElementById('ed');
    const sendBtn = document.getElementById('send');
    const form = document.getElementById('f');
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      window.__state.formSubmits++;
    });
    ed.addEventListener('keydown', (ev) => {
      window.__state.keyEvents.push({
        key: ev.key,
        code: ev.code,
        keyCode: ev.keyCode,
        which: ev.which,
        shiftKey: ev.shiftKey,
        ctrlKey: ev.ctrlKey,
      });
      if (ev.keyCode === 13 && !ev.shiftKey && !ev.ctrlKey) {
        window.__state.editorFocusedOnEnter = (document.activeElement === ed);
        ev.preventDefault();
        sendBtn.click();
      }
    });
    sendBtn.addEventListener('click', () => {
      const text = (ed.textContent || '').trim();
      getIdleGate().then((g) => {
        if (g.allowSend && text) window.__state.sentPayloads.push(text);
      });
    });
  </script>
</body>
</html>"""


class _FixtureHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = FIXTURE_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def _find_chrome() -> str:
    candidates = [
        Path(os.environ.get("PROGRAMFILES", "")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("PROGRAMFILES(X86)", "")) / "Google/Chrome/Application/chrome.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/Application/chrome.exe",
    ]
    for p in candidates:
        if p.is_file():
            return str(p)
    found = shutil.which("chrome") or shutil.which("chrome.exe")
    if found:
        return found
    raise RuntimeError("Chrome binary not found")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def main() -> None:
    chrome_exe = _find_chrome()
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    fixture_url = f"http://127.0.0.1:{srv.server_address[1]}/fixture"
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()

    tmp = Path(tempfile.mkdtemp(prefix="ff-liveness-live-"))
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    proc = subprocess.Popen(
        [
            chrome_exe,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--profile-directory=Default",
            "--remote-debugging-address=127.0.0.1",
            "--remote-debugging-port=0",
            f"--user-data-dir={tmp}",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=flags,
    )
    mgr: OwnerChromeHiddenSecondaryManager | None = None
    try:
        marker = tmp / "DevToolsActivePort"
        local_state = tmp / "Local State"
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if marker.is_file() and local_state.is_file():
                lines = marker.read_text(encoding="ascii", errors="ignore").splitlines()
                if len(lines) >= 2 and lines[0].strip().isdigit():
                    cdp_port = int(lines[0].strip())
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{cdp_port}/json/version", timeout=1.0) as r:
                            if r.status == 200:
                                break
                    except Exception:
                        pass
            time.sleep(0.1)
        else:
            raise RuntimeError(f"Isolated Chrome did not publish CDP endpoint (marker={marker.is_file()}, ls={local_state.is_file()})")

        ls_data = json.loads(local_state.read_text(encoding="utf-8"))
        ls_data.setdefault("profile", {})["last_used"] = "Default"
        ls_data["profile"]["last_active_profiles"] = ["Default"]
        local_state.write_text(json.dumps(ls_data), encoding="utf-8")

        mgr = OwnerChromeHiddenSecondaryManager(user_data_dir=tmp, profile_dir_name="Default")
        opened = mgr.call("open", {"owner": OWNER, "url": fixture_url})
        tab_id = opened["tab_id"]

        # Wait briefly for idle & raf callbacks to settle.
        time.sleep(0.25)
        liveness_mark = mgr.call(
            "evaluate",
            {
                "owner": OWNER,
                "tab_id": tab_id,
                "expression": "({mark: Boolean(globalThis[Symbol.for('__ff_hidden_target_liveness_v1__')]), hasFocus: document.hasFocus(), vis: document.visibilityState})",
            },
        )["value"]
        assert liveness_mark["mark"] is True, liveness_mark
        assert liveness_mark["hasFocus"] is True, liveness_mark
        assert liveness_mark["vis"] == "visible", liveness_mark
        st = mgr.call("evaluate", {"owner": OWNER, "tab_id": tab_id, "expression": "window.__state"})["value"]
        assert st["ricNoTimeout"] == 1, st
        assert st["ricWithTimeout"] == 1, st
        assert st["ricCancelledFired"] == 0, st
        assert st["rafFired"] == 1, st
        assert st["rafCancelledFired"] == 0, st
        print("PASS requestIdleCallback & requestAnimationFrame live with clean cancel in hidden target:", liveness_mark, st)

        # Fill editor and click idle-gated Send button.
        mgr.call("act", {
            "owner": OWNER,
            "tab_id": tab_id,
            "operation": "fill",
            "selector": "#ed",
            "value": "PAYLOAD_VIA_CLICK",
        })
        mgr.call("act", {
            "owner": OWNER,
            "tab_id": tab_id,
            "operation": "click",
            "selector": "#send",
        })
        time.sleep(0.15)
        st = mgr.call("evaluate", {"owner": OWNER, "tab_id": tab_id, "expression": "window.__state"})["value"]
        assert st["sentPayloads"] == ["PAYLOAD_VIA_CLICK"], st
        print("PASS idle-gated Send button fired on first click")

        # Shift+Enter on input inside <form> must NOT submit form.
        mgr.call("act", {
            "owner": OWNER,
            "tab_id": tab_id,
            "operation": "press",
            "selector": "#inp",
            "key": "Shift+Enter",
        })
        st = mgr.call("evaluate", {"owner": OWNER, "tab_id": tab_id, "expression": "window.__state"})["value"]
        assert st["formSubmits"] == 0, st

        # Press Enter on contenteditable editor (currently NOT focused since #inp was focused):
        # must focus #ed, dispatch keyCode=13 / which=13, and trigger send!
        mgr.call("act", {
            "owner": OWNER,
            "tab_id": tab_id,
            "operation": "fill",
            "selector": "#ed",
            "value": "PAYLOAD_VIA_ENTER",
        })
        mgr.call("act", {
            "owner": OWNER,
            "tab_id": tab_id,
            "operation": "press",
            "selector": "#ed",
            "key": "Shift+Enter",
        })
        mgr.call("act", {
            "owner": OWNER,
            "tab_id": tab_id,
            "operation": "press",
            "selector": "#ed",
            "key": "Enter",
        })
        time.sleep(0.15)
        st = mgr.call("evaluate", {"owner": OWNER, "tab_id": tab_id, "expression": "window.__state"})["value"]
        assert st["editorFocusedOnEnter"] is True, st
        assert len(st["keyEvents"]) == 2, st
        assert st["keyEvents"][0]["keyCode"] == 13 and st["keyEvents"][0]["shiftKey"] is True, st
        assert st["keyEvents"][1]["keyCode"] == 13 and st["keyEvents"][1]["which"] == 13 and st["keyEvents"][1]["shiftKey"] is False, st
        assert st["sentPayloads"] == ["PAYLOAD_VIA_CLICK", "PAYLOAD_VIA_ENTER"], st
        print("PASS press(Enter) & press(Shift+Enter) delivered keyCode=13/which=13 with focus")

        closed = mgr.call("close_owner", {"owner": OWNER})
        assert closed["closed"] == 1 and not closed["unconfirmed"], closed
        print("REAL_CHROMIUM_HIDDEN_LIVENESS_SEND_OK")
    finally:
        if mgr is not None:
            try:
                mgr.shutdown(close_targets=True)
            except Exception:
                pass
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        srv.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
