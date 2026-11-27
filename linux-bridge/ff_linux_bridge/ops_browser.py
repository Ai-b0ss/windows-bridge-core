"""Level-2 Browser Automation operations via Chrome DevTools Protocol (CDP).

Supports launching a managed headless/headed Chromium/Chrome instance OR
attaching to an existing loopback Chrome CDP endpoint (`http://127.0.0.1:9222`).
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

from .cdp_client import CDPError, CDPSession, cdp_http_json
from .ops_files import resolve_path


class BrowserOpError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


BROWSER_CANDIDATES = (
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "brave-browser",
    "microsoft-edge",
)


def find_browser_binary(preferred: str | None = None) -> str:
    if preferred:
        if os.path.isfile(preferred) and os.access(preferred, os.X_OK):
            return preferred
        found = shutil.which(preferred)
        if found:
            return found
        raise BrowserOpError("BROWSER_NOT_FOUND", f"Specified browser binary not found: {preferred}")
    env_bin = os.environ.get("FF_LINUX_BROWSER_BIN", "").strip()
    if env_bin:
        return find_browser_binary(env_bin)
    for name in BROWSER_CANDIDATES:
        found = shutil.which(name)
        if found:
            return found
    raise BrowserOpError(
        "BROWSER_NOT_FOUND",
        f"No Chromium/Chrome binary found in PATH (tried {', '.join(BROWSER_CANDIDATES)})",
    )


def _pick_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _parse_loopback_port(endpoint: str | int) -> int:
    if isinstance(endpoint, int):
        return endpoint
    raw = str(endpoint).strip()
    if raw.isdigit():
        return int(raw)
    parsed = urlsplit(raw)
    if parsed.scheme not in ("http", "ws"):
        raise BrowserOpError("INVALID_CDP_ENDPOINT", f"CDP endpoint must be http://127.0.0.1:<port>, got: {raw}")
    if parsed.hostname not in ("127.0.0.1", "localhost"):
        raise BrowserOpError("NON_LOOPBACK_CDP", f"Refusing non-loopback CDP endpoint: {raw}")
    if not parsed.port:
        raise BrowserOpError("INVALID_CDP_ENDPOINT", f"Missing port in CDP endpoint: {raw}")
    return int(parsed.port)


class BrowserManager:
    """Manages a single CDP browser connection (managed or attached)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.port: int | None = None
        self.proc: subprocess.Popen[bytes] | None = None
        self.temp_profile_dir: str | None = None
        self.active_target_id: str | None = None
        self.managed: bool = False
        self.binary: str | None = None
        self.headless: bool | None = None

    def _is_port_alive(self, port: int) -> dict[str, Any] | None:
        try:
            ver = cdp_http_json(port, "/json/version", timeout_s=2.0)
            return ver if isinstance(ver, dict) else None
        except CDPError:
            return None

    def launch(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if self.port and self._is_port_alive(self.port):
                if not bool(args.get("relaunch", False)):
                    return self.status()
                self.close()

            binary = find_browser_binary(args.get("binary"))
            port = int(args.get("port") or _pick_free_port())
            has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
            headless = bool(args.get("headless", not has_display))

            user_data_dir = args.get("user_data_dir")
            temp_dir = None
            if user_data_dir:
                profile_dir = str(Path(os.path.expanduser(str(user_data_dir))).resolve())
                Path(profile_dir).mkdir(parents=True, exist_ok=True)
            else:
                temp_dir = tempfile.mkdtemp(prefix="ff-linux-chrome-")
                profile_dir = temp_dir

            cmd = [
                binary,
                f"--remote-debugging-port={port}",
                "--remote-debugging-address=127.0.0.1",
                f"--user-data-dir={profile_dir}",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-sync",
                "--disable-dev-shm-usage",
                f"--window-size={int(args.get('width', 1440))},{int(args.get('height', 900))}",
            ]
            if headless:
                cmd.append("--headless=new")
            if bool(args.get("no_sandbox", os.geteuid() == 0)):
                cmd.append("--no-sandbox")
            extra_args = args.get("extra_args")
            if isinstance(extra_args, list):
                cmd.extend(str(a) for a in extra_args)
            start_url = str(args.get("url") or "about:blank")
            cmd.append(start_url)

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )

            timeout_s = max(3.0, min(float(args.get("timeout_s", 15.0)), 45.0))
            deadline = time.monotonic() + timeout_s
            ver = None
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    err = (proc.stderr.read() if proc.stderr else b"").decode("utf-8", errors="replace")[-1200:]
                    if temp_dir:
                        shutil.rmtree(temp_dir, ignore_errors=True)
                    raise BrowserOpError("BROWSER_LAUNCH_FAILED", f"Browser exited ({proc.returncode}): {err}")
                ver = self._is_port_alive(port)
                if ver:
                    break
                time.sleep(0.2)

            if not ver:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if temp_dir:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                raise BrowserOpError("BROWSER_LAUNCH_TIMEOUT", f"CDP did not become ready on 127.0.0.1:{port}")

            self.port = port
            self.proc = proc
            self.temp_profile_dir = temp_dir
            self.managed = True
            self.binary = binary
            self.headless = headless
            self.active_target_id = None
            return self.status()

    def connect(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            endpoint = args.get("endpoint") or args.get("url") or args.get("port") or 9222
            port = _parse_loopback_port(endpoint)
            ver = self._is_port_alive(port)
            if not ver:
                raise BrowserOpError("CDP_NOT_REACHABLE", f"No live CDP browser on 127.0.0.1:{port}")
            self.port = port
            self.proc = None
            self.managed = False
            self.binary = None
            self.headless = None
            self.active_target_id = None
            return self.status()

    def status(self) -> dict[str, Any]:
        with self._lock:
            if not self.port:
                return {"connected": False, "managed": False, "port": None, "tabs_count": 0}
            ver = self._is_port_alive(self.port)
            if not ver:
                return {"connected": False, "managed": self.managed, "port": self.port, "tabs_count": 0}
            pages = self._list_page_targets()
            return {
                "connected": True,
                "managed": self.managed,
                "pid": self.proc.pid if self.proc else None,
                "binary": self.binary,
                "headless": self.headless,
                "port": self.port,
                "browser": ver.get("Browser"),
                "protocol_version": ver.get("Protocol-Version"),
                "active_target_id": self.active_target_id,
                "tabs_count": len(pages),
            }

    def close(self) -> dict[str, Any]:
        with self._lock:
            was_managed = self.managed
            pid = self.proc.pid if self.proc else None
            if self.proc is not None:
                try:
                    os.killpg(self.proc.pid, signal.SIGTERM)
                    self.proc.wait(timeout=3.0)
                except Exception:
                    try:
                        os.killpg(self.proc.pid, signal.SIGKILL)
                    except Exception:
                        pass
                try:
                    if self.proc.stderr:
                        self.proc.stderr.close()
                except Exception:
                    pass
            if self.temp_profile_dir:
                shutil.rmtree(self.temp_profile_dir, ignore_errors=True)
            self.port = None
            self.proc = None
            self.temp_profile_dir = None
            self.active_target_id = None
            self.managed = False
            self.binary = None
            self.headless = None
            return {"closed": True, "was_managed": was_managed, "killed_pid": pid}

    def _require_port(self) -> int:
        if not self.port or not self._is_port_alive(self.port):
            raise BrowserOpError("BROWSER_NOT_CONNECTED", "Call browser_launch or browser_connect first")
        return self.port

    def _list_page_targets(self) -> list[dict[str, Any]]:
        port = self._require_port()
        targets = cdp_http_json(port, "/json/list", timeout_s=5.0)
        if not isinstance(targets, list):
            return []
        return [t for t in targets if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]

    def _resolve_target(self, target_id: str | None = None) -> dict[str, Any]:
        pages = self._list_page_targets()
        if not pages:
            self.open_tab({"url": "about:blank"})
            pages = self._list_page_targets()
        if not pages:
            raise BrowserOpError("NO_PAGE_TARGET", "No debuggable page tabs available")

        wanted = target_id or self.active_target_id
        if wanted:
            for p in pages:
                if p.get("id") == wanted:
                    self.active_target_id = p["id"]
                    return p
            if target_id:
                raise BrowserOpError("TARGET_NOT_FOUND", f"Tab target_id not found: {target_id}")

        self.active_target_id = pages[0]["id"]
        return pages[0]

    def tabs(self) -> dict[str, Any]:
        with self._lock:
            pages = self._list_page_targets()
            return {
                "active_target_id": self.active_target_id,
                "count": len(pages),
                "tabs": [
                    {
                        "target_id": p.get("id"),
                        "title": p.get("title", ""),
                        "url": p.get("url", ""),
                    }
                    for p in pages
                ],
            }

    def open_tab(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            port = self._require_port()
            url = str(args.get("url") or "about:blank")
            encoded = quote(url, safe=":/?&=#%+-._~")
            try:
                created = cdp_http_json(port, f"/json/new?{encoded}", method="PUT", timeout_s=8.0)
            except CDPError:
                created = cdp_http_json(port, f"/json/new?{encoded}", method="GET", timeout_s=8.0)
            tid = created.get("id")
            if tid:
                self.active_target_id = tid
            if url != "about:blank" and bool(args.get("wait_load", True)) and tid:
                self._wait_ready_state(tid, timeout_s=float(args.get("timeout_s", 15.0)))
            return {"target_id": tid, "url": created.get("url", url), "title": created.get("title", "")}

    def close_tab(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            port = self._require_port()
            target = self._resolve_target(args.get("target_id"))
            tid = target["id"]
            cdp_http_json(port, f"/json/close/{tid}", method="GET", timeout_s=5.0)
            if self.active_target_id == tid:
                self.active_target_id = None
            return {"closed_target_id": tid}

    def _eval_on_session(self, session: CDPSession, expression: str, timeout_s: float = 15.0) -> Any:
        res = session.send(
            "Runtime.evaluate",
            {
                "expression": expression,
                "returnByValue": True,
                "awaitPromise": True,
            },
            timeout_s=timeout_s,
        )
        if "exceptionDetails" in res:
            details = res["exceptionDetails"]
            exc_obj = details.get("exception") or {}
            msg = exc_obj.get("description") or details.get("text") or "JS evaluation error"
            raise BrowserOpError("JS_EXCEPTION", msg)
        return (res.get("result") or {}).get("value")

    def _wait_ready_state(self, target_id: str | None, timeout_s: float = 15.0) -> None:
        target = self._resolve_target(target_id)
        deadline = time.monotonic() + max(1.0, timeout_s)
        with CDPSession(target["webSocketDebuggerUrl"], timeout_s=timeout_s) as sess:
            while time.monotonic() < deadline:
                state = self._eval_on_session(sess, "document.readyState", timeout_s=5.0)
                if state in ("interactive", "complete"):
                    return
                time.sleep(0.15)

    def navigate(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            url = str(args.get("url") or "").strip()
            if not url:
                raise BrowserOpError("INVALID_ARGS", "url is required")
            timeout_s = max(2.0, min(float(args.get("timeout_s", 20.0)), 90.0))
            target = self._resolve_target(args.get("target_id"))
            with CDPSession(target["webSocketDebuggerUrl"], timeout_s=timeout_s) as sess:
                sess.send("Page.enable", timeout_s=5.0)
                nav = sess.send("Page.navigate", {"url": url}, timeout_s=timeout_s)
                if nav.get("errorText"):
                    raise BrowserOpError("NAVIGATION_ERROR", nav["errorText"])
                if bool(args.get("wait_load", True)):
                    try:
                        sess.wait_for_event("Page.loadEventFired", timeout_s=timeout_s)
                    except CDPError:
                        pass
                info = self._eval_on_session(
                    sess, "({ url: location.href, title: document.title, readyState: document.readyState })"
                )
            return {"target_id": target["id"], **(info or {"url": url})}

    def eval_js(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            expr = args.get("expression") or args.get("script") or args.get("js")
            if not isinstance(expr, str) or not expr.strip():
                raise BrowserOpError("INVALID_ARGS", "expression is required")
            timeout_s = max(2.0, min(float(args.get("timeout_s", 20.0)), 90.0))
            target = self._resolve_target(args.get("target_id"))
            with CDPSession(target["webSocketDebuggerUrl"], timeout_s=timeout_s) as sess:
                val = self._eval_on_session(sess, expr, timeout_s=timeout_s)
            return {"target_id": target["id"], "value": val}

    def text(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            selector = args.get("selector")
            max_chars = max(500, min(int(args.get("max_chars", 40_000)), 200_000))
            target = self._resolve_target(args.get("target_id"))
            sel_json = json.dumps(selector) if selector else "null"
            js = f"""(() => {{
                const el = {sel_json} ? document.querySelector({sel_json}) : document.body;
                if (!el) return {{ found: false, url: location.href, title: document.title, text: "" }};
                const raw = (el.innerText || el.textContent || "").trim();
                return {{
                    found: true,
                    url: location.href,
                    title: document.title,
                    total_chars: raw.length,
                    truncated: raw.length > {max_chars},
                    text: raw.slice(0, {max_chars}),
                }};
            }})()"""
            with CDPSession(target["webSocketDebuggerUrl"], timeout_s=15.0) as sess:
                val = self._eval_on_session(sess, js)
            return {"target_id": target["id"], **(val or {})}

    def snapshot(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            max_items = max(10, min(int(args.get("max_items", 120)), 500))
            target = self._resolve_target(args.get("target_id"))
            js = f"""(() => {{
                const cssPath = (el) => {{
                    if (el.id) return '#' + CSS.escape(el.id);
                    const parts = [];
                    let cur = el;
                    while (cur && cur.nodeType === 1 && parts.length < 4) {{
                        let s = cur.tagName.toLowerCase();
                        const name = cur.getAttribute('name');
                        if (name) {{ s += `[name="${{name.replace(/"/g, '\\\\"')}}"]`; parts.unshift(s); break; }}
                        const siblings = cur.parentElement ? Array.from(cur.parentElement.children).filter(c => c.tagName === cur.tagName) : [];
                        if (siblings.length > 1) s += `:nth-of-type(${{siblings.indexOf(cur) + 1}})`;
                        parts.unshift(s);
                        cur = cur.parentElement;
                    }}
                    return parts.join(' > ');
                }};
                const nodes = document.querySelectorAll('a, button, input, textarea, select, [role="button"], [role="link"], h1, h2, h3');
                const items = [];
                for (const el of nodes) {{
                    const rect = el.getBoundingClientRect();
                    if (rect.width === 0 && rect.height === 0) continue;
                    items.push({{
                        tag: el.tagName.toLowerCase(),
                        type: el.getAttribute('type') || undefined,
                        role: el.getAttribute('role') || undefined,
                        text: (el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '').trim().slice(0, 120),
                        href: el.tagName === 'A' ? el.href : undefined,
                        selector: cssPath(el),
                        box: {{ x: Math.round(rect.x), y: Math.round(rect.y), w: Math.round(rect.width), h: Math.round(rect.height) }},
                    }});
                    if (items.length >= {max_items}) break;
                }}
                return {{ url: location.href, title: document.title, count: items.length, elements: items }};
            }})()"""
            with CDPSession(target["webSocketDebuggerUrl"], timeout_s=15.0) as sess:
                val = self._eval_on_session(sess, js)
            return {"target_id": target["id"], **(val or {})}

    def click(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            selector = args.get("selector")
            x = args.get("x")
            y = args.get("y")
            target = self._resolve_target(args.get("target_id"))

            with CDPSession(target["webSocketDebuggerUrl"], timeout_s=15.0) as sess:
                if selector:
                    sel_json = json.dumps(str(selector))
                    pt = self._eval_on_session(
                        sess,
                        f"""(() => {{
                            const el = document.querySelector({sel_json});
                            if (!el) return null;
                            el.scrollIntoView({{ block: 'center', inline: 'center' }});
                            const r = el.getBoundingClientRect();
                            return {{ x: r.left + r.width / 2, y: r.top + r.height / 2, tag: el.tagName.toLowerCase() }};
                        }})()""",
                    )
                    if not pt:
                        raise BrowserOpError("ELEMENT_NOT_FOUND", f"Selector not found: {selector}")
                    cx, cy = float(pt["x"]), float(pt["y"])
                elif x is not None and y is not None:
                    cx, cy = float(x), float(y)
                else:
                    raise BrowserOpError("INVALID_ARGS", "Provide selector or x and y coordinates")

                button = str(args.get("button") or "left")
                click_count = int(args.get("click_count", 1))
                sess.send("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": cx, "y": cy})
                sess.send("Input.dispatchMouseEvent", {"type": "mousePressed", "x": cx, "y": cy, "button": button, "clickCount": click_count})
                sess.send("Input.dispatchMouseEvent", {"type": "mouseReleased", "x": cx, "y": cy, "button": button, "clickCount": click_count})
            return {"target_id": target["id"], "clicked": True, "x": round(cx, 1), "y": round(cy, 1), "selector": selector}

    def type_text(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            text = args.get("text")
            if not isinstance(text, str):
                raise BrowserOpError("INVALID_ARGS", "text must be a string")
            selector = args.get("selector")
            clear = bool(args.get("clear", False))
            press_enter = bool(args.get("press_enter", False))
            target = self._resolve_target(args.get("target_id"))

            with CDPSession(target["webSocketDebuggerUrl"], timeout_s=15.0) as sess:
                if selector:
                    sel_json = json.dumps(str(selector))
                    ok = self._eval_on_session(
                        sess,
                        f"""(() => {{
                            const el = document.querySelector({sel_json});
                            if (!el) return false;
                            el.scrollIntoView({{ block: 'center' }});
                            el.focus();
                            if ({'true' if clear else 'false'} && 'value' in el) {{
                                el.value = '';
                                el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                            }}
                            return true;
                        }})()""",
                    )
                    if not ok:
                        raise BrowserOpError("ELEMENT_NOT_FOUND", f"Selector not found: {selector}")
                sess.send("Input.insertText", {"text": text})
                if press_enter:
                    sess.send("Input.dispatchKeyEvent", {"type": "keyDown", "key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13, "nativeVirtualKeyCode": 13})
                    sess.send("Input.dispatchKeyEvent", {"type": "keyUp", "key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13, "nativeVirtualKeyCode": 13})
            return {"target_id": target["id"], "typed_chars": len(text), "selector": selector, "press_enter": press_enter}

    def wait_for(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            selector = args.get("selector")
            expression = args.get("expression")
            if not selector and not expression:
                raise BrowserOpError("INVALID_ARGS", "Provide selector or expression")
            timeout_s = max(0.5, min(float(args.get("timeout_s", 15.0)), 90.0))
            poll_ms = max(50, min(int(args.get("poll_ms", 200)), 2000))
            target = self._resolve_target(args.get("target_id"))
            check_js = f"Boolean(document.querySelector({json.dumps(str(selector))}))" if selector else f"Boolean({expression})"

            deadline = time.monotonic() + timeout_s
            started = time.monotonic()
            with CDPSession(target["webSocketDebuggerUrl"], timeout_s=timeout_s + 5.0) as sess:
                while time.monotonic() < deadline:
                    if self._eval_on_session(sess, check_js, timeout_s=5.0):
                        return {"target_id": target["id"], "matched": True, "elapsed_ms": int((time.monotonic() - started) * 1000)}
                    time.sleep(poll_ms / 1000.0)
            raise BrowserOpError("WAIT_TIMEOUT", f"Timed out after {timeout_s}s waiting for {selector or expression}")

    def screenshot(self, args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
        with self._lock:
            fmt = str(args.get("format") or "png").lower()
            if fmt not in ("png", "jpeg", "webp"):
                raise BrowserOpError("INVALID_ARGS", "format must be png, jpeg, or webp")
            full_page = bool(args.get("full_page", False))
            out_path = args.get("path")
            return_b64 = bool(args.get("return_base64", not bool(out_path)))
            target = self._resolve_target(args.get("target_id"))

            params: dict[str, Any] = {"format": fmt}
            if fmt == "jpeg" and args.get("quality") is not None:
                params["quality"] = int(args["quality"])
            if full_page:
                params["captureBeyondViewport"] = True

            with CDPSession(target["webSocketDebuggerUrl"], timeout_s=20.0) as sess:
                res = sess.send("Page.captureScreenshot", params, timeout_s=20.0)
            b64_data = res.get("data", "")
            raw = base64.b64decode(b64_data)

            result: dict[str, Any] = {"target_id": target["id"], "format": fmt, "size_bytes": len(raw)}
            if out_path:
                resolved = resolve_path(str(out_path), workspace_root)
                resolved.parent.mkdir(parents=True, exist_ok=True)
                resolved.write_bytes(raw)
                result["path"] = str(resolved)
            if return_b64:
                result["base64"] = b64_data
            return result

    def cookies(self, args: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            action = str(args.get("action") or "get").lower()
            target = self._resolve_target(args.get("target_id"))
            with CDPSession(target["webSocketDebuggerUrl"], timeout_s=15.0) as sess:
                sess.send("Network.enable", timeout_s=5.0)
                if action == "get":
                    urls = args.get("urls")
                    params = {"urls": urls} if isinstance(urls, list) else {}
                    res = sess.send("Network.getCookies", params, timeout_s=10.0)
                    return {"target_id": target["id"], "cookies": res.get("cookies", [])}
                elif action == "set":
                    cookie = args.get("cookie")
                    if not isinstance(cookie, dict) or not cookie.get("name"):
                        raise BrowserOpError("INVALID_ARGS", "cookie dict with name/value/url or domain required")
                    res = sess.send("Network.setCookie", cookie, timeout_s=10.0)
                    return {"target_id": target["id"], "success": bool(res.get("success", False))}
                elif action == "clear":
                    sess.send("Network.clearBrowserCookies", timeout_s=10.0)
                    return {"target_id": target["id"], "cleared": True}
                else:
                    raise BrowserOpError("INVALID_ARGS", f"Unknown cookies action: {action} (use get, set, clear)")

    def upload(self, args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
        with self._lock:
            selector = str(args.get("selector") or "").strip()
            files = args.get("files")
            if not selector or not isinstance(files, list) or not files:
                raise BrowserOpError("INVALID_ARGS", "selector and non-empty files list are required")
            resolved_files = [str(resolve_path(str(f), workspace_root, must_exist=True)) for f in files]
            target = self._resolve_target(args.get("target_id"))
            with CDPSession(target["webSocketDebuggerUrl"], timeout_s=15.0) as sess:
                doc = sess.send("DOM.getDocument", {"depth": -1}, timeout_s=10.0)
                root_id = doc["root"]["nodeId"]
                node = sess.send("DOM.querySelector", {"nodeId": root_id, "selector": selector}, timeout_s=10.0)
                node_id = node.get("nodeId")
                if not node_id:
                    raise BrowserOpError("ELEMENT_NOT_FOUND", f"File input not found: {selector}")
                sess.send("DOM.setFileInputFiles", {"nodeId": node_id, "files": resolved_files}, timeout_s=10.0)
            return {"target_id": target["id"], "selector": selector, "files": resolved_files}

    def print_pdf(self, args: dict[str, Any], workspace_root: str | None = None) -> dict[str, Any]:
        with self._lock:
            out_path = args.get("path")
            return_b64 = bool(args.get("return_base64", not bool(out_path)))
            target = self._resolve_target(args.get("target_id"))
            params = {
                "printBackground": bool(args.get("print_background", True)),
                "landscape": bool(args.get("landscape", False)),
            }
            with CDPSession(target["webSocketDebuggerUrl"], timeout_s=20.0) as sess:
                res = sess.send("Page.printToPDF", params, timeout_s=20.0)
            b64_data = res.get("data", "")
            raw = base64.b64decode(b64_data)
            result: dict[str, Any] = {"target_id": target["id"], "size_bytes": len(raw)}
            if out_path:
                resolved = resolve_path(str(out_path), workspace_root)
                resolved.parent.mkdir(parents=True, exist_ok=True)
                resolved.write_bytes(raw)
                result["path"] = str(resolved)
            if return_b64:
                result["base64"] = b64_data
            return result


def build_browser_ops(manager: BrowserManager, workspace_root: str | None = None) -> dict[str, Any]:
    return {
        "browser_launch": lambda args: manager.launch(args),
        "browser_connect": lambda args: manager.connect(args),
        "browser_status": lambda args: manager.status(),
        "browser_close": lambda args: manager.close(),
        "browser_tabs": lambda args: manager.tabs(),
        "browser_open": lambda args: manager.open_tab(args),
        "browser_close_tab": lambda args: manager.close_tab(args),
        "browser_navigate": lambda args: manager.navigate(args),
        "browser_eval": lambda args: manager.eval_js(args),
        "browser_text": lambda args: manager.text(args),
        "browser_snapshot": lambda args: manager.snapshot(args),
        "browser_click": lambda args: manager.click(args),
        "browser_type": lambda args: manager.type_text(args),
        "browser_wait": lambda args: manager.wait_for(args),
        "browser_screenshot": lambda args: manager.screenshot(args, workspace_root),
        "browser_cookies": lambda args: manager.cookies(args),
        "browser_upload": lambda args: manager.upload(args, workspace_root),
        "browser_pdf": lambda args: manager.print_pdf(args, workspace_root),
    }
