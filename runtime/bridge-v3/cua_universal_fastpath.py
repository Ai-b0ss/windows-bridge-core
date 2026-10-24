from __future__ import annotations

import base64
import ctypes
import ctypes.wintypes as wt
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import time
from typing import Any, Mapping
import urllib.parse
import urllib.request

from cua_programmatic_discovery import discover_programmatic_surfaces, owned_tcp_listeners


_EDITOR_VALUE_JS = r"""const editorValue=e=>{if(!e.isContentEditable)return e.value||'';const walk=n=>{if(n.nodeType===3)return n.nodeValue||'';if(n.nodeType!==1||n.getAttribute('aria-hidden')==='true')return '';if(n.tagName==='BR')return '\n';const children=[...n.childNodes].filter(x=>x.nodeType!==1||x.getAttribute('aria-hidden')!=='true'),block=n!==e&&['P','DIV'].includes(n.tagName);if(block&&children.length===1&&children[0].tagName==='BR')return '\n';let s=children.map(walk).join('');return block?s+'\n':s;};return walk(e).replace(/\r\n/g,'\n').replace(/\n$/,'');};"""


class _LocalWebSocket:
    def __init__(self, url: str, timeout: float):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost"} or not parsed.port:
            raise RuntimeError("LOCAL_WS_URL_REQUIRED")
        self.sock = socket.create_connection((parsed.hostname, parsed.port), timeout=timeout)
        self.sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(request.encode("ascii"))
        header = bytearray()
        while b"\r\n\r\n" not in header and len(header) < 16384:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            header.extend(chunk)
        text = header.decode("latin1", "replace")
        if not text.startswith("HTTP/1.1 101"):
            self.sock.close()
            raise RuntimeError("WS_HANDSHAKE_FAILED")
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()).decode("ascii")
        if f"sec-websocket-accept: {expected}".lower() not in text.lower():
            self.sock.close()
            raise RuntimeError("WS_ACCEPT_MISMATCH")

    def _recv_exact(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise EOFError("WS_EOF")
            out.extend(chunk)
        return bytes(out)

    def send(self, text: str) -> None:
        payload = text.encode("utf-8")
        mask = os.urandom(4)
        n = len(payload)
        head = bytearray([0x81])
        if n < 126:
            head.append(0x80 | n)
        elif n <= 0xFFFF:
            head.append(0x80 | 126)
            head.extend(struct.pack("!H", n))
        else:
            head.append(0x80 | 127)
            head.extend(struct.pack("!Q", n))
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(head) + mask + masked)

    def recv(self) -> str:
        parts = bytearray()
        while True:
            b1, b2 = self._recv_exact(2)
            fin, opcode = bool(b1 & 0x80), b1 & 0x0F
            n = b2 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._recv_exact(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._recv_exact(8))[0]
            masked = bool(b2 & 0x80)
            mask = self._recv_exact(4) if masked else b""
            payload = self._recv_exact(n)
            if masked:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:
                raise EOFError("WS_CLOSED")
            if opcode == 0x9:
                self._send_control(0xA, payload)
                continue
            if opcode in (0x1, 0x0):
                parts.extend(payload)
                if fin:
                    return parts.decode("utf-8")

    def _send_control(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes([0x80 | opcode, 0x80 | len(payload)]) + mask + masked)

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass


class FastPathError(RuntimeError):
    def __init__(self, code: str, details: Mapping[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


class UniversalFastPath:
    """Discover the fastest semantic route for a Windows app."""

    def __init__(self, cache_ttl_s: float = 0.75):
        self._cache: dict[str, dict[str, Any]] = {}
        self._cache_ttl_s = max(0.0, float(cache_ttl_s))

    @staticmethod
    def _norm(value: Any) -> str:
        return " ".join(str(value or "").lower().split())

    def _windows(self) -> list[dict[str, Any]]:
        if os.name != "nt":
            return []
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        out: list[dict[str, Any]] = []
        enum_proc = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

        def visit(hwnd, _):
            if not user32.IsWindowVisible(hwnd):
                return True
            n = user32.GetWindowTextLengthW(hwnd)
            if n <= 0:
                return True
            buf = ctypes.create_unicode_buffer(n + 1)
            user32.GetWindowTextW(hwnd, buf, n + 1)
            pid = wt.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            exe = ""
            h = kernel32.OpenProcess(0x1000, False, pid.value)
            if h:
                size = wt.DWORD(32768)
                path = ctypes.create_unicode_buffer(size.value)
                if kernel32.QueryFullProcessImageNameW(h, 0, path, ctypes.byref(size)):
                    exe = path.value
                kernel32.CloseHandle(h)
            out.append({"hwnd": int(hwnd), "pid": int(pid.value), "title": buf.value, "exe": exe})
            return True

        user32.EnumWindows(enum_proc(visit), 0)
        return out

    @staticmethod
    def _window_identity_valid(window: Mapping[str, Any]) -> bool:
        if os.name != "nt":
            return False
        try:
            hwnd = int(window.get("hwnd") or 0)
            expected_pid = int(window.get("pid") or 0)
        except Exception:
            return False
        if hwnd <= 0 or expected_pid <= 0:
            return False
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        if not user32.IsWindow(wt.HWND(hwnd)):
            return False
        pid = wt.DWORD()
        user32.GetWindowThreadProcessId(wt.HWND(hwnd), ctypes.byref(pid))
        return int(pid.value) == expected_pid

    def _cdp_identity_valid(self, cdp: Mapping[str, Any]) -> bool:
        try:
            port = int(cdp.get("port") or 0)
            page_id = str(cdp.get("page_id") or "")
            websocket_url = str(cdp.get("websocket_url") or "")
            if port <= 0 or not page_id or not websocket_url:
                return False
            endpoint = urllib.parse.urlparse(websocket_url)
            if endpoint.scheme != 'ws' or endpoint.hostname not in {'127.0.0.1', 'localhost'} or endpoint.port != port:
                return False
            # WebView generates the debugger URL from the requested Host.
            # Reuse that observed loopback authority, preserving exact page
            # URL comparison rather than accepting a different identity.
            pages = self._json_url(f"http://{endpoint.hostname}:{port}/json/list")
        except Exception:
            return False
        if not isinstance(pages, list):
            return False
        for page in pages:
            if not isinstance(page, Mapping):
                continue
            if str(page.get("id") or "") != page_id:
                continue
            return str(page.get("webSocketDebuggerUrl") or "") == websocket_url
        return False

    def _cached_discovery_valid(self, cached: Mapping[str, Any]) -> bool:
        route = str(cached.get("route") or "")
        if route == "PROGRAMMATIC_DISCOVERY":
            candidates = cached.get("programmatic_candidates")
            if not isinstance(candidates, list):
                return False
            for candidate in candidates:
                if not isinstance(candidate, Mapping):
                    continue
                if candidate.get("kind") == "cli_command":
                    path = str(candidate.get("path") or "")
                    if path and Path(path).is_file():
                        return True
            return False
        window = cached.get("window")
        if not isinstance(window, Mapping) or not self._window_identity_valid(window):
            return False
        if route == "APP_CDP":
            cdp = cached.get("cdp")
            return isinstance(cdp, Mapping) and self._cdp_identity_valid(cdp)
        return True

    def _pick_window(self, app: str) -> dict[str, Any]:
        needle = self._norm(app)
        ranked: list[tuple[int, dict[str, Any]]] = []
        for item in self._windows():
            stem = self._norm(Path(item["exe"]).stem if item["exe"] else "")
            title = self._norm(item["title"])
            score = 0
            if needle == stem:
                score += 100
            elif needle and needle in stem:
                score += 70
            if needle and needle in title:
                score += 50
            if score:
                ranked.append((score, item))
        if not ranked:
            raise FastPathError("APP_WINDOW_NOT_FOUND", {"app": app})
        ranked.sort(key=lambda x: x[0], reverse=True)
        if len(ranked) > 1 and ranked[0][0] == ranked[1][0] and ranked[0][1]["pid"] != ranked[1][1]["pid"]:
            raise FastPathError("APP_WINDOW_AMBIGUOUS", {"matches": [x[1] for x in ranked[:5]]})
        return ranked[0][1]

    def _devtools_files(self, app: str) -> list[Path]:
        roots = [Path(os.environ.get("APPDATA", "")), Path(os.environ.get("LOCALAPPDATA", ""))]
        needle = self._norm(app)
        seen: set[str] = set()
        patterns = (
            "*/DevToolsActivePort",
            "*/*/DevToolsActivePort",
            "*/*/*/DevToolsActivePort",
        )
        if not needle:
            return []
        for pattern in patterns:
            preferred: list[Path] = []
            for root in roots:
                if not str(root):
                    continue
                try:
                    for path in root.glob(pattern):
                        key = os.path.normcase(str(path))
                        if key in seen or not path.is_file():
                            continue
                        seen.add(key)
                        scope = self._norm(" ".join(path.parts[-4:-1]))
                        if needle in scope:
                            preferred.append(path)
                except OSError:
                    continue
            if preferred:
                return preferred
        return []

    @staticmethod
    def _json_url(url: str) -> Any:
        with urllib.request.urlopen(url, timeout=0.7) as response:
            return json.loads(response.read().decode("utf-8"))

    def _pick_cdp(self, app: str) -> dict[str, Any] | None:
        needle = self._norm(app)
        candidates: list[dict[str, Any]] = []
        for source in self._devtools_files(app):
            source_scope = self._norm(" ".join(source.parts[-4:-1]))
            if not needle or needle not in source_scope:
                continue
            try:
                port = int(source.read_text(encoding="utf-8").splitlines()[0].strip())
                pages = self._json_url(f"http://127.0.0.1:{port}/json/list")
            except Exception:
                continue
            if not isinstance(pages, list):
                continue
            source_pages: list[dict[str, Any]] = []
            for page in pages:
                if not isinstance(page, Mapping) or page.get("type") != "page":
                    continue
                ws = str(page.get("webSocketDebuggerUrl") or "")
                if not ws:
                    continue
                source_pages.append({
                    "source": str(source),
                    "port": port,
                    "page_id": str(page.get("id") or ""),
                    "title": str(page.get("title") or ""),
                    "url": str(page.get("url") or ""),
                    "websocket_url": ws,
                })
            if len(source_pages) == 1:
                candidates.append(source_pages[0])
        return candidates[0] if len(candidates) == 1 else None

    def _pick_pid_listener_cdp(self, window: Mapping[str, Any] | None) -> dict[str, Any] | None:
        if not isinstance(window, Mapping):
            return None
        try:
            pid = int(window.get("pid") or 0)
        except Exception:
            return None
        if pid <= 0:
            return None
        candidates: list[dict[str, Any]] = []
        seen_ports: set[int] = set()
        listeners = []
        for listener_pid in [pid, *self._child_process_ids(pid)]:
            listeners.extend(owned_tcp_listeners(listener_pid))
        for listener in listeners:
            try:
                port = int(listener.get("port") or 0)
            except Exception:
                continue
            if port <= 0 or port in seen_ports:
                continue
            seen_ports.add(port)
            try:
                version = self._json_url(f"http://127.0.0.1:{port}/json/version")
                pages = self._json_url(f"http://127.0.0.1:{port}/json/list")
            except Exception:
                continue
            if not isinstance(version, Mapping):
                continue
            if not str(version.get("Protocol-Version") or "") or not str(version.get("webSocketDebuggerUrl") or ""):
                continue
            if not isinstance(pages, list):
                continue
            source_pages: list[dict[str, Any]] = []
            for page in pages:
                if not isinstance(page, Mapping) or page.get("type") != "page":
                    continue
                ws = str(page.get("webSocketDebuggerUrl") or "")
                if not ws:
                    continue
                parsed = urllib.parse.urlparse(ws)
                if parsed.scheme != "ws" or parsed.hostname not in {"127.0.0.1", "localhost"} or parsed.port != port:
                    continue
                source_pages.append({
                    "source": f"pid_listener:{listener.get('pid', pid)}",
                    "owner_identity": self._process_identity(pid),
                    "listener_identity": self._process_identity(int(listener.get("pid", pid))),
                    "port": port,
                    "page_id": str(page.get("id") or ""),
                    "title": str(page.get("title") or ""),
                    "url": str(page.get("url") or ""),
                    "websocket_url": ws,
                })
            if len(source_pages) == 1:
                candidates.append(source_pages[0])
        return candidates[0] if len(candidates) == 1 else None

    def discover(self, app: str, *, refresh: bool = False) -> dict[str, Any]:
        key = self._norm(app)
        if not refresh and key in self._cache:
            cached = self._cache[key]
            cached_at = float(cached.get("_cached_at_monotonic") or 0.0)
            age_s = max(0.0, time.monotonic() - cached_at)
            if age_s <= self._cache_ttl_s:
                result = {k: v for k, v in cached.items() if not k.startswith("_")}
                result.update({"cache_hit": True, "cache_validated": False, "cache_age_ms": age_s * 1000.0})
                return result
            if self._cached_discovery_valid(cached):
                cached["_cached_at_monotonic"] = time.monotonic()
                result = {k: v for k, v in cached.items() if not k.startswith("_")}
                result.update({"cache_hit": True, "cache_validated": True, "cache_age_ms": age_s * 1000.0})
                return result
            self._cache.pop(key, None)

        started = time.perf_counter_ns()
        window: dict[str, Any] | None = None
        window_error: FastPathError | None = None
        try:
            window = self._pick_window(app)
        except FastPathError as exc:
            if exc.code != "APP_WINDOW_NOT_FOUND":
                raise
            window_error = exc

        cdp = self._pick_cdp(app)
        if cdp is None:
            cdp = self._pick_pid_listener_cdp(window)
        programmatic_candidates: list[dict[str, Any]] = []
        programmatic_discovery_complete = True
        programmatic_discovery_error = None
        try:
            programmatic_candidates = discover_programmatic_surfaces(
                app, window, cdp=cdp,
            )
        except Exception as exc:
            programmatic_discovery_complete = False
            programmatic_discovery_error = type(exc).__name__

        has_verified_programmatic = any(
            isinstance(item, Mapping) and (item.get("verified") is True or item.get("kind") == "cli_command")
            for item in programmatic_candidates
        )
        if cdp is not None:
            route = "APP_CDP"
        elif has_verified_programmatic:
            route = "PROGRAMMATIC_DISCOVERY"
        elif window is not None:
            route = "UIA_PATTERN"
        else:
            if window_error is not None:
                raise window_error
            raise FastPathError("APP_WINDOW_NOT_FOUND", {"app": app})

        result = {
            "app": app,
            "route": route,
            "window": window,
            "cdp": cdp,
            "programmatic_candidates": programmatic_candidates,
            "programmatic_discovery_complete": programmatic_discovery_complete,
            "programmatic_discovery_error": programmatic_discovery_error,
            "discovery_ms": (time.perf_counter_ns() - started) / 1_000_000,
            "cache_hit": False,
            "cache_validated": False,
            "_cached_at_monotonic": time.monotonic(),
        }
        self._cache[key] = dict(result)
        return {k: v for k, v in result.items() if not k.startswith("_")}


    @staticmethod
    def _process_identity(pid: int) -> dict[str, Any] | None:
        if os.name != "nt" or pid <= 0:
            return None
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        k.OpenProcess.restype = wt.HANDLE
        k.CloseHandle.argtypes = [wt.HANDLE]
        k.GetProcessTimes.argtypes = [wt.HANDLE, ctypes.POINTER(wt.FILETIME), ctypes.POINTER(wt.FILETIME), ctypes.POINTER(wt.FILETIME), ctypes.POINTER(wt.FILETIME)]
        k.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
        h = k.OpenProcess(0x1000, False, pid)
        if not h:
            return None
        try:
            born, end, kernel, user = wt.FILETIME(), wt.FILETIME(), wt.FILETIME(), wt.FILETIME()
            size = wt.DWORD(32768)
            path = ctypes.create_unicode_buffer(size.value)
            if not k.GetProcessTimes(h, ctypes.byref(born), ctypes.byref(end), ctypes.byref(kernel), ctypes.byref(user)):
                return None
            if not k.QueryFullProcessImageNameW(h, 0, path, ctypes.byref(size)):
                return None
            return {"pid": pid, "created": (born.dwHighDateTime << 32) | born.dwLowDateTime, "exe": os.path.normcase(path.value)}
        finally:
            k.CloseHandle(h)

    @staticmethod
    def _child_process_ids(pid: int) -> list[int]:
        if os.name != "nt":
            return []
        class Entry(ctypes.Structure):
            _fields_ = [("size", wt.DWORD), ("usage", wt.DWORD), ("pid", wt.DWORD),
                        ("heap", ctypes.c_size_t), ("module", wt.DWORD), ("threads", wt.DWORD),
                        ("parent", wt.DWORD), ("priority", wt.LONG), ("flags", wt.DWORD),
                        ("exe", wt.WCHAR * 260)]
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
        k.CreateToolhelp32Snapshot.restype = wt.HANDLE
        k.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(Entry)]
        k.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(Entry)]
        k.CloseHandle.argtypes = [wt.HANDLE]
        h = k.CreateToolhelp32Snapshot(2, 0)
        if h in (None, ctypes.c_void_p(-1).value):
            return []
        try:
            e = Entry()
            e.size = ctypes.sizeof(e)
            rows = []
            ok = k.Process32FirstW(h, ctypes.byref(e))
            while ok:
                rows.append((int(e.pid), int(e.parent)))
                ok = k.Process32NextW(h, ctypes.byref(e))
            return UniversalFastPath._verified_descendants(pid, rows)
        finally:
            k.CloseHandle(h)

    @staticmethod
    def _verified_descendants(pid, rows):
        """Reject recycled parent PIDs and identity drift in every chain edge."""
        root = UniversalFastPath._process_identity(pid)
        if root is None:
            return []
        identities = {pid: root}
        parents = {}
        for _ in range(len(rows)):
            added = False
            for child, parent in rows:
                if child in identities or parent not in identities:
                    continue
                current = UniversalFastPath._process_identity(child)
                if current is None or current['created'] < identities[parent]['created']:
                    continue
                identities[child] = current
                parents[child] = parent
                added = True
            if not added:
                break
        stable = {p for p, identity in identities.items()
                  if UniversalFastPath._process_identity(p) == identity}
        if pid not in stable:
            return []
        accepted = {pid}
        for _ in range(len(parents)):
            new = {child for child, parent in parents.items()
                   if child in stable and parent in accepted} - accepted
            if not new:
                break
            accepted.update(new)
        return sorted(accepted - {pid})

    def _panel_owner_valid(self, discovered: Mapping[str, Any]) -> bool:
        cdp, window = discovered.get("cdp"), discovered.get("window")
        if not isinstance(cdp, Mapping) or not isinstance(window, Mapping):
            return False
        owner, listener = cdp.get("owner_identity"), cdp.get("listener_identity")
        if not isinstance(owner, Mapping) or not isinstance(listener, Mapping):
            return False
        if int(window.get("pid") or 0) != owner.get("pid"):
            return False
        if self._process_identity(owner["pid"]) != owner or self._process_identity(listener["pid"]) != listener:
            return False
        if listener["pid"] != owner["pid"] and listener["pid"] not in self._child_process_ids(owner["pid"]):
            return False
        return any(x.get("port") == cdp.get("port") and x.get("scope") == "loopback"
                   for x in owned_tcp_listeners(listener["pid"]))

    @staticmethod
    def _panel_selector(value: Any) -> dict[str, str]:
        if not isinstance(value, Mapping) or set(value) - {"name", "text", "role", "tag"}:
            raise FastPathError("PANEL_SELECTOR_INVALID", {"attempted": False})
        if not any(isinstance(value.get(k), str) and value[k].strip() for k in ("name", "text")):
            raise FastPathError("PANEL_SELECTOR_INVALID", {"attempted": False})
        if any(not isinstance(v, str) or not v.strip() or len(v) > 4096 for v in value.values()):
            raise FastPathError("PANEL_SELECTOR_INVALID", {"attempted": False})
        return dict(value)

    @staticmethod
    def validate_panel_arguments(intent: str, action_args: Mapping[str, Any] | None = None):
        if intent not in {"panel.inspect", "panel.invoke", "panel.verify", "panel.type"}:
            raise FastPathError("INTENT_UNSUPPORTED", {"attempted": False})
        if action_args is not None and not isinstance(action_args, Mapping):
            raise FastPathError("PANEL_ARGUMENT_INVALID", {"attempted": False})
        args = dict(action_args or {})
        if set(args) - ({"selector", "postcondition", "timeout_s", "text"} if intent == "panel.type" else {"selector", "postcondition", "timeout_s"}):
            raise FastPathError("PANEL_ARGUMENT_INVALID", {"attempted": False})
        selector = UniversalFastPath._panel_selector(args.get("selector")) if intent in {"panel.invoke", "panel.type"} else None
        post = args.get("postcondition")
        if intent != "panel.inspect":
            if not isinstance(post, Mapping) or set(post) != {"selector", "state"}:
                raise FastPathError("PANEL_POSTCONDITION_REQUIRED", {"attempted": False})
            post = {"selector": UniversalFastPath._panel_selector(post["selector"]), "state": post["state"]}
            allowed = {"expanded", "selected", "checked", "disabled", "text", "value", "present"}
            if not isinstance(post["state"], Mapping) or not post["state"] or set(post["state"]) - allowed:
                raise FastPathError("PANEL_POSTCONDITION_INVALID", {"attempted": False})
            if any((k in {"disabled", "present"} and type(v) is not bool) or (k not in {"disabled", "present"} and not isinstance(v, str))
                   for k, v in post["state"].items()):
                raise FastPathError("PANEL_POSTCONDITION_INVALID", {"attempted": False})
        if post and post["state"].get("present") is False and set(post["state"]) != {"present"}:
            raise FastPathError("PANEL_POSTCONDITION_INVALID", {"attempted": False})
        timeout = args.get("timeout_s", 2.0)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.05 <= timeout <= 10:
            raise FastPathError("PANEL_TIMEOUT_INVALID", {"attempted": False})
        if intent == "panel.type":
            text = args.get("text")
            if not isinstance(text, str) or len(text) > 65536 or any(c in text for c in "\r\n"):
                raise FastPathError("PANEL_TEXT_INVALID", {"attempted": False})
            if selector.get("role") not in {"textbox", "combobox"} or post["selector"] != selector or post["state"] != {"value": text}:
                raise FastPathError("PANEL_INPUT_POSTCONDITION_INVALID", {"attempted": False})
        return args, selector, post, timeout

    def panel_action(self, discovered: Mapping[str, Any], intent: str, *, action_args: Mapping[str, Any] | None = None) -> dict[str, Any]:
        args, selector, post, timeout = self.validate_panel_arguments(intent, action_args)
        # Repeat only read-only identity discovery when a short probe times out.
        # Never replay an invocation, or adopt a different process/page.
        identity_valid = False
        for _ in range(2):
            if self._cached_discovery_valid(discovered) and self._panel_owner_valid(discovered):
                identity_valid = True
                break
        if not identity_valid:
            raise FastPathError("STALE_TARGET", {"attempted": False, "retry_safe": True})
        if intent == "panel.type":
            try:
                result = self._trusted_type(discovered["cdp"], args["text"], send=False, input_selector=selector)
                self.panel_action(discovered, "panel.verify", action_args={"postcondition": post, "timeout_s": timeout})
            except FastPathError as exc:
                exc.details.update({"attempted": True, "retry_safe": False})
                raise
            return {**result, "ok": True, "verified": True, "kind": intent, "route": "APP_CDP",
                    "attempted": True, "retry_safe": False, "physical_input_used": False, "window": discovered["window"]}
        cfg = json.dumps({"intent": intent, "selector": selector, "postcondition": post, "timeout_ms": timeout * 1000}, ensure_ascii=False)
        script = r"""(async()=>{
__EDITOR_VALUE__
const c=__CFG__,norm=s=>(s||'').replace(/\r\n/g,'\n').trim();
const vis=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>0&&r.height>0&&s.display!=='none'&&s.visibility!=='hidden'&&!e.closest('[aria-hidden="true"]')};
const role=e=>e.getAttribute('role')||({BUTTON:'button',INPUT:'textbox',TEXTAREA:'textbox',SELECT:'combobox'}[e.tagName]||'');
const name=e=>norm(e.getAttribute('aria-label')||e.innerText||e.getAttribute('title')||e.getAttribute('placeholder'));
const all=()=>[...document.querySelectorAll('button,[role],input,textarea,select,[contenteditable="true"]')].filter(e=>vis(e)&&!e.matches('input[type="password"]'));
const match=s=>all().filter(e=>(!s.name||name(e)===norm(s.name))&&(!s.text||norm(e.innerText)===norm(s.text))&&(!s.role||role(e)===s.role)&&(!s.tag||e.tagName===s.tag.toUpperCase()));
const data=e=>({name:name(e),role:role(e),tag:e.tagName,text:norm(e.innerText),value:editorValue(e),expanded:e.getAttribute('aria-expanded'),selected:e.getAttribute('aria-selected'),checked:e.getAttribute('aria-checked'),disabled:!!e.disabled||e.getAttribute('aria-disabled')==='true'});
const test=()=>{const a=match(c.postcondition.selector),s=c.postcondition.state;if(s.present===false)return a.length===0&&Object.keys(s).length===1;return a.length===1&&Object.entries(s).every(([k,v])=>k==='present'?v===true:data(a[0])[k]===v)};
if(c.intent==='panel.inspect'){const a=all().filter(e=>role(e)!=='none'),controls=a.slice(0,511).map(e=>{const d=data(e);return {...d,name:d.name.slice(0,4096),text:d.text.slice(0,8000),value:d.value.slice(0,8000),text_truncated:d.name.length>4096||d.text.length>8000||d.value.length>8000}});const body=document.body;if(body&&vis(body)){const text=norm(body.innerText);controls.push({name:'',role:'document',tag:'BODY',text:text.slice(0,8000),value:'',text_truncated:text.length>8000})}return {ok:true,verified:true,attempted:false,total_controls:a.length+(body?1:0),truncated:a.length>511,controls}};
if(c.intent==='panel.invoke'){
 const a=match(c.selector);if(a.length!==1)return {ok:false,code:a.length?'PANEL_ELEMENT_AMBIGUOUS':'PANEL_ELEMENT_MISSING',attempted:false};
 const e=a[0];if(data(e).disabled)return {ok:false,code:'PANEL_ELEMENT_DISABLED',attempted:false};
 if(!['button','option','menuitem','menuitemradio','menuitemcheckbox','radio','checkbox','tab','combobox'].includes(role(e)))return {ok:false,code:'PANEL_ELEMENT_NOT_INVOKABLE',attempted:false};
 if(test())return {ok:true,verified:true,attempted:false,already_satisfied:true};
 e.click();
}
const until=performance.now()+c.timeout_ms;
do{if(test())return {ok:true,verified:true,attempted:c.intent==='panel.invoke',postcondition:c.postcondition};await new Promise(r=>setTimeout(r,40))}while(performance.now()<until);
return {ok:false,code:'PANEL_POSTCONDITION_NOT_OBSERVED',attempted:c.intent==='panel.invoke'};
})()""".replace("__EDITOR_VALUE__", _EDITOR_VALUE_JS).replace("__CFG__", cfg)
        try:
            value = self._cdp_eval(discovered["cdp"], script, float(timeout) + 1)
        except FastPathError as exc:
            exc.details.update({"attempted": intent == "panel.invoke", "retry_safe": intent != "panel.invoke"})
            raise
        if not isinstance(value, Mapping):
            raise FastPathError("CDP_RESULT_INVALID", {"attempted": intent == "panel.invoke", "retry_safe": intent != "panel.invoke"})
        result = dict(value)
        if result.get("ok") is not True:
            result["retry_safe"] = not result.get("attempted", intent == "panel.invoke")
            raise FastPathError(str(result.get("code") or "PANEL_ACTION_FAILED"), result)
        result.update({"route": "APP_CDP", "kind": intent, "physical_input_used": False,
                       "retry_safe": not result.get("attempted", False), "window": discovered["window"]})
        return result

    @staticmethod
    def _cdp_eval(target: Mapping[str, Any], expression: str, timeout: float = 2.0) -> Any:
        try:
            ws = _LocalWebSocket(str(target["websocket_url"]), timeout)
        except Exception as exc:
            raise FastPathError("CDP_CONNECT_FAILED", {"type": type(exc).__name__}) from exc
        try:
            ws.send(json.dumps({"id": 1, "method": "Runtime.evaluate", "params": {
                "expression": expression, "returnByValue": True, "awaitPromise": True,
            }}))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    msg = json.loads(ws.recv())
                except (TimeoutError, socket.timeout) as exc:
                    raise FastPathError("CDP_TIMEOUT") from exc
                if msg.get("id") != 1:
                    continue
                if "error" in msg:
                    raise FastPathError("CDP_COMMAND_FAILED", {"error": msg["error"]})
                payload = msg.get("result", {}).get("result", {})
                return payload.get("value")
            raise FastPathError("CDP_TIMEOUT")
        finally:
            ws.close()

    @staticmethod
    def _trusted_type(target: Mapping[str, Any], text: str, *, send: bool, target_hint: str = "", input_selector: Mapping[str, str] | None = None) -> dict[str, Any]:
        try:
            ws = _LocalWebSocket(str(target["websocket_url"]), 2.5)
        except Exception as exc:
            raise FastPathError("CDP_CONNECT_FAILED", {"type": type(exc).__name__}) from exc
        seq = 0

        def call(
            method: str,
            params: Mapping[str, Any] | None = None,
            *,
            timeout_s: float = 2.5,
        ) -> dict[str, Any]:
            nonlocal seq
            seq += 1
            ident = seq
            ws.send(json.dumps({"id": ident, "method": method, "params": dict(params or {})}))
            deadline = time.monotonic() + max(0.05, float(timeout_s))
            while time.monotonic() < deadline:
                try:
                    msg = json.loads(ws.recv())
                except (TimeoutError, socket.timeout) as exc:
                    raise FastPathError("CDP_TIMEOUT", {"method": method}) from exc
                if msg.get("id") != ident:
                    continue
                if "error" in msg:
                    raise FastPathError("CDP_COMMAND_FAILED", {"method": method, "error": msg["error"]})
                return dict(msg.get("result") or {})
            raise FastPathError("CDP_TIMEOUT", {"method": method})

        def ev(expr: str, *, timeout_s: float = 2.5) -> Any:
            raw = call("Runtime.evaluate", {
                "expression": expr, "returnByValue": True, "awaitPromise": True,
            }, timeout_s=timeout_s)
            return raw.get("result", {}).get("value")

        def call_many(method: str, params_items: list[Mapping[str, Any]], *, timeout_s: float = 4.0) -> None:
            nonlocal seq
            pending: set[int] = set()
            for params in params_items:
                seq += 1
                pending.add(seq)
                ws.send(json.dumps({"id": seq, "method": method, "params": dict(params)}))
            deadline = time.monotonic() + max(0.1, float(timeout_s))
            while pending and time.monotonic() < deadline:
                try:
                    msg = json.loads(ws.recv())
                except (TimeoutError, socket.timeout) as exc:
                    raise FastPathError("CDP_TIMEOUT", {"method": method, "pending": len(pending)}) from exc
                ident = msg.get("id")
                if ident not in pending:
                    continue
                if "error" in msg:
                    raise FastPathError("CDP_COMMAND_FAILED", {"method": method, "error": msg["error"]})
                pending.remove(ident)
            if pending:
                raise FastPathError("CDP_TIMEOUT", {"method": method, "pending": len(pending)})

        try:
            focus_js = r"""(() => {
__EDITOR_VALUE__
const n=s=>(s||'').toLowerCase().replace(/\s+/g,' ').trim(),vis=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>1&&r.height>1&&s.display!=='none'&&s.visibility!=='hidden';};
const lab=e=>n([e.getAttribute('aria-label'),e.getAttribute('title'),e.getAttribute('placeholder'),e.innerText,e.textContent].filter(Boolean).join(' '));
const selector=__INPUT_SELECTOR__,match=e=>{if(!selector)return true;const name=(e.getAttribute('aria-label')||e.innerText||e.getAttribute('title')||e.getAttribute('placeholder')||'').replace(/\r\n/g,'\n').trim(),role=e.getAttribute('role')||({INPUT:'textbox',TEXTAREA:'textbox'}[e.tagName]||'');return (!selector.name||name===selector.name.trim())&&(!selector.text||(e.innerText||'').trim()===selector.text.trim())&&(!selector.role||role===selector.role)&&(!selector.tag||e.tagName===selector.tag.toUpperCase())};
const candidates=[...document.querySelectorAll('textarea,input:not([type=hidden]):not([type=password]),[contenteditable="true"],[role="textbox"]')].filter(e=>vis(e)&&!e.closest('[aria-hidden="true"]')&&match(e));
if(selector&&candidates.length!==1)return{ok:false,code:candidates.length?'PANEL_ELEMENT_AMBIGUOUS':'PANEL_ELEMENT_MISSING'};
if(selector&&(candidates[0].disabled||candidates[0].getAttribute('aria-disabled')==='true'))return{ok:false,code:'PANEL_ELEMENT_DISABLED'};
const a=candidates.map((e,i)=>{let q=0,l=lab(e),r=e.getBoundingClientRect();if(e.matches('textarea,[contenteditable="true"],[role="textbox"]'))q+=20;if(['message','chat','prompt','ask','write','input','сообщ','вопрос'].some(x=>l.includes(x)))q+=60;q+=Math.max(0,10-(innerHeight-r.bottom)/100);return[q,i,e];}).sort((x,y)=>y[0]-x[0]);
if(!a.length)return{ok:false};const e=a[0][2];e.focus();if(e.isContentEditable){const s=getSelection(),r=document.createRange();r.selectNodeContents(e);s.removeAllRanges();s.addRange(r);}else if(typeof e.select==='function'){e.select();}const v=editorValue(e);return{ok:true,input_index:a[0][1],contenteditable:!!e.isContentEditable,value:v};
})()""".replace("__EDITOR_VALUE__", _EDITOR_VALUE_JS).replace("__INPUT_SELECTOR__", json.dumps(input_selector, ensure_ascii=False))
            focused = ev(focus_js)
            if not isinstance(focused, Mapping) or focused.get("ok") is not True:
                raise FastPathError(str((focused or {}).get("code") or "INPUT_NOT_FOUND"))
            initial_value = str(focused.get("value") or "").replace("\r\n", "\n").rstrip("\n")
            if initial_value:
                call("Input.dispatchKeyEvent", {"type": "keyDown", "modifiers": 2, "key": "a", "code": "KeyA", "windowsVirtualKeyCode": 65})
                call("Input.dispatchKeyEvent", {"type": "keyUp", "modifiers": 2, "key": "a", "code": "KeyA", "windowsVirtualKeyCode": 65})
                call("Input.dispatchKeyEvent", {"type": "keyDown", "key": "Backspace", "code": "Backspace", "windowsVirtualKeyCode": 8})
                call("Input.dispatchKeyEvent", {"type": "keyUp", "key": "Backspace", "code": "Backspace", "windowsVirtualKeyCode": 8})
                # Controlled editors such as Lexical commit clearing asynchronously.
                time.sleep(0.06)
            normalized_text = text.replace("\r\n", "\n").replace("\r", "\n")
            if normalized_text:
                lines = normalized_text.split("\n")
                for line_index, line in enumerate(lines):
                    chars = [{"type": "char", "text": ch, "unmodifiedText": ch} for ch in line]
                    for start in range(0, len(chars), 256):
                        batch = chars[start:start + 256]
                        call_many("Input.dispatchKeyEvent", batch, timeout_s=max(4.0, len(batch) * 0.03))
                    if line_index + 1 < len(lines):
                        call("Input.dispatchKeyEvent", {"type": "keyDown", "modifiers": 8, "key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13})
                        call("Input.dispatchKeyEvent", {"type": "keyUp", "modifiers": 8, "key": "Enter", "code": "Enter", "windowsVirtualKeyCode": 13})
            typed = {"ok": True, "kind": "type", "input_index": focused.get("input_index"), "contenteditable": bool(focused.get("contenteditable"))}

            expected = json.dumps(normalized_text, ensure_ascii=False)
            verify_js = r"""(() => {
__EDITOR_VALUE__
const vis=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>1&&r.height>1&&s.display!=='none'&&s.visibility!=='hidden';};
const a=[...document.querySelectorAll('textarea,input:not([type=hidden]),[contenteditable="true"],[role="textbox"]')].filter(vis);
const e=a.find(x=>x===document.activeElement)||a[a.length-1];if(!e)return{ok:false};
const raw=editorValue(e);const v=raw;return{ok:v===__EXPECTED__,value:raw,normalized_value:v,contenteditable:!!e.isContentEditable};
})()""".replace("__EDITOR_VALUE__", _EDITOR_VALUE_JS).replace("__EXPECTED__", expected)
            verified = ev(verify_js)
            verify_deadline = time.monotonic() + 0.8
            while (not isinstance(verified, Mapping) or verified.get("ok") is not True) and time.monotonic() < verify_deadline:
                # Controlled editors render after the input event. Poll reads;
                # do not repeat typing or sending.
                time.sleep(0.03)
                verified = ev(verify_js)
            if not isinstance(verified, Mapping) or verified.get("ok") is not True:
                raise FastPathError("INPUT_VERIFY_FAILED", {"actual": (verified or {}).get("value")})
            if not send:
                return {"ok": True, "kind": "type", "input_index": typed.get("input_index"), "input_verified": True}

            hint = json.dumps(target_hint, ensure_ascii=False)
            send_js = r"""(async()=> {
const want=(__HINT__||'').toLowerCase(), norm=s=>(s||'').toLowerCase().replace(/\s+/g,' ').trim();
const vis=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>1&&r.height>1&&s.display!=='none'&&s.visibility!=='hidden';};
const lab=e=>norm([e.getAttribute('aria-label'),e.getAttribute('title'),e.innerText,e.textContent].filter(Boolean).join(' '));
for(let k=0;k<12;k++){const a=[...document.querySelectorAll('button,[role="button"]')].filter(vis).map((e,i)=>{let l=lab(e),q=0;if(want&&l.includes(want))q+=120;if(['send','submit','reply','отправ'].some(x=>l.includes(x)))q+=80;if(e.disabled||e.getAttribute('aria-disabled')==='true')q-=1000;return[q,i,e,l];}).sort((x,y)=>y[0]-x[0]);if(a.length&&a[0][0]>0){const e=a[0][2];setTimeout(()=>{try{e.click()}catch(_){}},0);return{ok:true,kind:'chat.send',button_index:a[0][1],label:a[0][3],scheduled:true};}await new Promise(r=>setTimeout(r,10));}return{ok:false,code:'SEND_NOT_FOUND'};
})()""".replace("__HINT__", hint)
            sent = ev(send_js)
            if not isinstance(sent, Mapping) or sent.get("ok") is not True:
                raise FastPathError(str((sent or {}).get("code") or "SEND_NOT_FOUND"))

            expected_commit = json.dumps(normalized_text, ensure_ascii=False)
            commit_js = r"""(() => {
__EDITOR_VALUE__
const n=s=>(s||'').toLowerCase().replace(/\s+/g,' ').trim(),vis=e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>1&&r.height>1&&s.display!=='none'&&s.visibility!=='hidden';};
const lab=e=>n([e.getAttribute('aria-label'),e.getAttribute('title'),e.getAttribute('placeholder'),e.innerText,e.textContent].filter(Boolean).join(' '));
const a=[...document.querySelectorAll('textarea,input:not([type=hidden]),[contenteditable="true"],[role="textbox"]')].filter(vis).map((e,i)=>{let q=0,l=lab(e),r=e.getBoundingClientRect();if(e.matches('textarea,[contenteditable="true"],[role="textbox"]'))q+=20;if(['message','chat','prompt','ask','write','input','сообщ','вопрос'].some(x=>l.includes(x)))q+=60;q+=Math.max(0,10-(innerHeight-r.bottom)/100);return[q,i,e,l];}).sort((x,y)=>y[0]-x[0]);
if(!a.length)return{ok:false,code:'INPUT_NOT_FOUND',url:location.href,title:document.title};
const e=a[0][2],v=editorValue(e),body=document.body.innerText||'';
const empty=v.trim()==='',rendered=body.includes(__EXPECTED__);return{ok:empty&&rendered,composer_empty:empty,target_value:v,target_input_index:a[0][1],target_label:a[0][3],body_contains_expected:rendered,url:location.href,title:document.title};
})()""".replace("__EDITOR_VALUE__", _EDITOR_VALUE_JS).replace("__EXPECTED__", expected_commit)
            committed = None
            deadline = time.monotonic() + 1.2
            while time.monotonic() < deadline:
                try:
                    committed = ev(commit_js, timeout_s=0.35)
                except FastPathError:
                    committed = None
                if isinstance(committed, Mapping) and committed.get("ok") is True:
                    break
                time.sleep(0.015)
            if not isinstance(committed, Mapping) or committed.get("ok") is not True:
                raise FastPathError(
                    "SEND_COMMIT_UNVERIFIED",
                    {"postcondition": dict(committed or {}), "retry_safe": False},
                )
            return {
                **dict(sent),
                "input_index": typed.get("input_index"),
                "input_verified": True,
                "send_verified": True,
                "ui_commit_verified": True,
                "body_contains_expected_at_commit": bool(committed.get("body_contains_expected")),
                "committed_url": committed.get("url"),
            }
        finally:
            ws.close()

    @staticmethod
    def _script(intent: str, text: str, target: str) -> str:
        cfg = json.dumps({"intent": intent, "text": text, "target": target}, ensure_ascii=False)
        source = r"""(async() => {
const c=__CFG__, n=s=>(s||'').toLowerCase().replace(/\s+/g,' ').trim();
const vis=e=>{if(!e)return false;const r=e.getBoundingClientRect(),s=getComputedStyle(e);return r.width>1&&r.height>1&&s.display!=='none'&&s.visibility!=='hidden';};
const lab=e=>n([e.getAttribute('aria-label'),e.getAttribute('title'),e.getAttribute('placeholder'),e.innerText,e.textContent].filter(Boolean).join(' '));
const inp=[...document.querySelectorAll('textarea,input:not([type=hidden]),[contenteditable="true"],[role="textbox"]')].filter(vis);
const btn=[...document.querySelectorAll('button,[role="button"],a[href],[role="link"],[role="menuitem"],[role="option"],[tabindex]')].filter(vis);
const words=(s,a)=>a.some(x=>s.includes(x));
const pi=()=>inp.map((e,i)=>{let q=0,l=lab(e),r=e.getBoundingClientRect();if(e.matches('textarea,[contenteditable="true"],[role="textbox"]'))q+=20;if(words(l,['message','chat','prompt','ask','write','input','сообщ','вопрос']))q+=60;q+=Math.max(0,10-(innerHeight-r.bottom)/100);return[q,i,e,l];}).sort((a,b)=>b[0]-a[0])[0];
const pb=(want,terms)=>btn.map((e,i)=>{let l=lab(e),q=0;if(want&&l.includes(n(want)))q+=120;if(words(l,terms))q+=80;if(e.disabled||e.getAttribute('aria-disabled')==='true')q-=1000;return[q,i,e,l];}).sort((a,b)=>b[0]-a[0])[0];
const setv=(e,t)=>{e.focus();if(e.isContentEditable){const s=getSelection(),r=document.createRange();r.selectNodeContents(e);s.removeAllRanges();s.addRange(r);let ok=false;try{ok=document.execCommand('insertText',false,t)}catch(_){}if(!ok){e.textContent=t;e.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:null}));}}else{const p=e.tagName==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype,d=Object.getOwnPropertyDescriptor(p,'value');d&&d.set?d.set.call(e,t):e.value=t;e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));}};
if(c.intent==='inspect')return {ok:true,title:document.title,url:location.href,inputs:inp.map((e,i)=>({i,label:lab(e),tag:e.tagName,ce:e.isContentEditable,text:n(e.innerText||e.value||''),disabled:!!e.disabled,ariaDisabled:e.getAttribute('aria-disabled')})),buttons:btn.map((e,i)=>({i,label:lab(e),disabled:!!e.disabled,ariaDisabled:e.getAttribute('aria-disabled')})),text:(document.body.innerText||'').slice(-8000)};
if(c.intent==='chat.new'){const b=pb(c.target,['new chat','new conversation','start chat','новый чат','новая беседа']);if(!b||b[0]<=0)return{ok:false,code:'TARGET_NOT_FOUND'};b[2].click();return{ok:true,kind:'chat.new',label:b[3]};}
if(c.intent==='type'||c.intent==='chat.send'){const x=pi();if(!x)return{ok:false,code:'INPUT_NOT_FOUND'};setv(x[2],c.text);if(c.intent==='type')return{ok:true,kind:'type',input_index:x[1]};let b=null;for(let i=0;i<16;i++){b=pb(c.target,['send','submit','reply','отправ']);if(b&&b[0]>0)break;await new Promise(r=>setTimeout(r,16));}if(!b||b[0]<=0)return{ok:false,code:'SEND_NOT_FOUND',input_index:x[1]};b[2].click();return{ok:true,kind:'chat.send',input_index:x[1],button_index:b[1],label:b[3]};}
if(c.intent==='click'){const b=pb(c.target,[]);if(!b||b[0]<=0)return{ok:false,code:'TARGET_NOT_FOUND'};const e=b[2],u0=location.href,t0=document.title,st=x=>[x?.getAttribute?.('aria-pressed'),x?.getAttribute?.('aria-selected'),x?.getAttribute?.('aria-expanded'),x?.getAttribute?.('aria-current'),String(!!x?.checked)].join('|'),s0=st(e);e.click();for(let i=0;i<20;i++){await new Promise(r=>setTimeout(r,25));const detached=!e.isConnected,urlChanged=location.href!==u0,titleChanged=document.title!==t0,stateChanged=!detached&&st(e)!==s0;if(detached||urlChanged||titleChanged||stateChanged)return{ok:true,kind:'click',label:b[3],ui_commit_verified:true,verification:{detached,url_changed:urlChanged,title_changed:titleChanged,state_changed:stateChanged,url:location.href,title:document.title}};}return{ok:true,kind:'click',label:b[3],ui_commit_verified:false,verification:{detached:false,url_changed:false,title_changed:false,state_changed:false,url:location.href,title:document.title}};}
if(c.intent==='read'){const t=document.body.innerText||'';return{ok:true,kind:'read',title:document.title,text:t.slice(-16000),length:t.length};}
return{ok:false,code:'INTENT_UNSUPPORTED'};
})()"""
        return source.replace("__CFG__", cfg)

    def action(
        self,
        discovered: Mapping[str, Any],
        intent: str,
        *,
        text: str = "",
        target: str = "",
    ) -> dict[str, Any]:
        cdp = discovered.get("cdp")
        if not isinstance(cdp, Mapping):
            raise FastPathError("CDP_ROUTE_UNAVAILABLE", {"discovery": {
                k: v for k, v in discovered.items() if k != "cdp"
            }})
        if not self._cached_discovery_valid(discovered):
            raise FastPathError("STALE_TARGET", {"app": discovered.get("app"), "route": discovered.get("route"), "attempted": False, "retry_safe": True})
        started = time.perf_counter_ns()
        if intent in {"type", "chat.send"}:
            value = self._trusted_type(
                cdp, text, send=(intent == "chat.send"), target_hint=target,
            )
        else:
            value = self._cdp_eval(cdp, self._script(intent, text, target))
        if not isinstance(value, Mapping):
            raise FastPathError("CDP_RESULT_INVALID")
        result = dict(value)
        if result.get("ok") is not True:
            raise FastPathError(str(result.get("code") or "CDP_ACTION_FAILED"), result)
        verified = bool(intent in {"read", "inspect"} or result.get("input_verified") is True or result.get("ui_commit_verified") is True)
        result.update({
            "route": "APP_CDP",
            "verified": verified,
            "attempted": True,
            "retry_safe": False if intent in {"click", "chat.new", "chat.send"} else True,
            "physical_input_used": False,
            "latency_ms": (time.perf_counter_ns() - started) / 1_000_000,
            "window": discovered["window"],
            "page": {k: cdp.get(k) for k in ("source", "port", "page_id", "title", "url")},
        })
        return result

    def dispatch(self, args: Mapping[str, Any]) -> dict[str, Any]:
        app = str(args.get("app") or "").strip()
        if not app:
            raise FastPathError("APP_REQUIRED")
        intent = str(args.get("intent") or "discover").strip()
        discovered = self.discover(app, refresh=bool(args.get("refresh")))
        if intent == "discover":
            return discovered
        return self.action(
            discovered,
            intent,
            text=str(args.get("text") or ""),
            target=str(args.get("target") or ""),
        )
