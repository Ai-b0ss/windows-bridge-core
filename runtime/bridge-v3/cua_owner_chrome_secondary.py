"""Owner Chrome Profile 1 hidden managed secondary target over verified browser-level CDP.

Empirical Chrome 158.0.8127.36 basis:
- All Win32 secondary-window paths (`Target.createTarget({newWindow: true, hidden: true})`,
  `windowState: "minimized"`, off-screen coordinates, `ShowWindow(SW_HIDE)`, `DWMWA_CLOAK`,
  and spawning a 2nd `chrome.exe` against the same `User Data`) either fail in Chrome 158
  or produce visible/taskbar/Z-order side effects and MUST remain fail-closed.
- Browser-level loopback CDP `Target.createTarget({url: "about:blank", hidden: true})`
  combined with `Emulation.setDeviceMetricsOverride(1280x800)` inside the ALREADY-RUNNING
  Chrome 158+ `Profile 1` instance creates a windowless hidden WebContents target with:
    * 0 new Win32 HWNDs, 0 taskbar entries, 0 tabs added to the owner's primary window,
    * 0 focus or cursor disturbance,
    * full `Profile 1` auth inheritance (`HttpOnly` cookies + `localStorage`) with ZERO
      profile/cookie file copying and ZERO re-login,
    * full DOM observe/fill/click/read/evaluate and clean `Target.closeTarget` teardown.
- Multi-profile safety: `Target.createTarget({hidden: true})` binds to Chrome's
  `defaultBrowserContextId`. When another profile (e.g. `Default`) owns
  `defaultBrowserContextId`, this module fails closed with
  `OWNER_CHROME_PROFILE_CONTEXT_MISMATCH`.
- Windowless hidden targets have no OS compositor surface; `screenshot` fails closed
  with `HIDDEN_TARGET_SCREENSHOT_UNSUPPORTED`.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import threading
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cua_browser_profiles import linked
from cua_programmatic_discovery import _netstat_text, _parse_local_endpoint, owned_tcp_listeners
from cua_universal_fastpath import _LocalWebSocket, _LocalWebSocketHandshakeError
from ff_win_process_identity import process_creation_token, process_identity_matches

ROUTE_NAME = "owner_chrome_profile1_hidden_secondary"
MIN_HIDDEN_TARGET_CHROME = (158, 0, 8127, 2)
PROFILE_DIR_RE = re.compile(r"^(?:Default|Profile [0-9]+)$")
CHROME_VERSION_RE = re.compile(r"^(Chrome|Chromium)/(\d+)\.(\d+)\.(\d+)\.(\d+)$")
MAX_TARGETS_PER_OWNER = 8
MAX_TARGETS_TOTAL = 24
DEFAULT_VIEWPORT = (1280, 800)


class OwnerChromeSecondaryError(RuntimeError):
    def __init__(self, code: str, message: str | None = None, **details: Any):
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.details = dict(details)


def _version_at_least(version: tuple[int, ...], minimum: tuple[int, ...]) -> bool:
    for a, b in zip(version, minimum):
        if a != b:
            return a > b
    return len(version) >= len(minimum)


def validate_profile_dir_name(profile_dir_name: str) -> str:
    if not isinstance(profile_dir_name, str) or not PROFILE_DIR_RE.fullmatch(profile_dir_name):
        raise OwnerChromeSecondaryError(
            "OWNER_CHROME_PROFILE_INVALID",
            "profile_dir_name must be 'Default' or 'Profile <N>'",
            profile_dir_name=profile_dir_name,
        )
    return profile_dir_name


def valid_url(url: Any) -> str:
    if url is None or url == "":
        return "about:blank"
    if not isinstance(url, str) or len(url) > 8192:
        raise OwnerChromeSecondaryError("URL_INVALID", "URL must be a bounded string", attempted=False)
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        raise OwnerChromeSecondaryError("URL_INVALID", "malformed URL", attempted=False) from None
    if url != "about:blank" and (
        parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password
    ):
        raise OwnerChromeSecondaryError(
            "URL_SCHEME_FORBIDDEN",
            "only http(s) and about:blank URLs are allowed",
            attempted=False,
        )
    return url


def reject_second_chrome_process_same_profile(
    user_data_dir: str | Path,
    profile_dir_name: str = "Profile 1",
) -> None:
    """Explicit fail-closed guard: never spawn a 2nd Chrome process on the same User Data / Profile."""
    raise OwnerChromeSecondaryError(
        "SECOND_CHROME_PROCESS_SAME_PROFILE_FORBIDDEN",
        "launching a second independent Chrome process against an existing User Data / Profile is forbidden; "
        "connect to the already-running Chrome instance via verified browser-level CDP instead",
        user_data_dir=str(user_data_dir),
        profile_dir_name=str(profile_dir_name),
        attempted=False,
    )


def _default_owner_user_data_dir() -> Path | None:
    local_app = os.environ.get("LOCALAPPDATA")
    if not local_app:
        return None
    return Path(local_app) / "Google" / "Chrome" / "User Data"


def _is_connection_refused(exc: BaseException) -> bool:
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, ConnectionRefusedError):
            return True
        if getattr(cur, "winerror", None) == 10061 or getattr(cur, "errno", None) in {111, 61, 10061}:
            return True
        nxt = getattr(cur, "reason", None)
        if isinstance(nxt, BaseException):
            cur = nxt
            continue
        cur = cur.__cause__ or cur.__context__
    return False


def _is_timeout_error(exc: BaseException) -> bool:
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, (TimeoutError, socket.timeout)):
            return True
        nxt = getattr(cur, "reason", None)
        if isinstance(nxt, BaseException):
            cur = nxt
            continue
        cur = cur.__cause__ or cur.__context__
    return False


def _parse_chrome_product(browser_str: str, *, allow_chromium: bool = False) -> tuple[str, tuple[int, ...]]:
    text = str(browser_str or "")
    match = CHROME_VERSION_RE.match(text)
    if not match or (match.group(1) == "Chromium" and not allow_chromium):
        raise OwnerChromeSecondaryError(
            "OWNER_CHROME_CDP_INVALID",
            "CDP endpoint is not a supported Google Chrome browser",
            browser=text,
        )
    ver_tuple = tuple(int(match.group(i)) for i in range(2, 6))
    if not _version_at_least(ver_tuple, MIN_HIDDEN_TARGET_CHROME):
        raise OwnerChromeSecondaryError(
            "OWNER_CHROME_VERSION_UNSUPPORTED",
            "Chrome >= 158.0.8127.2 is required for hidden secondary targets",
            chrome_version=".".join(str(x) for x in ver_tuple),
            required=".".join(str(x) for x in MIN_HIDDEN_TARGET_CHROME),
        )
    return text, ver_tuple


def _loopback_json_version(port: int, timeout: float = 2.0) -> dict[str, Any]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    url = f"http://127.0.0.1:{port}/json/version"
    try:
        with opener.open(url, timeout=timeout) as resp:
            if resp.status != 200:
                raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_INVALID", f"unexpected HTTP {resp.status}", http_status=int(resp.status))
            raw = resp.read(65537)
    except OwnerChromeSecondaryError:
        raise
    except urllib.error.HTTPError as exc:
        code = int(getattr(exc, "code", 0) or 0)
        try:
            exc.close()
        except Exception:
            pass
        if code == 404:
            raise OwnerChromeSecondaryError(
                "OWNER_CHROME_CDP_HTTP_DISCOVERY_DISABLED",
                "loopback CDP /json/version returned HTTP 404 (Chrome approval-gated WebSocket-only remote debugging)",
                http_status=404,
                discovery_mode="devtools_active_port_ws_only",
            ) from None
        if code in {401, 403}:
            raise OwnerChromeSecondaryError(
                "OWNER_CHROME_CDP_DENIED",
                f"loopback CDP /json/version rejected with HTTP {code}",
                http_status=code,
                denied=True,
                consent_gate="chrome_remote_debugging_dialog",
                hub_policy_separate=True,
                discovery_state="denied",
                execution_started=False,
                attempted=False,
                retry_safe=True,
            ) from None
        raise OwnerChromeSecondaryError(
            "OWNER_CHROME_CDP_INVALID",
            f"unexpected HTTP {code} from /json/version",
            http_status=code,
        ) from None
    except (TimeoutError, ConnectionError, urllib.error.URLError, OSError) as exc:
        if _is_connection_refused(exc):
            raise OwnerChromeSecondaryError(
                "OWNER_CHROME_CDP_CONNECTION_REFUSED",
                "loopback CDP port refused connection (listener is not accepting connections or DevToolsActivePort is stale)",
                cause="ConnectionRefusedError",
                refused=True,
                discovery_state="connection_refused",
                port=int(port),
                execution_started=False,
                attempted=False,
                retry_safe=True,
            ) from None
        cause = type(getattr(exc, "reason", exc)).__name__
        raise OwnerChromeSecondaryError(
            "OWNER_CHROME_HIDDEN_SECONDARY_CDP_UNAVAILABLE",
            "browser-level loopback CDP /json/version is unreachable",
            cause=cause,
        ) from exc
    if len(raw) > 65536:
        raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_INVALID", "/json/version response too large")
    try:
        data = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_INVALID", "invalid JSON from /json/version") from exc
    if not isinstance(data, dict):
        raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_INVALID", "unexpected /json/version payload")
    return data


def _read_devtools_active_port(user_data_dir: Path) -> tuple[int, str]:
    marker = user_data_dir / "DevToolsActivePort"
    if linked(user_data_dir) or linked(marker) or not marker.is_file() or marker.stat().st_size > 4096:
        raise OwnerChromeSecondaryError(
            "OWNER_CHROME_HIDDEN_SECONDARY_CDP_UNAVAILABLE",
            "DevToolsActivePort not present (browser-level remote debugging is not enabled on running Chrome)",
        )
    lines = marker.read_text(encoding="ascii", errors="strict").splitlines()
    if (
        len(lines) != 2
        or not re.fullmatch(r"[1-9][0-9]{0,4}", lines[0])
        or not 0 < int(lines[0]) <= 65535
        or not re.fullmatch(r"/devtools/browser/[A-Za-z0-9_-]{1,128}", lines[1])
    ):
        raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_INVALID", "invalid DevToolsActivePort format")
    return int(lines[0]), lines[1]


def _validate_loopback_ws_url(ws_url: str, expected_port: int | None = None, expected_path: str | None = None) -> tuple[int, str, str]:
    parsed = urllib.parse.urlsplit(str(ws_url or ""))
    if (
        parsed.scheme != "ws"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or not parsed.port
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"/devtools/browser/[A-Za-z0-9_-]{1,128}", parsed.path or "")
    ):
        raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_INVALID", "non-loopback or invalid browser WebSocket URL")
    if expected_port is not None and parsed.port != expected_port:
        raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_INVALID", "CDP WebSocket port mismatch")
    if expected_path is not None and parsed.path != expected_path:
        raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_INVALID", "CDP WebSocket path mismatch")
    host = "127.0.0.1" if parsed.hostname in {"127.0.0.1", "localhost"} else f"[{parsed.hostname}]"
    return int(parsed.port), parsed.path, f"ws://{host}:{parsed.port}{parsed.path}"


def _parse_cdp_endpoint(cdp_endpoint: str) -> tuple[int, str | None]:
    parsed = urllib.parse.urlsplit(str(cdp_endpoint or ""))
    if (
        parsed.scheme not in {"http", "ws"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or not parsed.port
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise OwnerChromeSecondaryError(
            "OWNER_CHROME_CDP_INVALID",
            "cdp_endpoint must be a loopback http://127.0.0.1:<port> or ws://127.0.0.1:<port>/devtools/browser/<id>",
        )
    if parsed.scheme == "ws":
        port, path, _ = _validate_loopback_ws_url(cdp_endpoint)
        return port, path
    return int(parsed.port), None


def _is_chrome_running_on_windows() -> bool | None:
    if os.name != "nt":
        return None
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$p = @(Get-Process chrome -ErrorAction SilentlyContinue); if ($p.Count -gt 0) { '1' } else { '0' }",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode == 0:
            return proc.stdout.strip().endswith("1")
    except Exception:
        pass
    return None


def _extract_profile_arg_from_cmdline(cmdline: str) -> str | None:
    if not cmdline:
        return None
    m = re.search(
        r'"--profile-directory=([^"]+)"|--profile-directory="([^"]+)"|--profile-directory=([^\s"]+)',
        cmdline,
    )
    if not m:
        return None
    return m.group(1) or m.group(2) or m.group(3)


def _query_process_cmdline_windows(pid: int) -> str | None:
    if os.name != "nt" or not isinstance(pid, int) or pid <= 0:
        return None
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"(Get-CimInstance Win32_Process -Filter 'ProcessId={int(pid)}' -ErrorAction SilentlyContinue).CommandLine",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode == 0:
            val = proc.stdout.strip()
            return val or None
    except Exception:
        pass
    return None


def _read_local_state_active_profiles(user_data_dir: Path | None) -> tuple[str | None, list[str]]:
    """Read ONLY profile directory names from Local State metadata (never cookies/tokens/passwords)."""
    if user_data_dir is None:
        return None, []
    local_state = user_data_dir / "Local State"
    if linked(user_data_dir) or linked(local_state) or not local_state.is_file():
        return None, []
    try:
        if local_state.stat().st_size > 8 * 1024 * 1024:
            return None, []
        data = json.loads(local_state.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, []
    prof = data.get("profile") if isinstance(data, dict) else None
    if not isinstance(prof, dict):
        return None, []
    last_used = prof.get("last_used") if isinstance(prof.get("last_used"), str) else None
    raw_active = prof.get("last_active_profiles")
    active = [str(item) for item in raw_active if isinstance(item, str)] if isinstance(raw_active, list) else []
    return last_used, active


def _query_process_chrome_version_windows(pid: int) -> str | None:
    """Read-only product version metadata for a running chrome.exe PID on Windows."""
    if os.name != "nt" or not isinstance(pid, int) or pid <= 0:
        return None
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    f"$p = Get-Process -Id {int(pid)} -ErrorAction SilentlyContinue; "
                    "if ($p -and $p.ProcessName -ieq 'chrome') { "
                    "$m = $p.MainModule; "
                    "if ($m -and $m.FileVersionInfo.ProductVersion) { $m.FileVersionInfo.ProductVersion } }"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode == 0:
            ver = proc.stdout.strip()
            if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ver):
                return f"Chrome/{ver}"
    except Exception:
        pass
    return None


def _find_listener_pid_for_port(port: int, hint_pid: int | None = None) -> int | None:
    if hint_pid is not None:
        listeners = [x for x in owned_tcp_listeners(hint_pid) if x.get("port") == port]
        if listeners and all(x.get("address") in {"127.0.0.1", "::1"} for x in listeners):
            return int(hint_pid)
        return None
    if os.name != "nt":
        return None
    text = _netstat_text(timeout_s=1.5)
    if text:
        for raw in text.splitlines():
            parts = raw.split()
            if len(parts) < 5 or parts[0].upper() != "TCP" or parts[3].upper() != "LISTENING":
                continue
            parsed = _parse_local_endpoint(parts[1])
            if parsed is None:
                continue
            host, local_port = parsed
            if local_port == int(port) and host in {"127.0.0.1", "::1"} and parts[4].isdigit():
                return int(parts[4])
        return None
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"$c = Get-NetTCPConnection -LocalPort {int(port)} -State Listen -ErrorAction SilentlyContinue | Where-Object {{ $_.LocalAddress -in @('127.0.0.1', '::1') }} | Select-Object -First 1; if ($c) {{ $c.OwningProcess }}",
            ],
            capture_output=True,
            text=True,
            timeout=5.0,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode == 0 and proc.stdout.strip().isdigit():
            return int(proc.stdout.strip())
    except Exception:
        pass
    return None


class _BrowserCDPClient:
    """Thread-safe loopback browser-target CDP client for one already-running Chrome instance."""

    KEEPALIVE_INTERVAL_S = 45.0
    KEEPALIVE_TIMEOUT_S = 4.0

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.socket: _LocalWebSocket | None = None
        self.endpoint: str | None = None
        self.seq = 0
        self.generation = 0
        self._keepalive_stop: threading.Event | None = None
        self.connected_at: float | None = None
        self.keepalive_ok_count = 0
        self.last_keepalive_at: float | None = None
        self.last_keepalive_error: str | None = None

    def stop_keepalive(self) -> None:
        with self._lock:
            if self._keepalive_stop is not None:
                self._keepalive_stop.set()
                self._keepalive_stop = None

    def start_keepalive(self) -> None:
        """Preserve an existing approved socket; never connect or request Chrome consent."""
        with self._lock:
            if self.socket is None:
                return
            if self._keepalive_stop is not None and not self._keepalive_stop.is_set():
                return
            stop = threading.Event()
            self._keepalive_stop = stop
            generation = self.generation
            threading.Thread(
                target=self._keepalive_loop,
                args=(generation, stop),
                name="owner-chrome-approved-cdp-keepalive",
                daemon=True,
            ).start()

    def _keepalive_loop(self, generation: int, stop: threading.Event) -> None:
        try:
            while not stop.wait(self.KEEPALIVE_INTERVAL_S):
                with self._lock:
                    if stop.is_set() or self.generation != generation or self.socket is None:
                        return
                    try:
                        # Browser.getVersion is read-only; no new WebSocket or target is created.
                        self.send("Browser.getVersion", timeout=self.KEEPALIVE_TIMEOUT_S)
                        self.keepalive_ok_count += 1
                        self.last_keepalive_at = time.time()
                        self.last_keepalive_error = None
                    except OwnerChromeSecondaryError as exc:
                        self.last_keepalive_error = exc.code
                        # send() tears down a broken socket. Never reattach automatically.
                        return
        finally:
            with self._lock:
                stop.set()
                if self._keepalive_stop is stop:
                    self._keepalive_stop = None

    def keepalive_status(self) -> dict[str, Any]:
        with self._lock:
            active = bool(
                self.socket is not None
                and self._keepalive_stop is not None
                and not self._keepalive_stop.is_set()
            )
            return {
                "keepalive_active": active,
                "keepalive_interval_s": float(self.KEEPALIVE_INTERVAL_S),
                "keepalive_ok_count": int(self.keepalive_ok_count),
                "last_keepalive_at": self.last_keepalive_at,
                "last_keepalive_error": self.last_keepalive_error,
                "connected_at": self.connected_at,
            }

    def connected(self) -> bool:
        with self._lock:
            return self.socket is not None

    def reset(self) -> None:
        with self._lock:
            if self._keepalive_stop is not None:
                self._keepalive_stop.set()
                self._keepalive_stop = None
            sock = self.socket
            self.socket = None
            self.endpoint = None
            self.connected_at = None
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def connect(self, ws_url: str, timeout: float = 5.0) -> None:
        with self._lock:
            if self.socket is not None and self.endpoint == ws_url:
                return
            self.reset()
            self.socket = _LocalWebSocket(ws_url, timeout=timeout)
            self.endpoint = ws_url
            self.generation += 1
            self.connected_at = time.time()
            self.keepalive_ok_count = 0
            self.last_keepalive_at = None
            self.last_keepalive_error = None

    def adopt(self, ws: _LocalWebSocket, ws_url: str, *, seq: int = 0) -> None:
        with self._lock:
            self.reset()
            self.socket = ws
            self.endpoint = ws_url
            self.seq = max(int(seq), 0)
            self.generation += 1
            self.connected_at = time.time()
            self.keepalive_ok_count = 0
            self.last_keepalive_at = None
            self.last_keepalive_error = None

    def _send_once(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        if self.socket is None:
            raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_DISCONNECTED", "CDP socket is not connected")
        self.seq += 1
        rid = self.seq
        packet: dict[str, Any] = {"id": rid, "method": method, "params": params or {}}
        if session_id is not None:
            packet["sessionId"] = session_id
        deadline = time.monotonic() + max(0.5, float(timeout))
        self.socket.set_deadline(deadline)
        self.socket.send(json.dumps(packet))
        while True:
            reply = json.loads(self.socket.recv())
            if reply.get("id") != rid:
                continue
            if "error" in reply and reply["error"]:
                err = reply["error"]
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_CDP_REJECTED",
                    str(err.get("message") or "CDP command rejected"),
                    cdp_code=err.get("code"),
                    method=method,
                )
            return reply.get("result") if isinstance(reply.get("result"), dict) else {}

    def send(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
        timeout: float = 10.0,
    ) -> dict[str, Any]:
        with self._lock:
            if self.socket is None:
                raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_DISCONNECTED", "CDP socket is not connected")
            try:
                return self._send_once(method, params, session_id=session_id, timeout=timeout)
            except OwnerChromeSecondaryError:
                raise
            except (TimeoutError, socket.timeout) as exc:
                # A slow page-session command must not destroy an already-approved
                # browser-level CDP channel if the WebSocket stream is still clean.
                if session_id is not None and not getattr(self.socket, "frame_dirty", False):
                    try:
                        self._send_once("Browser.getVersion", {}, timeout=2.0)
                    except Exception:
                        pass
                    else:
                        raise OwnerChromeSecondaryError(
                            "OWNER_CHROME_CDP_TIMEOUT",
                            "CDP page command timed out; approved browser connection preserved",
                            cause=type(exc).__name__,
                            method=method,
                            outcome_unknown=True,
                            retry_safe=False,
                            connection_preserved=True,
                        ) from exc
                self.reset()
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_CDP_DISCONNECTED",
                    "CDP transport failed during command",
                    cause=type(exc).__name__,
                    method=method,
                    outcome_unknown=True,
                    retry_safe=False,
                ) from exc
            except Exception as exc:
                self.reset()
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_CDP_DISCONNECTED",
                    "CDP transport failed during command",
                    cause=type(exc).__name__,
                    method=method,
                    outcome_unknown=True,
                    retry_safe=False,
                ) from exc


class OwnerChromeHiddenSecondaryManager:
    """Manages windowless hidden secondary targets in an already-running Chrome Profile 1.

    Guarantees:
    - Never launches a second Chrome process against the owner's User Data directory.
    - Never copies cookies, passwords, or any files from the owner's Chrome profile.
    - Never creates a visible or minimized Win32 window, taskbar entry, or tab in owner's window.
    - Enforces `defaultBrowserContextId` verification against `profile_dir_name` (fail-closed
      `OWNER_CHROME_PROFILE_CONTEXT_MISMATCH` on multi-profile mismatch).
    - Strict per-owner target ownership and verified `Target.closeTarget` teardown that never
      touches or closes the owner's primary Chrome windows/tabs.
    """

    def __init__(
        self,
        state_dir: str | Path | None = None,
        *,
        profile_dir_name: str | None = None,
        profile_directory: str | None = None,
        cdp_endpoint: str | None = None,
        user_data_dir: str | Path | None = None,
        chrome_pid: int | None = None,
        profile_verifier: Callable[..., dict[str, Any]] | None = None,
        allow_chromium: bool = False,
        viewport: tuple[int, int] = DEFAULT_VIEWPORT,
    ) -> None:
        self.state_dir = Path(state_dir) if state_dir is not None else None
        chosen_profile = profile_dir_name if profile_dir_name is not None else (profile_directory or "Profile 1")
        self.profile_dir_name = validate_profile_dir_name(chosen_profile)
        self.cdp_endpoint = cdp_endpoint
        self.user_data_dir = Path(user_data_dir) if user_data_dir is not None else None
        self.chrome_pid = int(chrome_pid) if chrome_pid is not None else None
        self._profile_verifier = profile_verifier
        self.allow_chromium = bool(allow_chromium)
        self.viewport = (int(viewport[0]), int(viewport[1]))
        self._lock = threading.RLock()
        self._cdp = _BrowserCDPClient()
        self._targets: dict[str, dict[str, Any]] = {}  # tab_id -> record
        self._verified_info: dict[str, Any] | None = None
        self._stopping = False

    def running(self) -> bool:
        with self._lock:
            return self._cdp.connected() or bool(self._targets)

    def _resolve_cdp_info(self, *, timeout_s: float = 3.0) -> dict[str, Any]:
        expected_path: str | None = None
        ws_host = "127.0.0.1"
        udd = self.user_data_dir or _default_owner_user_data_dir()
        if self.cdp_endpoint:
            parsed_ep = urllib.parse.urlsplit(str(self.cdp_endpoint or ""))
            if parsed_ep.hostname == "::1":
                ws_host = "[::1]"
            port, expected_path = _parse_cdp_endpoint(self.cdp_endpoint)
        else:
            if udd is None or not udd.is_dir():
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_HIDDEN_SECONDARY_CDP_UNAVAILABLE",
                    "owner Chrome User Data directory unavailable",
                )
            try:
                port, expected_path = _read_devtools_active_port(udd)
            except OwnerChromeSecondaryError:
                chrome_up = _is_chrome_running_on_windows()
                if chrome_up is False:
                    raise OwnerChromeSecondaryError(
                        "OWNER_CHROME_NOT_RUNNING",
                        "already-running Chrome instance is required; never spawning a second process on owner profile",
                    ) from None
                raise

        listener_pid = _find_listener_pid_for_port(port, hint_pid=self.chrome_pid)
        if self.chrome_pid is not None and listener_pid != self.chrome_pid:
            raise OwnerChromeSecondaryError(
                "OWNER_CHROME_LISTENER_NOT_OWNED",
                "loopback CDP listener is not owned by the expected Chrome process",
                port=port,
                expected_pid=self.chrome_pid,
            )

        try:
            version_payload = _loopback_json_version(port, timeout=min(float(timeout_s), 3.0))
        except OwnerChromeSecondaryError as exc:
            if exc.code != "OWNER_CHROME_CDP_HTTP_DISCOVERY_DISABLED":
                raise
            ws_path = expected_path
            if ws_path is None and udd is not None and udd.is_dir():
                try:
                    marker_port, marker_path = _read_devtools_active_port(udd)
                    if marker_port == port:
                        ws_path = marker_path
                except OwnerChromeSecondaryError:
                    ws_path = None
            if ws_path is None:
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_HIDDEN_SECONDARY_CDP_UNAVAILABLE",
                    "loopback CDP /json/version returned HTTP 404 and no matching DevToolsActivePort browser WebSocket path is available",
                    http_status=404,
                    http_discovery_status=404,
                    discovery_mode="devtools_active_port_ws_only",
                    ws_path_unavailable=True,
                ) from None
            ws_port, valid_ws_path, ws_url = _validate_loopback_ws_url(
                f"ws://{ws_host}:{port}{ws_path}",
                expected_port=port,
                expected_path=ws_path,
            )
            local_browser = _query_process_chrome_version_windows(listener_pid) if listener_pid else None
            local_ver_str: str | None = None
            if local_browser:
                _, local_ver_tuple = _parse_chrome_product(local_browser, allow_chromium=self.allow_chromium)
                local_ver_str = ".".join(str(x) for x in local_ver_tuple)
            return {
                "port": ws_port,
                "ws_path": valid_ws_path,
                "ws_url": ws_url,
                "browser": None,
                "local_browser": local_browser,
                "chrome_version": local_ver_str,
                "pid": listener_pid,
                "discovery_mode": "devtools_active_port_ws_only",
                "http_discovery_status": 404,
                "approval_gated": True,
            }

        browser_str, ver_tuple = _parse_chrome_product(
            str(version_payload.get("Browser") or ""),
            allow_chromium=self.allow_chromium,
        )
        ws_port, ws_path, ws_url = _validate_loopback_ws_url(
            str(version_payload.get("webSocketDebuggerUrl") or ""),
            expected_port=port,
            expected_path=expected_path,
        )
        return {
            "port": ws_port,
            "ws_path": ws_path,
            "ws_url": ws_url,
            "browser": browser_str,
            "chrome_version": ".".join(str(x) for x in ver_tuple),
            "pid": listener_pid,
            "discovery_mode": "http_json_version",
            "http_discovery_status": 200,
            "approval_gated": False,
        }

    def _precheck_local_profile_mismatch(self, *, profile_dir_name: str, info: dict[str, Any]) -> None:
        """Fail closed on obvious profile mismatch from OS cmdline / Local State before requesting Chrome confirmation."""
        if self._profile_verifier is not None:
            return
        udd = self.user_data_dir or _default_owner_user_data_dir()
        cmdline = _query_process_cmdline_windows(info["pid"]) if info.get("pid") else None
        cli_profile = _extract_profile_arg_from_cmdline(cmdline or "")
        last_used, active_profiles = _read_local_state_active_profiles(udd)
        common = {
            "cdp_discovered": True,
            "discovery_mode": info.get("discovery_mode"),
            "http_discovery_status": info.get("http_discovery_status"),
            "chrome_version": info.get("chrome_version"),
            "expected_profile": profile_dir_name,
        }
        if len(active_profiles) > 1:
            raise OwnerChromeSecondaryError(
                "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH",
                "multiple Chrome profiles are active in Local State; "
                f"defaultBrowserContextId can shift away from '{profile_dir_name}', refusing fail-closed",
                last_used=last_used,
                active_profiles=active_profiles,
                **common,
            )
        if cli_profile is not None:
            if cli_profile != profile_dir_name:
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH",
                    f"running Chrome default context belongs to '{cli_profile}', not '{profile_dir_name}'",
                    detected_default_profile=cli_profile,
                    **common,
                )
            if (last_used is not None and last_used != profile_dir_name) or (
                active_profiles and set(active_profiles) != {profile_dir_name}
            ):
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH",
                    f"Chrome Local State active/last_used profile ({last_used!r} / {active_profiles!r}) "
                    f"disagrees with '{profile_dir_name}' despite launch flag",
                    cli_profile=cli_profile,
                    last_used=last_used,
                    active_profiles=active_profiles,
                    **common,
                )
            return
        observed_profile = active_profiles[0] if len(active_profiles) == 1 else last_used
        if observed_profile is not None and observed_profile != profile_dir_name:
            raise OwnerChromeSecondaryError(
                "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH",
                f"Chrome active profile in Local State is '{observed_profile}', not '{profile_dir_name}'",
                detected_default_profile=observed_profile,
                last_used=last_used,
                active_profiles=active_profiles,
                **common,
            )

    def _approval_required_error(
        self,
        info: dict[str, Any],
        *,
        message: str,
        cause: str | None = None,
    ) -> OwnerChromeSecondaryError:
        details: dict[str, Any] = {
            "cdp_discovered": True,
            "approval_required": True,
            "confirmation_required": True,
            "consent_gate": "chrome_remote_debugging_dialog",
            "hub_policy_separate": True,
            "hub_risk_class": "owner_chrome_hidden_secondary",
            "discovery_mode": info.get("discovery_mode"),
            "http_discovery_status": info.get("http_discovery_status"),
            "chrome_version": info.get("chrome_version"),
            "remedy": "OWNER_CHROME_APPROVE_REMOTE_DEBUGGING_DIALOG",
            "automatic": False,
            "execution_started": False,
            "attempted": False,
            "retry_safe": True,
        }
        if cause:
            details["cause"] = cause
        return OwnerChromeSecondaryError("OWNER_CHROME_CDP_APPROVAL_REQUIRED", message, **details)

    def _connect_ws_classified(self, info: dict[str, Any], *, timeout_s: float) -> bool:
        """Connect browser-level loopback CDP WebSocket and classify refused/denied/approval-required errors without leaking ws_url."""
        if self._cdp.connected() is True and self._cdp.endpoint == info["ws_url"]:
            return True
        try:
            self._cdp.connect(info["ws_url"], timeout=timeout_s)
            return False
        except OwnerChromeSecondaryError:
            raise
        except _LocalWebSocketHandshakeError as exc:
            if exc.status_code in {401, 403, 500} or exc.closed_before_response:
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_CDP_DENIED",
                    "Chrome's native remote debugging WebSocket session was denied or closed before approval (separate from Hub policy)",
                    cdp_discovered=True,
                    denied=True,
                    consent_gate="chrome_remote_debugging_dialog",
                    hub_policy_separate=True,
                    discovery_state="denied",
                    discovery_mode=info.get("discovery_mode"),
                    http_discovery_status=info.get("http_discovery_status"),
                    chrome_version=info.get("chrome_version"),
                    ws_http_status=exc.status_code,
                    closed_before_response=exc.closed_before_response,
                    execution_started=False,
                    attempted=False,
                    retry_safe=True,
                ) from None
            if exc.status_code == 404:
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_CDP_INVALID",
                    "CDP browser WebSocket endpoint returned HTTP 404 (stale or mismatched DevToolsActivePort)",
                    discovery_mode=info.get("discovery_mode"),
                    http_discovery_status=info.get("http_discovery_status"),
                    ws_http_status=404,
                ) from None
            raise OwnerChromeSecondaryError(
                "OWNER_CHROME_CDP_INVALID",
                "CDP WebSocket handshake was rejected",
                discovery_mode=info.get("discovery_mode"),
                http_discovery_status=info.get("http_discovery_status"),
                ws_http_status=exc.status_code,
            ) from None
        except Exception as exc:
            if _is_connection_refused(exc):
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_CDP_CONNECTION_REFUSED",
                    "loopback CDP WebSocket port refused connection",
                    cause="ConnectionRefusedError",
                    refused=True,
                    discovery_state="connection_refused",
                    discovery_mode=info.get("discovery_mode"),
                    http_discovery_status=info.get("http_discovery_status"),
                    port=info.get("port"),
                    execution_started=False,
                    attempted=False,
                    retry_safe=True,
                ) from None
            if _is_timeout_error(exc):
                if info.get("approval_gated"):
                    raise self._approval_required_error(
                        info,
                        message=(
                            "Chrome's native remote debugging confirmation dialog is pending; approve the browser prompt in Chrome "
                            "(not clicked automatically; separate from Hub local standing policy)"
                        ),
                        cause="TimeoutError",
                    ) from None
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_HIDDEN_SECONDARY_CDP_UNAVAILABLE",
                    "loopback CDP WebSocket handshake timed out",
                    cause="TimeoutError",
                    discovery_mode=info.get("discovery_mode"),
                    http_discovery_status=info.get("http_discovery_status"),
                ) from None
            if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, EOFError)):
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_CDP_DENIED",
                    "Chrome's native remote debugging session was closed or denied during WebSocket handshake (separate from Hub policy)",
                    cdp_discovered=True,
                    denied=True,
                    consent_gate="chrome_remote_debugging_dialog",
                    hub_policy_separate=True,
                    discovery_state="denied",
                    discovery_mode=info.get("discovery_mode"),
                    http_discovery_status=info.get("http_discovery_status"),
                    chrome_version=info.get("chrome_version"),
                    cause=type(exc).__name__,
                    execution_started=False,
                    attempted=False,
                    retry_safe=True,
                ) from None
            raise OwnerChromeSecondaryError(
                "OWNER_CHROME_HIDDEN_SECONDARY_CDP_UNAVAILABLE",
                "loopback CDP WebSocket connection failed",
                cause=type(exc).__name__,
                discovery_mode=info.get("discovery_mode"),
                http_discovery_status=info.get("http_discovery_status"),
            ) from None

    def _verify_ws_browser_version(self, info: dict[str, Any], *, timeout_s: float, reused: bool) -> dict[str, Any]:
        if info.get("browser"):
            return info
        try:
            ver_res = self._cdp.send("Browser.getVersion", {}, timeout=min(float(timeout_s), 5.0))
        except OwnerChromeSecondaryError as exc:
            if reused and exc.code == "OWNER_CHROME_CDP_DISCONNECTED":
                raise
            if exc.code == "OWNER_CHROME_CDP_DISCONNECTED":
                if exc.details.get("cause") in {"TimeoutError", "timeout"} and info.get("approval_gated"):
                    raise self._approval_required_error(
                        info,
                        message=(
                            "Chrome's native remote debugging confirmation dialog is pending; approve the browser prompt in Chrome "
                            "(not clicked automatically; separate from Hub local standing policy)"
                        ),
                        cause="TimeoutError",
                    ) from None
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_CDP_DENIED",
                    "Chrome's native remote debugging session was closed or denied before Browser.getVersion completed (separate from Hub policy)",
                    cdp_discovered=True,
                    denied=True,
                    consent_gate="chrome_remote_debugging_dialog",
                    hub_policy_separate=True,
                    discovery_state="denied",
                    discovery_mode=info.get("discovery_mode"),
                    http_discovery_status=info.get("http_discovery_status"),
                    chrome_version=info.get("chrome_version"),
                    cause=exc.details.get("cause") or exc.code,
                    execution_started=False,
                    attempted=False,
                    retry_safe=True,
                ) from None
            if exc.code == "OWNER_CHROME_CDP_REJECTED":
                msg_low = exc.message.lower()
                if any(tok in msg_low for tok in ("denied", "forbidden", "unauthorized", "not allowed", "rejected")):
                    raise OwnerChromeSecondaryError(
                        "OWNER_CHROME_CDP_DENIED",
                        "Chrome's native remote debugging rejected Browser.getVersion (separate from Hub policy)",
                        cdp_discovered=True,
                        denied=True,
                        consent_gate="chrome_remote_debugging_dialog",
                        hub_policy_separate=True,
                        discovery_state="denied",
                        discovery_mode=info.get("discovery_mode"),
                        http_discovery_status=info.get("http_discovery_status"),
                        cdp_code=exc.details.get("cdp_code"),
                        execution_started=False,
                        attempted=False,
                        retry_safe=True,
                    ) from None
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_CDP_INVALID",
                    "CDP endpoint rejected Browser.getVersion",
                    discovery_mode=info.get("discovery_mode"),
                    http_discovery_status=info.get("http_discovery_status"),
                    cdp_code=exc.details.get("cdp_code"),
                ) from None
            raise
        product, ver_tuple = _parse_chrome_product(
            str(ver_res.get("product") or ""),
            allow_chromium=self.allow_chromium,
        )
        return {
            **info,
            "browser": product,
            "chrome_version": ".".join(str(x) for x in ver_tuple),
        }

    def _verify_profile_default_context(
        self,
        *,
        profile_dir_name: str,
        info: dict[str, Any],
        timeout_s: float = 5.0,
    ) -> dict[str, Any]:
        """Prove `profile_dir_name` owns Chrome's `defaultBrowserContextId` or fail closed."""
        contexts_res = self._cdp.send("Target.getBrowserContexts", {}, timeout=timeout_s)
        default_ctx = contexts_res.get("defaultBrowserContextId")
        if not isinstance(default_ctx, str) or not default_ctx:
            raise OwnerChromeSecondaryError(
                "OWNER_CHROME_PROFILE_CONTEXT_UNVERIFIED",
                "Chrome did not report a valid defaultBrowserContextId",
            )
        targets_res = self._cdp.send("Target.getTargets", {}, timeout=timeout_s)
        target_infos = targets_res.get("targetInfos") or []
        page_contexts = sorted({
            str(item.get("browserContextId"))
            for item in target_infos
            if item.get("type") == "page" and isinstance(item.get("browserContextId"), str) and item.get("browserContextId")
        })
        extra_contexts = [ctx for ctx in page_contexts if ctx != default_ctx]

        if self._profile_verifier is not None:
            verdict = self._profile_verifier(
                profile_dir_name=profile_dir_name,
                default_browser_context_id=default_ctx,
                page_contexts=page_contexts,
                info=info,
            )
            if not isinstance(verdict, dict) or not verdict.get("matched"):
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH",
                    str((verdict or {}).get("reason") or f"{profile_dir_name} does not own Chrome defaultBrowserContextId"),
                    expected_profile=profile_dir_name,
                    default_browser_context_id=default_ctx,
                    page_contexts=page_contexts,
                )
            return {
                "default_browser_context_id": default_ctx,
                "page_contexts": page_contexts,
                "verified_by": str(verdict.get("verified_by") or "verifier"),
            }

        # Multi-profile check: Chrome 158's `defaultBrowserContextId` dynamically tracks
        # the most recently opened/focused profile, and `Target.createTarget({hidden: true})`
        # ONLY binds to `defaultBrowserContextId` (passing another profile's browserContextId
        # fails -32602). Therefore, whenever multiple profile browserContextIds are open in
        # the same Chrome process, fail closed unconditionally unless an explicit
        # `profile_verifier` proved `defaultBrowserContextId` belongs to `profile_dir_name`.
        udd = self.user_data_dir or _default_owner_user_data_dir()
        cmdline = _query_process_cmdline_windows(info["pid"]) if info.get("pid") else None
        cli_profile = _extract_profile_arg_from_cmdline(cmdline or "")
        last_used, active_profiles = _read_local_state_active_profiles(udd)

        if extra_contexts:
            raise OwnerChromeSecondaryError(
                "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH",
                "multiple Chrome profile contexts are active in the same browser process; "
                f"defaultBrowserContextId can shift away from '{profile_dir_name}', refusing fail-closed",
                expected_profile=profile_dir_name,
                default_browser_context_id=default_ctx,
                page_contexts=page_contexts,
                cli_profile=cli_profile,
                last_used=last_used,
                active_profiles=active_profiles,
            )

        if cli_profile is not None:
            if cli_profile != profile_dir_name:
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH",
                    f"running Chrome default context belongs to '{cli_profile}', not '{profile_dir_name}'",
                    expected_profile=profile_dir_name,
                    detected_default_profile=cli_profile,
                    default_browser_context_id=default_ctx,
                    page_contexts=page_contexts,
                )
            if (last_used is not None and last_used != profile_dir_name) or (
                active_profiles and set(active_profiles) != {profile_dir_name}
            ):
                raise OwnerChromeSecondaryError(
                    "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH",
                    f"Chrome Local State active/last_used profile ({last_used!r} / {active_profiles!r}) "
                    f"disagrees with '{profile_dir_name}' despite launch flag",
                    expected_profile=profile_dir_name,
                    cli_profile=cli_profile,
                    last_used=last_used,
                    active_profiles=active_profiles,
                    default_browser_context_id=default_ctx,
                    page_contexts=page_contexts,
                )
            return {
                "default_browser_context_id": default_ctx,
                "page_contexts": page_contexts,
                "verified_by": "chrome_cmdline_single_profile_context",
            }

        observed_profile = active_profiles[0] if len(active_profiles) == 1 else last_used
        if observed_profile != profile_dir_name:
            raise OwnerChromeSecondaryError(
                "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH",
                f"Chrome default browser context could not be verified as '{profile_dir_name}' "
                f"(observed: {observed_profile!r})",
                expected_profile=profile_dir_name,
                detected_default_profile=observed_profile,
                default_browser_context_id=default_ctx,
                page_contexts=page_contexts,
            )
        return {
            "default_browser_context_id": default_ctx,
            "page_contexts": page_contexts,
            "verified_by": "local_state_single_active_profile",
        }

    def _ensure_connected(
        self,
        *,
        profile_dir_name: str,
        timeout_s: float = 5.0,
        info: dict[str, Any] | None = None,
        allow_reconnect_on_stale: bool = True,
    ) -> dict[str, Any]:
        resolved = dict(info) if info is not None else self._resolve_cdp_info(timeout_s=timeout_s)
        reused = self._connect_ws_classified(resolved, timeout_s=timeout_s)
        try:
            checked_info = self._verify_ws_browser_version(resolved, timeout_s=timeout_s, reused=reused)
            ctx_info = self._verify_profile_default_context(
                profile_dir_name=profile_dir_name,
                info=checked_info,
                timeout_s=timeout_s,
            )
        except OwnerChromeSecondaryError as exc:
            if reused and exc.code == "OWNER_CHROME_CDP_DISCONNECTED":
                self._cdp.reset()
                if not allow_reconnect_on_stale and resolved.get("approval_gated"):
                    raise self._approval_required_error(
                        resolved,
                        message=(
                            "previous Chrome remote debugging session closed; owner Chrome confirmation is required "
                            "to re-establish the connection"
                        ),
                    ) from None
                self._connect_ws_classified(resolved, timeout_s=timeout_s)
                try:
                    checked_info = self._verify_ws_browser_version(resolved, timeout_s=timeout_s, reused=False)
                    ctx_info = self._verify_profile_default_context(
                        profile_dir_name=profile_dir_name,
                        info=checked_info,
                        timeout_s=timeout_s,
                    )
                except Exception:
                    if not self._targets:
                        self._cdp.reset()
                    raise
            else:
                if not self._targets and not (reused and exc.code == "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH"):
                    self._cdp.reset()
                raise
        except Exception:
            if not self._targets:
                self._cdp.reset()
            raise
        merged = {**checked_info, **ctx_info, "profile_dir_name": profile_dir_name}
        self._verified_info = merged
        if merged.get("approval_gated"):
            # Only after browser identity and owner profile are verified.
            self._cdp.start_keepalive()
        return merged

    def preflight(
        self,
        *,
        profile_dir_name: str | None = None,
        timeout_s: float = 3.0,
        connect_ws: bool = False,
        allow_new_ws: bool = True,
    ) -> dict[str, Any]:
        """Read-only probe of owner Chrome hidden secondary target eligibility (consent-respecting on HTTP 404)."""
        t0 = time.monotonic()
        target_profile = validate_profile_dir_name(profile_dir_name or self.profile_dir_name)
        try:
            with self._lock:
                info = self._resolve_cdp_info(timeout_s=timeout_s)
                already_connected = self._cdp.connected() is True and self._cdp.endpoint == info["ws_url"]
                if info.get("approval_gated") and not already_connected and not connect_ws:
                    self._precheck_local_profile_mismatch(profile_dir_name=target_profile, info=info)
                    raise self._approval_required_error(
                        info,
                        message=(
                            "Chrome loopback CDP is active via DevToolsActivePort (HTTP /json/version returned 404, "
                            "approval-gated WebSocket-only mode); Chrome's native remote debugging confirmation dialog is "
                            "required when attaching (separate from Hub local standing policy `owner_chrome_hidden_secondary`)"
                        ),
                    )
                if not allow_new_ws and not already_connected:
                    self._precheck_local_profile_mismatch(profile_dir_name=target_profile, info=info)
                    raise OwnerChromeSecondaryError(
                        "OWNER_CHROME_CDP_NOT_CONNECTED",
                        "owner Chrome loopback CDP is not already connected; refusing to initiate a new connection in no-interruption mode",
                        cdp_discovered=True,
                        connected=False,
                        discovery_mode=info.get("discovery_mode"),
                        http_discovery_status=info.get("http_discovery_status"),
                        chrome_version=info.get("chrome_version"),
                        execution_started=False,
                        attempted=False,
                        retry_safe=True,
                    )
                verified = self._ensure_connected(
                    profile_dir_name=target_profile,
                    timeout_s=timeout_s,
                    info=info,
                    allow_reconnect_on_stale=(connect_ws or (allow_new_ws and not info.get("approval_gated"))),
                )
                if not self._targets and not verified.get("approval_gated") and allow_new_ws:
                    # Keep legacy HTTP-200 preflight stateless; preserve owner-approved WS-only sessions
                    # (and existing connected sessions under allow_new_ws=False) so subsequent calls
                    # reuse the already-connected Chrome session without re-prompting.
                    self._cdp.reset()
                connected_now = self._cdp.connected() is True
            return {
                "ok": True,
                "available": True,
                "connected": connected_now,
                "already_connected": already_connected,
                "cdp_discovered": True,
                "approval_required": False,
                "confirmation_required": False,
                "denied": False,
                "refused": False,
                "discovery_mode": verified.get("discovery_mode"),
                "http_discovery_status": verified.get("http_discovery_status"),
                "route": ROUTE_NAME,
                "profile_dir_name": target_profile,
                "chrome_version": verified["chrome_version"],
                "default_browser_context_id": verified["default_browser_context_id"],
                "profile_context_verified": True,
                "profile_verified_by": verified["verified_by"],
                "visible_side_effect_free": True,
                "hidden_target_supported": True,
                "screenshot_supported": False,
                "auth_inheritance": True,
                "profile_copied": False,
                "reason": (
                    "verified Chrome 158+ browser-level loopback CDP via DevToolsActivePort WebSocket (HTTP 404 mode)"
                    if verified.get("discovery_mode") == "devtools_active_port_ws_only"
                    else f"verified Chrome 158+ browser-level loopback CDP on {target_profile} default context"
                ),
                "error_code": None,
                "probe_ms": int((time.monotonic() - t0) * 1000),
            }
        except OwnerChromeSecondaryError as exc:
            with self._lock:
                if not self._targets and not (self._cdp.connected() is True and exc.code == "OWNER_CHROME_PROFILE_CONTEXT_MISMATCH"):
                    self._cdp.reset()
                connected_now = self._cdp.connected() is True
            details = dict(exc.details)
            return {
                "ok": False,
                "available": False,
                "connected": connected_now,
                "already_connected": False,
                "cdp_discovered": bool(details.get("cdp_discovered", False)),
                "approval_required": bool(details.get("approval_required", False)),
                "confirmation_required": bool(details.get("confirmation_required", False)),
                "denied": bool(details.get("denied", False)),
                "refused": bool(details.get("refused", False)),
                "discovery_mode": details.get("discovery_mode"),
                "http_discovery_status": details.get("http_discovery_status"),
                "chrome_version": details.get("chrome_version"),
                **({"consent_gate": details["consent_gate"]} if details.get("consent_gate") else {}),
                **({"hub_policy_separate": details["hub_policy_separate"]} if "hub_policy_separate" in details else {}),
                **({"remedy": details["remedy"]} if details.get("remedy") else {}),
                **({"automatic": details["automatic"]} if "automatic" in details else {}),
                "route": ROUTE_NAME,
                "profile_dir_name": target_profile,
                "profile_context_verified": False,
                "visible_side_effect_free": True,
                "hidden_target_supported": False,
                "screenshot_supported": False,
                "auth_inheritance": False,
                "profile_copied": False,
                "reason": exc.message,
                "error_code": exc.code,
                "details": details,
                "probe_ms": int((time.monotonic() - t0) * 1000),
            }

    def set_default_profile(self, profile_dir_name: str) -> str:
        """Update the default Chrome profile without resetting an approved CDP channel."""
        validated = validate_profile_dir_name(profile_dir_name)
        with self._lock:
            self.profile_dir_name = validated
        return validated

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "ok": True,
                "connected": self._cdp.connected(),
                "route": ROUTE_NAME,
                "profile_dir_name": self.profile_dir_name,
                "active_targets": len(self._targets),
                "owners": sorted({rec["owner"] for rec in self._targets.values()}),
                "chrome_version": self._verified_info.get("chrome_version") if self._verified_info else None,
                "discovery_mode": self._verified_info.get("discovery_mode") if self._verified_info else None,
                "default_browser_context_id": self._verified_info.get("default_browser_context_id") if self._verified_info else None,
                "visible_side_effect_free": True,
                "screenshot_supported": False,
                "cdp_handover_supported": os.name == "nt",
                **self._cdp.keepalive_status(),
            }

    def export_approved_cdp_socket(self, *, target_pid: int, target_create_time: int | None = None) -> dict[str, Any]:
        """Duplicate an ALREADY-APPROVED loopback CDP socket for a verified local target PID (Windows only).

        Never opens a new WebSocket or triggers Chrome consent; refuses if active targets exist.
        """
        if os.name != "nt":
            raise OwnerChromeSecondaryError("CDP_HANDOVER_WINDOWS_REQUIRED", "WinSock socket handover requires Windows")
        if type(target_pid) is not int or target_pid <= 0 or target_pid == os.getpid():
            raise OwnerChromeSecondaryError("CDP_HANDOVER_TARGET_INVALID", "invalid handover target PID")
        if target_create_time is not None and (
            type(target_create_time) is not int or not process_identity_matches(target_pid, target_create_time)
        ):
            raise OwnerChromeSecondaryError("CDP_HANDOVER_TARGET_INVALID", "target process identity mismatch")
        with self._lock:
            if self._targets:
                raise OwnerChromeSecondaryError(
                    "CDP_HANDOVER_TARGETS_ACTIVE",
                    "close active hidden targets before handing over the CDP socket",
                    active_targets=len(self._targets),
                )
            with self._cdp._lock:
                ws = self._cdp.socket
                if ws is None or not self._cdp.endpoint or not self._verified_info:
                    raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_DISCONNECTED", "no approved CDP socket to hand over")
                if getattr(ws, "frame_dirty", False):
                    raise OwnerChromeSecondaryError("CDP_HANDOVER_STREAM_DIRTY", "CDP stream is mid-frame; refusing handover")
                raw_sock = getattr(ws, "sock", None)
                if not isinstance(raw_sock, socket.socket):
                    raise OwnerChromeSecondaryError("CDP_HANDOVER_SOCKET_INVALID", "underlying WinSock socket unavailable")
                self._cdp.stop_keepalive()
                try:
                    peer = raw_sock.getpeername()
                    if not isinstance(peer, tuple) or len(peer) < 2 or peer[0] not in {"127.0.0.1", "::1"}:
                        raise OwnerChromeSecondaryError("CDP_HANDOVER_SOCKET_INVALID", "CDP peer is not loopback")
                    # Verify the existing approved socket is still live before duplicating it.
                    self._cdp.send("Browser.getVersion", {}, timeout=2.5)
                    share_bytes = raw_sock.share(target_pid)
                    buffered = ws.buffered_bytes() if hasattr(ws, "buffered_bytes") else b""
                    return {
                        "schema": "ff-cdp-socket-handover-v1",
                        "source_pid": os.getpid(),
                        "source_create_time": process_creation_token(os.getpid()),
                        "socket_share_b64": base64.b64encode(share_bytes).decode("ascii"),
                        "buffered_b64": base64.b64encode(buffered).decode("ascii"),
                        "seq": int(self._cdp.seq),
                        "endpoint": str(self._cdp.endpoint),
                        "verified_info": dict(self._verified_info),
                    }
                except Exception:
                    if self._cdp.connected() and self._verified_info and self._verified_info.get("approval_gated"):
                        self._cdp.start_keepalive()
                    raise

    def commit_cdp_handover(self) -> dict[str, Any]:
        """Release this process's duplicate handle after the peer verified adoption."""
        with self._lock:
            if self._targets:
                raise OwnerChromeSecondaryError("CDP_HANDOVER_TARGETS_ACTIVE", "cannot commit handover with active targets")
            self._cdp.reset()
            self._verified_info = None
            return {"committed": True, "connected": False}

    def abort_cdp_handover(self) -> dict[str, Any]:
        """Resume keepalive if a planned handover did not complete."""
        with self._lock:
            if self._cdp.connected() and self._verified_info and self._verified_info.get("approval_gated"):
                self._cdp.start_keepalive()
            return {"aborted": True, "connected": self._cdp.connected(), **self._cdp.keepalive_status()}

    def adopt_approved_cdp_socket(self, payload: dict[str, Any], *, profile_dir_name: str | None = None) -> dict[str, Any]:
        """Adopt a duplicated ALREADY-APPROVED loopback CDP socket from a verified local Hub process."""
        if os.name != "nt":
            raise OwnerChromeSecondaryError("CDP_HANDOVER_WINDOWS_REQUIRED", "WinSock socket handover requires Windows")
        if not isinstance(payload, dict) or payload.get("schema") != "ff-cdp-socket-handover-v1":
            raise OwnerChromeSecondaryError("CDP_HANDOVER_PAYLOAD_INVALID", "invalid handover payload schema")
        src_pid = payload.get("source_pid")
        src_ctime = payload.get("source_create_time")
        if (
            type(src_pid) is not int
            or src_pid <= 0
            or src_pid == os.getpid()
            or type(src_ctime) is not int
            or not process_identity_matches(src_pid, src_ctime)
        ):
            raise OwnerChromeSecondaryError("CDP_HANDOVER_SOURCE_INVALID", "unverified handover source process")
        raw_share_b64 = payload.get("socket_share_b64")
        raw_buf_b64 = payload.get("buffered_b64", "")
        raw_endpoint = payload.get("endpoint")
        raw_seq = payload.get("seq", 0)
        raw_info = payload.get("verified_info")
        if (
            not isinstance(raw_share_b64, str)
            or not raw_share_b64
            or not isinstance(raw_buf_b64, str)
            or not isinstance(raw_endpoint, str)
            or type(raw_seq) is not int
            or raw_seq < 0
            or not isinstance(raw_info, dict)
        ):
            raise OwnerChromeSecondaryError("CDP_HANDOVER_PAYLOAD_INVALID", "malformed handover payload fields")

        ep_port, ep_path, valid_ws_url = _validate_loopback_ws_url(raw_endpoint)
        target_profile = validate_profile_dir_name(
            profile_dir_name or raw_info.get("profile_dir_name") or self.profile_dir_name
        )
        try:
            share_bytes = base64.b64decode(raw_share_b64, validate=True)
            buffered = base64.b64decode(raw_buf_b64, validate=True) if raw_buf_b64 else b""
        except ValueError:
            raise OwnerChromeSecondaryError("CDP_HANDOVER_SOCKET_INVALID", "invalid base64 socket descriptor") from None

        with self._lock:
            if self._targets:
                raise OwnerChromeSecondaryError("CDP_HANDOVER_TARGETS_ACTIVE", "cannot adopt while targets are active")
            if self._cdp.connected():
                raise OwnerChromeSecondaryError("CDP_HANDOVER_ALREADY_CONNECTED", "CDP socket already connected")
            adopted_sock: socket.socket | None = None
            try:
                adopted_sock = socket.fromshare(share_bytes)
                if adopted_sock.type != socket.SOCK_STREAM:
                    raise OwnerChromeSecondaryError("CDP_HANDOVER_SOCKET_INVALID", "adopted socket is not TCP")
                peer = adopted_sock.getpeername()
                if (
                    not isinstance(peer, tuple)
                    or len(peer) < 2
                    or peer[0] not in {"127.0.0.1", "::1"}
                    or int(peer[1]) != ep_port
                ):
                    raise OwnerChromeSecondaryError("CDP_HANDOVER_SOCKET_INVALID", "adopted socket peer mismatch")
            except OwnerChromeSecondaryError:
                if adopted_sock is not None:
                    try:
                        adopted_sock.close()
                    except OSError:
                        pass
                raise
            except Exception as exc:
                if adopted_sock is not None:
                    try:
                        adopted_sock.close()
                    except OSError:
                        pass
                raise OwnerChromeSecondaryError(
                    "CDP_HANDOVER_SOCKET_INVALID",
                    "failed to restore duplicated WinSock descriptor",
                    cause=type(exc).__name__,
                ) from None

            ws = _LocalWebSocket.from_adopted_socket(adopted_sock, buffered=buffered, timeout=5.0)
            self._cdp.adopt(ws, valid_ws_url, seq=raw_seq)
            try:
                info = {
                    "port": ep_port,
                    "ws_path": ep_path,
                    "ws_url": valid_ws_url,
                    "browser": None,
                    "chrome_version": raw_info.get("chrome_version"),
                    "pid": raw_info.get("pid") or _find_listener_pid_for_port(ep_port, hint_pid=self.chrome_pid),
                    "discovery_mode": raw_info.get("discovery_mode") or "devtools_active_port_ws_only",
                    "http_discovery_status": raw_info.get("http_discovery_status", 404),
                    "approval_gated": bool(raw_info.get("approval_gated", True)),
                }
                checked_info = self._verify_ws_browser_version(info, timeout_s=5.0, reused=True)
                ctx_info = self._verify_profile_default_context(
                    profile_dir_name=target_profile,
                    info=checked_info,
                    timeout_s=5.0,
                )
            except Exception:
                self._cdp.reset()
                raise
            merged = {**checked_info, **ctx_info, "profile_dir_name": target_profile}
            self._verified_info = merged
            self.profile_dir_name = target_profile
            if merged.get("approval_gated"):
                self._cdp.start_keepalive()
            return {
                "adopted": True,
                "connected": True,
                "route": ROUTE_NAME,
                "profile_dir_name": target_profile,
                "chrome_version": merged["chrome_version"],
                "default_browser_context_id": merged["default_browser_context_id"],
                "discovery_mode": merged["discovery_mode"],
                **self._cdp.keepalive_status(),
            }

    def _require_target(self, owner: str, tab_or_target_id: Any) -> dict[str, Any]:
        key = str(tab_or_target_id or "")
        rec = self._targets.get(key)
        if rec is None:
            for item in self._targets.values():
                if item["target_id"] == key:
                    rec = item
                    break
        if rec is None:
            raise OwnerChromeSecondaryError("TARGET_NOT_FOUND", "no such hidden secondary target", tab_id=tab_or_target_id)
        if rec["owner"] != owner:
            raise OwnerChromeSecondaryError("TARGET_NOT_OWNED", "target belongs to another agent/task", tab_id=tab_or_target_id)
        return rec

    def _eval(self, rec: dict[str, Any], expression: str, timeout_s: float = 10.0) -> Any:
        res = self._cdp.send(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": True},
            session_id=rec["session_id"],
            timeout=timeout_s,
        )
        if "exceptionDetails" in res:
            raise OwnerChromeSecondaryError("SCRIPT_FAILED", "page script threw an exception", attempted=True, retry_safe=False)
        return res.get("result", {}).get("value")

    def _describe(self, rec: dict[str, Any]) -> dict[str, Any]:
        return {
            "tab_id": rec["tab_id"],
            "target_id": rec["target_id"],
            "url": rec["url"],
            "title": rec["title"],
            "state": "live",
            "hidden": True,
            "windowless": True,
            "route": ROUTE_NAME,
            "profile_dir_name": rec["profile_dir_name"],
        }

    def _check_expected_host(self, rec: dict[str, Any], expected_host: Any) -> None:
        if expected_host is None:
            return
        want = str(expected_host).strip().lower().rstrip(".")
        res = self._eval(rec, "({url:location.href})", timeout_s=3.0)
        actual_url = str(res.get("url") or "") if isinstance(res, dict) else ""
        try:
            actual = (urllib.parse.urlsplit(actual_url).hostname or "").lower().rstrip(".")
        except ValueError:
            actual = ""
        if actual != want:
            raise OwnerChromeSecondaryError(
                "TAB_HOST_CHANGED",
                "the live hidden target changed host; authorize its current address before acting",
                expected_host=want,
                actual_host=actual,
                attempted=False,
                retry_safe=False,
            )

    def _check_postcondition(self, rec: dict[str, Any], condition: dict[str, Any], timeout_s: float = 8.0) -> bool:
        if not isinstance(condition, dict):
            raise OwnerChromeSecondaryError("POSTCONDITION_REQUIRED", "postcondition dict is required", attempted=False)
        deadline = time.monotonic() + min(max(float(timeout_s), 0.2), 30.0)

        def eval_once() -> bool:
            ctype = condition.get("type")
            if ctype == "text_includes" and isinstance(condition.get("value"), str):
                return self._eval(rec, f"(document.body?.innerText||'').includes({json.dumps(condition['value'])})") is True
            if ctype == "url_equals" and isinstance(condition.get("value"), str):
                return self._eval(rec, f"location.href==={json.dumps(condition['value'])}") is True
            if ctype == "url_contains" and isinstance(condition.get("value"), str):
                return self._eval(rec, f"location.href.includes({json.dumps(condition['value'])})") is True
            if ctype == "value_equals" and isinstance(condition.get("selector"), str) and isinstance(condition.get("value"), str):
                expr = (
                    f"(()=>{{const n=document.querySelectorAll({json.dumps(condition['selector'])});"
                    f"return n.length===1&&String(n[0].value??'')==={json.dumps(condition['value'])};}})()"
                )
                return self._eval(rec, expr) is True
            if ctype == "checked_equals" and isinstance(condition.get("selector"), str) and type(condition.get("checked")) is bool:
                expr = (
                    f"(()=>{{const n=document.querySelectorAll({json.dumps(condition['selector'])});"
                    f"return n.length===1&&Boolean(n[0].checked)==={json.dumps(condition['checked'])};}})()"
                )
                return self._eval(rec, expr) is True
            if isinstance(condition.get("text_present"), str):
                return self._eval(rec, f"(document.body?.innerText||'').includes({json.dumps(condition['text_present'])})") is True
            if isinstance(condition.get("text_absent"), str):
                return self._eval(rec, f"!(document.body?.innerText||'').includes({json.dumps(condition['text_absent'])})") is True
            if isinstance(condition.get("url_contains"), str):
                return self._eval(rec, f"location.href.includes({json.dumps(condition['url_contains'])})") is True
            if isinstance(condition.get("target"), dict) and isinstance(condition["target"].get("selector"), str):
                sel = condition["target"]["selector"]
                if condition.get("state") == "absent":
                    return self._eval(rec, f"document.querySelectorAll({json.dumps(sel)}).length===0") is True
                if isinstance(condition.get("value"), str):
                    expr = (
                        f"(()=>{{const n=document.querySelectorAll({json.dumps(sel)});"
                        f"return n.length===1&&String(n[0].value??'')==={json.dumps(condition['value'])};}})()"
                    )
                    return self._eval(rec, expr) is True
                if type(condition.get("checked")) is bool:
                    expr = (
                        f"(()=>{{const n=document.querySelectorAll({json.dumps(sel)});"
                        f"return n.length===1&&Boolean(n[0].checked)==={json.dumps(condition['checked'])};}})()"
                    )
                    return self._eval(rec, expr) is True
                return self._eval(rec, f"document.querySelectorAll({json.dumps(sel)}).length===1") is True
            raise OwnerChromeSecondaryError("POSTCONDITION_INVALID", "unsupported postcondition format", attempted=False)

        while True:
            try:
                if eval_once():
                    return True
            except OwnerChromeSecondaryError as exc:
                if exc.code not in {"SCRIPT_FAILED", "OWNER_CHROME_CDP_REJECTED"}:
                    raise
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.1)

    def _close_single_target(self, rec: dict[str, Any], *, timeout_s: float = 5.0) -> dict[str, Any]:
        target_id = rec["target_id"]
        tab_id = rec["tab_id"]
        closed_in_browser = False
        error_code = None
        try:
            res = self._cdp.send("Target.closeTarget", {"targetId": target_id}, timeout=timeout_s)
            if res.get("success") is True:
                # Chromium returns success as soon as teardown begins; poll boundedly
                # for target removal before declaring TARGET_CLEANUP_UNCONFIRMED.
                verify_deadline = time.monotonic() + min(max(float(timeout_s), 0.2), 2.5)
                while True:
                    remaining = max(0.2, verify_deadline - time.monotonic())
                    targets = self._cdp.send("Target.getTargets", {}, timeout=min(timeout_s, remaining)).get("targetInfos") or []
                    if all(t.get("targetId") != target_id for t in targets):
                        closed_in_browser = True
                        break
                    if time.monotonic() >= verify_deadline:
                        break
                    time.sleep(0.05)
            if not closed_in_browser:
                error_code = "TARGET_CLEANUP_UNCONFIRMED"
        except OwnerChromeSecondaryError as exc:
            error_code = exc.code
            closed_in_browser = False

        if closed_in_browser:
            self._targets.pop(tab_id, None)
        return {
            "closed": closed_in_browser,
            "tab_id": tab_id,
            "target_id": target_id,
            "target_closed_in_browser": closed_in_browser,
            "primary_window_untouched": True,
            "route": ROUTE_NAME,
            **({"error_code": error_code} if error_code else {}),
        }

    def call(self, op: str, args: dict[str, Any] | None = None, *, timeout: float = 30.0) -> dict[str, Any]:
        args = dict(args or {})
        if op == "preflight":
            return self.preflight(
                profile_dir_name=args.get("profile_dir_name"),
                timeout_s=min(timeout, 5.0),
                connect_ws=bool(args.get("connect_ws", False)),
                allow_new_ws=bool(args.get("allow_new_ws", True)),
            )
        if op == "status":
            return self.status()
        if op == "shutdown":
            return self.shutdown(close_targets=args.get("close_targets", True))

        with self._lock:
            if self._stopping:
                raise OwnerChromeSecondaryError("MANAGER_SHUTTING_DOWN", "manager is shutting down")
            owner = str(args.get("owner") or "")
            if not owner:
                raise OwnerChromeSecondaryError("OWNER_REQUIRED", "owner identity is required", attempted=False)

            if op == "open":
                if args.get("spawn_new_process") is True:
                    reject_second_chrome_process_same_profile(
                        self.user_data_dir or _default_owner_user_data_dir() or "owner-user-data",
                        str(args.get("profile_dir_name") or self.profile_dir_name),
                    )
                if args.get("copy_profile") is True:
                    raise OwnerChromeSecondaryError(
                        "OWNER_PROFILE_COPY_FORBIDDEN",
                        "copying owner Chrome profile/cookie files is strictly forbidden",
                        attempted=False,
                    )
                if args.get("foreground") is True:
                    raise OwnerChromeSecondaryError(
                        "FOREGROUND_ROUTE_REQUIRED",
                        "owner Chrome hidden secondary route never uses foreground input",
                        attempted=False,
                    )
                if args.get("new_window") is True:
                    raise OwnerChromeSecondaryError(
                        "OWNER_CHROME_NEW_WINDOW_HIDDEN_UNSUPPORTED",
                        "Chrome 158 rejects Target.createTarget({newWindow: true, hidden: true}) and visible/minimized "
                        "secondary windows cause Win32 taskbar/focus side effects",
                        attempted=False,
                    )
                if args.get("window_state") is not None:
                    raise OwnerChromeSecondaryError(
                        "OWNER_CHROME_MINIMIZED_VISIBLE_SIDE_EFFECT_FORBIDDEN",
                        "windowState (including minimized) creates a visible taskbar HWND side effect",
                        attempted=False,
                    )
                profile_dir = validate_profile_dir_name(args.get("profile_dir_name") or self.profile_dir_name)
                url = valid_url(args.get("url"))
                if sum(1 for r in self._targets.values() if r["owner"] == owner) >= MAX_TARGETS_PER_OWNER:
                    raise OwnerChromeSecondaryError("TARGET_LIMIT_OWNER", "owner reached max hidden targets", attempted=False)
                if len(self._targets) >= MAX_TARGETS_TOTAL:
                    raise OwnerChromeSecondaryError("TARGET_LIMIT_TOTAL", "global hidden target pool full", attempted=False)

                verified = self._ensure_connected(profile_dir_name=profile_dir, timeout_s=min(timeout, 10.0))
                created = self._cdp.send("Target.createTarget", {"url": "about:blank", "hidden": True}, timeout=min(timeout, 10.0))
                target_id = created.get("targetId")
                if not isinstance(target_id, str) or not target_id:
                    raise OwnerChromeSecondaryError("HIDDEN_TARGET_CREATE_FAILED", "Chrome did not return targetId")

                # Verify target has NO OS browser window attached (zero visible side effect proof).
                window_attached = False
                try:
                    self._cdp.send("Browser.getWindowForTarget", {"targetId": target_id}, timeout=2.0)
                    window_attached = True
                except OwnerChromeSecondaryError:
                    window_attached = False
                if window_attached:
                    try:
                        self._cdp.send("Target.closeTarget", {"targetId": target_id}, timeout=3.0)
                    except Exception:
                        pass
                    raise OwnerChromeSecondaryError(
                        "OWNER_CHROME_HIDDEN_TARGET_WINDOW_LEAK",
                        "hidden target unexpectedly attached to a browser window; closed fail-closed",
                    )

                tab_id = "hsec-" + secrets.token_hex(8)
                try:
                    attached = self._cdp.send(
                        "Target.attachToTarget",
                        {"targetId": target_id, "flatten": True},
                        timeout=min(timeout, 10.0),
                    )
                    session_id = attached.get("sessionId")
                    if not isinstance(session_id, str) or not session_id:
                        raise OwnerChromeSecondaryError("HIDDEN_TARGET_ATTACH_FAILED", "missing sessionId")

                    vp = args.get("viewport")
                    width = int(vp.get("width", self.viewport[0])) if isinstance(vp, dict) else self.viewport[0]
                    height = int(vp.get("height", self.viewport[1])) if isinstance(vp, dict) else self.viewport[1]
                    width = min(max(width, 320), 3840)
                    height = min(max(height, 240), 2160)
                    self._cdp.send(
                        "Emulation.setDeviceMetricsOverride",
                        {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": False},
                        session_id=session_id,
                        timeout=5.0,
                    )
                    rec = {
                        "tab_id": tab_id,
                        "target_id": target_id,
                        "session_id": session_id,
                        "owner": owner,
                        "profile_dir_name": profile_dir,
                        "default_browser_context_id": verified["default_browser_context_id"],
                        "url": "about:blank",
                        "title": "",
                        "snapshot": None,
                        "viewport": {"width": width, "height": height},
                        "created_at": time.time(),
                    }
                    if url != "about:blank":
                        nav = self._cdp.send("Page.navigate", {"url": url}, session_id=session_id, timeout=min(timeout, 15.0))
                        if nav.get("errorText"):
                            raise OwnerChromeSecondaryError(
                                "NAVIGATION_FAILED",
                                str(nav["errorText"]),
                                attempted=True,
                                retry_safe=False,
                            )
                        open_wait_s = min(
                            max(float(args.get("timeout_ms", 10000)) / 1000.0, 0.2),
                            min(timeout, 25.0),
                        )
                        dl = time.monotonic() + open_wait_s
                        while time.monotonic() < dl:
                            try:
                                ready = self._eval(rec, "({rs:document.readyState, url:location.href, title:document.title})", timeout_s=3.0)
                            except OwnerChromeSecondaryError as exc:
                                if exc.code in {"SCRIPT_FAILED", "OWNER_CHROME_CDP_REJECTED"}:
                                    time.sleep(0.05)
                                    continue
                                raise
                            if isinstance(ready, dict) and ready.get("url") and ready["url"] != "about:blank":
                                rec["url"] = str(ready["url"])
                                rec["title"] = str(ready.get("title") or "")
                                if ready.get("rs") in {"interactive", "complete"}:
                                    break
                            time.sleep(0.05)
                    self._targets[tab_id] = rec
                    return {
                        "tab_id": tab_id,
                        "target_id": target_id,
                        "route": ROUTE_NAME,
                        "profile_dir_name": profile_dir,
                        "default_browser_context_id": verified["default_browser_context_id"],
                        "chrome_version": verified["chrome_version"],
                        "auth_inherited": True,
                        "profile_copied": False,
                        "hidden": True,
                        "windowless": True,
                        "visible_window_created": False,
                        "taskbar_window_created": False,
                        "owner_tab_strip_modified": False,
                        "physical_input_used": False,
                        "screenshot_supported": False,
                        "url": rec["url"],
                        "title": rec["title"],
                        "viewport": dict(rec["viewport"]),
                    }
                except Exception:
                    try:
                        self._cdp.send("Target.closeTarget", {"targetId": target_id}, timeout=3.0)
                    except Exception:
                        pass
                    raise

            if op == "list":
                mine = [self._describe(rec) for rec in self._targets.values() if rec["owner"] == owner]
                return {"tabs": mine, "route": ROUTE_NAME}

            if op == "close_owner":
                forget_unconfirmed = bool(args.get("forget_unconfirmed", False))
                owned = [rec for rec in list(self._targets.values()) if rec["owner"] == owner]
                closed_count = 0
                unconfirmed: list[str] = []
                errors: list[dict[str, Any]] = []
                results: list[dict[str, Any]] = []
                for rec in owned:
                    res = self._close_single_target(rec, timeout_s=min(timeout, 5.0))
                    results.append(res)
                    if res["target_closed_in_browser"]:
                        closed_count += 1
                    else:
                        if forget_unconfirmed:
                            self._targets.pop(rec["tab_id"], None)
                        unconfirmed.append(rec["tab_id"])
                        errors.append({
                            "tab_id": rec["tab_id"],
                            "target_id": rec["target_id"],
                            "code": res.get("error_code") or "TARGET_CLEANUP_UNCONFIRMED",
                        })
                return {
                    "closed": closed_count,
                    "unconfirmed": unconfirmed,
                    "errors": errors,
                    "results": results,
                    "primary_window_untouched": True,
                }

            rec = self._require_target(owner, args.get("tab_id") or args.get("target_id"))

            if op == "close":
                res = self._close_single_target(rec, timeout_s=min(timeout, 5.0))
                if not res["target_closed_in_browser"]:
                    raise OwnerChromeSecondaryError(
                        res.get("error_code") or "TARGET_CLEANUP_UNCONFIRMED",
                        "could not verify hidden secondary target closure",
                        tab_id=rec["tab_id"],
                        target_id=rec["target_id"],
                        target_closed_in_browser=False,
                        retry_safe=False,
                    )
                return res

            if op == "screenshot":
                raise OwnerChromeSecondaryError(
                    "HIDDEN_TARGET_SCREENSHOT_UNSUPPORTED",
                    "windowless Chrome 158 hidden targets have no OS compositor frame; "
                    "use DOM observe/read/evaluate rather than opening a visible window",
                    tab_id=rec["tab_id"],
                    target_id=rec["target_id"],
                    attempted=False,
                )

            if op == "navigate":
                url = valid_url(args.get("url"))
                prev_url = str(rec.get("url") or "")
                nav_token = uuid.uuid4().hex
                try:
                    self._eval(rec, f"(()=>{{window.__ffhsec_nav={json.dumps(nav_token)};return true;}})()", timeout_s=2.0)
                except OwnerChromeSecondaryError as exc:
                    if exc.code not in {"SCRIPT_FAILED", "OWNER_CHROME_CDP_REJECTED"}:
                        raise
                prev_parts = urllib.parse.urlsplit(prev_url)
                next_parts = urllib.parse.urlsplit(url)
                same_doc_fragment = (
                    prev_parts[:4] == next_parts[:4]
                    and prev_parts.fragment != next_parts.fragment
                )
                nav = self._cdp.send("Page.navigate", {"url": url}, session_id=rec["session_id"], timeout=min(timeout, 15.0))
                rec["snapshot"] = None
                if nav.get("errorText"):
                    raise OwnerChromeSecondaryError("NAVIGATION_FAILED", str(nav["errorText"]), attempted=True, retry_safe=False)
                dl = time.monotonic() + min(max(float(args.get("timeout_ms", 10000)) / 1000.0, 0.5), 25.0)
                last_ready: dict[str, Any] | None = None
                while time.monotonic() < dl:
                    try:
                        ready = self._eval(
                            rec,
                            f"({{rs:document.readyState, url:location.href, title:document.title, navigated:window.__ffhsec_nav!=={json.dumps(nav_token)}}})",
                            timeout_s=3.0,
                        )
                    except OwnerChromeSecondaryError as exc:
                        if exc.code in {"SCRIPT_FAILED", "OWNER_CHROME_CDP_REJECTED"}:
                            time.sleep(0.05)
                            continue
                        raise
                    if isinstance(ready, dict):
                        last_ready = ready
                        cur_url = str(ready.get("url") or "")
                        marker_cleared = ready.get("navigated")
                        committed = (
                            marker_cleared is True
                            or marker_cleared is None
                            or (same_doc_fragment and cur_url == url)
                        )
                        if committed and ready.get("rs") in {"interactive", "complete"}:
                            rec["url"] = cur_url or url
                            rec["title"] = str(ready.get("title") or "")
                            break
                    time.sleep(0.05)
                else:
                    if isinstance(last_ready, dict) and last_ready.get("url"):
                        rec["url"] = str(last_ready["url"])
                        rec["title"] = str(last_ready.get("title") or "")
                return {"tab_id": rec["tab_id"], "target_id": rec["target_id"], "url": rec["url"], "title": rec["title"], "navigated": True}

            if op == "reload":
                self._check_expected_host(rec, args.get("expected_host"))
                reload_token = uuid.uuid4().hex
                self._eval(rec, f"(()=>{{window.__ffhsec_reload={json.dumps(reload_token)};return true;}})()", timeout_s=3.0)
                self._cdp.send(
                    "Page.reload",
                    {"ignoreCache": bool(args.get("ignore_cache", False))},
                    session_id=rec["session_id"],
                    timeout=min(timeout, 15.0),
                )
                rec["snapshot"] = None
                dl = time.monotonic() + min(max(float(args.get("timeout_ms", 10000)) / 1000.0, 1.0), 30.0)
                reloaded = False
                while time.monotonic() < dl:
                    try:
                        ready = self._eval(
                            rec,
                            f"({{rs:document.readyState,url:location.href,title:document.title,reloaded:window.__ffhsec_reload!=={json.dumps(reload_token)}}})",
                            timeout_s=3.0,
                        )
                    except OwnerChromeSecondaryError as exc:
                        if exc.code in {"SCRIPT_FAILED", "OWNER_CHROME_CDP_REJECTED"}:
                            time.sleep(0.05)
                            continue
                        raise
                    if isinstance(ready, dict) and ready.get("reloaded") is True and ready.get("rs") in {"interactive", "complete"}:
                        rec["url"] = str(ready.get("url") or rec["url"])
                        rec["title"] = str(ready.get("title") or "")
                        reloaded = True
                        break
                    time.sleep(0.05)
                if not reloaded:
                    raise OwnerChromeSecondaryError("NAVIGATION_FAILED", "reload did not complete", attempted=True, retry_safe=False)
                return {
                    "tab_id": rec["tab_id"],
                    "target_id": rec["target_id"],
                    "url": rec["url"],
                    "title": rec["title"],
                    "reloaded": True,
                    "physical_input_used": False,
                    "route": ROUTE_NAME,
                }

            if op == "wait_for":
                self._check_expected_host(rec, args.get("expected_host"))
                condition = args.get("condition")
                t_s = min(max(float(args.get("timeout_ms", 5000)) / 1000.0, 0.2), 30.0)
                ok = self._check_postcondition(rec, condition, timeout_s=t_s)
                if not ok:
                    raise OwnerChromeSecondaryError("WAIT_TIMEOUT", "the condition did not become true", retry_safe=True)
                return {
                    "tab_id": rec["tab_id"],
                    "target_id": rec["target_id"],
                    "satisfied": True,
                    "url": rec["url"],
                    "route": ROUTE_NAME,
                }

            if op == "observe":
                token = uuid.uuid4().hex
                script = (
                    "(()=>{const nodes=[...document.querySelectorAll('input,textarea,button,select,a,[role=button],[contenteditable=true]')]"
                    ".filter(e=>e.getClientRects().length).slice(0,128);"
                    f"window.__ffhsec={{token:{json.dumps(token)},nodes}};"
                    "return {url:location.href,title:document.title,text:(document.body?.innerText||'').slice(0,16000),"
                    "controls:nodes.map((e,i)=>({ref:String(i),tag:e.tagName.toLowerCase(),type:e.type||'',id:e.id,"
                    "name:e.getAttribute('aria-label')||e.labels?.[0]?.innerText||e.innerText||e.name||'',"
                    "value:e.isContentEditable?(e.textContent??''):(e.value??null),"
                    "checked:(e.type==='checkbox'||e.type==='radio')?!!e.checked:null,"
                    "selected_text:e.tagName==='SELECT'?(e.selectedOptions?.[0]?.textContent?.trim()??null):null,"
                    "readonly:!!e.readOnly,disabled:!!e.disabled}))}})()"
                )
                data = self._eval(rec, script, timeout_s=min(timeout, 10.0))
                rec["snapshot"] = token
                rec["url"] = str(data.get("url") or rec["url"])
                rec["title"] = str(data.get("title") or rec["title"])
                return {**data, "snapshot": token, "tab_id": rec["tab_id"], "target_id": rec["target_id"], "route": ROUTE_NAME}

            if op == "read":
                limit = min(max(int(args.get("max_chars", 32000)), 256), 200000)
                selector = args.get("selector")
                if not selector and isinstance(args.get("target"), dict) and isinstance(args["target"].get("selector"), str):
                    selector = args["target"]["selector"]
                if isinstance(selector, str) and selector:
                    expr = (
                        f"(()=>{{const e=document.querySelector({json.dumps(selector)});"
                        "if(!e)return {url:location.href,title:document.title,text:''};"
                        "const tag=String(e.tagName||'').toUpperCase();"
                        "const typ=String(e.type||'').toLowerCase();"
                        "if(tag==='INPUT'||tag==='TEXTAREA'){"
                        "const chk=tag==='INPUT'&&(typ==='checkbox'||typ==='radio');"
                        "return {url:location.href,title:document.title,text:chk?(e.checked?'checked':'unchecked'):String(e.value??''),"
                        "value:String(e.value??''),...(chk?{checked:Boolean(e.checked)}:{})};}"
                        "if(tag==='SELECT'){"
                        "return {url:location.href,title:document.title,text:String(e.value??''),value:String(e.value??''),"
                        "selected:[...(e.selectedOptions||[])].map(o=>o.value)};}"
                        "return {url:location.href,title:document.title,text:(e.innerText??e.textContent??'')};})()"
                    )
                else:
                    expr = "({url:location.href,title:document.title,text:(document.body?.innerText||'')})"
                data = self._eval(rec, expr, timeout_s=min(timeout, 10.0))
                text = str(data.get("text") or "")
                rec["url"] = str(data.get("url") or rec["url"])
                rec["title"] = str(data.get("title") or rec["title"])
                extra = {k: data[k] for k in ("value", "checked", "selected") if k in data}
                return {
                    "tab_id": rec["tab_id"],
                    "target_id": rec["target_id"],
                    "url": rec["url"],
                    "title": rec["title"],
                    "text": text[:limit],
                    "truncated": len(text) > limit,
                    "route": ROUTE_NAME,
                    **extra,
                }

            if op == "act":
                if args.get("foreground") is True:
                    raise OwnerChromeSecondaryError("FOREGROUND_ROUTE_REQUIRED", "never falls back to foreground", attempted=False)
                self._check_expected_host(rec, args.get("expected_host"))
                operation = str(args.get("operation") or args.get("action") or "")
                if operation not in {"fill", "click", "select", "check", "uncheck", "press"}:
                    raise OwnerChromeSecondaryError("ACTION_INVALID", f"unsupported action: {operation}", attempted=False)
                raw_value = args.get("value")
                if operation == "select" and isinstance(raw_value, list):
                    select_values = [str(item) for item in raw_value]
                    if not select_values or sum(len(item) for item in select_values) > 16000:
                        raise OwnerChromeSecondaryError("ACTION_INVALID", "invalid select values", attempted=False)
                    value_payload: Any = select_values
                else:
                    value = str("" if raw_value is None else raw_value)
                    if len(value) > 16000:
                        raise OwnerChromeSecondaryError("ACTION_INVALID", "value too long", attempted=False)
                    value_payload = value
                key = args.get("key")
                if operation == "press" and (not isinstance(key, str) or not key or len(key) > 64):
                    raise OwnerChromeSecondaryError("KEY_REQUIRED", "press requires a non-empty key string", attempted=False)
                condition = args.get("postcondition")
                if condition is not None and not isinstance(condition, dict):
                    raise OwnerChromeSecondaryError("POSTCONDITION_INVALID", "postcondition must be a dict", attempted=False)

                target = args.get("target") if isinstance(args.get("target"), dict) else {}
                selector = args.get("selector")
                if not selector and isinstance(target.get("selector"), str):
                    selector = target["selector"]
                snap = args.get("snapshot")
                ref = args.get("ref") if args.get("ref") is not None else target.get("ref")
                target_id_attr = target.get("id")
                target_name_attr = target.get("name")
                target_label = target.get("label")

                has_explicit_target = bool(
                    selector or ref is not None or target_id_attr or target_name_attr or target_label
                )
                if operation == "press" and not has_explicit_target:
                    locate_js = "const e=document.activeElement||document.body;if(!e)return {error:'TARGET_NOT_FOUND'};"
                elif selector:
                    if not isinstance(selector, str) or len(selector) > 512:
                        raise OwnerChromeSecondaryError("TARGET_INVALID", "invalid selector", attempted=False)
                    locate_js = (
                        f"const nodes=document.querySelectorAll({json.dumps(selector)});"
                        "if(nodes.length===0)return {error:'TARGET_NOT_FOUND'};"
                        "if(nodes.length>1)return {error:'TARGET_AMBIGUOUS'};"
                        "const e=nodes[0];if(!e.isConnected)return {error:'TARGET_STALE'};"
                        "if(e.disabled)return {error:'TARGET_DISABLED'};"
                    )
                elif isinstance(target_id_attr, str) and target_id_attr:
                    locate_js = (
                        f"const e=document.getElementById({json.dumps(target_id_attr)});"
                        "if(!e)return {error:'TARGET_NOT_FOUND'};"
                        "if(e.disabled)return {error:'TARGET_DISABLED'};"
                    )
                elif isinstance(target_name_attr, str) and target_name_attr:
                    locate_js = (
                        f"const nodes=[...document.getElementsByName({json.dumps(target_name_attr)})];"
                        "if(nodes.length===0)return {error:'TARGET_NOT_FOUND'};"
                        "if(nodes.length>1)return {error:'TARGET_AMBIGUOUS'};"
                        "const e=nodes[0];if(e.disabled)return {error:'TARGET_DISABLED'};"
                    )
                elif isinstance(target_label, str) and target_label:
                    locate_js = (
                        f"const wantLabel={json.dumps(target_label.strip())};"
                        "const nodes=[...document.querySelectorAll('input,textarea,select,button,[contenteditable=true]')].filter(el=>{"
                        "const al=(el.getAttribute('aria-label')||'').trim();"
                        "const lt=[...(el.labels||[])].map(l=>(l.innerText||l.textContent||'').trim());"
                        "return al===wantLabel||lt.includes(wantLabel);});"
                        "if(nodes.length===0)return {error:'TARGET_NOT_FOUND'};"
                        "if(nodes.length>1)return {error:'TARGET_AMBIGUOUS'};"
                        "const e=nodes[0];if(e.disabled)return {error:'TARGET_DISABLED'};"
                    )
                else:
                    if not isinstance(snap, str) or rec.get("snapshot") != snap or not isinstance(ref, str) or not re.fullmatch(r"[0-9]{1,3}", ref):
                        raise OwnerChromeSecondaryError("TARGET_STALE", "stale snapshot or invalid ref", attempted=False)
                    locate_js = (
                        f"const s=window.__ffhsec;if(!s||s.token!=={json.dumps(snap)})return {{error:'TARGET_STALE'}};"
                        f"const e=s.nodes[{ref}];if(!e||!e.isConnected||e.disabled)return {{error:'TARGET_STALE'}};"
                    )

                expected_host = args.get("expected_host")
                host_guard_js = ""
                if expected_host is not None:
                    want_host = str(expected_host).strip().lower().rstrip(".")
                    host_guard_js = (
                        f"const curHost=(location.hostname||'').toLowerCase().replace(/\\.+$/,'');"
                        f"if(curHost!=={json.dumps(want_host)})return {{error:'TAB_HOST_CHANGED',actual_host:curHost}};"
                    )

                dom_click_js = (
                    "const box=e.getBoundingClientRect();"
                    "const init={bubbles:true,cancelable:true,composed:true,view:window,button:0,"
                    "clientX:box.left+box.width/2,clientY:box.top+box.height/2};"
                    "for(const [t,c] of [['pointerover','PointerEvent'],['mouseover','MouseEvent'],['pointerdown','PointerEvent'],['mousedown','MouseEvent']])"
                    "if(typeof window[c]==='function')e.dispatchEvent(new window[c](t,{...init,buttons:1}));"
                    "if(typeof e.focus==='function')e.focus({preventScroll:true});"
                    "for(const [t,c] of [['pointerup','PointerEvent'],['mouseup','MouseEvent']])"
                    "if(typeof window[c]==='function')e.dispatchEvent(new window[c](t,init));"
                    "e.click();"
                )

                action_js = {
                    "fill": (
                        "if(e.readOnly)return {error:'TARGET_NOT_EDITABLE'};"
                        "const tag=e.tagName;"
                        "const typ=String(e.type||'').toLowerCase();"
                        "const badInput=['button','submit','reset','image','checkbox','radio','file','hidden'].includes(typ);"
                        "if((tag==='INPUT'&&badInput)||(!['INPUT','TEXTAREA'].includes(tag)&&!e.isContentEditable))"
                        "return {error:'TARGET_NOT_EDITABLE'};"
                        "if(typeof e.focus==='function')e.focus({preventScroll:true});"
                        f"const val={json.dumps(value_payload)};"
                        "if(e.isContentEditable){e.textContent=val;}else{"
                        "const proto=tag==='TEXTAREA'?HTMLTextAreaElement.prototype:HTMLInputElement.prototype;"
                        "const setter=Object.getOwnPropertyDescriptor(proto,'value')?.set;"
                        "if(setter)setter.call(e,val);else e.value=val;}"
                        "const ie=typeof InputEvent==='function'?new InputEvent('input',{bubbles:true,composed:true,inputType:'insertText',data:val}):new Event('input',{bubbles:true,composed:true});"
                        "e.dispatchEvent(ie);e.dispatchEvent(new Event('change',{bubbles:true}));"
                        "const detail={mode:'dom-value-setter'};"
                    ),
                    "click": dom_click_js + "const detail={mode:'dom-click'};",
                    "select": (
                        "if(e.tagName!=='SELECT')return {error:'TARGET_NOT_SELECT'};"
                        f"const rawVals={json.dumps(value_payload)};"
                        "const wanted=Array.isArray(rawVals)?rawVals.map(String):[String(rawVals)];"
                        "if(!wanted.length||(!e.multiple&&wanted.length>1))return {error:'ACTION_INVALID'};"
                        "const opts=[...e.options];const matched=[];"
                        "for(const w of wanted){const opt=opts.find(o=>!o.disabled&&o.value===w)||opts.find(o=>!o.disabled&&String(o.textContent||'').trim()===w);"
                        "if(!opt)return {error:'OPTION_NOT_FOUND'};matched.push(opt);}"
                        "if(typeof e.focus==='function')e.focus({preventScroll:true});"
                        "if(e.multiple){const picked=new Set(matched);for(const o of opts)o.selected=picked.has(o);}"
                        "else{for(const o of opts)o.selected=(o===matched[0]);e.value=matched[0].value;}"
                        "e.dispatchEvent(new Event('input',{bubbles:true,composed:true}));"
                        "e.dispatchEvent(new Event('change',{bubbles:true}));"
                        "const detail={mode:'dom-select',selected:[...(e.selectedOptions||opts.filter(o=>o.selected))].map(o=>o.value)};"
                    ),
                    "check": (
                        "const tag=e.tagName;const typ=String(e.type||'').toLowerCase();"
                        "const role=String(e.getAttribute?.('role')||'').toLowerCase();"
                        "const isNative=tag==='INPUT'&&(typ==='checkbox'||typ==='radio');"
                        "const isAria=['checkbox','radio','switch'].includes(role);"
                        "if(!isNative&&!isAria)return {error:'TARGET_NOT_EDITABLE'};"
                        "const cur=isNative?Boolean(e.checked):e.getAttribute('aria-checked')==='true';"
                        "if(!cur){" + dom_click_js + "}"
                        "const after=isNative?Boolean(e.checked):e.getAttribute('aria-checked')==='true';"
                        "if(!after)return {error:'ACTION_NO_EFFECT',attempted:true};"
                        "const detail={mode:'dom-check',checked:true};"
                    ),
                    "uncheck": (
                        "const tag=e.tagName;const typ=String(e.type||'').toLowerCase();"
                        "const role=String(e.getAttribute?.('role')||'').toLowerCase();"
                        "if((tag==='INPUT'&&typ==='radio')||role==='radio')return {error:'TARGET_NOT_EDITABLE'};"
                        "const isNative=tag==='INPUT'&&typ==='checkbox';"
                        "const isAria=['checkbox','switch'].includes(role);"
                        "if(!isNative&&!isAria)return {error:'TARGET_NOT_EDITABLE'};"
                        "const cur=isNative?Boolean(e.checked):e.getAttribute('aria-checked')==='true';"
                        "if(cur){" + dom_click_js + "}"
                        "const after=isNative?Boolean(e.checked):e.getAttribute('aria-checked')==='true';"
                        "if(after)return {error:'ACTION_NO_EFFECT',attempted:true};"
                        "const detail={mode:'dom-check',checked:false};"
                    ),
                    "press": (
                        f"const k={json.dumps(key or '')};"
                        "const kinit={key:k,code:k.length===1?'Key'+k.toUpperCase():k,bubbles:true,cancelable:true,composed:true};"
                        "const proceed=e.dispatchEvent(new KeyboardEvent('keydown',kinit));"
                        "e.dispatchEvent(new KeyboardEvent('keyup',kinit));"
                        "let detail='dispatched';"
                        "if(!proceed){detail='prevented_by_page';}"
                        "else if(k==='Enter'&&e.tagName!=='TEXTAREA'&&e.form&&typeof e.form.requestSubmit==='function'){"
                        "const isSub=(e.tagName==='BUTTON'&&(e.type||'submit')==='submit')||(e.tagName==='INPUT'&&['submit','image'].includes(String(e.type||'').toLowerCase()));"
                        "if(isSub)e.form.requestSubmit(e);else e.form.requestSubmit();detail='form_submitted';}"
                    ),
                }[operation]
                url_before = rec["url"]
                rec["snapshot"] = None
                outcome = self._eval(
                    rec,
                    "(()=>{" + host_guard_js + locate_js + action_js + "return {acted:true,url:location.href,title:document.title,detail:detail};})()",
                    timeout_s=min(timeout, 10.0),
                )
                if not isinstance(outcome, dict) or outcome.get("error"):
                    err_code = str((outcome or {}).get("error") or "ACTION_FAILED")
                    was_attempted = bool((outcome or {}).get("attempted", False))
                    extra_err = {k: v for k, v in (outcome or {}).items() if k not in {"error", "attempted"}}
                    raise OwnerChromeSecondaryError(err_code, attempted=was_attempted, retry_safe=False, **extra_err)
                rec["url"] = str(outcome.get("url") or rec["url"])
                rec["title"] = str(outcome.get("title") or rec["title"])
                verified = True
                if condition is not None:
                    verified = self._check_postcondition(rec, condition, timeout_s=min(timeout, 8.0))
                    if not verified:
                        raise OwnerChromeSecondaryError("POSTCONDITION_FAILED", "postcondition not met", attempted=True, retry_safe=False)
                    try:
                        fresh = self._eval(rec, "({url:location.href,title:document.title})", timeout_s=2.0)
                        if isinstance(fresh, dict) and fresh.get("url"):
                            rec["url"] = str(fresh["url"])
                            rec["title"] = str(fresh.get("title") or rec["title"])
                    except OwnerChromeSecondaryError:
                        pass
                return {
                    "ok": True,
                    "acted": True,
                    "verified": verified,
                    "action": operation,
                    "detail": outcome.get("detail"),
                    "tab_id": rec["tab_id"],
                    "target_id": rec["target_id"],
                    "url": rec["url"],
                    "url_before": url_before,
                    "url_after": rec["url"],
                    "navigated": url_before != rec["url"],
                    "title": rec["title"],
                    "trusted_input": False,
                    "physical_input_used": False,
                    "route": ROUTE_NAME,
                }

            if op == "evaluate":
                self._check_expected_host(rec, args.get("expected_host"))
                expr = args.get("expression")
                if not isinstance(expr, str) or not expr or len(expr) > 32768:
                    raise OwnerChromeSecondaryError("SCRIPT_INVALID", "invalid expression", attempted=False)
                t_s = float(args.get("timeout_s", 10.0))
                if not 0 < t_s <= 15.0:
                    raise OwnerChromeSecondaryError("TIMEOUT_INVALID", "timeout_s must be in (0, 15]", attempted=False)
                val = self._eval(rec, expr, timeout_s=t_s)
                return {"tab_id": rec["tab_id"], "target_id": rec["target_id"], "value": val}

            raise OwnerChromeSecondaryError("OP_UNSUPPORTED", f"unsupported op: {op}", attempted=False)

    def shutdown(self, *, close_targets: bool = True) -> dict[str, Any]:
        with self._lock:
            self._stopping = True
            closed = 0
            unconfirmed: list[str] = []
            if close_targets:
                for rec in list(self._targets.values()):
                    res = self._close_single_target(rec, timeout_s=3.0)
                    if res["target_closed_in_browser"]:
                        closed += 1
                    else:
                        unconfirmed.append(rec["tab_id"])
            self._cdp.reset()
            return {"stopped": True, "closed": closed, "unconfirmed": unconfirmed, "primary_window_untouched": True}

    def stop(self) -> None:
        self.shutdown(close_targets=True)
