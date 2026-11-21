"""A fresh or persistent isolated Chrome process/profile on a private Windows desktop.

The worker owns the process through its kill-on-close Job. This module never
switches desktops, adopts an owner browser, touches owner Chrome User Data, or
weakens Chrome's sandbox.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import re
import subprocess
import time
from types import SimpleNamespace
import urllib.error
import urllib.parse
import urllib.request
import uuid

from cua_browser_profiles import (
    ManagedBrowserProfiles,
    PersistentBrowserProfile,
    ProfileIsolationError,
    assert_not_owner_browser_profile,
    is_owner_browser_profile_path,
    linked,
)
from cua_desktop_identity import desktop_identity
from cua_global_resources import process_is_same
from cua_programmatic_discovery import owned_tcp_listeners
from cua_sidecar_supervisor import _bind_windows_kill_on_close_job, _close_windows_job_handle
from ff_win_process_identity import process_creation_token


class HiddenChromeError(RuntimeError):
    def __init__(self, code, details=None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


def chrome_path():
    """Only standard installed Chrome/Chromium locations, never PATH or an RPC path."""
    candidates = []
    for value in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
                  os.environ.get("LOCALAPPDATA")):
        if value:
            candidates.extend(Path(value) / leaf for leaf in
                              ("Google/Chrome/Application/chrome.exe", "Chromium/Application/chrome.exe"))
    return next((p.resolve() for p in candidates if p.is_file() and not linked(p)), None)


def _private(desktop, hwnd=None, *, require_current_thread_on_desktop=True):
    identity = desktop_identity(hwnd if require_current_thread_on_desktop else None)
    if (not isinstance(desktop, str) or not desktop.startswith("FFBridge-Agent-")
            or identity["input"] == desktop):
        raise HiddenChromeError("HIDDEN_DESKTOP_IDENTITY_INVALID")
    if require_current_thread_on_desktop:
        if identity["current"] != desktop or identity.get("target", desktop) != desktop:
            raise HiddenChromeError("HIDDEN_DESKTOP_IDENTITY_INVALID")


def _profile(root, *, persistent=False):
    root = Path(root)
    if is_owner_browser_profile_path(root):
        raise HiddenChromeError("HIDDEN_CHROME_OWNER_PROFILE_FORBIDDEN", {"attempted": False})
    if (not root.is_absolute() or not root.is_dir() or any(linked(p) for p in (root, *root.parents))):
        raise HiddenChromeError("HIDDEN_CHROME_PROFILE_INVALID", {"attempted": False})
    if persistent:
        owner = PersistentBrowserProfile._read_owner(root)
        if owner is None or not process_is_same(owner["pid"], owner["creation"]):
            raise HiddenChromeError("HIDDEN_CHROME_PROFILE_OWNER_INVALID", {"attempted": False})
        profile = root / "chrome-profile"
        if is_owner_browser_profile_path(profile):
            raise HiddenChromeError("HIDDEN_CHROME_OWNER_PROFILE_FORBIDDEN", {"attempted": False})
        if profile.exists() or profile.is_symlink():
            if linked(profile) or not profile.is_dir():
                raise HiddenChromeError("HIDDEN_CHROME_PROFILE_INVALID", {"attempted": False})
        else:
            profile.mkdir()
        stale_marker = profile / "DevToolsActivePort"
        if stale_marker.is_symlink() or linked(stale_marker):
            raise HiddenChromeError("HIDDEN_CHROME_ENDPOINT_INVALID", {"attempted": False})
        if stale_marker.is_file():
            stale_marker.unlink()
        return root, owner, profile

    owner = ManagedBrowserProfiles._read_owner(root)
    if owner is None or not process_is_same(owner["pid"], owner["creation"]):
        raise HiddenChromeError("HIDDEN_CHROME_PROFILE_OWNER_INVALID", {"attempted": False})
    if {p.name for p in root.iterdir()} != {"owner.json"}:
        raise HiddenChromeError("HIDDEN_CHROME_PROFILE_NOT_FRESH", {"attempted": False})
    profile = root / "chrome-profile"
    profile.mkdir()  # exist_ok=False: never reuse another launch's browser state.
    return root, owner, profile


def _active_port(profile):
    marker = profile / "DevToolsActivePort"
    if linked(profile) or linked(marker) or not marker.is_file() or marker.stat().st_size > 4096:
        raise HiddenChromeError("HIDDEN_CHROME_ENDPOINT_UNAVAILABLE")
    lines = marker.read_text(encoding="ascii").splitlines()
    if (len(lines) != 2 or not re.fullmatch(r"[1-9][0-9]{0,4}", lines[0])
            or not 0 < int(lines[0]) <= 65535
            or not re.fullmatch(r"/devtools/browser/[A-Za-z0-9_-]{1,128}", lines[1])):
        raise HiddenChromeError("HIDDEN_CHROME_ENDPOINT_INVALID")
    return int(lines[0]), lines[1]


def _version(port):
    # Environment proxy variables must never turn this into an external request.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://127.0.0.1:{port}/json/version", timeout=1.5) as response:
        if response.status != 200:
            raise HiddenChromeError("HIDDEN_CHROME_ENDPOINT_INVALID")
        raw = response.read(65537)
    if len(raw) > 65536:
        raise HiddenChromeError("HIDDEN_CHROME_ENDPOINT_INVALID")
    return json.loads(raw)


def _write_download_preferences(profile: Path, downloads: Path, *, persistent: bool) -> None:
    preferences_dir = profile / "Default"
    if linked(preferences_dir):
        raise HiddenChromeError("HIDDEN_CHROME_PROFILE_INVALID", {"attempted": False})
    preferences_dir.mkdir(exist_ok=persistent)
    pref_file = preferences_dir / "Preferences"
    if linked(pref_file):
        raise HiddenChromeError("HIDDEN_CHROME_PROFILE_INVALID", {"attempted": False})
    data = {}
    if persistent and pref_file.is_file():
        try:
            loaded = json.loads(pref_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError):
            data = {}
    download_cfg = data.get("download") if isinstance(data.get("download"), dict) else {}
    download_cfg.update({
        "default_directory": str(downloads),
        "prompt_for_download": False,
        "directory_upgrade": True,
    })
    data["download"] = download_cfg
    if persistent:
        prof_cfg = data.get("profile") if isinstance(data.get("profile"), dict) else {}
        prof_cfg["exit_type"] = "Normal"
        prof_cfg["exited_cleanly"] = True
        data["profile"] = prof_cfg
    pref_file.write_text(json.dumps(data), encoding="utf-8")


def chrome_info(context, *, owns, window_info, desktop, retained_socket=False):
    """Revalidate native identity. Check listener owner before opening a new socket."""
    proc, result = context["proc"], context["result"]
    token = result["create_time"]
    if proc.poll() is not None or process_creation_token(proc.pid) != token:
        raise HiddenChromeError("HIDDEN_CHROME_PROCESS_CHANGED")
    root, profile = context["root"], Path(result["profile_path"])
    persistent = bool(context.get("persistent"))
    read_owner = PersistentBrowserProfile._read_owner if persistent else ManagedBrowserProfiles._read_owner
    if (is_owner_browser_profile_path(root) or is_owner_browser_profile_path(profile)
            or any(linked(p) for p in (root, *root.parents))
            or read_owner(root) != context["owner"]):
        raise HiddenChromeError("HIDDEN_CHROME_PROFILE_OWNER_CHANGED")
    hwnd = result["hwnd"]
    require_thread = context.get("require_current_thread_on_desktop", True)
    _private(desktop, hwnd, require_current_thread_on_desktop=require_thread)
    window = window_info(hwnd)
    if (not owns(hwnd) or window.get("pid") != proc.pid
            or window.get("class_name") != "Chrome_WidgetWin_1"):
        raise HiddenChromeError("HIDDEN_CHROME_WINDOW_CHANGED")
    port, path = _active_port(profile)
    if (port != result["cdp_port"] or path != result["browser_ws_path"]):
        raise HiddenChromeError("HIDDEN_CHROME_ENDPOINT_CHANGED")
    # The verified, connected TCP socket cannot be redirected by reassigning a listener.
    # Public discovery and every new connection still check the actual loopback listener.
    if not retained_socket:
        listeners = [x for x in owned_tcp_listeners(proc.pid) if x.get("port") == port]
        if (not listeners or any(x.get("address") not in {"127.0.0.1", "::1"}
                                 or x.get("pid") != proc.pid for x in listeners)):
            raise HiddenChromeError("HIDDEN_CHROME_LISTENER_NOT_OWNED")
        try:
            version = _version(port)
        except (TimeoutError, ConnectionError, urllib.error.URLError) as exc:
            if not isinstance(getattr(exc, "reason", exc), (TimeoutError, ConnectionError)):
                raise
            raise HiddenChromeError("HIDDEN_CHROME_VERSION_PROBE_UNAVAILABLE") from exc
        endpoint = urllib.parse.urlsplit(str(version.get("webSocketDebuggerUrl") or ""))
        if (endpoint.scheme != "ws" or endpoint.hostname not in {"127.0.0.1", "localhost", "::1"}
                or endpoint.port != port or endpoint.path != path or endpoint.username
                or endpoint.password or endpoint.query or endpoint.fragment
                or not re.match(r"^(?:Chrome|Chromium)/", str(version.get("Browser") or ""))):
            raise HiddenChromeError("HIDDEN_CHROME_ENDPOINT_INVALID")
    if process_creation_token(proc.pid) != token or not owns(hwnd):
        raise HiddenChromeError("HIDDEN_CHROME_PROCESS_CHANGED")
    _private(desktop, hwnd, require_current_thread_on_desktop=require_thread)
    return dict(result)


def verify_chrome(context, *, owns, desktop, retained_socket=False):
    """Worker's browser.info entry point; no cached endpoint is authority by itself."""
    return chrome_info(context, owns=owns, window_info=context["window_info"], desktop=desktop,
                       retained_socket=retained_socket)


def close_chrome(context, *, timeout_s: float = 6.0) -> dict:
    """Gracefully flush Chrome storage via CDP Browser.close, then verify exit with kill fallback."""
    proc = context["proc"]
    result = context["result"]
    graceful = False
    forced_kill = False
    if proc.poll() is None:
        ws_url = result.get("browser_ws_endpoint")
        if isinstance(ws_url, str) and ws_url.startswith("ws://127.0.0.1:"):
            try:
                from cua_universal_fastpath import _LocalWebSocket

                sock = _LocalWebSocket(ws_url, timeout=min(float(timeout_s), 3.0))
                try:
                    sock.send(json.dumps({"id": 1, "method": "Browser.close", "params": {}}))
                    graceful = True
                    try:
                        sock.set_deadline(time.monotonic() + 1.5)
                        sock.recv()
                    except Exception:
                        pass
                finally:
                    sock.close()
            except Exception:
                graceful = False
        try:
            proc.wait(timeout=max(0.5, float(timeout_s)))
        except Exception:
            if proc.poll() is None:
                forced_kill = True
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
    return {
        "exited": proc.poll() is not None,
        "returncode": proc.returncode,
        "graceful_cdp_close": graceful,
        "forced_kill": forced_kill,
    }


def launch_chrome(root, args, *, register, windows, owns, window_info, desktop, timeout_s=25, persistent=False):
    """Return {'proc', 'root', 'owner', 'result'}; root is parent-injected state only.

    Callbacks belong to the hidden worker: register(Popen), windows(pid),
    owns(hwnd), and window_info(hwnd). No caller-supplied executable or flags.
    """
    if not isinstance(args, dict) or args != {"command": "browser.launch"}:
        raise HiddenChromeError("HIDDEN_CHROME_OPTION_INVALID", {"attempted": False})
    if type(timeout_s) not in (int, float) or not 1 <= timeout_s <= 60:
        raise HiddenChromeError("HIDDEN_CHROME_TIMEOUT_INVALID", {"attempted": False})
    _private(desktop)
    executable = chrome_path()
    if executable is None:
        raise HiddenChromeError("HIDDEN_CHROME_NOT_INSTALLED", {"attempted": False})
    root, owner, profile = _profile(root, persistent=persistent)
    # Never fall back to the owner's Downloads if a CDP client disconnects.
    downloads = root / "artifacts" / "downloads"
    downloads.mkdir(parents=True, exist_ok=persistent)
    _write_download_preferences(profile, downloads, persistent=persistent)
    si = subprocess.STARTUPINFO()
    si.dwFlags = subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 4  # SW_SHOWNOACTIVATE, on the inherited private desktop.
    proc = None
    try:
        proc = subprocess.Popen([str(executable), "--user-data-dir=" + str(profile),
            "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0",
            "--no-first-run", "--no-default-browser-check", "--new-window", "about:blank"],
            startupinfo=si, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
        register(proc)
        token = process_creation_token(proc.pid)
        if type(token) is not int or token <= 0:
            raise HiddenChromeError("HIDDEN_CHROME_PROCESS_IDENTITY_UNAVAILABLE")
        deadline = time.monotonic() + timeout_s
        context = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise HiddenChromeError("HIDDEN_CHROME_EXITED_BEFORE_READY")
            _private(desktop)
            candidates = []
            for hwnd in windows(proc.pid):
                info = window_info(hwnd)
                rect = info.get("geometry") or {}
                if (owns(hwnd) and info.get("pid") == proc.pid
                        and info.get("class_name") == "Chrome_WidgetWin_1"
                        and rect.get("right", 0) > rect.get("left", 0)
                        and rect.get("bottom", 0) > rect.get("top", 0)):
                    candidates.append(hwnd)
            if len(candidates) == 1 and (profile / "DevToolsActivePort").is_file():
                if context is None:
                    port, path = _active_port(profile)
                    result = {"app": "chrome", "pid": proc.pid, "create_time": token,
                        "hwnd": candidates[0], "desktop": desktop, "profile_path": str(profile),
                        "cdp_port": port, "cdp_endpoint": f"http://127.0.0.1:{port}",
                        "browser_ws_path": path, "browser_ws_endpoint": f"ws://127.0.0.1:{port}{path}",
                        "route": "HIDDEN_DESKTOP_CHROME_CDP", "physical_input_used": False,
                        "headless": False, "owner_desktop_access_allowed": False,
                        "persistent_profile": bool(persistent)}
                    if persistent:
                        result["profile_id"] = owner.get("profile_id")
                    context = {"proc": proc, "root": root, "owner": owner, "result": result,
                               "window_info": window_info, "persistent": bool(persistent)}
                # Chrome can publish the marker before /json/version responds.
                # Recheck the same process, window, profile and listener on each
                # read-only probe. Never start another process on this path.
                try:
                    chrome_info(context, owns=owns, window_info=window_info, desktop=desktop)
                except HiddenChromeError as exc:
                    if exc.code != "HIDDEN_CHROME_VERSION_PROBE_UNAVAILABLE":
                        raise
                else:
                    return context
            time.sleep(0.1)
        if context is not None:
            raise HiddenChromeError("HIDDEN_CHROME_VERSION_PROBE_UNAVAILABLE")
        raise HiddenChromeError("HIDDEN_CHROME_WINDOW_OR_ENDPOINT_UNAVAILABLE")
    except Exception as exc:
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
        if isinstance(exc, HiddenChromeError):
            exc.details.update({"attempted": proc is not None, "retry_safe": False})
            raise
        raise HiddenChromeError("HIDDEN_CHROME_LAUNCH_FAILED", {
            "attempted": proc is not None, "retry_safe": False, "cause": type(exc).__name__}) from exc


class _WinStartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR), ("lpTitle", w.LPWSTR),
        ("dwX", w.DWORD), ("dwY", w.DWORD), ("dwXSize", w.DWORD), ("dwYSize", w.DWORD),
        ("dwXCountChars", w.DWORD), ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD),
        ("dwFlags", w.DWORD), ("wShowWindow", w.WORD), ("cbReserved2", w.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", w.HANDLE), ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE),
    ]


class _WinProcessInfo(ctypes.Structure):
    _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE), ("pid", w.DWORD), ("tid", w.DWORD)]


class _WinJobAccounting(ctypes.Structure):
    _fields_ = [
        ("TotalUserTime", ctypes.c_longlong), ("TotalKernelTime", ctypes.c_longlong),
        ("ThisPeriodTotalUserTime", ctypes.c_longlong), ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
        ("TotalPageFaultCount", w.DWORD), ("TotalProcesses", w.DWORD),
        ("ActiveProcesses", w.DWORD), ("TotalTerminatedProcesses", w.DWORD),
    ]


class _WinProcessHandle:
    """Minimal Popen-like adapter over a CreateProcessW handle."""

    def __init__(self, kernel32, handle: int, pid: int):
        self._k = kernel32
        self._handle = handle
        self.pid = int(pid)
        self.returncode: int | None = None

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        if not self._handle:
            return self.returncode
        # WaitForSingleObject(0) only returns WAIT_OBJECT_0 once the kernel has
        # actually finished tearing down the process (exit_time stamped).
        if self._k.WaitForSingleObject(self._handle, 0) != 0:
            return None
        code = w.DWORD()
        if not self._k.GetExitCodeProcess(self._handle, ctypes.byref(code)):
            self.returncode = 0
            return 0
        self.returncode = int(code.value)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.poll() is not None:
            return int(self.returncode or 0)
        ms = 0xFFFFFFFF if timeout is None else max(0, int(float(timeout) * 1000))
        res = self._k.WaitForSingleObject(self._handle, ms)
        if res == 0:
            code = self.poll()
            return 0 if code is None else code
        raise subprocess.TimeoutExpired(cmd="chrome", timeout=timeout or 0)

    def kill(self) -> None:
        if self._handle and self.poll() is None:
            self._k.TerminateProcess(self._handle, 1)

    def close_handle(self) -> None:
        handle, self._handle = self._handle, None
        if handle:
            self._k.CloseHandle(handle)


class IsolatedHiddenChromeSession:
    """Standalone Win32 Private Desktop Chrome + Kill-on-Close Job + PrivateBrowser CDP.

    Never switches desktops, never touches owner Chrome User Data, and guarantees
    graceful CDP Browser.close + Windows Job Object teardown with ActiveProcesses == 0.
    """

    def __init__(
        self,
        isolated_root: str | Path,
        *,
        profile_id: str | None = None,
        profile_dir: str | Path | None = None,
        persistent: bool = False,
        timeout_s: float = 25.0,
    ):
        if os.name != "nt":
            raise HiddenChromeError("HIDDEN_CHROME_WINDOWS_ONLY", {"attempted": False})
        if type(timeout_s) not in (int, float) or not 1 <= timeout_s <= 60:
            raise HiddenChromeError("HIDDEN_CHROME_TIMEOUT_INVALID", {"attempted": False})
        use_persistent = bool(persistent or profile_id is not None or profile_dir is not None)
        if persistent and profile_id is None and profile_dir is None:
            raise HiddenChromeError("HIDDEN_CHROME_PROFILE_ID_REQUIRED", {"attempted": False})

        try:
            assert_not_owner_browser_profile(Path(isolated_root).absolute())
            if profile_dir is not None:
                assert_not_owner_browser_profile(profile_dir)
        except ProfileIsolationError as exc:
            code = (
                "HIDDEN_CHROME_OWNER_PROFILE_FORBIDDEN"
                if exc.code == "OWNER_BROWSER_PROFILE_FORBIDDEN"
                else exc.code
            )
            raise HiddenChromeError(code, {"attempted": False, **exc.details}) from exc

        executable = chrome_path()
        if executable is None:
            raise HiddenChromeError("HIDDEN_CHROME_NOT_INSTALLED", {"attempted": False})

        self.persistent = use_persistent
        self.desktop_name = "FFBridge-Agent-" + uuid.uuid4().hex
        self._desktop = None
        self._job = None
        self._proc: _WinProcessHandle | None = None
        self._profile_lease = None
        self.context: dict | None = None
        self.browser = None
        self.closed = False
        self.cleanup_receipt: dict = {}

        self._u = ctypes.WinDLL("user32", use_last_error=True)
        self._k = ctypes.WinDLL("kernel32", use_last_error=True)
        self._u.CreateDesktopW.argtypes = [w.LPCWSTR, w.LPCWSTR, ctypes.c_void_p, w.DWORD, w.DWORD, ctypes.c_void_p]
        self._u.CreateDesktopW.restype = w.HANDLE
        self._u.CloseDesktop.argtypes = [w.HANDLE]
        self._u.GetUserObjectInformationW.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)]
        self._u.GetUserObjectInformationW.restype = w.BOOL
        self._u.EnumDesktopWindows.argtypes = [w.HANDLE, ctypes.c_void_p, w.LPARAM]
        self._u.EnumDesktopWindows.restype = w.BOOL
        self._u.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
        self._u.GetWindowThreadProcessId.restype = w.DWORD
        self._u.GetClassNameW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
        self._u.GetClassNameW.restype = ctypes.c_int
        self._u.GetWindowRect.argtypes = [w.HWND, ctypes.POINTER(w.RECT)]
        self._u.GetWindowRect.restype = w.BOOL
        self._k.CreateProcessW.argtypes = [
            w.LPCWSTR, w.LPWSTR, ctypes.c_void_p, ctypes.c_void_p, w.BOOL, w.DWORD,
            ctypes.c_void_p, w.LPCWSTR, ctypes.POINTER(_WinStartupInfo), ctypes.POINTER(_WinProcessInfo),
        ]
        self._k.CreateProcessW.restype = w.BOOL
        self._k.ResumeThread.argtypes = [w.HANDLE]
        self._k.ResumeThread.restype = w.DWORD
        self._k.CloseHandle.argtypes = [w.HANDLE]
        self._k.CloseHandle.restype = w.BOOL
        self._k.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
        self._k.TerminateProcess.restype = w.BOOL
        self._k.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        self._k.GetExitCodeProcess.restype = w.BOOL
        self._k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        self._k.WaitForSingleObject.restype = w.DWORD
        self._k.TerminateJobObject.argtypes = [w.HANDLE, w.UINT]
        self._k.TerminateJobObject.restype = w.BOOL
        self._k.QueryInformationJobObject.argtypes = [
            w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)
        ]
        self._k.QueryInformationJobObject.restype = w.BOOL

        try:
            if use_persistent:
                try:
                    self._profile_lease = PersistentBrowserProfile(
                        isolated_root, profile_id=profile_id, profile_dir=profile_dir
                    )
                except ProfileIsolationError as exc:
                    code = (
                        "HIDDEN_CHROME_OWNER_PROFILE_FORBIDDEN"
                        if exc.code == "OWNER_BROWSER_PROFILE_FORBIDDEN"
                        else exc.code
                    )
                    raise HiddenChromeError(code, {"attempted": False, **exc.details}) from exc
            else:
                try:
                    self._profile_lease = ManagedBrowserProfiles(isolated_root)
                except ProfileIsolationError as exc:
                    code = (
                        "HIDDEN_CHROME_OWNER_PROFILE_FORBIDDEN"
                        if exc.code == "OWNER_BROWSER_PROFILE_FORBIDDEN"
                        else exc.code
                    )
                    raise HiddenChromeError(code, {"attempted": False, **exc.details}) from exc

            root, owner, profile = _profile(self._profile_lease.path, persistent=use_persistent)
            downloads = root / "artifacts" / "downloads"
            downloads.mkdir(parents=True, exist_ok=use_persistent)
            _write_download_preferences(profile, downloads, persistent=use_persistent)

            self._desktop = self._u.CreateDesktopW(self.desktop_name, None, None, 0, 0x01FF, None)
            if not self._desktop:
                raise ctypes.WinError(ctypes.get_last_error())

            argv = [
                str(executable),
                "--user-data-dir=" + str(profile),
                "--remote-debugging-address=127.0.0.1",
                "--remote-debugging-port=0",
                "--no-first-run",
                "--no-default-browser-check",
                "--new-window",
                "about:blank",
            ]
            cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            si = _WinStartupInfo()
            si.cb = ctypes.sizeof(_WinStartupInfo)
            si.lpDesktop = "winsta0\\" + self.desktop_name
            si.dwFlags = 0x00000001  # STARTF_USESHOWWINDOW
            si.wShowWindow = 4       # SW_SHOWNOACTIVATE
            pi = _WinProcessInfo()
            # CREATE_SUSPENDED (0x4) | CREATE_NO_WINDOW (0x08000000)
            if not self._k.CreateProcessW(
                None, cmdline, None, None, False, 0x08000004, None, str(root), ctypes.byref(si), ctypes.byref(pi)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            self._proc = _WinProcessHandle(self._k, pi.hProcess, pi.pid)
            try:
                self._job = _bind_windows_kill_on_close_job(SimpleNamespace(pid=pi.pid))
                if self._k.ResumeThread(pi.hThread) == 0xFFFFFFFF:
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                self._k.CloseHandle(pi.hThread)

            token = process_creation_token(self._proc.pid)
            if type(token) is not int or token <= 0:
                raise HiddenChromeError("HIDDEN_CHROME_PROCESS_IDENTITY_UNAVAILABLE")

            deadline = time.monotonic() + timeout_s
            context = None
            while time.monotonic() < deadline:
                if self._proc.poll() is not None:
                    raise HiddenChromeError("HIDDEN_CHROME_EXITED_BEFORE_READY")
                candidates = []
                for hwnd in self._desktop_windows_for_pid(self._proc.pid):
                    info = self._window_info(hwnd)
                    rect = info.get("geometry") or {}
                    if (self._owns(hwnd) and info.get("pid") == self._proc.pid
                            and info.get("class_name") == "Chrome_WidgetWin_1"
                            and rect.get("right", 0) > rect.get("left", 0)
                            and rect.get("bottom", 0) > rect.get("top", 0)):
                        candidates.append(hwnd)
                if len(candidates) >= 1 and (profile / "DevToolsActivePort").is_file():
                    if context is None:
                        port, ws_path = _active_port(profile)
                        result = {
                            "app": "chrome",
                            "pid": self._proc.pid,
                            "create_time": token,
                            "hwnd": candidates[0],
                            "desktop": self.desktop_name,
                            "profile_path": str(profile),
                            "cdp_port": port,
                            "cdp_endpoint": f"http://127.0.0.1:{port}",
                            "browser_ws_path": ws_path,
                            "browser_ws_endpoint": f"ws://127.0.0.1:{port}{ws_path}",
                            "route": "HIDDEN_DESKTOP_CHROME_CDP",
                            "physical_input_used": False,
                            "headless": False,
                            "owner_desktop_access_allowed": False,
                            "persistent_profile": bool(use_persistent),
                        }
                        if use_persistent:
                            result["profile_id"] = owner.get("profile_id")
                        context = {
                            "proc": self._proc,
                            "root": root,
                            "owner": owner,
                            "result": result,
                            "window_info": self._window_info,
                            "persistent": bool(use_persistent),
                            "require_current_thread_on_desktop": False,
                        }
                    try:
                        chrome_info(
                            context,
                            owns=self._owns,
                            window_info=self._window_info,
                            desktop=self.desktop_name,
                        )
                    except HiddenChromeError as exc:
                        if exc.code != "HIDDEN_CHROME_VERSION_PROBE_UNAVAILABLE":
                            raise
                    else:
                        self.context = context
                        break
                time.sleep(0.1)

            if self.context is None:
                raise HiddenChromeError("HIDDEN_CHROME_WINDOW_OR_ENDPOINT_UNAVAILABLE")

            from cua_private_browser import PrivateBrowser

            self.browser = PrivateBrowser(self.context, self._owns, self.desktop_name)
        except Exception:
            self.close()
            raise

    def _desktop_windows_for_pid(self, pid: int) -> list[int]:
        if not self._desktop:
            return []
        found: list[int] = []
        cb_type = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)

        @cb_type
        def callback(hwnd, _):
            actual = w.DWORD()
            self._u.GetWindowThreadProcessId(hwnd, ctypes.byref(actual))
            if actual.value == pid:
                found.append(int(hwnd))
            return True

        self._u.EnumDesktopWindows(self._desktop, callback, 0)
        return found

    def _owns(self, hwnd: int) -> bool:
        if type(hwnd) is not int or hwnd <= 0 or self._proc is None or self._proc.poll() is not None or not self._desktop:
            return False
        buf = ctypes.create_unicode_buffer(256)
        size = w.DWORD()
        if (not self._u.GetUserObjectInformationW(self._desktop, 2, buf, ctypes.sizeof(buf), ctypes.byref(size))
                or buf.value != self.desktop_name):
            return False
        return int(hwnd) in self._desktop_windows_for_pid(self._proc.pid)

    def _window_info(self, hwnd: int) -> dict:
        pid = w.DWORD()
        self._u.GetWindowThreadProcessId(int(hwnd), ctypes.byref(pid))
        cls = ctypes.create_unicode_buffer(256)
        self._u.GetClassNameW(int(hwnd), cls, len(cls))
        rect = w.RECT()
        self._u.GetWindowRect(int(hwnd), ctypes.byref(rect))
        return {
            "hwnd": int(hwnd),
            "pid": int(pid.value),
            "class_name": cls.value,
            "geometry": {
                "left": int(rect.left),
                "top": int(rect.top),
                "right": int(rect.right),
                "bottom": int(rect.bottom),
            },
        }

    @property
    def info(self) -> dict:
        if self.context is None:
            raise HiddenChromeError("HIDDEN_CHROME_NOT_STARTED")
        return dict(self.context["result"])

    def close(self, *, graceful: bool = True, timeout_s: float = 6.0) -> dict:
        if self.closed:
            return dict(self.cleanup_receipt)
        self.closed = True
        graceful_report = {"exited": False, "graceful_cdp_close": False, "forced_kill": False}
        if self.browser is not None:
            try:
                self.browser.close(close_browser=graceful, timeout=min(timeout_s, 3.0))
            except Exception:
                pass
            self.browser = None
        if self.context is not None and self._proc is not None:
            if graceful and self._proc.poll() is None:
                graceful_report = close_chrome(self.context, timeout_s=timeout_s)
            else:
                graceful_report["exited"] = self._proc.poll() is not None

        job, self._job = self._job, None
        job_cleanup_verified = False
        active_remaining = None
        proc_pid = self._proc.pid if self._proc is not None else None
        proc_token = self.context["result"].get("create_time") if self.context else None
        deadline = time.monotonic() + 8.0
        try:
            if job:
                # Always terminate the Job Object after graceful exit (or timeout) so
                # zero renderer/GPU/utility/crashpad child processes can linger.
                terminated = bool(self._k.TerminateJobObject(job, 1))
                proc_exited = True
                if self._proc is not None:
                    if not terminated and self._proc.poll() is None:
                        self._proc.kill()
                    try:
                        self._proc.wait(timeout=max(0.5, deadline - time.monotonic()))
                        proc_exited = True
                    except Exception:
                        proc_exited = self._proc.poll() is not None
                accounting = _WinJobAccounting()
                while self._k.QueryInformationJobObject(
                    job, 1, ctypes.byref(accounting), ctypes.sizeof(accounting), None
                ):
                    active_remaining = int(accounting.ActiveProcesses)
                    root_still_live = (
                        proc_pid is not None
                        and type(proc_token) is int
                        and process_creation_token(proc_pid) == proc_token
                    )
                    if active_remaining == 0 and proc_exited and not root_still_live:
                        job_cleanup_verified = terminated
                        break
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(0.05)
            else:
                if self._proc is not None and self._proc.poll() is None:
                    self._proc.kill()
                    try:
                        self._proc.wait(timeout=3.0)
                    except Exception:
                        pass
                job_cleanup_verified = self._proc is None or self._proc.poll() is not None
                active_remaining = 0 if job_cleanup_verified else 1
        finally:
            _close_windows_job_handle(job)
            if self._proc is not None:
                self._proc.close_handle()
                self._proc = None
            if self._desktop:
                self._u.CloseDesktop(self._desktop)
                self._desktop = None

        profile_report: dict = {}
        lease, self._profile_lease = self._profile_lease, None
        if lease is not None:
            try:
                res = lease.close()
                if isinstance(res, dict):
                    profile_report = res
                else:
                    profile_report = {"removed": bool(res), "preserved": False, "root": str(lease.path)}
            except Exception as exc:
                profile_report = {"removed": False, "released": False, "error": str(exc)}

        self.cleanup_receipt = {
            "closed": True,
            "persistent_profile": self.persistent,
            "graceful_close": graceful_report,
            "job_cleanup_verified": job_cleanup_verified,
            "active_processes_remaining": active_remaining,
            "profile": profile_report,
        }
        return dict(self.cleanup_receipt)

    def __enter__(self) -> IsolatedHiddenChromeSession:
        return self

    def __exit__(self, *_exc) -> None:
        self.close()
