"""A fresh Chrome process/profile on the caller's already private Windows desktop.

The worker owns the process through its existing kill-on-close Job.  This module
never switches desktops, adopts an existing browser or weakens Chrome's sandbox.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.parse
import urllib.request

from cua_browser_profiles import ManagedBrowserProfiles, linked
from cua_desktop_identity import desktop_identity
from cua_global_resources import process_is_same
from cua_programmatic_discovery import owned_tcp_listeners
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


def _private(desktop, hwnd=None):
    identity = desktop_identity(hwnd)
    if (not isinstance(desktop, str) or not desktop.startswith("FFBridge-Agent-")
            or identity["current"] != desktop or identity["input"] == desktop
            or identity.get("target", desktop) != desktop):
        raise HiddenChromeError("HIDDEN_DESKTOP_IDENTITY_INVALID")


def _profile(root):
    root = Path(root)
    if (not root.is_absolute() or not root.is_dir() or any(linked(p) for p in (root, *root.parents))):
        raise HiddenChromeError("HIDDEN_CHROME_PROFILE_INVALID", {"attempted": False})
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


def chrome_info(context, *, owns, window_info, desktop, retained_socket=False):
    """Revalidate native identity. Check listener owner before opening a new socket."""
    proc, result = context["proc"], context["result"]
    token = result["create_time"]
    if proc.poll() is not None or process_creation_token(proc.pid) != token:
        raise HiddenChromeError("HIDDEN_CHROME_PROCESS_CHANGED")
    root, profile = context["root"], Path(result["profile_path"])
    if (any(linked(p) for p in (root, *root.parents))
            or ManagedBrowserProfiles._read_owner(root) != context["owner"]):
        raise HiddenChromeError("HIDDEN_CHROME_PROFILE_OWNER_CHANGED")
    hwnd = result["hwnd"]
    _private(desktop, hwnd)
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
        version = _version(port)
        endpoint = urllib.parse.urlsplit(str(version.get("webSocketDebuggerUrl") or ""))
        if (endpoint.scheme != "ws" or endpoint.hostname not in {"127.0.0.1", "localhost", "::1"}
                or endpoint.port != port or endpoint.path != path or endpoint.username
                or endpoint.password or endpoint.query or endpoint.fragment
                or not re.match(r"^(?:Chrome|Chromium)/", str(version.get("Browser") or ""))):
            raise HiddenChromeError("HIDDEN_CHROME_ENDPOINT_INVALID")
    if process_creation_token(proc.pid) != token or not owns(hwnd):
        raise HiddenChromeError("HIDDEN_CHROME_PROCESS_CHANGED")
    _private(desktop, hwnd)
    return dict(result)


def verify_chrome(context, *, owns, desktop, retained_socket=False):
    """Worker's browser.info entry point; no cached endpoint is authority by itself."""
    return chrome_info(context, owns=owns, window_info=context["window_info"], desktop=desktop,
                       retained_socket=retained_socket)


def launch_chrome(root, args, *, register, windows, owns, window_info, desktop, timeout_s=25):
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
    root, owner, profile = _profile(root)
    # Never fall back to the owner's Downloads if a CDP client disconnects.
    downloads=root/'artifacts'/'downloads';downloads.mkdir(parents=True)
    preferences=profile/'Default';preferences.mkdir()
    (preferences/'Preferences').write_text(json.dumps({'download':{'default_directory':str(downloads),
        'prompt_for_download':False,'directory_upgrade':True}}),encoding='utf-8')
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
                port, path = _active_port(profile)
                result = {"app": "chrome", "pid": proc.pid, "create_time": token,
                    "hwnd": candidates[0], "desktop": desktop, "profile_path": str(profile),
                    "cdp_port": port, "cdp_endpoint": f"http://127.0.0.1:{port}",
                    "browser_ws_path": path, "browser_ws_endpoint": f"ws://127.0.0.1:{port}{path}",
                    "route": "HIDDEN_DESKTOP_CHROME_CDP", "physical_input_used": False,
                    "headless": False, "owner_desktop_access_allowed": False}
                context = {"proc": proc, "root": root, "owner": owner, "result": result,
                           "window_info": window_info}
                chrome_info(context, owns=owns, window_info=window_info, desktop=desktop)
                return context
            time.sleep(.1)
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
