"""Fail closed before focus/input if the caller or target is on another desktop.

Win32 Private Desktop boundaries (CreateDesktopW / SetThreadDesktop):
- Hardware input (SendInput, mouse/keyboard hooks, SetCursorPos) and
  SetForegroundWindow for owner interaction operate only on the active input
  desktop and cannot target an inactive private desktop without SwitchDesktop,
  which is forbidden because it would hijack the owner's visible session.
- UIA3 (System.Windows.Automation) operates only within the calling thread's
  desktop; cross-desktop UIA targeting is unsupported and fails closed.
- Win32 HWND message routes (WM_SETTEXT, EM_REPLACESEL, WM_CHAR, BM_CLICK,
  CB/LB_SETCURSEL + WM_COMMAND, WM_GETTEXT, PrintWindow) operate only on owned
  HWNDs belonging to the same private desktop, without SendInput, focus hijack,
  or clipboard access.
"""
import ctypes
from ctypes import wintypes as w
import os

PRIVATE_DESKTOP_BOUNDARIES = {
    "cross_desktop_sendinput_supported": False,
    "cross_desktop_uia_supported": False,
    "switch_desktop_allowed": False,
    "visible_desktop_fallback_allowed": False,
    "supported_private_desktop_routes": [
        "HWND_MESSAGE",
        "PRINTWINDOW",
        "UIA_PATTERN_IN_DESKTOP",
    ],
    "unsupported_private_desktop_routes": [
        "SENDINPUT",
        "CROSS_DESKTOP_UIA",
        "SWITCH_DESKTOP",
        "VISIBLE_DESKTOP_FALLBACK",
    ],
}


class DesktopIdentityError(RuntimeError):
    pass


def _desktop_name(u, handle):
    value = ctypes.create_unicode_buffer(512)
    size = w.DWORD()
    if not handle or not u.GetUserObjectInformationW(handle, 2, value, ctypes.sizeof(value), ctypes.byref(size)):
        raise DesktopIdentityError("INPUT_DESKTOP_IDENTITY_UNAVAILABLE")
    return value.value


def thread_and_target_desktop(hwnd):
    """Compare current thread desktop and target HWND desktop without OpenInputDesktop."""
    if os.name != "nt":
        raise DesktopIdentityError("DESKTOP_IDENTITY_WINDOWS_ONLY")
    if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
        raise DesktopIdentityError("TARGET_DESKTOP_IDENTITY_UNAVAILABLE")
    u = ctypes.WinDLL("user32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    u.GetThreadDesktop.argtypes = [w.DWORD]
    u.GetThreadDesktop.restype = w.HANDLE
    u.GetUserObjectInformationW.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)]
    u.GetUserObjectInformationW.restype = w.BOOL
    u.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
    u.GetWindowThreadProcessId.restype = w.DWORD
    current = _desktop_name(u, u.GetThreadDesktop(k.GetCurrentThreadId()))
    pid = w.DWORD()
    tid = u.GetWindowThreadProcessId(w.HWND(hwnd), ctypes.byref(pid))
    if not tid:
        raise DesktopIdentityError("TARGET_DESKTOP_IDENTITY_UNAVAILABLE")
    target = _desktop_name(u, u.GetThreadDesktop(tid))
    return {"current": current, "target": target}


def require_same_desktop(hwnd):
    """Fail closed if target HWND lives on a different Windows desktop."""
    identity = thread_and_target_desktop(hwnd)
    if identity["target"] != identity["current"]:
        raise DesktopIdentityError("CROSS_DESKTOP_TARGET_FORBIDDEN")
    return identity


def desktop_identity(hwnd=None):
    if os.name != "nt":
        raise DesktopIdentityError("DESKTOP_IDENTITY_WINDOWS_ONLY")
    u = ctypes.WinDLL("user32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    u.GetThreadDesktop.argtypes = [w.DWORD]; u.GetThreadDesktop.restype = w.HANDLE
    u.OpenInputDesktop.argtypes = [w.DWORD, w.BOOL, w.DWORD]; u.OpenInputDesktop.restype = w.HANDLE
    u.CloseDesktop.argtypes = [w.HANDLE]; u.CloseDesktop.restype = w.BOOL
    u.GetUserObjectInformationW.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)]
    u.GetUserObjectInformationW.restype = w.BOOL
    u.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]; u.GetWindowThreadProcessId.restype = w.DWORD
    current = _desktop_name(u, u.GetThreadDesktop(k.GetCurrentThreadId()))
    input_handle = u.OpenInputDesktop(0, False, 1)
    try:
        active = _desktop_name(u, input_handle)
    finally:
        if input_handle:
            u.CloseDesktop(input_handle)
    result = {"current": current, "input": active}
    if hwnd is not None:
        if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
            raise DesktopIdentityError("TARGET_DESKTOP_IDENTITY_UNAVAILABLE")
        pid = w.DWORD(); tid = u.GetWindowThreadProcessId(w.HWND(hwnd), ctypes.byref(pid))
        if not tid:
            raise DesktopIdentityError("TARGET_DESKTOP_IDENTITY_UNAVAILABLE")
        result["target"] = _desktop_name(u, u.GetThreadDesktop(tid))
    return result


def require_input_desktop(hwnd=None):
    identity = desktop_identity(hwnd)
    if identity["current"] != identity["input"] or identity.get("target", identity["current"]) != identity["input"]:
        raise DesktopIdentityError("PHYSICAL_INPUT_DESKTOP_MISMATCH")
    return identity


def require_private_desktop(expected=None, *, hwnd=None):
    """Revalidate on every worker request, not only at worker startup."""
    identity = desktop_identity() if hwnd is None else desktop_identity(hwnd)
    if (not identity["current"].startswith("FFBridge-Agent-")
            or identity["current"] == identity["input"]
            or (expected is not None and identity["current"] != expected)):
        raise DesktopIdentityError("HIDDEN_DESKTOP_IDENTITY_INVALID")
    if hwnd is not None and (
        identity.get("target") != identity["current"]
        or identity.get("target") == identity["input"]
    ):
        raise DesktopIdentityError("CROSS_DESKTOP_TARGET_FORBIDDEN")
    return identity
