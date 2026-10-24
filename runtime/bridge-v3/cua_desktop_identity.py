"""Fail closed before focus/input if the caller or target is on another desktop."""
import ctypes
from ctypes import wintypes as w


class DesktopIdentityError(RuntimeError):
    pass


def desktop_identity(hwnd=None):
    u = ctypes.WinDLL("user32", use_last_error=True)
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    u.GetThreadDesktop.argtypes = [w.DWORD]; u.GetThreadDesktop.restype = w.HANDLE
    u.OpenInputDesktop.argtypes = [w.DWORD, w.BOOL, w.DWORD]; u.OpenInputDesktop.restype = w.HANDLE
    u.CloseDesktop.argtypes = [w.HANDLE]
    u.GetUserObjectInformationW.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)]
    u.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]; u.GetWindowThreadProcessId.restype = w.DWORD
    def name(handle):
        value = ctypes.create_unicode_buffer(512); size = w.DWORD()
        if not handle or not u.GetUserObjectInformationW(handle, 2, value, ctypes.sizeof(value), ctypes.byref(size)):
            raise DesktopIdentityError("INPUT_DESKTOP_IDENTITY_UNAVAILABLE")
        return value.value
    current = name(u.GetThreadDesktop(k.GetCurrentThreadId()))
    input_handle = u.OpenInputDesktop(0, False, 1)
    try: active = name(input_handle)
    finally:
        if input_handle: u.CloseDesktop(input_handle)
    result = {"current": current, "input": active}
    if hwnd is not None:
        pid = w.DWORD(); tid = u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not tid: raise DesktopIdentityError("TARGET_DESKTOP_IDENTITY_UNAVAILABLE")
        result["target"] = name(u.GetThreadDesktop(tid))
    return result


def require_input_desktop(hwnd=None):
    identity = desktop_identity(hwnd)
    if identity["current"] != identity["input"] or identity.get("target", identity["current"]) != identity["input"]:
        raise DesktopIdentityError("PHYSICAL_INPUT_DESKTOP_MISMATCH")
    return identity
