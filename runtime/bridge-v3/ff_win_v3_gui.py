from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import time
from typing import Any

user32 = ctypes.windll.user32
gdi32 = ctypes.windll.gdi32
gdiplus = ctypes.windll.gdiplus
kernel32 = ctypes.windll.kernel32

# Enable per-monitor DPI awareness
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)
except Exception:
    try:
        user32.SetProcessDPIAware()
    except Exception:
        pass


def attach_desktop() -> bool:
    """Ensure process and thread are attached to the interactive window station and desktop."""
    try:
        hwinsta = user32.OpenWindowStationW("WinSta0", False, 0x037F)
        if hwinsta:
            user32.SetProcessWindowStation(hwinsta)
        hdesk = user32.OpenDesktopW("default", 0, False, 0x01FF)
        if hdesk:
            user32.SetThreadDesktop(hdesk)
            return True
    except Exception:
        pass
    return False


# GDI+ Structures
class GdiplusStartupInput(ctypes.Structure):
    _fields_ = [
        ("GdiplusVersion", ctypes.c_uint32),
        ("DebugEventCallback", ctypes.c_void_p),
        ("SuppressBackgroundThread", ctypes.c_int),
        ("SuppressExternalCodecs", ctypes.c_int),
    ]


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class EncoderParameter(ctypes.Structure):
    _fields_ = [
        ("Guid", GUID),
        ("NumberOfValues", ctypes.c_ulong),
        ("Type", ctypes.c_ulong),
        ("Value", ctypes.c_void_p),
    ]


class EncoderParameters(ctypes.Structure):
    _fields_ = [
        ("Count", ctypes.c_uint),
        ("Parameter", EncoderParameter * 1),
    ]


CLSID_JPEG = GUID(0x557CF401, 0x1A04, 0x11D3, (ctypes.c_ubyte * 8)(0x9A, 0x73, 0x00, 0x00, 0xF8, 0x1E, 0xF3, 0x2E))
EncoderQuality = GUID(0x1D5BE4B5, 0xFA4A, 0x452D, (ctypes.c_ubyte * 8)(0x9C, 0xDD, 0x5D, 0xB3, 0x51, 0x05, 0xE7, 0xEB))

# Mouse Flags
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_LEFTDOWN = 0x0002
MOUSEEVENTF_LEFTUP = 0x0004
MOUSEEVENTF_RIGHTDOWN = 0x0008
MOUSEEVENTF_RIGHTUP = 0x0010
MOUSEEVENTF_MIDDLEDOWN = 0x0020
MOUSEEVENTF_MIDDLEUP = 0x0040
MOUSEEVENTF_WHEEL = 0x0800

# Virtual Keys
VK_MAP = {
    "enter": 0x0D, "return": 0x0D,
    "tab": 0x09,
    "esc": 0x1B, "escape": 0x1B,
    "backspace": 0x08,
    "space": 0x20,
    "ctrl": 0x11, "control": 0x11,
    "shift": 0x10,
    "alt": 0x12,
    "win": 0x5B, "cmd": 0x5B,
    "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27,
    "pageup": 0x21, "pagedown": 0x22,
    "home": 0x24, "end": 0x23,
    "delete": 0x2E, "insert": 0x2D,
    "f1": 0x70, "f2": 0x71, "f3": 0x72, "f4": 0x73,
    "f5": 0x74, "f6": 0x75, "f7": 0x76, "f8": 0x77,
    "f9": 0x78, "f10": 0x79, "f11": 0x7A, "f12": 0x7B,
}


def get_mouse_pos() -> tuple[int, int]:
    class POINT(ctypes.Structure):
        _fields_ = [("x", ctypes.c_long), ("y", ctypes.c_long)]
    pt = POINT()
    user32.GetCursorPos(ctypes.byref(pt))
    return pt.x, pt.y


def capture_screen_jpeg_base64(
    max_width: int = 1280,
    quality: int = 65,
    save_local: bool = True,
    compact: bool = False,
    max_base64_len: int = 0,
) -> dict[str, Any]:
    """
    Ultra-fast native Win32/GDI+ screen capture to JPEG with adaptive payload size bounding.
    Takes ~10-25ms. Always safely within GitHub issue comment limits when compact=True.
    """
    attach_desktop()
    t0 = time.perf_counter()

    if compact:
        if max_width > 640 or max_width <= 0:
            max_width = 640
        quality = min(quality, 30)
        if max_base64_len <= 0:
            max_base64_len = 34000

    token = ctypes.c_ulong()
    startup_in = GdiplusStartupInput(1, None, 0, 0)
    gdiplus.GdiplusStartup(ctypes.byref(token), ctypes.byref(startup_in), None)

    orig_w = user32.GetSystemMetrics(0)
    orig_h = user32.GetSystemMetrics(1)

    cur_max_w = max_width
    cur_q = quality
    best_result = None

    for attempt in range(3):
        if cur_max_w > 0 and cur_max_w < orig_w:
            w = cur_max_w
            h = int(orig_h * (cur_max_w / orig_w))
        else:
            w = orig_w
            h = orig_h

        hdc_screen = user32.GetDC(0)
        hdc_mem = gdi32.CreateCompatibleDC(hdc_screen)
        hbm = gdi32.CreateCompatibleBitmap(hdc_screen, w, h)
        old = gdi32.SelectObject(hdc_mem, hbm)

        if w != orig_w or h != orig_h:
            gdi32.SetStretchBltMode(hdc_mem, 3)  # HALFTONE
            gdi32.SetBrushOrgEx(hdc_mem, 0, 0, None)
            gdi32.StretchBlt(hdc_mem, 0, 0, w, h, hdc_screen, 0, 0, orig_w, orig_h, 0x00CC0020 | 0x40000000)
        else:
            gdi32.BitBlt(hdc_mem, 0, 0, w, h, hdc_screen, 0, 0, 0x00CC0020 | 0x40000000)

        pBitmap = ctypes.c_void_p()
        gdiplus.GdipCreateBitmapFromHBITMAP(hbm, 0, ctypes.byref(pBitmap))

        encoder_params = EncoderParameters()
        encoder_params.Count = 1
        encoder_params.Parameter[0].Guid = EncoderQuality
        encoder_params.Parameter[0].NumberOfValues = 1
        encoder_params.Parameter[0].Type = 4  # EncoderParameterValueTypeLong
        q_val = (ctypes.c_ulong * 1)(max(10, min(100, int(cur_q))))
        encoder_params.Parameter[0].Value = ctypes.cast(q_val, ctypes.c_void_p)

        temp_path = os.path.join(os.environ.get("TEMP", "C:/Temp"), f"ff_shot_{int(time.time()*1000)}.jpg")
        ret = gdiplus.GdipSaveImageToFile(pBitmap, temp_path, ctypes.byref(CLSID_JPEG), ctypes.byref(encoder_params))

        persisted_path = None
        if save_local and ret == 0 and attempt == 0:
            try:
                screenshots_dir = Path(os.environ.get("LOCALAPPDATA", "C:/")) / "FF-Windows-Bridge" / "screenshots"
                screenshots_dir.mkdir(parents=True, exist_ok=True)
                latest = screenshots_dir / "latest.jpg"
                if os.path.exists(temp_path):
                    import shutil
                    shutil.copy2(temp_path, str(latest))
                    persisted_path = str(latest)
            except Exception:
                pass

        gdiplus.GdipDisposeImage(pBitmap)
        gdi32.SelectObject(hdc_mem, old)
        gdi32.DeleteObject(hbm)
        gdi32.DeleteDC(hdc_mem)
        user32.ReleaseDC(0, hdc_screen)

        if ret == 0 and os.path.exists(temp_path):
            size_bytes = os.path.getsize(temp_path)
            with open(temp_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("ascii")
            try:
                os.remove(temp_path)
            except Exception:
                pass

            best_result = {
                "width": w,
                "height": h,
                "original_width": orig_w,
                "original_height": orig_h,
                "format": "jpeg",
                "size_bytes": size_bytes,
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 2),
                "persisted_path": persisted_path,
                "base64": b64,
            }

            if max_base64_len <= 0 or len(b64) <= max_base64_len:
                break
            # Exceeded budget, reduce resolution and quality for next quick pass
            cur_max_w = int(w * 0.75)
            cur_q = max(15, cur_q - 10)
        else:
            break

    gdiplus.GdiplusShutdown(token)

    if best_result is not None:
        return best_result
    raise RuntimeError("Gdiplus screen capture failed")


def list_windows(visible_only: bool = True) -> list[dict[str, Any]]:
    attach_desktop()
    windows: list[dict[str, Any]] = []

    class RECT(ctypes.Structure):
        _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), ("right", ctypes.c_long), ("bottom", ctypes.c_long)]

    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def enum_proc(hwnd, lparam):
        if visible_only and not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length > 0:
            buf = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buf, length + 1)
            title = buf.value.strip()
            if title:
                r = RECT()
                user32.GetWindowRect(hwnd, ctypes.byref(r))
                pid = ctypes.c_ulong()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                w = r.right - r.left
                h = r.bottom - r.top
                if not visible_only or (w > 0 and h > 0):
                    windows.append({
                        "hwnd": int(hwnd),
                        "pid": pid.value,
                        "title": title,
                        "rect": {"left": r.left, "top": r.top, "right": r.right, "bottom": r.bottom,
                                 "width": w, "height": h}
                    })
        return True

    cb = WNDENUMPROC(enum_proc)
    hdesk = user32.OpenDesktopW("default", 0, False, 0x01FF)
    if hdesk:
        user32.EnumDesktopWindows(hdesk, cb, 0)
    else:
        user32.EnumWindows(cb, 0)

    return windows


def focus_window(hwnd: int | None = None, title: str | None = None) -> dict[str, Any]:
    attach_desktop()
    target_hwnd = None
    target_title = ""

    if hwnd:
        target_hwnd = int(hwnd)
    elif title:
        lowered = title.lower()
        for win in list_windows(visible_only=True):
            if lowered in win["title"].lower():
                target_hwnd = win["hwnd"]
                target_title = win["title"]
                break

    if not target_hwnd or not user32.IsWindow(target_hwnd):
        return {"ok": False, "error": f"Window not found: hwnd={hwnd}, title={title}"}

    fore_wnd = user32.GetForegroundWindow()
    fore_thread = user32.GetWindowThreadProcessId(fore_wnd, None)
    app_thread = kernel32.GetCurrentThreadId()

    if fore_thread != app_thread:
        user32.AttachThreadInput(fore_thread, app_thread, True)
        user32.BringWindowToTop(target_hwnd)
        user32.ShowWindow(target_hwnd, 9)  # SW_RESTORE
        user32.SetForegroundWindow(target_hwnd)
        user32.AttachThreadInput(fore_thread, app_thread, False)
    else:
        user32.BringWindowToTop(target_hwnd)
        user32.ShowWindow(target_hwnd, 9)
        user32.SetForegroundWindow(target_hwnd)

    time.sleep(0.05)
    foreground = int(user32.GetForegroundWindow())
    if foreground != int(target_hwnd):
        return {
            "ok": False,
            "error": "FOCUS_FAILED",
            "hwnd": int(target_hwnd),
            "foreground_hwnd": foreground,
            "title": target_title,
        }
    return {"ok": True, "hwnd": int(target_hwnd), "title": target_title, "foreground_hwnd": foreground}


def mouse_click(x: int, y: int, button: str = "left", clicks: int = 1) -> dict[str, Any]:
    attach_desktop()
    user32.SetCursorPos(int(x), int(y))
    time.sleep(0.03)
    btn = button.lower()
    for _ in range(max(1, int(clicks))):
        if btn == "right":
            user32.mouse_event(MOUSEEVENTF_RIGHTDOWN, 0, 0, 0, 0)
            time.sleep(0.02)
            user32.mouse_event(MOUSEEVENTF_RIGHTUP, 0, 0, 0, 0)
        elif btn == "middle":
            user32.mouse_event(MOUSEEVENTF_MIDDLEDOWN, 0, 0, 0, 0)
            time.sleep(0.02)
            user32.mouse_event(MOUSEEVENTF_MIDDLEUP, 0, 0, 0, 0)
        else:
            user32.mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0, 0)
            time.sleep(0.02)
            user32.mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0, 0)
        if clicks > 1:
            time.sleep(0.05)
    return {"ok": True, "x": int(x), "y": int(y), "button": btn, "clicks": clicks}


def mouse_move(x: int, y: int) -> dict[str, Any]:
    attach_desktop()
    user32.SetCursorPos(int(x), int(y))
    return {"ok": True, "x": int(x), "y": int(y)}


def keyboard_type(text: str, press_enter: bool = False) -> dict[str, Any]:
    attach_desktop()

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [
            ("wVk", wintypes.WORD),
            ("wScan", wintypes.WORD),
            ("dwFlags", wintypes.DWORD),
            ("time", wintypes.DWORD),
            ("dwExtraInfo", ctypes.c_ulonglong),
        ]

    class INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("ki", KEYBDINPUT), ("padding", ctypes.c_ubyte * 16)]

    KEYEVENTF_UNICODE = 0x0004
    KEYEVENTF_KEYUP = 0x0002

    for ch in text:
        inp_down = INPUT()
        inp_down.type = 1  # INPUT_KEYBOARD
        inp_down.ki.wScan = ord(ch)
        inp_down.ki.dwFlags = KEYEVENTF_UNICODE

        inp_up = INPUT()
        inp_up.type = 1
        inp_up.ki.wScan = ord(ch)
        inp_up.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP

        inputs = (INPUT * 2)(inp_down, inp_up)
        user32.SendInput(2, ctypes.byref(inputs), ctypes.sizeof(INPUT))
        time.sleep(0.005)

    if press_enter:
        time.sleep(0.02)
        user32.keybd_event(0x0D, 0, 0, 0)
        time.sleep(0.01)
        user32.keybd_event(0x0D, 0, 2, 0)

    return {"ok": True, "length": len(text), "press_enter": press_enter}


def keyboard_hotkey(keys: list[str]) -> dict[str, Any]:
    attach_desktop()
    vk_codes = []
    for k in keys:
        low = k.lower().strip()
        if low in VK_MAP:
            vk_codes.append(VK_MAP[low])
        elif len(low) == 1:
            vk_codes.append(user32.VkKeyScanW(ord(low)) & 0xFF)

    # Press down
    for vk in vk_codes:
        user32.keybd_event(vk, 0, 0, 0)
        time.sleep(0.01)

    time.sleep(0.05)

    # Release up in reverse
    for vk in reversed(vk_codes):
        user32.keybd_event(vk, 0, 2, 0)
        time.sleep(0.01)

    return {"ok": True, "keys": keys}
