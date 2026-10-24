from __future__ import annotations

"""Marker-aware Windows PHYSICAL_INPUT sink.

One call emits one indivisible input gesture. Paired down/up events use one
SendInput array; Windows guarantees that array is not interspersed with owner
or other injected input. The arbiter revalidates before every gesture.
"""

import ctypes
import ctypes.wintypes as wt
from dataclasses import dataclass
import platform
import secrets
from typing import Any, Mapping, Optional, Protocol

from cua_input_windows import WindowsEventSource

IS_WINDOWS = platform.system().lower() == "windows"
INPUT_MOUSE = 0
INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
MOUSEEVENTF_MOVE = 0x0001
MOUSEEVENTF_ABSOLUTE = 0x8000
MOUSEEVENTF_VIRTUALDESK = 0x4000
SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79


class PhysicalInputSinkError(RuntimeError):
    def __init__(self, code: str, details: Optional[dict[str, Any]] = None):
        super().__init__(code)
        self.code = code
        self.details = details or {}
ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong


class MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wt.LONG),
        ("dy", wt.LONG),
        ("mouseData", wt.DWORD),
        ("dwFlags", wt.DWORD),
        ("time", wt.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wt.WORD),
        ("wScan", wt.WORD),
        ("dwFlags", wt.DWORD),
        ("time", wt.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wt.DWORD), ("wParamL", wt.WORD), ("wParamH", wt.WORD)]
class _INPUTUNION(ctypes.Union):
    _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("union",)
    _fields_ = [("type", wt.DWORD), ("union", _INPUTUNION)]


class SendInputApi(Protocol):
    def send_keyboard_tap(self, vk: int, *, marker: int) -> None: ...
    def send_mouse_click(self, down_flags: int, up_flags: int, *, marker: int) -> None: ...
    def send_mouse_click_at(self, x: int, y: int, down_flags: int, up_flags: int, *, marker: int) -> None: ...
    def send_mouse(self, flags: int, *, data: int, marker: int) -> None: ...
    def send_unicode_char(self, text: str, *, marker: int) -> None: ...
    def send_key_chord(self, keys: list[int], *, marker: int) -> None: ...


class CtypesSendInputApi:
    def __init__(self) -> None:
        if not IS_WINDOWS:
            raise PhysicalInputSinkError("WINDOWS_ONLY")
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.user32.SendInput.argtypes = [wt.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
        self.user32.SendInput.restype = wt.UINT
        self.user32.GetSystemMetrics.argtypes = [ctypes.c_int]
        self.user32.GetSystemMetrics.restype = ctypes.c_int

    def _send_many(self, items: list[INPUT]) -> None:
        from cua_desktop_identity import require_input_desktop, DesktopIdentityError
        try: require_input_desktop()
        except DesktopIdentityError as exc: raise PhysicalInputSinkError(str(exc)) from exc
        ctypes.set_last_error(0)
        array = (INPUT * len(items))(*items)
        sent = int(self.user32.SendInput(len(items), array, ctypes.sizeof(INPUT)))
        if sent != len(items):
            raise PhysicalInputSinkError(
                "SENDINPUT_OUTCOME_UNKNOWN",
                {"sent": sent, "requested": len(items),
                 "winerror": int(ctypes.get_last_error()), "retry_safe": False},
            )
    def send_keyboard_tap(self, vk: int, *, marker: int) -> None:
        if isinstance(vk, bool) or not isinstance(vk, int) or not 0 <= vk <= 0xFF:
            raise PhysicalInputSinkError("PHYSICAL_KEY_INVALID")
        down = INPUT(type=INPUT_KEYBOARD, union=_INPUTUNION(ki=KEYBDINPUT(vk, 0, 0, 0, marker)))
        up = INPUT(type=INPUT_KEYBOARD, union=_INPUTUNION(ki=KEYBDINPUT(vk, 0, KEYEVENTF_KEYUP, 0, marker)))
        self._send_many([down, up])

    def send_mouse_click(self, down_flags: int, up_flags: int, *, marker: int) -> None:
        if not all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in (down_flags, up_flags)):
            raise PhysicalInputSinkError("PHYSICAL_MOUSE_FLAGS_INVALID")
        down = INPUT(type=INPUT_MOUSE, union=_INPUTUNION(mi=MOUSEINPUT(0, 0, 0, down_flags, 0, marker)))
        up = INPUT(type=INPUT_MOUSE, union=_INPUTUNION(mi=MOUSEINPUT(0, 0, 0, up_flags, 0, marker)))
        self._send_many([down, up])

    def send_unicode_char(self, text, *, marker):
        if not isinstance(text, str) or len(text) != 1:
            raise PhysicalInputSinkError("PHYSICAL_UNICODE_CHAR_INVALID")
        raw = text.encode("utf-16-le")
        items = []
        for i in range(0, len(raw), 2):
            unit = int.from_bytes(raw[i:i+2], "little")
            items.extend([INPUT(type=INPUT_KEYBOARD, union=_INPUTUNION(ki=KEYBDINPUT(0, unit, 4, 0, marker))),
                          INPUT(type=INPUT_KEYBOARD, union=_INPUTUNION(ki=KEYBDINPUT(0, unit, 6, 0, marker)))])
        self._send_many(items)

    def send_key_chord(self, keys, *, marker):
        if not isinstance(keys, list) or not 1 <= len(keys) <= 8 or any(type(k) is not int or not 0 <= k <= 255 for k in keys):
            raise PhysicalInputSinkError("PHYSICAL_CHORD_INVALID")
        items = [INPUT(type=INPUT_KEYBOARD, union=_INPUTUNION(ki=KEYBDINPUT(k, 0, 0, 0, marker))) for k in keys]
        items += [INPUT(type=INPUT_KEYBOARD, union=_INPUTUNION(ki=KEYBDINPUT(k, 0, KEYEVENTF_KEYUP, 0, marker))) for k in reversed(keys)]
        self._send_many(items)

    def send_mouse_click_at(self, x: int, y: int, down_flags: int, up_flags: int, *, marker: int) -> None:
        if any(isinstance(v, bool) or not isinstance(v, int) for v in (x, y)):
            raise PhysicalInputSinkError("PHYSICAL_POINT_INVALID")
        if not all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in (down_flags, up_flags)):
            raise PhysicalInputSinkError("PHYSICAL_MOUSE_FLAGS_INVALID")
        left = int(self.user32.GetSystemMetrics(SM_XVIRTUALSCREEN))
        top = int(self.user32.GetSystemMetrics(SM_YVIRTUALSCREEN))
        width = int(self.user32.GetSystemMetrics(SM_CXVIRTUALSCREEN))
        height = int(self.user32.GetSystemMetrics(SM_CYVIRTUALSCREEN))
        if width <= 1 or height <= 1 or not (left <= x < left + width and top <= y < top + height):
            raise PhysicalInputSinkError("PHYSICAL_POINT_OUTSIDE_VIRTUAL_SCREEN", {
                "point": [x, y], "virtual_screen": [left, top, left + width, top + height],
            })
        dx = round((x - left) * 65535 / (width - 1))
        dy = round((y - top) * 65535 / (height - 1))
        move_flags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK
        move = INPUT(type=INPUT_MOUSE, union=_INPUTUNION(mi=MOUSEINPUT(dx, dy, 0, move_flags, 0, marker)))
        down = INPUT(type=INPUT_MOUSE, union=_INPUTUNION(mi=MOUSEINPUT(0, 0, 0, down_flags, 0, marker)))
        up = INPUT(type=INPUT_MOUSE, union=_INPUTUNION(mi=MOUSEINPUT(0, 0, 0, up_flags, 0, marker)))
        self._send_many([move, down, up])

    def send_mouse(self, flags: int, *, data: int, marker: int) -> None:
        if isinstance(flags, bool) or not isinstance(flags, int) or flags <= 0:
            raise PhysicalInputSinkError("PHYSICAL_MOUSE_FLAGS_INVALID")
        if isinstance(data, bool) or not isinstance(data, int):
            raise PhysicalInputSinkError("PHYSICAL_MOUSE_DATA_INVALID")
        item = INPUT(type=INPUT_MOUSE, union=_INPUTUNION(mi=MOUSEINPUT(0, 0, data & 0xFFFFFFFF, flags, 0, marker)))
        self._send_many([item])

    def send_mouse_move_at(self, x, y, *, marker):
        # Coordinate conversion is identical to click_at, but send only MOVE.
        outer = self
        class MoveOnly:
            user32 = outer.user32
            def _send_many(_, items): outer._send_many(items[:1])
        CtypesSendInputApi.send_mouse_click_at(MoveOnly(), x, y, 2, 4, marker=marker)


def allocate_marker() -> int:
    marker = 0
    while marker == 0:
        marker = secrets.randbits(32)
    return marker
@dataclass
class MarkedWindowsInputSink:
    event_source: WindowsEventSource
    sequence_id: str
    api: Optional[SendInputApi] = None
    marker: int = 0
    marker_ttl_seconds: float = 2.0

    def __post_init__(self) -> None:
        if not self.sequence_id:
            raise ValueError("sequence_id is required")
        if self.marker == 0:
            self.marker = allocate_marker()
        if not 0 < self.marker <= 0xFFFFFFFF:
            raise ValueError("marker must be a non-zero ULONG")
        if self.marker_ttl_seconds <= 0:
            raise ValueError("marker_ttl_seconds must be > 0")
        if self.api is None:
            self.api = CtypesSendInputApi()

    def __call__(self, event: Mapping[str, Any]) -> None:
        kind = str(event.get("kind") or "")
        if kind == "mouse_move_at":
            self.event_source.register_synthetic_marker(self.marker, kind="raw_mouse", ttl_seconds=self.marker_ttl_seconds)
            self.api.send_mouse_move_at(event.get("x"), event.get("y"), marker=self.marker)
            return
        if kind in {"unicode_char", "key_chord"}:
            self.event_source.register_synthetic_marker(self.marker, kind="raw_keyboard", ttl_seconds=self.marker_ttl_seconds)
            if kind == "unicode_char": self.api.send_unicode_char(event.get("text"), marker=self.marker)
            else: self.api.send_key_chord(event.get("keys"), marker=self.marker)
            return
        if kind == "key_tap":
            self.event_source.register_synthetic_marker(
                self.marker, kind="raw_keyboard", ttl_seconds=self.marker_ttl_seconds
            )
            self.api.send_keyboard_tap(event.get("vk"), marker=self.marker)
            return
        if kind == "mouse_click":
            self.event_source.register_synthetic_marker(
                self.marker, kind="raw_mouse", ttl_seconds=self.marker_ttl_seconds
            )
            self.api.send_mouse_click(
                event.get("down_flags"), event.get("up_flags"), marker=self.marker
            )
            return
        if kind == "mouse_click_at":
            self.event_source.register_synthetic_marker(
                self.marker, kind="raw_mouse", ttl_seconds=self.marker_ttl_seconds
            )
            self.api.send_mouse_click_at(
                event.get("x"), event.get("y"), event.get("down_flags"), event.get("up_flags"), marker=self.marker
            )
            return
        if kind == "mouse":
            self.event_source.register_synthetic_marker(
                self.marker, kind="raw_mouse", ttl_seconds=self.marker_ttl_seconds
            )
            self.api.send_mouse(
                event.get("flags"), data=event.get("data", 0), marker=self.marker
            )
            return
        raise PhysicalInputSinkError("PHYSICAL_EVENT_UNSUPPORTED", {"kind": kind})


def key_tap_event(vk: int) -> dict[str, Any]:
    return {"kind": "key_tap", "vk": vk}


def mouse_click_event(down_flags: int, up_flags: int) -> dict[str, Any]:
    return {"kind": "mouse_click", "down_flags": down_flags, "up_flags": up_flags}

def mouse_click_at_event(x: int, y: int, down_flags: int, up_flags: int) -> dict[str, Any]:
    return {"kind": "mouse_click_at", "x": x, "y": y, "down_flags": down_flags, "up_flags": up_flags}


def mouse_event(flags: int, *, data: int = 0) -> dict[str, Any]:
    return {"kind": "mouse", "flags": flags, "data": data}
