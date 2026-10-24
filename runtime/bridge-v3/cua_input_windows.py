from __future__ import annotations
"""Windows Raw Input + foreground event source for the CUA human-input arbiter.

This module never injects input. It only observes:
- keyboard/mouse Raw Input delivered to a private message-only window;
- EVENT_SYSTEM_FOREGROUND WinEvents.

Live safety still requires owner-PC contention testing. Import remains safe on
non-Windows hosts so the contract can be unit-tested offline.
"""
import ctypes
import ctypes.wintypes as wt
from dataclasses import dataclass
import platform
import threading
import time
from typing import Callable, Optional, Protocol

IS_WINDOWS = platform.system().lower() == "windows"

RIDEV_REMOVE = 0x00000001
RIDEV_INPUTSINK = 0x00000100
RID_INPUT = 0x10000003
RIM_TYPEMOUSE = 0
RIM_TYPEKEYBOARD = 1
WM_INPUT = 0x00FF
WM_CLOSE = 0x0010
WM_DESTROY = 0x0002
HWND_MESSAGE = -3
HID_USAGE_PAGE_GENERIC = 0x01
HID_USAGE_GENERIC_MOUSE = 0x02
HID_USAGE_GENERIC_KEYBOARD = 0x06

EVENT_SYSTEM_FOREGROUND = 0x0003
WINEVENT_OUTOFCONTEXT = 0x0000


class WindowsEventSourceUnavailable(RuntimeError):
    def __init__(self, code: str, details: Optional[dict] = None):
        super().__init__(code)
        self.code = code
        self.details = details or {}


class RAWINPUTDEVICE(ctypes.Structure):
    _fields_ = [
        ("usUsagePage", wt.USHORT),
        ("usUsage", wt.USHORT),
        ("dwFlags", wt.DWORD),
        ("hwndTarget", wt.HWND),
    ]


class RAWINPUTHEADER(ctypes.Structure):
    _fields_ = [
        ("dwType", wt.DWORD),
        ("dwSize", wt.DWORD),
        ("hDevice", wt.HANDLE),
        ("wParam", wt.WPARAM),
    ]


class RAWKEYBOARD(ctypes.Structure):
    _fields_ = [("MakeCode", wt.USHORT), ("Flags", wt.USHORT), ("Reserved", wt.USHORT),
                ("VKey", wt.USHORT), ("Message", wt.UINT), ("ExtraInformation", wt.ULONG)]

class _RAWMOUSE_BUTTONS(ctypes.Structure):
    _fields_ = [("usButtonFlags", wt.USHORT), ("usButtonData", wt.USHORT)]
class _RAWMOUSE_UNION(ctypes.Union):
    _anonymous_ = ("buttons",); _fields_ = [("ulButtons", wt.ULONG), ("buttons", _RAWMOUSE_BUTTONS)]
class RAWMOUSE(ctypes.Structure):
    _anonymous_ = ("u",); _fields_ = [("usFlags", wt.USHORT), ("u", _RAWMOUSE_UNION),
        ("ulRawButtons", wt.ULONG), ("lLastX", wt.LONG), ("lLastY", wt.LONG), ("ulExtraInformation", wt.ULONG)]

@dataclass(frozen=True)
class RawInputEvent:
    kind: str
    device: int
    extra_info: int | None


if hasattr(ctypes, "WINFUNCTYPE"):
    WNDPROC = ctypes.WINFUNCTYPE(wt.LPARAM, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)
    WINEVENTPROC = ctypes.WINFUNCTYPE(
        None, wt.HANDLE, wt.DWORD, wt.HWND, wt.LONG, wt.LONG, wt.DWORD, wt.DWORD
    )
else:
    WNDPROC = ctypes.CFUNCTYPE(wt.LPARAM, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)
    WINEVENTPROC = ctypes.CFUNCTYPE(
        None, wt.HANDLE, wt.DWORD, wt.HWND, wt.LONG, wt.LONG, wt.DWORD, wt.DWORD
    )


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.UINT),
        ("style", wt.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wt.HINSTANCE),
        ("hIcon", wt.HICON),
        ("hCursor", wt.HANDLE),
        ("hbrBackground", wt.HBRUSH),
        ("lpszMenuName", wt.LPCWSTR),
        ("lpszClassName", wt.LPCWSTR),
        ("hIconSm", wt.HICON),
    ]


class Win32InputApi(Protocol):
    def run(
        self,
        on_raw_input: Callable[[RawInputEvent], None],
        on_foreground: Callable[[int], None],
        ready: threading.Event,
        stop: threading.Event,
    ) -> None: ...

    def request_stop(self) -> None: ...


class CtypesWin32InputApi:
    """Owns all Win32 handles and executes them on one message-loop thread."""

    def __init__(self) -> None:
        if not IS_WINDOWS:
            raise WindowsEventSourceUnavailable("WINDOWS_ONLY")
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._hwnd: int = 0
        self._hook = None
        self._wndproc = None
        self._wineventproc = None
        self._class_atom = 0
        self._raw_registered = False
        self._class_name = f"FFCUAInputSink_{id(self):x}"

        # Explicit signatures are mandatory on 64-bit Python. ctypes otherwise
        # defaults to c_int and can truncate HWND/HANDLE values.
        self.kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
        self.kernel32.GetModuleHandleW.restype = wt.HMODULE
        self.user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
        self.user32.RegisterClassExW.restype = wt.ATOM
        self.user32.CreateWindowExW.argtypes = [
            wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID,
        ]
        self.user32.CreateWindowExW.restype = wt.HWND
        self.user32.RegisterRawInputDevices.argtypes = [
            ctypes.POINTER(RAWINPUTDEVICE), wt.UINT, wt.UINT
        ]
        self.user32.RegisterRawInputDevices.restype = wt.BOOL
        self.user32.GetRawInputData.argtypes = [
            wt.HANDLE, wt.UINT, wt.LPVOID, ctypes.POINTER(wt.UINT), wt.UINT
        ]
        self.user32.GetRawInputData.restype = wt.UINT
        self.user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
        self.user32.DefWindowProcW.restype = wt.LPARAM
        self.user32.SetWinEventHook.argtypes = [
            wt.DWORD, wt.DWORD, wt.HMODULE, WINEVENTPROC,
            wt.DWORD, wt.DWORD, wt.DWORD,
        ]
        self.user32.SetWinEventHook.restype = wt.HANDLE
        self.user32.UnhookWinEvent.argtypes = [wt.HANDLE]
        self.user32.UnhookWinEvent.restype = wt.BOOL
        self.user32.GetForegroundWindow.argtypes = []
        self.user32.GetForegroundWindow.restype = wt.HWND
        self.user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
        self.user32.GetMessageW.restype = wt.BOOL
        self.user32.TranslateMessage.argtypes = [ctypes.POINTER(wt.MSG)]
        self.user32.TranslateMessage.restype = wt.BOOL
        self.user32.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
        self.user32.DispatchMessageW.restype = wt.LPARAM
        self.user32.DestroyWindow.argtypes = [wt.HWND]
        self.user32.DestroyWindow.restype = wt.BOOL
        self.user32.IsWindow.argtypes = [wt.HWND]
        self.user32.IsWindow.restype = wt.BOOL
        self.user32.PostQuitMessage.argtypes = [ctypes.c_int]
        self.user32.PostQuitMessage.restype = None
        self.user32.PostMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
        self.user32.PostMessageW.restype = wt.BOOL
        self.user32.UnregisterClassW.argtypes = [wt.LPCWSTR, wt.HINSTANCE]
        self.user32.UnregisterClassW.restype = wt.BOOL

    @staticmethod
    def _raise_last(code: str) -> None:
        err = ctypes.get_last_error()
        raise WindowsEventSourceUnavailable(code, {"winerror": int(err)})

    def _read_raw_event(self, hraw: int) -> Optional[RawInputEvent]:
        size = wt.UINT(0)
        header_size = ctypes.sizeof(RAWINPUTHEADER)
        result = self.user32.GetRawInputData(
            wt.HANDLE(hraw), RID_INPUT, None, ctypes.byref(size), header_size
        )
        if result == 0xFFFFFFFF:
            self._raise_last("GET_RAW_INPUT_SIZE_FAILED")
        if size.value < header_size:
            raise WindowsEventSourceUnavailable(
                "RAW_INPUT_SIZE_INVALID", {"bytes": int(size.value), "header": header_size}
            )
        buf = ctypes.create_string_buffer(size.value)
        copied = self.user32.GetRawInputData(
            wt.HANDLE(hraw), RID_INPUT, buf, ctypes.byref(size), header_size
        )
        if copied == 0xFFFFFFFF:
            self._raise_last("GET_RAW_INPUT_DATA_FAILED")
        if copied < header_size:
            raise WindowsEventSourceUnavailable(
                "RAW_INPUT_TRUNCATED", {"bytes": int(copied), "header": header_size}
            )
        header = RAWINPUTHEADER.from_buffer_copy(buf.raw[:header_size])
        payload = buf.raw[header_size:copied]
        device = int(header.hDevice or 0)
        if header.dwType == RIM_TYPEMOUSE:
            extra = RAWMOUSE.from_buffer_copy(payload[:ctypes.sizeof(RAWMOUSE)]).ulExtraInformation if len(payload) >= ctypes.sizeof(RAWMOUSE) else None
            return RawInputEvent("raw_mouse", device, None if extra is None else int(extra))
        if header.dwType == RIM_TYPEKEYBOARD:
            extra = RAWKEYBOARD.from_buffer_copy(payload[:ctypes.sizeof(RAWKEYBOARD)]).ExtraInformation if len(payload) >= ctypes.sizeof(RAWKEYBOARD) else None
            return RawInputEvent("raw_keyboard", device, None if extra is None else int(extra))
        return None

    def _register_raw_input(self, hwnd: int) -> None:
        devices = (RAWINPUTDEVICE * 2)(
            RAWINPUTDEVICE(HID_USAGE_PAGE_GENERIC, HID_USAGE_GENERIC_MOUSE, RIDEV_INPUTSINK, wt.HWND(hwnd)),
            RAWINPUTDEVICE(HID_USAGE_PAGE_GENERIC, HID_USAGE_GENERIC_KEYBOARD, RIDEV_INPUTSINK, wt.HWND(hwnd)),
        )
        if not self.user32.RegisterRawInputDevices(devices, len(devices), ctypes.sizeof(RAWINPUTDEVICE)):
            self._raise_last("REGISTER_RAW_INPUT_FAILED")
        self._raw_registered = True

    def _unregister_raw_input(self) -> None:
        if not self._raw_registered:
            return
        devices = (RAWINPUTDEVICE * 2)(
            RAWINPUTDEVICE(HID_USAGE_PAGE_GENERIC, HID_USAGE_GENERIC_MOUSE, RIDEV_REMOVE, None),
            RAWINPUTDEVICE(HID_USAGE_PAGE_GENERIC, HID_USAGE_GENERIC_KEYBOARD, RIDEV_REMOVE, None),
        )
        if self.user32.RegisterRawInputDevices(devices, len(devices), ctypes.sizeof(RAWINPUTDEVICE)):
            self._raw_registered = False

    def _cleanup(self, hinstance: int) -> None:
        if self._hook:
            try:
                self.user32.UnhookWinEvent(self._hook)
            except Exception:
                pass
            self._hook = None
        try:
            self._unregister_raw_input()
        except Exception:
            pass
        if self._hwnd:
            try:
                if self.user32.IsWindow(wt.HWND(self._hwnd)):
                    self.user32.DestroyWindow(wt.HWND(self._hwnd))
            except Exception:
                pass
            self._hwnd = 0
        if self._class_atom:
            try:
                self.user32.UnregisterClassW(self._class_name, hinstance)
            except Exception:
                pass
            self._class_atom = 0

    def run(
        self,
        on_raw_input: Callable[[RawInputEvent], None],
        on_foreground: Callable[[int], None],
        ready: threading.Event,
        stop: threading.Event,
    ) -> None:
        hinstance = self.kernel32.GetModuleHandleW(None)
        if not hinstance:
            self._raise_last("GET_MODULE_HANDLE_FAILED")

        def wndproc(hwnd, msg, wparam, lparam):
            try:
                if msg == WM_INPUT:
                    event = self._read_raw_event(int(lparam))
                    if event:
                        on_raw_input(event)
                    return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)
                if msg == WM_CLOSE:
                    self.user32.DestroyWindow(hwnd)
                    return 0
                if msg == WM_DESTROY:
                    self.user32.PostQuitMessage(0)
                    return 0
            except Exception:
                # Fail safe: inability to parse a registered Raw Input message
                # becomes owner activity rather than a false-negative silence.
                if msg == WM_INPUT:
                    try:
                        on_raw_input("raw_unknown")
                    except Exception:
                        pass
                return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)
            return self.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        try:
            self._wndproc = WNDPROC(wndproc)
            wc = WNDCLASSEXW()
            wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
            wc.lpfnWndProc = self._wndproc
            wc.hInstance = hinstance
            wc.lpszClassName = self._class_name
            atom = self.user32.RegisterClassExW(ctypes.byref(wc))
            if not atom:
                self._raise_last("REGISTER_WINDOW_CLASS_FAILED")
            self._class_atom = int(atom)

            hwnd = self.user32.CreateWindowExW(
                0, self._class_name, self._class_name, 0, 0, 0, 0, 0,
                wt.HWND(HWND_MESSAGE), None, hinstance, None,
            )
            if not hwnd:
                self._raise_last("CREATE_MESSAGE_WINDOW_FAILED")
            self._hwnd = int(hwnd)
            self._register_raw_input(self._hwnd)

            def winevent(_hook, event, hwnd, _obj, _child, _thread, _time):
                if event == EVENT_SYSTEM_FOREGROUND and hwnd:
                    try:
                        on_foreground(int(hwnd))
                    except Exception:
                        pass

            self._wineventproc = WINEVENTPROC(winevent)
            hook = self.user32.SetWinEventHook(
                EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, None,
                self._wineventproc, 0, 0, WINEVENT_OUTOFCONTEXT,
            )
            if not hook:
                self._raise_last("SET_WINEVENT_HOOK_FAILED")
            self._hook = hook

            initial = self.user32.GetForegroundWindow()
            if initial:
                on_foreground(int(initial))
            ready.set()

            msg = wt.MSG()
            while not stop.is_set():
                rc = self.user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                if rc == -1:
                    self._raise_last("GET_MESSAGE_FAILED")
                if rc == 0:
                    break
                self.user32.TranslateMessage(ctypes.byref(msg))
                self.user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            self._cleanup(hinstance)

    def request_stop(self) -> None:
        hwnd = self._hwnd
        if hwnd:
            self.user32.PostMessageW(wt.HWND(hwnd), WM_CLOSE, 0, 0)


class WindowsEventSource:
    """Threaded, fail-closed lifecycle around the Win32 message pump."""

    def __init__(
        self,
        on_owner_input: Callable[[str], None],
        on_foreground: Callable[[int], None],
        *,
        api: Optional[Win32InputApi] = None,
    ):
        if api is None and not IS_WINDOWS:
            raise WindowsEventSourceUnavailable("WINDOWS_ONLY")
        self.on_owner_input = on_owner_input
        self.on_foreground = on_foreground
        self._api = api or CtypesWin32InputApi()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._failure: Optional[BaseException] = None
        self._lock = threading.Lock()
        self._synthetic_lock = threading.Lock()
        self._synthetic_markers: dict[tuple[str, int], int] = {}

    def start(self, timeout_seconds: float = 3.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._ready.clear()
            self._failure = None
            self._thread = threading.Thread(target=self._run, daemon=True, name="cua-input-events")
            self._thread.start()
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if self._ready.wait(0.01):
                if self._failure is not None:
                    raise WindowsEventSourceUnavailable(
                        "WINDOWS_EVENT_SOURCE_START_FAILED",
                        {"error": f"{type(self._failure).__name__}: {self._failure}"},
                    ) from self._failure
                if not self._thread or not self._thread.is_alive():
                    raise WindowsEventSourceUnavailable("WINDOWS_EVENT_SOURCE_EXITED_DURING_START")
                return
            if self._failure is not None:
                raise WindowsEventSourceUnavailable(
                    "WINDOWS_EVENT_SOURCE_START_FAILED",
                    {"error": f"{type(self._failure).__name__}: {self._failure}"},
                ) from self._failure
            if self._thread and not self._thread.is_alive():
                break
        self.stop(timeout_seconds=0.5)
        if self._failure is not None:
            raise WindowsEventSourceUnavailable(
                "WINDOWS_EVENT_SOURCE_START_FAILED",
                {"error": f"{type(self._failure).__name__}: {self._failure}"},
            ) from self._failure
        raise WindowsEventSourceUnavailable("WINDOWS_EVENT_SOURCE_START_TIMEOUT")

    def stop(self, timeout_seconds: float = 2.0) -> None:
        self._stop.set()
        try:
            self._api.request_stop()
        except Exception:
            pass
        thread = self._thread
        if thread and thread is not threading.current_thread():
            thread.join(max(0.0, timeout_seconds))

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive() and self._ready.is_set() and self._failure is None)

    @property
    def failure(self) -> Optional[str]:
        if self._failure is None:
            return None
        return f"{type(self._failure).__name__}: {self._failure}"

    def _run(self) -> None:
        try:
            self._api.run(self._safe_owner_input, self._safe_foreground, self._ready, self._stop)
            if not self._stop.is_set():
                raise WindowsEventSourceUnavailable("WINDOWS_EVENT_SOURCE_EXITED")
        except BaseException as exc:
            self._failure = exc
            self._ready.set()

    def register_synthetic_marker(self, marker: int, *, kind: str = "raw_keyboard", ttl_seconds: float = 2.0) -> None:
        if kind not in {"raw_keyboard", "raw_mouse"}: raise ValueError("unsupported synthetic kind")
        if not isinstance(marker, int) or marker < 0 or marker > 0xFFFFFFFF: raise ValueError("marker must fit ULONG")
        if ttl_seconds <= 0: raise ValueError("ttl_seconds must be > 0")
        with self._synthetic_lock:
            self._synthetic_markers[(kind, marker)] = time.monotonic_ns() + int(ttl_seconds * 1_000_000_000)

    def _safe_owner_input(self, event: RawInputEvent | str) -> None:
        if isinstance(event, str): event = RawInputEvent(event, 0, None)
        if event.kind not in {"raw_mouse", "raw_keyboard", "raw_unknown"}: return
        synthetic = False
        now = time.monotonic_ns()
        if event.extra_info is not None:
            with self._synthetic_lock:
                expired = [key for key, deadline in self._synthetic_markers.items() if deadline < now]
                for key in expired: self._synthetic_markers.pop(key, None)
                synthetic = (event.kind, event.extra_info) in self._synthetic_markers
        try:
            self.on_owner_input("synthetic" if synthetic else event.kind)
        except Exception:
            pass

    def _safe_foreground(self, hwnd: int) -> None:
        if not isinstance(hwnd, int) or hwnd <= 0:
            return
        try:
            self.on_foreground(hwnd)
        except Exception:
            pass
