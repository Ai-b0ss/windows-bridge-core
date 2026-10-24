from __future__ import annotations

import ctypes
import ctypes.wintypes
import platform
from dataclasses import dataclass
from typing import Any, Protocol

from cua_native_core import NativeError

WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E
WM_SETTEXT = 0x000C
WM_COMMAND = 0x0111
BM_GETCHECK = 0x00F0
BM_CLICK = 0x00F5
CB_GETCURSEL = 0x0147
CB_SETCURSEL = 0x014E
LB_GETCURSEL = 0x0188
LB_SETCURSEL = 0x0186
CBN_SELCHANGE = 1
LBN_SELCHANGE = 1
SMTO_BLOCK = 0x0001
SMTO_ABORTIFHUNG = 0x0002
GWL_STYLE = -16
BS_TYPEMASK = 0x000F
BS_CHECKBOX_TYPES = {0x0002, 0x0003, 0x0005, 0x0006}

_EDIT_CLASSES = {"edit", "richedit", "richedit20a", "richedit20w", "richedit50w"}
_BUTTON_CLASS = "button"
_COMBOBOX_CLASS = "combobox"
_LISTBOX_CLASS = "listbox"


class HwndTransport(Protocol):
    def is_window(self, hwnd: int) -> bool: ...
    def window_info(self, hwnd: int) -> dict[str, Any]: ...
    def child_windows(self, hwnd: int) -> list[int]: ...
    def get_text(self, hwnd: int) -> str: ...
    def send_timeout(self, hwnd: int, msg: int, wparam: int = 0, lparam: int | str = 0, timeout_ms: int = 2000) -> int: ...


@dataclass
class Win32Transport:
    timeout_ms: int = 2000

    def __post_init__(self) -> None:
        if platform.system().lower() != "windows":
            raise NativeError("HWND_WINDOWS_ONLY", "HWND message backend requires Windows")
        self.user32 = ctypes.windll.user32
        ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong
        self.user32.SendMessageTimeoutW.argtypes = [
            ctypes.wintypes.HWND,
            ctypes.wintypes.UINT,
            ctypes.c_size_t,
            ctypes.c_ssize_t,
            ctypes.wintypes.UINT,
            ctypes.wintypes.UINT,
            ctypes.POINTER(ULONG_PTR),
        ]
        self.user32.SendMessageTimeoutW.restype = ctypes.c_ssize_t

    def is_window(self, hwnd: int) -> bool:
        return bool(self.user32.IsWindow(hwnd))

    def foreground_hwnd(self) -> int:
        return int(self.user32.GetForegroundWindow() or 0)

    def cursor_position(self) -> tuple[int, int] | None:
        point = ctypes.wintypes.POINT()
        if not self.user32.GetCursorPos(ctypes.byref(point)):
            # GetCursorPos requires the input desktop. On a proven inactive
            # desktop, lack of cursor observation is expected, not an action
            # failure. Never report a fabricated preserved cursor.
            if self._on_inactive_desktop():
                return None
            raise NativeError("HWND_QUERY_FAILED", "GetCursorPos failed")
        return int(point.x), int(point.y)

    def _on_inactive_desktop(self) -> bool:
        u = self.user32
        u.GetThreadDesktop.argtypes = [ctypes.wintypes.DWORD]
        u.GetThreadDesktop.restype = ctypes.wintypes.HANDLE
        u.OpenInputDesktop.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
        u.OpenInputDesktop.restype = ctypes.wintypes.HANDLE
        u.CloseDesktop.argtypes = [ctypes.wintypes.HANDLE]
        u.GetUserObjectInformationW.argtypes = [
            ctypes.wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
            ctypes.wintypes.DWORD, ctypes.POINTER(ctypes.wintypes.DWORD),
        ]
        thread = u.GetThreadDesktop(ctypes.windll.kernel32.GetCurrentThreadId())
        input_desktop = u.OpenInputDesktop(0, False, 1)
        if not input_desktop:
            return False
        if not thread:
            u.CloseDesktop(input_desktop)
            return False
        def name(handle):
            buf = ctypes.create_unicode_buffer(256)
            size = ctypes.wintypes.DWORD()
            if not u.GetUserObjectInformationW(handle, 2, buf, ctypes.sizeof(buf), ctypes.byref(size)):
                return None
            return buf.value
        try:
            current_name, input_name = name(thread), name(input_desktop)
            return bool(current_name and input_name and current_name != input_name)
        finally:
            u.CloseDesktop(input_desktop)

    def window_info(self, hwnd: int) -> dict[str, Any]:
        if not self.is_window(hwnd):
            raise NativeError("STALE_TARGET", "HWND is no longer valid", {"hwnd": hwnd})
        pid = ctypes.wintypes.DWORD(0)
        self.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        cls = ctypes.create_unicode_buffer(256)
        if not self.user32.GetClassNameW(hwnd, cls, len(cls)):
            raise NativeError("HWND_QUERY_FAILED", "GetClassNameW failed", {"hwnd": hwnd})
        control_id = int(self.user32.GetDlgCtrlID(hwnd))
        parent_hwnd = int(self.user32.GetParent(hwnd) or 0)
        self.user32.GetWindowLongPtrW.restype = ctypes.c_ssize_t
        style = int(self.user32.GetWindowLongPtrW(hwnd, GWL_STYLE))
        rect = ctypes.wintypes.RECT()
        if not self.user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            raise NativeError("HWND_QUERY_FAILED", "GetWindowRect failed", {"hwnd": hwnd})
        return {
            "hwnd": int(hwnd),
            "pid": int(pid.value),
            "class_name": cls.value,
            "control_id": control_id,
            "parent_hwnd": parent_hwnd,
            "style": style,
            "enabled": bool(self.user32.IsWindowEnabled(hwnd)),
            "geometry": {
                "left": int(rect.left), "top": int(rect.top),
                "right": int(rect.right), "bottom": int(rect.bottom),
            },
        }

    def child_windows(self, hwnd: int) -> list[int]:
        if not self.is_window(hwnd):
            raise NativeError("STALE_TARGET", "Root HWND is no longer valid", {"hwnd": hwnd})
        out: list[int] = []
        CALLBACK = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        @CALLBACK
        def cb(child: int, _lparam: int) -> bool:
            out.append(int(child))
            return True

        self.user32.EnumChildWindows(hwnd, cb, 0)
        return out

    def get_text(self, hwnd: int) -> str:
        if not self.is_window(hwnd):
            raise NativeError("STALE_TARGET", "HWND is no longer valid", {"hwnd": hwnd})
        length = self.send_timeout(hwnd, WM_GETTEXTLENGTH, 0, 0, self.timeout_ms)
        if length < 0 or length > 1_000_000:
            raise NativeError("HWND_TEXT_LENGTH_INVALID", "Control returned invalid text length", {"hwnd": hwnd, "length": length})
        buf = ctypes.create_unicode_buffer(max(1, length + 1))
        ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong
        result = ULONG_PTR(0)
        ok = self.user32.SendMessageTimeoutW(
            hwnd, WM_GETTEXT, len(buf), ctypes.cast(buf, ctypes.c_void_p).value or 0,
            SMTO_BLOCK | SMTO_ABORTIFHUNG, self.timeout_ms, ctypes.byref(result),
        )
        if not ok:
            raise NativeError("HWND_MESSAGE_TIMEOUT", "WM_GETTEXT failed or timed out", {"hwnd": hwnd, "timeout_ms": self.timeout_ms})
        return buf.value

    def send_timeout(self, hwnd: int, msg: int, wparam: int = 0, lparam: int | str = 0, timeout_ms: int = 2000) -> int:
        if not self.is_window(hwnd):
            raise NativeError("STALE_TARGET", "HWND is no longer valid", {"hwnd": hwnd})
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms < 1 or timeout_ms > 10000:
            raise NativeError("INVALID_ARGUMENT", "timeout_ms must be between 1 and 10000")
        ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong
        result = ULONG_PTR(0)
        if isinstance(lparam, str):
            text = ctypes.create_unicode_buffer(lparam)
            lparam_value = ctypes.cast(text, ctypes.c_void_p).value or 0
        elif isinstance(lparam, int) and not isinstance(lparam, bool):
            text = None
            lparam_value = lparam
        else:
            raise NativeError("INVALID_ARGUMENT", "lparam must be integer or string")
        ok = self.user32.SendMessageTimeoutW(
            hwnd, msg, wparam, lparam_value,
            SMTO_BLOCK | SMTO_ABORTIFHUNG, timeout_ms, ctypes.byref(result),
        )
        if not ok:
            raise NativeError("HWND_MESSAGE_TIMEOUT", "SendMessageTimeoutW failed or timed out", {"hwnd": hwnd, "message": msg, "timeout_ms": timeout_ms})
        return int(ctypes.c_ssize_t(result.value).value)


class HwndMessageBackend:
    route = "HWND_MESSAGE"

    def __init__(self, transport: HwndTransport | None = None, *, timeout_ms: int = 2000):
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms < 1 or timeout_ms > 10000:
            raise NativeError("INVALID_ARGUMENT", "timeout_ms must be between 1 and 10000")
        self.timeout_ms = timeout_ms
        self.transport = transport if transport is not None else Win32Transport(timeout_ms=timeout_ms)

    def capabilities(self) -> dict[str, Any]:
        return {
            "engine": "win32-hwnd-message",
            "semantic_only": True,
            "physical_input": False,
            "arbitrary_messages": False,
            "background_safe_actions": ["set_value", "invoke", "toggle", "select_index"],
            "desktop_exclusive_actions": [],
            "supported_classes": sorted(_EDIT_CLASSES | {_BUTTON_CLASS, _COMBOBOX_CLASS, _LISTBOX_CLASS}),
            "timeout_ms": self.timeout_ms,
            "selection_notification": "WM_COMMAND(CBN_SELCHANGE/LBN_SELCHANGE)",
            "mutating_timeout_retry_safe": False,
        }

    def fingerprint(self, target: dict[str, Any]) -> dict[str, Any]:
        hwnd = self._target_hwnd(target)
        info = self.transport.window_info(hwnd)
        return {"hwnd": info["hwnd"], "pid": info["pid"], "class_name": info["class_name"]}

    def snapshot(self, target: dict[str, Any], options: dict[str, Any]) -> list[dict[str, Any]]:
        root = self._target_hwnd(target)
        hwnds = [root] + self.transport.child_windows(root)
        out: list[dict[str, Any]] = []
        max_items = options.get("max_items", 500)
        if isinstance(max_items, bool) or not isinstance(max_items, int) or not 1 <= max_items <= 5000:
            raise NativeError("INVALID_ARGUMENT", "max_items must be between 1 and 5000")
        for hwnd in hwnds[:max_items]:
            try:
                entity = self._entity(hwnd)
            except NativeError as exc:
                if exc.code == "STALE_TARGET":
                    continue
                raise
            if entity["actions"]:
                out.append(entity)
        return out

    def resolve(self, target: dict[str, Any], identity: dict[str, Any]) -> list[dict[str, Any]]:
        root = self._target_hwnd(target)
        wanted_hwnd = identity.get("hwnd")
        if isinstance(wanted_hwnd, bool) or not isinstance(wanted_hwnd, int) or wanted_hwnd <= 0:
            raise NativeError("BACKEND_CONTRACT_ERROR", "HWND identity is missing a valid hwnd")
        allowed = {root, *self.transport.child_windows(root)}
        if wanted_hwnd not in allowed or not self.transport.is_window(wanted_hwnd):
            return []
        entity = self._entity(wanted_hwnd)
        return [entity] if entity["identity"] == identity else []

    def act(self, target: dict[str, Any], entity: dict[str, Any], action: str, args: dict[str, Any]) -> dict[str, Any]:
        hwnd = self._entity_hwnd(entity)
        if action == "select_index":
            info = self.transport.window_info(hwnd)
            identity = {
                "hwnd": int(info["hwnd"]), "pid": int(info["pid"]),
                "class_name": str(info["class_name"]), "control_id": int(info.get("control_id", 0)),
                "parent_hwnd": int(info.get("parent_hwnd", 0) or 0),
                "style_type": int(info.get("style", 0)) & BS_TYPEMASK,
            }
            if identity != entity.get("identity"):
                raise NativeError("TARGET_MOVED", "HWND identity changed before action", {"hwnd": hwnd})
            cls = identity["class_name"].lower()
            if cls in {_COMBOBOX_CLASS, _LISTBOX_CLASS}:
                parent_hwnd = identity["parent_hwnd"]
                if parent_hwnd <= 0 or not self.transport.is_window(parent_hwnd):
                    raise NativeError("NO_BACKGROUND_ROUTE", "Selection control has no valid parent HWND for a semantic change notification", {"hwnd": hwnd, "parent_hwnd": parent_hwnd})
        current = self._entity(hwnd)
        if current["identity"] != entity["identity"]:
            raise NativeError("TARGET_MOVED", "HWND identity changed before action", {"hwnd": hwnd})
        cls = current["class_name"].lower()
        if (current.get("state") or {}).get("enabled") is False:
            raise NativeError("ACTION_UNAVAILABLE", "HWND target control is disabled", {"hwnd": hwnd, "action": action})
        interaction_before = self._interaction_state()
        if action == "set_value" and cls in _EDIT_CLASSES:
            value = args.get("value")
            if not isinstance(value, str):
                raise NativeError("INVALID_ARGUMENT", "set_value requires string value")
            result = self._mutating_send(hwnd, WM_SETTEXT, 0, value, "WM_SETTEXT")
            return self._with_interaction_receipt({"message": "WM_SETTEXT", "result": result}, interaction_before)
        if action == "invoke" and cls == _BUTTON_CLASS:
            result = self._mutating_send(hwnd, BM_CLICK, 0, 0, "BM_CLICK")
            return self._with_interaction_receipt({"message": "BM_CLICK", "result": result}, interaction_before)
        if action == "toggle" and cls == _BUTTON_CLASS and "toggle" in current["actions"]:
            result = self._mutating_send(hwnd, BM_CLICK, 0, 0, "BM_CLICK")
            return self._with_interaction_receipt({"message": "BM_CLICK", "result": result}, interaction_before)
        if action == "select_index" and cls in {_COMBOBOX_CLASS, _LISTBOX_CLASS}:
            index = args.get("index")
            if isinstance(index, bool) or not isinstance(index, int) or index < 0:
                raise NativeError("INVALID_ARGUMENT", "select_index requires non-negative integer index")
            parent_hwnd = int(current["identity"].get("parent_hwnd") or 0)
            control_id = int(current["identity"].get("control_id") or 0)
            if parent_hwnd <= 0 or not self.transport.is_window(parent_hwnd):
                raise NativeError(
                    "NO_BACKGROUND_ROUTE",
                    "Selection control has no valid parent HWND for a semantic change notification",
                    {"hwnd": hwnd, "parent_hwnd": parent_hwnd},
                )
            set_msg = CB_SETCURSEL if cls == _COMBOBOX_CLASS else LB_SETCURSEL
            get_msg = CB_GETCURSEL if cls == _COMBOBOX_CLASS else LB_GETCURSEL
            previous_index = self.transport.send_timeout(hwnd, get_msg, 0, 0, self.timeout_ms)
            result = self._mutating_send(
                hwnd,
                set_msg,
                index,
                0,
                "CB_SETCURSEL" if cls == _COMBOBOX_CLASS else "LB_SETCURSEL",
            )
            if result < 0:
                raise NativeError("HWND_ACTION_FAILED", "Selection message rejected index", {"hwnd": hwnd, "index": index})
            notification = CBN_SELCHANGE if cls == _COMBOBOX_CLASS else LBN_SELCHANGE
            command_wparam = ((notification & 0xFFFF) << 16) | (control_id & 0xFFFF)
            try:
                self._mutating_send(parent_hwnd, WM_COMMAND, command_wparam, hwnd, "WM_COMMAND selection notification")
            except NativeError as exc:
                if exc.code != "HWND_ACTION_OUTCOME_UNKNOWN":
                    raise
                rollback_succeeded = False
                rollback_error = None
                if previous_index >= 0:
                    try:
                        restore = self.transport.send_timeout(hwnd, set_msg, previous_index, 0, self.timeout_ms)
                        rollback_succeeded = restore >= 0
                    except NativeError as rollback_exc:
                        rollback_error = rollback_exc.code
                details = dict(exc.details or {})
                details.update(
                    {
                        "selection_changed_to": index,
                        "previous_index": previous_index,
                        "rollback_attempted": previous_index >= 0,
                        "rollback_succeeded": rollback_succeeded,
                        "rollback_error": rollback_error,
                        "retry_safe": False,
                    }
                )
                raise NativeError(
                    "HWND_ACTION_OUTCOME_UNKNOWN",
                    "Selection changed but application notification timed out; do not retry automatically",
                    details,
                ) from exc
            return self._with_interaction_receipt({
                "message": "CB_SETCURSEL" if cls == _COMBOBOX_CLASS else "LB_SETCURSEL",
                "result": result,
                "notification": "CBN_SELCHANGE" if cls == _COMBOBOX_CLASS else "LBN_SELCHANGE",
                "notification_parent_hwnd": parent_hwnd,
            }, interaction_before)
        raise NativeError("ACTION_UNSUPPORTED", f"HWND action {action!r} is not allowlisted for class {current['class_name']!r}")

    def read_entity(self, target: dict[str, Any], entity: dict[str, Any]) -> dict[str, Any]:
        current = self._entity(self._entity_hwnd(entity))
        if current["identity"] != entity["identity"]:
            raise NativeError("TARGET_MOVED", "HWND identity changed during read")
        return current

    def _interaction_state(self) -> tuple[int | None, tuple[int, int] | None]:
        foreground = getattr(self.transport, "foreground_hwnd", None)
        cursor = getattr(self.transport, "cursor_position", None)
        if not callable(foreground) or not callable(cursor):
            return None, None
        position = cursor()
        return int(foreground()), tuple(position) if position is not None else None

    def _with_interaction_receipt(self, result: dict[str, Any], before: tuple[int | None, tuple[int, int] | None]) -> dict[str, Any]:
        before_fg, before_cursor = before
        after_fg, after_cursor = self._interaction_state()
        result = dict(result)
        result["foreground_before"] = before_fg
        result["foreground_after"] = after_fg
        result["cursor_before"] = list(before_cursor) if before_cursor is not None else None
        result["cursor_after"] = list(after_cursor) if after_cursor is not None else None
        result["focus_preserved"] = before_fg is not None and after_fg == before_fg
        result["cursor_preserved"] = after_cursor == before_cursor if before_cursor is not None and after_cursor is not None else None
        return result

    def _mutating_send(self, hwnd: int, msg: int, wparam: int, lparam: int | str, label: str) -> int:
        try:
            return self.transport.send_timeout(hwnd, msg, wparam, lparam, self.timeout_ms)
        except NativeError as exc:
            if exc.code != "HWND_MESSAGE_TIMEOUT":
                raise
            raise NativeError(
                "HWND_ACTION_OUTCOME_UNKNOWN",
                f"{label} timed out after dispatch; action may already have executed",
                {
                    "hwnd": hwnd,
                    "message": msg,
                    "operation": label,
                    "timeout_ms": self.timeout_ms,
                    "retry_safe": False,
                },
            ) from exc

    def _entity(self, hwnd: int) -> dict[str, Any]:
        info = self.transport.window_info(hwnd)
        cls = str(info["class_name"])
        cls_lower = cls.lower()
        actions: list[str] = []
        state: dict[str, Any] = {"enabled": bool(info.get("enabled", True))}
        value: Any = self.transport.get_text(hwnd)
        role = "window"
        if cls_lower in _EDIT_CLASSES:
            role = "edit"
            actions = ["set_value"]
        elif cls_lower == _BUTTON_CLASS:
            role = "button"
            actions = ["invoke"]
            button_type = int(info.get("style", 0)) & BS_TYPEMASK
            if button_type in BS_CHECKBOX_TYPES:
                actions.append("toggle")
                state["checked"] = self.transport.send_timeout(hwnd, BM_GETCHECK, 0, 0, self.timeout_ms)
        elif cls_lower == _COMBOBOX_CLASS:
            role = "combobox"
            actions = ["select_index"]
            state["selected_index"] = self.transport.send_timeout(hwnd, CB_GETCURSEL, 0, 0, self.timeout_ms)
        elif cls_lower == _LISTBOX_CLASS:
            role = "listbox"
            actions = ["select_index"]
            state["selected_index"] = self.transport.send_timeout(hwnd, LB_GETCURSEL, 0, 0, self.timeout_ms)
        identity = {
            "hwnd": int(info["hwnd"]),
            "pid": int(info["pid"]),
            "class_name": cls,
            "control_id": int(info.get("control_id", 0)),
            "parent_hwnd": int(info.get("parent_hwnd", 0) or 0),
            "style_type": int(info.get("style", 0)) & BS_TYPEMASK,
        }
        return {
            "identity": identity,
            "role": role,
            "name": value,
            "automation_id": None,
            "class_name": cls,
            "control_id": identity["control_id"],
            "value": value,
            "state": state,
            "actions": actions,
            "geometry": dict(info.get("geometry") or {}),
        }

    @staticmethod
    def _target_hwnd(target: dict[str, Any]) -> int:
        hwnd = target.get("hwnd")
        if isinstance(hwnd, str):
            try:
                hwnd = int(hwnd, 0)
            except ValueError as exc:
                raise NativeError("INVALID_ARGUMENT", "target hwnd is invalid") from exc
        if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
            raise NativeError("INVALID_ARGUMENT", "target requires positive hwnd")
        return hwnd

    @staticmethod
    def _entity_hwnd(entity: dict[str, Any]) -> int:
        identity = entity.get("identity") or {}
        hwnd = identity.get("hwnd")
        if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
            raise NativeError("BACKEND_CONTRACT_ERROR", "entity identity has no valid hwnd")
        return hwnd
