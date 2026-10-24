from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import platform
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from cua_input_arbiter import ArbiterError, FileLeaseStore, HumanInputArbiter, TargetFingerprint
from cua_input_router_adapter import ArbiterLeaseValidator
from cua_input_windows import WindowsEventSource
from cua_physical_input_windows import MarkedWindowsInputSink
from cua_router import RouteExecutionError

IS_WINDOWS = platform.system().lower() == "windows"
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


class PhysicalRuntimeError(RuntimeError):
    def __init__(self, code: str, details: Mapping[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wt.DWORD), ("dwHighDateTime", wt.DWORD)]


def fingerprint_dict(target: TargetFingerprint) -> dict[str, Any]:
    return {
        "hwnd": target.hwnd,
        "pid": target.pid,
        "process_start_ns": target.process_start_ns,
        "rect": list(target.rect),
        "generation": target.generation,
    }


class Win32TargetApi:
    def __init__(self) -> None:
        if not IS_WINDOWS:
            raise PhysicalRuntimeError("WINDOWS_ONLY")
        self.user32 = ctypes.WinDLL("user32", use_last_error=True)
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.user32.IsWindow.argtypes = [wt.HWND]
        self.user32.IsWindow.restype = wt.BOOL
        self.user32.GetWindowRect.argtypes = [wt.HWND, ctypes.POINTER(wt.RECT)]
        self.user32.GetWindowRect.restype = wt.BOOL
        self.user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]
        self.user32.GetWindowThreadProcessId.restype = wt.DWORD
        self.user32.GetForegroundWindow.argtypes = []
        self.user32.GetForegroundWindow.restype = wt.HWND
        self.user32.GetCursorPos.argtypes = [ctypes.POINTER(wt.POINT)]
        self.user32.GetCursorPos.restype = wt.BOOL
        self.user32.GetWindowTextLengthW.argtypes = [wt.HWND]
        self.user32.GetWindowTextLengthW.restype = ctypes.c_int
        self.user32.GetWindowTextW.argtypes = [wt.HWND, wt.LPWSTR, ctypes.c_int]
        self.user32.GetWindowTextW.restype = ctypes.c_int
        self.kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        self.kernel32.OpenProcess.restype = wt.HANDLE
        self.kernel32.GetProcessTimes.argtypes = [wt.HANDLE] + [ctypes.POINTER(FILETIME)] * 4
        self.kernel32.GetProcessTimes.restype = wt.BOOL
        self.kernel32.CloseHandle.argtypes = [wt.HANDLE]
        self.kernel32.CloseHandle.restype = wt.BOOL

    @staticmethod
    def _filetime_value(value: FILETIME) -> int:
        return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)

    def fingerprint(self, hwnd: int, generation: int) -> TargetFingerprint:
        if not hwnd or not self.user32.IsWindow(wt.HWND(hwnd)):
            raise PhysicalRuntimeError("STALE_TARGET", {"hwnd": int(hwnd or 0)})
        pid = wt.DWORD(0)
        if not self.user32.GetWindowThreadProcessId(wt.HWND(hwnd), ctypes.byref(pid)) or not pid.value:
            raise PhysicalRuntimeError("TARGET_FINGERPRINT_UNAVAILABLE", {"hwnd": hwnd})
        rect = wt.RECT()
        if not self.user32.GetWindowRect(wt.HWND(hwnd), ctypes.byref(rect)):
            raise PhysicalRuntimeError("TARGET_FINGERPRINT_UNAVAILABLE", {"hwnd": hwnd})
        process = self.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid.value)
        if not process:
            raise PhysicalRuntimeError("TARGET_FINGERPRINT_UNAVAILABLE", {"hwnd": hwnd, "pid": int(pid.value)})
        try:
            creation, exit_time, kernel, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
            if not self.kernel32.GetProcessTimes(process, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel), ctypes.byref(user)):
                raise PhysicalRuntimeError("TARGET_FINGERPRINT_UNAVAILABLE", {"hwnd": hwnd, "pid": int(pid.value)})
        finally:
            self.kernel32.CloseHandle(process)
        return TargetFingerprint(
            int(hwnd), int(pid.value), self._filetime_value(creation) * 100,
            (int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)), int(generation),
        )

    def foreground(self) -> int:
        return int(self.user32.GetForegroundWindow() or 0)

    def focus(self, hwnd):
        from cua_desktop_identity import require_input_desktop, DesktopIdentityError
        try: require_input_desktop(hwnd)
        except DesktopIdentityError as exc: raise PhysicalRuntimeError(str(exc)) from exc
        self.user32.SetForegroundWindow.argtypes = [wt.HWND]
        self.user32.SetForegroundWindow.restype = wt.BOOL
        if self.foreground() == hwnd:
            return
        if not self.user32.SetForegroundWindow(wt.HWND(hwnd)):
            raise PhysicalRuntimeError("FOCUS_NOT_GRANTED_BY_WINDOWS", {"retry_safe": False})

    def caption_activation_point(self, hwnd, guard):
        """Expose this authorized window and return a freshly hit-tested caption.

        Never click guessed client coordinates or caption buttons. Custom or
        unavailable captions fail without input; no Alt or thread attachment.
        """
        from cua_desktop_identity import require_input_desktop, DesktopIdentityError
        try: require_input_desktop(hwnd)
        except DesktopIdentityError as exc: raise PhysicalRuntimeError(str(exc)) from exc
        u = self.user32
        u.IsWindowVisible.argtypes = [wt.HWND]; u.IsWindowVisible.restype = wt.BOOL
        u.IsIconic.argtypes = [wt.HWND]; u.IsIconic.restype = wt.BOOL
        if not u.IsWindowVisible(hwnd) or u.IsIconic(hwnd):
            raise PhysicalRuntimeError("ACTIVATION_CAPTION_UNAVAILABLE", {"retry_safe": False})
        u.SetWindowPos.argtypes = [wt.HWND, wt.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, wt.UINT]
        u.SetWindowPos.restype = wt.BOOL
        u.WindowFromPoint.argtypes = [wt.POINT]; u.WindowFromPoint.restype = wt.HWND
        u.GetAncestor.argtypes = [wt.HWND, wt.UINT]; u.GetAncestor.restype = wt.HWND
        u.SendMessageTimeoutW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM, wt.UINT, wt.UINT, ctypes.POINTER(ctypes.c_size_t)]
        u.SendMessageTimeoutW.restype = wt.LPARAM
        guard()
        # Only Z order changes. Do not show, restore, resize or move a window.
        if not u.SetWindowPos(hwnd, None, 0, 0, 0, 0, 0x0013):
            raise PhysicalRuntimeError("ACTIVATION_CAPTION_UNAVAILABLE", {"retry_safe": False})
        guard()
        rect = wt.RECT()
        if not u.GetWindowRect(hwnd, ctypes.byref(rect)):
            raise PhysicalRuntimeError("TARGET_FINGERPRINT_UNAVAILABLE")
        width = rect.right-rect.left
        xs = [rect.left+width//3, rect.left+width//2]
        probes = []
        for offset in (12, 20, 28, 36):
            for x in xs:
                y = rect.top+offset
                if not rect.left <= x < rect.right or not rect.top <= y < rect.bottom or not (-32768 <= x <= 32767 and -32768 <= y <= 32767):
                    continue
                guard()
                hit = u.WindowFromPoint(wt.POINT(x, y))
                actual_root = int(u.GetAncestor(hit, 2) or 0) if hit else 0
                if actual_root != hwnd:
                    probes.append({"point":[x,y], "same_root":False, "root":actual_root})
                    continue
                result = ctypes.c_size_t()
                packed = (x & 0xffff) | ((y & 0xffff) << 16)
                delivered = bool(u.SendMessageTimeoutW(hwnd, 0x0084, 0, packed, 0x0002, 100, ctypes.byref(result)))
                probes.append({"point":[x,y], "same_root":True, "delivered":delivered, "hit_test":int(result.value)})
                if not delivered or result.value != 2:
                    continue
                guard()
                # Recheck after the target's hit-test response, before SendInput.
                hit = u.WindowFromPoint(wt.POINT(x, y))
                if hit and int(u.GetAncestor(hit, 2) or 0) == hwnd:
                    return x, y
        raise PhysicalRuntimeError("ACTIVATION_CAPTION_UNAVAILABLE", {"retry_safe": False})

    def cursor(self) -> tuple[int, int]:
        point = wt.POINT()
        if not self.user32.GetCursorPos(ctypes.byref(point)):
            raise PhysicalRuntimeError("CURSOR_STATE_UNAVAILABLE")
        return int(point.x), int(point.y)

    def title(self, hwnd: int) -> str:
        length = max(0, int(self.user32.GetWindowTextLengthW(wt.HWND(hwnd))))
        buffer = ctypes.create_unicode_buffer(length + 1)
        self.user32.GetWindowTextW(wt.HWND(hwnd), buffer, len(buffer))
        return buffer.value


class PhysicalInputRouteAdapter:
    def __init__(self, runtime: "WindowsPhysicalRuntime", surface: Mapping[str, Any]):
        self.runtime = runtime
        self.surface = surface

    @staticmethod
    def _events(request: Mapping[str, Any]) -> list[dict[str, Any]]:
        args = request.get("action_args") if isinstance(request.get("action_args"), Mapping) else {}
        raw_events = args.get("events")
        if not isinstance(raw_events, list) or not raw_events or len(raw_events) > 32:
            raise PhysicalRuntimeError("PHYSICAL_SEQUENCE_INVALID")
        events: list[dict[str, Any]] = []
        for raw in raw_events:
            if not isinstance(raw, Mapping):
                raise PhysicalRuntimeError("PHYSICAL_EVENT_UNSUPPORTED")
            kind = str(raw.get("kind") or "")
            if kind == "key_tap":
                vk = raw.get("vk")
                if isinstance(vk, bool) or not isinstance(vk, int) or not 0 <= vk <= 0xFF:
                    raise PhysicalRuntimeError("PHYSICAL_KEY_INVALID")
            elif kind == "unicode_char":
                if not isinstance(raw.get("text"), str) or len(raw["text"]) != 1:
                    raise PhysicalRuntimeError("PHYSICAL_UNICODE_CHAR_INVALID")
            elif kind == "key_chord":
                keys = raw.get("keys")
                if not isinstance(keys, list) or not 1 <= len(keys) <= 8 or any(type(k) is not int or not 0 <= k <= 255 for k in keys):
                    raise PhysicalRuntimeError("PHYSICAL_CHORD_INVALID")
            elif kind == "mouse_click":
                flags = (raw.get("down_flags"), raw.get("up_flags"))
                if not all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in flags):
                    raise PhysicalRuntimeError("PHYSICAL_MOUSE_FLAGS_INVALID")
            elif kind in {"mouse_click_at", "mouse_move_at"}:
                x, y = raw.get("x"), raw.get("y")
                flags = (raw.get("down_flags"), raw.get("up_flags"))
                if any(isinstance(v, bool) or not isinstance(v, int) for v in (x, y)):
                    raise PhysicalRuntimeError("PHYSICAL_POINT_INVALID")
                if kind == "mouse_click_at" and not all(isinstance(v, int) and not isinstance(v, bool) and v > 0 for v in flags):
                    raise PhysicalRuntimeError("PHYSICAL_MOUSE_FLAGS_INVALID")
            elif kind == "mouse":
                flags, data = raw.get("flags"), raw.get("data", 0)
                if isinstance(flags, bool) or not isinstance(flags, int) or flags <= 0:
                    raise PhysicalRuntimeError("PHYSICAL_MOUSE_FLAGS_INVALID")
                if isinstance(data, bool) or not isinstance(data, int):
                    raise PhysicalRuntimeError("PHYSICAL_MOUSE_DATA_INVALID")
            else:
                raise PhysicalRuntimeError("PHYSICAL_EVENT_UNSUPPORTED")
            events.append(dict(raw))
        return events

    def can_handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("operation") != "physical_sequence":
            return {"supported": False, "reason": "physical_sequence_only"}
        try:
            self._events(request)
        except PhysicalRuntimeError as exc:
            return {"supported": False, "reason": exc.code}
        return {"supported": True, "background_safe": False, "desktop_exclusive": True}

    def act(self, request: Mapping[str, Any]) -> dict[str, Any]:
        validated = request.get("_validated_physical_lease")
        if not isinstance(validated, Mapping) or not validated.get("lease_id"):
            raise RouteExecutionError("PHYSICAL_LEASE_VALIDATION_UNAVAILABLE", attempted=False)
        lease_id = str(validated["lease_id"])
        events = self._events(request)
        try:
            lease = self.runtime.arbiter.get_active_lease(lease_id)
            target_before = self.runtime.target_for(self.surface, request)
        except (ArbiterError, PhysicalRuntimeError) as exc:
            raise RouteExecutionError(
                str(exc.code), attempted=False,
                details={"retry_safe": False, "terminal_failure_reason": str(exc.code)},
            ) from exc
        sink = MarkedWindowsInputSink(self.runtime.event_source, lease.sequence_id, api=self.runtime.send_api_factory())
        args = request.get("action_args") if isinstance(request.get("action_args"), Mapping) else {}
        delay_ms = args.get("inter_event_delay_ms", 0)
        if isinstance(delay_ms, bool) or not isinstance(delay_ms, (int, float)) or not 0 <= float(delay_ms) <= 1000:
            raise RouteExecutionError("PHYSICAL_SEQUENCE_DELAY_INVALID", attempted=False)
        delay_seconds = float(delay_ms) / 1000.0
        emitted = 0

        def paced_sink(event: Mapping[str, Any]) -> None:
            nonlocal emitted
            from cua_task_authority import DESKTOP_ACTION_EXPIRY
            expires = DESKTOP_ACTION_EXPIRY.get()
            if expires is not None and expires <= time.time():
                raise PhysicalRuntimeError("DESKTOP_MODE_EXPIRED", {"retry_safe": False})
            if str(event.get("kind", "")).startswith("mouse"):
                point = (event["x"], event["y"]) if event["kind"] in {"mouse_click_at", "mouse_move_at"} else self.runtime.target_api.cursor()
                left, top, right, bottom = self.runtime.target_for(self.surface, request).rect
                if not left <= point[0] < right or not top <= point[1] < bottom:
                    raise PhysicalRuntimeError("PHYSICAL_POINT_OUTSIDE_TARGET", {"retry_safe": False})
            sink(event)
            emitted += 1
            if delay_seconds and emitted < len(events):
                time.sleep(delay_seconds)

        sequence = self.runtime.arbiter.execute_sequence(
            lease_id,
            events,
            target_provider=lambda: self.runtime.target_for(self.surface, request),
            foreground_provider=self.runtime.target_api.foreground,
            sink=paced_sink,
        )
        verification = None
        verified = False
        verification_error = None
        if sequence.get("ok"):
            try:
                verified, verification = self.runtime.verify_postcondition(self.surface, request)
            except PhysicalRuntimeError as exc:
                verification_error = exc.code

        receipt = self.runtime.arbiter.finish(
            lease_id,
            verified=bool(sequence.get("ok") and verified and verification_error is None),
            foreground_after=self.runtime.target_api.foreground(),
            cursor_after=self.runtime.target_api.cursor(),
        )
        receipt.update({
            "operation": "physical_sequence",
            "target_before": fingerprint_dict(target_before),
            "target": fingerprint_dict(target_before),
            "sent": sequence.get("sent"),
            "sequence_ok": bool(sequence.get("ok")),
            "user_active": sequence.get("error_code") == "USER_ACTIVE",
            "physical_effect_unknown": bool(sequence.get("physical_effect_unknown", False)),
            "verification": verification,
            "verification_error": verification_error,
            "physical_input_used": True,
            "background_safe": False,
            "desktop_exclusive": True,
            "terminal_failure_reason": sequence.get("error_code") or verification_error,
        })
        if not sequence.get("ok"):
            code = str(sequence.get("error_code") or "PHYSICAL_SEQUENCE_FAILED")
            raise RouteExecutionError(
                code, attempted=bool((sequence.get("sent") or 0) > 0 or sequence.get("physical_effect_unknown")),
                details={"receipt": receipt, "retry_safe": False, "terminal_failure_reason": code},
            )
        if verification_error is not None:
            raise RouteExecutionError(
                verification_error, attempted=True,
                details={"receipt": receipt, "retry_safe": False, "terminal_failure_reason": verification_error},
            )
        if request.get("postcondition") is not None and not verified:
            raise RouteExecutionError(
                "POSTCONDITION_FAILED", attempted=True,
                details={"receipt": receipt, "retry_safe": False, "terminal_failure_reason": "POSTCONDITION_FAILED"},
            )
        return receipt


class WindowsPhysicalRuntime:
    def __init__(
        self,
        root: str | Path,
        *,
        target_api: Any | None = None,
        event_source_factory: Callable[[Callable[[str], None], Callable[[int], None]], Any] | None = None,
        send_api_factory: Callable[[], Any] | None = None,
        quiet_window_ms: int = 500,
        lease_ttl_ms: int = 1500,
    ):
        self.root = Path(root).resolve()
        self.arbiter = HumanInputArbiter(
            FileLeaseStore(self.root / "state" / "physical-input.lease"),
            quiet_window_ms=quiet_window_ms,
            lease_ttl_ms=lease_ttl_ms,
        )
        self.target_api = target_api or Win32TargetApi()
        source_factory = event_source_factory or (
            lambda owner, foreground: WindowsEventSource(owner, foreground)
        )
        self.event_source = source_factory(self.arbiter.observe_owner_input, self.arbiter.observe_foreground)
        if send_api_factory is None:
            from cua_physical_input_windows import CtypesSendInputApi
            send_api_factory = CtypesSendInputApi
        self.send_api_factory = send_api_factory
        self._started = False

    def start(self) -> None:
        if not self._started:
            self.event_source.start(3.0)
            self._started = True

    def health(self) -> dict[str, Any]:
        return {
            "initialized": True,
            "event_source_running": bool(self._started and self.event_source.running),
            "event_source_failure": self.event_source.failure if self._started else None,
            "active_leases": len(self.arbiter.active),
        }

    @staticmethod
    def _hwnd(surface: Mapping[str, Any]) -> int:
        if surface.get("kind") != "native":
            raise PhysicalRuntimeError("PHYSICAL_TARGET_UNSUPPORTED", {"surface_kind": surface.get("kind")})
        target = surface.get("target") if isinstance(surface.get("target"), Mapping) else {}
        hwnd = target.get("hwnd")
        if isinstance(hwnd, str):
            try:
                hwnd = int(hwnd, 0)
            except ValueError as exc:
                raise PhysicalRuntimeError("PHYSICAL_TARGET_HWND_REQUIRED") from exc
        if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
            raise PhysicalRuntimeError("PHYSICAL_TARGET_HWND_REQUIRED")
        return hwnd

    def target_for(self, surface: Mapping[str, Any], request: Mapping[str, Any]) -> TargetFingerprint:
        generation = request.get("generation")
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
            raise PhysicalRuntimeError("PHYSICAL_TARGET_GENERATION_REQUIRED")
        return self.target_api.fingerprint(self._hwnd(surface), generation)

    def acquire(self, surface: Mapping[str, Any], *, generation: int, owner_id: str) -> dict[str, Any]:
        self.start()
        request = {"generation": generation}
        target = self.target_for(surface, request)
        cursor = self.target_api.cursor()
        self.arbiter.observe_cursor(*cursor)
        foreground = self.target_api.foreground()
        lease = self.arbiter.acquire(owner_id, target, expected_foreground=foreground)
        return {
            "lease_id": lease.lease_id,
            "sequence_id": lease.sequence_id,
            "expires_ns": lease.expires_ns,
            "target": fingerprint_dict(target),
        }

    def focus(self, surface, *, generation, owner_id, allow_pointer_activation=False):
        self.start()
        request = {"generation": generation}
        target = self.target_for(surface, request)
        def activate(hwnd, guard):
            from cua_task_authority import DESKTOP_ACTION_EXPIRY
            def input_guard():
                expires = DESKTOP_ACTION_EXPIRY.get()
                if expires is not None and expires <= time.time():
                    raise PhysicalRuntimeError("DESKTOP_MODE_EXPIRED", {"retry_safe": False})
                guard()
            point = self.target_api.caption_activation_point(hwnd, input_guard)
            input_guard()
            sink = MarkedWindowsInputSink(self.event_source, __import__("uuid").uuid4().hex,
                                          api=self.send_api_factory())
            try:
                sink({"kind": "mouse_click_at", "x": point[0], "y": point[1],
                      "down_flags": 2, "up_flags": 4})
            except Exception as exc:
                raise PhysicalRuntimeError("PHYSICAL_ACTIVATION_OUTCOME_UNKNOWN",
                                           {"retry_safe": False}) from exc
            return {"activation_method": "caption_click", "activation_point": list(point)}
        return self.arbiter.focus_transition(owner_id, target,
            foreground_provider=self.target_api.foreground, focus=self.target_api.focus,
            target_provider=lambda: self.target_for(surface, request),
            activation_fallback=activate if allow_pointer_activation else None)

    def validator(self, surface: Mapping[str, Any]) -> ArbiterLeaseValidator:
        self.start()
        return ArbiterLeaseValidator(
            self.arbiter,
            lambda request: self.target_for(surface, request),
            self.target_api.foreground,
        )

    def adapter(self, surface: Mapping[str, Any]) -> PhysicalInputRouteAdapter:
        self.start()
        return PhysicalInputRouteAdapter(self, surface)

    def abort_if_active(self, lease_id: str, reason: str = "ACTION_COMPLETE") -> None:
        if lease_id in self.arbiter.active:
            self.arbiter.abort(lease_id, reason)

    def release(self, lease_id: str) -> None:
        self.abort_if_active(lease_id, "LEASE_RELEASED")

    def verify_postcondition(
        self, surface: Mapping[str, Any], request: Mapping[str, Any]
    ) -> tuple[bool, dict[str, Any] | None]:
        condition = request.get("postcondition")
        if condition is None:
            return False, None
        if not isinstance(condition, Mapping):
            raise PhysicalRuntimeError("POSTCONDITION_INVALID")
        kind = str(condition.get("kind") or "")
        if kind == "cursor_position":
            if type(condition.get("x")) is not int or type(condition.get("y")) is not int:
                raise PhysicalRuntimeError("POSTCONDITION_INVALID")
            actual = self.target_api.cursor()
            expected = (condition["x"], condition["y"])
            return actual == expected, {"kind":kind,"expected":list(expected),"actual":list(actual),"matched":actual==expected}
        hwnd = self._hwnd(surface)
        if kind in {"window_title_contains", "window_title_equals"}:
            expected = condition.get("value")
            if not isinstance(expected, str):
                raise PhysicalRuntimeError("POSTCONDITION_INVALID")
            deadline = time.monotonic() + 0.25
            attempts = 0
            while True:
                actual = self.target_api.title(hwnd)
                attempts += 1
                matched = expected in actual if kind == "window_title_contains" else expected == actual
                if matched or time.monotonic() >= deadline:
                    return matched, {
                        "kind": kind, "expected": expected, "actual": actual,
                        "matched": matched, "attempts": attempts,
                    }
                time.sleep(0.01)
        raise PhysicalRuntimeError("POSTCONDITION_UNSUPPORTED", {"kind": kind})

    def close(self) -> None:
        for lease_id in list(self.arbiter.active):
            try:
                self.arbiter.abort(lease_id, "RUNTIME_CLOSE")
            except Exception:
                pass
        if self._started:
            try:
                self.event_source.stop(2.0)
            finally:
                self._started = False
