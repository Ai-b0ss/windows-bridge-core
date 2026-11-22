from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from cua_native_core import NativeError
from cua_native_supervisor import NativeSidecarSupervisor, SidecarSupervisorError

_FORBIDDEN_PHYSICAL_ACTIONS = frozenset({
    "physical_sequence", "send_input", "mouse_click", "mouse_move",
    "key_tap", "key_chord", "unicode_char", "visual_click", "switch_desktop",
})


def _default_process_creation_token(pid: int) -> int | None:
    if os.name != "nt":
        return None
    from ff_win_process_identity import process_creation_token
    return process_creation_token(pid)


class Uia3PersistentBackend:
    """Persistent System.Windows.Automation backend behind a killable process boundary.

    The child owns a dedicated COM MTA worker and never exposes physical input.
    UIA3 operates strictly within the calling thread's Windows desktop; cross-
    desktop UIA targeting is unsupported and fails closed. Mutation uses
    action-time re-resolution. Stable AutomationId is preferred; elements
    without one use a hierarchy path plus a short-lived runtime-id guard.
    """

    route = "UIA_PATTERN"
    no_focus = False

    def __init__(
        self,
        executable: str | Path,
        timeout_seconds: float = 5.0,
        *,
        no_focus: bool = False,
        same_desktop_check: bool = True,
        process_token_fn: Callable[[int], int | None] | None = None,
    ):
        if type(no_focus) is not bool:raise ValueError("no_focus must be boolean")
        if type(same_desktop_check) is not bool:raise ValueError("same_desktop_check must be boolean")
        self.no_focus = no_focus
        self._same_desktop_check = same_desktop_check
        self._process_token_fn = process_token_fn or _default_process_creation_token
        self.supervisor = NativeSidecarSupervisor(executable, timeout_seconds=timeout_seconds, engine="uia3")

    def close(self) -> None:
        self.supervisor.stop()

    def capabilities(self) -> dict[str, Any]:
        response = self._request("capabilities")
        return {
            **{k: v for k, v in response.items() if k not in {"id", "ok"}},
            "background_safe_actions": [],
            "desktop_exclusive_actions": ["set_value", "invoke", "toggle", "select", "expand", "collapse", "scroll_into_view", "scroll"],
            "stable_automation_id_required_for_mutation": False,
            "hierarchy_path_for_mutation": True,
            "runtime_id_guard": True,
            "process_timeout_isolation": True,
            "same_desktop_required": True,
            "cross_desktop_uia_supported": False,
            "cross_desktop_sendinput_supported": False,
            "hwnd_pid_create_time_enforced": True,
        }

    def _guard_same_desktop(self, hwnd: int) -> None:
        if not self._same_desktop_check or os.name != "nt":
            return
        from cua_desktop_identity import DesktopIdentityError, thread_and_target_desktop
        try:
            identity = thread_and_target_desktop(hwnd)
        except DesktopIdentityError as exc:
            # If Windows reports no thread for hwnd, let UIA/caller handle staleness
            # unless the desktop identity itself explicitly mismatches.
            if str(exc) == "TARGET_DESKTOP_IDENTITY_UNAVAILABLE":
                return
            raise NativeError(
                "CROSS_DESKTOP_UIA_UNSUPPORTED",
                "UIA3 desktop identity could not be verified",
                {"hwnd": hwnd, "reason": str(exc), "retry_safe": False},
            ) from exc
        if identity["target"] != identity["current"]:
            raise NativeError(
                "CROSS_DESKTOP_UIA_UNSUPPORTED",
                "UIA3 cannot inspect or act on a window belonging to another Windows desktop without switching desktops",
                {
                    "hwnd": hwnd,
                    "current_desktop": identity["current"],
                    "target_desktop": identity["target"],
                    "physical_input_used": False,
                    "retry_safe": False,
                },
            )

    @staticmethod
    def _validate_optional_identity(target: dict[str, Any]) -> tuple[int | None, int | None]:
        expected_pid = target.get("pid")
        if expected_pid is not None and (isinstance(expected_pid, bool) or not isinstance(expected_pid, int) or expected_pid <= 0):
            raise NativeError("INVALID_ARGUMENT", "target.pid must be a positive integer")
        expected_create_time = target.get("create_time")
        if expected_create_time is not None and (isinstance(expected_create_time, bool) or not isinstance(expected_create_time, int) or expected_create_time <= 0):
            raise NativeError("INVALID_ARGUMENT", "target.create_time must be a positive integer")
        return expected_pid, expected_create_time

    def fingerprint(self, target: dict[str, Any]) -> dict[str, Any]:
        hwnd = self._hwnd(target)
        expected_pid, expected_create_time = self._validate_optional_identity(target)
        self._guard_same_desktop(hwnd)
        response = self._request("fingerprint", {"hwnd": hwnd})
        actual_hwnd = int(response["hwnd"])
        pid = int(response["process_id"])
        if expected_pid is not None and pid != expected_pid:
            raise NativeError(
                "TARGET_IDENTITY_MISMATCH",
                "UIA3 target PID does not match expected ownership",
                {"hwnd": actual_hwnd, "expected_pid": expected_pid, "actual_pid": pid},
            )
        create_time = self._process_token_fn(pid)
        if expected_create_time is not None:
            if create_time is None or create_time != expected_create_time:
                raise NativeError(
                    "TARGET_IDENTITY_MISMATCH",
                    "UIA3 target process creation time does not match expected ownership",
                    {"hwnd": actual_hwnd, "pid": pid},
                )
        result: dict[str, Any] = {"hwnd": actual_hwnd, "process_id": pid}
        if create_time is not None:
            result["create_time"] = int(create_time)
        return result

    def snapshot(self, target: dict[str, Any], options: dict[str, Any]) -> list[dict[str, Any]]:
        hwnd = self._hwnd(target)
        self._guard_same_desktop(hwnd)
        max_items = options.get("max_items", 256)
        if isinstance(max_items, bool) or not isinstance(max_items, int) or not 1 <= max_items <= 512:
            raise NativeError("INVALID_ARGUMENT", "max_items must be between 1 and 512")
        response = self._request("snapshot", {"hwnd": hwnd, "max_items": max_items})
        entities = response.get("entities")
        if not isinstance(entities, list):
            raise NativeError("BACKEND_CONTRACT_ERROR", "UIA3 snapshot did not return entities")
        return [self._normalize_entity(x) for x in entities if isinstance(x, dict)]

    def resolve(self, target: dict[str, Any], identity: dict[str, Any]) -> list[dict[str, Any]]:
        hwnd = self._hwnd(target)
        self._guard_same_desktop(hwnd)
        try:
            response = self._request("get", {"hwnd": hwnd, "identity": identity})
        except NativeError as exc:
            if exc.code == "STALE_TARGET":
                return []
            raise
        entity = response.get("entity")
        return [self._normalize_entity(entity)] if isinstance(entity, dict) else []

    def read_entity(self, target: dict[str, Any], entity: dict[str, Any]) -> dict[str, Any]:
        hwnd = self._hwnd(target)
        self._guard_same_desktop(hwnd)
        identity = entity.get("identity")
        if not isinstance(identity, dict):
            raise NativeError("BACKEND_CONTRACT_ERROR", "UIA3 entity has no identity")
        response = self._request("get", {"hwnd": hwnd, "identity": identity})
        current = response.get("entity")
        if not isinstance(current, dict):
            raise NativeError("BACKEND_CONTRACT_ERROR", "UIA3 get did not return an entity")
        return self._normalize_entity(current)

    def act(self, target: dict[str, Any], entity: dict[str, Any], action: str, args: dict[str, Any]) -> dict[str, Any]:
        if action in _FORBIDDEN_PHYSICAL_ACTIONS:
            raise NativeError(
                "PRIVATE_DESKTOP_PHYSICAL_INPUT_UNSUPPORTED",
                f"Physical input action {action!r} is unsupported in UIA3 backend",
                {"action": action, "physical_input_used": False, "retry_safe": False},
            )
        if self.no_focus and action!="invoke":raise NativeError("ACTION_UNSUPPORTED","No-focus route supports invoke only")
        hwnd = self._hwnd(target)
        self._guard_same_desktop(hwnd)
        identity = entity.get("identity")
        if not isinstance(identity, dict):
            raise NativeError("BACKEND_CONTRACT_ERROR", "UIA3 entity has no identity")
        if not identity.get("automation_id"):
            path = identity.get("hierarchy_path")
            runtime_id = identity.get("runtime_id")
            if not isinstance(path, list) or not path or not isinstance(runtime_id, list) or not runtime_id:
                raise NativeError(
                    "TARGET_AMBIGUOUS",
                    "UIA3 mutation without AutomationId requires hierarchy_path + runtime_id guard",
                    {"identity": identity},
                )
        payload: dict[str, Any] = {"hwnd": hwnd, "identity": identity, "action": action}
        if self.no_focus:payload["no_focus"]=True
        if action == "set_value":
            value = args.get("value")
            if not isinstance(value, str):
                raise NativeError("INVALID_ARGUMENT", "set_value requires string value")
            payload["value"] = value
        elif action == "scroll":
            allowed = {"NoAmount", "LargeDecrement", "SmallDecrement", "LargeIncrement", "SmallIncrement"}
            horizontal = args.get("horizontal", "NoAmount")
            vertical = args.get("vertical", "NoAmount")
            if horizontal not in allowed or vertical not in allowed or (horizontal == "NoAmount" and vertical == "NoAmount"):
                raise NativeError("INVALID_ARGUMENT", "scroll requires a valid non-zero horizontal or vertical ScrollAmount")
            payload["horizontal"] = horizontal
            payload["vertical"] = vertical
        try:
            response = self._request("act", payload)
        except NativeError as exc:
            # The C# UIA3 sidecar re-resolves the original identity immediately
            # after performing the UIA pattern call. When a rerendering control
            # replaces its runtime node after SetValue/Invoke, allow
            # NativeSemanticCore to run postcondition receipt recovery instead
            # of aborting before postcondition verification.
            if (not self.no_focus
                    and exc.code == "STALE_TARGET"
                    and "after action" in exc.message.lower()):
                return {
                    "action": action,
                    "target_rerendered_after_action": True,
                    "physical_input_used": False,
                    "verified": False,
                }
            raise
        if self.no_focus and (response.get("auto_set_focus_disabled") is not True or
                              not (response.get("direct_msaa_default_action") is True or
                                   (response.get("direct_uia_invoke") is True and
                                    response.get("no_focus_route") == "NATIVE_UIA_INVOKE"))):
            raise NativeError("BACKEND_CONTRACT_ERROR","No-focus action route was not confirmed",{"retry_safe":False})
        return {k: v for k, v in response.items() if k not in {"id", "ok"}}

    def _request(self, op: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        document_mutation = op == "excel_save" or (op in {"word_document","powerpoint_document"} and (args or {}).get("action") != "read")
        try:
            response = self.supervisor.request(op, args)
        except SidecarSupervisorError as exc:
            code = str(exc).split(":", 1)[0]
            raise NativeError(code, str(exc), {
                "restarts": self.supervisor.restart_count,
                **({"attempted": True, "retry_safe": False} if op == "act" or document_mutation else {}),
            }) from exc
        if response.get("ok") is False:
            error = response.get("error") if isinstance(response.get("error"), dict) else {}
            details = dict(error.get("details") or {})
            if op == "act":
                details.update(attempted=True, retry_safe=False)
            elif document_mutation and "attempted" not in details:
                details.update(attempted=True, retry_safe=False)
            raise NativeError(str(error.get("code") or "UIA3_ERROR"), str(error.get("message") or "UIA3 backend error"), details)
        return response
    @staticmethod
    def _hwnd(target: dict[str, Any]) -> int:
        hwnd = target.get("hwnd")
        if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
            raise NativeError("INVALID_ARGUMENT", "target.hwnd must be a positive integer")
        return hwnd

    @staticmethod
    def _normalize_entity(entity: dict[str, Any]) -> dict[str, Any]:
        role = entity.get("role")
        if isinstance(role, str) and role.startswith("ControlType."):
            role = role[len("ControlType."):]
        return {
            "identity": dict(entity.get("identity") or {}),
            "role": role,
            "name": entity.get("name"),
            "automation_id": entity.get("automation_id"),
            "class_name": entity.get("class_name"),
            "value": entity.get("value"),
            "state": {
                "enabled": entity.get("enabled"), "offscreen": entity.get("offscreen"),
                "toggle_state": entity.get("toggle_state"), "selected": entity.get("selected"),
                "expand_state": entity.get("expand_state"),
                "horizontally_scrollable": entity.get("horizontally_scrollable"),
                "vertically_scrollable": entity.get("vertically_scrollable"),
                "horizontal_scroll_percent": entity.get("horizontal_scroll_percent"),
                "vertical_scroll_percent": entity.get("vertical_scroll_percent"),
            },
            "actions": list(entity.get("actions") or []),
            "geometry": None,
        }
