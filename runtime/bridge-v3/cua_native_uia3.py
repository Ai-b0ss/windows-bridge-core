from __future__ import annotations

from pathlib import Path
from typing import Any

from cua_native_core import NativeError
from cua_native_supervisor import NativeSidecarSupervisor, SidecarSupervisorError


class Uia3PersistentBackend:
    """Persistent System.Windows.Automation backend behind a killable process boundary.

    The child owns a dedicated COM MTA worker and never exposes physical input.
    Mutation uses action-time re-resolution. Stable AutomationId is preferred;
    elements without one use a hierarchy path plus a short-lived runtime-id guard.
    """

    route = "UIA_PATTERN"
    no_focus = False

    def __init__(self, executable: str | Path, timeout_seconds: float = 5.0, *, no_focus: bool = False):
        if type(no_focus) is not bool:raise ValueError("no_focus must be boolean")
        self.no_focus = no_focus
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
        }
    def fingerprint(self, target: dict[str, Any]) -> dict[str, Any]:
        hwnd = self._hwnd(target)
        response = self._request("fingerprint", {"hwnd": hwnd})
        return {"hwnd": int(response["hwnd"]), "process_id": int(response["process_id"])}

    def snapshot(self, target: dict[str, Any], options: dict[str, Any]) -> list[dict[str, Any]]:
        max_items = options.get("max_items", 256)
        if isinstance(max_items, bool) or not isinstance(max_items, int) or not 1 <= max_items <= 512:
            raise NativeError("INVALID_ARGUMENT", "max_items must be between 1 and 512")
        response = self._request("snapshot", {"hwnd": self._hwnd(target), "max_items": max_items})
        entities = response.get("entities")
        if not isinstance(entities, list):
            raise NativeError("BACKEND_CONTRACT_ERROR", "UIA3 snapshot did not return entities")
        return [self._normalize_entity(x) for x in entities if isinstance(x, dict)]

    def resolve(self, target: dict[str, Any], identity: dict[str, Any]) -> list[dict[str, Any]]:
        try:
            response = self._request("get", {"hwnd": self._hwnd(target), "identity": identity})
        except NativeError as exc:
            if exc.code == "STALE_TARGET":
                return []
            raise
        entity = response.get("entity")
        return [self._normalize_entity(entity)] if isinstance(entity, dict) else []

    def read_entity(self, target: dict[str, Any], entity: dict[str, Any]) -> dict[str, Any]:
        identity = entity.get("identity")
        if not isinstance(identity, dict):
            raise NativeError("BACKEND_CONTRACT_ERROR", "UIA3 entity has no identity")
        response = self._request("get", {"hwnd": self._hwnd(target), "identity": identity})
        current = response.get("entity")
        if not isinstance(current, dict):
            raise NativeError("BACKEND_CONTRACT_ERROR", "UIA3 get did not return an entity")
        return self._normalize_entity(current)
    def act(self, target: dict[str, Any], entity: dict[str, Any], action: str, args: dict[str, Any]) -> dict[str, Any]:
        if self.no_focus and action!="invoke":raise NativeError("ACTION_UNSUPPORTED","No-focus route supports invoke only")
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
        payload: dict[str, Any] = {"hwnd": self._hwnd(target), "identity": identity, "action": action}
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
        response = self._request("act", payload)
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
