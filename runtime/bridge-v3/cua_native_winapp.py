from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Callable

from cua_native_core import NativeError


class WinAppCliBackend:
    """Semantic backend adapter for Microsoft winapp ui JSON commands.

    The adapter accepts both the current WinApp CLI envelopes and the older
    public JSON shapes where doing so is unambiguous. It deliberately exposes
    no mouse/keyboard/touch/pen verbs: physical input belongs to the outer
    router/lease policy.
    """

    route = "UIA_PATTERN"

    def __init__(self, executable: str = "winapp", runner: Callable[..., subprocess.CompletedProcess[str]] | None = None):
        self.executable = executable
        self._runner = runner or subprocess.run

    def capabilities(self) -> dict[str, Any]:
        return {
            "engine": "microsoft-winapp-cli",
            "executable": self.executable,
            "available": shutil.which(self.executable) is not None,
            "preview_dependency": True,
            "semantic_actions": ["invoke", "set_value", "scroll_into_view"],
            "physical_actions_exposed": False,
            # WinApp documents set-value and scroll-into-view as shared/background
            # UIA mutations. Invoke is semantic UIA but takes an exclusive desktop
            # turn in WinApp's own coordinator, so the outer policy must not infer
            # background-safety solely from route == UIA_PATTERN.
            "background_safe_actions": ["set_value", "scroll_into_view"],
            "desktop_exclusive_actions": ["invoke"],
        }

    def fingerprint(self, target: dict[str, Any]) -> dict[str, Any]:
        # list-windows accepts -a but intentionally does NOT accept -w. For an
        # HWND target enumerate windows then select the exact numeric handle.
        if target.get("hwnd") is not None:
            payload = self._run(["ui", "list-windows", "--json"])
            windows = self._window_list(payload)
            wanted = self._hwnd_int(target["hwnd"])
            if wanted is None:
                raise NativeError("INVALID_ARGUMENT", "Invalid hwnd target", {"hwnd": target.get("hwnd")})
            windows = [item for item in windows if self._hwnd_int(item.get("hwnd")) == wanted]
        elif target.get("app"):
            payload = self._run(["ui", "list-windows", "-a", str(target["app"]), "--json"])
            windows = self._window_list(payload)
        else:
            raise NativeError("INVALID_ARGUMENT", "Target requires hwnd or app")

        if len(windows) != 1:
            code = "TARGET_AMBIGUOUS" if len(windows) > 1 else "TARGET_NOT_FOUND"
            raise NativeError(code, "Target window did not resolve uniquely", {"count": len(windows), "target": target})
        win = windows[0]
        hwnd = self._hwnd_int(win.get("hwnd"))
        if hwnd is None:
            raise NativeError("BACKEND_CONTRACT_ERROR", "winapp list-windows result has invalid hwnd")
        # Title and foreground state are mutable evidence, not target identity.
        return {
            "hwnd": hex(hwnd),
            "class_name": win.get("className") or win.get("class_name"),
            "pid": win.get("processId", win.get("pid")),
        }

    def snapshot(self, target: dict[str, Any], options: dict[str, Any]) -> list[dict[str, Any]]:
        args = ["ui", "inspect", *self._target_args(target), "--json"]
        if options.get("interactive"):
            args.append("--interactive")
        depth = options.get("depth")
        if isinstance(depth, int) and not isinstance(depth, bool) and depth >= 0:
            args += ["--depth", str(depth)]
        payload = self._run(args)
        windows = payload.get("windows", []) if isinstance(payload, dict) else []
        if len(windows) != 1:
            code = "TARGET_AMBIGUOUS" if len(windows) > 1 else "TARGET_NOT_FOUND"
            raise NativeError(code, "Inspect target did not resolve uniquely", {"count": len(windows)})
        elements = windows[0].get("elements") or []
        if not isinstance(elements, list):
            raise NativeError("BACKEND_CONTRACT_ERROR", "winapp inspect elements is not a list")
        out: list[dict[str, Any]] = []
        self._flatten(elements, out)
        return out

    def resolve(self, target: dict[str, Any], identity: dict[str, Any]) -> list[dict[str, Any]]:
        selector = identity.get("selector")
        if not selector:
            return []
        try:
            payload = self._run(["ui", "search", str(selector), *self._target_args(target), "--json"])
        except NativeError as exc:
            if exc.code in {"element_not_found", "TARGET_NOT_FOUND"}:
                return []
            raise
        matches = self._search_matches(payload)
        normalized = [self._entity(item) for item in matches]
        return [item for item in normalized if item["identity"] == identity]

    def act(self, target: dict[str, Any], entity: dict[str, Any], action: str, args: dict[str, Any]) -> dict[str, Any]:
        selector = str(entity["identity"]["selector"])
        target_args = self._target_args(target)
        if action == "invoke":
            result = self._run(["ui", "invoke", selector, *target_args, "--json"])
        elif action == "set_value":
            if "value" not in args:
                raise NativeError("INVALID_ARGUMENT", "set_value requires value")
            result = self._run(["ui", "set-value", selector, str(args["value"]), *target_args, "--json"])
        elif action == "scroll_into_view":
            result = self._run(["ui", "scroll-into-view", selector, *target_args, "--json"])
        else:
            raise NativeError("ACTION_UNSUPPORTED", f"WinApp semantic adapter does not expose {action!r}")
        return {"engine_result": result}

    def read_entity(self, target: dict[str, Any], entity: dict[str, Any]) -> dict[str, Any]:
        selector = str(entity["identity"]["selector"])
        payload = self._run(["ui", "search", selector, *self._target_args(target), "--json"])
        matches = self._search_matches(payload)
        normalized = [self._entity(item) for item in matches]
        exact = [item for item in normalized if item["identity"] == entity["identity"]]
        if len(exact) != 1:
            raise NativeError("STALE_TARGET" if not exact else "TARGET_AMBIGUOUS", "Entity no longer resolves uniquely")
        current = exact[0]

        # Current WinApp get-value is itself a background-safe read and succeeds
        # with text/null even when it must fall back from TextPattern/ValuePattern
        # to Name. Do not hide transport/coordination/staleness failures here.
        value_payload = self._run(["ui", "get-value", selector, *self._target_args(target), "--json"])
        if not isinstance(value_payload, dict):
            raise NativeError("BACKEND_CONTRACT_ERROR", "Unexpected winapp get-value JSON shape")
        if "text" in value_payload:
            current["value"] = value_payload.get("text")
        elif "value" in value_payload:  # compatibility with older preview shape
            current["value"] = value_payload.get("value")
        else:
            raise NativeError("BACKEND_CONTRACT_ERROR", "winapp get-value result has no text/value field")
        return current

    def _run(self, args: list[str]) -> Any:
        env = os.environ.copy()
        try:
            cp = self._runner(
                [self.executable, *args],
                text=True,
                capture_output=True,
                timeout=10,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise NativeError("SIDECAR_BACKEND_TIMEOUT", "winapp command timed out", {"args": args}) from exc
        if cp.returncode != 0:
            err = self._parse_json(cp.stderr)
            if isinstance(err, dict) and isinstance(err.get("error"), dict):
                item = err["error"]
                raise NativeError(str(item.get("code") or "WINAPP_ERROR"), str(item.get("message") or "winapp failed"), item)
            raise NativeError("WINAPP_ERROR", (cp.stderr or cp.stdout or "winapp failed")[-2000:], {"exit_code": cp.returncode})
        payload = self._parse_json(cp.stdout)
        if payload is None:
            raise NativeError("BACKEND_CONTRACT_ERROR", "winapp returned non-JSON output", {"stdout": cp.stdout[-1000:]})
        return payload

    @staticmethod
    def _parse_json(text: str) -> Any | None:
        text = (text or "").strip().lstrip("\ufeff")
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _target_args(target: dict[str, Any]) -> list[str]:
        if target.get("hwnd") is not None:
            return ["-w", str(target["hwnd"])]
        if target.get("app"):
            return ["-a", str(target["app"])]
        raise NativeError("INVALID_ARGUMENT", "Target requires hwnd or app")

    @staticmethod
    def _window_list(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict) and isinstance(payload.get("windows"), list):
            return [item for item in payload["windows"] if isinstance(item, dict)]
        raise NativeError("BACKEND_CONTRACT_ERROR", "Unexpected winapp list-windows JSON shape")

    @staticmethod
    def _search_matches(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            # Current WinApp main uses UiSearchResult.matches. Keep older public
            # `elements` shape for compatibility with preview builds.
            for key in ("matches", "elements"):
                value = payload.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
        raise NativeError("BACKEND_CONTRACT_ERROR", "Unexpected winapp search JSON shape")

    @staticmethod
    def _hwnd_int(value: Any) -> int | None:
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, int):
            return value if value > 0 else None
        if isinstance(value, str):
            raw = value.strip()
            try:
                parsed = int(raw, 0)
            except ValueError:
                try:
                    parsed = int(raw, 10)
                except ValueError:
                    return None
            return parsed if parsed > 0 else None
        return None

    def _flatten(self, nodes: list[dict[str, Any]], out: list[dict[str, Any]]) -> None:
        for node in nodes:
            if not isinstance(node, dict):
                continue
            out.append(self._entity(node))
            children = node.get("children") or []
            if isinstance(children, list):
                self._flatten(children, out)

    @staticmethod
    def _entity(node: dict[str, Any]) -> dict[str, Any]:
        selector = node.get("selector")
        if not selector:
            raise NativeError("BACKEND_CONTRACT_ERROR", "winapp element missing selector")
        # UiElement currently serializes `type`; the v0.3.1 public envelope docs
        # used `controlType`, so support both while the preview contract settles.
        role = node.get("type") or node.get("controlType") or node.get("role")
        actions = []
        text = str(role or "").lower()
        if bool(node.get("isInvokable")) or any(x in text for x in ("button", "menuitem", "hyperlink", "tabitem")):
            actions.append("invoke")
        if node.get("value") is not None or any(x in text for x in ("edit", "textbox", "combobox", "slider")):
            actions.append("set_value")
        actions.append("scroll_into_view")

        rect = node.get("boundingRectangle") or node.get("bounds")
        if isinstance(rect, dict):
            geometry = dict(rect)
        else:
            geometry = {
                "x": node.get("x"),
                "y": node.get("y"),
                "width": node.get("width"),
                "height": node.get("height"),
            }
            geometry = {key: value for key, value in geometry.items() if value is not None}

        state = {
            "enabled": node.get("isEnabled"),
            "offscreen": node.get("isOffscreen"),
            "focused": node.get("hasKeyboardFocus"),
            "toggle": node.get("toggleState"),
            "expand": node.get("expandState"),
            "scroll_dir": node.get("scrollDir"),
        }
        return {
            "identity": {"selector": str(selector)},
            "role": role,
            "name": node.get("name"),
            "automation_id": node.get("automationId"),
            "class_name": node.get("className"),
            "value": node.get("value"),
            "state": {key: value for key, value in state.items() if value is not None},
            "actions": sorted(set(actions)),
            "geometry": geometry,
        }
