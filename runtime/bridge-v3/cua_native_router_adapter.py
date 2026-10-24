from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from cua_router import RouteExecutionError
from cua_native_supervisor import SidecarSupervisorError


class NativeSupervisor(Protocol):
    def request(self, op: str, args: dict[str, Any] | None = None) -> dict[str, Any]: ...


_EXPECTED_ACTION_SAFETY: dict[str, dict[str, tuple[bool, bool]]] = {
    "UIA_PATTERN": {
        "set_value": (False, True),
        "invoke": (False, True),
        "toggle": (False, True),
        "select": (False, True),
        "expand": (False, True),
        "collapse": (False, True),
        "scroll_into_view": (False, True),
        "scroll": (False, True),
    },
    "HWND_MESSAGE": {
        "set_value": (True, False),
        "invoke": (True, False),
        "toggle": (True, False),
        "select_index": (True, False),
    },
}

_MUTATION_MAY_HAVE_OCCURRED = frozenset({
    "HWND_ACTION_OUTCOME_UNKNOWN",
    "HWND_ACTION_FAILED",
    "POSTCONDITION_FAILED",
    "ACTION_UNVERIFIED",
})


@dataclass
class NativeSidecarRouterAdapter:
    """Expose a native semantic JSONL sidecar as one ControlRouter route.

    Action safety is checked twice: the integration contract supplies the
    expected safety class, while the live sidecar capability response is the
    runtime source of truth. Any disagreement is a hard pre-action failure so a
    backend update cannot silently turn a background-safe request into an
    exclusive-desktop mutation.
    """

    route: str
    supervisor: NativeSupervisor
    _capability_cache: dict[str, Any] | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.route not in _EXPECTED_ACTION_SAFETY:
            raise ValueError("route must be UIA_PATTERN or HWND_MESSAGE")

    def _backend_capabilities(self) -> dict[str, Any]:
        if self._capability_cache is not None:
            return self._capability_cache
        try:
            response = self.supervisor.request("capabilities", {})
        except Exception as exc:
            raise RouteExecutionError(
                "ROUTE_UNAVAILABLE",
                f"native capability probe failed: {type(exc).__name__}: {exc}",
                attempted=False,
            ) from exc
        if not isinstance(response, Mapping) or not bool(response.get("ok", False)):
            raise RouteExecutionError(
                "ROUTE_UNAVAILABLE",
                "native capability probe did not succeed",
                attempted=False,
            )
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise RouteExecutionError(
                "ROUTE_UNAVAILABLE",
                "native capability probe returned no result",
                attempted=False,
            )
        if result.get("route") != self.route:
            raise RouteExecutionError(
                "BACKEND_CAPABILITY_DRIFT",
                "native sidecar route does not match adapter route",
                attempted=False,
                details={"expected_route": self.route, "actual_route": result.get("route")},
            )
        backend = result.get("backend")
        if not isinstance(backend, Mapping):
            raise RouteExecutionError(
                "BACKEND_CAPABILITY_DRIFT",
                "native sidecar has no backend capability object",
                attempted=False,
            )
        self._capability_cache = dict(backend)
        return self._capability_cache

    def can_handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        action = request.get("operation")
        if not isinstance(action, str):
            return {"supported": False, "reason": "operation_missing"}
        expected = _EXPECTED_ACTION_SAFETY[self.route].get(action)
        if expected is None:
            return {"supported": False, "reason": "unsupported_action"}

        backend = self._backend_capabilities()
        background_actions = backend.get("background_safe_actions")
        exclusive_actions = backend.get("desktop_exclusive_actions")
        if not isinstance(background_actions, list) or not isinstance(exclusive_actions, list):
            raise RouteExecutionError(
                "BACKEND_CAPABILITY_DRIFT",
                "native backend does not expose action-safety capability lists",
                attempted=False,
            )
        actual = (action in background_actions, action in exclusive_actions)
        if actual != expected:
            raise RouteExecutionError(
                "BACKEND_CAPABILITY_DRIFT",
                "native backend action safety differs from the integration contract",
                attempted=False,
                details={"route": self.route, "action": action, "expected": expected, "actual": actual},
            )
        return {
            "supported": True,
            "background_safe": actual[0],
            "desktop_exclusive": actual[1],
        }

    def act(self, request: Mapping[str, Any]) -> dict[str, Any]:
        ref = request.get("ref")
        action = request.get("operation")
        if not isinstance(ref, str) or not ref:
            raise RouteExecutionError("STALE_TARGET", "native semantic action requires a ref", attempted=False)
        if not isinstance(action, str) or action not in _EXPECTED_ACTION_SAFETY[self.route]:
            raise RouteExecutionError("ACTION_UNSUPPORTED", attempted=False)

        requested_generation = request.get("generation")
        if requested_generation is not None and (
            isinstance(requested_generation, bool)
            or not isinstance(requested_generation, int)
            or requested_generation <= 0
        ):
            raise RouteExecutionError(
                "INVALID_ARGUMENT", "generation must be a positive integer", attempted=False,
            )
        generation = requested_generation

        args = request.get("action_args")
        if args is None:
            args = {}
        if not isinstance(args, Mapping):
            raise RouteExecutionError("INVALID_ARGUMENT", "action_args must be an object", attempted=False)
        postcondition = request.get("postcondition")
        if postcondition is not None and not isinstance(postcondition, Mapping):
            raise RouteExecutionError("INVALID_ARGUMENT", "postcondition must be an object", attempted=False)

        payload = {
            "ref": ref,
            "generation": generation,
            "action": action,
            "action_args": dict(args),
            "postcondition": dict(postcondition) if postcondition is not None else None,
            "policy": {},
        }
        try:
            response = self.supervisor.request("act", payload)
        except SidecarSupervisorError as exc:
            raise RouteExecutionError(
                "ROUTE_EXECUTION_UNCERTAIN",
                str(exc),
                attempted=True,
                details={"route": self.route, "sidecar_error": str(exc), "retry_safe": False},
            ) from exc
        except Exception as exc:
            raise RouteExecutionError(
                "ROUTE_EXECUTION_UNCERTAIN",
                f"{type(exc).__name__}: {exc}",
                attempted=True,
                details={"route": self.route, "retry_safe": False},
            ) from exc

        if not isinstance(response, Mapping):
            raise RouteExecutionError(
                "ROUTE_EXECUTION_UNCERTAIN",
                "native sidecar returned a non-object response",
                attempted=True,
                details={"route": self.route, "retry_safe": False},
            )
        if not bool(response.get("ok", False)):
            error = response.get("error")
            if isinstance(error, Mapping):
                code = str(error.get("code") or "NATIVE_ACTION_FAILED")
                message = str(error.get("message") or code)
                details = dict(error.get("details") or {})
            else:
                code = "NATIVE_ACTION_FAILED"
                message = code
                details = {}
            attempted = (code in _MUTATION_MAY_HAVE_OCCURRED
                         or details.get("attempted") is True
                         or details.get("retry_safe") is False)
            if attempted:
                details["retry_safe"] = False
            if code == "HWND_ACTION_OUTCOME_UNKNOWN":
                details.setdefault("retry_safe", False)
            raise RouteExecutionError(code, message, attempted=attempted, details=details)

        result = response.get("result")
        if not isinstance(result, Mapping):
            raise RouteExecutionError(
                "ROUTE_EXECUTION_UNCERTAIN",
                "native sidecar response has no result object",
                attempted=True,
                details={"route": self.route, "retry_safe": False},
            )
        return dict(result)
