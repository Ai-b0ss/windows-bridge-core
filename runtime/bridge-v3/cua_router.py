from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Mapping, Protocol

ROUTE_ORDER = (
    "APP_API",
    "BROWSER_PLAYWRIGHT",
    "BROWSER_CDP",
    "UIA_PATTERN",
    "HWND_MESSAGE",
    "VISION_SEMANTIC",
    "PHYSICAL_INPUT",
)

SAFE_PREACTION_FALLBACK_CODES = frozenset({
    "ROUTE_UNAVAILABLE",
    "ACTION_UNSUPPORTED",
    "NO_MATCH",
    "NO_SEMANTIC_TARGET",
})

FAIL_CLOSED_CODES = frozenset({
    "STALE_TARGET",
    "TARGET_MOVED",
    "TARGET_AMBIGUOUS",
    "TARGET_DETACHED",
    "USER_ACTIVE",
    "FOREGROUND_CHANGED",
    "SIDECAR_TIMEOUT",
    "ACTION_UNVERIFIED",
    "POSTCONDITION_FAILED",
})

_SEMANTIC_EFFECT_UNKNOWN_CODES = frozenset({
    "HWND_ACTION_OUTCOME_UNKNOWN",
    "ROUTE_EXECUTION_UNCERTAIN",
})


class ControlRouterError(RuntimeError):
    def __init__(self, code: str, message: str | None = None, *, details: Mapping[str, Any] | None = None):
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.details = dict(details or {})


class RouteExecutionError(ControlRouterError):
    """Adapter error with an explicit mutation-attempt boundary."""

    def __init__(
        self,
        code: str,
        message: str | None = None,
        *,
        attempted: bool = False,
        details: Mapping[str, Any] | None = None,
    ):
        super().__init__(code, message, details=details)
        self.attempted = bool(attempted)


@dataclass(frozen=True)
class RoutePolicy:
    background_required: bool = False
    foreground_allowed: bool = True
    physical_input_allowed: bool = False
    require_verified: bool = True


@dataclass(frozen=True)
class RouteRegistration:
    adapter: "RouteAdapter"
    # Static route-level safety is only an upper bound.  A True value does not
    # prove that every operation exposed by the adapter is background-safe.
    background_safe: bool
    physical_input: bool = False


class RouteAdapter(Protocol):
    def can_handle(self, request: Mapping[str, Any]) -> bool | Mapping[str, Any]: ...
    def act(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...


@dataclass
class ControlRouter:
    routes: dict[str, RouteRegistration] = field(default_factory=dict)
    lease_validator: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any] | bool] | None = None

    def register(
        self,
        route: str,
        adapter: RouteAdapter,
        *,
        background_safe: bool,
        physical_input: bool = False,
    ) -> None:
        if route not in ROUTE_ORDER:
            raise ValueError(f"unknown route: {route}")
        if physical_input and route != "PHYSICAL_INPUT":
            raise ValueError("physical_input may only be registered for PHYSICAL_INPUT")
        self.routes[route] = RouteRegistration(
            adapter=adapter,
            background_safe=bool(background_safe),
            physical_input=bool(physical_input),
        )

    def act(
        self,
        request: Mapping[str, Any],
        *,
        policy: RoutePolicy | None = None,
        lease: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        policy = policy or RoutePolicy()
        attempts: list[dict[str, Any]] = []
        skipped_physical = False
        physical_needs_lease = False

        for route in ROUTE_ORDER:
            registration = self.routes.get(route)
            if registration is None:
                continue

            # A statically unsafe route can be rejected immediately.  Static
            # background_safe=True is deliberately not sufficient: action-level
            # safety is established by can_handle() below.
            if policy.background_required and not registration.background_safe:
                attempts.append({
                    "route": route,
                    "status": "policy_rejected",
                    "reason": "route_not_background_safe",
                    "background_safe": False,
                    "desktop_exclusive": registration.physical_input,
                })
                if registration.physical_input:
                    skipped_physical = True
                continue

            if registration.physical_input:
                if not policy.foreground_allowed or not policy.physical_input_allowed:
                    attempts.append({"route": route, "status": "policy_rejected", "reason": "physical_input_disallowed"})
                    skipped_physical = True
                    continue
                if not lease or not lease.get("lease_id"):
                    attempts.append({"route": route, "status": "policy_rejected", "reason": "lease_required"})
                    physical_needs_lease = True
                    continue
                if self.lease_validator is None:
                    raise ControlRouterError(
                        "PHYSICAL_LEASE_VALIDATION_UNAVAILABLE",
                        details={"route": route, "route_attempts": attempts},
                    )
                try:
                    lease_validation = self.lease_validator(lease, request)
                except ControlRouterError:
                    raise
                except Exception as exc:
                    code = getattr(exc, "code", "PHYSICAL_LEASE_INVALID")
                    raise ControlRouterError(
                        str(code),
                        details={"route": route, "lease_id": lease.get("lease_id"), "route_attempts": attempts},
                    ) from exc
                if isinstance(lease_validation, Mapping):
                    lease_valid = bool(lease_validation.get("ok", False))
                    lease_error = str(lease_validation.get("error_code") or "PHYSICAL_LEASE_INVALID")
                else:
                    lease_valid = bool(lease_validation)
                    lease_error = "PHYSICAL_LEASE_INVALID"
                if not lease_valid:
                    raise ControlRouterError(
                        lease_error,
                        details={
                            "route": route, "lease_id": lease.get("lease_id"),
                            "lease_validation": dict(lease_validation) if isinstance(lease_validation, Mapping) else lease_validation,
                            "terminal_failure_reason": lease_error, "route_attempts": attempts,
                        },
                    )

            route_request: Mapping[str, Any] = request
            if policy.background_required:
                route_request = dict(route_request)
                route_request["_router_background_required"] = True
            if registration.physical_input:
                route_request = dict(route_request)
                route_request["_validated_physical_lease"] = dict(lease or {})
                if isinstance(lease_validation, Mapping):
                    route_request["_lease_validation"] = dict(lease_validation)

            adapter = registration.adapter
            try:
                supported = adapter.can_handle(route_request)
            except RouteExecutionError as exc:
                try:
                    self._handle_route_error(route, exc, attempts)
                except _ContinueRouting:
                    continue
            except Exception as exc:
                raise ControlRouterError(
                    "ROUTE_PROBE_FAILED",
                    details={"route": route, "error": f"{type(exc).__name__}: {exc}", "route_attempts": attempts},
                ) from exc

            action_background_safe: bool | None = None
            desktop_exclusive: bool | None = None
            if isinstance(supported, Mapping):
                is_supported = bool(supported.get("supported", False))
                reason = supported.get("reason")
                if isinstance(supported.get("background_safe"), bool):
                    action_background_safe = bool(supported["background_safe"])
                if isinstance(supported.get("desktop_exclusive"), bool):
                    desktop_exclusive = bool(supported["desktop_exclusive"])
            else:
                is_supported = bool(supported)
                reason = None

            if not is_supported:
                attempts.append({"route": route, "status": "unsupported", "reason": reason})
                continue

            # Background-required requests need affirmative, request-specific
            # safety evidence.  Unknown safety fails closed even if the route's
            # static upper bound is True.  This is essential for UIA_PATTERN,
            # where e.g. set_value may be background-safe while invoke is
            # desktop-exclusive.
            if policy.background_required:
                if action_background_safe is not True or desktop_exclusive is not False:
                    if desktop_exclusive is True:
                        rejection_reason = "action_desktop_exclusive"
                    elif action_background_safe is False:
                        rejection_reason = "action_not_background_safe"
                    else:
                        rejection_reason = "action_background_safety_unknown"
                    attempts.append({
                        "route": route,
                        "status": "policy_rejected",
                        "reason": rejection_reason,
                        "background_safe": action_background_safe,
                        "desktop_exclusive": desktop_exclusive,
                    })
                    continue

            started = time.monotonic_ns()
            try:
                raw = dict(adapter.act(route_request))
            except RouteExecutionError as exc:
                latency_ms = (time.monotonic_ns() - started) / 1_000_000
                exc.details.setdefault("latency_ms", latency_ms)
                terminal = exc.attempted or exc.code in FAIL_CLOSED_CODES or exc.code not in SAFE_PREACTION_FALLBACK_CODES
                if terminal and isinstance(exc.details.get("receipt"), Mapping):
                    existing_receipt = dict(exc.details["receipt"])
                    receipt_raw = dict(existing_receipt)
                    receipt_raw.setdefault("attempted", exc.attempted)
                    receipt_raw.setdefault("retry_safe", exc.details.get("retry_safe", False))
                    receipt_raw.setdefault(
                        "terminal_failure_reason",
                        exc.details.get("terminal_failure_reason", exc.code),
                    )
                    normalized = self._normalize_receipt(
                        route=route, request=request, raw=receipt_raw, policy=policy, lease=lease,
                        latency_ms=latency_ms, route_attempts=attempts,
                        action_background_safe=action_background_safe, desktop_exclusive=desktop_exclusive,
                    )
                    for key in (
                        "route", "attempted", "retry_safe", "terminal_failure_reason",
                        "fallback_chain", "route_attempts",
                    ):
                        existing_receipt[key] = normalized[key]
                    exc.details["receipt"] = existing_receipt
                elif terminal and "receipt" not in exc.details:
                    effect_unknown = exc.code in _SEMANTIC_EFFECT_UNKNOWN_CODES
                    failure_raw = {
                        "verified": False,
                        "physical_input_used": route == "PHYSICAL_INPUT",
                        "physical_effect_unknown": route == "PHYSICAL_INPUT" and effect_unknown,
                        "semantic_effect_unknown": route != "PHYSICAL_INPUT" and effect_unknown,
                        "terminal_failure_reason": exc.code,
                        "attempted": exc.attempted,
                        "retry_safe": exc.details.get("retry_safe", False),
                        "retries": 0,
                    }
                    failure_receipt = self._normalize_receipt(
                        route=route,
                        request=request,
                        raw=failure_raw,
                        policy=policy,
                        lease=lease,
                        latency_ms=latency_ms,
                        route_attempts=attempts,
                        action_background_safe=action_background_safe,
                        desktop_exclusive=desktop_exclusive,
                    )
                    failure_receipt["error_code"] = exc.code
                    exc.details["receipt"] = failure_receipt
                try:
                    self._handle_route_error(route, exc, attempts)
                except _ContinueRouting:
                    continue
            except Exception as exc:
                latency_ms = (time.monotonic_ns() - started) / 1_000_000
                code = "ROUTE_EXECUTION_UNCERTAIN"
                failure_receipt = self._normalize_receipt(
                    route=route,
                    request=request,
                    raw={
                        "verified": False,
                        "physical_input_used": route == "PHYSICAL_INPUT",
                        "physical_effect_unknown": route == "PHYSICAL_INPUT",
                        "semantic_effect_unknown": route != "PHYSICAL_INPUT",
                        "terminal_failure_reason": code,
                        "attempted": True,
                        "retry_safe": False,
                    },
                    policy=policy,
                    lease=lease,
                    latency_ms=latency_ms,
                    route_attempts=attempts,
                    action_background_safe=action_background_safe,
                    desktop_exclusive=desktop_exclusive,
                )
                raise ControlRouterError(
                    code,
                    details={
                        "route": route,
                        "error": f"{type(exc).__name__}: {exc}",
                        "receipt": failure_receipt,
                        "terminal_failure_reason": code,
                        "route_attempts": attempts,
                    },
                ) from exc

            latency_ms = (time.monotonic_ns() - started) / 1_000_000
            receipt = self._normalize_receipt(
                route=route,
                request=request,
                raw=raw,
                policy=policy,
                lease=lease,
                latency_ms=latency_ms,
                route_attempts=attempts,
                action_background_safe=action_background_safe,
                desktop_exclusive=desktop_exclusive,
            )
            if policy.require_verified and not receipt["verified"]:
                verification = receipt.get("verification")
                explicit_mismatch = (
                    request.get("postcondition") is not None
                    and isinstance(verification, Mapping)
                    and "expected" in verification
                    and "actual" in verification
                    and verification.get("expected") != verification.get("actual")
                )
                code = "POSTCONDITION_FAILED" if explicit_mismatch else "ACTION_UNVERIFIED"
                receipt["terminal_failure_reason"] = code
                receipt["attempted"] = True
                receipt["retry_safe"] = False
                raise ControlRouterError(
                    code,
                    details={
                        "route": route,
                        "receipt": receipt,
                        "terminal_failure_reason": code,
                    },
                )
            return receipt

        if policy.background_required:
            # A malformed operation has no executable route at all; it is not a
            # background-policy failure. Keep NO_BACKGROUND_ROUTE for valid
            # operations that exhausted the background-safe choices.
            operation = request.get("operation")
            if not isinstance(operation, str) or not operation:
                raise ControlRouterError("ROUTE_UNAVAILABLE", details={"route_attempts": attempts})
            raise ControlRouterError("NO_BACKGROUND_ROUTE", details={"route_attempts": attempts})
        if physical_needs_lease:
            raise ControlRouterError("NEEDS_FOREGROUND_LEASE", details={"route_attempts": attempts})
        raise ControlRouterError("ROUTE_UNAVAILABLE", details={"route_attempts": attempts})

    def _handle_route_error(
        self,
        route: str,
        exc: RouteExecutionError,
        attempts: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if exc.attempted or exc.code in FAIL_CLOSED_CODES or exc.code not in SAFE_PREACTION_FALLBACK_CODES:
            raise ControlRouterError(
                exc.code,
                exc.message,
                details={
                    **exc.details, "route": route, "attempted": exc.attempted,
                    "terminal_failure_reason": exc.details.get("terminal_failure_reason", exc.code),
                    "route_attempts": attempts,
                },
            ) from exc
        attempts.append({"route": route, "status": "fallback", "error_code": exc.code, "details": exc.details})
        raise _ContinueRouting(attempts)

    @staticmethod
    def _normalize_receipt(
        *,
        route: str,
        request: Mapping[str, Any],
        raw: Mapping[str, Any],
        policy: RoutePolicy,
        lease: Mapping[str, Any] | None,
        latency_ms: float,
        route_attempts: list[dict[str, Any]],
        action_background_safe: bool | None,
        desktop_exclusive: bool | None,
    ) -> dict[str, Any]:
        target_before = raw.get("target_before", request.get("target"))
        generation = raw.get("generation", request.get("generation"))
        ref = raw.get("ref", request.get("ref"))
        verified = bool(raw.get("verified", False))
        fallback_chain = [item["route"] for item in route_attempts if item.get("status") in {"fallback", "unsupported", "policy_rejected"}]
        raw_fallback_chain = [
            item for item in raw.get("fallback_chain", [])
            if isinstance(item, str) and item != route and item not in fallback_chain
        ]
        return {
            "operation": raw.get("operation", request.get("operation", "act")),
            "route": route,
            "target_before": target_before,
            "generation": generation,
            "ref": ref,
            "policy": asdict(policy),
            "background_safe": raw.get("background_safe", action_background_safe),
            "desktop_exclusive": raw.get("desktop_exclusive", desktop_exclusive),
            "physical_input_used": bool(raw.get("physical_input_used", route == "PHYSICAL_INPUT")),
            "semantic_effect_unknown": bool(raw.get("semantic_effect_unknown", False)),
            "physical_effect_unknown": bool(raw.get("physical_effect_unknown", False)),
            "attempted": bool(raw.get("attempted", True)),
            "retry_safe": raw.get("retry_safe"),
            "user_active": raw.get("user_active"),
            "sent": raw.get("sent"),
            "sequence_ok": raw.get("sequence_ok"),
            "verification_error": raw.get("verification_error"),
            "lease_id": (lease or {}).get("lease_id"),
            "started_at": raw.get("started_at"),
            "ended_at": raw.get("ended_at"),
            "latency_ms": raw.get("latency_ms", latency_ms),
            "action_result": raw.get("action_result", raw.get("result")),
            "verified": verified,
            "verification": raw.get("verification"),
            "focus_preserved": raw.get("focus_preserved"),
            "cursor_preserved": raw.get("cursor_preserved"),
            "foreground_before": raw.get("foreground_before"),
            "foreground_after": raw.get("foreground_after"),
            "fallback_chain": fallback_chain + raw_fallback_chain,
            "route_attempts": [dict(item) for item in route_attempts],
            "retries": int(raw.get("retries", 0)),
            "recovery": raw.get("recovery"),
            "trace_id": raw.get("trace_id"),
            "artifact_ids": list(raw.get("artifact_ids", [])),
            "target": raw.get("target", target_before),
            "lease": raw.get("lease", dict(lease) if lease else None),
            "privileged_capability_route": raw.get("privileged_capability_route"),
            "operation_id": raw.get("operation_id"),
            "matched": raw.get("matched"),
            "completed": raw.get("completed"),
            "cleanup": raw.get("cleanup"),
            "terminal_failure_reason": raw.get("terminal_failure_reason"),
            "wrong_target": raw.get("wrong_target"),
            "visual_capture_id": raw.get("visual_capture_id"),
            "visual_generation": raw.get("visual_generation"),
            "visual_fresh": raw.get("visual_fresh"),
            "visual_drift_px": raw.get("visual_drift_px"),
            "visual_target": raw.get("visual_target"),
        }


class _ContinueRouting(Exception):
    def __init__(self, attempts: list[dict[str, Any]]):
        self.attempts = attempts
