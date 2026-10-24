from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol


class NativeError(RuntimeError):
    def __init__(self, code: str, message: str | None = None, details: dict[str, Any] | None = None):
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.details = details or {}

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "details": self.details}


class NativeBackend(Protocol):
    route: str

    def capabilities(self) -> dict[str, Any]: ...
    def fingerprint(self, target: dict[str, Any]) -> dict[str, Any]: ...
    def snapshot(self, target: dict[str, Any], options: dict[str, Any]) -> list[dict[str, Any]]: ...
    def resolve(self, target: dict[str, Any], identity: dict[str, Any]) -> list[dict[str, Any]]: ...
    def act(self, target: dict[str, Any], entity: dict[str, Any], action: str, args: dict[str, Any]) -> dict[str, Any]: ...
    def read_entity(self, target: dict[str, Any], entity: dict[str, Any]) -> dict[str, Any]: ...


@dataclass
class SnapshotState:
    generation: int
    target: dict[str, Any]
    fingerprint: dict[str, Any]
    entities: dict[str, dict[str, Any]] = field(default_factory=dict)


class NativeSemanticCore:
    """Backend-independent semantic native-control contract.

    There is intentionally no coordinate or physical-input fallback here. A
    stale or ambiguous ref fails closed and the outer router decides whether a
    more disruptive route is allowed.
    """

    _QUERY_KEYS = {"role", "name", "automation_id", "class_name", "control_id"}
    _POSTCONDITION_TYPES = {"value_equals", "state_equals"}
    _POLICY_KEYS = {"background_required"}

    def __init__(self, backend: NativeBackend):
        self.backend = backend
        self._generation = 0
        self._snapshots: dict[int, SnapshotState] = {}

    def capabilities(self) -> dict[str, Any]:
        return {
            "route": self.backend.route,
            "semantic_only": True,
            "physical_input_fallback": False,
            "generation_scoped_refs": True,
            "action_time_reresolution": True,
            "explicit_verification": True,
            "backend": self.backend.capabilities(),
        }

    def observe(self, target: dict[str, Any], options: dict[str, Any] | None = None) -> dict[str, Any]:
        options = dict(options or {})
        fingerprint = self.backend.fingerprint(target)
        raw = self.backend.snapshot(target, options)
        self._generation += 1
        generation = self._generation
        entities: dict[str, dict[str, Any]] = {}
        out = []
        for index, entity in enumerate(raw, 1):
            normalized = self._normalize_entity(entity)
            ref = f"g{generation}e{index}"
            normalized["ref"] = ref
            normalized["generation"] = generation
            entities[ref] = normalized
            out.append(normalized)
        self._snapshots[generation] = SnapshotState(
            generation=generation,
            target=dict(target),
            fingerprint=fingerprint,
            entities=entities,
        )
        for old in sorted(self._snapshots)[:-8]:
            self._snapshots.pop(old, None)
        return {
            "generation": generation,
            "route": self.backend.route,
            "target": dict(target),
            "fingerprint": fingerprint,
            "entities": out,
        }

    def find(self, generation: int, query: dict[str, Any]) -> dict[str, Any]:
        self._validate_generation(generation)
        self._validate_query(query)
        state = self._snapshots.get(generation)
        if not state:
            raise NativeError("STALE_TARGET", "Snapshot generation is no longer available", {"generation": generation})
        matches = [entity for entity in state.entities.values() if self._matches(entity, query)]
        return {"generation": generation, "matches": matches, "count": len(matches)}

    def get(self, ref: str) -> dict[str, Any]:
        state, entity = self._state_and_entity(ref)
        self._guard_surface(state)
        resolved = self._resolve_one(state, entity)
        current = self.backend.read_entity(state.target, resolved)
        return {"ref": ref, "generation": state.generation, "entity": current, "route": self.backend.route}

    def act(
        self,
        ref: str,
        action: str,
        args: dict[str, Any] | None = None,
        postcondition: dict[str, Any] | None = None,
        policy: dict[str, Any] | None = None,
        *,
        generation: int | None = None,
    ) -> dict[str, Any]:
        args = dict(args or {})
        policy = self._validate_policy(policy)
        if generation is not None:
            self._validate_generation(generation)
        # A malformed verification request must fail before the mutation. Otherwise
        # a caller can receive an error even though the target was already changed.
        if postcondition is not None:
            self._validate_postcondition(postcondition)

        started = time.monotonic()
        state, entity = self._state_and_entity(ref)
        if state.generation != self._generation:
            raise NativeError(
                "STALE_TARGET",
                "Semantic ref is not from the current snapshot generation",
                {"ref": ref, "generation": state.generation, "current_generation": self._generation},
            )
        if generation is not None and generation != state.generation:
            raise NativeError(
                "STALE_TARGET",
                "Requested generation does not match the semantic ref generation",
                {"ref": ref, "generation": generation, "ref_generation": state.generation},
            )
        self._guard_surface(state)
        resolved = self._resolve_one(state, entity)
        actions = set(resolved.get("actions") or entity.get("actions") or [])
        if action not in actions:
            raise NativeError(
                "ACTION_UNSUPPORTED",
                f"Action {action!r} is not supported by the resolved entity",
                {"ref": ref, "supported": sorted(actions)},
            )

        safety = self._action_safety(action)
        if policy["background_required"] and not safety["background_safe"]:
            raise NativeError(
                "NO_BACKGROUND_ROUTE",
                f"Action {action!r} is not proven background-safe for this backend",
                {"ref": ref, "route": self.backend.route, "action": action, **safety},
            )

        before = self.backend.read_entity(state.target, resolved)
        phase = "native_action_dispatch"
        try:
            action_result = self.backend.act(state.target, resolved, action, args)
            phase = "native_postcondition"
            verified = False
            verification: dict[str, Any] | None = None
            if postcondition is not None:
                # An action can replace its target; a later stale reference does
                # not prove that the original mutation never happened.
                self._guard_surface(state)
                resolved_after = self._resolve_one(state, entity)
                after = self.backend.read_entity(state.target, resolved_after)
                verified, verification = self._verify(postcondition, after)
        except NativeError as exc:
            raise NativeError(exc.code, exc.message, {
                **exc.details, "attempted": True, "retry_safe": False, "phase": phase,
            }) from exc
        except Exception as exc:
            raise NativeError("NATIVE_ACTION_OUTCOME_UNKNOWN", type(exc).__name__, {
                "attempted": True, "retry_safe": False, "phase": phase,
            }) from exc
        elapsed = int((time.monotonic() - started) * 1000)
        return {
            "ok": True,
            "route": self.backend.route,
            "ref": ref,
            "generation": state.generation,
            "target_before": state.fingerprint,
            "precondition": {"entity": before},
            "policy": policy,
            "background_safe": safety["background_safe"],
            "desktop_exclusive": safety["desktop_exclusive"],
            "action": action,
            "action_result": action_result,
            "latency_ms": elapsed,
            "verified": verified,
            "verification": verification,
            "focus_preserved": action_result.get("focus_preserved") if isinstance(action_result, dict) else None,
            "cursor_preserved": action_result.get("cursor_preserved") if isinstance(action_result, dict) else None,
            "physical_input_used": False,
            "fallback_chain": [self.backend.route],
            "retries": 0,
        }

    def wait_for(
        self,
        target: dict[str, Any],
        query: dict[str, Any],
        timeout_ms: int = 5000,
        poll_ms: int = 100,
    ) -> dict[str, Any]:
        self._validate_query(query)
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms < 0:
            raise NativeError("INVALID_ARGUMENT", "Invalid wait timeout")
        if isinstance(poll_ms, bool) or not isinstance(poll_ms, int) or poll_ms < 1:
            raise NativeError("INVALID_ARGUMENT", "Invalid wait poll interval")
        deadline = time.monotonic() + timeout_ms / 1000.0
        attempts = 0
        while True:
            attempts += 1
            snap = self.observe(target, {"interactive": False})
            found = self.find(snap["generation"], query)
            if found["matches"]:
                return {"ok": True, "generation": snap["generation"], "matches": found["matches"], "attempts": attempts}
            if time.monotonic() >= deadline:
                raise NativeError("WAIT_TIMEOUT", "Condition did not become true", {"query": query, "attempts": attempts})
            time.sleep(min(poll_ms / 1000.0, max(0.0, deadline - time.monotonic())))

    def _state_and_entity(self, ref: str) -> tuple[SnapshotState, dict[str, Any]]:
        if not isinstance(ref, str) or not ref.startswith("g") or "e" not in ref:
            raise NativeError("REF_INVALID", "Malformed semantic ref", {"ref": ref})
        try:
            generation = int(ref[1:].split("e", 1)[0])
        except ValueError as exc:
            raise NativeError("REF_INVALID", "Malformed semantic ref", {"ref": ref}) from exc
        state = self._snapshots.get(generation)
        if not state or ref not in state.entities:
            raise NativeError("STALE_TARGET", "Semantic ref is stale or unknown", {"ref": ref})
        return state, state.entities[ref]

    def _guard_surface(self, state: SnapshotState) -> None:
        current = self.backend.fingerprint(state.target)
        if current != state.fingerprint:
            raise NativeError(
                "STALE_TARGET",
                "Target surface fingerprint changed since observation",
                {"expected": state.fingerprint, "actual": current},
            )

    def _resolve_one(self, state: SnapshotState, entity: dict[str, Any]) -> dict[str, Any]:
        matches = self.backend.resolve(state.target, entity["identity"])
        if not matches:
            raise NativeError("STALE_TARGET", "Observed entity no longer resolves", {"ref": entity["ref"]})
        if len(matches) != 1:
            raise NativeError("TARGET_AMBIGUOUS", "Semantic identity resolves to multiple elements", {"ref": entity["ref"], "matches": len(matches)})
        resolved = self._normalize_entity(matches[0])
        if resolved["identity"] != entity["identity"]:
            raise NativeError("TARGET_MOVED", "Resolved element identity changed", {"ref": entity["ref"]})
        return resolved

    def _action_safety(self, action: str) -> dict[str, bool]:
        caps = self.backend.capabilities()
        background = caps.get("background_safe_actions") or []
        exclusive = caps.get("desktop_exclusive_actions") or []
        return {
            "background_safe": isinstance(background, list) and action in background,
            "desktop_exclusive": isinstance(exclusive, list) and action in exclusive,
        }

    @staticmethod
    def _normalize_entity(entity: dict[str, Any]) -> dict[str, Any]:
        identity = entity.get("identity")
        if not isinstance(identity, dict) or not identity:
            raise NativeError("BACKEND_CONTRACT_ERROR", "Backend entity has no semantic identity")
        return {
            "identity": dict(identity),
            "role": entity.get("role"),
            "name": entity.get("name"),
            "automation_id": entity.get("automation_id"),
            "class_name": entity.get("class_name"),
            "control_id": entity.get("control_id"),
            "value": entity.get("value"),
            "state": dict(entity.get("state") or {}),
            "actions": list(entity.get("actions") or []),
            "geometry": dict(entity.get("geometry") or {}),
        }

    @staticmethod
    def _validate_generation(generation: int) -> None:
        if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
            raise NativeError("INVALID_ARGUMENT", "Generation must be a positive integer")

    @classmethod
    def _validate_query(cls, query: dict[str, Any]) -> None:
        if not isinstance(query, dict):
            raise NativeError("INVALID_ARGUMENT", "Query must be an object")
        recognized = [key for key in cls._QUERY_KEYS if query.get(key) is not None]
        if not recognized:
            raise NativeError(
                "INVALID_ARGUMENT",
                "Query must contain at least one semantic selector",
                {"allowed": sorted(cls._QUERY_KEYS)},
            )
        unknown = sorted(set(query) - cls._QUERY_KEYS - {"contains"})
        if unknown:
            raise NativeError("INVALID_ARGUMENT", "Query contains unsupported keys", {"keys": unknown})
        if "contains" in query and not isinstance(query["contains"], bool):
            raise NativeError("INVALID_ARGUMENT", "contains must be boolean")
        if query.get("control_id") is not None:
            control_id = query["control_id"]
            if isinstance(control_id, bool) or not isinstance(control_id, int):
                raise NativeError("INVALID_ARGUMENT", "control_id must be an integer")

    @classmethod
    def _validate_postcondition(cls, postcondition: dict[str, Any]) -> None:
        if not isinstance(postcondition, dict):
            raise NativeError("INVALID_ARGUMENT", "Postcondition must be an object")
        kind = postcondition.get("type")
        if kind not in cls._POSTCONDITION_TYPES:
            raise NativeError(
                "POSTCONDITION_UNSUPPORTED",
                "Unsupported verification postcondition",
                {"postcondition": postcondition},
            )
        if "value" not in postcondition:
            raise NativeError("INVALID_ARGUMENT", f"{kind} requires value")
        if kind == "state_equals":
            key = postcondition.get("key")
            if not isinstance(key, str) or not key:
                raise NativeError("INVALID_ARGUMENT", "state_equals requires non-empty key")

    @classmethod
    def _validate_policy(cls, policy: dict[str, Any] | None) -> dict[str, Any]:
        if policy is None:
            return {"background_required": False}
        if not isinstance(policy, dict):
            raise NativeError("INVALID_ARGUMENT", "Policy must be an object")
        unknown = sorted(set(policy) - cls._POLICY_KEYS)
        if unknown:
            raise NativeError("INVALID_ARGUMENT", "Policy contains unsupported keys", {"keys": unknown})
        background_required = policy.get("background_required", False)
        if not isinstance(background_required, bool):
            raise NativeError("INVALID_ARGUMENT", "background_required must be boolean")
        return {"background_required": background_required}

    @staticmethod
    def _matches(entity: dict[str, Any], query: dict[str, Any]) -> bool:
        for key in ("role", "name", "automation_id", "class_name", "control_id"):
            wanted = query.get(key)
            if wanted is None:
                continue
            actual = entity.get(key)
            if query.get("contains") and isinstance(actual, str) and isinstance(wanted, str):
                if wanted.lower() not in actual.lower():
                    return False
            elif actual != wanted:
                return False
        return True

    @staticmethod
    def _verify(postcondition: dict[str, Any], after: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        kind = postcondition.get("type")
        if kind == "value_equals":
            expected = postcondition.get("value")
            actual = after.get("value")
            return actual == expected, {"type": kind, "expected": expected, "actual": actual}
        if kind == "state_equals":
            key = postcondition.get("key")
            expected = postcondition.get("value")
            actual = (after.get("state") or {}).get(key)
            return actual == expected, {"type": kind, "key": key, "expected": expected, "actual": actual}
        raise NativeError("POSTCONDITION_UNSUPPORTED", "Unsupported verification postcondition", {"postcondition": postcondition})
