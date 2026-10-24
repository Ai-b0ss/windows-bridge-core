from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from cua_native_core import NativeError, NativeSemanticCore


class NativeWaitController:
    """Backend-independent semantic waits built on top of NativeSemanticCore.

    The controller never injects input. It repeatedly observes semantic state and
    returns only after the requested condition is satisfied. Every returned
    receipt therefore explicitly reports `physical_input_used=False`.
    """

    _TYPES = {"present", "absent", "value_equals", "state_equals", "tree_stable"}

    def __init__(self, core: NativeSemanticCore):
        self.core = core

    @classmethod
    def capabilities(cls) -> dict[str, Any]:
        return {
            "conditions": sorted(cls._TYPES),
            "semantic_only": True,
            "physical_input_used": False,
        }

    def wait(
        self,
        target: dict[str, Any],
        condition: dict[str, Any],
        *,
        timeout_ms: int = 5000,
        poll_ms: int = 100,
        stable_for_ms: int = 300,
    ) -> dict[str, Any]:
        spec = self._validate_condition(condition)
        self._validate_timing(timeout_ms, poll_ms, stable_for_ms, tree_stable=(spec["type"] == "tree_stable"))

        started = time.monotonic()
        deadline = started + timeout_ms / 1000.0
        attempts = 0
        last_digest: str | None = None
        stable_since: float | None = None
        last_summary: dict[str, Any] | None = None

        while True:
            attempts += 1
            snapshot = self.core.observe(target, {"interactive": False})
            now = time.monotonic()
            satisfied = False
            evidence: dict[str, Any]

            kind = spec["type"]
            if kind == "tree_stable":
                digest, summary = self._tree_digest(snapshot, include_geometry=spec["include_geometry"])
                last_summary = summary
                if digest != last_digest:
                    last_digest = digest
                    stable_since = now
                assert stable_since is not None
                stable_ms = max(0, int((now - stable_since) * 1000))
                satisfied = stable_ms >= stable_for_ms
                evidence = {
                    "digest": digest,
                    "stable_ms": stable_ms,
                    **summary,
                }
            else:
                found = self.core.find(snapshot["generation"], spec["query"])
                matches = list(found.get("matches") or [])
                if kind == "present":
                    satisfied = bool(matches)
                    evidence = {"match_count": len(matches), "refs": [m.get("ref") for m in matches[:20]]}
                elif kind == "absent":
                    satisfied = not matches
                    evidence = {"match_count": len(matches)}
                else:
                    if len(matches) > 1:
                        raise NativeError(
                            "TARGET_AMBIGUOUS",
                            "Wait condition query resolves to multiple elements",
                            {"condition": spec, "matches": len(matches)},
                        )
                    if not matches:
                        evidence = {"match_count": 0}
                    else:
                        entity = matches[0]
                        if kind == "value_equals":
                            actual = entity.get("value")
                            expected = spec["value"]
                            satisfied = actual == expected
                            evidence = {"match_count": 1, "ref": entity.get("ref"), "expected": expected, "actual": actual}
                        else:
                            actual = (entity.get("state") or {}).get(spec["key"])
                            expected = spec["value"]
                            satisfied = actual == expected
                            evidence = {
                                "match_count": 1,
                                "ref": entity.get("ref"),
                                "key": spec["key"],
                                "expected": expected,
                                "actual": actual,
                            }

            if satisfied:
                latency_ms = int((time.monotonic() - started) * 1000)
                return {
                    "ok": True,
                    "condition": spec,
                    "generation": snapshot["generation"],
                    "route": snapshot.get("route") or self.core.capabilities().get("route"),
                    "target_before": snapshot.get("fingerprint"),
                    "attempts": attempts,
                    "latency_ms": latency_ms,
                    "verified": True,
                    "verification": evidence,
                    "physical_input_used": False,
                    "background_safe": True,
                    "focus_preserved": None,
                    "cursor_preserved": None,
                    "fallback_chain": [snapshot.get("route") or self.core.capabilities().get("route")],
                    "retries": max(0, attempts - 1),
                }

            if time.monotonic() >= deadline:
                details: dict[str, Any] = {
                    "condition": spec,
                    "attempts": attempts,
                    "last_generation": snapshot.get("generation"),
                    "last_evidence": evidence,
                }
                if last_summary is not None:
                    details["last_tree"] = last_summary
                raise NativeError("WAIT_TIMEOUT", "Semantic wait condition did not become true", details)

            remaining = max(0.0, deadline - time.monotonic())
            time.sleep(min(poll_ms / 1000.0, remaining))

    @classmethod
    def _validate_condition(cls, condition: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(condition, dict):
            raise NativeError("INVALID_ARGUMENT", "condition must be an object")
        kind = condition.get("type")
        if kind not in cls._TYPES:
            raise NativeError(
                "WAIT_CONDITION_UNSUPPORTED",
                "Unsupported semantic wait condition",
                {"type": kind, "supported": sorted(cls._TYPES)},
            )

        if kind == "tree_stable":
            unknown = sorted(set(condition) - {"type", "include_geometry"})
            if unknown:
                raise NativeError("INVALID_ARGUMENT", "tree_stable contains unsupported keys", {"keys": unknown})
            include_geometry = condition.get("include_geometry", False)
            if not isinstance(include_geometry, bool):
                raise NativeError("INVALID_ARGUMENT", "include_geometry must be boolean")
            return {"type": kind, "include_geometry": include_geometry}

        query = condition.get("query")
        if not isinstance(query, dict):
            raise NativeError("INVALID_ARGUMENT", f"{kind} requires query object")

        if kind in {"present", "absent"}:
            unknown = sorted(set(condition) - {"type", "query"})
            if unknown:
                raise NativeError("INVALID_ARGUMENT", f"{kind} contains unsupported keys", {"keys": unknown})
            return {"type": kind, "query": dict(query)}

        if "value" not in condition:
            raise NativeError("INVALID_ARGUMENT", f"{kind} requires value")
        if kind == "value_equals":
            unknown = sorted(set(condition) - {"type", "query", "value"})
            if unknown:
                raise NativeError("INVALID_ARGUMENT", "value_equals contains unsupported keys", {"keys": unknown})
            return {"type": kind, "query": dict(query), "value": condition["value"]}

        key = condition.get("key")
        if not isinstance(key, str) or not key:
            raise NativeError("INVALID_ARGUMENT", "state_equals requires non-empty key")
        unknown = sorted(set(condition) - {"type", "query", "key", "value"})
        if unknown:
            raise NativeError("INVALID_ARGUMENT", "state_equals contains unsupported keys", {"keys": unknown})
        return {"type": kind, "query": dict(query), "key": key, "value": condition["value"]}

    @staticmethod
    def _validate_timing(timeout_ms: int, poll_ms: int, stable_for_ms: int, *, tree_stable: bool) -> None:
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms < 0:
            raise NativeError("INVALID_ARGUMENT", "timeout_ms must be a non-negative integer")
        if isinstance(poll_ms, bool) or not isinstance(poll_ms, int) or poll_ms < 1:
            raise NativeError("INVALID_ARGUMENT", "poll_ms must be a positive integer")
        if isinstance(stable_for_ms, bool) or not isinstance(stable_for_ms, int) or stable_for_ms < 0:
            raise NativeError("INVALID_ARGUMENT", "stable_for_ms must be a non-negative integer")
        if tree_stable and stable_for_ms > timeout_ms:
            raise NativeError("INVALID_ARGUMENT", "stable_for_ms cannot exceed timeout_ms for tree_stable")

    @staticmethod
    def _tree_digest(snapshot: dict[str, Any], *, include_geometry: bool) -> tuple[str, dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for raw in snapshot.get("entities") or []:
            record = {
                "identity": raw.get("identity"),
                "role": raw.get("role"),
                "name": raw.get("name"),
                "automation_id": raw.get("automation_id"),
                "class_name": raw.get("class_name"),
                "value": raw.get("value"),
                "state": raw.get("state") or {},
                "actions": raw.get("actions") or [],
            }
            if include_geometry:
                record["geometry"] = raw.get("geometry") or {}
            records.append(record)
        encoded = json.dumps(records, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        digest = hashlib.sha256(encoded).hexdigest()
        return digest, {"entity_count": len(records), "semantic_bytes": len(encoded)}
