from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable
import math

from cua_capture_contract import CaptureError, CaptureObservation, VisualEntity, validate_visual_entity
from cua_input_arbiter import ArbiterError, HumanInputArbiter, TargetFingerprint


class VisualActionError(RuntimeError):
    def __init__(self, code: str, details: dict[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = details or {}


@dataclass(frozen=True)
class GroundedVisualMatch:
    entity: VisualEntity
    evidence_fingerprint: str

    def __post_init__(self) -> None:
        if not self.evidence_fingerprint or not self.evidence_fingerprint.strip():
            raise VisualActionError("VISUAL_EVIDENCE_FINGERPRINT_REQUIRED")


@dataclass(frozen=True)
class FreshGrounding:
    observation: CaptureObservation
    matches: tuple[GroundedVisualMatch, ...]


def _translate_error(exc: Exception) -> VisualActionError:
    if isinstance(exc, VisualActionError):
        return exc
    if isinstance(exc, (CaptureError, ArbiterError)):
        return VisualActionError(exc.code, getattr(exc, "details", None) or {})
    return VisualActionError("VISUAL_ACTION_INTERNAL_ERROR", {"type": type(exc).__name__})


def _point(
    match: GroundedVisualMatch,
    observation: CaptureObservation,
    target: TargetFingerprint,
    minimum_confidence: float,
) -> tuple[int, int]:
    result = validate_visual_entity(
        match.entity,
        latest_observation=observation,
        current_target=target,
        minimum_confidence=minimum_confidence,
    )
    x, y = result["point_virtual_physical_px"]
    return int(x), int(y)


def prepare_fresh_visual_action(
    *,
    initial: GroundedVisualMatch,
    initial_observation: CaptureObservation,
    current_target: TargetFingerprint,
    reground: Callable[[GroundedVisualMatch], FreshGrounding],
    minimum_confidence: float = 0.90,
    max_center_drift_px: float = 16.0,
) -> dict[str, Any]:
    """Re-capture and re-ground before authorizing any physical coordinate.

    A coordinate from the initial capture is never returned for action. The returned
    point comes only from the fresh observation and fresh visual match.
    """
    if max_center_drift_px < 0:
        raise VisualActionError("VISUAL_DRIFT_LIMIT_INVALID")
    try:
        initial_point = _point(initial, initial_observation, current_target, minimum_confidence)
        fresh = reground(initial)
        if not isinstance(fresh, FreshGrounding):
            raise VisualActionError("VISUAL_REGROUND_RESULT_INVALID")
        if len(fresh.matches) == 0:
            raise VisualActionError("STALE_TARGET")
        if len(fresh.matches) != 1:
            raise VisualActionError("TARGET_AMBIGUOUS", {"candidate_count": len(fresh.matches)})
        candidate = fresh.matches[0]
        if candidate.evidence_fingerprint != initial.evidence_fingerprint:
            raise VisualActionError("VISUAL_EVIDENCE_CHANGED")

        # Intentionally invalidate the plan on surface/transform drift. The caller
        # may observe and create a new plan, but intent is never carried across the
        # changed surface implicitly.
        if fresh.observation.target != initial_observation.target:
            raise VisualActionError("TARGET_MOVED")
        if fresh.observation.coordinate_space != initial_observation.coordinate_space:
            raise VisualActionError("COORDINATE_TRANSFORM_CHANGED")

        fresh_point = _point(candidate, fresh.observation, current_target, minimum_confidence)
        drift = math.hypot(fresh_point[0] - initial_point[0], fresh_point[1] - initial_point[1])
        if drift > max_center_drift_px:
            raise VisualActionError(
                "VISUAL_TARGET_DRIFTED",
                {"drift_px": drift, "maximum_px": max_center_drift_px},
            )
        return {
            "fresh": fresh,
            "match": candidate,
            "point": fresh_point,
            "drift_px": drift,
        }
    except Exception as exc:
        raise _translate_error(exc) from exc


def execute_guarded_visual_click(
    *,
    arbiter: HumanInputArbiter,
    owner_id: str,
    initial: GroundedVisualMatch,
    initial_observation: CaptureObservation,
    target_provider: Callable[[], TargetFingerprint],
    foreground_provider: Callable[[], int],
    cursor_provider: Callable[[], tuple[int, int]],
    reground: Callable[[GroundedVisualMatch], FreshGrounding],
    sink: Callable[[dict[str, Any]], None],
    verify: Callable[[], bool] | None = None,
    minimum_confidence: float = 0.90,
    max_center_drift_px: float = 16.0,
) -> dict[str, Any]:
    """Fresh-ground a visual target, then use the global physical-input lease.

    No event is emitted until all visual guards pass and the arbiter grants a lease.
    The arbiter still validates target/foreground/user state immediately before the
    physical event. Verification is explicit and never inferred from event emission.
    """
    lease_id: str | None = None
    prepared: dict[str, Any] | None = None
    try:
        target = target_provider()
        prepared = prepare_fresh_visual_action(
            initial=initial,
            initial_observation=initial_observation,
            current_target=target,
            reground=reground,
            minimum_confidence=minimum_confidence,
            max_center_drift_px=max_center_drift_px,
        )

        # Capture/matching work can take time and never implicitly reserves the
        # owner's foreground. Re-read foreground after fresh grounding.
        foreground = int(foreground_provider())
        lease = arbiter.acquire(owner_id, target, expected_foreground=foreground)
        lease_id = lease.lease_id
        x, y = prepared["point"]
        event = {"type": "mouse_click", "x": x, "y": y, "button": "left"}

        physical_effect_unknown = False
        try:
            sequence = arbiter.execute_sequence(
                lease_id,
                [event],
                target_provider=target_provider,
                foreground_provider=foreground_provider,
                sink=sink,
            )
        except Exception as sink_exc:
            # A sink can fail after partially injecting an OS event. Preserve this
            # uncertainty in the receipt instead of throwing away the action record.
            physical_effect_unknown = True
            sequence = {
                "ok": False,
                "sent": None,
                "aborted": True,
                "error_code": "PHYSICAL_SINK_ERROR",
                "sink_error_type": type(sink_exc).__name__,
            }

        verified = False
        verification_error: str | None = None
        if sequence.get("ok") and verify is not None:
            try:
                verified = bool(verify())
            except Exception as verify_exc:
                verification_error = type(verify_exc).__name__
                verified = False

        receipt = arbiter.finish(
            lease_id,
            verified=verified,
            foreground_after=int(foreground_provider()),
            cursor_after=tuple(cursor_provider()),
        )
        lease_id = None
        receipt.update(
            {
                "visual_capture_id": prepared["fresh"].observation.capture_id,
                "visual_generation": prepared["fresh"].observation.generation,
                "visual_evidence_fingerprint": initial.evidence_fingerprint,
                "visual_drift_px": prepared["drift_px"],
                "point_virtual_physical_px": list(prepared["point"]),
                "sent": None if (physical_effect_unknown or sequence.get("physical_effect_unknown")) else sequence.get("sent"),
                "sequence_ok": bool(sequence.get("ok")),
                "error_code": sequence.get("error_code"),
                "physical_effect_unknown": bool(physical_effect_unknown or sequence.get("physical_effect_unknown")),
                "retry_safe": sequence.get("retry_safe"),
                "verification_error": verification_error,
            }
        )
        return receipt
    except Exception as exc:
        if lease_id is not None:
            try:
                arbiter.abort(lease_id, getattr(exc, "code", "VISUAL_ACTION_ABORTED"))
            except Exception:
                pass
        raise _translate_error(exc) from exc
