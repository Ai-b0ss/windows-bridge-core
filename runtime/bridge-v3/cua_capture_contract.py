from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any
import time
import uuid

from cua_input_arbiter import TargetFingerprint


class CaptureError(RuntimeError):
    def __init__(self, code: str, details: dict[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = details or {}


@dataclass(frozen=True)
class CoordinateSpace:
    kind: str
    origin_x: int
    origin_y: int
    width: int
    height: int
    dpi_x: int = 96
    dpi_y: int = 96
    monitor_id: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in {
            "VIRTUAL_SCREEN_PHYSICAL_PX",
            "MONITOR_PHYSICAL_PX",
            "WINDOW_CLIENT_PHYSICAL_PX",
            "WINDOW_DWM_FRAME_PHYSICAL_PX",
            "WINDOW_LOGICAL_DIP",
            "BROWSER_CSS_PX",
        }:
            raise CaptureError("COORDINATE_SPACE_UNSUPPORTED", {"kind": self.kind})
        if self.width <= 0 or self.height <= 0:
            raise CaptureError("COORDINATE_SPACE_INVALID")
        if self.dpi_x <= 0 or self.dpi_y <= 0:
            raise CaptureError("DPI_INVALID")

    def contains_local(self, x: float, y: float) -> bool:
        return 0 <= x < self.width and 0 <= y < self.height

    def local_to_virtual_physical(self, x: float, y: float) -> tuple[int, int]:
        if not self.contains_local(x, y):
            raise CaptureError("POINT_OUTSIDE_CAPTURE", {"x": x, "y": y})
        if self.kind == "WINDOW_LOGICAL_DIP":
            px = x * self.dpi_x / 96.0
            py = y * self.dpi_y / 96.0
        elif self.kind == "BROWSER_CSS_PX":
            raise CaptureError("COORDINATE_TRANSFORM_REQUIRES_BROWSER_SCALE")
        else:
            px, py = x, y
        return (self.origin_x + round(px), self.origin_y + round(py))


@dataclass(frozen=True)
class CaptureEngineCapabilities:
    engine: str
    target_kinds: tuple[str, ...]
    can_capture_occluded: bool | None
    can_capture_minimized: bool | None
    includes_cursor: bool | None
    provides_cursor_metadata: bool | None
    is_target_driven: bool
    may_block_on_target: bool
    live_proven: bool = False


@dataclass(frozen=True)
class CaptureObservation:
    capture_id: str
    generation: int
    engine: str
    target: TargetFingerprint
    coordinate_space: CoordinateSpace
    captured_ns: int
    content_sha256: str | None = None

    @classmethod
    def new(
        cls,
        generation: int,
        engine: str,
        target: TargetFingerprint,
        coordinate_space: CoordinateSpace,
        *,
        captured_ns: int | None = None,
        content_sha256: str | None = None,
    ) -> "CaptureObservation":
        if generation < 1:
            raise CaptureError("CAPTURE_GENERATION_INVALID")
        return cls(
            capture_id=uuid.uuid4().hex,
            generation=generation,
            engine=engine,
            target=target,
            coordinate_space=coordinate_space,
            captured_ns=time.monotonic_ns() if captured_ns is None else captured_ns,
            content_sha256=content_sha256,
        )


@dataclass(frozen=True)
class VisualEntity:
    entity_id: str
    capture_id: str
    generation: int
    target: TargetFingerprint
    coordinate_space: CoordinateSpace
    bbox_local: tuple[float, float, float, float]
    confidence: float
    evidence_kind: str
    candidate_count: int = 1

    @classmethod
    def from_bbox(
        cls,
        observation: CaptureObservation,
        bbox_local: tuple[float, float, float, float],
        *,
        confidence: float,
        evidence_kind: str,
        candidate_count: int = 1,
    ) -> "VisualEntity":
        x, y, w, h = bbox_local
        if w <= 0 or h <= 0:
            raise CaptureError("VISUAL_ENTITY_BOUNDS_INVALID")
        if not observation.coordinate_space.contains_local(x, y):
            raise CaptureError("VISUAL_ENTITY_OUTSIDE_CAPTURE")
        if not observation.coordinate_space.contains_local(x + w - 1e-9, y + h - 1e-9):
            raise CaptureError("VISUAL_ENTITY_OUTSIDE_CAPTURE")
        if not 0.0 <= confidence <= 1.0:
            raise CaptureError("VISUAL_CONFIDENCE_INVALID")
        if candidate_count < 1:
            raise CaptureError("VISUAL_CANDIDATE_COUNT_INVALID")
        return cls(
            entity_id=uuid.uuid4().hex,
            capture_id=observation.capture_id,
            generation=observation.generation,
            target=observation.target,
            coordinate_space=observation.coordinate_space,
            bbox_local=bbox_local,
            confidence=confidence,
            evidence_kind=evidence_kind,
            candidate_count=candidate_count,
        )

    def center_local(self) -> tuple[float, float]:
        x, y, w, h = self.bbox_local
        return (x + w / 2.0, y + h / 2.0)


def validate_visual_entity(
    entity: VisualEntity,
    *,
    latest_observation: CaptureObservation,
    current_target: TargetFingerprint,
    minimum_confidence: float = 0.90,
) -> dict[str, Any]:
    """Resolve a visual entity only if capture generation, target and transform are still exact.

    This does not authorize physical input. The caller must still acquire and validate
    a HumanInputArbiter lease immediately before each injected event.
    """
    if latest_observation.capture_id != entity.capture_id or latest_observation.generation != entity.generation:
        raise CaptureError(
            "STALE_CAPTURE",
            {"entity_generation": entity.generation, "latest_generation": latest_observation.generation},
        )
    if current_target != entity.target or latest_observation.target != entity.target:
        raise CaptureError("TARGET_MOVED")
    if latest_observation.coordinate_space != entity.coordinate_space:
        raise CaptureError("COORDINATE_TRANSFORM_CHANGED")
    if entity.candidate_count != 1:
        raise CaptureError("TARGET_AMBIGUOUS", {"candidate_count": entity.candidate_count})
    if entity.confidence < minimum_confidence:
        raise CaptureError(
            "VISUAL_CONFIDENCE_TOO_LOW",
            {"confidence": entity.confidence, "minimum": minimum_confidence},
        )
    local_x, local_y = entity.center_local()
    virtual_x, virtual_y = entity.coordinate_space.local_to_virtual_physical(local_x, local_y)
    left, top, right, bottom = current_target.rect
    if not (left <= virtual_x < right and top <= virtual_y < bottom):
        raise CaptureError(
            "POINT_OUTSIDE_TARGET_WINDOW",
            {"point": [virtual_x, virtual_y], "target_rect": list(current_target.rect)},
        )
    return {
        "ok": True,
        "entity_id": entity.entity_id,
        "capture_id": entity.capture_id,
        "generation": entity.generation,
        "point_virtual_physical_px": [virtual_x, virtual_y],
        "confidence": entity.confidence,
        "evidence_kind": entity.evidence_kind,
    }


def capture_receipt(
    observation: CaptureObservation,
    capabilities: CaptureEngineCapabilities,
    *,
    latency_ms: float,
    success: bool,
    content_verified: bool = False,
    error_code: str | None = None,
) -> dict[str, Any]:
    if observation.engine != capabilities.engine:
        raise CaptureError("CAPTURE_ENGINE_MISMATCH")
    return {
        "route": "VISION_SEMANTIC",
        "capture_id": observation.capture_id,
        "generation": observation.generation,
        "engine": observation.engine,
        "target_hwnd": observation.target.hwnd,
        "coordinate_space": asdict(observation.coordinate_space),
        "latency_ms": latency_ms,
        "success": bool(success),
        "verified": bool(success and content_verified),
        "error_code": error_code,
        "capabilities": {
            "target_kinds": list(capabilities.target_kinds),
            "can_capture_occluded": capabilities.can_capture_occluded,
            "can_capture_minimized": capabilities.can_capture_minimized,
            "includes_cursor": capabilities.includes_cursor,
            "provides_cursor_metadata": capabilities.provides_cursor_metadata,
            "is_target_driven": capabilities.is_target_driven,
            "may_block_on_target": capabilities.may_block_on_target,
            "live_proven": capabilities.live_proven,
        },
    }


# This table contains only structural/officially documented facts. Behavior that
# must be measured on the owner's Windows host remains None/live_proven=False.
OFFLINE_ENGINE_CAPABILITIES: dict[str, CaptureEngineCapabilities] = {
    "GDI_COPY_FROM_SCREEN": CaptureEngineCapabilities(
        "GDI_COPY_FROM_SCREEN", ("desktop", "region"), False, False, None, None, False, False, False
    ),
    "WINDOWS_GRAPHICS_CAPTURE": CaptureEngineCapabilities(
        "WINDOWS_GRAPHICS_CAPTURE", ("window", "monitor"), None, None, None, None, False, False, False
    ),
    "DXGI_DESKTOP_DUPLICATION": CaptureEngineCapabilities(
        "DXGI_DESKTOP_DUPLICATION", ("monitor",), None, False, None, True, False, False, False
    ),
    "PRINT_WINDOW": CaptureEngineCapabilities(
        "PRINT_WINDOW", ("window",), None, None, None, None, True, True, False
    ),
}
