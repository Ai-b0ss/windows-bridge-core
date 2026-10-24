from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

from cua_input_arbiter import ArbiterError, HumanInputArbiter, TargetFingerprint


@dataclass
class ArbiterLeaseValidator:
    """Bridge ControlRouter physical-input lease checks to HumanInputArbiter.

    The router invokes this immediately before it even probes the physical adapter.
    The physical adapter must still use HumanInputArbiter.execute_sequence so every
    individual mouse/keyboard event is revalidated during the sequence.
    """

    arbiter: HumanInputArbiter
    target_provider: Callable[[Mapping[str, Any]], TargetFingerprint]
    foreground_provider: Callable[[], int]

    def __call__(self, lease: Mapping[str, Any], request: Mapping[str, Any]) -> dict[str, Any]:
        lease_id = str(lease.get("lease_id") or "")
        if not lease_id:
            return {"ok": False, "error_code": "LEASE_NOT_FOUND"}
        try:
            return dict(
                self.arbiter.validate_before_event(
                    lease_id,
                    self.target_provider(request),
                    current_foreground=int(self.foreground_provider()),
                )
            )
        except ArbiterError as exc:
            return {"ok": False, "error_code": exc.code, "details": dict(exc.details)}
