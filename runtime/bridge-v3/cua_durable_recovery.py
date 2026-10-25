"""No-replay recovery decisions over an existing durable request journal.

A journal entry describes recorded dispatch, NOT proof that a remote effect
actually happened or succeeded. Every state requires independent verification
before declaring task completion or choosing a new non-idempotent mutation.
"""
from __future__ import annotations
from collections.abc import Mapping
from typing import Any


def advise_recovery(status: Mapping[str, Any]) -> dict[str, Any]:
    """Produce a redacted, read-only decision; NEVER execute an action."""
    state = status.get("state") if isinstance(status, Mapping) else None
    # Never forward response: task output may contain private user content.
    result: dict[str, Any] = {
        "schema": "ff-task-recovery-decision-v1",
        "journal_state": state if state in {
            "not_found", "completed", "outcome_unknown", "outcome_expired",
        } else "unrecognized",
        "recovery_read_only": True,
        "automatic_retry_allowed": False,
        "previous_effect_independently_verified": False,
        "new_mutation_started": False,
        "owner_permission_verified": False,
        "response_contents_returned": False,
        "next_step": "inspect_request_status_and_external_target",
        "explanation_code": "JOURNAL_STATE_UNKNOWN_FAIL_CLOSED",
    }
    if state == "completed":
        result["journal_has_recorded_response"] = isinstance(status.get("response"), Mapping)
        result["next_step"] = "verify_external_postcondition_and_cleanup_task_owned_resources"
        result["explanation_code"] = "RESPONSE_RECORDED_NOT_EFFECT_PROVEN"
    elif state == "outcome_unknown":
        result["journal_has_recorded_response"] = False
        result["next_step"] = "inspect_external_effect_and_reconcile_before_new_work"
        result["explanation_code"] = "DISPATCH_MAY_HAVE_COMMITTED_BEFORE_LOST_ACK"
    elif state == "outcome_expired":
        result["journal_has_recorded_response"] = False
        result["next_step"] = "manual_or_independent_external_reconciliation"
        result["explanation_code"] = "RESPONSE_EXPIRED_KEY_RESERVED"
    elif state == "not_found":
        result["journal_has_recorded_response"] = False
        result["next_step"] = "confirm_correct_device_journal_key_and_external_history"
        result["explanation_code"] = "ABSENCE_OF_RECORD_IS_NOT_PROOF_OF_NO_EFFECT"
    else:
        result["journal_has_recorded_response"] = False
    return result


class RecoveryCoordinator:
    """Adapter for RequestJournal.status(); no dispatcher or mutation method."""

    def __init__(self, journal: Any):
        self._journal = journal

    def plan(self, request_key: str) -> dict[str, Any]:
        status = self._journal.status(request_key)
        return advise_recovery(status)
