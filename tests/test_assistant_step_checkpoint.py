"""Checkpoint the EXISTING multi-step assistant workflow, not a new wrapper.

Evidence: a request retry under a different RPC request key cannot resend a
prompt if a prior task finished, failed after effect, or crashed mid-stage.
Only task IDs and stage names persist; never prompt/document/assistant text.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
from cua_assistant_step_ledger import AssistantStepLedger, WorkflowLedgerError
from cua_assistant_workflow import AssistantWorkflow, AssistantError
from cua_cli_first_policy import _gui_target


class SimulatedExistingWorkflow(AssistantWorkflow):
    """Fake ONLY I/O; use original .run() sequence + real SQLite ledger."""
    def __init__(self, dispatch, *, step_ledger, effects, fail_at=None):
        super().__init__(dispatch, step_ledger=step_ledger)
        self.effects = effects
        self.fail_at = fail_at
    @classmethod
    def _open_panel_validate(cls, args):
        return False
    @staticmethod
    def _panel_validate(args):
        return
    def step(self, args):
        stage = args["stage"]
        if stage == "send":
            # This represents a real nonidempotent assistant prompt send.
            self.effects.append("SENT")
        if stage == self.fail_at:
            raise AssistantError("SIMULATED_POST_SEND_CRASH", {"attempted": True})
        return {"stage": stage, "ok": True, "verified": True}


class TestAssistantCheckpointLedger(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.store = AssistantStepLedger(self.dir / "state" / "assistant-checkpoints")
        self.steps = [{"stage": step, "route": "native"} for step in (
            "open_panel", "set_prompt", "send", "read_reply", "save", "verify_artifact"
        )]
        self.args = {
            "app": "Cursor", "agent_id": "agent-01", "task_id": "task-01",
            "command": "assistant_task", "steps": self.steps,
            "prompt": "TOP_SECRET_UNLOGGED_ASSISTANT_PROMPT",
            "artifact_root": str(self.dir), "path": str(self.dir / "TOP_SECRET_PATH.txt"),
        }

    def test_checkpoint_is_durable_across_ledger_reinstantiation(self):
        self.store.reserve(self.args)
        self.store.before("agent-01", "task-01", 0, "open_panel")
        again = AssistantStepLedger(self.store.root)
        snap = again.status("agent-01", "task-01")
        self.assertEqual(snap["state"], "DISPATCHING")
        self.assertEqual(snap["last_checkpoint_stage"], "open_panel")
        self.assertEqual(snap["verified_steps"], 0)
        self.assertFalse(snap["automatic_replay_allowed"])
        self.assertTrue(snap["external_reconciliation_required"])
        with self.assertRaises(WorkflowLedgerError) as cm:
            again.reserve(self.args)
        self.assertEqual(cm.exception.code, "ASSISTANT_WORKFLOW_ALREADY_RECORDED")
        self.assertFalse("TOP_SECRET" in repr(cm.exception.details))

    def test_original_workflow_runs_exact_sequence_and_durably_finishes(self):
        effects = []
        wf = SimulatedExistingWorkflow(lambda _: None,
                                       step_ledger=self.store, effects=effects)
        result = wf.run(self.args)
        self.assertTrue(result["verified"])
        self.assertEqual(result["durable_checkpoint"]["state"], "COMPLETED")
        self.assertEqual(result["durable_checkpoint"]["verified_steps"], 6)
        self.assertEqual(effects, ["SENT"])
        snap = AssistantStepLedger(self.store.root).status("agent-01", "task-01")
        self.assertEqual(snap["state"], "COMPLETED")
        self.assertEqual(snap["last_verified_stage"], "verify_artifact")
        with self.assertRaises(AssistantError) as cm:
            wf.run(self.args)
        self.assertEqual(cm.exception.args[0], "ASSISTANT_WORKFLOW_ALREADY_RECORDED")
        self.assertEqual(effects, ["SENT"])

    def test_crash_after_send_persists_unknown_and_never_replays_send(self):
        effects = []
        failing = SimulatedExistingWorkflow(lambda _: None, step_ledger=self.store,
                                            effects=effects, fail_at="save")
        with self.assertRaises(AssistantError) as cm:
            failing.run(self.args)
        self.assertEqual(cm.exception.details["failed_stage"], "save")
        self.assertFalse(cm.exception.details["workflow_retry_safe"])
        self.assertEqual(effects, ["SENT"])
        status = AssistantStepLedger(self.store.root).status("agent-01", "task-01")
        self.assertEqual(status["state"], "OUTCOME_UNKNOWN")
        self.assertEqual(status["last_checkpoint_stage"], "save")
        self.assertEqual(status["verified_steps"], 4)
        succeeding = SimulatedExistingWorkflow(lambda _: None,
                                               step_ledger=AssistantStepLedger(self.store.root),
                                               effects=effects)
        with self.assertRaises(AssistantError) as cm:
            succeeding.run(self.args)
        self.assertEqual(cm.exception.args[0], "ASSISTANT_WORKFLOW_ALREADY_RECORDED")
        self.assertEqual(effects, ["SENT"])

    def test_invalid_receipt_remains_unknown_and_cannot_commit_completion(self):
        self.store.reserve(self.args)
        self.store.before("agent-01", "task-01", 0, "send")
        for receipt in (
            {"stage": "send", "ok": True, "verified": "true"},
            {"stage": "send", "ok": False, "verified": True},
            {"stage": "read_reply", "ok": True, "verified": True},
        ):
            with self.assertRaises(WorkflowLedgerError) as cm:
                self.store.after("agent-01", "task-01", 0, "send", receipt)
            self.assertEqual(cm.exception.code, "ASSISTANT_CHECKPOINT_EFFECT_UNVERIFIED")
        with self.assertRaises(WorkflowLedgerError):
            self.store.finish("agent-01", "task-01")
        self.assertEqual(self.store.status("agent-01", "task-01")["state"], "DISPATCHING")

    def test_request_payload_and_owner_paths_are_never_in_database(self):
        wf = SimulatedExistingWorkflow(lambda _: None, step_ledger=self.store, effects=[])
        wf.run(self.args)
        raw=self.store.path.read_bytes()
        self.assertNotIn(b"TOP_SECRET", raw)
        self.assertNotIn(str(self.dir).encode(), raw)
        self.assertNotIn(b"assistant_step", raw)
        self.assertIn(b"verify_artifact", raw)

    def test_new_request_key_or_mutated_prompt_cannot_replay_same_task(self):
        self.store.reserve(self.args)
        for args in (dict(self.args), {**self.args, "prompt":"another"}):
            with self.assertRaises(WorkflowLedgerError) as cm:
                AssistantStepLedger(self.store.root).reserve(args)
            self.assertEqual(cm.exception.code,"ASSISTANT_WORKFLOW_ALREADY_RECORDED")

    def test_concurrent_same_identity_only_one_reservation(self):
        def reserve():
            try:
                AssistantStepLedger(self.store.root).reserve(self.args)
                return "CREATED"
            except WorkflowLedgerError as exc:
                return exc.code
        with ThreadPoolExecutor(max_workers=6) as executor:
            results = list(executor.map(lambda _: reserve(), range(6)))
        self.assertEqual(results.count("CREATED"), 1)
        self.assertEqual(results.count("ASSISTANT_WORKFLOW_ALREADY_RECORDED"),5)

    def test_forged_identity_and_unknown_status_fail_closed(self):
        for identity in ("", "../../abc", "a"*129, None):
            with self.subTest(identity=identity):
                with self.assertRaises(WorkflowLedgerError):
                    self.store.status(identity, "task-01")
        state = self.store.status("another-agent","task-01")
        self.assertEqual(state["state"],"NOT_FOUND")
        self.assertFalse(state["automatic_replay_allowed"])

    def test_cli_first_still_guards_mutating_assistant_workflows(self):
        self.assertIsNone(_gui_target(None, {"command": "assistant_task_status",
                                            "app":"Cursor","agent_id":"a","task_id":"b"},
                                      "computer_use"))
        self.assertIsNotNone(_gui_target(None, {"command": "assistant_task",
                                               "app":"Cursor", "steps": []},
                                         "computer_use"))

    def test_no_auto_retry_after_any_partial_checkpoint(self):
        self.store.reserve(self.args)
        self.store.before("agent-01","task-01",0,"send")
        self.store.unknown("agent-01","task-01")
        status=self.store.status("agent-01","task-01")
        self.assertEqual(status["state"],"OUTCOME_UNKNOWN")
        self.assertFalse(status["retry_safe"])
        with self.assertRaises(WorkflowLedgerError):
            self.store.before("agent-01","task-01",0,"send")


if __name__ == "__main__":
    unittest.main()
