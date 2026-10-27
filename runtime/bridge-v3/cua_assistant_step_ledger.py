"""Durable per-step checkpoints for the EXISTING AssistantWorkflow.run.

No duplicate assistant step engine is introduced here. Reserve the whole scoped
workflow, persist DISPATCHING *before* each existing UI/model effect, persist
VERIFIED *after* independent step verification. Crash or lost ACK leaves a
read-only recovery marker and NEVER causes automatic replay of Send/Accept/Save.

Only identities, a SHA-256 of the request and stage names are stored; never
persist prompt text, screen values, account data, model replies or file paths.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Mapping

from cua_task_authority import AuthorityError, identity


class WorkflowLedgerError(RuntimeError):
    def __init__(self, code: str, *, details: dict[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = details or {}


class AssistantStepLedger:
    SCHEMA = "ff-assistant-step-checkpoint-v1"
    MAX_STEPS = 24
    MAX_JOBS = 100000

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.path = self.root / "assistant-step-checkpoints.sqlite3"

    def _connect(self):
        try:
            if not self.root.is_absolute() or self.root.is_symlink() or self.path.is_symlink():
                raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_ROOT_UNTRUSTED")
            self.root.mkdir(parents=True, exist_ok=True)
            con = sqlite3.connect(self.path, timeout=5, isolation_level=None)
            con.execute("PRAGMA synchronous=FULL")
            con.execute("CREATE TABLE IF NOT EXISTS tasks ("
                        "agent TEXT NOT NULL, task TEXT NOT NULL, fingerprint TEXT NOT NULL,"
                        "total INTEGER NOT NULL, state TEXT NOT NULL,"
                        "step_index INTEGER NOT NULL, step_name TEXT,"
                        "verified_count INTEGER NOT NULL, last_verified TEXT,"
                        "PRIMARY KEY (agent,task))")
            return con
        except (sqlite3.Error, OSError) as exc:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_UNAVAILABLE") from exc

    @staticmethod
    def _scope(agent_id, task_id):
        try:
            return identity(agent_id), identity(task_id)
        except AuthorityError as exc:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_SCOPE_REQUIRED") from exc

    @staticmethod
    def _fingerprint(request):
        try:
            data = json.dumps(request, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_REQUEST_INVALID") from exc
        if len(data) > 1024 * 1024:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_REQUEST_TOO_LARGE")
        return hashlib.sha256(data).hexdigest()

    @classmethod
    def _state(cls, row):
        if row is None:
            return {"schema": cls.SCHEMA, "state": "NOT_FOUND",
                    "retry_safe": False, "automatic_replay_allowed": False}
        state, total, idx, stage, verified_count, last_verified = row
        # Never return fingerprints, content, prompts, paths, selectors,
        # output, arbitrary error messages, or billing/account context.
        return {
            "schema": cls.SCHEMA,
            "state": state if state in {
                "PREPARED", "DISPATCHING", "VERIFIED", "COMPLETED", "OUTCOME_UNKNOWN"
            } else "OUTCOME_UNKNOWN",
            "total_steps": total,
            "last_checkpoint_index": idx,
            "last_checkpoint_stage": stage,
            "verified_steps": verified_count,
            "last_verified_stage": last_verified,
            "retry_safe": False,
            "automatic_replay_allowed": False,
            "external_reconciliation_required": state != "COMPLETED",
        }

    def status(self, agent_id, task_id) -> dict:
        agent, task = self._scope(agent_id, task_id)
        try:
            with closing(self._connect()) as con:
                row = con.execute(
                    "SELECT state,total,step_index,step_name,verified_count,last_verified "
                    "FROM tasks WHERE agent=? AND task=?", (agent, task)
                ).fetchone()
                return self._state(row)
        except (sqlite3.Error, OSError) as exc:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_UNAVAILABLE") from exc

    def _transition(self, agent_id, task_id, allowed, update, parameters=()):
        agent, task = self._scope(agent_id, task_id)
        try:
            with closing(self._connect()) as con:
                con.execute("BEGIN IMMEDIATE")
                row = con.execute(
                    "SELECT state,total,step_index,step_name,verified_count,last_verified "
                    "FROM tasks WHERE agent=? AND task=?", (agent, task)
                ).fetchone()
                if row is None or row[0] not in allowed:
                    raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_TRANSITION_DENIED",
                                              details=self._state(row))
                con.execute(update, (*parameters, agent, task))
                con.commit()
                return self._state(con.execute(
                    "SELECT state,total,step_index,step_name,verified_count,last_verified "
                    "FROM tasks WHERE agent=? AND task=?", (agent, task)
                ).fetchone())
        except (sqlite3.Error, OSError) as exc:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_UNAVAILABLE") from exc

    def reserve(self, args: Mapping[str, Any]) -> dict:
        agent, task = self._scope(args.get("agent_id"), args.get("task_id"))
        steps = args.get("steps")
        if not isinstance(steps, list) or not 1 <= len(steps) <= self.MAX_STEPS:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_STEPS_INVALID")
        digest = self._fingerprint(args)
        try:
            with closing(self._connect()) as con:
                con.execute("BEGIN IMMEDIATE")
                existing = con.execute(
                    "SELECT state,total,step_index,step_name,verified_count,last_verified "
                    "FROM tasks WHERE agent=? AND task=?", (agent, task)
                ).fetchone()
                if existing:
                    raise WorkflowLedgerError("ASSISTANT_WORKFLOW_ALREADY_RECORDED",
                                              details=self._state(existing))
                if con.execute("SELECT count(*) FROM tasks").fetchone()[0] >= self.MAX_JOBS:
                    raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_CAPACITY_EXHAUSTED")
                con.execute("INSERT INTO tasks VALUES (?,?,?,?,?,?,?,?,?)",
                            (agent, task, digest, len(steps), "PREPARED", -1, None, 0, None))
                con.commit()
                return self._state(("PREPARED", len(steps), -1, None, 0, None))
        except (sqlite3.Error, OSError) as exc:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_UNAVAILABLE") from exc

    def before(self, agent_id, task_id, index: int, stage: str) -> dict:
        if type(index) is not int or not 0 <= index < self.MAX_STEPS:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_INDEX_INVALID")
        if stage not in {
            "open_panel", "select_assistant", "set_prompt", "send",
            "read_reply", "accept_edits", "save", "verify_artifact"
        }:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_STAGE_INVALID")
        agent, task = self._scope(agent_id, task_id)
        try:
            with closing(self._connect()) as con:
                con.execute("BEGIN IMMEDIATE")
                row = con.execute(
                    "SELECT total,state,step_index,verified_count FROM tasks "
                    "WHERE agent=? AND task=?", (agent, task)
                ).fetchone()
                if (row is None or row[0] <= index or
                        row[1] not in {"PREPARED", "VERIFIED"} or
                        row[2] != index - 1 or row[3] != index):
                    raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_TRANSITION_DENIED")
                con.execute("UPDATE tasks SET state='DISPATCHING',step_index=?,step_name=? "
                            "WHERE agent=? AND task=?", (index, stage, agent, task))
                con.commit()
                return {"state": "DISPATCHING", "stage": stage}
        except (sqlite3.Error, OSError) as exc:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_UNAVAILABLE") from exc

    def after(self, agent_id, task_id, index: int, stage: str, receipt: Mapping[str, Any]) -> dict:
        if (not isinstance(receipt, Mapping) or receipt.get("verified") is not True
                or receipt.get("ok") is False or receipt.get("stage") != stage):
            # DISPATCHING remains on disk (outcome may have occurred).
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_EFFECT_UNVERIFIED")
        agent, task = self._scope(agent_id, task_id)
        try:
            with closing(self._connect()) as con:
                con.execute("BEGIN IMMEDIATE")
                row = con.execute(
                    "SELECT state,step_index,step_name,verified_count FROM tasks "
                    "WHERE agent=? AND task=?", (agent, task)
                ).fetchone()
                if row != ("DISPATCHING", index, stage, index):
                    raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_TRANSITION_DENIED")
                con.execute("UPDATE tasks SET state='VERIFIED',verified_count=?,last_verified=? "
                            "WHERE agent=? AND task=?", (index + 1, stage, agent, task))
                con.commit()
                return {"state": "VERIFIED", "verified_steps": index + 1}
        except (sqlite3.Error, OSError) as exc:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_UNAVAILABLE") from exc

    def finish(self, agent_id, task_id):
        agent, task = self._scope(agent_id, task_id)
        try:
            with closing(self._connect()) as con:
                con.execute("BEGIN IMMEDIATE")
                row = con.execute(
                    "SELECT state,total,step_index,verified_count,last_verified "
                    "FROM tasks WHERE agent=? AND task=?", (agent, task)
                ).fetchone()
                if (row is None or row[0] != "VERIFIED" or
                        row[2] != row[1] - 1 or row[3] != row[1] or
                        row[4] != "verify_artifact"):
                    raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_NOT_ALL_VERIFIED")
                con.execute("UPDATE tasks SET state='COMPLETED' "
                            "WHERE agent=? AND task=?", (agent, task))
                con.commit()
                return {"state": "COMPLETED", "verified_steps": row[3]}
        except (sqlite3.Error, OSError) as exc:
            raise WorkflowLedgerError("ASSISTANT_CHECKPOINT_UNAVAILABLE") from exc

    def unknown(self, agent_id, task_id):
        return self._transition(
            agent_id, task_id, {"PREPARED", "DISPATCHING", "VERIFIED"},
            "UPDATE tasks SET state='OUTCOME_UNKNOWN' WHERE agent=? AND task=?",
        )
