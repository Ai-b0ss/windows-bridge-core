"""Durable state of the agent Hub: sessions, owned resources, the request journal and the audit log.

One SQLite file (WAL). Everything an agent owns is a row with an explicit owner, so a restart of
the Hub, of an agent client or of the Bridge loses nothing and never hands one agent's resource
to another. Locks are per resource; there is no global lock for agents to queue behind.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

SESSION_TTL_SECONDS = 180.0
ORPHAN_TTL_SECONDS = 1800.0
JOURNAL_KEEP_SECONDS = 14 * 86400.0
AUDIT_KEEP_ROWS = 50000
RESOURCE_KINDS = frozenset({
    "browser_tab", "window", "process", "terminal", "file", "directory", "app_session", "connection", "custom",
})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions(
  session_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
  secret_hash TEXT NOT NULL, resume_hash TEXT NOT NULL, state TEXT NOT NULL,
  created_at REAL NOT NULL, last_seen_at REAL NOT NULL, closed_at REAL, note TEXT, entry_grant_id TEXT);
CREATE INDEX IF NOT EXISTS sessions_owner ON sessions(agent_id, task_id, state);
CREATE TABLE IF NOT EXISTS resources(
  resource_id TEXT PRIMARY KEY, kind TEXT NOT NULL, key TEXT NOT NULL, mode TEXT NOT NULL,
  session_id TEXT NOT NULL, agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
  state TEXT NOT NULL, created_at REAL NOT NULL, released_at REAL, meta TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS resources_key ON resources(kind, key, state);
CREATE INDEX IF NOT EXISTS resources_session ON resources(session_id, state);
CREATE TABLE IF NOT EXISTS journal(
  request_key TEXT PRIMARY KEY, agent_id TEXT NOT NULL, task_id TEXT NOT NULL, op TEXT NOT NULL,
  digest TEXT NOT NULL, state TEXT NOT NULL, boot_id TEXT NOT NULL, started_at REAL NOT NULL,
  finished_at REAL, response TEXT);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL, agent_id TEXT, task_id TEXT,
  session_id TEXT, event TEXT NOT NULL, detail TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS permission_requests(
  request_id TEXT PRIMARY KEY, at REAL NOT NULL, agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
  risk_class TEXT NOT NULL, target TEXT NOT NULL, reason TEXT NOT NULL, state TEXT NOT NULL);
"""


class HubError(RuntimeError):
    def __init__(self, code: str, message: str | None = None, /, **details: Any):
        # Positional-only: lower layers legitimately report a `message` among their details.
        super().__init__(code)
        self.code = code
        inner = details.pop("message", None)
        self.message = message or (inner if isinstance(inner, str) and inner else code)
        self.details = details


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _ident(value: Any, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 128 or any(ord(ch) < 32 for ch in value):
        raise HubError("IDENTITY_INVALID", f"{field} must be a short printable string", field=field)
    return value


class HubStore:
    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time,
                 session_ttl: float = SESSION_TTL_SECONDS, orphan_ttl: float = ORPHAN_TTL_SECONDS):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.session_ttl = session_ttl
        self.orphan_ttl = orphan_ttl
        self.boot_id = uuid.uuid4().hex
        self._lock = threading.RLock()
        self._running: set[str] = set()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None, timeout=10)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(_SCHEMA)
        if "entry_grant_id" not in {row[1] for row in self._db.execute("PRAGMA table_info(sessions)")}:
            self._db.execute("ALTER TABLE sessions ADD COLUMN entry_grant_id TEXT")

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # ---- audit ---------------------------------------------------------------------------
    def audit(self, event: str, *, agent_id: str | None = None, task_id: str | None = None,
              session_id: str | None = None, **detail: Any) -> None:
        with self._lock:
            self._db.execute("INSERT INTO audit(at,agent_id,task_id,session_id,event,detail) VALUES(?,?,?,?,?,?)",
                             (self.clock(), agent_id, task_id, session_id, event,
                              json.dumps(detail, ensure_ascii=False, sort_keys=True, default=str)[:8000]))

    def read_audit(self, *, agent_id: str | None = None, task_id: str | None = None, limit: int = 100) -> list[dict]:
        limit = max(1, min(int(limit), 1000))
        query, params = "SELECT * FROM audit", []
        clauses = [(name, value) for name, value in (("agent_id", agent_id), ("task_id", task_id)) if value]
        if clauses:
            query += " WHERE " + " AND ".join(f"{name}=?" for name, _ in clauses)
            params = [value for _, value in clauses]
        with self._lock:
            rows = self._db.execute(query + " ORDER BY id DESC LIMIT ?", (*params, limit)).fetchall()
        return [{"at": row["at"], "agent_id": row["agent_id"], "task_id": row["task_id"],
                 "session_id": row["session_id"], "event": row["event"], "detail": json.loads(row["detail"])}
                for row in reversed(rows)]

    # ---- sessions ------------------------------------------------------------------------
    def _session_row(self, session_id: str) -> sqlite3.Row | None:
        return self._db.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()

    def _is_stale(self, row: sqlite3.Row) -> bool:
        return row["state"] == "active" and self.clock() - row["last_seen_at"] > self.session_ttl

    def open_session(self, agent_id: str, task_id: str, *, resume_token: str | None = None,
                     note: str | None = None, entry_grant_id: str | None = None,
                     entry_secret: str | None = None) -> dict:
        """Open a session, or take over this agent's earlier session for the same task.

        Taking over an earlier session always needs its resume token. An idle timeout is not
        evidence of identity: another caller can guess an agent_id/task_id.
        """
        agent_id, task_id = _ident(agent_id, "agent_id"), _ident(task_id, "task_id")
        now = self.clock()
        with self._lock:
            previous = self._db.execute(
                "SELECT * FROM sessions WHERE agent_id=? AND task_id=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
                (agent_id, task_id)).fetchall()
            for row in previous:
                if entry_grant_id and row["entry_grant_id"] == entry_grant_id and secrets.compare_digest(
                        row["secret_hash"], _hash(entry_secret)):
                    if row["state"] == "active":
                        self._db.execute("UPDATE sessions SET last_seen_at=? WHERE session_id=?", (now, row["session_id"]))
                    return {"session_id": row["session_id"], "state": row["state"], "reused": True,
                            "heartbeat_seconds": self.session_ttl / 3, "session_ttl_seconds": self.session_ttl}
                token_ok = (not entry_grant_id and not row["entry_grant_id"] and isinstance(resume_token, str)
                            and secrets.compare_digest(row["resume_hash"], _hash(resume_token)))
                if not token_ok:
                    raise HubError("SESSION_ACTIVE_ELSEWHERE",
                                   "this agent/task was registered earlier; prove ownership with its latest resume_token",
                                   session_id=row["session_id"], idle_seconds=round(now - row["last_seen_at"], 1),
                                   resume_token_required=True, retry_safe=False)
            session_id = "ses-" + uuid.uuid4().hex
            secret, resume = entry_secret or secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._db.execute(
                    "INSERT INTO sessions(session_id,agent_id,task_id,secret_hash,resume_hash,state,created_at,last_seen_at,note,entry_grant_id)"
                    " VALUES(?,?,?,?,?,'active',?,?,?,?)",
                    (session_id, agent_id, task_id, _hash(secret), _hash(resume), now, now, (note or "")[:500], entry_grant_id))
                adopted = 0
                for row in previous:
                    adopted += self._db.execute(
                        "UPDATE resources SET session_id=? WHERE session_id=? AND state='held'",
                        (session_id, row["session_id"])).rowcount
                    self._db.execute("UPDATE sessions SET state='superseded', closed_at=? WHERE session_id=?",
                                     (now, row["session_id"]))
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        self.audit("session_open", agent_id=agent_id, task_id=task_id, session_id=session_id,
                   resumed_from=[row["session_id"] for row in previous], adopted_resources=adopted,
                   entry_grant_id=entry_grant_id)
        if entry_grant_id:
            return {"session_id": session_id, "state": "active", "reused": False,
                    "heartbeat_seconds": self.session_ttl / 3, "session_ttl_seconds": self.session_ttl}
        return {"session_id": session_id, "session_secret": secret, "resume_token": resume,
                "agent_id": agent_id, "task_id": task_id, "resumed": bool(previous), "adopted_resources": adopted,
                "heartbeat_seconds": self.session_ttl / 3, "session_ttl_seconds": self.session_ttl}

    def authenticate(self, session_id: Any, secret: Any, *, allow_closed=False) -> dict:
        if not isinstance(session_id, str) or not isinstance(secret, str):
            raise HubError("SESSION_REQUIRED", "open a session first (session_open)")
        with self._lock:
            row = self._session_row(session_id)
            if row is None or not secrets.compare_digest(row["secret_hash"], _hash(secret)):
                raise HubError("SESSION_INVALID", "unknown session or wrong session secret")
            if row["state"] == "superseded" or (row["state"] != "active" and not allow_closed):
                raise HubError("SESSION_CLOSED", "this session ended; open or resume one", state=row["state"])
            if row['state']=='active':self._db.execute("UPDATE sessions SET last_seen_at=? WHERE session_id=?", (self.clock(), session_id))
        return {"session_id": session_id, "agent_id": row["agent_id"], "task_id": row["task_id"]}

    def close_session(self, session_id: str) -> list[dict]:
        """End a session and return the resources it still held, for the caller to clean up."""
        with self._lock:
            held = self.resources(session_id=session_id)
            now = self.clock()
            self._db.execute("UPDATE resources SET state='released', released_at=? WHERE session_id=? AND state='held'",
                             (now, session_id))
            self._db.execute("UPDATE sessions SET state='closed', closed_at=? WHERE session_id=? AND state='active'",
                             (now, session_id))
        return held

    def sessions(self, *, include_closed: bool = False) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM sessions" + ("" if include_closed else " WHERE state='active'")
                                    + " ORDER BY created_at").fetchall()
            return [{"session_id": row["session_id"], "agent_id": row["agent_id"], "task_id": row["task_id"],
                     "state": "stale" if self._is_stale(row) else row["state"], "created_at": row["created_at"],
                     "idle_seconds": round(self.clock() - row["last_seen_at"], 1),
                     "resources": self._db.execute(
                         "SELECT COUNT(*) FROM resources WHERE session_id=? AND state='held'",
                         (row["session_id"],)).fetchone()[0]} for row in rows]

    def active_entry_sessions(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT session_id, agent_id, task_id, entry_grant_id FROM sessions "
                "WHERE state='active' AND entry_grant_id IS NOT NULL").fetchall()
            return [dict(row) for row in rows]

    def is_active_entry_session(self, session_id: str) -> bool:
        with self._lock:
            row = self._session_row(session_id)
            return bool(row and row["entry_grant_id"] and row["state"] == "active")

    def expire_sessions(self, *, session_id: str | None = None) -> list[dict]:
        """Sessions silent for longer than the orphan window: close them, return what they held."""
        expired = []
        with self._lock:
            query = "SELECT * FROM sessions WHERE state='active' AND ?-last_seen_at>?"
            params: tuple = (self.clock(), self.session_ttl + self.orphan_ttl)
            if session_id is not None:
                query += " AND session_id=?"
                params += (session_id,)
            rows = self._db.execute(query, params).fetchall()
            for row in rows:
                held = self.close_session(row["session_id"])
                expired.append({"session_id": row["session_id"], "agent_id": row["agent_id"],
                                "task_id": row["task_id"], "resources": held})
        for item in expired:
            self.audit("session_expired", agent_id=item["agent_id"], task_id=item["task_id"],
                       session_id=item["session_id"], resources=len(item["resources"]))
        return expired

    # ---- resources -----------------------------------------------------------------------
    @staticmethod
    def _resource(row: sqlite3.Row) -> dict:
        return {"resource_id": row["resource_id"], "kind": row["kind"], "key": row["key"], "mode": row["mode"],
                "session_id": row["session_id"], "agent_id": row["agent_id"], "task_id": row["task_id"],
                "state": row["state"], "created_at": row["created_at"], "meta": json.loads(row["meta"])}

    def _holders(self, kind: str, key: str) -> list[sqlite3.Row]:
        return self._db.execute("SELECT * FROM resources WHERE kind=? AND key=? AND state='held'", (kind, key)).fetchall()

    def claim(self, session: dict, kind: str, key: str, *, mode: str = "exclusive",
              meta: dict | None = None, wait_seconds: float = 0.0,
              check_access: Callable | None = None) -> dict:
        if kind not in RESOURCE_KINDS:
            raise HubError("RESOURCE_KIND_INVALID", kinds=sorted(RESOURCE_KINDS))
        if mode not in {"exclusive", "shared"}:
            raise HubError("RESOURCE_MODE_INVALID")
        if not isinstance(key, str) or not 1 <= len(key) <= 1024:
            raise HubError("RESOURCE_KEY_INVALID")
        if type(wait_seconds) not in (int, float) or not 0 <= wait_seconds <= 60:
            raise HubError("RESOURCE_WAIT_INVALID", allowed="0..60 seconds")
        deadline = time.monotonic() + wait_seconds
        while True:
            with self._lock:
                if check_access:
                    check_access()
                self._db.execute("BEGIN IMMEDIATE")
                try:
                    blockers = []
                    for row in self._holders(kind, key):
                        if row["session_id"] == session["session_id"]:
                            if row["mode"] == mode:
                                self._db.execute("COMMIT")
                                return {**self._resource(row), "already_held": True}
                            continue
                        if mode == "exclusive" or row["mode"] == "exclusive":
                            blockers.append(row)
                    if not blockers:
                        resource_id = "res-" + uuid.uuid4().hex
                        self._db.execute(
                            "INSERT INTO resources(resource_id,kind,key,mode,session_id,agent_id,task_id,state,created_at,meta)"
                            " VALUES(?,?,?,?,?,?,?,'held',?,?)",
                            (resource_id, kind, key, mode, session["session_id"], session["agent_id"],
                             session["task_id"], self.clock(), json.dumps(meta or {}, ensure_ascii=False, default=str)))
                        self._db.execute("COMMIT")
                        row = self._db.execute("SELECT * FROM resources WHERE resource_id=?", (resource_id,)).fetchone()
                        return {**self._resource(row), "already_held": False}
                    self._db.execute("ROLLBACK")
                except BaseException:
                    if self._db.in_transaction:
                        self._db.execute("ROLLBACK")
                    raise
            if time.monotonic() >= deadline:
                holder = blockers[0]
                details = {} if check_access else {
                    "held_by": {"agent_id": holder["agent_id"], "task_id": holder["task_id"], "mode": holder["mode"]}}
                raise HubError("RESOURCE_BUSY", "another agent holds this resource", kind=kind, key=key,
                               retry_safe=True, retry_after_ms=1000, **details)
            time.sleep(0.05)

    def release(self, session: dict, *, resource_id: str | None = None, kind: str | None = None,
                key: str | None = None) -> dict:
        with self._lock:
            if resource_id:
                rows = self._db.execute("SELECT * FROM resources WHERE resource_id=? AND state='held'", (resource_id,)).fetchall()
            else:
                rows = [row for row in self._holders(str(kind), str(key))]
            mine = [row for row in rows if row["session_id"] == session["session_id"]]
            if rows and not mine:
                raise HubError("RESOURCE_NOT_OWNED", "this resource belongs to another agent")
            now = self.clock()
            for row in mine:
                self._db.execute("UPDATE resources SET state='released', released_at=? WHERE resource_id=?",
                                 (now, row["resource_id"]))
        return {"released": len(mine)}

    def owner_of(self, kind: str, key: str) -> dict | None:
        with self._lock:
            rows = self._holders(kind, key)
        return self._resource(rows[0]) if rows else None

    def require_owned(self, session: dict, kind: str, key: str) -> dict:
        owner = self.owner_of(kind, key)
        if owner is None:
            raise HubError("RESOURCE_NOT_FOUND", kind=kind, key=key)
        if owner["session_id"] != session["session_id"]:
            raise HubError("RESOURCE_NOT_OWNED", "this resource belongs to another agent", kind=kind)
        return owner

    def resources(self, *, session_id: str | None = None, kind: str | None = None) -> list[dict]:
        query, params = "SELECT * FROM resources WHERE state='held'", []
        for name, value in (("session_id", session_id), ("kind", kind)):
            if value:
                query += f" AND {name}=?"
                params.append(value)
        with self._lock:
            return [self._resource(row) for row in self._db.execute(query + " ORDER BY created_at", params).fetchall()]

    def drop_resources(self, kind: str) -> list[dict]:
        """Release every held resource of a kind whose real object cannot have survived (Hub restart)."""
        with self._lock:
            held = self.resources(kind=kind)
            self._db.execute("UPDATE resources SET state='released', released_at=? WHERE kind=? AND state='held'",
                             (self.clock(), kind))
        return held

    def update_resource_meta(self, resource_id: str, meta: dict) -> None:
        with self._lock:
            self._db.execute("UPDATE resources SET meta=? WHERE resource_id=?",
                             (json.dumps(meta, ensure_ascii=False, default=str), resource_id))

    # ---- request journal -----------------------------------------------------------------
    def journal_execute(self, session: dict, request_key: Any, op: str, payload: Any, run: Callable[[], dict]) -> dict:
        """Run a mutating operation at most once per request_key.

        A repeated key with the same payload returns the recorded outcome. If the Hub died while
        the operation was running, the outcome is unknown and is reported as such: the caller
        must look at the real state before deciding anything, and the Hub never replays it.
        """
        if request_key is None:
            raise HubError("REQUEST_KEY_REQUIRED", "effectful requests require a stable request_key; keep it for request_status",
                           execution_started=False, retry_safe=False)
        if not isinstance(request_key, str) or not 8 <= len(request_key) <= 200:
            raise HubError("REQUEST_KEY_INVALID", "request_key is a stable string of 8..200 characters")
        key = f"{session['agent_id']}\x1f{session['task_id']}\x1f{request_key}"
        digest = _hash(json.dumps([op, payload], sort_keys=True, ensure_ascii=False, default=str))
        with self._lock:
            row = self._db.execute("SELECT * FROM journal WHERE request_key=?", (key,)).fetchone()
            if row is not None:
                if row["digest"] != digest:
                    raise HubError("REQUEST_KEY_REUSED", "this request_key was used for a different request", retry_safe=False)
                if row["state"] == "started":
                    if key in self._running and row["boot_id"] == self.boot_id:
                        raise HubError("REQUEST_IN_PROGRESS", "the same request is still running", retry_safe=True, retry_after_ms=1000)
                    self._db.execute("UPDATE journal SET state='unknown', finished_at=? WHERE request_key=?", (self.clock(), key))
                    row = self._db.execute("SELECT * FROM journal WHERE request_key=?", (key,)).fetchone()
                if row["state"] == "unknown":
                    raise HubError("REQUEST_OUTCOME_UNKNOWN",
                                   "the operation was started and its result was lost; verify the real state, do not repeat blindly",
                                   request_key=request_key, started_at=row["started_at"], retry_safe=False,
                                   automatic_replay=False)
                if row["state"] in {"completed", "failed"}:
                    stored = json.loads(row["response"])
                    if row["state"] == "failed":
                        if stored.get("retry_safe") is True:
                            self._db.execute("DELETE FROM journal WHERE request_key=?", (key,))
                        else:
                            raise HubError(stored["code"], stored.get("message"), **{**stored.get("details", {}), "deduplicated": True})
                    else:
                        return {**stored, "deduplicated": True}
            self._db.execute(
                "INSERT INTO journal(request_key,agent_id,task_id,op,digest,state,boot_id,started_at) VALUES(?,?,?,?,?,'started',?,?)",
                (key, session["agent_id"], session["task_id"], op, digest, self.boot_id, self.clock()))
            self._running.add(key)
        try:
            result = run()
        except HubError as exc:
            with self._lock:
                state = "unknown" if exc.details.get("outcome_unknown") is True else "failed"
                self._db.execute("UPDATE journal SET state=?, finished_at=?, response=? WHERE request_key=?",
                                 (state, self.clock(), json.dumps({"code": exc.code, "message": exc.message, "details": exc.details,
                                                            "retry_safe": exc.details.get("retry_safe") is True
                                                            and exc.details.get("attempted") is not True},
                                                           ensure_ascii=False, default=str), key))
                self._running.discard(key)
            raise
        except BaseException:
            with self._lock:
                self._db.execute("UPDATE journal SET state='unknown', finished_at=? WHERE request_key=?", (self.clock(), key))
                self._running.discard(key)
            raise
        with self._lock:
            self._db.execute("UPDATE journal SET state='completed', finished_at=?, response=? WHERE request_key=?",
                             (self.clock(), json.dumps(result, ensure_ascii=False, default=str), key))
            self._running.discard(key)
        return {**result, "deduplicated": False}

    def journal_status(self, session: dict, request_key: str) -> dict:
        key = f"{session['agent_id']}\x1f{session['task_id']}\x1f{request_key}"
        with self._lock:
            row = self._db.execute("SELECT * FROM journal WHERE request_key=?", (key,)).fetchone()
            if row is None:
                return {"request_key": request_key, "state": "not_found", "execution_started": False}
            state = row["state"]
            if state == "started" and not (key in self._running and row["boot_id"] == self.boot_id):
                state = "unknown"
        return {"request_key": request_key, "state": state, "op": row["op"], "started_at": row["started_at"],
                "finished_at": row["finished_at"], "execution_started": True, "automatic_replay": False,
                "response": json.loads(row["response"]) if row["response"] else None}

    # ---- permission requests -------------------------------------------------------------
    def record_permission_request(self, session: dict, risk_class: str, target: dict, reason: str) -> dict:
        signature = _hash(json.dumps([session["agent_id"], risk_class, target], sort_keys=True, default=str))[:24]
        with self._lock:
            row = self._db.execute("SELECT * FROM permission_requests WHERE request_id=?", (signature,)).fetchone()
            if row is None:
                self._db.execute("INSERT INTO permission_requests VALUES(?,?,?,?,?,?,?,'pending')",
                                 (signature, self.clock(), session["agent_id"], session["task_id"], risk_class,
                                  json.dumps(target, ensure_ascii=False, default=str), reason[:500]))
        return {"request_id": signature, "state": row["state"] if row else "pending", "repeated": row is not None}

    def permission_requests(self, state: str = "pending") -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM permission_requests WHERE state=? ORDER BY at", (state,)).fetchall()
        return [{**dict(row), "target": json.loads(row["target"])} for row in rows]

    def resolve_permission_request(self, request_id: str, state: str) -> bool:
        with self._lock:
            return self._db.execute("UPDATE permission_requests SET state=? WHERE request_id=?", (state, request_id)).rowcount > 0

    # ---- maintenance ---------------------------------------------------------------------
    def maintain(self) -> dict:
        with self._lock:
            now = self.clock()
            journal = self._db.execute("DELETE FROM journal WHERE state IN ('completed','failed') AND finished_at<?",
                                       (now - JOURNAL_KEEP_SECONDS,)).rowcount
            released = self._db.execute("DELETE FROM resources WHERE state='released' AND released_at<?",
                                        (now - JOURNAL_KEEP_SECONDS,)).rowcount
            top = self._db.execute("SELECT MAX(id) FROM audit").fetchone()[0] or 0
            audit = self._db.execute("DELETE FROM audit WHERE id<=?", (top - AUDIT_KEEP_ROWS,)).rowcount
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return {"journal_rows_removed": journal, "resource_rows_removed": released, "audit_rows_removed": audit}
