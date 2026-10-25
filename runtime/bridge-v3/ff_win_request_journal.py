"""Persistent request outcomes. A lost reply must not cause a second mutation."""
from __future__ import annotations
from contextlib import closing
import hashlib
import json
import re
import sqlite3
import time
from ff_win_evidence import redact
from pathlib import Path
from typing import Any, Callable

def choose_request_journal_root(
    *,
    bridge_root: str | Path,
    override: str | None,
    local_appdata: str | None,
    home: str | Path,
) -> Path:
    """Preserve legacy production journal; isolate explicit FF_BRIDGE_ROOT.

    Deliberately do NOT move existing live machine records. Moving the
    request-key tombstones could allow a previously dispatched operation
    to be retried after an upgrade.
    """
    if override:
        expected = Path(override)
        if not expected.is_absolute():
            raise RequestJournalError("REQUEST_JOURNAL_ROOT_NOT_ABSOLUTE")
        resolved = Path(bridge_root)
        if not resolved.is_absolute() or resolved.resolve() != expected.resolve():
            raise RequestJournalError("REQUEST_JOURNAL_ROOT_MISMATCH")
        return resolved / "state" / "request-outcomes"
    local = Path(local_appdata) if local_appdata else Path(home) / "AppData" / "Local"
    return local / "FFWindowsBridge" / "state" / "request-outcomes"


class RequestJournalError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code

def _key(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        raise RequestJournalError("REQUEST_KEY_INVALID")
    return value

class RequestJournal:
    def __init__(self, directory: str | Path, *, retention_seconds=7*86400, max_response_bytes=64*1024*1024, max_keys=100000):
        self.directory = Path(directory)
        self.path = self.directory / "request-outcomes.sqlite3"
        self.retention_seconds, self.max_response_bytes, self.max_keys = retention_seconds, max_response_bytes, max_keys

    def _connect(self):
        connection = None
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.path, timeout=2.0)
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("CREATE TABLE IF NOT EXISTS outcomes (request_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, state TEXT NOT NULL, response TEXT)")
            # Keep the original four-column table compatible with installed
            # clients that use INSERT INTO outcomes VALUES (...). Retention
            # metadata belongs in a separate table, not a breaking ALTER.
            connection.execute("CREATE TABLE IF NOT EXISTS outcome_timestamps (request_key TEXT PRIMARY KEY, updated REAL NOT NULL)")
            columns = {r[1] for r in connection.execute("PRAGMA table_info(outcomes)")}
            if "updated" in columns:
                # Undo the former incompatible migration atomically while
                # preserving every key, fingerprint, state, response and age.
                connection.execute("INSERT OR IGNORE INTO outcome_timestamps SELECT request_key,updated FROM outcomes")
                connection.execute("CREATE TABLE outcomes_compat (request_key TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, state TEXT NOT NULL, response TEXT)")
                connection.execute("INSERT INTO outcomes_compat SELECT request_key,fingerprint,state,response FROM outcomes")
                missing = connection.execute("SELECT count(*) FROM (SELECT request_key,fingerprint,state,response FROM outcomes EXCEPT SELECT request_key,fingerprint,state,response FROM outcomes_compat)").fetchone()[0]
                if missing:
                    raise sqlite3.IntegrityError("REQUEST_JOURNAL_MIGRATION_LOSS")
                connection.execute("DROP TABLE outcomes")
                connection.execute("ALTER TABLE outcomes_compat RENAME TO outcomes")
            connection.execute("INSERT OR IGNORE INTO outcome_timestamps SELECT request_key,? FROM outcomes", (time.time(),))
            connection.execute("CREATE TRIGGER IF NOT EXISTS outcomes_timestamp_insert AFTER INSERT ON outcomes BEGIN INSERT OR REPLACE INTO outcome_timestamps VALUES (NEW.request_key,CAST(strftime('%s','now') AS REAL)); END")
            connection.execute("CREATE TRIGGER IF NOT EXISTS outcomes_timestamp_complete AFTER UPDATE OF state,response ON outcomes WHEN NEW.state='completed' BEGIN INSERT OR REPLACE INTO outcome_timestamps VALUES (NEW.request_key,CAST(strftime('%s','now') AS REAL)); END")
            connection.commit()
            return connection
        except (OSError, sqlite3.Error) as exc:
            if connection is not None:
                connection.close()
            raise RequestJournalError("REQUEST_JOURNAL_UNAVAILABLE") from exc

    def status(self, request_key: str) -> dict[str, Any]:
        key = _key(request_key)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._prune(connection)
                row = connection.execute("SELECT state,response FROM outcomes WHERE request_key=?", (key,)).fetchone()
                connection.commit()
            return self._status(key, row)
        except sqlite3.Error as exc:
            raise RequestJournalError("REQUEST_JOURNAL_UNAVAILABLE") from exc

    @staticmethod
    def _status(key, row):
        if row is None:
            return {"request_key": key, "state": "not_found", "retry_safe": False}
        state, raw = row
        if state == "expired":
            return {"request_key": key, "state": "outcome_expired", "retry_safe": False,
                    "reason": "response retention elapsed; key and fingerprint remain reserved; do not repeat the effect"}
        if state == "completed":
            return {"request_key": key, "state": state, "response": json.loads(raw), "retry_safe": False}
        # Dispatch may have committed its external side effect before a crash.
        # No age-based or dead-owner replay is safe here.
        return {"request_key": key, "state": "outcome_unknown", "retry_safe": False,
                "reason": "dispatch began; retrieve or inspect the external result before any new mutation"}

    def _prune(self, connection):
        # Keep fingerprints/tombstones. The admission cap bounds their size;
        # exhaustion rejects new work instead of forgetting old effects.
        connection.execute("UPDATE outcomes SET state='expired',response=NULL WHERE state='completed' AND request_key IN (SELECT request_key FROM outcome_timestamps WHERE updated<?)", (time.time()-self.retention_seconds,))
        size = connection.execute("SELECT coalesce(sum(length(CAST(response AS BLOB))),0) FROM outcomes").fetchone()[0]
        while size > self.max_response_bytes:
            row = connection.execute("SELECT o.request_key,length(CAST(o.response AS BLOB)) FROM outcomes o JOIN outcome_timestamps t ON o.request_key=t.request_key WHERE o.state='completed' ORDER BY t.updated LIMIT 1").fetchone()
            if not row: break
            connection.execute("UPDATE outcomes SET state='expired',response=NULL WHERE request_key=?", (row[0],))
            size -= row[1]

    def maintain(self):
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._prune(connection)
            connection.commit()
            connection.execute("VACUUM")
        return {"retention_seconds": self.retention_seconds, "max_response_bytes": self.max_response_bytes,
                "max_keys": self.max_keys, "tombstones_preserved": True, "capacity_policy": "reject_new_keys"}

    def execute(self, request_key: str, payload: dict[str, Any], dispatch: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        key = _key(request_key)
        try:
            canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        except (TypeError, ValueError) as exc:
            raise RequestJournalError("REQUEST_PAYLOAD_INVALID") from exc
        fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._prune(connection)
            row = connection.execute("SELECT fingerprint,state,response FROM outcomes WHERE request_key=?", (key,)).fetchone()
            if row is not None:
                connection.commit()
                if row[0] != fingerprint:
                    raise RequestJournalError("REQUEST_KEY_CONFLICT")
                result = self._status(key, row[1:])
                result["cached"] = row[1] == "completed"
                return result
            if connection.execute("SELECT count(*) FROM outcomes").fetchone()[0] >= self.max_keys:
                raise RequestJournalError("REQUEST_JOURNAL_CAPACITY_EXHAUSTED")
            connection.execute("INSERT INTO outcomes(request_key,fingerprint,state,response) VALUES (?,?,?,NULL)", (key, fingerprint, "dispatching"))
            connection.execute("UPDATE outcome_timestamps SET updated=? WHERE request_key=?", (time.time(), key))
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise RequestJournalError("REQUEST_JOURNAL_UNAVAILABLE") from exc
        finally:
            connection.close()
        # The durable dispatching record is committed before calling the tool.
        # If dispatch or serialization crashes, leave it uncertain, never replay.
        response = dispatch()
        try:
            response = redact(response)
            encoded = json.dumps(response, ensure_ascii=False, allow_nan=False)
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("UPDATE outcomes SET state='completed',response=? WHERE request_key=? AND fingerprint=? AND state='dispatching'", (encoded,key,fingerprint))
                connection.execute("UPDATE outcome_timestamps SET updated=? WHERE request_key=?", (time.time(), key))
                self._prune(connection)
                connection.commit()
        except (TypeError, ValueError, sqlite3.Error, RequestJournalError) as exc:
            raise RequestJournalError("REQUEST_OUTCOME_NOT_PERSISTED") from exc
        return {"request_key": key, "state": "completed", "cached": False, "response": response, "retry_safe": False}
