"""Bounded, redacted task evidence; separate from deduplication authority."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import time
try:
    from ff_win_v3_security import scrub_text
except ImportError:
    from tools.ff_win_v3_security import scrub_text

def redact(value):
    if isinstance(value, dict):
        return {str(k): "<redacted>" if any(x in str(k).lower().replace("-", "_") for x in
                ("token", "secret", "cookie", "password", "authorization", "credential", "api_key", "private_key"))
                else redact(v) for k, v in value.items()}
    if isinstance(value, (tuple, list)):
        return [redact(v) for v in value]
    return scrub_text(value) if isinstance(value, str) else value

class TaskEvidence:
    def __init__(self, root, *, max_rows=2000, max_bytes=8*1024*1024, ttl_seconds=7*86400):
        self.path = Path(root) / "task-evidence.sqlite3"
        self.max_rows, self.max_bytes, self.ttl = max_rows, max_bytes, ttl_seconds

    def _connect(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(self.path, timeout=5)
        con.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, created REAL, agent TEXT, task TEXT, record TEXT)")
        return con

    def append(self, agent, task, record):
        raw = json.dumps(redact(record), ensure_ascii=False, allow_nan=False)
        if len(raw.encode()) > min(self.max_bytes, 64000):
            raw = json.dumps({"event": "evidence_oversize", "details_retained": False})
        with closing(self._connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("INSERT INTO events(created,agent,task,record) VALUES (?,?,?,?)", (time.time(), agent, task, raw))
            con.execute("DELETE FROM events WHERE created<?", (time.time()-self.ttl,))
            while True:
                count, size = con.execute("SELECT count(*),coalesce(sum(length(CAST(record AS BLOB))),0) FROM events").fetchone()
                if count <= self.max_rows and size <= self.max_bytes:
                    break
                con.execute("DELETE FROM events WHERE id=(SELECT min(id) FROM events)")
            con.commit()

    def export(self, *, agent, task=None, limit=100):
        limit = min(max(int(limit), 1), 500)
        with closing(self._connect()) as con:
            rows = con.execute("SELECT created,task,record FROM events WHERE agent=? AND (? IS NULL OR task=?) AND created>=? ORDER BY id DESC LIMIT ?",
                               (agent, task, task, time.time()-self.ttl, limit)).fetchall()
        return {"agent_id": agent, "task_id": task, "records": [{"created": r[0], "task_id": r[1], **json.loads(r[2])} for r in reversed(rows)],
                "retention_seconds": self.ttl, "max_bytes": self.max_bytes}


def assess_response(response):
    """Delivery, effect and verification are different facts, never caller claims."""
    nodes, processes = [], []
    def visit(value, *, process_snapshot=False):
        if isinstance(value, dict):
            nodes.append(value)
            if not process_snapshot and ("exit_code" in value or "running" in value):
                processes.append(value)
            has_current_process = "exit_code" in value and "running" in value
            for key, child in value.items():
                visit(child, process_snapshot=process_snapshot or
                      (key == "initial" and has_current_process))
        elif isinstance(value, list):
            for child in value: visit(child, process_snapshot=process_snapshot)
    visit(response)
    exit_failures = [n for n in processes if n.get("exit_code") is not None
                     and n["exit_code"] != 0]
    failed = bool(exit_failures) or any(n.get("ok") is False or n.get("error_code") for n in nodes)
    running = any(n.get("running") is True for n in processes)
    unknown = any("exit_code" in n and n["exit_code"] is None for n in processes)
    verified = not (failed or running or unknown) and any(n.get("verified") is True and
                                 (n.get("verification") or n.get("sha256") or n.get("stage") == "read_reply") for n in nodes)
    return {"assessment_version": 2,
            "delivery": "known_response",
            "execution": "failed" if failed else "running" if running else "unknown" if unknown else "returned",
            "task_completion": "failed" if failed else "in_progress" if running else "verified" if verified else "verification_required",
            "verification": {"verified": verified, "source": "tool_observation" if verified else "none"},
            "error": next((n["error_code"] for n in nodes if n.get("error_code")),
                          {"exit_code": exit_failures[0]["exit_code"]} if exit_failures else None),
            "cleanup": [n["cleanup"] for n in nodes if "cleanup" in n] or "not_reported"}
