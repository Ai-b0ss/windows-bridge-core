"""Owner chat permission: the owner's "да" in the chat opens a time-boxed desktop grant.

Owner decision (2026-10-31): trust is expressed in the chat and enforced by the
Skill, not by a signature per action. The Bridge cannot verify that a quote is
genuine; it records it, bounds the grant and keeps an audit trail.

The feature is off until the owner enables it in a LOCAL config file, which is
never writable through the RPC registry:

    {"schema":"ff-chat-permission-v1","enabled":true,"max_ttl_seconds":7200}

Optional "owner_opt_in_until" (Unix UTC seconds) makes the opt-in expire.
Every grant and every blocked attempt is appended to JSONL files so the owner
can review them (`scope_report`) and later switch on blocking per violation type.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

SCHEMA = "ff-chat-permission-v1"
DEFAULT_TTL = 3600
DEFAULT_MAX_TTL = 7200
MIN_TTL = 60
HARD_MAX_TTL = 86400
# Sending a message in the owner's name and owner interference are not listed on
# purpose: the Bridge cannot see what an app sends (the Skill covers that), and
# interference is prevented by the OWNER_ACTIVE pause instead of logged afterwards.
VIOLATION_KINDS = frozenset({
    "VISIBLE_INPUT_WITHOUT_PERMISSION",
    "PERMISSION_EXPIRED",
    "OUT_OF_SCOPE_APP",
    "ROUTE_SEARCH_SKIPPED",
})
ROUTE_SEARCH_COMMANDS = frozenset({
    "task_preflight", "programmatic_plan", "plan_action", "discover_cli",
    "prepare_tool", "app_api_probe", "resolve_app",
})
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


class ChatPermissionError(ValueError):
    pass


def _is_int(value) -> bool:
    return type(value) is int


class ChatPermissionPolicy:
    def __init__(self, config_path, state_dir, clock=time.time):
        self.config_path = Path(config_path)
        self.state_dir = Path(state_dir)
        self.clock = clock
        self._route_searched = set()

    # -- configuration (local file only) -------------------------------------
    def _config(self) -> dict:
        try:
            data = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"enabled": False}
        if not isinstance(data, dict) or data.get("schema") != SCHEMA or data.get("enabled") is not True:
            return {"enabled": False}
        until = data.get("owner_opt_in_until")
        if until is not None and (not _is_int(until) or until <= self.clock()):
            return {"enabled": False}
        ttl = data.get("max_ttl_seconds", DEFAULT_MAX_TTL)
        if not _is_int(ttl):
            ttl = DEFAULT_MAX_TTL
        return {"enabled": True, "max_ttl_seconds": max(MIN_TTL, min(ttl, HARD_MAX_TTL)),
                "owner_opt_in_until": until}

    def status(self) -> dict:
        cfg = self._config()
        return {"schema": SCHEMA, "enabled": cfg["enabled"],
                "max_ttl_seconds": cfg.get("max_ttl_seconds"),
                "owner_opt_in_until": cfg.get("owner_opt_in_until"),
                "quote_verified_by_bridge": False}

    # -- grant ---------------------------------------------------------------
    def authorize(self, args: dict) -> float:
        """Validate a chat permission and return its expiry (Unix seconds)."""
        cfg = self._config()
        if not cfg["enabled"]:
            raise ChatPermissionError("CHAT_PERMISSION_DISABLED")
        permission = args.get("owner_chat_permission")
        if not isinstance(permission, dict) or set(permission) - {"quote", "apps", "duration_seconds"}:
            raise ChatPermissionError("CHAT_PERMISSION_INVALID")
        quote = permission.get("quote")
        if not isinstance(quote, str) or not 2 <= len(quote.strip()) <= 2000:
            raise ChatPermissionError("CHAT_PERMISSION_QUOTE_REQUIRED")
        for name in ("agent_id", "task_id"):
            value = args.get(name)
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ChatPermissionError("CHAT_PERMISSION_IDENTITY_INVALID")
        apps = permission.get("apps", [])
        if not isinstance(apps, list) or len(apps) > 16 or not all(
                isinstance(a, str) and 1 <= len(a) <= 128 for a in apps):
            raise ChatPermissionError("CHAT_PERMISSION_APPS_INVALID")
        duration = permission.get("duration_seconds", DEFAULT_TTL)
        if not _is_int(duration) or duration < MIN_TTL:
            raise ChatPermissionError("CHAT_PERMISSION_DURATION_INVALID")
        duration = min(duration, cfg["max_ttl_seconds"])
        now = self.clock()
        expires = now + duration
        try:  # a new grant starts clean: forget an old Stop press
            (self.state_dir / "stop.flag").unlink()
        except OSError:
            pass
        self._append("chat-permission.jsonl", {
            "kind": "GRANT", "agent_id": args["agent_id"], "task_id": args["task_id"],
            "quote": quote.strip(), "apps": apps, "duration_seconds": duration,
            "expires": expires,
        }, required=True)
        if not self.has_route_search(args["agent_id"], args["task_id"]):
            # Log only: the owner reviews this and decides whether to enforce it.
            self.log_violation("ROUTE_SEARCH_SKIPPED", agent_id=args["agent_id"],
                               task_id=args["task_id"])
        return expires

    # -- evidence that programmatic routes were looked at first ----------------
    def note_route_search(self, agent, task, command) -> None:
        if command not in ROUTE_SEARCH_COMMANDS:
            return
        if not (isinstance(agent, str) and isinstance(task, str)
                and _ID.fullmatch(agent) and _ID.fullmatch(task)):
            return
        key = (agent, task)
        if key in self._route_searched:
            return
        self._route_searched.add(key)
        self._append("route-search.jsonl", {"agent_id": agent, "task_id": task,
                                            "command": command}, required=False)

    def has_route_search(self, agent, task) -> bool:
        if (agent, task) in self._route_searched:
            return True
        return any(row.get("agent_id") == agent and row.get("task_id") == task
                   for row in self._read("route-search.jsonl"))

    # -- trap: record what went outside the owner's words --------------------
    def log_violation(self, kind: str, **details) -> None:
        if kind not in VIOLATION_KINDS:
            raise ValueError("UNKNOWN_VIOLATION_KIND")
        self._append("scope-violations.jsonl", {"kind": kind, **details}, required=False)

    def scope_report(self, hours: int = 24) -> dict:
        if not _is_int(hours) or not 1 <= hours <= 720:
            raise ChatPermissionError("SCOPE_REPORT_RANGE_INVALID")
        since = self.clock() - hours * 3600
        counts: dict[str, int] = {}
        examples: dict[str, list] = {}
        grants = 0
        for name, is_grant in (("scope-violations.jsonl", False), ("chat-permission.jsonl", True)):
            for row in self._read(name):
                if row.get("ts", 0) < since:
                    continue
                if is_grant:
                    grants += 1
                    continue
                kind = str(row.get("kind"))
                counts[kind] = counts.get(kind, 0) + 1
                if len(examples.setdefault(kind, [])) < 5:
                    examples[kind].append(row)
        return {"hours": hours, "grants": grants, "violations": counts, "examples": examples,
                "violation_total": sum(counts.values())}

    # -- storage -------------------------------------------------------------
    def _append(self, name: str, row: dict, *, required: bool) -> None:
        row = {"ts": self.clock(), **row}
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            with open(self.state_dir / name, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        except OSError as exc:
            if required:
                raise ChatPermissionError("CHAT_PERMISSION_LOG_UNAVAILABLE") from exc

    def _read(self, name: str):
        try:
            lines = (self.state_dir / name).read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for line in lines[-5000:]:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                yield row
