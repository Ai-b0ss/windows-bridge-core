"""Task-scoped agent entry grants. Issuance and revocation are local owner operations."""
from __future__ import annotations

import base64
from contextlib import closing
from hashlib import sha256
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

from ff_hub_store import HubError, _ident

ENTRY_PATH = "/agent/v1"
SCHEMA = "ff-agent-entry-v1"
BASE_OPS = {"capabilities", "route_plan", "session_open", "session_status",
            "session_heartbeat", "request_status", "task_cancel", "audit_read"}
SCOPES = {
    "private_browser": {"private_browser"},
    "private_app": {"app_discover", "app_open", "app_windows", "app_observe",
                    "app_find", "app_act", "app_capture", "app_close"},
    "locks": {"resource_claim", "resource_list", "resource_release"},
    "artifacts": {"task_file"},
}
BROWSER_COMMANDS = ("open", "info", "close", "tabs", "tab_open", "tab_close", "navigate",
                    "observe", "read", "act", "upload", "download_prepare", "download_read", "screenshot")
READ_ONLY = {"info", "tabs", "observe", "read", "download_read", "screenshot"}
MUTATIONS = {"task_cancel", "resource_claim", "resource_release", "app_open", "app_act", "app_close"}
SAFE_APPS = {"charmap", "word", "excel", "powerpoint"}
LOCK_KINDS = {"custom", "file", "directory"}
GRANT_ID = re.compile(r"eg-[0-9a-f]{32}\Z", re.ASCII)
TOKEN = re.compile(r"(eg-[0-9a-f]{32})\.([A-Za-z0-9_-]{43})\Z", re.ASCII)
FILENAME = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?\Z", re.ASCII)
WINDOWS_DEVICE = re.compile(r"con|prn|aux|nul|com[1-9]|lpt[1-9]", re.ASCII)
MAX_FILE_BYTES = 1024 * 1024
MAX_TASK_FILES = 16
MAX_TASK_BYTES = 4 * MAX_FILE_BYTES


def _digest(value: str) -> str:
    return sha256(value.encode("ascii")).hexdigest()


class EntryAuthority:
    def __init__(self, state_dir: Path, *, clock=time.time):
        self.path = Path(state_dir) / "entry-grants.sqlite3"
        self.clock = clock

    def issue(self, *, client_id: str, agent_id: str, task_id: str, scopes: list[str],
              apps: list[str], ttl: int) -> tuple[dict, str]:
        client_id, agent_id, task_id = (_ident(value, key) for key, value in
                                        (("client_id", client_id), ("agent_id", agent_id), ("task_id", task_id)))
        if type(ttl) is not int or not 1 <= ttl <= 86400:
            raise HubError("ENTRY_TTL_INVALID")
        if not set(scopes) <= SCOPES.keys() or not set(apps) <= SAFE_APPS:
            raise HubError("ENTRY_SCOPE_INVALID")
        if ("private_app" in scopes) != bool(apps):
            raise HubError("ENTRY_APPS_REQUIRED_FOR_SCOPE")
        grant_id = "eg-" + secrets.token_hex(16)
        token = f"{grant_id}.{secrets.token_urlsafe(32)}"
        expires_at = self.clock() + ttl
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with closing(sqlite3.connect(self.path)) as db, db:
                db.execute("""CREATE TABLE IF NOT EXISTS grants (
                    grant_id TEXT PRIMARY KEY, digest TEXT NOT NULL, client_id TEXT NOT NULL,
                    agent_id TEXT NOT NULL, task_id TEXT NOT NULL, scopes TEXT NOT NULL, apps TEXT NOT NULL,
                    expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, UNIQUE(agent_id, task_id))""")
                db.execute("INSERT INTO grants VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
                           (grant_id, _digest(token), client_id, agent_id, task_id, ",".join(scopes),
                            ",".join(apps), expires_at))
        except sqlite3.IntegrityError:
            raise HubError("ENTRY_TASK_ALREADY_ENROLLED") from None
        return {"grant_id": grant_id, "client_id": client_id, "agent_id": agent_id,
                "task_id": task_id, "expires_at": expires_at, "scopes": scopes, "apps": apps}, token

    def _row(self, grant_id: str) -> sqlite3.Row | None:
        if not self.path.is_file():
            return None
        with closing(sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True)) as db:
            db.row_factory = sqlite3.Row
            return db.execute("SELECT * FROM grants WHERE grant_id=?", (grant_id,)).fetchone()

    def authorize(self, authorization: str) -> dict:
        match = TOKEN.fullmatch(authorization.removeprefix("Bearer ")) if authorization.startswith("Bearer ") else None
        if match is None:
            raise HubError("ENTRY_UNAUTHORIZED", execution_started=False)
        row = self._row(match[1])
        token = match[0]
        if (row is None or not secrets.compare_digest(row["digest"], _digest(token))
                or row["revoked"] or row["expires_at"] <= self.clock()):
            raise HubError("ENTRY_UNAUTHORIZED", execution_started=False)
        return {**{key: row[key] for key in ("grant_id", "client_id", "agent_id", "task_id", "expires_at")},
                "scopes": set(filter(None, row["scopes"].split(","))),
                "apps": set(filter(None, row["apps"].split(","))),
                "entry_secret": _digest("ff-agent-entry-session-v1:" + token)}

    def active(self, grant_id: str) -> bool:
        row = self._row(grant_id)
        return bool(row and not row["revoked"] and row["expires_at"] > self.clock())

    def revoke(self, grant_id: str) -> bool:
        if not GRANT_ID.fullmatch(grant_id) or not self.path.is_file():
            return False
        with closing(sqlite3.connect(self.path)) as db, db:
            result = db.execute("UPDATE grants SET revoked=1 WHERE grant_id=? AND revoked=0", (grant_id,))
            return bool(result.rowcount)


def route_plan(scope: dict, surface: str = "browser") -> dict:
    private_browser = surface == "browser" and "private_browser" in scope["scopes"]
    private_app = surface == "app" and "private_app" in scope["scopes"]
    if surface not in ("browser", "app"):
        raise HubError("ENTRY_SURFACE_INVALID", execution_started=False)
    routes = [
        {"route": "api_cli_sdk_com", "state": "UNMANAGED",
         "reason": "provider must participate in the broker to supply managed task receipts"},
        {"route": "native_agent_extension", "state": "UNMANAGED",
         "reason": "no verified broker ownership or persistent platform approval"},
        {"route": "owner_chrome_extension", "state": "UNAVAILABLE",
         "reason": "the scoped entry cannot attach to the owner's Chrome"},
        {"route": "private_cdp", "state": "ELIGIBLE" if private_browser else "UNAVAILABLE",
         "reason": "requires an installed Chrome and local app_launch policy",
         "authorization": "managed private profile, no owner Chrome grant"},
        {"route": "persistent_playwright", "state": "UNAVAILABLE",
         "reason": "no managed Playwright adapter registered at this entry"},
        {"route": "private_uia", "state": "ELIGIBLE" if private_app else "UNAVAILABLE",
         "reason": "requires a scoped app, local app_launch policy and a supported private launch"},
    ]
    return {"surface": surface, "selected": "private_cdp" if private_browser else "private_uia" if private_app else None,
            "routes": routes, "health_probed": False, "foreground_fallback": False}


class EntryArtifacts:
    def __init__(self, state_dir: Path):
        self.root = state_dir / "entry-artifacts"

    def _folder(self, session_id: str) -> Path:
        folder = self.root / session_id
        if not re.fullmatch(r"ses-[0-9a-f]{32}", session_id) or any(
                path.is_symlink() or getattr(path, "is_junction", lambda: False)() for path in (self.root, folder)):
            raise HubError("ENTRY_FILE_STORAGE_INVALID")
        return folder

    def call(self, session_id: str, args: dict) -> dict:
        folder = self._folder(session_id)
        command = args.get("command")
        if command == "list":
            return {"files": sorted(path.name for path in folder.glob("*") if FILENAME.fullmatch(path.name))}
        name = args.get("name")
        if (not isinstance(name, str) or not FILENAME.fullmatch(name) or name == "stop.flag"
                or WINDOWS_DEVICE.fullmatch(name.split(".")[0])):
            raise HubError("ENTRY_FILENAME_INVALID", execution_started=False)
        path = folder / name
        if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
            raise HubError("ENTRY_FILE_STORAGE_INVALID")
        if command == "read":
            try:
                with path.open("rb") as source:
                    body = source.read(MAX_FILE_BYTES + 1)
            except FileNotFoundError:
                raise HubError("ENTRY_FILE_NOT_FOUND", execution_started=False) from None
            if len(body) > MAX_FILE_BYTES:
                raise HubError("ENTRY_FILE_TOO_LARGE", execution_started=False)
            return {"name": name, "size": len(body), "sha256": sha256(body).hexdigest(),
                    "content_base64": base64.b64encode(body).decode("ascii")}
        if command != "put":
            raise HubError("ENTRY_FILE_COMMAND_INVALID", execution_started=False)
        try:
            body = base64.b64decode(args.get("content_base64"), validate=True)
        except (TypeError, ValueError):
            raise HubError("ENTRY_FILE_CONTENT_INVALID", execution_started=False) from None
        if len(body) > MAX_FILE_BYTES:
            raise HubError("ENTRY_FILE_TOO_LARGE", execution_started=False)
        existing = [item for item in folder.glob("*") if item != path and FILENAME.fullmatch(item.name)]
        if len(existing) >= MAX_TASK_FILES or sum(item.stat().st_size for item in existing) + len(body) > MAX_TASK_BYTES:
            raise HubError("ENTRY_FILE_QUOTA", execution_started=False)
        folder.mkdir(parents=True, exist_ok=True)
        temporary = folder / (".put-" + secrets.token_hex(16))
        try:
            with temporary.open("xb") as output:
                output.write(body)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        return {"name": name, "size": len(body), "sha256": sha256(body).hexdigest()}

    def close(self, session_id: str) -> int:
        folder = self._folder(session_id)
        if not folder.exists():
            return 0
        removed = 0
        # Delete only direct files in the task's own directory. Unexpected
        # child directories prevent claiming complete cleanup.
        for path in folder.iterdir():
            if path.name == "stop.flag":
                raise HubError("ENTRY_FILE_STORAGE_INVALID")
            path.unlink()
            removed += 1
        folder.rmdir()
        return removed


def entry_call(hub, authority: EntryAuthority, authorization: str, request: dict) -> dict:
    scope = authority.authorize(authorization)
    if not isinstance(request, dict) or set(request) - {"op", "args", "session_id", "request_key"}:
        raise HubError("ENTRY_REQUEST_INVALID", execution_started=False)
    op, args = request.get("op"), request.get("args", {})
    if not isinstance(op, str) or not isinstance(args, dict):
        raise HubError("ENTRY_REQUEST_INVALID", execution_started=False)
    operations = BASE_OPS.union(*(SCOPES[item] for item in scope["scopes"]))
    if op not in operations:
        raise HubError("ENTRY_SCOPE_DENIED", execution_started=False)
    if op == "capabilities":
        return {"schema": SCHEMA, "http_path": ENTRY_PATH, "mcp_transport": "stdio",
                "operations": sorted(operations), "browser_commands": list(BROWSER_COMMANDS) if "private_browser" in operations else [],
                "file_commands": ["list", "put", "read"] if "task_file" in operations else [],
                "apps": sorted(scope["apps"]), "client_id": scope["client_id"], "agent_id": scope["agent_id"],
                "task_id": scope["task_id"], "expires_at": scope["expires_at"],
                "foreground_fallback": False, "automatic_mutation_replay": False}
    if op == "route_plan":
        return route_plan(scope, args.get("surface", "browser"))
    if op == "session_open":
        if args:
            raise HubError("ENTRY_IDENTITY_FIXED", execution_started=False)
        return hub.open_entry_session(scope)
    if op == "audit_read":
        args = {**args, "task_id": scope["task_id"]}
    command = args.get("command")
    if op == "private_browser" and (command not in BROWSER_COMMANDS or {"route", "foreground"} & args.keys()):
        raise HubError("ENTRY_BROWSER_COMMAND_DENIED", execution_started=False)
    if op in {"app_open", "app_discover"} and (set(args) != {"app"} or args["app"] not in sorted(scope["apps"])):
        raise HubError("ENTRY_APP_DENIED", execution_started=False)
    if op in {"resource_claim", "resource_release"} and args.get("kind") not in sorted(LOCK_KINDS):
        raise HubError("ENTRY_LOCK_KIND_DENIED", execution_started=False)
    if op in MUTATIONS or (op == "private_browser" and command not in READ_ONLY) or (op == "task_file" and command == "put"):
        key = request.get("request_key")
        if not isinstance(key, str) or not key:
            raise HubError("REQUEST_KEY_REQUIRED", execution_started=False)
    return hub.dispatch({**request, "args": args, "session_secret": scope["entry_secret"]},
                        check_access=lambda: authority.authorize(authorization))
