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
import threading
import time
import uuid

from ff_app_catalog import AppCatalog, DEFAULT_SAFE_APPS
from ff_hub_store import HubError, _ident

ENTRY_PATH = "/agent/v1"
SCHEMA = "ff-agent-entry-v1"
BASE_OPS = {"capabilities", "route_plan", "session_open", "session_status",
            "session_heartbeat", "session_close", "request_status", "task_cancel", "audit_read"}
SCOPES = {
    "owner_chrome_hidden": {"owner_chrome_hidden"},
    "private_browser": {"private_browser", "managed_browser"},
    "private_app": {"app_discover", "app_open", "app_windows", "app_observe",
                    "app_find", "app_act", "app_capture", "app_document", "app_close"},
    "locks": {"resource_claim", "resource_list", "resource_release"},
    "artifacts": {"task_file"},
}
BROWSER_COMMANDS = ("open", "info", "close", "tabs", "tab_open", "tab_close", "navigate",
                    "observe", "snapshot", "read", "act", "upload", "download_prepare", "download_read", "screenshot")
READ_ONLY = {"info", "tabs", "observe", "snapshot", "read", "download_read", "screenshot"}
OWNER_CHROME_HIDDEN_COMMANDS = ("preflight", "status", "open", "list", "navigate", "observe", "read", "act", "screenshot", "close")
OWNER_CHROME_HIDDEN_READ_ONLY = {"preflight", "status", "list", "observe", "read", "screenshot"}
MUTATIONS = {"session_close", "task_cancel", "resource_claim", "resource_release", "app_open", "app_act", "app_close"}
FORBIDDEN_BROWSER_ARGS = frozenset({"route", "foreground", "headless", "profile_dir"})
FORBIDDEN_OWNER_CHROME_HIDDEN_ARGS = frozenset({
    "route", "foreground", "new_window", "newWindow", "window_state", "windowState",
    "copy_profile", "spawn_new_process", "second_process", "user_data_dir", "cdp_endpoint",
})
SAFE_APPS = DEFAULT_SAFE_APPS
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
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / "entry-grants.sqlite3"
        self.catalog = AppCatalog(self.state_dir)
        self.clock = clock
        self._lock = threading.RLock()

    def _connect(self, *, readonly: bool = False) -> sqlite3.Connection:
        if readonly:
            db = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=10)
            db.row_factory = sqlite3.Row
            return db
        self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def _ensure_schema(self, db: sqlite3.Connection) -> None:
        cols = {row["name"] for row in db.execute("PRAGMA table_info(grants)").fetchall()}
        if not cols:
            db.execute("""CREATE TABLE IF NOT EXISTS grants (
                grant_id TEXT PRIMARY KEY, digest TEXT NOT NULL, session_seed TEXT NOT NULL,
                client_id TEXT NOT NULL, agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
                scopes TEXT NOT NULL, apps TEXT NOT NULL, issued_at REAL NOT NULL,
                expires_at REAL NOT NULL, renewed_at REAL, revision INTEGER NOT NULL DEFAULT 1,
                revoked INTEGER NOT NULL DEFAULT 0, superseded_by TEXT)""")
        elif "session_seed" not in cols:
            # Migrate legacy UNIQUE(agent_id, task_id) table without losing existing grants.
            db.execute("""CREATE TABLE grants_v2 (
                grant_id TEXT PRIMARY KEY, digest TEXT NOT NULL, session_seed TEXT NOT NULL,
                client_id TEXT NOT NULL, agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
                scopes TEXT NOT NULL, apps TEXT NOT NULL, issued_at REAL NOT NULL,
                expires_at REAL NOT NULL, renewed_at REAL, revision INTEGER NOT NULL DEFAULT 1,
                revoked INTEGER NOT NULL DEFAULT 0, superseded_by TEXT)""")
            db.execute("""INSERT INTO grants_v2
                SELECT grant_id, digest, '', client_id, agent_id, task_id, scopes, apps,
                       expires_at, expires_at, NULL, 1, revoked, NULL FROM grants""")
            db.execute("DROP TABLE grants")
            db.execute("ALTER TABLE grants_v2 RENAME TO grants")
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS grants_active_identity
            ON grants(agent_id, task_id) WHERE superseded_by IS NULL""")
        db.execute("""CREATE TABLE IF NOT EXISTS grant_receipts (
            receipt_id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, action TEXT NOT NULL,
            client_id TEXT NOT NULL, agent_id TEXT NOT NULL, task_id TEXT NOT NULL,
            revision INTEGER NOT NULL, expires_at REAL NOT NULL, at REAL NOT NULL)""")

    def _record_receipt(self, db: sqlite3.Connection, *, grant_id: str, action: str,
                        client_id: str, agent_id: str, task_id: str, revision: int,
                        expires_at: float, at: float) -> str:
        receipt_id = "egr-" + uuid.uuid4().hex
        db.execute("INSERT INTO grant_receipts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (receipt_id, grant_id, action, client_id, agent_id, task_id, revision, expires_at, at))
        return receipt_id

    @staticmethod
    def _grant_view(row: sqlite3.Row | dict, **extra) -> dict:
        scopes = sorted(filter(None, row["scopes"].split(","))) if isinstance(row["scopes"], str) else list(row["scopes"])
        apps = sorted(filter(None, row["apps"].split(","))) if isinstance(row["apps"], str) else list(row["apps"])
        data = {
            "grant_id": row["grant_id"],
            "client_id": row["client_id"],
            "agent_id": row["agent_id"],
            "task_id": row["task_id"],
            "expires_at": row["expires_at"],
            "issued_at": row["issued_at"],
            "renewed_at": row["renewed_at"],
            "revision": row["revision"],
            "scopes": scopes,
            "apps": apps,
        }
        data.update(extra)
        return data

    def issue(self, *, client_id: str, agent_id: str, task_id: str, scopes: list[str],
              apps: list[str], ttl: int) -> tuple[dict, str]:
        client_id, agent_id, task_id = (_ident(value, key) for key, value in
                                        (("client_id", client_id), ("agent_id", agent_id), ("task_id", task_id)))
        if type(ttl) is not int or not 1 <= ttl <= 86400:
            raise HubError("ENTRY_TTL_INVALID")
        if not set(scopes) <= SCOPES.keys():
            raise HubError("ENTRY_SCOPE_INVALID")
        normalized_apps = self.catalog.validate_entry_apps(apps)
        if ("private_app" in scopes) != bool(normalized_apps):
            raise HubError("ENTRY_APPS_REQUIRED_FOR_SCOPE")
        grant_id = "eg-" + secrets.token_hex(16)
        token = f"{grant_id}.{secrets.token_urlsafe(32)}"
        session_seed = secrets.token_urlsafe(32)
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._ensure_schema(db)
                now = self.clock()
                expires_at = now + ttl
                existing = db.execute(
                    "SELECT * FROM grants WHERE agent_id=? AND task_id=? AND superseded_by IS NULL",
                    (agent_id, task_id)).fetchone()
                reissued = False
                previous_grant_id = None
                if existing is not None:
                    if not existing["revoked"] and existing["expires_at"] > now:
                        raise HubError("ENTRY_TASK_ALREADY_ENROLLED",
                                       grant_id=existing["grant_id"],
                                       expires_at=existing["expires_at"],
                                       hint="active grant exists; use renew to extend or rotate")
                    reissued = True
                    previous_grant_id = existing["grant_id"]
                    db.execute("UPDATE grants SET superseded_by=? WHERE grant_id=?", (grant_id, previous_grant_id))
                scopes_csv = ",".join(sorted(set(scopes)))
                apps_csv = ",".join(sorted(set(normalized_apps)))
                db.execute(
                    "INSERT INTO grants(grant_id,digest,session_seed,client_id,agent_id,task_id,"
                    "scopes,apps,issued_at,expires_at,renewed_at,revision,revoked,superseded_by)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,NULL,1,0,NULL)",
                    (grant_id, _digest(token), session_seed, client_id, agent_id, task_id,
                     scopes_csv, apps_csv, now, expires_at))
                receipt_id = self._record_receipt(
                    db, grant_id=grant_id, action="reissue" if reissued else "issue",
                    client_id=client_id, agent_id=agent_id, task_id=task_id,
                    revision=1, expires_at=expires_at, at=now)
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        view = {
            "grant_id": grant_id, "client_id": client_id, "agent_id": agent_id, "task_id": task_id,
            "issued_at": now, "expires_at": expires_at, "renewed_at": None, "revision": 1,
            "scopes": sorted(set(scopes)), "apps": sorted(set(normalized_apps)),
            "reissued": reissued, "previous_grant_id": previous_grant_id, "receipt_id": receipt_id,
        }
        return view, token

    def renew(self, *, client_id: str, agent_id: str, task_id: str, ttl: int,
              grant_id: str | None = None, scopes: list[str] | None = None,
              apps: list[str] | None = None) -> tuple[dict, str]:
        client_id, agent_id, task_id = (_ident(value, key) for key, value in
                                        (("client_id", client_id), ("agent_id", agent_id), ("task_id", task_id)))
        if type(ttl) is not int or not 1 <= ttl <= 86400:
            raise HubError("ENTRY_TTL_INVALID")
        if grant_id is not None and not GRANT_ID.fullmatch(grant_id):
            raise HubError("ENTRY_GRANT_INVALID")
        if not self.path.is_file():
            raise HubError("ENTRY_GRANT_NOT_FOUND")
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._ensure_schema(db)
                if grant_id is not None:
                    row = db.execute("SELECT * FROM grants WHERE grant_id=?", (grant_id,)).fetchone()
                else:
                    row = db.execute(
                        "SELECT * FROM grants WHERE agent_id=? AND task_id=? AND superseded_by IS NULL",
                        (agent_id, task_id)).fetchone()
                if row is None:
                    raise HubError("ENTRY_GRANT_NOT_FOUND")
                if row["superseded_by"] is not None:
                    raise HubError("ENTRY_GRANT_SUPERSEDED", superseded_by=row["superseded_by"])
                if (row["client_id"], row["agent_id"], row["task_id"]) != (client_id, agent_id, task_id):
                    raise HubError("ENTRY_GRANT_OWNER_MISMATCH")
                if row["revoked"]:
                    raise HubError("ENTRY_GRANT_REVOKED", grant_id=row["grant_id"],
                                   hint="revoked grants cannot be renewed; issue a new grant")
                if not row["session_seed"]:
                    raise HubError("ENTRY_LEGACY_GRANT_REISSUE_REQUIRED", grant_id=row["grant_id"])
                cur_scopes = set(filter(None, row["scopes"].split(",")))
                cur_apps = set(filter(None, row["apps"].split(",")))
                next_scopes = cur_scopes if scopes is None else set(scopes)
                next_apps = cur_apps if apps is None else set(self.catalog.validate_entry_apps(apps))
                if not next_scopes <= set(SCOPES.keys()):
                    raise HubError("ENTRY_SCOPE_INVALID")
                if not next_scopes <= cur_scopes or not next_apps <= cur_apps:
                    raise HubError("ENTRY_SCOPE_ESCALATION_DENIED", execution_started=False)
                if ("private_app" in next_scopes) != bool(next_apps):
                    raise HubError("ENTRY_APPS_REQUIRED_FOR_SCOPE")
                now = self.clock()
                expires_at = now + ttl
                revision = int(row["revision"]) + 1
                token = f"{row['grant_id']}.{secrets.token_urlsafe(32)}"
                scopes_csv = ",".join(sorted(next_scopes))
                apps_csv = ",".join(sorted(next_apps))
                db.execute(
                    "UPDATE grants SET digest=?, scopes=?, apps=?, expires_at=?, renewed_at=?, revision=? "
                    "WHERE grant_id=?",
                    (_digest(token), scopes_csv, apps_csv, expires_at, now, revision, row["grant_id"]))
                receipt_id = self._record_receipt(
                    db, grant_id=row["grant_id"], action="renew", client_id=client_id,
                    agent_id=agent_id, task_id=task_id, revision=revision, expires_at=expires_at, at=now)
                updated = db.execute("SELECT * FROM grants WHERE grant_id=?", (row["grant_id"],)).fetchone()
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
        return self._grant_view(updated, receipt_id=receipt_id), token

    def _row(self, grant_id: str) -> sqlite3.Row | None:
        if not self.path.is_file():
            return None
        with closing(self._connect(readonly=True)) as db:
            return db.execute("SELECT * FROM grants WHERE grant_id=?", (grant_id,)).fetchone()

    def receipts(self, *, agent_id: str | None = None, task_id: str | None = None,
                 grant_id: str | None = None) -> list[dict]:
        if not self.path.is_file():
            return []
        with closing(self._connect(readonly=True)) as db:
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            if "grant_receipts" not in tables:
                return []
            clauses, params = [], []
            for col, val in (("agent_id", agent_id), ("task_id", task_id), ("grant_id", grant_id)):
                if val is not None:
                    clauses.append(f"{col}=?")
                    params.append(val)
            query = "SELECT * FROM grant_receipts"
            if clauses:
                query += " WHERE " + " AND ".join(clauses)
            rows = db.execute(query + " ORDER BY rowid", params).fetchall()
            return [dict(row) for row in rows]

    def authorize(self, authorization: str) -> dict:
        match = TOKEN.fullmatch(authorization.removeprefix("Bearer ")) if authorization.startswith("Bearer ") else None
        if match is None:
            raise HubError("ENTRY_UNAUTHORIZED", execution_started=False)
        row = self._row(match[1])
        token = match[0]
        if (row is None or not secrets.compare_digest(row["digest"], _digest(token))
                or row["revoked"] or row["superseded_by"] is not None or row["expires_at"] <= self.clock()):
            raise HubError("ENTRY_UNAUTHORIZED", execution_started=False)
        seed = row["session_seed"] if "session_seed" in row.keys() and row["session_seed"] else token
        return {**{key: row[key] for key in ("grant_id", "client_id", "agent_id", "task_id", "expires_at")},
                "revision": row["revision"] if "revision" in row.keys() else 1,
                "scopes": set(filter(None, row["scopes"].split(","))),
                "apps": set(filter(None, row["apps"].split(","))),
                "entry_secret": _digest("ff-agent-entry-session-v1:" + seed)}

    def active(self, grant_id: str) -> bool:
        row = self._row(grant_id)
        if not row:
            return False
        superseded = row["superseded_by"] if "superseded_by" in row.keys() else None
        return bool(not row["revoked"] and superseded is None and row["expires_at"] > self.clock())

    def revoke(self, grant_id: str) -> bool:
        if not GRANT_ID.fullmatch(grant_id) or not self.path.is_file():
            return False
        with self._lock, closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._ensure_schema(db)
                row = db.execute("SELECT * FROM grants WHERE grant_id=?", (grant_id,)).fetchone()
                if row is None or row["revoked"]:
                    db.execute("ROLLBACK")
                    return False
                db.execute("UPDATE grants SET revoked=1 WHERE grant_id=? AND revoked=0", (grant_id,))
                self._record_receipt(
                    db, grant_id=grant_id, action="revoke", client_id=row["client_id"],
                    agent_id=row["agent_id"], task_id=row["task_id"],
                    revision=int(row["revision"]), expires_at=row["expires_at"], at=self.clock())
                db.execute("COMMIT")
                return True
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise


def route_plan(
    scope: dict,
    surface: str = "browser",
    *,
    hub: object | None = None,
    capability: str = "dom",
    prefer: str | None = None,
    profile_dir_name: str = "Profile 1",
) -> dict:
    from ff_browser_routes import route_plan as live_route_plan
    return live_route_plan(
        scope,
        surface=surface,
        hub=hub,
        capability=capability,
        prefer=prefer,
        profile_dir_name=profile_dir_name,
    )


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
                "operations": sorted(operations),
                "owner_chrome_hidden_commands": list(OWNER_CHROME_HIDDEN_COMMANDS) if "owner_chrome_hidden" in operations else [],
                "browser_commands": list(BROWSER_COMMANDS) if "private_browser" in operations else [],
                "managed_browser_commands": list(BROWSER_COMMANDS) if "managed_browser" in operations else [],
                "managed_browser_profile_args": ["profile_id", "profile_name", "persistent_profile"] if "managed_browser" in operations else [],
                "file_commands": ["list", "put", "read"] if "task_file" in operations else [],
                "apps": sorted(scope["apps"]), "client_id": scope["client_id"], "agent_id": scope["agent_id"],
                "task_id": scope["task_id"], "expires_at": scope["expires_at"],
                "primary_owner_auth_route": "owner_chrome_profile1_hidden_secondary",
                "owner_chrome_hidden_available": "owner_chrome_hidden" in operations,
                "optional_isolated_mode_available": bool({"managed_browser", "private_browser"} & operations),
                "default_browser_route": "owner_chrome_profile1_hidden_secondary" if "owner_chrome_hidden" in operations else "isolated_hidden_browser",
                "owner_chrome_available": "owner_chrome_hidden" in operations,
                "isolated_substitution_forbidden": True,
                "silent_playwright_fallback": False,
                "cleanup_receipt_fields": ["closed", "cleanup_verified", "resources_retained"],
                "foreground_fallback": False, "automatic_mutation_replay": False}
    if op == "route_plan":
        default_profile = getattr(getattr(hub, "owner_chrome_secondary", None), "profile_dir_name", None) or "Profile 1"
        return route_plan(
            scope,
            args.get("surface", "browser"),
            hub=hub,
            capability=args.get("capability", "dom"),
            prefer=args.get("prefer"),
            profile_dir_name=str(args.get("profile_dir_name") or default_profile),
        )
    if op == "session_open":
        if args:
            raise HubError("ENTRY_IDENTITY_FIXED", execution_started=False)
        return hub.open_entry_session(scope)
    if op == "audit_read":
        args = {**args, "task_id": scope["task_id"]}
    command = args.get("command")
    if op == "owner_chrome_hidden" and (
            command not in OWNER_CHROME_HIDDEN_COMMANDS or FORBIDDEN_OWNER_CHROME_HIDDEN_ARGS & args.keys()):
        raise HubError("ENTRY_BROWSER_COMMAND_DENIED", execution_started=False)
    if op in {"private_browser", "managed_browser"} and (
            command not in BROWSER_COMMANDS or FORBIDDEN_BROWSER_ARGS & args.keys()):
        raise HubError("ENTRY_BROWSER_COMMAND_DENIED", execution_started=False)
    if op == "app_discover":
        cid = authority.catalog.canonical_id(args.get("app")) if set(args) == {"app"} else None
        if cid is None or cid not in scope["apps"]:
            raise HubError("ENTRY_APP_DENIED", execution_started=False)
        args = {"app": cid}
    if op == "app_open":
        allowed_open = {"app", "document_path", "arguments", "working_directory", "window_timeout_s", "code_link"}
        cid = authority.catalog.canonical_id(args.get("app")) if "app" in args and not (set(args) - allowed_open) else None
        if cid is None or cid not in scope["apps"]:
            raise HubError("ENTRY_APP_DENIED", execution_started=False)
        args = {**args, "app": cid}
    if op in {"resource_claim", "resource_release"} and args.get("kind") not in sorted(LOCK_KINDS):
        raise HubError("ENTRY_LOCK_KIND_DENIED", execution_started=False)
    if (op in MUTATIONS
            or (op == "owner_chrome_hidden" and command not in OWNER_CHROME_HIDDEN_READ_ONLY)
            or (op in {"private_browser", "managed_browser"} and command not in READ_ONLY)
            or (op == "task_file" and command == "put")
            or (op == "app_document" and command != "read")):
        key = request.get("request_key")
        if not isinstance(key, str) or not key:
            raise HubError("REQUEST_KEY_REQUIRED", execution_started=False)
    return hub.dispatch({**request, "args": args, "session_secret": scope["entry_secret"]},
                        check_access=lambda: authority.authorize(authorization))
