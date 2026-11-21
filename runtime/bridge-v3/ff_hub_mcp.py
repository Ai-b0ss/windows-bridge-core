"""Dependency-free MCP stdio adapter for an existing FF Hub.

Owner configuration fixes the endpoint/state and client label. Models never
receive transport keys, session secrets or resume tokens. A disconnected MCP
client leaves its session intact for explicit recovery in a later process.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import time
import uuid

# Portable embedded Python omits the script directory from its isolated path.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ff_hub import HubClient, _pid_alive, default_state_dir, ensure_running
from ff_hub_io import atomic_json
from ff_hub_store import HubError, _ident
from ff_win_process_identity import process_creation_token, process_identity_matches

PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
MCP_ADAPTER_VERSION = "1.1.0"
PUBLIC = {"capabilities", "hub_status", "route_plan"}
OPS = PUBLIC | {"session_open", "session_resume", "session_heartbeat", "session_status", "session_close", "task_cancel",
                "resource_claim", "resource_release", "resource_list", "permission_check", "permission_describe",
                "site_read", "owner_chrome_hidden", "browser", "private_browser", "managed_browser", "app_discover", "app_open", "app_windows", "app_observe", "app_find",
                "app_act", "app_capture", "app_document", "app_close", "files", "terminal", "request_status",
                "audit_read"}
_PRIVATE_RESULT_KEYS = frozenset({"session_secret", "resume_token", "_mcp_owner", "_mcp_pending"})

TOOL = {
    "name": "hub",
    "description": (
        "Shared FF Hub: call capabilities or route_plan first, then session_open with a unique task_id. "
        "Primary owner-auth browser route is owner_chrome_hidden (owner_chrome_profile1_hidden_secondary: windowless hidden target inside already-running owner Chrome selected active profile via loopback CDP; inherits auth with zero cookie copying and zero visible side effects; fail-closed if CDP or selected-profile default context is unavailable — NEVER silently substitute an isolated profile). "
        "For a no-interruption read-only site read using only already authorized and connected supported providers, use site_read (or route_plan capability='background_tab_read' with url and visibility='background_tab'|'strict_invisible'): distinguishes ordinary non-activating background tabs from strict invisibility (never substitutes a visible tab when strict invisibility is requested), reports one actionable capability result before any UI or pending request when no provider is eligible, and closes owned tabs deterministically. FF Browser Companion 0.1.1 only supports downloads and Native Messaging (never a browser page reader). "
        "For supported background form operations on already authorized owned tabs without foreground interaction or policy changes, plan with route_plan capability='background_tab_form' and drive owned tabs through owner_chrome_hidden or browser (open, observe/snapshot, act: fill|click|select|check|uncheck|press, wait_for, reload, read, close) with a stable request_key for every mutation to prevent duplicate submission. "
        "Optional isolated mode (no owner auth): managed_browser or private_browser. "
        "Explicit visible-tab extension mode: browser (adds tabs to owner Chrome tab strip; hidden secondary window unsupported). "
        "Use a stable request_key for mutations. After a lost reply call request_status with the same key; "
        "never replay unknown work. Credentials stay private in per-task checkpoints owned by the live MCP process; "
        "concurrent processes cannot hijack an active task_id. Close only your resources with session_close "
        "(verify cleanup_verified=true and resources_retained=0). No foreground input, paid model calls or owner grants here."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "op": {
                "type": "string",
                "enum": sorted(OPS),
                "description": "Hub operation name. Start with capabilities/route_plan, then session_open.",
            },
            "task_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "description": "Unique task label owned by this MCP process; required except capabilities/hub_status/route_plan.",
            },
            "request_key": {
                "type": "string",
                "minLength": 8,
                "maxLength": 200,
                "description": "Stable idempotency key (8..200 chars); required for mutating operations and recommended for session_close.",
            },
            "args": {
                "type": "object",
                "description": "Operation-specific arguments (command, url, tab_id, profile_dir_name, browser_id, profile_id, app, path, argv, etc.).",
                "properties": {
                    "command": {"type": "string", "description": "Sub-command for site_read/owner_chrome_hidden/browser/managed_browser/private_browser/files/terminal/app_document (including reload and wait_for on owned browser tabs)."},
                    "surface": {"type": "string", "enum": ["browser", "app"], "description": "Target surface for route_plan."},
                    "capability": {"type": "string", "description": "Requested capability for route_plan (background_tab_read, background_tab_form, owner_profile_hidden, dom, extension_bridge, download)."},
                    "prefer": {"type": "string", "description": "Optional preferred route name for route_plan."},
                    "visibility": {"type": "string", "enum": ["background_tab", "strict_invisible"], "description": "Target visibility for site_read/route_plan: ordinary non-activating background_tab vs strict_invisible (never substitutes visible tabs)."},
                    "strict_invisibility": {"type": "boolean", "description": "When true, requires a fully invisible windowless target and forbids substituting a visible browser tab."},
                    "read_mode": {"type": "string", "enum": ["read", "observe", "snapshot"], "description": "Read-only capture mode for site_read (read, observe, snapshot)."},
                    "max_chars": {"type": "integer", "minimum": 100, "maximum": 400000, "description": "Maximum text characters returned by site_read/read/snapshot."},
                    "profile_dir_name": {"type": "string", "description": "Owner Chrome profile directory name (e.g. 'Default' or 'Profile 1') for site_read/owner_chrome_hidden/route_plan."},
                    "connect_ws": {"type": "boolean", "description": "For owner_chrome_hidden preflight: actively attach via loopback CDP WebSocket (requires Hub policy grant and Chrome confirmation dialog if prompted)."},
                    "host": {"type": "string", "description": "Optional concrete target hostname (e.g. 'example.com') for site-scoped owner_chrome_hidden preflight connect_ws."},
                    "viewport": {"type": "object", "properties": {"width": {"type": "integer"}, "height": {"type": "integer"}}, "description": "Emulated {width, height} viewport for owner_chrome_hidden open."},
                    "url": {"type": "string", "description": "Target http(s) URL for browser navigation/open."},
                    "browser_id": {"type": "string", "description": "Owned managed_browser or private_browser identifier."},
                    "tab_id": {"type": "string", "description": "Owned browser or owner_chrome_hidden target identifier."},
                    "sticky": {"type": "boolean", "description": "Reuse sticky task browser affinity on managed_browser open."},
                    "profile_id": {"type": "string", "description": "Named isolated persistent profile ID (optional isolated mode only; never owner Chrome User Data)."},
                    "profile_name": {"type": "string", "description": "Alias for profile_id on optional isolated managed_browser/private_browser open."},
                    "persistent_profile": {"type": "boolean", "description": "Persist optional isolated profile across browser restarts."},
                    "action": {"type": "string", "description": "DOM action (click, fill, select, check, uncheck, press)."},
                    "operation": {"type": "string", "description": "DOM operation alias (fill, click, select, check, uncheck, press) for owner_chrome_hidden/private_browser act."},
                    "selector": {"type": "string", "description": "CSS selector for owner_chrome_hidden read/act."},
                    "ref": {"type": "string", "description": "Snapshot element ref for observe/act."},
                    "snapshot": {"type": "string", "description": "Snapshot token from observe."},
                    "target": {"type": "object", "additionalProperties": True, "description": "Element locator or permission target object."},
                    "value": {"description": "Action value for fill/select."},
                    "key": {"type": "string", "description": "Key name for background DOM press action (e.g. Enter, Escape, Tab)."},
                    "condition": {"type": "object", "additionalProperties": True, "description": "Observable condition object for browser/owner_chrome_hidden wait_for."},
                    "postcondition": {"type": "object", "additionalProperties": True, "description": "Observable postcondition for browser/app act."},
                    "timeout_ms": {"type": "number", "description": "Bounded operation timeout in milliseconds for navigate/reload/act/wait_for."},
                    "ignore_cache": {"type": "boolean", "description": "Optional cache-bypass flag for owner_chrome_hidden reload."},
                    "app": {"type": "string", "description": "Catalog app ID, alias or path for app_discover/app_open."},
                    "app_id": {"type": "string", "description": "Owned private desktop app identifier."},
                    "hwnd": {"type": "integer", "description": "Owned window handle on the private desktop."},
                    "path": {"type": "string", "description": "Absolute filesystem path for files operations."},
                    "text": {"type": "string", "description": "UTF-8 file content for files write."},
                    "expected_sha256": {"type": ["string", "null"], "description": "Current SHA-256 precondition (or null to create new file)."},
                    "argv": {"type": "array", "items": {"type": "string"}, "description": "Command argv list (shell=false) for terminal start."},
                    "cwd": {"type": "string", "description": "Absolute working directory for terminal start."},
                    "timeout_seconds": {"type": "number", "description": "Timeout in seconds (0.1..300) for terminal start."},
                    "terminal_id": {"type": "string", "description": "Owned terminal job ID for status/cancel."},
                    "kind": {"type": "string", "description": "Resource lock kind for resource_claim/resource_release/resource_list."},
                    "key": {"type": "string", "description": "Resource lock key for resource_claim/resource_release."},
                    "mode": {"type": "string", "enum": ["exclusive", "shared"], "description": "Lock mode for resource_claim."},
                    "wait_seconds": {"type": "number", "description": "Lock wait timeout (0..60s) for resource_claim."},
                    "resource_id": {"type": "string", "description": "Exact resource_id for resource_release."},
                    "risk_class": {"type": "string", "description": "Risk class name for permission_check."},
                    "request_key": {"type": "string", "description": "Exact request_key to inspect via request_status."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "Max records for audit_read."},
                    "note": {"type": "string", "description": "Optional short task note on session_open."},
                    "resume_token": {"type": "string", "description": "Explicit resume_token required to take over a checkpoint owned by another live process."},
                },
                "additionalProperties": True,
            },
        },
        "required": ["op"],
        "additionalProperties": False,
    },
}

_LIVE_INSTANCES_LOCK = threading.Lock()
_LIVE_INSTANCES: set[str] = set()


@contextmanager
def credential_lock(path: Path, *, timeout: float = 190.0):
    """Serialize session bootstrap and per-task calls between MCP processes sharing one task."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            # Windows byte-range locks are mandatory for ReadFile/WriteFile and
            # permit locking beyond EOF. Lock byte 0 BEFORE any I/O so competing
            # processes wait cleanly instead of hitting WinError 33 (EACCES).
            deadline = time.monotonic() + max(0.1, float(timeout))
            while True:
                try:
                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise HubError("MCP_TASK_BUSY", execution_started=False, retry_safe=True) from None
                    time.sleep(0.05)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def public_result(value):
    if isinstance(value, dict):
        return {key: public_result(item) for key, item in value.items()
                if key not in _PRIVATE_RESULT_KEYS}
    if isinstance(value, list):
        return [public_result(item) for item in value]
    return value


class Adapter:
    def __init__(self, state: Path, agent: str, *, client=None, start_if_stopped=False,
                 heartbeat_seconds: float = 0.0):
        self.state, self.agent = Path(state), _ident(agent, "agent_id")
        self.client = client or HubClient(self.state)
        self.start_if_stopped = start_if_stopped
        self.checkpoints = self.state / "clients" / hashlib.sha256(agent.encode()).hexdigest()[:24]
        self.instance_id = uuid.uuid4().hex
        self._pid = os.getpid()
        self._create_time = process_creation_token(self._pid) if os.name == "nt" else None
        self._heartbeat_seconds = max(0.0, float(heartbeat_seconds or 0.0))
        self._active_lock = threading.Lock()
        self._active_sessions: dict[str, dict] = {}
        self._hb_stop = threading.Event()
        self._hb_thread: threading.Thread | None = None
        with _LIVE_INSTANCES_LOCK:
            _LIVE_INSTANCES.add(self.instance_id)
        if self._heartbeat_seconds > 0:
            self._hb_thread = threading.Thread(target=self._heartbeat_loop, daemon=True, name="hub-mcp-hb")
            self._hb_thread.start()

    def close(self) -> None:
        """Mark this MCP adapter instance closed (does NOT close durable Hub sessions)."""
        self._hb_stop.set()
        if self._hb_thread is not None and self._hb_thread.is_alive():
            self._hb_thread.join(timeout=2.0)
        with _LIVE_INSTANCES_LOCK:
            _LIVE_INSTANCES.discard(self.instance_id)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _owner_identity(self) -> dict:
        return {"pid": self._pid, "create_time": self._create_time, "instance_id": self.instance_id}

    def _is_owned_by_other_live(self, session: dict) -> dict | None:
        owner = session.get("_mcp_owner")
        if not isinstance(owner, dict):
            return None
        opid = owner.get("pid")
        octime = owner.get("create_time")
        oinst = owner.get("instance_id")
        if oinst == self.instance_id and opid == self._pid:
            return None
        if type(opid) is not int or opid <= 0:
            return None
        same_process = opid == self._pid and (os.name != "nt" or octime == self._create_time)
        if same_process:
            with _LIVE_INSTANCES_LOCK:
                if isinstance(oinst, str) and oinst in _LIVE_INSTANCES:
                    return owner
            return None
        alive = (
            process_identity_matches(opid, octime)
            if (os.name == "nt" and type(octime) is int)
            else _pid_alive(opid)
        )
        return owner if alive else None

    def _heartbeat_loop(self) -> None:
        while not self._hb_stop.wait(self._heartbeat_seconds):
            with self._active_lock:
                items = list(self._active_sessions.items())
            for task, sess in items:
                try:
                    self._send("session_heartbeat", {}, session=sess)
                except (HubError, OSError):
                    with self._active_lock:
                        if self._active_sessions.get(task) is sess:
                            self._active_sessions.pop(task, None)

    def _track_session(self, task: str, session: dict | None) -> None:
        with self._active_lock:
            if session is None:
                self._active_sessions.pop(task, None)
            else:
                self._active_sessions[task] = session

    def _send(self, op, args=None, session=None, key=None):
        if self.start_if_stopped:
            # Owner opt-in only. Neither MCP arguments nor an RPC can create it.
            try:
                flag = json.loads((self.state.parent / "universal-agent-runtime.json").read_text(encoding="utf-8"))
            except (ValueError, OSError):
                flag = None
            if (not isinstance(flag, dict) or type(flag.get("version")) is not int
                    or flag.get("version") != 1 or flag.get("enabled") is not True):
                raise HubError("HUB_FEATURE_DISABLED", execution_started=False)
            ensure_running(self.state)
        request = {"op": op, "args": args or {}}
        if session:
            request.update(session_id=session["session_id"], session_secret=session["session_secret"])
        if key is not None:
            request["request_key"] = key
        try:
            response = self.client.raw(request)
        except HubError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise HubError("HUB_UNREACHABLE", "no valid reply from the Hub; the request may have run",
                           cause=type(exc).__name__, retry_safe=False) from None
        if not isinstance(response, dict) or type(response.get("ok")) is not bool:
            raise HubError("HUB_REPLY_INVALID", retry_safe=False, automatic_replay=False)
        if response["ok"]:
            if not isinstance(response.get("result"), dict):
                raise HubError("HUB_REPLY_INVALID", retry_safe=False, automatic_replay=False)
            return response["result"]
        details = response.get("details")
        if details is None:
            details = {}
        if not isinstance(details, dict):
            raise HubError("HUB_REPLY_INVALID", retry_safe=False, automatic_replay=False)
        raise HubError(response.get("error_code") or "HUB_REPLY_INVALID", response.get("message"), **details)

    @staticmethod
    def _save(path: Path, session: dict) -> None:
        atomic_json(path, session)
        if os.name != "nt":
            path.chmod(0o600)

    def _validate_session(self, session: object, task: str) -> dict:
        if (not isinstance(session, dict) or session.get("agent_id") != self.agent or session.get("task_id") != task
                or not all(isinstance(session.get(field), str) and session.get(field)
                           for field in ("session_id", "session_secret", "resume_token"))):
            raise HubError("MCP_CHECKPOINT_INVALID", automatic_replay=False)
        return session

    def _bootstrap(self, path: Path, task: str, session: dict | None, *, resume: bool = False,
                   args: dict | None = None, resume_token: str | None = None) -> dict:
        # Never automatically repeat a credential rotation whose reply or local
        # save was lost. Write durable intent BEFORE the RPC.
        pending = {
            **(session or {}),
            "agent_id": self.agent,
            "task_id": task,
            "_mcp_pending": "session_resume" if resume else "session_open",
            "_mcp_owner": self._owner_identity(),
        }
        self._save(path, pending)
        try:
            payload: dict = {"agent_id": self.agent, "task_id": task}
            if resume:
                payload["resume_token"] = resume_token if resume_token is not None else session["resume_token"]
            else:
                raw_note = (args or {}).get("note")
                if raw_note is not None and not isinstance(raw_note, str):
                    raise HubError("ARGS_INVALID", "note must be a string", field="note", execution_started=False)
                payload["note"] = str(raw_note or "MCP client")[:500]
            result = self._send("session_open", payload)
            self._validate_session(result, task)
            stored = {**result, "_mcp_owner": self._owner_identity()}
            self._save(path, stored)
            self._track_session(task, stored)
            return public_result(stored)
        except HubError as exc:
            if exc.code in {"HUB_FEATURE_DISABLED", "HUB_NOT_RUNNING", "HUB_ENDPOINT_INVALID",
                            "SESSION_ACTIVE_ELSEWHERE", "IDENTITY_INVALID", "RESUME_TOKEN_INVALID",
                            "SESSION_NOTE_INVALID", "ARGS_INVALID", "HUB_STOPPING"}:
                if session:
                    self._save(path, session)
                else:
                    path.unlink(missing_ok=True)
            raise

    def call(self, params: dict) -> dict:
        if not isinstance(params, dict) or set(params) - {"op", "args", "task_id", "request_key"}:
            raise HubError("MCP_ARGUMENTS_INVALID")
        op, args = params.get("op"), params.get("args", {})
        if not isinstance(op, str) or op not in OPS or not isinstance(args, dict):
            raise HubError("MCP_ARGUMENTS_INVALID")
        key = params.get("request_key")
        if "request_key" in params and key is not None and (not isinstance(key, str) or not 8 <= len(key) <= 200):
            raise HubError("REQUEST_KEY_INVALID", execution_started=False)
        if op in PUBLIC:
            send_args = {**args, "agent_id": self.agent} if (op == "route_plan" and "agent_id" not in args) else args
            result = public_result(self._send(op, send_args))
            if op == "capabilities":
                operations = {name: spec for name, spec in result.get("operations", {}).items() if name in OPS}
                operations["session_open"] = {"session": False, "args": {"note": "str?"}}
                operations["session_resume"] = {"session": False, "explicit": True, "credentials": "private checkpoint"}
                result = {
                    **result,
                    "operations": operations,
                    "mcp": {
                        "tool": "hub",
                        "adapter_version": MCP_ADAPTER_VERSION,
                        "agent_id": self.agent,
                        "task_id_location": "arguments.task_id",
                        "credentials": "managed privately; do not pass session credentials in arguments",
                        "checkpoint_ownership": "bound to live MCP process identity; concurrent processes fail closed",
                        "primary_owner_auth_route": "owner_chrome_profile1_hidden_secondary",
                        "optional_isolated_mode": "isolated_hidden_browser",
                        "default_browser_route": "owner_chrome_profile1_hidden_secondary",
                        "owner_chrome_requires_explicit_selection": True,
                        "isolated_substitution_forbidden": True,
                        "silent_playwright_fallback": False,
                        "disconnect": "sessions persist; explicit session_resume rotates credentials",
                        "cancellation": "accepted Hub work finishes in journal; reconcile request_status",
                        "legacy_unkeyed_operations": ["session_close", "resource_release"],
                    },
                    "quickstart": [
                        "hub {op:'route_plan', args:{surface:'browser', capability:'owner_profile_hidden'}} -> primary owner Chrome selected active profile hidden secondary target (owner_chrome_hidden; fail-closed if CDP/selected-profile unavailable; never silently substitutes isolated profile)",
                        "optional isolated mode (no owner auth): managed_browser / private_browser; explicit visible-tab extension mode: browser",
                        "hub {op:'session_open', task_id:'unique-task', args:{}}",
                        "keep task_id on every task call; agent identity and credentials are fixed by this adapter",
                        "use request_key for mutations; request_status uses args.request_key after a lost reply",
                        "on PERMISSION_REQUIRED stop and tell the owner once; never bypass policy",
                        "close only your resources, then session_close with a stable request_key and verify cleanup_verified=true and resources_retained=0",
                        "session_resume is explicit; taking over a live process checkpoint requires its valid resume_token",
                    ],
                }
            return result
        task = _ident(params.get("task_id"), "task_id")
        path = self.checkpoints / (hashlib.sha256(task.encode()).hexdigest() + ".json")
        with credential_lock(path.with_suffix(".lock")):
            try:
                raw_session = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(raw_session, dict) and raw_session.get("_mcp_pending"):
                    raise HubError(
                        "MCP_SESSION_OUTCOME_UNKNOWN",
                        automatic_replay=False,
                        instruction="credential bootstrap was interrupted; preserve this checkpoint for owner reconciliation",
                    )
                session = self._validate_session(raw_session, task)
            except FileNotFoundError:
                session = None
            except (ValueError, OSError):
                raise HubError("MCP_CHECKPOINT_INVALID", automatic_replay=False) from None

            other_owner = self._is_owned_by_other_live(session) if session is not None else None
            if other_owner is not None:
                if op == "session_resume":
                    provided = args.get("resume_token")
                    if not (isinstance(provided, str) and provided and secrets.compare_digest(provided, session["resume_token"])):
                        raise HubError(
                            "CHECKPOINT_OWNED_BY_LIVE_PROCESS",
                            "another live MCP process owns this task checkpoint; provide valid resume_token or use a unique task_id",
                            owner_pid=other_owner.get("pid"),
                            task_id=task,
                            session_active_elsewhere=True,
                            resume_token_required=True,
                            execution_started=False,
                            retry_safe=False,
                        )
                    return self._bootstrap(path, task, session, resume=True, resume_token=provided)
                raise HubError(
                    "CHECKPOINT_OWNED_BY_LIVE_PROCESS",
                    "another live MCP process owns this task checkpoint; use a unique task_id",
                    owner_pid=other_owner.get("pid"),
                    task_id=task,
                    session_active_elsewhere=True,
                    execution_started=False,
                    retry_safe=False,
                )

            if op == "session_open":
                if session is not None:
                    result = self._send("session_status", session=session)
                    if session.get("_mcp_owner") != self._owner_identity():
                        session = {**session, "_mcp_owner": self._owner_identity()}
                        self._save(path, session)
                    self._track_session(task, session)
                    return {**public_result(result), "checkpoint_reused": True}
                return self._bootstrap(path, task, None, args=args)

            if session is None:
                raise HubError("MCP_SESSION_REQUIRED", instruction="session_open with a new unique task_id")

            if op == "session_resume":
                provided = args.get("resume_token")
                if provided is not None and not (isinstance(provided, str) and provided):
                    raise HubError("RESUME_TOKEN_INVALID", execution_started=False)
                return self._bootstrap(path, task, session, resume=True, resume_token=provided)

            # Keep the task's credentials stable until its request finishes.
            # Another process must not rotate them between load and dispatch.
            result = self._send(op, args, session, key)
            if (op in {"session_close", "task_cancel"}
                    and result.get("closed") is True
                    and result.get("cleanup_verified") is True
                    and int(result.get("resources_retained") or 0) == 0):
                self._track_session(task, None)
                path.unlink(missing_ok=True)
            return public_result(result)


def handle(adapter: Adapter, request: dict):
    if (not isinstance(request, dict) or request.get("jsonrpc") != "2.0"
            or not isinstance(request.get("method"), str)
            or ("id" in request and type(request["id"]) not in (int, str))):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    if "id" not in request:
        return None
    response = {"jsonrpc": "2.0", "id": request["id"]}
    method, params = request.get("method"), request.get("params", {})
    if not isinstance(params, dict):
        return {**response, "error": {"code": -32602, "message": "Invalid params"}}
    if method == "initialize":
        version = params.get("protocolVersion")
        if version is not None and not isinstance(version, str):
            return {**response, "error": {"code": -32602, "message": "Invalid initialize params"}}
        if "capabilities" in params and not isinstance(params["capabilities"], dict):
            return {**response, "error": {"code": -32602, "message": "Invalid initialize params"}}
        if "clientInfo" in params:
            info = params["clientInfo"]
            if not isinstance(info, dict) or not all(isinstance(info.get(k), str) for k in ("name", "version")):
                return {**response, "error": {"code": -32602, "message": "Invalid initialize params"}}
        result = {"protocolVersion": version if version in PROTOCOLS else PROTOCOLS[-1],
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "ff-universal-hub", "version": MCP_ADAPTER_VERSION},
                  "instructions": TOOL["description"]}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [TOOL]}
    elif method == "tools/call":
        if params.get("name") != "hub":
            return {**response, "error": {"code": -32602, "message": "Unknown tool"}}
        try:
            value = adapter.call(params.get("arguments", {}))
            result = {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}], "isError": False}
        except (HubError, OSError, ValueError) as exc:
            value = {"error_code": exc.code if isinstance(exc, HubError) else "MCP_TRANSPORT_ERROR",
                     "message": exc.message if isinstance(exc, HubError) else "No transport reply; reconcile request_status before retrying",
                     "details": public_result(exc.details) if isinstance(exc, HubError) else {"automatic_replay": False}}
            result = {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}], "isError": True}
        except Exception:
            # One bad checkpoint/reply must not kill the MCP connection. Never
            # include exception text: it may contain credentials or arguments.
            result = {"content": [{"type": "text", "text": json.dumps({"error_code": "MCP_INTERNAL_ERROR",
                      "details": {"automatic_replay": False}})}], "isError": True}
    else:
        return {**response, "error": {"code": -32601, "message": "Method not found"}}
    return {**response, "result": result}


class Connection:
    """One negotiated stdio connection, independent of durable Hub sessions."""

    def __init__(self, adapter: Adapter):
        self.adapter = adapter
        self.phase = "new"

    def handle(self, request: dict):
        if (not isinstance(request, dict) or request.get("jsonrpc") != "2.0"
                or not isinstance(request.get("method"), str)
                or ("id" in request and type(request["id"]) not in (int, str))):
            return handle(self.adapter, request)
        method = request["method"]
        if "id" not in request:
            if method == "notifications/initialized" and self.phase in {"initialized", "ready"}:
                self.phase = "ready"
            # Cancellation does not undo accepted Hub mutations. They finish in
            # the journal for explicit request_status reconciliation.
            return None
        if method == "ping":
            return handle(self.adapter, request)
        if method == "initialize" and self.phase == "new":
            response = handle(self.adapter, request)
            if "result" in response:
                self.phase = "initialized"
            return response
        if method == "initialize" or self.phase == "new":
            return {"jsonrpc": "2.0", "id": request["id"], "error": {
                "code": -32600, "message": "Initialize once before calling tools"}}
        return handle(self.adapter, request)


def serve_stdio(adapter: Adapter, incoming, outgoing) -> None:
    connection = Connection(adapter)
    writer = threading.Lock()
    pending_lock = threading.Lock()
    pending: set = set()
    slots = threading.BoundedSemaphore(16)
    broken = threading.Event()

    def emit(response) -> None:
        if response is not None and not broken.is_set():
            with writer:
                try:
                    outgoing.write(json.dumps(response, ensure_ascii=False) + "\n")
                    outgoing.flush()
                except (OSError, ValueError):
                    broken.set()

    def work(request: dict) -> None:
        try:
            emit(connection.handle(request))
        finally:
            with pending_lock:
                pending.discard(request["id"])
            slots.release()

    # Keep ping/discovery responsive during a slow Hub call, without an
    # unbounded queue. The checkpoint lock serializes only the same task.
    try:
        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="hub-mcp") as pool:
            while not broken.is_set():
                line = incoming.readline(2 * 1024 * 1024 + 1)
                if not line:
                    break
                try:
                    if len(line) > 2 * 1024 * 1024:
                        while line and not line.endswith(b"\n"):
                            line = incoming.readline(65536)
                        raise ValueError("oversized")
                    raw_text = line.decode("utf-8") if isinstance(line, (bytes, bytearray)) else line
                    request = json.loads(raw_text)
                except (ValueError, UnicodeError, RecursionError):
                    emit({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                    continue
                if (isinstance(request, dict) and request.get("method") == "tools/call"
                        and connection.phase in {"initialized", "ready"}
                        and type(request.get("id")) in (int, str) and request.get("jsonrpc") == "2.0"):
                    with pending_lock:
                        busy = request["id"] in pending or not slots.acquire(blocking=False)
                        if not busy:
                            pending.add(request["id"])
                    if busy:
                        emit({"jsonrpc": "2.0", "id": request["id"], "error": {"code": -32000,
                              "message": "Request already pending or server busy", "data": {"execution_started": False}}})
                    else:
                        pool.submit(work, request)
                else:
                    emit(connection.handle(request))
    finally:
        adapter.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=None)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--start-if-stopped", action="store_true",
                        help="owner opt-in: start this installed Hub version if stopped; requires enabled local feature flag")
    parser.add_argument("--heartbeat-seconds", type=float, default=0.0,
                        help="optional periodic session_heartbeat interval for active tasks owned by this adapter (0 disables)")
    options = parser.parse_args()
    adapter = Adapter(
        options.state_dir or default_state_dir(),
        options.agent,
        start_if_stopped=options.start_if_stopped,
        heartbeat_seconds=options.heartbeat_seconds,
    )
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    serve_stdio(adapter, sys.stdin.buffer, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
