from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import re
import sqlite3
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from pathlib import Path
from typing import Any
try:
    from ff_win_transport_faults import barrier
    from ff_win_evidence import redact
except ImportError:
    from tools.ff_win_transport_faults import barrier
    from tools.ff_win_evidence import redact

ROOT = Path(os.environ.get("FF_BRIDGE_ROOT") or (Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "FF-Windows-Bridge"))
FAST_ROOT = ROOT / "fast-transport"
DB = FAST_ROOT / "transport_journal.sqlite3"
SECRET = ROOT / "bridge-v3" / "secret"
V3_RPC_URL = os.environ.get("FF_V3_RPC_URL", "http://127.0.0.1:39073/rpc")
BACKGROUND_RPC_URL = os.environ.get("FF_V3_BACKGROUND_RPC_URL", "")
_rpc_target = urlsplit(V3_RPC_URL)
if _rpc_target.scheme != "http" or _rpc_target.hostname not in {"127.0.0.1", "localhost", "::1"} or _rpc_target.path != "/rpc" or _rpc_target.username:
    raise ValueError("V3_RPC_MUST_BE_LOCAL_LOOPBACK")
if BACKGROUND_RPC_URL:
    _background_target = urlsplit(BACKGROUND_RPC_URL)
    if _background_target.scheme != "http" or _background_target.hostname not in {"127.0.0.1", "localhost", "::1"} or _background_target.path != "/rpc" or _background_target.username:
        raise ValueError("BACKGROUND_RPC_MUST_BE_LOCAL_LOOPBACK")
try:
    MAX_RESULT_BYTES = min(max(int(os.environ.get("FF_TRANSPORT_MAX_RESULT_BYTES", "48000")), 48_000), 8 * 1024 * 1024)
except ValueError:
    MAX_RESULT_BYTES = 48_000

SAFE_EXACT = {
    "ping", "capabilities", "device_info", "get_config", "read_file", "stat",
    "hash_file", "screenshot", "gui_screenshot", "gui_cursor", "window_state", "uia_read", "read_process_output",
    "list_file_streams", "visual_status", "visual_latest", "list_processes",
    "list_directory", "get_file_info", "list_sessions", "list_searches",
    "get_recent_tool_calls", "list_windows", "gui_list_windows",
}
SAFE_PREFIXES = ("get_", "list_", "read_", "find_", "search_", "inspect_", "status_")
BACKGROUND_AUTO_OPS = {"ping", "capabilities", "device_info", "get_config", "read_file", "read_multiple_files",
                      "write_file", "create_directory", "list_directory", "move_file", "get_file_info",
                      "search_files", "search_code", "edit_block", "list_processes"}


class TransportCoreError(RuntimeError):
    pass

class InteractiveSessionRequired(TransportCoreError):
    pass

RESULT_RETENTION_SECONDS = 7 * 86400
MAX_JOURNAL_KEYS = 100000
MAX_JOURNAL_RESPONSE_BYTES = 64 * 1024 * 1024

def _prune_journal(con):
    con.execute("UPDATE tasks SET state='expired',response=NULL WHERE state='done' AND updated<?", (time.time()-RESULT_RETENTION_SECONDS,))
    size = con.execute("SELECT coalesce(sum(length(CAST(response AS BLOB))),0) FROM tasks").fetchone()[0]
    while size > MAX_JOURNAL_RESPONSE_BYTES:
        row = con.execute("SELECT k,length(CAST(response AS BLOB)) FROM tasks WHERE state='done' ORDER BY updated LIMIT 1").fetchone()
        if not row: break
        con.execute("UPDATE tasks SET state='expired',response=NULL WHERE k=?", (row[0],))
        size -= row[1]


class RpcFailure(TransportCoreError):
    """Stage is assigned by our RPC boundary, never parsed from exception text."""
    def __init__(self, stage: str, cause: Exception):
        super().__init__("RPC_" + stage.upper() + ":" + type(cause).__name__)
        self.stage, self.cause = stage, cause


class _NoRpcRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # POST may already have taken effect. Never resend it, change it to GET,
        # or disclose X-FF3-Key to a Location supplied by a response.
        raise RpcFailure("response", TransportCoreError("RPC_REDIRECT_FORBIDDEN"))


_RPC_OPENER = urllib.request.build_opener(_NoRpcRedirect())


def _rpc_urlopen(request, timeout):
    # Explicit RPC-only injection seam. Production always uses this private
    # opener; test/environment detection must never bypass its redirect policy.
    return _RPC_OPENER.open(request, timeout=timeout)


def _open_rpc(request, timeout):
    try:
        response = _rpc_urlopen(request, timeout)
    except RpcFailure:
        raise
    except urllib.error.HTTPError as exc:
        # HTTP status errors are delivered, known responses when their body is valid.
        response = exc
    except Exception as exc:
        raise RpcFailure("connect", exc) from exc
    try:
        with response:
            status = getattr(response, "status", None) or response.code
            if 300 <= status < 400:
                raise RpcFailure("response", TransportCoreError("RPC_REDIRECT_FORBIDDEN"))
            return status, response.read(MAX_RESULT_BYTES + 1)
    except RpcFailure:
        raise
    except Exception as exc:
        raise RpcFailure("read", exc) from exc


def is_safe(op: Any) -> bool:
    value = str(op or "").strip().lower()
    return value in SAFE_EXACT


def _secret() -> str:
    value = SECRET.read_text(encoding="ascii").strip()
    if len(value) < 32:
        raise TransportCoreError("BRIDGE_SECRET_INVALID")
    return value


def _db() -> sqlite3.Connection:
    FAST_ROOT.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB, timeout=10, isolation_level=None)
    try:
        deadline = time.monotonic() + 10
        while True:
            try:
                cursor = con.execute("PRAGMA journal_mode")
                mode = cursor.fetchone()[0]
                cursor.close()
                if mode != "wal":
                    cursor = con.execute("PRAGMA journal_mode=WAL")
                    cursor.fetchone(); cursor.close()
                break
            except sqlite3.OperationalError as exc:
                # WAL-mode switching can return SQLITE_BUSY without honouring the
                # connection busy timeout. Only initial metadata acquisition retries.
                # Never retry dispatch/effects; each thread/process still journals.
                if getattr(exc, "sqlite_errorcode", None) not in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED} or time.monotonic() >= deadline:
                    raise
                time.sleep(.01)
        con.execute("PRAGMA synchronous=FULL")
        con.execute("BEGIN IMMEDIATE")
        con.execute(
            "CREATE TABLE IF NOT EXISTS tasks ("
            "k TEXT PRIMARY KEY, digest TEXT NOT NULL, op TEXT NOT NULL, "
            "state TEXT NOT NULL, status INTEGER, response TEXT, updated REAL NOT NULL, "
            "owner_pid INTEGER)"
        )
        columns = {str(row[1]) for row in con.execute("PRAGMA table_info(tasks)")}
        if "owner_pid" not in columns:
            con.execute("ALTER TABLE tasks ADD COLUMN owner_pid INTEGER")
        if "owner_birth" not in columns:
            con.execute("ALTER TABLE tasks ADD COLUMN owner_birth TEXT")
        # Older fallback workers update owner_pid without owner_birth. Never
        # mistake the stale birth from a previous owner for their identity.
        con.execute("CREATE TRIGGER IF NOT EXISTS clear_legacy_owner_birth AFTER UPDATE OF owner_pid ON tasks "
                    "WHEN NEW.owner_pid != OLD.owner_pid AND NEW.owner_birth IS OLD.owner_birth "
                    "BEGIN UPDATE tasks SET owner_birth=NULL WHERE k=NEW.k; END")
        con.execute("COMMIT")
    except BaseException:
        con.close()
        raise
    return con


def _pid_alive(pid: Any) -> bool:
    try:
        value = int(pid)
    except (TypeError, ValueError):
        return False
    if value <= 0:
        return False
    if value == os.getpid():
        return True
    if os.name == "nt":
        process_query_limited_information = 0x1000
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        handle = kernel.OpenProcess(
            process_query_limited_information, False, value
        )
        if not handle:
            return ctypes.get_last_error() == 5  # access denied is not proof of death
        try:
            code = ctypes.c_ulong()
            return not kernel.GetExitCodeProcess(handle, ctypes.byref(code)) or code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(value, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _pid_birth(pid: int) -> str | None:
    if os.name != "nt":
        try:
            return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[19]
        except OSError:
            return None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel.GetProcessTimes.argtypes = [ctypes.c_void_p] + [ctypes.c_void_p] * 4
    handle = kernel.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return None
    try:
        values = [ctypes.c_ulonglong() for _ in range(4)]
        if kernel.GetProcessTimes(handle, *(ctypes.byref(x) for x in values)):
            return str(values[0].value)
        return None
    finally:
        kernel.CloseHandle(handle)


def _owner_alive(pid, birth) -> bool:
    if not _pid_alive(pid):
        return False
    actual = _pid_birth(int(pid))
    return birth is None or actual is None or actual == birth


def _digest(task: dict[str, Any]) -> str:
    stable = {
        "op": task["op"],
        "args": task.get("args") or {},
        "allow_foreground": bool(task.get("allow_foreground", False)),
    }
    if task.get("execution_context"):
        stable["execution_context"] = task["execution_context"]
    raw = json.dumps(stable, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _key(task: dict[str, Any]) -> str:
    return f"{task['client_id']}::{task['task_id']}"


def journal_begin(task: dict[str, Any]) -> tuple[str, Any]:
    if is_safe(task["op"]):
        return "execute", None

    key, digest = _key(task), _digest(task)
    con = _db()
    try:
        con.execute("BEGIN IMMEDIATE")
        _prune_journal(con)
        row = con.execute(
            "SELECT digest,state,status,response,updated,owner_pid,owner_birth FROM tasks WHERE k=?", (key,)
        ).fetchone()
        if row:
            if row[0] != digest:
                return "conflict", None
            state = row[1]
            if state == "done":
                con.execute("COMMIT")
                return "cached", (row[2], json.loads(row[3]))
            if state == "expired":
                con.execute("COMMIT")
                return "expired", None
            if state == "claimed":
                age = time.time() - float(row[4] or 0)
                owner_pid = row[5]
                if owner_pid is not None and not _owner_alive(owner_pid, row[6]):
                    con.execute(
                        "UPDATE tasks SET owner_pid=?,owner_birth=?,updated=? WHERE k=?",
                        (os.getpid(), _pid_birth(os.getpid()), time.time(), key),
                    )
                    con.execute("COMMIT")
                    return "execute", None
                if owner_pid is None and age > 30:
                    con.execute(
                        "UPDATE tasks SET owner_pid=?,owner_birth=?,updated=? WHERE k=?",
                        (os.getpid(), _pid_birth(os.getpid()), time.time(), key),
                    )
                    con.execute("COMMIT")
                    return "execute", None
                return "in_progress", None
            if state in {"dispatching", "processing"}:
                owner_pid = row[5]
                if owner_pid is not None and _owner_alive(owner_pid, row[6]):
                    return "in_progress", None
                return "uncertain", None
            if state == "uncertain":
                return "uncertain", None
            if state == "retryable":
                con.execute(
                    "UPDATE tasks SET state=?,owner_pid=?,owner_birth=?,updated=? WHERE k=?",
                    ("claimed", os.getpid(), _pid_birth(os.getpid()), time.time(), key),
                )
                con.execute("COMMIT")
                return "execute", None
            return "uncertain", None

        if con.execute("SELECT count(*) FROM tasks").fetchone()[0] >= MAX_JOURNAL_KEYS:
            con.execute("COMMIT")
            return "capacity", None
        con.execute(
            "INSERT INTO tasks(k,digest,op,state,updated,owner_pid,owner_birth) VALUES(?,?,?,?,?,?,?)",
            (key, digest, task["op"], "claimed", time.time(), os.getpid(), _pid_birth(os.getpid())),
        )
        con.execute("COMMIT")
        return "execute", None
    finally:
        try:
            con.execute("ROLLBACK")
        except Exception:
            pass
        con.close()


def journal_mark_dispatching(task: dict[str, Any]) -> None:
    if is_safe(task["op"]):
        return
    con = _db()
    try:
        con.execute(
            "UPDATE tasks SET state=?,owner_pid=?,updated=? WHERE k=?",
            ("dispatching", os.getpid(), time.time(), _key(task)),
        )
    finally:
        con.close()


def journal_finish(
    task: dict[str, Any], status: int, response: dict[str, Any], state: str = "done"
) -> None:
    if is_safe(task["op"]):
        return
    con = _db()
    try:
        con.execute("BEGIN IMMEDIATE")
        con.execute(
            "UPDATE tasks SET state=?,status=?,response=?,updated=? WHERE k=?",
            (
                state,
                status,
                json.dumps(redact(response), ensure_ascii=False, separators=(",", ":")),
                time.time(),
                _key(task),
            ),
        )
        _prune_journal(con)
        con.execute("COMMIT")
    finally:
        con.close()


def journal_mark_uncertain(task: dict[str, Any], reason: Exception) -> None:
    payload = {
        "ok": False,
        "error_code": "TASK_OUTCOME_UNKNOWN",
        "message": str(reason)[:500],
    }
    journal_finish(task, 599, payload, state="uncertain")


def _rpc(task: dict[str, Any], timeout: float) -> tuple[int, dict[str, Any]]:
    background = bool(BACKGROUND_RPC_URL and task.get("execution_context") == "background")
    rpc_args = dict(task.get("args") or {})
    if str(task["op"]).strip().lower() == "gui_screenshot":
        rpc_args.setdefault("compact", True)
        rpc_args.setdefault("max_width", 640)
        rpc_args.setdefault("quality", 30)
        rpc_args.setdefault("max_base64_len", 34000)
        rpc_args.setdefault("save_local", False)
    payload = {
        "op": task["op"],
        "args": rpc_args,
        "client_id": task["client_id"],
        "task_id": task["task_id"],
        "allow_foreground": bool(task.get("allow_foreground", False)),
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        BACKGROUND_RPC_URL if background else V3_RPC_URL,
        data=raw,
        headers={"Content-Type": "application/json", "X-FF3-Key": _secret()},
        method="POST",
    )
    try:
        status, body = _open_rpc(request, timeout)
    except RpcFailure as exc:
        if not BACKGROUND_RPC_URL or background or not _definitely_not_delivered(exc):
            raise
        op = str(task["op"]).lower()
        if task.get("allow_foreground") or task.get("execution_context") == "interactive" or op not in BACKGROUND_AUTO_OPS:
            raise InteractiveSessionRequired("INTERACTIVE_SESSION_REQUIRED") from exc
        fallback = urllib.request.Request(BACKGROUND_RPC_URL, data=raw, headers={"Content-Type":"application/json","X-FF3-Key":_secret()}, method="POST")
        status, body = _open_rpc(fallback, timeout)
        background = True

    if len(body) > MAX_RESULT_BYTES:
        raise TransportCoreError("RESULT_TOO_LARGE")
    result = json.loads(body.decode("utf-8"))
    if not isinstance(result, dict):
        raise TransportCoreError("RESULT_NOT_OBJECT")
    if background:
        result["execution_context"] = "background"
    return status, result


def _definitely_not_delivered(exc: Exception) -> bool:
    if isinstance(exc, RpcFailure):
        if exc.stage != "connect":
            return False
        exc = exc.cause
    # Only an actual network refusal proves that no connection accepted bytes.
    # Timeouts (including WSAETIMEDOUT=10060), reset, JSON offsets and arbitrary
    # error messages never prove nondelivery.
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    return isinstance(reason, OSError) and (
        getattr(reason, "winerror", None) == 10061
        or getattr(reason, "errno", None) in {errno.ECONNREFUSED, 10061}
    )


def execute_task(task: dict[str, Any]) -> tuple[int, dict[str, Any], dict[str, Any]]:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", str(task.get("client_id", ""))):
        return 400, {"ok":False,"error_code":"CLIENT_ID_INVALID"}, {"route":"validation"}
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", str(task.get("task_id", ""))):
        return 400, {"ok":False,"error_code":"TASK_ID_INVALID"}, {"route":"validation"}
    action, cached = journal_begin(task)
    if action == "cached":
        status, result = cached
        return status, result, {"route": "journal-cache", "deduplicated": True}
    if action == "conflict":
        return 409, {"ok": False, "error_code": "TASK_ID_PAYLOAD_CONFLICT"}, {"route": "journal"}
    if action == "in_progress":
        return 409, {"ok": False, "error_code": "TASK_IN_PROGRESS"}, {"route": "journal"}
    if action == "uncertain":
        return 409, {"ok": False, "error_code": "TASK_OUTCOME_UNKNOWN"}, {"route": "journal"}
    if action in {"expired", "capacity"}:
        return 409, {"ok": False, "error_code": "TASK_OUTCOME_EXPIRED" if action == "expired" else "TASK_JOURNAL_CAPACITY_EXHAUSTED", "retry_safe": False}, {"route": "journal"}

    safe = is_safe(task["op"])
    timeout = max(0.5, min(float(task.get("timeout_seconds", 60)), 300.0))

    if safe:
        try:
            status, result = _rpc(task, timeout)
            return status, result, {"route": "v3", "deduplicated": False}
        except InteractiveSessionRequired:
            return 503, {"ok":False,"error_code":"INTERACTIVE_SESSION_REQUIRED"}, {"route":"v3","definitely_not_executed":True}
        except TransportCoreError as exc:
            if str(exc) == "RESULT_TOO_LARGE":
                return (
                    413,
                    {
                        "ok": False,
                        "error_code": "RESULT_TOO_LARGE",
                        "message": "V3 completed the read-only operation, but its response exceeded the Fast transport inline limit.",
                    },
                    {"route": "v3", "response_too_large": True},
                )
            raise
        except Exception as first:
            time.sleep(0.25)
            try:
                status, result = _rpc(task, timeout)
                return status, result, {
                    "route": "v3-retry",
                    "recovered": True,
                    "cause": type(first).__name__,
                }
            except TransportCoreError as second:
                if str(second) == "RESULT_TOO_LARGE":
                    return (
                        413,
                        {
                            "ok": False,
                            "error_code": "RESULT_TOO_LARGE",
                            "message": "V3 completed the read-only operation, but its response exceeded the Fast transport inline limit.",
                        },
                        {"route": "v3-retry", "response_too_large": True},
                    )
                raise
            except Exception as second:
                raise TransportCoreError(
                    f"V3_UNAVAILABLE:{type(first).__name__}:{type(second).__name__}"
                ) from second

    phase = "journal"
    try:
        # After dispatching is durable, an ambiguous failure must never be retried
        # automatically because the mutation may already have happened.
        barrier("before_dispatching", task)
        journal_mark_dispatching(task)
        barrier("after_dispatching_before_rpc", task)
        phase = "rpc"
        status, result = _rpc(task, timeout)
        phase = "persist"
        barrier("after_rpc", task)
        journal_finish(task, status, result)
        phase = "publication"
        barrier("after_done_before_publication", task)
        return status, result, {"route": "v3", "deduplicated": False}
    except Exception as exc:
        if phase == "publication":
            # Outcome was durably committed. A publication failure must not
            # overwrite the cache with uncertainty or permit another effect.
            return status, result, {"route": "journal-cache", "publication_failed": True}
        if phase == "rpc" and isinstance(exc, InteractiveSessionRequired):
            payload = {"ok":False,"error_code":"INTERACTIVE_SESSION_REQUIRED"}
            journal_finish(task,503,payload,state="retryable")
            return 503,payload,{"route":"v3","definitely_not_executed":True}
        if phase == "rpc" and _definitely_not_delivered(exc):
            payload = {"ok": False, "error_code": "REQUEST_NOT_DELIVERED"}
            journal_finish(task, 503, payload, state="retryable")
            return 503, payload, {"route": "v3", "definitely_not_executed": True}
        journal_mark_uncertain(task, exc)
        barrier("after_uncertain", task)
        return (
            599,
            {"ok": False, "error_code": "TASK_OUTCOME_UNKNOWN"},
            {"route": "v3", "automatic_retry_blocked": True},
        )
