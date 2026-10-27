from __future__ import annotations

import argparse
import ast
import base64
import ctypes
import ctypes.wintypes
import difflib
import hashlib
import http.server
import json
import os
import platform
import queue
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from collections import deque
from pathlib import Path
from typing import Any

from ff_win_process_identity import ProcessReference, process_creation_token, process_identity_matches

PROTOCOL_VERSION = 1
HOST = "127.0.0.1"
PORT = 39073
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_INLINE_BYTES = 2 * 1024 * 1024
SESSION_BUFFER_CHARS = 2 * 1024 * 1024
DEFAULT_AUDIT_MAX_BYTES = 10 * 1024 * 1024

BRIDGE_ROOT = Path(os.environ.get("FF_BRIDGE_ROOT") or (Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "FF-Windows-Bridge"))
V3_ROOT = BRIDGE_ROOT / "bridge-v3"
SECRET_PATH = V3_ROOT / "secret"
CONFIG_PATH = V3_ROOT / "config.json"
AUDIT_PATH = V3_ROOT / "audit.jsonl"
PID_PATH = V3_ROOT / "agent.pid"

LEGACY_BROAD_BLOCKLIST = ["format", "diskpart", "shutdown", "reboot", "bcdedit", "cipher", "takeown"]

DEFAULT_CONFIG: dict[str, Any] = {
    "allowedDirectories": [],
    "blockedCommands": ["mkfs", "format", "fdisk", "dd", "parted", "diskpart", "bcdedit", "cipher"],
    "defaultShell": "powershell.exe",
    "allowedShells": ["powershell.exe", "pwsh.exe", "cmd.exe"],
    "fileReadLineLimit": 2000,
    "fileWriteLineLimit": 5000,
    "auditEnabled": True,
    "auditMaxBytes": DEFAULT_AUDIT_MAX_BYTES,
    "urlReadEnabled": True,
}

SENSITIVE_KEY_PARTS = (
    "token", "secret", "password", "passwd", "cookie", "authorization",
    "api_key", "apikey", "private_key", "credential",
)


class RPCError(RuntimeError):
    def __init__(self, code: str, message: str | None = None, details: Any = None):
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.details = details


def now_ms() -> int:
    return int(time.time() * 1000)


def self_sha256() -> str:
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    except Exception:
        return "unknown"


BUILD_SHA256 = self_sha256()


def ensure_dirs() -> None:
    V3_ROOT.mkdir(parents=True, exist_ok=True)


def atomic_write_text(path: Path, text: str, encoding: str = "utf-8") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding=encoding, newline="")
    os.replace(tmp, path)


def load_or_create_secret() -> str:
    ensure_dirs()
    if SECRET_PATH.is_file():
        value = SECRET_PATH.read_text(encoding="ascii").strip()
        if len(value) >= 32:
            return value
    value = secrets.token_urlsafe(48)
    atomic_write_text(SECRET_PATH, value + "\n", "ascii")
    try:
        os.chmod(SECRET_PATH, 0o600)
    except Exception:
        pass
    return value


def load_config() -> dict[str, Any]:
    ensure_dirs()
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_PATH.is_file():
        try:
            raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
            if isinstance(raw, dict):
                cfg.update(raw)
                if cfg.get("blockedCommands") == LEGACY_BROAD_BLOCKLIST:
                    cfg["blockedCommands"] = list(DEFAULT_CONFIG["blockedCommands"])
        except Exception:
            pass
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    atomic_write_text(CONFIG_PATH, json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")


_SENSITIVE_NAME_RE = r"(?:token|secret|password|passwd|cookie|authorization|api[_-]?key|apikey|private[_-]?key|credential)"
_SENSITIVE_VALUE_RE = r'''(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&]+)'''
_SENSITIVE_STRING_PATTERNS = (
    re.compile(rf"""(?i)(?P<prefix>\bBearer\s+)(?P<value>[A-Za-z0-9._~+/=-]{{8,}})"""),
    re.compile(rf"""(?i)(?P<prefix>--[A-Za-z0-9_.-]*{_SENSITIVE_NAME_RE}[A-Za-z0-9_.-]*(?:=|\s+))(?P<value>{_SENSITIVE_VALUE_RE})"""),
    re.compile(rf"""(?i)(?P<prefix>\$env:[A-Za-z0-9_]*{_SENSITIVE_NAME_RE}[A-Za-z0-9_]*\s*=\s*)(?P<value>{_SENSITIVE_VALUE_RE})"""),
    re.compile(rf"""(?i)(?P<prefix>(?:["']?[A-Za-z0-9_.-]*{_SENSITIVE_NAME_RE}[A-Za-z0-9_.-]*["']?)\s*[:=]\s*)(?P<value>{_SENSITIVE_VALUE_RE})"""),
)


def _redacted_value(raw: str) -> str:
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {"'", '"'}:
        return raw[0] + "<redacted>" + raw[0]
    return "<redacted>"


def redact_string(value: str) -> str:
    text = str(value)
    # Audit strings are capped at 4000 characters anyway. Truncate before
    # running the secret-detection regexes so a very large command result
    # cannot monopolize the interpreter during audit redaction.
    truncated = len(text) > 4000
    if truncated:
        text = text[:4000]
    for pattern in _SENSITIVE_STRING_PATTERNS:
        text = pattern.sub(lambda match: match.group("prefix") + _redacted_value(match.group("value")), text)
    if truncated:
        text += "...<truncated>"
    return text


def redact(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "<depth-limit>"
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if any(part in normalized for part in SENSITIVE_KEY_PARTS):
                out[str(key)] = "<redacted>"
            else:
                out[str(key)] = redact(child, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v, depth + 1) for v in value[:100]]
    if isinstance(value, str):
        return redact_string(value)
    return value


# Serialize rotation and append: concurrent RPC workers must not race the rename.
_AUDIT_LOCK = threading.RLock()


def rotate_audit_if_needed(max_bytes: int) -> bool:
    try:
        if AUDIT_PATH.is_file() and AUDIT_PATH.stat().st_size >= max_bytes:
            old = AUDIT_PATH.with_suffix(".jsonl.1")
            old.unlink(missing_ok=True)
            os.replace(AUDIT_PATH, old)
        return True
    except OSError:
        return False


def audit(op: str, args: dict[str, Any], status: str, duration_ms: int, error: str | None = None) -> str | None:
    """Diagnostic loss must be visible without changing an already known effect."""
    cfg = STATE.config
    if not bool(cfg.get("auditEnabled", True)):
        return None
    try:
        with _AUDIT_LOCK:
            ensure_dirs()
            maximum = int(cfg.get("auditMaxBytes", DEFAULT_AUDIT_MAX_BYTES))
            if maximum <= 0 or not rotate_audit_if_needed(maximum):
                return "AUDIT_UNAVAILABLE"
            record: dict[str, Any] = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "pid": os.getpid(),
                "device": platform.node(),
                "op": op,
                "status": status,
                "duration_ms": duration_ms,
                "args": redact(args),
            }
            if error:
                record["error"] = redact_string(error[:1000])
            with AUDIT_PATH.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        return None
    except (OSError, TypeError, ValueError):
        return "AUDIT_UNAVAILABLE"


def normalize_path(raw: str) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise RPCError("PATH_INVALID")
    expanded = os.path.expandvars(os.path.expanduser(raw))
    return Path(expanded).resolve(strict=False)


def is_subpath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def enforce_allowed(path: Path) -> None:
    allowed = STATE.config.get("allowedDirectories", [])
    if not isinstance(allowed, list):
        raise RPCError("CONFIG_ALLOWED_DIRECTORIES_INVALID")
    if not allowed:
        return
    roots = [normalize_path(str(item)) for item in allowed]
    if not any(path == root or is_subpath(path, root) for root in roots):
        raise RPCError("PATH_NOT_ALLOWED", details={"path": str(path)})


def command_blocked(text: str) -> str | None:
    from cua_task_authority import APPROVED_EFFECT
    if APPROVED_EFFECT.get():
        return None
    # Block only when a protected executable appears in command position.
    # This deliberately allows ordinary admin commands and harmless mentions
    # of words such as "format" inside arguments, source code, or log text.
    return _command_head_blocked(text)


def _blocked_executable(value: str) -> str | None:
    token = str(value or "").strip().strip("'\"")
    if not token:
        return None
    base = Path(token).name.lower()
    for suffix in (".exe", ".com", ".bat", ".cmd"):
        if base.endswith(suffix):
            base = base[:-len(suffix)]
            break
    blocked = STATE.config.get("blockedCommands", [])
    if not isinstance(blocked, list):
        return None
    words = {str(item).strip().lower() for item in blocked if str(item).strip()}
    return base if base in words else None


def _split_command_head(command: str) -> tuple[str, str]:
    text = str(command or "").lstrip()
    if not text:
        return "", ""
    quote = text[0] if text[0] in {"'", '"'} else None
    if quote is not None:
        end = text.find(quote, 1)
        if end < 0:
            return text[1:], ""
        return text[1:end], text[end + 1:].lstrip()
    match = re.match(r"(\S+)(?:\s+|$)", text)
    if not match:
        return text, ""
    return match.group(1), text[match.end():].lstrip()


def _command_head_blocked(command: str) -> str | None:
    # Best-effort guardrail for statically visible command strings. This is
    # intentionally command-position aware; arbitrary source text is not a shell
    # command and may legitimately contain words such as git --pretty=format.
    for segment in re.split(r"(?:&&|\|\||[;|\r\n])", str(command or "")):
        text = segment.strip()
        if not text:
            continue
        token, rest = _split_command_head(text)
        blocked = _blocked_executable(token)
        if blocked:
            return blocked
        base = Path(token).name.lower()
        if base in {"cmd", "cmd.exe"}:
            wrapper = re.match(r"(?i)(?:(?:/d|/s)\s+)*(?:/c|/k)\s+(.+)$", rest)
            if wrapper:
                blocked = _command_head_blocked(wrapper.group(1))
                if blocked:
                    return blocked
        if base in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
            wrapper = re.search(r"(?i)(?:^|\s)-(?:command|c)\s+(.+)$", rest)
            if wrapper:
                nested = wrapper.group(1).strip().strip("'\"")
                blocked = _command_head_blocked(nested)
                if blocked:
                    return blocked
    return None


def _qualified_call_name(func: ast.expr) -> str:
    parts: list[str] = []
    while isinstance(func, ast.Attribute):
        parts.append(func.attr)
        func = func.value
    if isinstance(func, ast.Name):
        parts.append(func.id)
    return ".".join(reversed(parts))


def _python_command_arg(node: ast.Call) -> ast.expr | None:
    if node.args:
        return node.args[0]
    for keyword in node.keywords:
        if keyword.arg in {"args", "command"}:
            return keyword.value
    return None


def _python_code_blocked(code: str) -> str | None:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return None

    command_calls = {
        "os.system",
        "os.popen",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _qualified_call_name(node.func)
        if name not in command_calls:
            continue
        first = _python_command_arg(node)
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            blocked = _command_head_blocked(first.value)
            if blocked:
                return blocked
        elif isinstance(first, (ast.List, ast.Tuple)) and first.elts:
            head = first.elts[0]
            if isinstance(head, ast.Constant) and isinstance(head.value, str):
                blocked = _blocked_executable(head.value)
                if blocked:
                    return blocked
    return None


def code_blocked(language: str, code: str) -> str | None:
    from cua_task_authority import APPROVED_EFFECT
    if APPROVED_EFFECT.get():
        return None
    if language in {"python", "py"}:
        return _python_code_blocked(code)
    return _command_head_blocked(code)


def select_shell(name: str | None) -> str:
    shell = (name or str(STATE.config.get("defaultShell", "powershell.exe"))).strip()
    allowed = [str(x).lower() for x in STATE.config.get("allowedShells", DEFAULT_CONFIG["allowedShells"])]
    base = Path(shell).name.lower()
    if base not in allowed:
        raise RPCError("SHELL_NOT_ALLOWED", details={"shell": shell, "allowed": allowed})
    resolved = shutil.which(shell) or shutil.which(base)
    if not resolved:
        raise RPCError("SHELL_NOT_FOUND", details={"shell": shell})
    return resolved


def shell_argv(command: str, shell: str | None) -> list[str]:
    exe = select_shell(shell)
    base = Path(exe).name.lower()
    if base in {"powershell.exe", "pwsh.exe"}:
        return [exe, "-NoLogo", "-NoProfile", "-Command", command]
    if base == "cmd.exe":
        return [exe, "/d", "/s", "/c", command]
    raise RPCError("SHELL_NOT_SUPPORTED")


def safe_decode(data: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "cp1251", "cp866"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    ]


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", ctypes.wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.wintypes.DWORD),
        ("SchedulingClass", ctypes.wintypes.DWORD),
    ]


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _job_kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = ctypes.wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, ctypes.wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = ctypes.wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = ctypes.wintypes.BOOL
    kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    kernel32.CloseHandle.restype = ctypes.wintypes.BOOL
    return kernel32


def create_kill_on_close_job():
    if os.name != "nt":
        return None
    kernel32 = _job_kernel32()
    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise RPCError("PROCESS_OWNERSHIP_JOB_CREATE_FAILED", details={"winerror": ctypes.get_last_error()})
    info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    ok = kernel32.SetInformationJobObject(handle, JOB_OBJECT_EXTENDED_LIMIT_INFORMATION, ctypes.byref(info), ctypes.sizeof(info))
    if not ok:
        error = ctypes.get_last_error()
        kernel32.CloseHandle(handle)
        raise RPCError("PROCESS_OWNERSHIP_JOB_CONFIG_FAILED", details={"winerror": error})
    return handle


def assign_process_to_job(process: subprocess.Popen[bytes], job_handle) -> None:
    if os.name != "nt":
        return
    if not job_handle:
        raise RPCError("PROCESS_OWNERSHIP_JOB_UNAVAILABLE")
    kernel32 = _job_kernel32()
    if not kernel32.AssignProcessToJobObject(job_handle, ctypes.wintypes.HANDLE(process._handle)):
        raise RPCError("PROCESS_OWNERSHIP_BIND_FAILED", details={"pid": process.pid, "winerror": ctypes.get_last_error()})


def close_job_handle(job_handle) -> None:
    if os.name == "nt" and job_handle:
        _job_kernel32().CloseHandle(job_handle)


try:
    _AGENT_JOB_HANDLE = create_kill_on_close_job()
except RPCError:
    _AGENT_JOB_HANDLE = None


def assign_process_to_agent_job(process: subprocess.Popen[bytes]) -> None:
    assign_process_to_job(process, _AGENT_JOB_HANDLE)


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
        if not h:
            return False
        exit_code = ctypes.wintypes.DWORD()
        ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(exit_code))
        ctypes.windll.kernel32.CloseHandle(h)
        return exit_code.value == 259
    except Exception:
        return False


class DetachedProcessStub:
    def __init__(self, pid: int, creation_token: int):
        self.pid = pid
        self.creation_token = creation_token
        self._reference = ProcessReference(pid, creation_token)
        self.exit_code_known = True
        self.stdin = None
        self.stdout = None
        self.stderr = None

    def poll(self) -> int | None:
        try:
            return self._reference.poll()
        except OSError:
            self.exit_code_known = False
            return -1  # Internal stopped sentinel; never exposed as a real exit.

    def terminate(self):
        self._reference.terminate()

    def wait(self, timeout: float | None = None) -> int:
        start = time.time()
        while self.poll() is None:
            if timeout and time.time() - start > timeout:
                raise subprocess.TimeoutExpired(["detached", str(self.pid)], timeout)
            time.sleep(0.1)
        return self.poll()

    @property
    def returncode(self) -> int | None:
        return self.poll()


DETACHED_STATE_PATH = V3_ROOT / "state" / "detached_sessions.json"


class Session:
    def __init__(
        self,
        process: Any,
        command: str,
        cwd: str,
        shell: str,
        *,
        session_id: str | None = None,
        detached: bool = False,
        pid: int | None = None,
        log_path: Path | None = None,
        created_at: int | None = None,
        owner_scope: tuple[str, str] | None = None,
    ):
        self.id = session_id or uuid.uuid4().hex[:16]
        self.process = process
        self.command = command
        self.cwd = cwd
        self.shell = shell
        self.detached = detached
        self.pid = pid or (getattr(process, "pid", 0) if process else 0)
        self.log_path = log_path
        self.created_at = created_at or now_ms()
        self.owner_scope = owner_scope
        self.closed_at: int | None = None
        self.events: deque[dict[str, Any]] = deque()
        self.next_seq = 1
        self.total_chars = 0
        self.lock = threading.RLock()
        if log_path:
            threading.Thread(target=self._log_tailer, daemon=True).start()
        elif process and getattr(process, "stdout", None):
            self._start_reader(process.stdout, "stdout")
            self._start_reader(process.stderr, "stderr")
            threading.Thread(target=self._waiter, daemon=True).start()

    def is_running(self) -> bool:
        if self.process:
            return self.process.poll() is None
        if self.detached and self.pid > 0:
            return is_pid_alive(self.pid)
        return False

    def poll(self) -> int | None:
        if self.process:
            return self.process.poll()
        if self.detached and self.pid > 0:
            return None if is_pid_alive(self.pid) else 0
        return self.closed_at and 0

    def _log_tailer(self) -> None:
        pos = 0
        while True:
            try:
                if self.log_path and self.log_path.is_file():
                    with open(self.log_path, "rb") as f:
                        f.seek(pos)
                        lines = f.readlines()
                        pos = f.tell()
                        for line in lines:
                            self.append_event("stdout", safe_decode(line))
            except Exception:
                pass
            if not self.is_running():
                try:
                    if self.log_path and self.log_path.is_file():
                        with open(self.log_path, "rb") as f:
                            f.seek(pos)
                            for line in f.readlines():
                                self.append_event("stdout", safe_decode(line))
                except Exception:
                    pass
                self.closed_at = now_ms()
                code = self.poll()
                if not getattr(self.process, "exit_code_known", True):
                    code = "unknown"
                self.append_event("meta", f"<process exited code={code}>\n")
                break
            time.sleep(0.2)

    def _start_reader(self, stream: Any, name: str) -> None:
        if stream is None:
            return
        threading.Thread(target=self._reader, args=(stream, name), daemon=True).start()

    def _reader(self, stream: Any, name: str) -> None:
        while True:
            try:
                chunk = stream.readline()
            except Exception:
                break
            if not chunk:
                break
            self.append_event(name, safe_decode(chunk))

    def _waiter(self) -> None:
        try:
            self.process.wait()
        finally:
            self.closed_at = now_ms()
            self.append_event("meta", f"<process exited code={self.process.returncode}>\n")

    def append_event(self, stream: str, text: str) -> None:
        with self.lock:
            safe_text = redact_string(text)
            event = {"seq": self.next_seq, "stream": stream, "text": safe_text, "ts": now_ms()}
            self.next_seq += 1
            self.events.append(event)
            self.total_chars += len(safe_text)
            while self.events and self.total_chars > SESSION_BUFFER_CHARS:
                old = self.events.popleft()
                self.total_chars -= len(str(old.get("text", "")))

    def snapshot(self, from_seq: int = 1, max_chars: int = 200_000) -> dict[str, Any]:
        with self.lock:
            selected: list[dict[str, Any]] = []
            total = 0
            for event in self.events:
                if int(event["seq"]) < from_seq:
                    continue
                size = len(str(event.get("text", "")))
                if selected and total + size > max_chars:
                    break
                selected.append(event)
                total += size
            exit_code = self.poll()
            known = getattr(self.process, "exit_code_known", True)
            return {
                "session_id": self.id,
                "running": self.is_running(),
                "pid": self.pid,
                "exit_code": exit_code if known else None,
                "exit_code_known": known,
                "created_at": self.created_at,
                "closed_at": self.closed_at,
                "detached": self.detached,
                "process_ownership_model": ("job_at_creation" if hasattr(self.process, "terminate_tree")
                                            else "root_process_only"),
                "events": selected,
                "next_seq": selected[-1]["seq"] + 1 if selected else from_seq,
                "buffer_first_seq": self.events[0]["seq"] if self.events else self.next_seq,
                "buffer_next_seq": self.next_seq,
            }


def detached_log_path(session_id: str, saved_path: Any) -> Path | None:
    """Validate ownership before resolving links; reject reparse points too.

    This is a restore-time check, not an OS sandbox against a concurrent local
    account rewriting files after validation.
    """
    if not isinstance(session_id, str) or not re.fullmatch(r"[0-9a-f]{16}", session_id):
        return None
    if not isinstance(saved_path, (str, Path)):
        return None
    expected = V3_ROOT / "state" / "detached_logs" / f"{session_id}.log"
    try:
        if Path(saved_path).absolute() != expected.absolute():
            return None
        # Do not call resolve() first: it erases the link being checked.
        for path in (V3_ROOT, expected.parent.parent, expected.parent, expected):
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                return None
            if path != expected and not stat.S_ISDIR(info.st_mode):
                return None
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            return None
        return expected
    except (OSError, ValueError, TypeError):
        return None


def save_detached_session(session: Session) -> None:
    # A PID alone is not a durable identity; Windows may recycle it for a
    # different user process. Never write an unbound record.
    token = process_creation_token(session.pid)
    if token is None or session.log_path is None:
        return
    if detached_log_path(session.id, session.log_path) is None:
        return
    try:
        DETACHED_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        current = {}
        if DETACHED_STATE_PATH.is_file():
            try:
                current = json.loads(DETACHED_STATE_PATH.read_text("utf-8"))
            except Exception:
                current = {}
        current[session.id] = {
            "session_id": session.id,
            "pid": session.pid,
            "pid_creation_token": token,
            "command": session.command,
            "cwd": session.cwd,
            "shell": session.shell,
            "log_path": str(session.log_path) if session.log_path else None,
            "created_at": session.created_at,
            "owner_scope": list(session.owner_scope) if session.owner_scope else None,
        }
        atomic_write_text(DETACHED_STATE_PATH, json.dumps(current, indent=2))
    except Exception:
        pass


def recover_detached_sessions() -> dict[str, Session]:
    recovered: dict[str, Session] = {}
    if not DETACHED_STATE_PATH.is_file():
        return recovered
    try:
        raw = json.loads(DETACHED_STATE_PATH.read_text("utf-8"))
    except Exception:
        return recovered
    updated = {}
    if not isinstance(raw, dict):
        return recovered
    for sid, info in raw.items():
        if not isinstance(sid, str) or not re.fullmatch(r"[0-9a-f]{16}", sid):
            continue
        if not isinstance(info, dict):
            continue
        pid, token = info.get("pid"), info.get("pid_creation_token")
        # No migration for legacy PID-only entries: ownership not proven.
        if not process_identity_matches(pid, token):
            continue
        saved_log = info.get("log_path")
        if not isinstance(saved_log, str):
            continue
        expected_log = detached_log_path(sid, saved_log)
        if expected_log is None:
            continue
        try:
            created_at = int(info.get("created_at") or now_ms())
        except (OSError, ValueError, TypeError):
            continue
        try:
            stub = DetachedProcessStub(pid, token)
        except OSError:
            continue
        owner = info.get("owner_scope")
        if not (isinstance(owner, list) and len(owner) == 2 and
                all(isinstance(x, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", x) for x in owner)):
            owner = None  # Legacy/unbound sessions never acquire caller ownership.
        s = Session(
            stub,
            command=str(info.get("command") or ""),
            cwd=str(info.get("cwd") or ""),
            shell=str(info.get("shell") or ""),
            session_id=sid,
            detached=True,
            pid=pid,
            log_path=expected_log,
            created_at=created_at,
            owner_scope=tuple(owner) if owner else None,
        )
        recovered[sid] = s
        updated[sid] = info
    try:
        atomic_write_text(DETACHED_STATE_PATH, json.dumps(updated, indent=2))
    except Exception:
        pass
    return recovered


class State:
    def __init__(self) -> None:
        self.started_at = now_ms()
        self.config = load_config()
        self.secret = load_or_create_secret()
        self.sessions: dict[str, Session] = recover_detached_sessions()
        self.lock = threading.RLock()
        self.server: http.server.ThreadingHTTPServer | None = None


STATE = State()


def get_session(session_id: str) -> Session:
    with STATE.lock:
        session = STATE.sessions.get(session_id)
    if not session:
        raise RPCError("SESSION_NOT_FOUND", details={"session_id": session_id})
    return session


def op_ping(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "ok": True,
        "protocol_version": PROTOCOL_VERSION,
        "agent_sha256": BUILD_SHA256,
        "pid": os.getpid(),
        "device": platform.node(),
        "uptime_seconds": max(0, (now_ms() - STATE.started_at) // 1000),
        "session_count": len(STATE.sessions),
    }


def op_capabilities(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "agent_sha256": BUILD_SHA256,
        "device": platform.node(),
        "operations": sorted(OPS),
        "features": {
            "persistent_terminal_sessions": True,
            "interactive_process_input": True,
            "incremental_process_output": True,
            "detached_process_survival": True,
            "filesystem_read_write_move_search": True,
            "code_search": True,
            "surgical_edit": True,
            "dynamic_config": True,
            "audit_log_rotation": True,
            "url_read": True,
            "run_code_in_memory": True,
            "device_target_guard": True,
            "gui_bridge_compatibility": True,
        },
    }


def op_device_info(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "device": platform.node(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "user": os.environ.get("USERNAME") or os.environ.get("USER"),
        "pid": os.getpid(),
        "bridge_root": str(BRIDGE_ROOT),
        "v3_root": str(V3_ROOT),
        "agent_sha256": BUILD_SHA256,
    }


def op_get_config(args: dict[str, Any]) -> dict[str, Any]:
    return redact(dict(STATE.config))


def op_set_config_value(args: dict[str, Any]) -> dict[str, Any]:
    key = args.get("key")
    if not isinstance(key, str) or key not in DEFAULT_CONFIG:
        raise RPCError("CONFIG_KEY_INVALID", details={"allowed": sorted(DEFAULT_CONFIG)})
    value = args.get("value")
    cfg = dict(STATE.config)
    if key in {"allowedDirectories", "blockedCommands", "allowedShells"}:
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise RPCError("CONFIG_VALUE_INVALID")
    elif key in {"fileReadLineLimit", "fileWriteLineLimit", "auditMaxBytes"}:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise RPCError("CONFIG_VALUE_INVALID")
    elif key in {"auditEnabled", "urlReadEnabled"}:
        if not isinstance(value, bool):
            raise RPCError("CONFIG_VALUE_INVALID")
    elif key == "defaultShell":
        if not isinstance(value, str):
            raise RPCError("CONFIG_VALUE_INVALID")
        _ = select_shell(value)
    cfg[key] = value
    STATE.config = cfg
    save_config(cfg)
    return {"ok": True, "key": key, "value": redact(value)}


def op_start_process(args: dict[str, Any]) -> dict[str, Any]:
    from cua_task_authority import identity, AuthorityError
    owner_scope = None
    if "agent_id" in args or "task_id" in args:
        try:
            owner_scope = (identity(args.get("agent_id")), identity(args.get("task_id")))
        except AuthorityError as exc:
            raise RPCError(str(exc), details={"execution_started": False}) from exc
    command = args.get("command")
    if not isinstance(command, str) or not command.strip():
        raise RPCError("COMMAND_INVALID")
    blocked = command_blocked(command)
    if blocked:
        raise RPCError("COMMAND_BLOCKED", details={"match": blocked})
    cwd = normalize_path(str(args.get("cwd") or Path.home()))
    if not cwd.is_dir():
        raise RPCError("CWD_NOT_FOUND", details={"cwd": str(cwd)})
    argv = shell_argv(command, args.get("shell"))
    env = os.environ.copy()
    for key in list(env):
        upper = key.upper()
        if upper.startswith("GITHUB_") or upper in {"GH_TOKEN", "GH_ENTERPRISE_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "RUNNER_TRACKING_ID"}:
            env.pop(key, None)
    detached = bool(args.get("detached", False))
    flags = 0
    session_id = uuid.uuid4().hex[:16]
    log_file: Path | None = None
    if detached:
        log_dir = V3_ROOT / "state" / "detached_logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"{session_id}.log"
        log_handle = open(log_file, "ab")
        if os.name == "nt":
            # DETACHED_PROCESS leaves legacy Windows PowerShell without a
            # console host: it can exit 0 without executing -Command. A hidden
            # console process still survives this Bridge's exit because this
            # branch is deliberately NOT assigned to the kill-on-close job.
            flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        process = subprocess.Popen(
            argv,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            creationflags=flags,
        )
        try:
            log_handle.close()
        except Exception:
            pass
    else:
        if os.name == "nt":
            from ff_win_owned_job import OwnedJobProcess
            try:
                process = OwnedJobProcess(argv, cwd=str(cwd), env=env)
            except OSError as exc:
                raise RPCError("OWNED_JOB_PROCESS_START_FAILED", details={"execution_started": False}) from exc
        else:
            process = subprocess.Popen(argv, cwd=str(cwd), env=env,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    session = Session(
        process,
        command=command,
        cwd=str(cwd),
        shell=Path(argv[0]).name,
        session_id=session_id,
        detached=detached,
        log_path=log_file,
        owner_scope=owner_scope,
    )
    with STATE.lock:
        STATE.sessions[session.id] = session
        if detached:
            # Serialize read-modify-write of the shared detached registry.
            save_detached_session(session)
    wait_ms = args.get("wait_ms", 250)
    if isinstance(wait_ms, int) and wait_ms > 0:
        time.sleep(min(wait_ms, 5000) / 1000.0)
    return {
        "session_id": session.id,
        "pid": process.pid,
        "running": session.is_running(),
        "exit_code": session.poll(),
        "initial": session.snapshot(),
    }


def op_read_process_output(args: dict[str, Any]) -> dict[str, Any]:
    session_id = str(args.get("session_id") or "")
    from_seq = args.get("from_seq", 1)
    max_chars = args.get("max_chars", 200_000)
    if not isinstance(from_seq, int) or from_seq < 1:
        raise RPCError("FROM_SEQ_INVALID")
    if not isinstance(max_chars, int) or max_chars < 1 or max_chars > 1_000_000:
        raise RPCError("MAX_CHARS_INVALID")
    return get_session(session_id).snapshot(from_seq=from_seq, max_chars=max_chars)


def op_interact_with_process(args: dict[str, Any]) -> dict[str, Any]:
    session_id = str(args.get("session_id") or "")
    text = args.get("input")
    if not isinstance(text, str):
        raise RPCError("PROCESS_INPUT_INVALID")
    blocked = command_blocked(text)
    if blocked:
        raise RPCError("PROCESS_INPUT_BLOCKED", details={"match": blocked})
    session = get_session(session_id)
    if not session.is_running() or session.process is None or getattr(session.process, "stdin", None) is None:
        raise RPCError("PROCESS_NOT_RUNNING")
    data = text + ("\n" if bool(args.get("append_newline", True)) else "")
    try:
        session.process.stdin.write(data.encode("utf-8"))
        session.process.stdin.flush()
    except Exception as exc:
        raise RPCError("PROCESS_INPUT_FAILED", str(exc)) from exc
    wait_ms = args.get("wait_ms", 250)
    if isinstance(wait_ms, int) and wait_ms > 0:
        time.sleep(min(wait_ms, 5000) / 1000.0)
    return session.snapshot(from_seq=int(args.get("from_seq", 1)))


def terminate_pid(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    else:
        os.kill(pid, signal.SIGKILL)


def op_force_terminate(args: dict[str, Any]) -> dict[str, Any]:
    session_id = str(args.get("session_id") or "")
    session = get_session(session_id)
    cleanup = {"termination_scope": "owned_root_process", "descendant_cleanup_verified": False}
    # A shell can exit while its ordinary descendants remain in the owned job.
    if session.is_running() or hasattr(session.process, "terminate_tree"):
        cleanup = terminate_owned_session(session)
        try:
            if hasattr(session.process, "wait"):
                session.process.wait(timeout=10)
        except Exception:
            pass
    code = session.poll()
    known = getattr(session.process, "exit_code_known", True)
    return {"ok": True, "session_id": session_id, "exit_code": code if known else None,
            "exit_code_known": known, **cleanup}


def terminate_owned_session(session):
    if os.name == "nt":
        try:
            if hasattr(session.process, "terminate_tree"):
                return session.process.terminate_tree()
            # Popen retains its exact process handle; restored stubs use the
            # birth-bound ProcessReference. Never delegate to taskkill /PID.
            session.process.terminate()
        except (OSError, AttributeError) as exc:
            raise RPCError("OWNED_PROCESS_TERMINATION_FAILED", details={"retry_safe": False}) from exc
    else:
        terminate_pid(session.pid)
    return {"termination_scope": "owned_root_process", "descendant_cleanup_verified": False}


def op_list_sessions(args: dict[str, Any]) -> dict[str, Any]:
    with STATE.lock:
        sessions = list(STATE.sessions.values())
    items = []
    for session in sessions:
        code = session.poll()
        known = getattr(session.process, "exit_code_known", True)
        items.append({
            "session_id": session.id,
            "pid": session.pid,
            "running": session.is_running(),
            "exit_code": code if known else None,
            "exit_code_known": known,
            "command": redact_string(session.command),
            "cwd": session.cwd,
            "shell": session.shell,
            "detached": session.detached,
            "created_at": session.created_at,
            "closed_at": session.closed_at,
            "buffer_next_seq": session.next_seq,
        })
    return {"sessions": items}


def op_list_processes(args: dict[str, Any]) -> dict[str, Any]:
    powershell = shutil.which("powershell.exe") or "powershell.exe"
    script = "Get-Process | Select-Object -First 500 Id,ProcessName,CPU,@{n='WorkingSet';e={$_.WorkingSet64}},Path | ConvertTo-Json -Compress"
    completed = subprocess.run([powershell, "-NoLogo", "-NoProfile", "-Command", script], capture_output=True, timeout=30)
    if completed.returncode != 0:
        raise RPCError("PROCESS_LIST_FAILED", safe_decode(completed.stderr))
    text = safe_decode(completed.stdout).strip()
    data = json.loads(text) if text else []
    if isinstance(data, dict):
        data = [data]
    return {"processes": data}


def op_kill_process(args: dict[str, Any]) -> dict[str, Any]:
    pid = args.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise RPCError("PID_INVALID")
    if pid in {os.getpid(), os.getppid()}:
        raise RPCError("PID_PROTECTED")
    owned_session_id = None
    owned_session = None
    with STATE.lock:
        for session_id, session in STATE.sessions.items():
            if session.pid == pid:
                owned_session_id = session_id
                owned_session = session
                break
    if owned_session is None:
        raise RPCError("PROCESS_NOT_OWNED", details={"pid": pid})
    if not owned_session.is_running():
        raise RPCError("PROCESS_NOT_RUNNING", details={"pid": pid, "session_id": owned_session_id})
    cleanup = terminate_owned_session(owned_session)
    return {"ok": True, "pid": pid, "ownership": "bridge_session", "session_id": owned_session_id,
            **cleanup}


def read_text_file(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    if len(raw) > MAX_INLINE_BYTES:
        raise RPCError("FILE_TOO_LARGE_FOR_INLINE_READ", details={"bytes": len(raw), "limit": MAX_INLINE_BYTES})
    for encoding in ("utf-8-sig", "utf-8", "utf-16", "cp1251", "cp866"):
        try:
            return raw.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    raise RPCError("FILE_TEXT_DECODE_FAILED")


def op_read_file(args: dict[str, Any]) -> dict[str, Any]:
    if bool(args.get("is_url", False)):
        if not STATE.config.get("urlReadEnabled", True):
            raise RPCError("URL_READ_DISABLED")
        url = args.get("path") or args.get("url")
        if not isinstance(url, str) or not re.match(r"^https?://", url, re.I):
            raise RPCError("URL_INVALID")
        request = urllib.request.Request(url, headers={"User-Agent": "FF-Windows-Bridge-V3/1"})
        with urllib.request.urlopen(request, timeout=min(int(args.get("timeout_seconds", 30)), 60)) as response:
            raw = response.read(MAX_INLINE_BYTES + 1)
            if len(raw) > MAX_INLINE_BYTES:
                raise RPCError("URL_RESPONSE_TOO_LARGE")
            content_type = response.headers.get("Content-Type", "")
            final_url = response.geturl()
        if content_type.lower().startswith("text/") or "json" in content_type.lower() or "xml" in content_type.lower():
            return {"is_url": True, "url": final_url, "content_type": content_type, "content": safe_decode(raw), "bytes": len(raw)}
        return {"is_url": True, "url": final_url, "content_type": content_type, "base64": base64.b64encode(raw).decode("ascii"), "bytes": len(raw)}

    path = normalize_path(str(args.get("path") or ""))
    enforce_allowed(path)
    if not path.is_file():
        raise RPCError("FILE_NOT_FOUND", details={"path": str(path)})
    text, encoding = read_text_file(path)
    lines = text.splitlines(keepends=True)
    length = args.get("length", STATE.config.get("fileReadLineLimit", 2000))
    offset = args.get("offset", 0)
    if not isinstance(length, int) or length < 1:
        raise RPCError("READ_LENGTH_INVALID")
    length = min(length, int(STATE.config.get("fileReadLineLimit", 2000)))
    if not isinstance(offset, int):
        raise RPCError("READ_OFFSET_INVALID")
    start = max(0, len(lines) + offset) if offset < 0 else min(offset, len(lines))
    selected = lines[start:start + length]
    return {
        "path": str(path), "encoding": encoding, "offset": start, "length": len(selected),
        "total_lines": len(lines), "content": "".join(selected), "bytes": path.stat().st_size,
    }


def op_read_multiple_files(args: dict[str, Any]) -> dict[str, Any]:
    paths = args.get("paths")
    if not isinstance(paths, list) or not paths or len(paths) > 50:
        raise RPCError("PATHS_INVALID")
    results = []
    for item in paths:
        try:
            result = op_read_file({"path": str(item), "offset": args.get("offset", 0), "length": args.get("length", STATE.config.get("fileReadLineLimit", 2000))})
            results.append({"ok": True, "result": result})
        except RPCError as exc:
            results.append({"ok": False, "path": str(item), "error": exc.code, "message": exc.message})
    return {"results": results}


def op_write_file(args: dict[str, Any]) -> dict[str, Any]:
    path = normalize_path(str(args.get("path") or ""))
    enforce_allowed(path)
    content = args.get("content")
    if not isinstance(content, str):
        raise RPCError("FILE_CONTENT_INVALID")
    line_count = content.count("\n") + (1 if content else 0)
    limit = int(STATE.config.get("fileWriteLineLimit", 5000))
    if line_count > limit:
        raise RPCError("FILE_WRITE_LINE_LIMIT", details={"lines": line_count, "limit": limit})
    mode = str(args.get("mode", "rewrite"))
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode == "append":
        with path.open("a", encoding="utf-8", newline="") as handle:
            handle.write(content)
    elif mode == "rewrite":
        atomic_write_text(path, content, "utf-8")
    else:
        raise RPCError("FILE_WRITE_MODE_INVALID")
    return {"ok": True, "path": str(path), "bytes": path.stat().st_size, "mode": mode}


def op_create_directory(args: dict[str, Any]) -> dict[str, Any]:
    path = normalize_path(str(args.get("path") or ""))
    enforce_allowed(path)
    path.mkdir(parents=True, exist_ok=True)
    return {"ok": True, "path": str(path)}


def op_list_directory(args: dict[str, Any]) -> dict[str, Any]:
    path = normalize_path(str(args.get("path") or ""))
    enforce_allowed(path)
    if not path.is_dir():
        raise RPCError("DIRECTORY_NOT_FOUND")
    items = []
    max_items = min(int(args.get("max_items", 1000)), 5000)
    for child in sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))[:max_items]:
        try:
            stat = child.stat()
            items.append({
                "name": child.name, "path": str(child), "is_dir": child.is_dir(),
                "bytes": None if child.is_dir() else stat.st_size, "mtime": int(stat.st_mtime * 1000),
            })
        except OSError:
            continue
    return {"path": str(path), "items": items}


def op_move_file(args: dict[str, Any]) -> dict[str, Any]:
    source = normalize_path(str(args.get("source") or ""))
    destination = normalize_path(str(args.get("destination") or ""))
    enforce_allowed(source)
    enforce_allowed(destination)
    if not source.exists():
        raise RPCError("SOURCE_NOT_FOUND")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(destination))
    return {"ok": True, "source": str(source), "destination": str(destination)}


def op_get_file_info(args: dict[str, Any]) -> dict[str, Any]:
    path = normalize_path(str(args.get("path") or ""))
    enforce_allowed(path)
    if not path.exists():
        raise RPCError("PATH_NOT_FOUND")
    stat = path.stat()
    info: dict[str, Any] = {
        "path": str(path), "name": path.name, "is_file": path.is_file(), "is_dir": path.is_dir(),
        "bytes": stat.st_size, "mtime": int(stat.st_mtime * 1000), "ctime": int(stat.st_ctime * 1000),
    }
    if path.is_file() and stat.st_size <= 32 * 1024 * 1024:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        info["sha256"] = digest.hexdigest()
    return info


def op_search_files(args: dict[str, Any]) -> dict[str, Any]:
    root = normalize_path(str(args.get("path") or args.get("root") or ""))
    enforce_allowed(root)
    if not root.is_dir():
        raise RPCError("DIRECTORY_NOT_FOUND")
    query = str(args.get("query") or "").lower()
    if not query:
        raise RPCError("SEARCH_QUERY_INVALID")
    max_results = min(int(args.get("max_results", 200)), 2000)
    results: list[str] = []
    for base, dirs, files in os.walk(root):
        for name in dirs + files:
            if query in name.lower():
                results.append(str(Path(base) / name))
                if len(results) >= max_results:
                    return {"results": results, "matches": results, "truncated": True}
    return {"results": results, "matches": results, "truncated": False}


def _find_ripgrep() -> str | None:
    bundled = BRIDGE_ROOT / "tools" / "ripgrep" / "rg.exe"
    if bundled.is_file():
        return str(bundled)
    return shutil.which("rg.exe") or shutil.which("rg")


def _ripgrep_search(
    argv: list[str], max_results: int, timeout_seconds: int
) -> tuple[list[str], bool, bool, int]:
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    items: queue.Queue[bytes | None] = queue.Queue()
    nonfatal_error_count = 0
    fatal_stderr: list[str] = []
    fatal_stderr_chars = 0

    def pump_stdout() -> None:
        try:
            assert process.stdout is not None
            for line in iter(process.stdout.readline, b""):
                items.put(line)
        finally:
            items.put(None)

    def pump_stderr() -> None:
        nonlocal nonfatal_error_count, fatal_stderr_chars
        assert process.stderr is not None
        for raw in iter(process.stderr.readline, b""):
            line = safe_decode(raw).strip()
            if not line:
                continue
            if re.match(r"^rg: .+\(os error \d+\)$", line):
                nonfatal_error_count += 1
                continue
            if len(fatal_stderr) < 8 and fatal_stderr_chars < 4000:
                remaining = 4000 - fatal_stderr_chars
                kept = line[:remaining]
                fatal_stderr.append(kept)
                fatal_stderr_chars += len(kept)

    reader = threading.Thread(target=pump_stdout, daemon=True)
    stderr_reader = threading.Thread(target=pump_stderr, daemon=True)
    reader.start()
    stderr_reader.start()
    deadline = time.monotonic() + timeout_seconds
    lines: list[str] = []
    reached_eof = False
    timed_out = False
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                item = items.get(timeout=min(0.05, remaining))
            except queue.Empty:
                if process.poll() is not None and not reader.is_alive():
                    reached_eof = True
                    break
                continue
            if item is None:
                reached_eof = True
                break
            lines.append(safe_decode(item).rstrip("\r\n"))
            if len(lines) > max_results:
                break
    finally:
        if process.poll() is None and reached_eof:
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
        reader.join(timeout=0.2)
        stderr_reader.join(timeout=0.2)

    if timed_out:
        raise RPCError("SEARCH_TIMEOUT", details={"engine": "ripgrep", "timeout_seconds": timeout_seconds})

    partial = nonfatal_error_count > 0
    if reached_eof and process.returncode not in (0, 1):
        if not (process.returncode == 2 and partial and not fatal_stderr):
            raise RPCError(
                "SEARCH_FAILED",
                details={
                    "engine": "ripgrep",
                    "returncode": process.returncode,
                    "stderr": "\n".join(fatal_stderr)[:4000],
                    "nonfatal_error_count": nonfatal_error_count,
                },
            )
    return lines[:max_results], len(lines) > max_results, partial, nonfatal_error_count


def op_search_code(args: dict[str, Any]) -> dict[str, Any]:
    root = normalize_path(str(args.get("path") or args.get("root") or ""))
    enforce_allowed(root)
    if not root.exists():
        raise RPCError("PATH_NOT_FOUND")
    query = args.get("query")
    if not isinstance(query, str) or not query:
        raise RPCError("SEARCH_QUERY_INVALID")
    max_results = min(max(int(args.get("max_results", 200)), 1), 1000)
    literal = bool(args.get("literal", True))
    case_sensitive = bool(args.get("case_sensitive", False))
    timeout_seconds = min(max(int(args.get("timeout_seconds", 30)), 1), 120)
    rg = _find_ripgrep()
    if rg:
        argv = [rg, "--line-number", "--no-heading", "--color", "never", "--no-config", "--hidden", "--no-ignore", "--max-filesize", str(MAX_INLINE_BYTES)]
        if literal:
            argv.append("-F")
        if not case_sensitive:
            argv.append("-i")
        argv += [query, str(root)]
        lines, truncated, partial, error_count = _ripgrep_search(argv, max_results, timeout_seconds)
        return {
            "engine": "ripgrep",
            "results": lines,
            "matches": lines,
            "truncated": truncated,
            "partial": partial,
            "error_count": error_count,
        }
    flags = 0 if case_sensitive else re.IGNORECASE
    pattern = re.compile(re.escape(query) if literal else query, flags)
    results: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_seconds
    paths = [root] if root.is_file() else (Path(base) / name for base, _, files in os.walk(root) for name in files)
    for path in paths:
        if time.monotonic() >= deadline:
            raise RPCError("SEARCH_TIMEOUT", details={"engine": "python", "timeout_seconds": timeout_seconds})
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                continue
            text, _ = read_text_file(path)
        except Exception:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            if pattern.search(line):
                results.append({"path": str(path), "line": line_number, "text": line[:1000]})
                if len(results) >= max_results:
                    return {"engine": "python", "results": results, "matches": results, "truncated": True}
    return {"engine": "python", "results": results, "matches": results, "truncated": False}


def op_edit_block(args: dict[str, Any]) -> dict[str, Any]:
    path = normalize_path(str(args.get("path") or ""))
    enforce_allowed(path)
    if not path.is_file():
        raise RPCError("FILE_NOT_FOUND")
    old_text = args.get("old_text")
    new_text = args.get("new_text")
    if not isinstance(old_text, str) or not old_text:
        raise RPCError("EDIT_OLD_TEXT_INVALID")
    if not isinstance(new_text, str):
        raise RPCError("EDIT_NEW_TEXT_INVALID")
    expected = int(args.get("expected_replacements", 1))
    if expected < 1 or expected > 1000:
        raise RPCError("EDIT_EXPECTED_REPLACEMENTS_INVALID")
    text, encoding = read_text_file(path)
    count = text.count(old_text)
    if count != expected:
        old_lines = old_text.splitlines()
        file_lines = text.splitlines()
        closest = None
        similarity = 0.0
        if old_lines and file_lines:
            width = max(1, len(old_lines))
            for index in range(0, max(1, len(file_lines) - width + 1)):
                candidate = "\n".join(file_lines[index:index + width])
                ratio = difflib.SequenceMatcher(None, old_text, candidate).ratio()
                if ratio > similarity:
                    similarity = ratio
                    closest = {"start_line": index + 1, "similarity": round(ratio, 4), "text": candidate[:4000]}
        raise RPCError("EDIT_MATCH_COUNT_MISMATCH", details={"found": count, "expected": expected, "closest": closest})
    updated = text.replace(old_text, new_text, expected)
    diff = "".join(difflib.unified_diff(text.splitlines(True), updated.splitlines(True), fromfile=str(path), tofile=str(path), n=3))
    atomic_write_text(path, updated, "utf-8")
    return {
        "ok": True, "path": str(path), "replacements": expected, "previous_encoding": encoding,
        "diff": diff[:100_000], "diff_truncated": len(diff) > 100_000,
    }


def op_run_code(args: dict[str, Any]) -> dict[str, Any]:
    language = str(args.get("language") or "").lower()
    code = args.get("code")
    if not isinstance(code, str) or not code:
        raise RPCError("CODE_INVALID")
    blocked = code_blocked(language, code)
    if blocked:
        raise RPCError("CODE_BLOCKED", details={"match": blocked})
    timeout = min(max(int(args.get("timeout_seconds", 30)), 1), 300)
    if language in {"python", "py"}:
        executable = sys.executable
        argv = [executable, "-c", code]
    elif language in {"powershell", "pwsh", "ps1"}:
        argv = shell_argv(code, "pwsh.exe" if language == "pwsh" else "powershell.exe")
    elif language in {"node", "javascript", "js"}:
        executable = shutil.which("node.exe") or shutil.which("node")
        if not executable:
            raise RPCError("NODE_NOT_FOUND")
        argv = [executable, "-e", code]
    elif language in {"r", "rscript"}:
        executable = shutil.which("Rscript.exe") or shutil.which("Rscript")
        if not executable:
            raise RPCError("RSCRIPT_NOT_FOUND")
        argv = [executable, "-e", code]
    else:
        raise RPCError("LANGUAGE_UNSUPPORTED")
    cwd = normalize_path(str(args.get("cwd") or Path.home()))
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("GITHUB_") and k.upper() not in {"GH_TOKEN", "GH_ENTERPRISE_TOKEN", "ACTIONS_RUNTIME_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "RUNNER_TRACKING_ID"}}
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               cwd=str(cwd), env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        assign_process_to_agent_job(process)
        stdout, stderr = process.communicate(timeout=timeout)
    except BaseException:
        if process.poll() is None:
            terminate_pid(process.pid)
            process.wait(timeout=10)
        raise
    return {
        "exit_code": process.returncode,
        "stdout": safe_decode(stdout)[-500_000:],
        "stderr": safe_decode(stderr)[-500_000:],
    }


def op_read_audit(args: dict[str, Any]) -> dict[str, Any]:
    limit = min(max(int(args.get("limit", 100)), 1), 1000)
    if not AUDIT_PATH.is_file():
        return {"records": []}
    lines = AUDIT_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    records = []
    for line in lines[-limit:]:
        try:
            records.append(json.loads(line))
        except Exception:
            continue
    return {"records": records}


def op_cleanup_sessions(args: dict[str, Any]) -> dict[str, Any]:
    older_seconds = max(int(args.get("older_than_seconds", 3600)), 0)
    cutoff = now_ms() - older_seconds * 1000
    removed = []
    with STATE.lock:
        for session_id, session in list(STATE.sessions.items()):
            if session.poll() is not None and (session.closed_at or now_ms()) <= cutoff:
                removed.append(session_id)
                STATE.sessions.pop(session_id, None)
    if removed and DETACHED_STATE_PATH.is_file():
        try:
            current = json.loads(DETACHED_STATE_PATH.read_text("utf-8"))
            for sid in removed:
                current.pop(sid, None)
            atomic_write_text(DETACHED_STATE_PATH, json.dumps(current, indent=2))
        except Exception:
            pass
    return {"removed": removed}


OPS = {
    "ping": op_ping,
    "capabilities": op_capabilities,
    "device_info": op_device_info,
    "get_config": op_get_config,
    "set_config_value": op_set_config_value,
    "start_process": op_start_process,
    "read_process_output": op_read_process_output,
    "interact_with_process": op_interact_with_process,
    "force_terminate": op_force_terminate,
    "list_sessions": op_list_sessions,
    "list_processes": op_list_processes,
    "kill_process": op_kill_process,
    "read_file": op_read_file,
    "read_multiple_files": op_read_multiple_files,
    "write_file": op_write_file,
    "create_directory": op_create_directory,
    "list_directory": op_list_directory,
    "move_file": op_move_file,
    "get_file_info": op_get_file_info,
    "search_files": op_search_files,
    "search_code": op_search_code,
    "edit_block": op_edit_block,
    "run_code": op_run_code,
    "read_audit": op_read_audit,
    "cleanup_sessions": op_cleanup_sessions,
}


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    started = now_ms()
    op = request.get("op")
    args = request.get("args", {})
    request_id = request.get("request_id") or request.get("task_id")
    if not isinstance(op, str) or op not in OPS:
        raise RPCError("OP_UNSUPPORTED", details={"op": op, "supported": sorted(OPS)})
    if not isinstance(args, dict):
        raise RPCError("ARGS_INVALID")
    target = request.get("target_device")
    if target and str(target).lower() != platform.node().lower():
        raise RPCError("DEVICE_MISMATCH", details={"target": target, "actual": platform.node()})
    try:
        result = OPS[op](args)
        duration = now_ms() - started
        audit_error = audit(op, args, "ok", duration)
        return {
            **({"audit_error": audit_error} if audit_error else {}),
            "schema": "ff-win-v3-result-v1", "ok": True, "request_id": request_id,
            "device": platform.node(), "op": op, "duration_ms": duration, "result": result,
        }
    except RPCError as exc:
        duration = now_ms() - started
        audit_error = audit(op, args, "error", duration, exc.code)
        return {
            **({"audit_error": audit_error} if audit_error else {}),
            "schema": "ff-win-v3-result-v1", "ok": False, "request_id": request_id,
            "device": platform.node(), "op": op, "duration_ms": duration,
            "error_code": exc.code, "message": exc.message, "details": exc.details,
        }
    except subprocess.TimeoutExpired:
        duration = now_ms() - started
        audit_error = audit(op, args, "error", duration, "PROCESS_TIMEOUT")
        return {
            **({"audit_error": audit_error} if audit_error else {}),
            "schema": "ff-win-v3-result-v1", "ok": False, "request_id": request_id,
            "device": platform.node(), "op": op, "duration_ms": duration, "error_code": "PROCESS_TIMEOUT",
        }
    except Exception as exc:
        duration = now_ms() - started
        audit_error = audit(op, args, "error", duration, type(exc).__name__)
        return {
            **({"audit_error": audit_error} if audit_error else {}),
            "schema": "ff-win-v3-result-v1", "ok": False, "request_id": request_id,
            "device": platform.node(), "op": op, "duration_ms": duration,
            "error_code": "INTERNAL_ERROR", "message": f"{type(exc).__name__}: {exc}"[:2000],
        }


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "FFWinBridgeV3/1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def auth_ok(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-FF3-Key", ""), STATE.secret)

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        if self.path != "/health":
            self.send_json(404, {"ok": False, "error_code": "NOT_FOUND"})
            return
        if not self.auth_ok():
            self.send_json(403, {"ok": False, "error_code": "AUTH_FAILED"})
            return
        self.send_json(200, op_ping({}))

    def do_POST(self) -> None:
        if not self.auth_ok():
            self.send_json(403, {"ok": False, "error_code": "AUTH_FAILED"})
            return
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0 or length > MAX_REQUEST_BYTES:
            self.send_json(413, {"ok": False, "error_code": "REQUEST_SIZE_INVALID"})
            return
        raw = self.rfile.read(length)
        try:
            request = json.loads(raw.decode("utf-8"))
        except Exception:
            self.send_json(400, {"ok": False, "error_code": "REQUEST_JSON_INVALID"})
            return
        if not isinstance(request, dict):
            self.send_json(400, {"ok": False, "error_code": "REQUEST_NOT_OBJECT"})
            return
        if self.path == "/rpc":
            try:
                self.send_json(200, dispatch(request))
            except RPCError as exc:
                self.send_json(400, {"ok": False, "error_code": exc.code, "message": exc.message, "details": exc.details})
            return
        if self.path == "/shutdown":
            self.send_json(200, {"ok": True})
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        self.send_json(404, {"ok": False, "error_code": "NOT_FOUND"})


def _serve_direct(server: http.server.ThreadingHTTPServer) -> None:
    # On some Windows environments the selector used by BaseServer.serve_forever()
    # can leave accepted loopback connections queued indefinitely. Accept directly
    # with a short timeout while preserving BaseServer.shutdown() semantics.
    server._BaseServer__is_shut_down.clear()
    server.socket.settimeout(0.5)
    try:
        while not server._BaseServer__shutdown_request:
            try:
                request, client_address = server.get_request()
            except socket.timeout:
                server.service_actions()
                continue
            except OSError:
                if server._BaseServer__shutdown_request:
                    break
                raise
            if server.verify_request(request, client_address):
                try:
                    server.process_request(request, client_address)
                except Exception:
                    server.handle_error(request, client_address)
                    server.shutdown_request(request)
            else:
                server.shutdown_request(request)
            server.service_actions()
    finally:
        server._BaseServer__shutdown_request = False
        server._BaseServer__is_shut_down.set()


class BridgeHTTPServer(http.server.ThreadingHTTPServer):
    # Preserve the installed burst-connection fix: the default queue of five
    # can drop concurrent connections before they reach the handler.
    request_queue_size = 64


def serve(host: str, port: int) -> int:
    ensure_dirs()
    atomic_write_text(PID_PATH, str(os.getpid()) + "\n", "ascii")
    try:
        server = BridgeHTTPServer((host, port), Handler)
    except OSError as exc:
        print(f"FF3_BIND_FAILED:{exc}", file=sys.stderr)
        return 3
    STATE.server = server
    try:
        _serve_direct(server)
    finally:
        server.server_close()
        try:
            if PID_PATH.is_file() and PID_PATH.read_text(encoding="ascii").strip() == str(os.getpid()):
                PID_PATH.unlink(missing_ok=True)
        except Exception:
            pass
    return 0


def client_request(host: str, port: int, op: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
    secret = load_or_create_secret()
    payload = json.dumps({"op": op, "args": args or {}}, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"http://{host}:{port}/rpc",
        data=payload,
        headers={"Content-Type": "application/json", "X-FF3-Key": secret},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="cmd", required=True)
    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--host", default=HOST)
    serve_parser.add_argument("--port", type=int, default=PORT)
    ping_parser = subparsers.add_parser("ping")
    ping_parser.add_argument("--host", default=HOST)
    ping_parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    if args.cmd == "serve":
        return serve(args.host, args.port)
    if args.cmd == "ping":
        try:
            print(json.dumps(client_request(args.host, args.port, "ping"), ensure_ascii=False))
            return 0
        except Exception as exc:
            print(f"FF3_PING_FAILED:{exc}", file=sys.stderr)
            return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
