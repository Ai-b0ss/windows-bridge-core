from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
import uuid
from typing import Any, Mapping

ROOT = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "FF-Windows-Bridge"
RUNTIME = ROOT / "bridge-v3"
STATE_ROOT = ROOT / "continuations"
PORT = 39073
REPO_ROOT = Path(os.environ.get("FF_BRIDGE_REPO", r"C:\\notion-agent-bridge"))
BRIDGE_CONTINUATION_SCOPE = "bridge_work"
BRIDGE_CONTINUATION_POLICY = "failure_or_stall"


def _is_bridge_managed(state: Mapping[str, Any]) -> bool:
    return (
        state.get("continuation_scope") == BRIDGE_CONTINUATION_SCOPE
        and state.get("continuation_enabled") is True
    )


def _require_bridge_managed(state: Mapping[str, Any]) -> None:
    if not _is_bridge_managed(state):
        raise ContinuationError("BRIDGE_SCOPE_REQUIRED")


DEFAULT_CONTINUATION_WINDOW_S = 1560  # 26 minutes (sweet spot: 23-29 min)
MAX_CONTINUATION_WINDOW_S = 1800      # 30 minutes safety padding
ACTIVE_TOOL_THRESHOLD_S = 120.0       # 2 minutes grace while tool calls are actively running
EARLY_COMPLETION_QUIET_PERIOD_S = 45.0


def _last_bridge_audit_mtime() -> float:
    audit_path = RUNTIME / "audit.jsonl"
    if not audit_path.is_file():
        return 0.0
    try:
        return float(audit_path.stat().st_mtime)
    except Exception:
        return 0.0


def _has_active_tool_execution(threshold_s: float = ACTIVE_TOOL_THRESHOLD_S) -> bool:
    """Check internal execution signals: returns True if Bridge tools are actively running."""
    mtime = _last_bridge_audit_mtime()
    if mtime > 0 and (time.time() - mtime) < threshold_s:
        return True
    return False


def _detect_early_completion(task_id: str, state: Mapping[str, Any]) -> bool:
    """Detect if agent physically completed the goal earlier than the 23-26m window."""
    if state.get("status") == "completed":
        return True
    handoff = str(state.get("handoff") or "").lower()
    completion_markers = (
        "task completed",
        "work complete",
        "задача завершена",
        "работа завершена",
        "all steps complete",
        "completion proof verified",
    )
    if any(marker in handoff for marker in completion_markers):
        return True
    return False




class ContinuationError(RuntimeError):
    def __init__(self, code: str, details: Mapping[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


def _task_id(value: str) -> str:
    text = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,80}", text):
        raise ContinuationError("TASK_ID_INVALID")
    return text


def _paths(task_id: str) -> tuple[Path, Path, Path]:
    task = _task_id(task_id)
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    return (
        STATE_ROOT / f"{task}.json",
        STATE_ROOT / f"{task}.launch.lock",
        STATE_ROOT / f"{task}.watcher.pid",
    )


def _boot_id() -> int:
    return int(round(time.time() - time.monotonic()))


def _read_pid_record(pid_path: Path) -> tuple[int, int | None] | None:
    if not pid_path.is_file():
        return None
    raw = pid_path.read_text(encoding="ascii").strip()
    try:
        if raw.startswith("{"):
            obj = json.loads(raw)
            return int(obj["pid"]), int(obj.get("boot_id")) if obj.get("boot_id") is not None else None
        return int(raw), None
    except Exception:
        return None


def _pid_record_alive(pid_path: Path) -> tuple[bool, int | None]:
    record = _read_pid_record(pid_path)
    if record is None:
        return False, None
    pid, boot_id = record
    if boot_id is not None and abs(boot_id - _boot_id()) > 5:
        return False, pid
    return _process_alive(pid), pid


def _write_pid_record(pid_path: Path, pid: int) -> None:
    pid_path.write_text(
        json.dumps({"pid": int(pid), "boot_id": _boot_id(), "written_at": time.time()}),
        encoding="ascii",
    )


def _process_alive(pid: int) -> bool:
    pid = int(pid)
    if pid <= 0:
        return False
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return int(code.value) == 259
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except Exception:
        return False


def _acquire_launch_lock(lock_path: Path) -> None:
    for attempt in range(2):
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            payload = json.dumps({
                "pid": os.getpid(),
                "boot_id": _boot_id(),
                "created_at": time.time(),
            }).encode("ascii")
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
            return
        except FileExistsError:
            stale = True
            try:
                obj = json.loads(lock_path.read_text(encoding="ascii"))
                pid = int(obj.get("pid", 0))
                boot = int(obj.get("boot_id", 0))
                created = float(obj.get("created_at", 0))
                stale = (
                    abs(boot - _boot_id()) > 5
                    or not _process_alive(pid)
                    or time.time() - created > 180
                )
            except Exception:
                stale = True
            if stale and attempt == 0:
                lock_path.unlink(missing_ok=True)
                continue
            raise ContinuationError("LAUNCH_ALREADY_CLAIMED")
    raise ContinuationError("LAUNCH_ALREADY_CLAIMED")


def _state_write_lock_path(task_id: str) -> Path:
    return STATE_ROOT / f"{_task_id(task_id)}.state-write.lock"


def _acquire_state_write_lock(task_id: str, timeout_s: float = 8.0) -> Path:
    lock_path = _state_write_lock_path(task_id)
    deadline = time.monotonic() + max(0.5, float(timeout_s))
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            payload = json.dumps({
                "pid": os.getpid(),
                "boot_id": _boot_id(),
                "created_at": time.time(),
            }).encode("ascii")
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
            return lock_path
        except FileExistsError:
            stale = False
            try:
                obj = json.loads(lock_path.read_text(encoding="ascii"))
                pid = int(obj.get("pid", 0))
                boot = int(obj.get("boot_id", 0))
                created = float(obj.get("created_at", 0))
                stale = (
                    abs(boot - _boot_id()) > 5
                    or not _process_alive(pid)
                    or time.time() - created > 60
                )
            except Exception:
                stale = True
            if stale:
                try:
                    lock_path.unlink(missing_ok=True)
                    continue
                except Exception:
                    pass
            if time.monotonic() >= deadline:
                raise ContinuationError("STATE_WRITE_BUSY", {"task_id": _task_id(task_id)})
            time.sleep(0.02)


def _release_state_write_lock(lock_path: Path) -> None:
    try:
        lock_path.unlink(missing_ok=True)
    except Exception:
        pass


def _load(task_id: str) -> dict[str, Any]:
    state_path, _, _ = _paths(task_id)
    if not state_path.is_file():
        raise ContinuationError("TASK_NOT_FOUND", {"task_id": task_id})
    lock_path = _acquire_state_write_lock(task_id)
    try:
        try:
            return json.loads(state_path.read_text(encoding="utf-8-sig"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            backup = state_path.with_name(f"{state_path.name}.last-good")
            if backup.is_file():
                return json.loads(backup.read_text(encoding="utf-8-sig"))
            raise
    finally:
        _release_state_write_lock(lock_path)


def _save(task_id: str, state: Mapping[str, Any]) -> dict[str, Any]:
    state_path, _, _ = _paths(task_id)
    lock_path = _acquire_state_write_lock(task_id)
    tmp = state_path.with_name(
        f"{state_path.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    payload = json.dumps(dict(state), ensure_ascii=False, indent=2).encode("utf-8")
    original = state_path.read_bytes() if state_path.is_file() else None
    replaced = False
    try:
        tmp.write_bytes(payload)
        for attempt in range(20):
            try:
                os.replace(tmp, state_path)
                replaced = True
                break
            except PermissionError:
                if attempt >= 19:
                    break
                time.sleep(min(0.02 * (2 ** attempt), 0.25))

        if not replaced:
            # Some long-lived readers on Windows (notably Desktop Commander)
            # may omit FILE_SHARE_DELETE. In that case atomic replacement is
            # impossible even though the file itself is writable. Keep a
            # last-good copy, then rewrite the existing handle under our
            # cross-process state lock.
            if original is not None:
                backup = state_path.with_name(f"{state_path.name}.last-good")
                backup.write_bytes(original)
            try:
                mode = "r+b" if state_path.exists() else "w+b"
                with state_path.open(mode) as handle:
                    handle.seek(0)
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                    handle.truncate()
                    handle.flush()
                    os.fsync(handle.fileno())
                check = json.loads(state_path.read_text(encoding="utf-8"))
                if not isinstance(check, Mapping) or check.get("task_id") != dict(state).get("task_id"):
                    raise ContinuationError("STATE_WRITE_VERIFY_FAILED")
            except Exception:
                if original is not None:
                    with state_path.open("r+b") as handle:
                        handle.seek(0)
                        handle.write(original)
                        handle.flush()
                        os.fsync(handle.fileno())
                        handle.truncate()
                raise
    finally:
        tmp.unlink(missing_ok=True)
        _release_state_write_lock(lock_path)
    return dict(state)


def arm_task(
    task_id: str,
    goal: str,
    handoff: str,
    launch_after_s: int = DEFAULT_CONTINUATION_WINDOW_S,
    *,
    bridge_managed: bool = False,
) -> dict[str, Any]:
    if not bridge_managed:
        raise ContinuationError("BRIDGE_SCOPE_REQUIRED")
    state_path, _, _ = _paths(task_id)
    if state_path.is_file():
        state = _load(task_id)
        now = time.time()
        state["goal"] = str(goal)
        state["handoff"] = str(handoff)
        state["status"] = "armed"
        state["launch_at"] = now + max(60, int(launch_after_s))
        state["last_heartbeat"] = now
        state["updated_at"] = now
        state["boot_id"] = _boot_id()
        state["owner"] = "chatgpt"
        state["continuation_scope"] = BRIDGE_CONTINUATION_SCOPE
        state["continuation_enabled"] = True
        state["continuation_policy"] = BRIDGE_CONTINUATION_POLICY
        state.pop("completed_at", None)
        state = _save(task_id, state)
    else:
        state = init_task(
            task_id, goal, handoff, launch_after_s,
            bridge_managed=True,
        )
    watcher = spawn_watch(task_id)
    return {"ok": True, "state": state, "watcher": watcher}


def init_task(
    task_id: str,
    goal: str,
    handoff: str,
    launch_after_s: int = DEFAULT_CONTINUATION_WINDOW_S,
    *,
    bridge_managed: bool = False,
) -> dict[str, Any]:
    now = time.time()
    state = {
        "schema": "ff-continuation-v2",
        "task_id": _task_id(task_id),
        "goal": str(goal),
        "handoff": str(handoff),
        "generation": 1,
        "status": "armed",
        "created_at": now,
        "updated_at": now,
        "boot_id": _boot_id(),
        "launch_at": now + max(60, int(launch_after_s)),
        "last_heartbeat": now,
        "launch_attempts": 0,
        "last_launch": None,
        "owner": "chatgpt",
        "continuation_scope": (
            BRIDGE_CONTINUATION_SCOPE if bridge_managed else "unmanaged"
        ),
        "continuation_enabled": bool(bridge_managed),
        "continuation_policy": (
            BRIDGE_CONTINUATION_POLICY if bridge_managed else "disabled"
        ),
    }
    return _save(task_id, state)


def enable_bridge_task(task_id: str) -> dict[str, Any]:
    state = _load(task_id)
    state["schema"] = "ff-continuation-v2"
    state["continuation_scope"] = BRIDGE_CONTINUATION_SCOPE
    state["continuation_enabled"] = True
    state["continuation_policy"] = BRIDGE_CONTINUATION_POLICY
    state["updated_at"] = time.time()
    return _save(task_id, state)


def update_task(task_id: str, *, handoff: str | None = None, note: str | None = None) -> dict[str, Any]:
    state = _load(task_id)
    if handoff is not None:
        state["handoff"] = str(handoff)
    if note is not None:
        state["note"] = str(note)
    state["updated_at"] = time.time()
    return _save(task_id, state)


def heartbeat(task_id: str) -> dict[str, Any]:
    state = _load(task_id)
    state["last_heartbeat"] = time.time()
    state["updated_at"] = state["last_heartbeat"]
    return _save(task_id, state)


def complete(task_id: str) -> dict[str, Any]:
    state = _load(task_id)
    now = time.time()
    state["status"] = "completed"
    state["completed_at"] = now
    state["updated_at"] = now
    return _save(task_id, state)


def rearm(task_id: str, launch_after_s: int = DEFAULT_CONTINUATION_WINDOW_S) -> dict[str, Any]:
    state = _load(task_id)
    _require_bridge_managed(state)
    now = time.time()
    state["generation"] = int(state.get("generation", 0)) + 1
    state["status"] = "armed"
    state["launch_at"] = now + max(60, int(launch_after_s))
    state["last_heartbeat"] = now
    state["updated_at"] = now
    state["owner"] = "chatgpt"
    return _save(task_id, state)


def _secret() -> str:
    path = RUNTIME / "secret"
    if not path.is_file():
        raise ContinuationError("BRIDGE_SECRET_MISSING")
    value = path.read_text(encoding="ascii").strip()
    if not value:
        raise ContinuationError("BRIDGE_SECRET_EMPTY")
    return value


def _rpc(args: Mapping[str, Any], timeout: float = 15.0) -> dict[str, Any]:
    body = json.dumps({"op": "computer_use", "args": dict(args)}).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/rpc",
        data=body,
        headers={"X-FF3-Key": _secret(), "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise ContinuationError("BRIDGE_RPC_FAILED", {"type": type(exc).__name__}) from exc
    if not payload.get("ok"):
        raise ContinuationError(
            str(payload.get("error_code") or "BRIDGE_RPC_FAILED"),
            payload.get("details") if isinstance(payload.get("details"), Mapping) else {},
        )
    result = payload.get("result")
    return dict(result) if isinstance(result, Mapping) else {"value": result}


def _continuation_prompt(state: Mapping[str, Any]) -> str:
    state_path, _, _ = _paths(str(state["task_id"]))
    if state.get("mode") == "canary":
        return (
            "CONTINUATION CANARY. Do not use tools and do not re-arm anything. "
            f"Reply only with CONTINUATION-CANARY-OK-{state['task_id']}."
        )
    task_id = str(state["task_id"])
    head = _repo_head() or "unknown"
    return (
        "CONTINUATION BATON — continue the existing work autonomously.\n\n"
        f"Task id: {task_id}\n"
        f"Generation: {state.get('generation')}\n"
        f"Git HEAD: {head}\n"
        f"Durable baton: {state_path}\n\n"
        f"Goal:\n{state.get('goal','')}\n\n"
        f"Latest handoff:\n{state.get('handoff','')}\n\n"
        "The durable watcher has already scheduled the next continuation generation; do NOT start another watcher. "
        "Verify current repo/runtime state instead of restarting the project, continue autonomously, "
        "and update the baton after meaningful progress when safe. Do not wait for the user between safe steps. "
        "If the task is fully complete, mark the baton completed so the watcher stops."
    )


def _find_editor(surface_id: str) -> dict[str, Any]:
    last_error: Exception | None = None
    for _ in range(8):
        for query in (
            {"role": "textbox", "action": "fill"},
            {"role": "textarea", "action": "fill"},
            {"text": "ChatGPT", "action": "fill"},
            {"action": "fill"},
        ):
            try:
                found = _rpc({"command": "find", "surface_id": surface_id, "query": query})
                matches = found.get("matches") if isinstance(found.get("matches"), list) else []
                if len(matches) == 1 and isinstance(matches[0], Mapping):
                    return dict(matches[0])
            except Exception as exc:
                last_error = exc
        time.sleep(0.15)
    raise ContinuationError(
        "CHATGPT_EDITOR_NOT_FOUND",
        {"last_error": type(last_error).__name__ if last_error else None},
    )


_STREAM_HEALTH_MARKERS: dict[str, tuple[str, ...]] = {
    "stream_interrupted": (
        "streaming interrupted",
        "stream interrupted",
        "thinking connection interrupted",
        "error in message stream",
        "потоковая передача сообщения прервана",
        "ожидайте полного ответа",
    ),
    "reasoning_stopped": (
        "reasoning stopped",
        "thinking stopped",
        "рассуждение остановлено",
    ),
    "generation_failed": (
        "generation failed",
        "there was an error generating a response",
        "something went wrong",
        "something seems to have gone wrong",
        "ошибка при создании ответа",
        "генерация не удалась",
        "что-то пошло не так",
    ),
    "reasoning_failed": (
        "reasoning failed",
        "thinking failed",
        "рассуждение не удалось",
    ),
    "request_timeout": (
        "request timed out",
        "request timeout",
        "request time limit exceeded",
        "time limit exceeded for request",
        "превышен лимит времени на запрос",
    ),
    "rate_limited": (
        "too many requests",
        "too many concurrent requests",
        "reached concurrency limit",
        "you're making requests too quickly",
        "you’re making requests too quickly",
        "слишком много запросов",
        "слишком много параллельных запросов",
    ),
    "content_missing": (
        "content not found",
        "could not load this chatgpt conversation",
        "контент не найден",
        "не удалось загрузить этот диалог",
    ),
    "network_error": (
        "network error",
        "connection interrupted",
        "ошибка сети",
        "соединение прервано",
    ),
    "retry_banner": (
        "hmm...something seems to have gone wrong",
        "hmm…something seems to have gone wrong",
        "please try again",
        "try again",
        "не удалось. попробуйте снова",
        "попробовать снова",
    ),
}

_ACTIVE_UI_MARKERS = (
    "stop generating",
    "stop response",
    "остановить создание",
    "остановить ответ",
    "прервать ответ",
)

_THINKING_UI_MARKERS = (
    "thinking",
    "думаю",
)



def _has_retry_control(surface_id: str) -> bool:
    for text in ("Try again", "Retry", "Повторить", "Попробовать снова"):
        try:
            found = _rpc({
                "command": "find",
                "surface_id": surface_id,
                "query": {"role": "button", "text": text},
            }, timeout=5)
            matches = found.get("matches") if isinstance(found.get("matches"), list) else []
            if matches:
                return True
        except Exception:
            continue
    return False


def _health_log_path(task_id: str) -> Path:
    return STATE_ROOT / f"{_task_id(task_id)}.health.jsonl"


def _last_health_event(task_id: str) -> dict[str, Any] | None:
    path = _health_log_path(task_id)
    if not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if not lines:
            return None
        value = json.loads(lines[-1])
        return dict(value) if isinstance(value, Mapping) else None
    except Exception:
        return None


def _repo_head() -> str | None:
    if not REPO_ROOT.is_dir():
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        value = proc.stdout.strip()
        return value if proc.returncode == 0 and re.fullmatch(r"[0-9a-fA-F]{40}", value) else None
    except Exception:
        return None


def _handoff_digest(state: Mapping[str, Any]) -> str:
    return hashlib.sha256(str(state.get("handoff") or "").encode("utf-8")).hexdigest()


def _classify_successor_health(
    tree_text: str,
    *,
    repo_progress: bool = False,
    handoff_progress: bool = False,
    retry_control: bool = False,
) -> dict[str, Any]:
    text = " ".join(str(tree_text or "").lower().split())
    signals = [
        name
        for name, markers in _STREAM_HEALTH_MARKERS.items()
        if any(marker in text for marker in markers)
    ]
    if retry_control:
        signals.append("retry_control")
    active_ui = any(marker in text for marker in _ACTIVE_UI_MARKERS)
    thinking_ui = any(marker in text for marker in _THINKING_UI_MARKERS)
    progress = bool(repo_progress or handoff_progress)
    if signals and progress:
        state = "ui_degraded_work_progressing"
    elif signals:
        state = "ui_degraded_progress_unknown"
    elif progress:
        state = "work_progressing"
    elif active_ui:
        state = "ui_reports_active"
    elif thinking_ui:
        state = "ui_thinking_without_active_generation"
    else:
        state = "unknown_or_idle"
    return {
        "state": state,
        "signals": signals,
        "active_ui": active_ui,
        "thinking_ui": thinking_ui,
        "retry_control": bool(retry_control),
        "progress_evidence": {
            "repo_head_changed": bool(repo_progress),
            "handoff_changed": bool(handoff_progress),
        },
    }



def _event_has_progress(event: Mapping[str, Any] | None) -> bool:
    if not isinstance(event, Mapping):
        return False
    evidence = event.get("progress_evidence")
    return isinstance(evidence, Mapping) and any(bool(v) for v in evidence.values())


def _confirmed_failure_reason(
    current: Mapping[str, Any] | None,
    previous: Mapping[str, Any] | None,
) -> str | None:
    if not isinstance(current, Mapping) or _event_has_progress(current):
        return None
    if current.get("state") == "stalled_or_desynced_thinking":
        return "stalled_thinking"
    if current.get("state") != "ui_degraded_progress_unknown":
        return None
    current_signals = set(current.get("signals") or ())
    actionable = current_signals - {"rate_limited", "retry_control"}
    if not actionable or not isinstance(previous, Mapping) or _event_has_progress(previous):
        return None
    if int(previous.get("generation") or -1) != int(current.get("generation") or -2):
        return None
    previous_signals = set(previous.get("signals") or ()) - {"rate_limited", "retry_control"}
    overlap = sorted(actionable & previous_signals)
    if not overlap:
        return None

    # Most red/orange generation failures expose an actual Retry button.
    # Requiring the control on two samples prevents quoted error text inside the
    # conversation from being mistaken for a real ChatGPT failure. A missing
    # conversation is the exception: it may replace the whole page and expose no
    # retry button at all.
    if "content_missing" not in overlap:
        if not bool(current.get("retry_control")) or not bool(previous.get("retry_control")):
            return None
    return "confirmed_ui_failure:" + ",".join(overlap)


def _append_health_event(task_id: str, event: Mapping[str, Any]) -> None:
    path = _health_log_path(task_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if path.is_file() and path.stat().st_size > 1_000_000:
            rotated = path.with_suffix(".health.jsonl.1")
            rotated.unlink(missing_ok=True)
            os.replace(path, rotated)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(dict(event), ensure_ascii=False, separators=(",", ":")) + "\n")
    except Exception:
        pass


def _sample_successor_health(task_id: str) -> dict[str, Any] | None:
    state = _load(task_id)
    surface_id = str(state.get("active_surface_id") or "")
    baseline = state.get("successor_baseline")
    if not surface_id or not isinstance(baseline, Mapping):
        return None
    current_head = _repo_head()
    current_handoff = _handoff_digest(state)
    previous = _last_health_event(task_id)
    same_generation = bool(
        isinstance(previous, Mapping)
        and int(previous.get("generation") or -1) == int(baseline.get("generation") or -2)
    )
    reference_head = (
        previous.get("repo_head")
        if same_generation and previous.get("repo_head")
        else baseline.get("repo_head")
    )
    reference_handoff = (
        previous.get("handoff_sha256")
        if same_generation and previous.get("handoff_sha256")
        else baseline.get("handoff_sha256")
    )
    repo_progress = bool(current_head and reference_head and current_head != reference_head)
    handoff_progress = bool(
        reference_handoff
        and current_handoff != str(reference_handoff)
    )
    identity = _rpc({"command": "identity", "surface_id": surface_id})
    observation = _rpc({
        "command": "observe",
        "surface_id": surface_id,
        "options": {"mode": "aria", "maxChars": 24000},
    })
    tree_text = json.dumps(observation.get("semantic_tree") or {}, ensure_ascii=False)
    retry_control = _has_retry_control(surface_id)
    classified = _classify_successor_health(
        tree_text,
        repo_progress=repo_progress,
        handoff_progress=handoff_progress,
        retry_control=retry_control,
    )
    if (
        classified.get("state") == "ui_thinking_without_active_generation"
        and isinstance(previous, Mapping)
        and previous.get("state") in {
            "ui_thinking_without_active_generation",
            "stalled_or_desynced_thinking",
        }
        and int(previous.get("generation") or -1) == int(baseline.get("generation") or -2)
        and not any(bool(v) for v in (classified.get("progress_evidence") or {}).values())
        and not any(bool(v) for v in (previous.get("progress_evidence") or {}).values())
    ):
        classified["state"] = "stalled_or_desynced_thinking"
    event = {
        "at": time.time(),
        "task_id": task_id,
        "generation": baseline.get("generation"),
        "surface_id": surface_id,
        "url": str(identity.get("url") or ""),
        "fingerprint": str(observation.get("fingerprint") or ""),
        "repo_head": current_head,
        "handoff_sha256": current_handoff,
        **classified,
    }
    _append_health_event(task_id, event)
    return event


def launch_successor(task_id: str) -> dict[str, Any]:
    state_path, lock_path, _ = _paths(task_id)
    _acquire_launch_lock(lock_path)
    surface_id: str | None = None
    keep_surface = False
    previous_surface: str | None = None
    try:
        state = _load(task_id)
        _require_bridge_managed(state)
        if state.get("status") not in {"armed", "launching"}:
            raise ContinuationError("TASK_NOT_ARMED", {"status": state.get("status")})
        generation = int(state.get("generation", 0))
        successor_baseline = {
            "at": time.time(),
            "generation": generation,
            "repo_head": _repo_head(),
            "handoff_sha256": _handoff_digest(state),
        }
        state["status"] = "launching"
        state["launch_attempts"] = int(state.get("launch_attempts", 0)) + 1
        state["updated_at"] = time.time()
        _save(task_id, state)

        previous_surface = str(state.get("active_surface_id") or "") or None
        attached = _rpc({"command": "attach", "surface_kind": "browser", "transport": "extension"})
        surface_id = str(attached["surface_id"])
        state["active_surface_id"] = surface_id
        state["updated_at"] = time.time()
        _save(task_id, state)
        _rpc({
            "command": "navigate", "surface_id": surface_id,
            "url": "https://chatgpt.com/", "timeout_ms": 12000,
        })
        editor = _find_editor(surface_id)
        prompt = _continuation_prompt(state)

        _rpc({
            "command": "act", "surface_id": surface_id,
            "operation": "fill", "ref": editor["ref"],
            "generation": editor["generation"],
            "action_args": {"text": prompt},
            "postcondition": {"value": prompt},
            "policy": {"background_required": True, "require_verified": True},
        })
        editor = _find_editor(surface_id)
        receipt = _rpc({
            "command": "act", "surface_id": surface_id,
            "operation": "press", "ref": editor["ref"],
            "generation": editor["generation"],
            "action_args": {"key": "Enter"},
            "policy": {"background_required": True, "require_verified": False},
        })
        proof = None
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            try:
                identity = _rpc({"command": "identity", "surface_id": surface_id})
                observation = _rpc({"command": "observe", "surface_id": surface_id})
                fingerprint = str(observation.get("fingerprint") or "")
                tree = json.dumps(observation.get("semantic_tree") or {}, ensure_ascii=False)
                if ("/c/" in fingerprint or "/c/" in str(identity)) and task_id in tree:
                    proof = {"identity": identity, "fingerprint": fingerprint}
                    break
            except ContinuationError:
                pass
            time.sleep(0.2)
        if proof is None:
            raise ContinuationError("SUCCESSOR_SEND_UNVERIFIED", {"task_id": task_id})
        keep_surface = True
        if previous_surface and previous_surface != surface_id:
            try:
                _rpc({"command": "close", "surface_id": previous_surface}, timeout=5)
            except Exception:
                pass
        latest = _load(task_id)
        if int(latest.get("generation", 0)) == generation:
            latest["status"] = "successor_launched"
            latest["last_launch"] = {
                "at": time.time(),
                "generation": generation,
                "verified": bool(receipt.get("verified")),
            }
            latest["successor_baseline"] = {**successor_baseline, "surface_id": surface_id}
            latest["updated_at"] = time.time()
            _save(task_id, latest)
            try:
                _sample_successor_health(task_id)
            except Exception:
                pass
        return {
            "ok": True, "task_id": task_id, "generation": generation,
            "verified": bool(receipt.get("verified")), "state_path": str(state_path),
        }
    finally:
        if surface_id and not keep_surface:
            try:
                _rpc({"command": "close", "surface_id": surface_id}, timeout=5)
            except Exception:
                pass
        lock_path.unlink(missing_ok=True)


def watch(task_id: str, poll_s: float = 1.0) -> int:
    _, _, pid_path = _paths(task_id)
    initial = _load(task_id)
    _require_bridge_managed(initial)
    _write_pid_record(pid_path, os.getpid())
    next_health_probe = 0.0
    try:
        while True:
            state = _load(task_id)
            if not _is_bridge_managed(state):
                return 0
            status = str(state.get("status") or "")
            if status not in {"armed", "launching"}:
                return 0
            # 1. Early Completion Check: if agent physically finished the work early, stop cleanly
            if _detect_early_completion(task_id, state):
                complete(task_id)
                _append_health_event(task_id, {
                    "at": time.time(),
                    "task_id": task_id,
                    "state": "early_completion_verified",
                })
                return 0

            launch_at = float(state.get("launch_at") or 0)
            now = time.time()

            # 2. Internal Execution Active Check:
            # If the model is actively calling tools or mutating the system via Bridge,
            # dynamically extend launch_at so we never kill an active 30+ minute run!
            if _has_active_tool_execution(ACTIVE_TOOL_THRESHOLD_S):
                if now >= launch_at - 60.0:
                    state["launch_at"] = now + ACTIVE_TOOL_THRESHOLD_S
                    state["last_execution_extension"] = {
                        "at": now,
                        "reason": "ACTIVE_BRIDGE_TOOL_EXECUTION",
                    }
                    _save(task_id, state)
                    _append_health_event(task_id, {
                        "at": now,
                        "task_id": task_id,
                        "state": "active_tool_execution_extended",
                    })
                    launch_at = state["launch_at"]

            observable = bool(
                state.get("active_surface_id")
                and isinstance(state.get("successor_baseline"), Mapping)
            )
            trigger_reason = None

            if observable and now >= next_health_probe:
                previous_event = _last_health_event(task_id)
                try:
                    health_event = _sample_successor_health(task_id)
                    # Protect the 23-29m window: do NOT collapse chat on transient UI errors
                    # before the window expires, and NEVER while internal tool calls are active.
                    if now >= launch_at and not _has_active_tool_execution(ACTIVE_TOOL_THRESHOLD_S):
                        trigger_reason = _confirmed_failure_reason(
                            health_event, previous_event
                        )
                except ContinuationError as exc:
                    error_event = {
                        "at": time.time(),
                        "task_id": task_id,
                        "generation": (state.get("successor_baseline") or {}).get("generation"),
                        "state": "health_probe_error",
                        "error_code": exc.code,
                    }
                    _append_health_event(task_id, error_event)
                    if (
                        exc.code == "SURFACE_NOT_FOUND"
                        and isinstance(previous_event, Mapping)
                        and previous_event.get("state") == "health_probe_error"
                        and previous_event.get("error_code") == "SURFACE_NOT_FOUND"
                        and (now >= launch_at or not _has_active_tool_execution(ACTIVE_TOOL_THRESHOLD_S))
                    ):
                        trigger_reason = "confirmed_surface_missing"
                except Exception as exc:
                    _append_health_event(task_id, {
                        "at": time.time(),
                        "task_id": task_id,
                        "generation": (state.get("successor_baseline") or {}).get("generation"),
                        "state": "health_probe_error",
                        "error_code": type(exc).__name__,
                    })
                next_health_probe = now + 30.0

            # The timer is only a bootstrap fallback for a Bridge job that has
            # no observable ChatGPT surface yet. Once a surface exists, healthy
            # or merely idle work is never cloned because time elapsed; only a
            # confirmed UI failure/stall may trigger a successor.
            if trigger_reason is None and now >= launch_at and not observable and not _has_active_tool_execution(ACTIVE_TOOL_THRESHOLD_S):
                trigger_reason = "unobservable_bridge_fallback"

            if trigger_reason:
                try:
                    state["last_trigger_reason"] = trigger_reason
                    state["updated_at"] = time.time()
                    _save(task_id, state)
                    launch_successor(task_id)
                    state = _load(task_id)
                    state["consecutive_launch_failures"] = 0
                    _save(task_id, state)
                    if state.get("mode") == "canary":
                        return 0
                    if state.get("status") == "successor_launched":
                        rearm(task_id, DEFAULT_CONTINUATION_WINDOW_S)
                    continue
                except ContinuationError as exc:
                    state = _load(task_id)
                    failures = int(state.get("consecutive_launch_failures") or 0) + 1
                    state["consecutive_launch_failures"] = failures
                    state["last_error"] = {
                        "code": exc.code,
                        "details": exc.details,
                        "at": time.time(),
                    }
                    if failures >= 10:
                        state["status"] = "recovery_exhausted"
                        state["exhausted_reason"] = "MAX_CONSECUTIVE_LAUNCH_FAILURES_EXCEEDED"
                        _save(task_id, state)
                        return 1
                    backoff_s = min(1800, 30 * (2 ** min(failures - 1, 6)))
                    state["status"] = "armed"
                    state["launch_at"] = time.time() + backoff_s
                    _save(task_id, state)
            time.sleep(max(0.2, min(float(poll_s), 10.0)))
    finally:
        try:
            record = _read_pid_record(pid_path)
            if record is not None and record[0] == os.getpid():
                pid_path.unlink(missing_ok=True)
        except Exception:
            pass


def spawn_watch(task_id: str) -> dict[str, Any]:
    state = _load(task_id)
    _require_bridge_managed(state)
    _, _, pid_path = _paths(task_id)
    alive, pid = _pid_record_alive(pid_path)
    if alive and pid is not None:
        return {"ok": True, "already_running": True, "pid": pid}
    pid_path.unlink(missing_ok=True)
    log = STATE_ROOT / f"{_task_id(task_id)}.watcher.log"
    handle = open(log, "ab", buffering=0)
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    proc = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "watch", "--task-id", task_id],
        stdin=subprocess.DEVNULL, stdout=handle, stderr=handle,
        creationflags=flags, close_fds=True,
    )
    handle.close()
    _write_pid_record(pid_path, proc.pid)
    return {"ok": True, "already_running": False, "pid": proc.pid, "log": str(log)}


MAX_STALE_BATON_AGE_S = 1800
DAEMON_PID_PATH = STATE_ROOT / "continuation_daemon.pid"


def ensure_watchers() -> dict[str, Any]:
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    now = time.time()
    current_boot = _boot_id()
    for state_path in sorted(STATE_ROOT.glob("*.json")):
        try:
            state = json.loads(state_path.read_text(encoding="utf-8-sig"))
            task_id = _task_id(str(state.get("task_id") or state_path.stem))
            status = str(state.get("status") or "")
            if status not in {"armed", "launching"} or not _is_bridge_managed(state):
                continue

            # Stale baton protection: never revive tasks from a prior boot session or expired time
            launch_at = float(state.get("launch_at") or 0)
            updated_at = float(state.get("updated_at") or 0)
            task_boot = state.get("boot_id")

            is_stale = False
            stale_reason = None
            if task_boot is not None and abs(int(task_boot) - current_boot) > 10:
                is_stale = True
                stale_reason = "EXPIRED_PRIOR_BOOT_SESSION"
            elif now > launch_at + MAX_STALE_BATON_AGE_S:
                is_stale = True
                stale_reason = "EXPIRED_LAUNCH_TIMEOUT"
            elif updated_at > 0 and now - updated_at > 86400:
                is_stale = True
                stale_reason = "EXPIRED_MAX_AGE_TIMEOUT"

            if is_stale:
                state["status"] = "stale_expired"
                state["stale_reason"] = stale_reason
                state["expired_at"] = now
                _save(task_id, state)
                results.append({
                    "task_id": task_id,
                    "ok": True,
                    "stale_expired": True,
                    "reason": stale_reason,
                })
                continue

            result = spawn_watch(task_id)
            results.append({"task_id": task_id, **result})
        except Exception as exc:
            results.append({
                "task_id": state_path.stem, "ok": False,
                "error": f"{type(exc).__name__}:{exc}",
            })
    return {
        "ok": all(bool(item.get("ok")) for item in results),
        "armed_count": len([r for r in results if not r.get("stale_expired")]),
        "results": results,
    }


def daemon(interval_s: float = 2.0) -> int:
    alive, pid = _pid_record_alive(DAEMON_PID_PATH)
    if alive and pid is not None and pid != os.getpid():
        print(json.dumps({"ok": False, "error_code": "DAEMON_ALREADY_RUNNING", "pid": pid}))
        return 0
    _write_pid_record(DAEMON_PID_PATH, os.getpid())
    delay = max(0.5, min(float(interval_s), 30.0))
    try:
        while True:
            try:
                ensure_watchers()
            except Exception:
                pass
            time.sleep(delay)
    finally:
        try:
            record = _read_pid_record(DAEMON_PID_PATH)
            if record is not None and record[0] == os.getpid():
                DAEMON_PID_PATH.unlink(missing_ok=True)
        except Exception:
            pass


def _runtime_python() -> Path:
    path_file = RUNTIME / "python-path.txt"
    if path_file.is_file():
        candidate = Path(path_file.read_text(encoding="utf-8").strip())
        if candidate.is_file():
            return candidate
    return Path(sys.executable)


def delegate_to_antigravity(task_id: str, timeout_s: float = 30.0) -> dict[str, Any]:
    _, _, pid_path = _paths(task_id)
    runtime_script = RUNTIME / "cua_session_continuation.py"
    command = f'"{_runtime_python()}" "{runtime_script}" spawn-watch --task-id {_task_id(task_id)}'
    prompt = (
        "Use your terminal tool now. Run the following Windows command exactly once, detached watcher setup only. "
        "Do not merely explain the command. After it exits, report the PID/result. COMMAND: "
        f"{command}"
    )
    sent = _rpc({
        "command": "auto", "app": "Antigravity",
        "intent": "chat.send", "text": prompt,
    })
    deadline = time.monotonic() + max(2.0, timeout_s)
    while time.monotonic() < deadline:
        if pid_path.is_file():
            try:
                record = _read_pid_record(pid_path)
                pid = int(record[0]) if record else 0
                if _process_alive(pid):
                    return {"ok": True, "delegated": True, "pid": pid, "antigravity": sent}
            except Exception:
                pass
        time.sleep(0.5)
    raise ContinuationError("ANTIGRAVITY_DELEGATION_UNVERIFIED", {"command": command})


def rearm_spawn(task_id: str, launch_after_s: int = DEFAULT_CONTINUATION_WINDOW_S) -> dict[str, Any]:
    state = rearm(task_id, launch_after_s)
    watcher = spawn_watch(task_id)
    return {"ok": True, "state": state, "watcher": watcher}


def main() -> int:
    parser = argparse.ArgumentParser(description="Durable ChatGPT session continuation baton")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init")
    p_init.add_argument("--task-id", required=True)
    p_init.add_argument("--goal", required=True)
    p_init.add_argument("--handoff", default="")
    p_init.add_argument("--launch-after", type=int, default=DEFAULT_CONTINUATION_WINDOW_S)
    p_init.add_argument("--bridge-work", action="store_true")

    p_arm = sub.add_parser("arm")
    p_arm.add_argument("--task-id", required=True)
    p_arm.add_argument("--goal", required=True)
    p_arm.add_argument("--handoff", default="")
    p_arm.add_argument("--launch-after", type=int, default=DEFAULT_CONTINUATION_WINDOW_S)
    p_arm.add_argument("--bridge-work", action="store_true")

    for name in ("heartbeat", "complete", "status", "launch", "spawn-watch", "delegate", "mark-bridge-work"):
        p = sub.add_parser(name)
        p.add_argument("--task-id", required=True)
    sub.add_parser("ensure-watchers")

    p_update = sub.add_parser("update")
    p_update.add_argument("--task-id", required=True)
    p_update.add_argument("--handoff")
    p_update.add_argument("--note")

    p_rearm = sub.add_parser("rearm")
    p_rearm.add_argument("--task-id", required=True)
    p_rearm.add_argument("--launch-after", type=int, default=DEFAULT_CONTINUATION_WINDOW_S)

    p_rs = sub.add_parser("rearm-spawn")
    p_rs.add_argument("--task-id", required=True)
    p_rs.add_argument("--launch-after", type=int, default=DEFAULT_CONTINUATION_WINDOW_S)

    p_watch = sub.add_parser("watch")
    p_watch.add_argument("--task-id", required=True)
    p_watch.add_argument("--poll", type=float, default=1.0)

    p_daemon = sub.add_parser("daemon")
    p_daemon.add_argument("--interval", type=float, default=2.0)

    ns = parser.parse_args()
    try:
        if ns.cmd == "init":
            result = init_task(
                ns.task_id, ns.goal, ns.handoff, ns.launch_after,
                bridge_managed=bool(ns.bridge_work),
            )
        elif ns.cmd == "arm":
            result = arm_task(
                ns.task_id, ns.goal, ns.handoff, ns.launch_after,
                bridge_managed=bool(ns.bridge_work),
            )
        elif ns.cmd == "heartbeat":
            result = heartbeat(ns.task_id)
        elif ns.cmd == "complete":
            result = complete(ns.task_id)
        elif ns.cmd == "status":
            result = _load(ns.task_id)
        elif ns.cmd == "update":
            result = update_task(ns.task_id, handoff=ns.handoff, note=ns.note)
        elif ns.cmd == "rearm":
            result = rearm(ns.task_id, ns.launch_after)
        elif ns.cmd == "rearm-spawn":
            result = rearm_spawn(ns.task_id, ns.launch_after)
        elif ns.cmd == "watch":
            return watch(ns.task_id, ns.poll)
        elif ns.cmd == "daemon":
            return daemon(ns.interval)
        elif ns.cmd == "launch":
            result = launch_successor(ns.task_id)
        elif ns.cmd == "spawn-watch":
            result = spawn_watch(ns.task_id)
        elif ns.cmd == "ensure-watchers":
            result = ensure_watchers()
        elif ns.cmd == "mark-bridge-work":
            result = enable_bridge_task(ns.task_id)
        else:
            result = delegate_to_antigravity(ns.task_id, timeout_s=90.0)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except ContinuationError as exc:
        print(json.dumps({"ok": False, "error_code": exc.code, "details": exc.details}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
