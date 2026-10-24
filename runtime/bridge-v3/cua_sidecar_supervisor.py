from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


class SidecarError(RuntimeError):
    def __init__(self, code: str, *, details: Mapping[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


def _bind_windows_kill_on_close_job(proc: subprocess.Popen[str]) -> int | None:
    """Bind a Windows child to a job that dies with the owning agent process."""
    if os.name != "nt":
        return None

    import ctypes
    from ctypes import wintypes

    class _IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimitInformation),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        error = ctypes.get_last_error()
        raise OSError(error, "CreateJobObjectW failed")
    try:
        info = _ExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
            error = ctypes.get_last_error()
            raise OSError(error, "SetInformationJobObject failed")

        # PROCESS_TERMINATE | PROCESS_SET_QUOTA are required by AssignProcessToJobObject.
        process_handle = kernel32.OpenProcess(0x0001 | 0x0100, False, int(proc.pid))
        if not process_handle:
            error = ctypes.get_last_error()
            raise OSError(error, "OpenProcess for job assignment failed")
        try:
            if not kernel32.AssignProcessToJobObject(job, process_handle):
                error = ctypes.get_last_error()
                raise OSError(error, "AssignProcessToJobObject failed")
        finally:
            kernel32.CloseHandle(process_handle)
    except Exception:
        kernel32.CloseHandle(job)
        raise
    return int(job)


def _close_windows_job_handle(handle: int | None) -> None:
    if handle is None:
        return
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(wintypes.HANDLE(handle))


@dataclass(frozen=True)
class SidecarHealth:
    name: str
    running: bool
    pid: int | None
    restart_count: int
    request_count: int
    timeout_count: int
    crash_count: int
    protocol_error_count: int
    last_error: str | None


class JsonLineSidecarSupervisor:
    """Fail-closed restartable boundary for local JSON-lines sidecars.

    Requests are serialized per child. Timeout, child exit, malformed output or
    response-id mismatch invalidates the child and restarts on the next request.
    Stderr is drained independently so a noisy child cannot deadlock on a full pipe.
    """

    def __init__(
        self,
        name: str,
        argv: Sequence[str],
        *,
        cwd: str | Path | None = None,
        env: Mapping[str, str] | None = None,
        timeout_seconds: float = 3.0,
        startup_grace_seconds: float = 0.05,
        max_line_chars: int = 2_000_000,
        multiplex: bool = False,
    ):
        if not name:
            raise ValueError("name is required")
        if not argv:
            raise ValueError("argv is required")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.name = name
        self.argv = [str(x) for x in argv]
        self.cwd = str(cwd) if cwd is not None else None
        self.env = dict(env) if env is not None else None
        self.timeout_seconds = float(timeout_seconds)
        self.startup_grace_seconds = max(0.0, float(startup_grace_seconds))
        self.max_line_chars = int(max_line_chars)
        self.multiplex = bool(multiplex)
        self.process: subprocess.Popen[str] | None = None
        self._job_handle: int | None = None
        self._responses: queue.Queue[dict[str, Any]] = queue.Queue()
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None
        self._request_lock = threading.Lock()
        self._write_lock = threading.RLock()
        self._pending_lock = threading.Lock()
        self._pending: dict[str, queue.Queue[dict[str, Any]]] = {}
        self._stderr_tail: list[str] = []
        self.restart_count = 0
        self.request_count = 0
        self.timeout_count = 0
        self.crash_count = 0
        self.protocol_error_count = 0
        self.last_error: str | None = None

    def start(self) -> None:
        if self.process is not None and self.process.poll() is None:
            return
        child_env = os.environ.copy()
        if self.env:
            child_env.update(self.env)
        response_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self._responses = response_queue
        pending: dict[str, queue.Queue[dict[str, Any]]] = {}
        if self.multiplex:
            with self._pending_lock:
                self._pending = pending
        self._stderr_tail = []
        self.process = subprocess.Popen(
            self.argv,
            cwd=self.cwd,
            env=child_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            bufsize=1,
        )
        try:
            self._job_handle = _bind_windows_kill_on_close_job(self.process)
        except OSError as exc:
            failed_pid = self.process.pid
            self.last_error = "SIDECAR_CONTAINMENT_FAILED"
            details = {
                "name": self.name,
                "pid": failed_pid,
                "winerror": getattr(exc, "winerror", None) or getattr(exc, "errno", None),
                "error": str(exc),
            }
            self._invalidate(kill=True)
            raise SidecarError("SIDECAR_CONTAINMENT_FAILED", details=details) from exc
        self._reader = threading.Thread(
            target=self._read_loop, args=(self.process, response_queue, pending), daemon=True
        )
        self._stderr_reader = threading.Thread(target=self._stderr_loop, args=(self.process,), daemon=True)
        self._reader.start()
        self._stderr_reader.start()
        if self.startup_grace_seconds:
            time.sleep(self.startup_grace_seconds)
        if self.process.poll() is not None:
            self.crash_count += 1
            code = self.process.returncode
            self.last_error = "SIDECAR_START_FAILED"
            self._invalidate(kill=False)
            raise SidecarError(
                "SIDECAR_START_FAILED",
                details={"name": self.name, "exit_code": code, "stderr_tail": self.stderr_tail},
            )

    @property
    def stderr_tail(self) -> list[str]:
        return list(self._stderr_tail[-20:])

    def health(self) -> dict[str, Any]:
        proc = self.process
        state = SidecarHealth(
            name=self.name,
            running=bool(proc is not None and proc.poll() is None),
            pid=proc.pid if proc is not None and proc.poll() is None else None,
            restart_count=self.restart_count,
            request_count=self.request_count,
            timeout_count=self.timeout_count,
            crash_count=self.crash_count,
            protocol_error_count=self.protocol_error_count,
            last_error=self.last_error,
        )
        return asdict(state)

    def stop(self) -> None:
        self._invalidate(kill=True)

    def restart(self) -> None:
        self._invalidate(kill=True)
        self.restart_count += 1
        self.start()

    def request(
        self,
        op: str,
        args: Mapping[str, Any] | None = None,
        *,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        if not op:
            raise ValueError("op is required")
        timeout = self.timeout_seconds if timeout_seconds is None else float(timeout_seconds)
        if timeout <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.multiplex:
            return self._request_multiplexed(op, args, timeout)
        with self._request_lock:
            self.start()
            proc = self.process
            assert proc is not None
            if proc.poll() is not None:
                self.crash_count += 1
                code = proc.returncode
                self.last_error = "SIDECAR_EXITED"
                self._invalidate(kill=False)
                raise SidecarError(
                    "SIDECAR_EXITED",
                    details={"name": self.name, "exit_code": code, "stderr_tail": self.stderr_tail},
                )
            assert proc.stdin is not None
            request_id = uuid.uuid4().hex
            payload = {"id": request_id, "op": op, "args": dict(args or {})}
            try:
                proc.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
                proc.stdin.flush()
            except (BrokenPipeError, OSError) as exc:
                self.crash_count += 1
                self.last_error = "SIDECAR_WRITE_FAILED"
                self._invalidate(kill=True)
                raise SidecarError(
                    "SIDECAR_WRITE_FAILED",
                    details={"name": self.name, "stderr_tail": self.stderr_tail},
                ) from exc
            self.request_count += 1
            try:
                response = self._responses.get(timeout=timeout)
            except queue.Empty as exc:
                proc_now = self.process
                if proc_now is not None and proc_now.poll() is not None:
                    self.crash_count += 1
                    code = proc_now.returncode
                    self.last_error = "SIDECAR_EXITED"
                    self._invalidate(kill=False)
                    raise SidecarError(
                        "SIDECAR_EXITED",
                        details={"name": self.name, "exit_code": code, "stderr_tail": self.stderr_tail},
                    ) from exc
                self.timeout_count += 1
                self.restart_count += 1
                self.last_error = "SIDECAR_TIMEOUT"
                self._invalidate(kill=True)
                raise SidecarError(
                    "SIDECAR_TIMEOUT",
                    details={"name": self.name, "timeout_seconds": timeout, "stderr_tail": self.stderr_tail},
                ) from exc
            if response.get("_protocol_error"):
                self.protocol_error_count += 1
                self.restart_count += 1
                code = str(response.get("_protocol_error"))
                self.last_error = code
                details = dict(response.get("details") or {})
                self._invalidate(kill=True)
                raise SidecarError(code, details={"name": self.name, **details})
            if response.get("id") != request_id:
                self.protocol_error_count += 1
                self.restart_count += 1
                self.last_error = "SIDECAR_PROTOCOL_DESYNC"
                got = response.get("id")
                self._invalidate(kill=True)
                raise SidecarError(
                    "SIDECAR_PROTOCOL_DESYNC",
                    details={"name": self.name, "expected_id": request_id, "got_id": got},
                )
            self.last_error = None
            return response

    def _request_multiplexed(
        self,
        op: str,
        args: Mapping[str, Any] | None,
        timeout: float,
    ) -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        response_queue: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=1)
        payload = {"id": request_id, "op": op, "args": dict(args or {})}
        with self._write_lock:
            self.start()
            proc = self.process
            assert proc is not None
            if proc.poll() is not None:
                self.crash_count += 1
                code = proc.returncode
                self.last_error = "SIDECAR_EXITED"
                self._invalidate(kill=False)
                raise SidecarError("SIDECAR_EXITED", details={"name": self.name, "exit_code": code, "stderr_tail": self.stderr_tail})
            assert proc.stdin is not None
            with self._pending_lock:
                self._pending[request_id] = response_queue
            try:
                proc.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
                proc.stdin.flush()
                self.request_count += 1
            except (BrokenPipeError, OSError) as exc:
                with self._pending_lock:
                    self._pending.pop(request_id, None)
                self.crash_count += 1
                self.last_error = "SIDECAR_WRITE_FAILED"
                self._invalidate(kill=True)
                raise SidecarError("SIDECAR_WRITE_FAILED", details={"name": self.name, "stderr_tail": self.stderr_tail}) from exc
        try:
            response = response_queue.get(timeout=timeout)
        except queue.Empty as exc:
            with self._pending_lock:
                self._pending.pop(request_id, None)
            proc_now = self.process
            if proc_now is not None and proc_now.poll() is not None:
                self.crash_count += 1
                code = proc_now.returncode
                self.last_error = "SIDECAR_EXITED"
                self._invalidate(kill=False)
                raise SidecarError("SIDECAR_EXITED", details={"name": self.name, "exit_code": code, "stderr_tail": self.stderr_tail}) from exc
            self.timeout_count += 1
            self.restart_count += 1
            self.last_error = "SIDECAR_TIMEOUT"
            self._invalidate(kill=True)
            raise SidecarError("SIDECAR_TIMEOUT", details={"name": self.name, "timeout_seconds": timeout, "stderr_tail": self.stderr_tail}) from exc
        finally:
            with self._pending_lock:
                self._pending.pop(request_id, None)
        if response.get("_protocol_error"):
            self.protocol_error_count += 1
            self.restart_count += 1
            code = str(response.get("_protocol_error"))
            self.last_error = code
            details = dict(response.get("details") or {})
            self._invalidate(kill=True)
            raise SidecarError(code, details={"name": self.name, **details})
        if response.get("id") != request_id:
            self.protocol_error_count += 1
            self.restart_count += 1
            self.last_error = "SIDECAR_PROTOCOL_DESYNC"
            got = response.get("id")
            self._invalidate(kill=True)
            raise SidecarError("SIDECAR_PROTOCOL_DESYNC", details={"name": self.name, "expected_id": request_id, "got_id": got})
        self.last_error = None
        return response

    def _kill_process_tree(self, proc: subprocess.Popen[str]) -> None:
        if proc.poll() is not None:
            return
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=2.0,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        if proc.poll() is None:
            proc.kill()

    def _invalidate(self, *, kill: bool) -> None:
        with self._write_lock:
            proc = self.process
            job_handle = self._job_handle
            self.process = None
            self._job_handle = None
            self._responses = queue.Queue()
            pending_targets = []
            if self.multiplex:
                with self._pending_lock:
                    pending_targets = list(self._pending.values())
                    self._pending = {}
        if pending_targets:
            error = {"_protocol_error": "SIDECAR_INVALIDATED"}
            for target in pending_targets:
                try:
                    target.put_nowait(error)
                except queue.Full:
                    pass
        # Closing a KILL_ON_JOB_CLOSE handle terminates the whole Windows
        # sidecar tree, including grandchildren. Keep taskkill as a fallback
        # for pre-job or non-job children and for tests that inject fake procs.
        _close_windows_job_handle(job_handle)
        if proc is None:
            return
        if proc.poll() is None and kill:
            self._kill_process_tree(proc)
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                self._kill_process_tree(proc)
                proc.wait(timeout=1)
            except Exception:
                pass
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass

    def _read_loop(
        self,
        proc: subprocess.Popen[str],
        responses: queue.Queue[dict[str, Any]],
        pending: dict[str, queue.Queue[dict[str, Any]]] | None = None,
    ) -> None:
        if proc.stdout is None:
            return

        def deliver_protocol_error(error: dict[str, Any]) -> None:
            if not self.multiplex:
                responses.put(error)
                return
            with self._pending_lock:
                targets = list((pending or {}).values())
            for target in targets:
                try:
                    target.put_nowait(error)
                except queue.Full:
                    pass

        for raw_line in proc.stdout:
            if len(raw_line) > self.max_line_chars:
                deliver_protocol_error(
                    {"_protocol_error": "SIDECAR_RESPONSE_TOO_LARGE", "details": {"chars": len(raw_line)}}
                )
                return
            try:
                item = json.loads(raw_line)
            except json.JSONDecodeError:
                deliver_protocol_error({"_protocol_error": "SIDECAR_PROTOCOL_INVALID_JSON"})
                return
            if not isinstance(item, dict):
                deliver_protocol_error({"_protocol_error": "SIDECAR_PROTOCOL_NOT_OBJECT"})
                return
            if not self.multiplex:
                responses.put(item)
                continue
            request_id = item.get("id")
            with self._pending_lock:
                target = (pending or {}).get(request_id) if isinstance(request_id, str) else None
            if target is None:
                deliver_protocol_error(
                    {"_protocol_error": "SIDECAR_PROTOCOL_DESYNC", "details": {"got_id": request_id}}
                )
                return
            try:
                target.put_nowait(item)
            except queue.Full:
                return

    def _stderr_loop(self, proc: subprocess.Popen[str]) -> None:
        if proc.stderr is None:
            return
        for line in proc.stderr:
            clean = line.rstrip("\r\n")
            if clean:
                self._stderr_tail.append(clean[-2000:])
                if len(self._stderr_tail) > 50:
                    del self._stderr_tail[:-50]
