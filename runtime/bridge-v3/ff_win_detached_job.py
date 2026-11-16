"""Persistent named Windows Job Object + EOF-Pipe stdin for detached Bridge sessions."""
from __future__ import annotations

import ctypes as C
import os
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

D, H, P, S = C.c_uint32, C.c_void_p, C.c_void_p, C.c_size_t

JOB_OBJECT_ASSIGN_PROCESS = 0x0001
JOB_OBJECT_SET_ATTRIBUTES = 0x0002
JOB_OBJECT_QUERY = 0x0004
JOB_OBJECT_TERMINATE = 0x0008

PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D


class SecurityAttributes(C.Structure):
    _fields_ = [("length", D), ("descriptor", P), ("inherit", C.c_int)]


class StartupInfo(C.Structure):
    _fields_ = [
        ("cb", D), ("reserved", C.c_wchar_p), ("desktop", C.c_wchar_p),
        ("title", C.c_wchar_p), ("x", D), ("y", D), ("xsize", D), ("ysize", D),
        ("xchars", D), ("ychars", D), ("fill", D), ("flags", D),
        ("show", C.c_uint16), ("reserved_size", C.c_uint16), ("reserved_ptr", P),
        ("stdin", H), ("stdout", H), ("stderr", H),
    ]


class StartupInfoEx(C.Structure):
    _fields_ = [("info", StartupInfo), ("attributes", P)]


class ProcessInfo(C.Structure):
    _fields_ = [("process", H), ("thread", H), ("pid", D), ("tid", D)]


class BasicLimits(C.Structure):
    _fields_ = [
        ("process_time", C.c_int64), ("job_time", C.c_int64), ("flags", D),
        ("min_ws", S), ("max_ws", S), ("active_limit", D), ("affinity", S),
        ("priority", D), ("scheduling", D),
    ]


class ExtendedLimits(C.Structure):
    _fields_ = [
        ("basic", BasicLimits), ("io", C.c_uint64 * 6),
        ("process_memory", S), ("job_memory", S),
        ("peak_process", S), ("peak_job", S),
    ]


class Accounting(C.Structure):
    _fields_ = [
        ("times", C.c_int64 * 4), ("faults", D),
        ("total", D), ("active", D), ("terminated", D),
    ]


def kernel_api():
    api = C.WinDLL("kernel32", use_last_error=True)
    specs = {
        "CreateJobObjectW": ([P, C.c_wchar_p], H),
        "OpenJobObjectW": ([D, C.c_int, C.c_wchar_p], H),
        "SetInformationJobObject": ([H, C.c_int, P, D], C.c_int),
        "QueryInformationJobObject": ([H, C.c_int, P, D, P], C.c_int),
        "TerminateJobObject": ([H, D], C.c_int),
        "CreatePipe": ([C.POINTER(H), C.POINTER(H), P, D], C.c_int),
        "CreateFileW": ([C.c_wchar_p, D, D, P, D, D, H], H),
        "CloseHandle": ([H], C.c_int),
        "InitializeProcThreadAttributeList": ([P, D, D, C.POINTER(S)], C.c_int),
        "UpdateProcThreadAttribute": ([P, D, S, P, S, P, P], C.c_int),
        "DeleteProcThreadAttributeList": ([P], None),
        "CreateProcessW": (
            [C.c_wchar_p, C.c_wchar_p, P, P, C.c_int, D, P, C.c_wchar_p, P, C.POINTER(ProcessInfo)],
            C.c_int,
        ),
        "ResumeThread": ([H], D),
        "WaitForSingleObject": ([H, D], D),
        "GetExitCodeProcess": ([H, C.POINTER(D)], C.c_int),
    }
    for name, (args, result) in specs.items():
        fn = getattr(api, name)
        fn.argtypes, fn.restype = args, result
    return api


def require(ok, code: str) -> None:
    if not ok:
        raise OSError(code, f"winerror={C.get_last_error()}")


def detached_job_name(session_id: str) -> str:
    if not isinstance(session_id, str) or not re.fullmatch(r"[0-9a-f]{16}", session_id):
        raise ValueError("DETACHED_SESSION_ID_INVALID")
    return f"Local\\FFWinBridgeDetached_{session_id}"


def open_detached_job(session_id: str):
    if os.name != "nt":
        return None
    api = kernel_api()
    name = detached_job_name(session_id)
    handle = api.OpenJobObjectW(JOB_OBJECT_TERMINATE | JOB_OBJECT_QUERY, False, name)
    return handle if handle else None


def detached_job_active_members(session_id: str) -> int | None:
    """None means no named job; query errors must remain visible."""
    if os.name != "nt":
        return None
    api = kernel_api()
    job = open_detached_job(session_id)
    if not job:
        return None
    try:
        info = Accounting()
        require(api.QueryInformationJobObject(job, 1, C.byref(info), C.sizeof(info), None),
                "DETACHED_JOB_ACCOUNTING_FAILED")
        return int(info.active)
    finally:
        api.CloseHandle(job)


def terminate_detached_job_by_name(session_id: str, timeout: float = 10.0) -> dict | None:
    if os.name != "nt":
        return None
    api = kernel_api()
    job = open_detached_job(session_id)
    if not job:
        return None
    try:
        require(api.TerminateJobObject(job, 1), "DETACHED_JOB_TERMINATION_FAILED")
        deadline = time.monotonic() + max(0.5, timeout)
        while True:
            info = Accounting()
            require(
                api.QueryInformationJobObject(job, 1, C.byref(info), C.sizeof(info), None),
                "DETACHED_JOB_ACCOUNTING_FAILED",
            )
            if info.active == 0:
                break
            if time.monotonic() >= deadline:
                raise OSError("DETACHED_JOB_CLEANUP_UNCONFIRMED")
            time.sleep(0.02)
        return {
            "termination_scope": "detached_named_job_members",
            "descendant_cleanup_verified": True,
            "external_broker_children_verified": False,
        }
    finally:
        api.CloseHandle(job)


def _launch_detached_bound(api, job, executable: str, command: str, env_block, cwd: str,
                           stdin_pipe_r, log_h):
    size = S()
    api.InitializeProcThreadAttributeList(None, 2, 0, C.byref(size))
    require(size.value > 0, "DETACHED_JOB_ATTR_SIZE_FAILED")
    attributes = C.create_string_buffer(size.value)
    require(
        api.InitializeProcThreadAttributeList(attributes, 2, 0, C.byref(size)),
        "DETACHED_JOB_ATTR_INIT_FAILED",
    )
    info, pi = StartupInfoEx(), ProcessInfo()
    unique_handles = []
    for h in (stdin_pipe_r, log_h, job):
        if h and h not in unique_handles:
            unique_handles.append(h)
    handle_array = (H * len(unique_handles))(*unique_handles)
    jobs = (H * 1)(job)
    try:
        require(
            api.UpdateProcThreadAttribute(
                attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                handle_array, C.sizeof(handle_array), None, None,
            ),
            "DETACHED_JOB_HANDLE_LIST_FAILED",
        )
        require(
            api.UpdateProcThreadAttribute(
                attributes, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                jobs, C.sizeof(jobs), None, None,
            ),
            "DETACHED_JOB_BIND_FAILED",
        )
        info.info.cb = C.sizeof(info)
        info.info.flags = 0x100
        info.info.stdin = stdin_pipe_r
        info.info.stdout = log_h
        info.info.stderr = log_h
        info.attributes = C.cast(attributes, P)
        flags = 0x80000 | 0x400 | 0x4 | 0x200 | 0x8000000
        require(
            api.CreateProcessW(
                executable, C.create_unicode_buffer(command), None, None, True,
                flags, env_block, cwd, C.byref(info), C.byref(pi),
            ),
            "DETACHED_JOB_CREATE_PROCESS_FAILED",
        )
        return pi
    finally:
        api.DeleteProcThreadAttributeList(attributes)


class DetachedJobProcess:
    """Restart-surviving named-Job wrapper with EOF-pipe stdin for detached sessions."""

    def __init__(self, argv: list[str], *, cwd: str, env: dict[str, str],
                 session_id: str, log_file: Path):
        if os.name != "nt":
            raise OSError("WINDOWS_REQUIRED")
        self.stdin = self.stdout = self.stderr = None
        self._job = self._handle = None
        self.returncode: int | None = None
        self.exit_code_known = True
        self.session_id = session_id
        self.job_name = detached_job_name(session_id)
        self._lock = threading.RLock()
        self._api = api = kernel_api()

        r_pipe = H()
        w_pipe = H()
        log_handle = thread = None
        INVALID_HANDLE_VALUE = C.c_void_p(-1).value
        try:
            executable = shutil.which(argv[0])
            require(executable is not None, "DETACHED_JOB_EXECUTABLE_MISSING")
            sa_inherit = SecurityAttributes(C.sizeof(SecurityAttributes), None, True)

            self._job = api.CreateJobObjectW(C.byref(sa_inherit), self.job_name)
            require(bool(self._job), "DETACHED_JOB_CREATE_FAILED")
            limits = ExtendedLimits()
            limits.basic.flags = 0
            require(
                api.SetInformationJobObject(self._job, 9, C.byref(limits), C.sizeof(limits)),
                "DETACHED_JOB_LIMIT_FAILED",
            )

            require(api.CreatePipe(C.byref(r_pipe), C.byref(w_pipe), C.byref(sa_inherit), 0), "DETACHED_JOB_EOF_PIPE_FAILED")
            api.CloseHandle(w_pipe.value)
            w_pipe.value = None

            log_file.parent.mkdir(parents=True, exist_ok=True)
            log_handle = api.CreateFileW(
                str(log_file), 0x0004, 7, C.byref(sa_inherit), 4, 0x80, None
            )
            require(log_handle and log_handle != INVALID_HANDLE_VALUE, "DETACHED_JOB_LOG_OPEN_FAILED")

            env_copy = dict(env)
            env_copy.setdefault("PYTHON_BASIC_REPL", "1")
            env_copy.setdefault("PYTHONIOENCODING", "utf-8")

            environment = C.create_unicode_buffer(
                "\0".join(
                    f"{k}={v}" for k, v in sorted(env_copy.items(), key=lambda item: item[0].upper())
                ) + "\0\0"
            )
            pi = _launch_detached_bound(
                api, self._job, executable, subprocess.list2cmdline(argv),
                environment, cwd, r_pipe.value, log_handle,
            )
            self._handle, thread, self.pid = pi.process, pi.thread, pi.pid
            require(api.ResumeThread(thread) != 0xFFFFFFFF, "DETACHED_JOB_RESUME_FAILED")
        except BaseException:
            if self._job:
                try:
                    api.TerminateJobObject(self._job, 1)
                except Exception:
                    pass
            self.close()
            raise
        finally:
            if thread:
                api.CloseHandle(thread)
            if w_pipe.value:
                api.CloseHandle(w_pipe.value)
            if r_pipe.value:
                api.CloseHandle(r_pipe.value)
            if log_handle and log_handle != INVALID_HANDLE_VALUE:
                api.CloseHandle(log_handle)

    def poll(self) -> int | None:
        with self._lock:
            if self.returncode is not None:
                return self.returncode
            if not self._handle:
                return None
            result = self._api.WaitForSingleObject(self._handle, 0)
            if result == 258:
                return None
            require(result == 0, "DETACHED_JOB_WAIT_FAILED")
            code = D()
            require(self._api.GetExitCodeProcess(self._handle, C.byref(code)), "DETACHED_JOB_EXIT_QUERY_FAILED")
            self.returncode = code.value
            return self.returncode

    def wait(self, timeout: float | None = None) -> int | None:
        milliseconds = 0xFFFFFFFF if timeout is None else min(int(max(0.0, timeout) * 1000), 0xFFFFFFFE)
        result = self._api.WaitForSingleObject(self._handle, milliseconds)
        if result == 258:
            raise subprocess.TimeoutExpired(["detached-job", str(self.pid)], timeout)
        require(result == 0, "DETACHED_JOB_WAIT_FAILED")
        return self.poll()

    def active_members(self) -> int:
        info = Accounting()
        require(
            self._api.QueryInformationJobObject(self._job, 1, C.byref(info), C.sizeof(info), None),
            "DETACHED_JOB_ACCOUNTING_FAILED",
        )
        return int(info.active)

    def terminate(self) -> None:
        require(self._api.TerminateJobObject(self._job, 1), "DETACHED_JOB_TERMINATION_FAILED")

    kill = terminate

    def terminate_tree(self, timeout: float = 10.0) -> dict:
        self.terminate()
        try:
            self.wait(timeout=timeout)
        except Exception:
            pass
        deadline = time.monotonic() + max(0.5, timeout)
        while self.active_members() > 0:
            if time.monotonic() >= deadline:
                raise OSError("DETACHED_JOB_CLEANUP_UNCONFIRMED")
            time.sleep(0.02)
        return {
            "termination_scope": "detached_named_job_members",
            "descendant_cleanup_verified": True,
            "external_broker_children_verified": False,
        }

    def close(self) -> None:
        api = getattr(self, "_api", None)
        if api:
            if self._job:
                api.CloseHandle(self._job)
                self._job = None
            if self._handle:
                api.CloseHandle(self._handle)
                self._handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
