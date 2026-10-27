"""Owned non-detached Windows terminal: bind the Job before user code runs.

Windows 10+/Server 2016+ JOB_LIST and an explicit stdio HANDLE_LIST are required.
No PID lookup, process-name cleanup, breakaway flag or unsafe Popen fallback.
Jobs contain ordinary CreateProcess descendants, not external broker/WMI tasks.
"""
from __future__ import annotations
import ctypes as C
import os
import shutil
import subprocess
import threading
import time

D, H, P, S = C.c_uint32, C.c_void_p, C.c_void_p, C.c_size_t


class SecurityAttributes(C.Structure):
    _fields_ = [("length", D), ("descriptor", P), ("inherit", C.c_int)]


class StartupInfo(C.Structure):
    _fields_ = [("cb", D), ("reserved", C.c_wchar_p), ("desktop", C.c_wchar_p),
                ("title", C.c_wchar_p), ("x", D), ("y", D), ("xsize", D), ("ysize", D),
                ("xchars", D), ("ychars", D), ("fill", D), ("flags", D),
                ("show", C.c_uint16), ("reserved_size", C.c_uint16), ("reserved_ptr", P),
                ("stdin", H), ("stdout", H), ("stderr", H)]


class StartupInfoEx(C.Structure):
    _fields_ = [("info", StartupInfo), ("attributes", P)]


class ProcessInfo(C.Structure):
    _fields_ = [("process", H), ("thread", H), ("pid", D), ("tid", D)]


class BasicLimits(C.Structure):
    _fields_ = [("process_time", C.c_int64), ("job_time", C.c_int64), ("flags", D),
                ("min_ws", S), ("max_ws", S), ("active_limit", D), ("affinity", S),
                ("priority", D), ("scheduling", D)]


class ExtendedLimits(C.Structure):
    _fields_ = [("basic", BasicLimits), ("io", C.c_uint64 * 6),
                ("process_memory", S), ("job_memory", S), ("peak_process", S), ("peak_job", S)]


class Accounting(C.Structure):
    _fields_ = [("times", C.c_int64 * 4), ("faults", D), ("total", D),
                ("active", D), ("terminated", D)]


def kernel_api():
    api = C.WinDLL("kernel32", use_last_error=True)
    specs = {
        "CreateJobObjectW": ([P, C.c_wchar_p], H),
        "SetInformationJobObject": ([H, C.c_int, P, D], C.c_int),
        "QueryInformationJobObject": ([H, C.c_int, P, D, P], C.c_int),
        "TerminateJobObject": ([H, D], C.c_int),
        "CloseHandle": ([H], C.c_int),
        "CreatePipe": ([C.POINTER(H), C.POINTER(H), P, D], C.c_int),
        "SetHandleInformation": ([H, D, D], C.c_int),
        "InitializeProcThreadAttributeList": ([P, D, D, C.POINTER(S)], C.c_int),
        "UpdateProcThreadAttribute": ([P, D, S, P, S, P, P], C.c_int),
        "DeleteProcThreadAttributeList": ([P], None),
        "CreateProcessW": ([C.c_wchar_p, C.c_wchar_p, P, P, C.c_int, D, P,
                            C.c_wchar_p, P, C.POINTER(ProcessInfo)], C.c_int),
        "ResumeThread": ([H], D),
        "WaitForSingleObject": ([H, D], D),
        "GetExitCodeProcess": ([H, C.POINTER(D)], C.c_int),
    }
    for name, (args, result) in specs.items():
        function = getattr(api, name)
        function.argtypes, function.restype = args, result
    return api


def require(ok, code):
    if not ok:
        raise OSError(code, "winerror=" + str(C.get_last_error()))


def launch_bound(api, job, executable, command, env_block, cwd, child_handles):
    """There is no create-then-assign interval: JOB_LIST is a creation attribute."""
    size = S()
    api.InitializeProcThreadAttributeList(None, 2, 0, C.byref(size))
    require(size.value > 0, "JOB_ATTRIBUTE_SIZE_FAILED")
    attributes = C.create_string_buffer(size.value)
    require(api.InitializeProcThreadAttributeList(attributes, 2, 0, C.byref(size)), "JOB_ATTRIBUTE_INIT_FAILED")
    info, pi = StartupInfoEx(), ProcessInfo()
    handles = (H * 3)(*child_handles)
    jobs = (H * 1)(job)
    try:
        require(api.UpdateProcThreadAttribute(attributes, 0, 0x20002, handles, C.sizeof(handles), None, None),
                "JOB_STDIO_HANDLE_LIST_FAILED")
        require(api.UpdateProcThreadAttribute(attributes, 0, 0x2000D, jobs, C.sizeof(jobs), None, None),
                "JOB_CREATION_BIND_FAILED")
        info.info.cb = C.sizeof(info)
        info.info.flags = 0x100  # STARTF_USESTDHANDLES
        info.info.stdin, info.info.stdout, info.info.stderr = child_handles
        info.attributes = C.cast(attributes, P)
        flags = 0x80000 | 0x400 | 0x4 | 0x200 | 0x8000000
        # EXTENDED_STARTUPINFO_PRESENT | UNICODE_ENVIRONMENT | SUSPENDED |
        # NEW_PROCESS_GROUP | NO_WINDOW. No breakaway; no handle inheritance
        # beyond exactly the three whitelisted child stdio handles.
        require(api.CreateProcessW(executable, C.create_unicode_buffer(command), None, None, True,
                                   flags, env_block, cwd, C.byref(info), C.byref(pi)), "OWNED_JOB_CREATE_FAILED")
        return pi
    finally:
        api.DeleteProcThreadAttributeList(attributes)


class OwnedJobProcess:
    """Small binary-stdio Popen contract for Session; job HANDLE stays private."""
    def __init__(self, argv, *, cwd, env):
        if os.name != "nt":
            raise OSError("WINDOWS_REQUIRED")
        import msvcrt
        self.stdin = self.stdout = self.stderr = None
        self._job = self._handle = None
        self.returncode = None
        self._lock = threading.RLock()
        self._api = api = kernel_api()
        all_handles, parents, children = set(), [], []
        thread = None
        try:
            executable = shutil.which(argv[0])
            require(executable is not None, "OWNED_JOB_EXECUTABLE_MISSING")
            self._job = api.CreateJobObjectW(None, None)
            require(self._job, "OWNED_JOB_CREATE_FAILED")
            limits = ExtendedLimits()
            limits.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE; neither breakaway flag.
            require(api.SetInformationJobObject(self._job, 9, C.byref(limits), C.sizeof(limits)),
                    "OWNED_JOB_LIMIT_FAILED")
            sa = SecurityAttributes(C.sizeof(SecurityAttributes), None, True)
            for index in range(3):
                read, write = H(), H()
                require(api.CreatePipe(C.byref(read), C.byref(write), C.byref(sa), 0), "OWNED_JOB_PIPE_FAILED")
                all_handles.update((read.value, write.value))
                child, parent = (read.value, write.value) if index == 0 else (write.value, read.value)
                require(api.SetHandleInformation(parent, 1, 0), "OWNED_JOB_PIPE_INHERIT_FAILED")
                children.append(child)
                parents.append(parent)
            # Windows requires a case-insensitively sorted, double-NUL block.
            environment = C.create_unicode_buffer("\0".join(k + "=" + v for k, v in sorted(
                env.items(), key=lambda item: item[0].upper())) + "\0\0")
            pi = launch_bound(api, self._job, executable, subprocess.list2cmdline(argv), environment, cwd, children)
            self._handle, thread, self.pid = pi.process, pi.thread, pi.pid
            for handle in children:
                api.CloseHandle(handle)
                all_handles.remove(handle)
            streams = []
            for index, handle in enumerate(parents):
                fd = msvcrt.open_osfhandle(handle, os.O_BINARY | (os.O_WRONLY if index == 0 else os.O_RDONLY))
                all_handles.remove(handle)  # fd now owns the kernel handle.
                try:
                    streams.append(os.fdopen(fd, "wb" if index == 0 else "rb"))
                except BaseException:
                    os.close(fd)
                    raise
                if index == 0: self.stdin = streams[-1]
                elif index == 1: self.stdout = streams[-1]
                else: self.stderr = streams[-1]
            require(api.ResumeThread(thread) != 0xFFFFFFFF, "OWNED_JOB_RESUME_FAILED")
        except BaseException:
            self.close()  # Killing the job also kills a still-suspended child.
            raise
        finally:
            if thread: api.CloseHandle(thread)
            for handle in all_handles: api.CloseHandle(handle)

    def poll(self):
        with self._lock:
            if self.returncode is not None:
                return self.returncode
            result = self._api.WaitForSingleObject(self._handle, 0)
            if result == 258:
                return None
            require(result == 0, "OWNED_JOB_PROCESS_WAIT_FAILED")
            code = D()
            require(self._api.GetExitCodeProcess(self._handle, C.byref(code)), "OWNED_JOB_EXIT_QUERY_FAILED")
            self.returncode = code.value
            return self.returncode

    def wait(self, timeout=None):
        milliseconds = 0xFFFFFFFF if timeout is None else min(int(max(0, timeout) * 1000), 0xFFFFFFFE)
        result = self._api.WaitForSingleObject(self._handle, milliseconds)
        if result == 258:
            raise subprocess.TimeoutExpired(["owned-job"], timeout)
        require(result == 0, "OWNED_JOB_PROCESS_WAIT_FAILED")
        return self.poll()

    def active_members(self):
        info = Accounting()
        require(self._api.QueryInformationJobObject(self._job, 1, C.byref(info), C.sizeof(info), None),
                "OWNED_JOB_ACCOUNTING_FAILED")
        return info.active

    def terminate(self):
        require(self._api.TerminateJobObject(self._job, 1), "OWNED_JOB_TERMINATION_FAILED")

    kill = terminate

    def terminate_tree(self, timeout=10):
        self.terminate()
        self.wait(timeout=timeout)
        deadline = time.monotonic() + timeout
        while self.active_members():
            if time.monotonic() >= deadline:
                raise OSError("OWNED_JOB_CLEANUP_UNCONFIRMED")
            time.sleep(.02)
        return {"termination_scope": "owned_job_members", "descendant_cleanup_verified": True,
                "external_broker_children_verified": False}

    def close(self):
        api = getattr(self, "_api", None)
        if api:
            if self._job:
                api.CloseHandle(self._job)
                self._job = None
            if self._handle:
                api.CloseHandle(self._handle)
                self._handle = None
        for name in ("stdin", "stdout", "stderr"):
            stream = getattr(self, name, None)
            if stream:
                stream.close()
                setattr(self, name, None)

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
