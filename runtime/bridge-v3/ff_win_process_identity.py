"""Windows process identity, retained observation and exact-handle termination.

Observation is read-only. ProcessReference.terminate is an explicit mutation
used only after the Bridge's existing operation authorization checks.
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes
import os
import threading


class _FileTime(ctypes.Structure):
    _fields_=[
        ("low",ctypes.wintypes.DWORD),
        ("high",ctypes.wintypes.DWORD),
    ]


def process_creation_token(pid: int) -> int | None:
    """Return 64-bit Windows process creation FILETIME, fail closed if unknown."""
    if os.name!="nt" or type(pid) is not int or not 0 < pid <= 0xffffffff:
        return None
    try:
        kernel=ctypes.windll.kernel32
        open_process=kernel.OpenProcess
        open_process.argtypes=[ctypes.wintypes.DWORD,ctypes.wintypes.BOOL,
                               ctypes.wintypes.DWORD]
        open_process.restype=ctypes.wintypes.HANDLE
        close=kernel.CloseHandle
        close.argtypes=[ctypes.wintypes.HANDLE]
        close.restype=ctypes.wintypes.BOOL
        times=kernel.GetProcessTimes
        times.argtypes=[
            ctypes.wintypes.HANDLE,ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
        ]
        times.restype=ctypes.wintypes.BOOL
        handle=open_process(0x1000,False,pid)
        if not handle:
            return None
        try:
            start=_FileTime()
            exit_time=_FileTime()
            kernel_time=_FileTime()
            user_time=_FileTime()
            if not times(handle,ctypes.byref(start),ctypes.byref(exit_time),
                         ctypes.byref(kernel_time),ctypes.byref(user_time)):
                return None
            # An exited process may retain a valid queryable HANDLE. Its birth
            # identity alone does not mean that the task is still running.
            if exit_time.high or exit_time.low:
                return None
            token=(int(start.high)<<32)|int(start.low)
            return token if token>0 else None
        finally:
            close(handle)
    except (OSError,ValueError,AttributeError,TypeError):
        return None


def process_identity_matches(pid: int, token: object) -> bool:
    """False on legacy records, PID recycling, stopped or inaccessible tasks."""
    if type(pid) is not int or pid<=0 or type(token) is not int or token<=0:
        return False
    current=process_creation_token(pid)
    return current is not None and current==token


def _kernel_api():
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    signatures = {
        "OpenProcess": ([ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD], ctypes.wintypes.HANDLE),
        "CloseHandle": ([ctypes.wintypes.HANDLE], ctypes.wintypes.BOOL),
        "GetProcessTimes": ([ctypes.wintypes.HANDLE] + [ctypes.POINTER(_FileTime)] * 4, ctypes.wintypes.BOOL),
        "GetExitCodeProcess": ([ctypes.wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.DWORD)], ctypes.wintypes.BOOL),
        "WaitForSingleObject": ([ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD], ctypes.wintypes.DWORD),
        "TerminateProcess": ([ctypes.wintypes.HANDLE, ctypes.wintypes.UINT], ctypes.wintypes.BOOL),
    }
    for name, (args, result) in signatures.items():
        function = getattr(kernel, name)
        function.argtypes, function.restype = args, result
    return kernel


def _handle_birth(kernel, handle):
    values = [_FileTime() for _ in range(4)]
    if not kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
        raise OSError("PROCESS_IDENTITY_UNAVAILABLE")
    return (int(values[0].high) << 32) | int(values[0].low)


class ProcessReference:
    """A retained kernel object, rather than a re-opened PID on each poll.

    Only query/synchronize rights are requested for observation. Termination
    separately obtains and verifies its own exact-object handle.
    """
    def __init__(self, pid, token):
        self._handle = None
        self._lock = threading.RLock()
        self._exit_code = None
        if os.name != "nt" or type(pid) is not int or not 0 < pid <= 0xffffffff or type(token) is not int or token <= 0:
            raise OSError("PROCESS_IDENTITY_INVALID")
        self.pid, self.token = pid, token
        self._kernel = _kernel_api()
        self._handle = self._kernel.OpenProcess(0x1000 | 0x100000, False, pid)
        try:
            if not self._handle or _handle_birth(self._kernel, self._handle) != token:
                raise OSError("PROCESS_IDENTITY_MISMATCH")
        except BaseException:
            self.close()
            raise

    def poll(self):
        with self._lock:
            if self._exit_code is not None:
                return self._exit_code
            if not self._handle:
                raise OSError("PROCESS_REFERENCE_CLOSED")
            state = self._kernel.WaitForSingleObject(self._handle, 0)
            if state == 258:  # WAIT_TIMEOUT, the exact process is still alive.
                return None
            if state != 0:
                raise OSError("PROCESS_WAIT_FAILED")
            code = ctypes.wintypes.DWORD()
            if not self._kernel.GetExitCodeProcess(self._handle, ctypes.byref(code)):
                raise OSError("PROCESS_EXIT_CODE_UNAVAILABLE")
            self._exit_code = int(code.value)
            self.close()
            return self._exit_code

    def terminate(self):
        # Query, verify and terminate on ONE handle. No taskkill/PID lookup
        # occurs after the ownership check, eliminating the PID-reuse gap.
        with self._lock:
            if self.poll() is not None:
                return
            handle = self._kernel.OpenProcess(0x1 | 0x1000 | 0x100000, False, self.pid)
            try:
                if not handle or _handle_birth(self._kernel, handle) != self.token:
                    raise OSError("PROCESS_TERMINATION_IDENTITY_MISMATCH")
                state = self._kernel.WaitForSingleObject(handle, 0)
                if state == 0:
                    return
                if state != 258 or not self._kernel.TerminateProcess(handle, 1):
                    raise OSError("PROCESS_TERMINATION_FAILED")
            finally:
                if handle:
                    self._kernel.CloseHandle(handle)

    def close(self):
        with self._lock:
            if self._handle:
                self._kernel.CloseHandle(self._handle)
                self._handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass
