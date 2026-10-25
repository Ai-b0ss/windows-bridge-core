"""Windows PID reuse defence: process start FILETIME as read-only identity.

No process terminate, attach, or mutable kernel operation is performed.
"""
from __future__ import annotations
import ctypes
import ctypes.wintypes
import os


class _FileTime(ctypes.Structure):
    _fields_=[
        ("low",ctypes.wintypes.DWORD),
        ("high",ctypes.wintypes.DWORD),
    ]


def process_creation_token(pid: int) -> int | None:
    """Return 64-bit Windows process creation FILETIME, fail closed if unknown."""
    if os.name!="nt" or type(pid) is not int or pid<=0:
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
