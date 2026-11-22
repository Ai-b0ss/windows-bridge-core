"""Launch one approved MSIX app execution alias on an owned inactive desktop.

Windows may create the actual packaged process outside the caller's inherited
JobObject. To avoid orphaned Electron processes on worker termination, create
the alias process *suspended*, assign a dedicated kill-on-close JobObject, then
resume. Do not use ShellExecute or an activation manager that can target the
interactive desktop. Package files and ACLs are never touched.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as w
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

from cua_hidden_desktop import _StartupInfo, _ProcessInfo
from cua_sidecar_supervisor import _bind_windows_kill_on_close_job, _close_windows_job_handle


class OwnedMsixAliasProcess:
    def __init__(self, executable: Path, arguments: list[str], desktop: str):
        if os.name != "nt":
            raise RuntimeError("OWN_MSIX_WINDOWS_ONLY")
        local = os.environ.get("LOCALAPPDATA")
        expected = Path(local) / "Microsoft" / "WindowsApps" / "claude-desktop.exe" if local else None
        valid_args=(arguments in ([], ["--force-renderer-accessibility=complete"]))
        if len(arguments)==3 and arguments[:2]==["--force-renderer-accessibility=complete","--"]:
            from cua_hidden_apps import claude_code_link
            try:
                claude_code_link(arguments[2])
                valid_args=True
            except ValueError:
                valid_args=False
        if (expected is None or executable != expected or not expected.is_file()
                or not valid_args or not desktop.startswith("FFBridge-Agent-")):
            raise RuntimeError("OWN_MSIX_ALIAS_INVALID")
        u = ctypes.WinDLL("user32", use_last_error=True)
        u.GetThreadDesktop.argtypes = [w.DWORD]
        u.GetThreadDesktop.restype = w.HANDLE
        u.GetUserObjectInformationW.argtypes = [
            w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)
        ]
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.GetCurrentThreadId.restype = w.DWORD
        buf = ctypes.create_unicode_buffer(256)
        needed = w.DWORD()
        current = u.GetThreadDesktop(k.GetCurrentThreadId())
        if not current or not u.GetUserObjectInformationW(current, 2, buf, ctypes.sizeof(buf), ctypes.byref(needed)):
            raise RuntimeError("OWN_MSIX_DESKTOP_UNKNOWN")
        if buf.value != desktop:
            raise RuntimeError("OWN_MSIX_DESKTOP_MISMATCH")
        k.CreateProcessW.argtypes = [
            w.LPCWSTR, w.LPWSTR, w.LPVOID, w.LPVOID, w.BOOL,
            w.DWORD, w.LPVOID, w.LPCWSTR, ctypes.POINTER(_StartupInfo), ctypes.POINTER(_ProcessInfo)
        ]
        k.CreateProcessW.restype = w.BOOL
        k.ResumeThread.argtypes = [w.HANDLE]
        k.ResumeThread.restype = w.DWORD
        k.GetExitCodeProcess.argtypes = [w.HANDLE, ctypes.POINTER(w.DWORD)]
        k.GetExitCodeProcess.restype = w.BOOL
        k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        k.WaitForSingleObject.restype = w.DWORD
        k.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
        k.TerminateProcess.restype = w.BOOL
        k.CloseHandle.argtypes = [w.HANDLE]
        k.CloseHandle.restype = w.BOOL

        self._kernel = k
        self._process = None
        self._job = None
        self.pid = None
        si = _StartupInfo()
        si.cb = ctypes.sizeof(si)
        si.lpDesktop = "winsta0\\" + desktop
        si.dwFlags = 1  # STARTF_USESHOWWINDOW
        si.wShowWindow = 4  # SW_SHOWNOACTIVATE
        pi = _ProcessInfo()
        command = ctypes.create_unicode_buffer(subprocess.list2cmdline([str(expected), *arguments]))
        if not k.CreateProcessW(None, command, None, None, False, 0x4 | 0x200,
                                None, str(Path.home()), ctypes.byref(si), ctypes.byref(pi)):
            raise OSError(ctypes.get_last_error(), "OWN_MSIX_CREATE_PROCESS_FAILED")
        try:
            # Must complete before the child can execute or spawn other processes.
            self._job = _bind_windows_kill_on_close_job(SimpleNamespace(pid=pi.pid))
            if k.ResumeThread(pi.hThread) == 0xFFFFFFFF:
                raise OSError(ctypes.get_last_error(), "OWN_MSIX_RESUME_FAILED")
            self._process = pi.hProcess
            self.pid = int(pi.pid)
        except BaseException:
            if self._job is not None:
                _close_windows_job_handle(self._job)
                self._job = None
            k.TerminateProcess(pi.hProcess, 1)
            k.WaitForSingleObject(pi.hProcess, 5000)
            k.CloseHandle(pi.hProcess)
            raise
        finally:
            k.CloseHandle(pi.hThread)

    def poll(self):
        if self._process is None:
            return 0
        code = w.DWORD()
        if not self._kernel.GetExitCodeProcess(self._process, ctypes.byref(code)):
            raise RuntimeError("OWN_MSIX_EXIT_CODE_UNAVAILABLE")
        return None if code.value == 259 else int(code.value)

    def kill(self):
        # Closing the dedicated job terminates its entire *owned* process tree
        # even if the worker itself is killed before its Python finally runs.
        if self._job is not None:
            _close_windows_job_handle(self._job)
            self._job = None
        if self._process is not None and self.poll() is None:
            self._kernel.TerminateProcess(self._process, 1)

    def wait(self, timeout=5):
        if self._process is None:
            return 0
        ms = max(0, int(timeout * 1000))
        state = self._kernel.WaitForSingleObject(self._process, ms)
        if state != 0:
            raise TimeoutError("OWN_MSIX_PROCESS_WAIT_FAILED")
        result = self.poll()
        if self._job is not None:
            _close_windows_job_handle(self._job)
            self._job = None
        self._kernel.CloseHandle(self._process)
        self._process = None
        return result

    def __del__(self):
        # Interpreter shutdown also closes OS handles automatically.
        try:
            if self._job is not None:
                _close_windows_job_handle(self._job)
                self._job = None
            if self._process is not None:
                self._kernel.CloseHandle(self._process)
                self._process = None
        except Exception:
            pass
