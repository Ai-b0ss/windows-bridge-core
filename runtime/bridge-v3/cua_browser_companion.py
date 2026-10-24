from __future__ import annotations

import ctypes
import json
import os
import time
import uuid
from ctypes import wintypes
from pathlib import Path
from typing import Any, Mapping

PIPE_PATH = r"\\.\pipe\ff_browser_companion_v1"
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True) if os.name == "nt" else None
if _kernel32 is not None:
    _kernel32.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
    _kernel32.WaitNamedPipeW.restype = wintypes.BOOL
    _kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.WriteFile.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    _kernel32.WriteFile.restype = wintypes.BOOL
    _kernel32.ReadFile.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
    _kernel32.ReadFile.restype = wintypes.BOOL
    _kernel32.CloseHandle.argtypes = [wintypes.HANDLE]


class CompanionError(RuntimeError):
    def __init__(self, code: str, message: str | None = None, *, details: Mapping[str, Any] | None = None):
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.details = dict(details or {})


def _winerr(code: str) -> CompanionError:
    return CompanionError(code, details={"winerror": ctypes.get_last_error()})


def _read_secret(root: Path) -> str:
    path = root / "secret"
    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise CompanionError("BROWSER_COMPANION_SECRET_UNAVAILABLE") from exc
    if len(value) < 16:
        raise CompanionError("BROWSER_COMPANION_SECRET_INVALID")
    return value


class BrowserCompanionClient:
    def __init__(self, package_root: str | Path, *, pipe_path: str = PIPE_PATH):
        self.root = Path(package_root).resolve()
        self.pipe_path = pipe_path

    def _open(self, timeout_ms: int) -> int:
        if _kernel32 is None:
            raise CompanionError("BROWSER_COMPANION_PLATFORM_UNSUPPORTED")
        timeout = max(1, min(int(timeout_ms), 30000))
        if not _kernel32.WaitNamedPipeW(self.pipe_path, timeout):
            raise _winerr("BROWSER_COMPANION_UNAVAILABLE")
        handle = _kernel32.CreateFileW(self.pipe_path, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None)
        if handle == INVALID_HANDLE_VALUE:
            raise _winerr("BROWSER_COMPANION_UNAVAILABLE")
        return handle
    @staticmethod
    def _write_all(handle: int, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            written = wintypes.DWORD()
            chunk = data[offset:]
            buffer = ctypes.create_string_buffer(chunk)
            if not _kernel32.WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None):
                raise _winerr("BROWSER_COMPANION_IPC_WRITE_FAILED")
            if written.value <= 0:
                raise CompanionError("BROWSER_COMPANION_IPC_WRITE_FAILED")
            offset += written.value

    @staticmethod
    def _read_line(handle: int, limit: int = 1024 * 1024) -> bytes:
        output = bytearray()
        buffer = ctypes.create_string_buffer(4096)
        while len(output) < limit:
            read = wintypes.DWORD()
            if not _kernel32.ReadFile(handle, buffer, len(buffer), ctypes.byref(read), None):
                raise _winerr("BROWSER_COMPANION_IPC_READ_FAILED")
            if read.value <= 0:
                break
            output.extend(buffer.raw[:read.value])
            newline = output.find(b"\n")
            if newline >= 0:
                return bytes(output[:newline])
        raise CompanionError("BROWSER_COMPANION_IPC_RESPONSE_INVALID")

    def request(self, method: str, params: Mapping[str, Any] | None = None, *, timeout_ms: int = 2000) -> dict[str, Any]:
        request_id = "ff-" + uuid.uuid4().hex
        payload = {
            "auth": _read_secret(self.root),
            "request_id": request_id,
            "method": str(method),
            "params": dict(params or {}),
        }
        encoded = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        handle = self._open(timeout_ms)
        try:
            self._write_all(handle, encoded)
            raw = self._read_line(handle)
        finally:
            _kernel32.CloseHandle(handle)
        try:
            response = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise CompanionError("BROWSER_COMPANION_IPC_RESPONSE_INVALID") from exc
        if not isinstance(response, dict):
            raise CompanionError("BROWSER_COMPANION_IPC_RESPONSE_INVALID")
        if response.get("request_id") not in {None, request_id}:
            raise CompanionError("BROWSER_COMPANION_IPC_RESPONSE_MISMATCH")
        if not bool(response.get("ok", False)):
            code = str(response.get("error_code") or "BROWSER_COMPANION_REQUEST_FAILED")
            raise CompanionError(code, str(response.get("message") or code))
        result = response.get("result")
        if not isinstance(result, dict):
            raise CompanionError("BROWSER_COMPANION_IPC_RESPONSE_INVALID")
        return dict(result)

    def capabilities(self) -> dict[str, Any]:
        return self.request("capabilities", timeout_ms=1500)

    def prepare_download(self, spec: Mapping[str, Any]) -> dict[str, Any]:
        return self.request("download.prepare", spec, timeout_ms=1500)

    def wait_download(self, operation_id: str, timeout_ms: int) -> dict[str, Any]:
        return self.request("download.wait", {"operation_id": operation_id, "timeout_ms": int(timeout_ms)}, timeout_ms=min(max(int(timeout_ms) + 1000, 1500), 31000))

    def status_download(self, operation_id: str) -> dict[str, Any]:
        return self.request("download.status", {"operation_id": operation_id}, timeout_ms=1500)

    def cleanup_download(self, operation_id: str) -> dict[str, Any]:
        return self.request("download.cleanup", {"operation_id": operation_id}, timeout_ms=5000)
