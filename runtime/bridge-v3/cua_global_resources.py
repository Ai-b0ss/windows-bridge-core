from __future__ import annotations

"""Local-machine cross-process reader/writer leases for CUA resources."""

from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import platform
import re
import tempfile
import threading
import time
import uuid
from typing import Iterable, Iterator


class GlobalResourceError(RuntimeError):
    def __init__(self, code: str, details: dict | None = None):
        super().__init__(code)
        self.code = code
        self.details = details or {}


def process_creation_identity(pid: int | None = None) -> str:
    """OS creation identity, not a PID-only owner key."""
    pid = os.getpid() if pid is None else int(pid)
    if platform.system() == "Windows":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        handle_t = ctypes.c_void_p

        class FILETIME(ctypes.Structure):
            _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]

        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.OpenProcess.restype = handle_t
        kernel.GetProcessTimes.argtypes = [handle_t, ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME)]
        kernel.GetProcessTimes.restype = ctypes.c_int
        kernel.CloseHandle.argtypes = [handle_t]
        kernel.CloseHandle.restype = ctypes.c_int
        handle = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            raise GlobalResourceError("PROCESS_IDENTITY_UNAVAILABLE", {"pid": pid, "winerror": ctypes.get_last_error()})
        created, exited, kernel_time, user_time = FILETIME(), FILETIME(), FILETIME(), FILETIME()
        try:
            if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel_time), ctypes.byref(user_time)):
                raise GlobalResourceError("PROCESS_IDENTITY_UNAVAILABLE", {"pid": pid, "winerror": ctypes.get_last_error()})
        finally:
            kernel.CloseHandle(handle)
        return f"win:{(created.high << 32) | created.low}"
    try:
        # /proc stat's comm field can contain spaces; split after its final ')'.
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = stat[stat.rfind(")") + 2:].split()
        return f"proc:{fields[19]}"  # field 22 (starttime), after pid/comm
    except Exception as exc:
        raise GlobalResourceError("PROCESS_IDENTITY_UNAVAILABLE", {"pid": pid}) from exc


def process_is_same(pid: int, creation: str) -> bool:
    """True if live, exact owner OR identity/liveness is ambiguous (fail closed)."""
    if platform.system() == "Windows":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        handle_t = ctypes.c_void_p
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.OpenProcess.restype = handle_t
        kernel.GetExitCodeProcess.argtypes = [handle_t, ctypes.POINTER(ctypes.c_uint32)]
        kernel.GetExitCodeProcess.restype = ctypes.c_int
        kernel.CloseHandle.argtypes = [handle_t]
        kernel.CloseHandle.restype = ctypes.c_int
        # QUERY_INFORMATION is needed by GetExitCodeProcess on older Windows.
        handle = kernel.OpenProcess(0x0400 | 0x1000 | 0x00100000, False, int(pid))
        if not handle:
            error = ctypes.get_last_error()
            if error in (6, 87):  # invalid handle / invalid PID
                return False
            return True  # access denied or other uncertainty: retain lease
        try:
            exit_code = ctypes.c_uint32()
            if not kernel.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                return True
            if exit_code.value != 259:  # STILL_ACTIVE
                return False
        finally:
            kernel.CloseHandle(handle)
        try:
            return process_creation_identity(pid) == str(creation)
        except GlobalResourceError:
            return True
    try:
        return process_creation_identity(pid) == str(creation)
    except GlobalResourceError:
        try:
            os.kill(int(pid), 0)
            return True
        except PermissionError:
            return True
        except OSError:
            return False


_ID = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_NAMESPACE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_EXACT = frozenset({"clipboard", "physical-input"})
_DENIED_WRITES = frozenset({"physical-input", "foreground"})
_THREAD_LOCK_GUARD = threading.Lock()
_THREAD_LOCKS: dict[str, threading.Lock] = {}


def canonical_resource(resource: str) -> str:
    """Validate supported core forms while allowing explicit extension namespaces."""
    if not isinstance(resource, str) or not resource or resource != resource.strip() or len(resource) > 512:
        raise GlobalResourceError("RESOURCE_NAME_INVALID")
    if resource in _EXACT:
        return resource
    if resource == "foreground":
        return resource
    if resource.startswith("native:hwnd:"):
        return canonical_resource("hwnd:" + resource[len("native:hwnd:"):])
    if resource.startswith("native:pid:"):
        pid_text = resource[len("native:pid:"):]
        if not pid_text.isdigit() or int(pid_text) <= 0:
            raise GlobalResourceError("RESOURCE_NAME_INVALID", {"resource": resource})
        pid = int(pid_text)
        return f"process/{pid}/{process_creation_identity(pid)}"
    if resource.startswith("foreground:"):
        suffix = resource[len("foreground:"):]
        if not suffix or not _ID.fullmatch(suffix):
            raise GlobalResourceError("RESOURCE_NAME_INVALID", {"resource": resource})
        return resource
    if resource.startswith("hwnd:"):
        value = resource[5:]
        if not value or not re.fullmatch(r"(?:[1-9][0-9]*|0x[0-9a-fA-F]+)", value):
            raise GlobalResourceError("RESOURCE_NAME_INVALID", {"resource": resource})
        return f"hwnd:{int(value, 0)}"
    if resource.startswith("process/"):
        parts = resource.split("/")
        if len(parts) != 3 or not parts[1].isdigit() or int(parts[1]) <= 0 or not re.fullmatch(r"(?:win:[0-9]+|proc:[0-9]+)", parts[2]):
            raise GlobalResourceError("RESOURCE_NAME_INVALID", {"resource": resource})
        return resource
    if resource.startswith("browser-surface/tab:"):
        suffix = resource[len("browser-surface/tab:"):]
        if not _ID.fullmatch(suffix):
            raise GlobalResourceError("RESOURCE_NAME_INVALID", {"resource": resource})
        return resource
    for namespace in ("browser-profile",):
        prefix = namespace + ":"
        if resource.startswith(prefix):
            if not _ID.fullmatch(resource[len(prefix):]):
                raise GlobalResourceError("RESOURCE_NAME_INVALID", {"resource": resource})
            return resource
    if "/" in resource and ":" not in resource:
        raise GlobalResourceError("RESOURCE_NAME_INVALID", {"resource": resource})
    if ":" in resource:
        namespace, suffix = resource.split(":", 1)
        if namespace in {"clipboard", "physical-input"} or not _NAMESPACE.fullmatch(namespace) or not re.fullmatch(r"[A-Za-z0-9._:/-]{1,448}", suffix):
            raise GlobalResourceError("RESOURCE_NAME_INVALID", {"resource": resource})
        return resource
    if not _NAMESPACE.fullmatch(resource):
        raise GlobalResourceError("RESOURCE_NAME_INVALID", {"resource": resource})
    return resource


def resource_namespace(resource: str) -> str:
    canonical = canonical_resource(resource)
    if canonical.startswith("browser-surface/tab:"):
        return "browser-surface"
    if canonical.startswith("process/"):
        return "process"
    if ":" in canonical:
        return canonical.split(":", 1)[0]
    return canonical


class _StateLock:
    """Short OS state-file lock, automatically released when the process exits."""
    WINDOWS_LOCK_TIMEOUT = 5.0

    def __init__(self, path: Path):
        self.path = path
        self.handle = None
        self._win_kernel = None
        self._win_overlapped = None
        self._win_os_handle = None
        key = str(path.resolve()).casefold()
        with _THREAD_LOCK_GUARD:
            self.thread_lock = _THREAD_LOCKS.setdefault(key, threading.Lock())

    def __enter__(self):
        self.thread_lock.acquire()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if os.name == "nt":
                # LockFileEx locks byte zero even when the lock file is empty.
                # The lock file is created/opened atomically; its content is
                # never read or written, avoiding a read-vs-lock race.
                from ctypes import wintypes
                import msvcrt

                class OVERLAPPED(ctypes.Structure):
                    _fields_ = [
                        ("Internal", ctypes.c_size_t),
                        ("InternalHigh", ctypes.c_size_t),
                        ("Offset", wintypes.DWORD),
                        ("OffsetHigh", wintypes.DWORD),
                        ("hEvent", wintypes.HANDLE),
                    ]

                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.LockFileEx.argtypes = [
                    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                    wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(OVERLAPPED),
                ]
                kernel.LockFileEx.restype = wintypes.BOOL
                kernel.UnlockFileEx.argtypes = [
                    wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
                    wintypes.DWORD, ctypes.POINTER(OVERLAPPED),
                ]
                kernel.UnlockFileEx.restype = wintypes.BOOL
                deadline = time.monotonic() + self.WINDOWS_LOCK_TIMEOUT
                delay = 0.001
                fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
                self.handle = os.fdopen(fd, "r+b", buffering=0)
                self._win_kernel = kernel
                self._win_overlapped = OVERLAPPED()
                self._win_os_handle = msvcrt.get_osfhandle(self.handle.fileno())
                while True:
                    ctypes.set_last_error(0)
                    locked = kernel.LockFileEx(
                        self._win_os_handle,
                        0x00000002 | 0x00000001,  # EXCLUSIVE | FAIL_IMMEDIATELY
                        0, 1, 0, ctypes.byref(self._win_overlapped),
                    )
                    if locked:
                        break
                    error = ctypes.get_last_error()
                    # Lock violation is normal contention. Sharing violations
                    # can also arise transiently on Windows filesystems. Access
                    # denied and all other errors are storage failures.
                    if error not in (32, 33) or time.monotonic() >= deadline:
                        raise GlobalResourceError(
                            "GLOBAL_RESOURCE_STATE_LOCK_UNAVAILABLE",
                            {"path": str(self.path), "winerror": error},
                        )
                    time.sleep(min(delay, max(0.001, deadline - time.monotonic())))
                    delay = min(0.025, delay * 1.7)
            else:
                self.handle = open(self.path, "a+b")
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX)
            return self
        except BaseException:
            if self.handle is not None:
                self.handle.close()
            self.thread_lock.release()
            raise

    def __exit__(self, *_):
        if self.handle is not None:
            if os.name == "nt":
                unlocked = self._win_kernel.UnlockFileEx(
                    self._win_os_handle, 0, 1, 0,
                    ctypes.byref(self._win_overlapped),
                )
                if not unlocked:
                    error = ctypes.get_last_error()
                    self.handle.close()
                    self.thread_lock.release()
                    raise GlobalResourceError(
                        "GLOBAL_RESOURCE_STATE_UNLOCK_FAILED", {"winerror": error}
                    )
            else:
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
            self.thread_lock.release()


class GlobalResourceCoordinator:
    """Cross-process RW leases. Expiry is diagnostic; live owners never expire."""
    DEFAULT_SHAREABLE = frozenset({"hwnd", "browser-surface", "office"})

    def __init__(self, state_dir: str | os.PathLike[str] | None = None, *, timeout: float = 0.0, lease_ttl: float = 120.0,
                 shareable_namespaces: Iterable[str] | None = None):
        if state_dir is None:
            local_app_data = os.environ.get("LOCALAPPDATA")
            if not local_app_data:
                raise GlobalResourceError("GLOBAL_RESOURCE_STATE_DIR_UNAVAILABLE")
            state_dir = Path(local_app_data) / "FFWindowsBridge" / "state" / "global-resources"
        self.state_dir = Path(state_dir)
        self.state_path = self.state_dir / "leases.json"
        self.lock_path = self.state_dir / "leases.lock"
        self.timeout = max(0.0, float(timeout))
        self.lease_ttl = max(1.0, float(lease_ttl))
        self.shareable = frozenset(shareable_namespaces if shareable_namespaces is not None else self.DEFAULT_SHAREABLE)
        for namespace in self.shareable:
            if not _NAMESPACE.fullmatch(namespace):
                raise ValueError(f"invalid shareable namespace: {namespace!r}")
        self.pid = os.getpid()
        self.creation = process_creation_identity(self.pid)
        self.nonce = uuid.uuid4().hex
        self.owner = {"pid": self.pid, "creation": self.creation, "nonce": self.nonce}

    def _read_locked(self) -> dict:
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("leases"), dict):
                raise ValueError("schema")
            return data
        except FileNotFoundError:
            return {"schema": 1, "leases": {}}
        except Exception as exc:
            raise GlobalResourceError("GLOBAL_RESOURCE_STATE_CORRUPT") from exc

    def _write_locked(self, data: dict) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix="leases-", suffix=".tmp", dir=self.state_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(data, stream, sort_keys=True, separators=(",", ":"))
                stream.flush(); os.fsync(stream.fileno())
            os.replace(name, self.state_path)
        finally:
            try: os.unlink(name)
            except FileNotFoundError: pass

    def _prune(self, data: dict, resources: Iterable[str] | None = None) -> None:
        candidates = list(data["leases"]) if resources is None else list(resources)
        for resource in candidates:
            leases = data["leases"].get(resource, [])
            if not leases:
                continue
            live = []
            for lease in leases:
                owner = lease.get("owner", {})
                try:
                    same = process_is_same(int(owner["pid"]), str(owner["creation"]))
                except (KeyError, TypeError, ValueError):
                    same = True  # malformed/unknown owner is not safe to reclaim
                if same:
                    live.append(lease)
            if live: data["leases"][resource] = live
            else: data["leases"].pop(resource, None)

    def acquire_many(self, resources: Iterable[str], mode: str = "write") -> list[str]:
        if mode not in {"read", "write"}:
            raise ValueError("mode must be read or write")
        keys = tuple(sorted({canonical_resource(key) for key in resources}))
        denied = sorted(key for key in keys if resource_namespace(key) in _DENIED_WRITES)
        if denied:
            raise GlobalResourceError("GLOBAL_RESOURCE_POLICY_DENIED", {"resources": denied})
        deadline = time.monotonic() + self.timeout
        while True:
            now = time.time()
            with _StateLock(self.lock_path):
                data = self._read_locked(); self._prune(data, keys)
                conflict = None
                for key in keys:
                    namespace = resource_namespace(key)
                    existing = data["leases"].get(key, [])
                    if existing and (mode == "write" or namespace not in self.shareable or any(item.get("mode") == "write" for item in existing)):
                        conflict = key; break
                if conflict is None:
                    lease_ids = []
                    for key in keys:
                        lease_id = uuid.uuid4().hex; lease_ids.append(lease_id)
                        data["leases"].setdefault(key, []).append({
                            "lease_id": lease_id, "mode": mode, "owner": self.owner,
                            "issued_at": now, "expires_at": now + self.lease_ttl,
                        })
                    self._write_locked(data)
                    return lease_ids
                self._write_locked(data)
            if time.monotonic() >= deadline:
                raise GlobalResourceError("GLOBAL_RESOURCE_BUSY", {"resource": conflict, "mode": mode})
            time.sleep(min(0.025, max(0.001, deadline - time.monotonic())))

    def release_many(self, lease_ids: Iterable[str]) -> None:
        ids = set(lease_ids)
        if not ids: return
        with _StateLock(self.lock_path):
            data = self._read_locked()
            for key, leases in list(data["leases"].items()):
                kept = [lease for lease in leases if not (lease.get("lease_id") in ids and lease.get("owner", {}).get("nonce") == self.nonce)]
                if kept: data["leases"][key] = kept
                else: data["leases"].pop(key, None)
            self._write_locked(data)

    @contextmanager
    def hold_many(self, resources: Iterable[str], mode: str = "write") -> Iterator[None]:
        ids = self.acquire_many(resources, mode)
        try: yield
        finally: self.release_many(ids)

    def snapshot(self) -> dict:
        with _StateLock(self.lock_path):
            data = self._read_locked(); self._prune(data); self._write_locked(data)
        now = time.time(); resources = {}
        for key, leases in data["leases"].items():
            resources[key] = [{"mode": lease["mode"], "owner": lease["owner"],
                               "age_seconds": max(0, round(now - lease["issued_at"], 3)),
                               "expires_in_seconds": max(0, round(lease["expires_at"] - now, 3))} for lease in leases]
        return {"resource_count": len(resources), "resources": resources,
                "owner": {"pid": self.pid, "creation": self.creation, "nonce": self.nonce}}


class CoordinatedResources:
    """In-process fast layer combined with mandatory global leases."""
    def __init__(self, local, global_coordinator):
        self.local, self.global_coordinator = local, global_coordinator

    @contextmanager
    def _hold(self, method: str, resources: Iterable[str], mode: str):
        keys = tuple(resources)
        with self.global_coordinator.hold_many(keys, mode):
            with getattr(self.local, method)(keys):
                yield

    def read(self, key: str): return self._hold("read", (key,), "read")
    def write(self, key: str): return self._hold("write", (key,), "write")
    def read_many(self, keys: Iterable[str]): return self._hold("read_many", keys, "read")
    def write_many(self, keys: Iterable[str]): return self._hold("write_many", keys, "write")
    def snapshot(self): return {"local": self.local.snapshot(), "global": self.global_coordinator.snapshot()}
