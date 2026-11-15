from __future__ import annotations

import argparse
import ast
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

# Embedded Python used by the live Bridge runs in isolated mode and may omit
# the script directory from sys.path. Anchor sibling imports explicitly.
_MODULE_DIR = Path(__file__).resolve().parent
if str(_MODULE_DIR) not in sys.path:
    sys.path.insert(0, str(_MODULE_DIR))

from cua_release_manifest import RUNTIME_SOURCE_MAP, git_blob_bytes, resolve_ref
from cua_windows_paths import extended_path

SCHEMA = "cua-runtime-install/v1"
LOCK_SCHEMA = "cua-runtime-deploy-lock/v1"
JOURNAL_SCHEMA = LOCK_SCHEMA + "/journal/v2"
MANIFEST_NAME = "installed-runtime-manifest.json"
LOCK_NAME = ".cua-runtime-deploy-lock.json"
TX_DIR_NAME = ".cua-deploy"


@contextmanager
def _windows_plain_handle(path: Path, *, directory: bool = False, delete: bool = False):
    """Pin a non-reparse object; deny renames and (for files) concurrent writes."""
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.GetFileInformationByHandleEx.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                   ctypes.c_void_p, wintypes.DWORD]
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    # READ_ATTRIBUTES alone is a metadata-only open and does not enforce
    # sharing restrictions. FILE_LIST_DIRECTORY must participate in the open.
    access = 0x81 if directory else 0x80000000  # list + attributes / GENERIC_READ
    if delete:
        access |= 0x10000  # DELETE
    handle = kernel.CreateFileW(str(extended_path(path, force=True)), access,
                                3 if directory else 1, None, 3,
                                0x00200000 | (0x02000000 if directory else 0), None)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attributes = (wintypes.DWORD * 2)()  # FILE_ATTRIBUTE_TAG_INFO
        if not kernel.GetFileInformationByHandleEx(handle, 9, attributes, ctypes.sizeof(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        if attributes[0] & 0x400 or bool(attributes[0] & 0x10) != directory:
            raise RuntimeError("DEPLOY_REPARSE_OR_TYPE_FORBIDDEN")
        yield handle
    finally:
        kernel.CloseHandle(handle)


class _DirectoryPins(ExitStack):
    """Keep checked Windows directory components from being swapped for junctions."""
    def __init__(self):
        super().__init__()
        self.paths: dict[Path, ExitStack] = {}

    def pin(self, path: Path, *, create: bool = False) -> None:
        path = extended_path(Path(os.path.abspath(path)), force=True)
        if path in self.paths:
            return
        if path.parent != path:
            self.pin(path.parent, create=create)
        if create:
            path.mkdir(exist_ok=True)
        context = self.enter_context(ExitStack())
        if os.name == "nt":
            context.enter_context(_windows_plain_handle(path, directory=True))
        elif path.is_symlink() or not path.is_dir():
            raise RuntimeError("DEPLOY_REPARSE_OR_TYPE_FORBIDDEN")
        self.paths[path] = context

    def release_tree(self, root: Path) -> None:
        for path in reversed(list(self.paths)):
            if path.is_relative_to(root):
                self.paths.pop(path).close()


def _retire_file(path: Path, expected_sha: str) -> None:
    """Hash and delete the SAME locked file, never a later occupant of its name."""
    if os.name != "nt":
        raise RuntimeError("RETIRE_WINDOWS_REQUIRED")
    import msvcrt
    from ctypes import wintypes
    with _windows_plain_handle(path, delete=True) as handle:
        # Duplicate the handle: fdopen owns its duplicate, the context owns the original.
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = wintypes.HANDLE
        kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.HANDLE,
                                           ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                                           wintypes.BOOL, wintypes.DWORD]
        kernel.DuplicateHandle.restype = wintypes.BOOL
        process = kernel.GetCurrentProcess()
        duplicate = wintypes.HANDLE()
        if not kernel.DuplicateHandle(process, handle, process, ctypes.byref(duplicate), 0, False, 2):
            raise ctypes.WinError(ctypes.get_last_error())
        with os.fdopen(msvcrt.open_osfhandle(duplicate.value, os.O_RDONLY | os.O_BINARY), "rb") as stream:
            actual = hashlib.file_digest(stream, "sha256").hexdigest()
        if actual != expected_sha:
            raise RuntimeError("RETIRED_FILE_CHANGED")
        kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                      ctypes.c_void_p, wintypes.DWORD]
        kernel.SetFileInformationByHandle.restype = wintypes.BOOL
        disposition = wintypes.BOOL(True)  # FILE_DISPOSITION_INFO
        if not kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(disposition), ctypes.sizeof(disposition)):
            raise ctypes.WinError(ctypes.get_last_error())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    path = extended_path(path, force=True)
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _replace_with_retry(src: str | Path, dst: str | Path, *, attempts: int = 8) -> None:
    src, dst = extended_path(src, force=True), extended_path(dst, force=True)
    for attempt in range(max(1, int(attempts))):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if attempt >= attempts - 1:
                raise
            time.sleep(min(0.02 * (2 ** attempt), 0.25))


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path = extended_path(path, force=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        _replace_with_retry(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _process_alive(pid: int, *, created_before: float | None = None) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        # A terminated process can remain queryable while another process
        # retains its handle. OpenProcess success alone is not liveness.
        from ctypes import wintypes
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        handle = kernel.OpenProcess(0x00101000, False, pid)  # SYNCHRONIZE + query
        if not handle:
            # Unknown/access denied must not permit another writer's rollback.
            return ctypes.get_last_error() not in (87, 1168)
        try:
            if created_before is not None:
                kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
                kernel.GetProcessTimes.restype = wintypes.BOOL
                times = [wintypes.FILETIME() for _ in range(4)]
                if not kernel.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
                    return True  # Uncertain identity cannot authorize recovery.
                born = ((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime) / 10_000_000 - 11644473600
                if born > created_before:
                    return False  # The numeric PID now belongs to a later process.
            return kernel.WaitForSingleObject(handle, 0) != 0
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _runtime_source_map_from_ref(repo: Path, head: str) -> dict[str, str]:
    raw = git_blob_bytes(repo, head, "tools/cua_release_manifest.py")
    tree = ast.parse(raw.decode("utf-8"), filename="cua_release_manifest.py")
    components = None
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == "COMPONENTS" for target in targets):
                components = ast.literal_eval(node.value)
                break
    if not isinstance(components, (tuple, list)) or not all(isinstance(item, str) for item in components):
        raise RuntimeError("RUNTIME_COMPONENTS_INVALID")
    result: dict[str, str] = {}
    for source in components:
        normalized = source.replace("\\", "/")
        if normalized.startswith("tools/"):
            result[source] = normalized[len("tools/"):]
        elif normalized.startswith("browser_companion/"):
            result[source] = normalized
        elif normalized == "docs/HIDDEN_PANEL_AGENT_GUIDE.md":
            result[source] = "HIDDEN-PANEL-GUIDE.md"
    if not result:
        raise RuntimeError("RUNTIME_SOURCE_MAP_EMPTY")
    return result


def _public_runtime_source_map(repo: Path, head: str) -> dict[str, str]:
    """Use the PUBLIC Core's pinned runtime tree, not legacy private tools/."""
    cp = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", head,
         "--", "runtime/bridge-v3/"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if cp.returncode != 0:
        raise RuntimeError("PUBLIC_RUNTIME_TREE_UNAVAILABLE")
    names = cp.stdout.splitlines()
    if len(names) > 400:
        raise RuntimeError("PUBLIC_RUNTIME_FILE_COUNT_INVALID")
    mapping = {}
    seen = set()
    for name in names:
        if not name.startswith("runtime/bridge-v3/"):
            raise RuntimeError("PUBLIC_RUNTIME_SOURCE_INVALID")
        target = name[len("runtime/bridge-v3/"):]
        if (not target or any(part in {"", ".", ".."} for part in target.split("/"))
                or "\\" in target or ":" in target
                or target.casefold() in seen):
            raise RuntimeError("PUBLIC_RUNTIME_SOURCE_INVALID")
        seen.add(target.casefold())
        mapping[name] = target
    if mapping and "runtime/bridge-v3/ff_win_v3_agent.py" not in mapping:
        raise RuntimeError("PUBLIC_RUNTIME_AGENT_MISSING")
    return mapping


def build_plan(repo: Path, ref: str = "HEAD") -> dict[str, Any]:
    repo = repo.resolve()
    head = resolve_ref(repo, ref)
    source_map = _public_runtime_source_map(repo, head)
    if not source_map:
        current_head = resolve_ref(repo, "HEAD")
        source_map = (RUNTIME_SOURCE_MAP if head == current_head
                      else _runtime_source_map_from_ref(repo, head))
    files = []
    for source, target in source_map.items():
        raw = git_blob_bytes(repo, head, source)
        files.append({
            "source": source,
            "target": target,
            "bytes": len(raw),
            "sha256": sha256_bytes(raw),
        })
    identity = {"head": head, "files": files}
    release_id = sha256_bytes(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return {
        "schema": SCHEMA,
        "source_head": head,
        "release_id": release_id,
        "files": files,
    }


def _previous_owned_files(repo: Path, candidate: dict[str, Any], previous: Any) -> dict[str, str]:
    """The installed manifest is a claim, not authority for retiring owner files.

    Rebuild v1 identity from local Git, restricted to the candidate's history.
    No fetch, mutable branch name, hash supplied only by the manifest, or
    current module's legacy COMPONENTS constant can authorize retirement.
    """
    try:
        if not isinstance(previous, dict) or previous.get("schema") != SCHEMA:
            raise ValueError("schema")
        head = previous.get("source_head")
        if (not isinstance(head, str) or len(head) != 40
                or any(c not in "0123456789abcdef" for c in head)):
            raise ValueError("commit")
        ancestry = subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor", head, candidate["source_head"]],
            capture_output=True, timeout=30, check=False,
        )
        if ancestry.returncode != 0:
            raise ValueError("history unavailable or unrelated")
        # Always derive old legacy mappings from that commit, even at HEAD.
        mapping = (_public_runtime_source_map(repo, head)
                   or _runtime_source_map_from_ref(repo, head))
        files = []
        for source, target in mapping.items():
            raw = git_blob_bytes(repo, head, source)
            files.append({"source": source, "target": target,
                          "bytes": len(raw), "sha256": sha256_bytes(raw)})
        identity = {"head": head, "files": files}
        release_id = sha256_bytes(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        if previous.get("release_id") != release_id or previous.get("files") != files:
            raise ValueError("identity differs from Git")
        return {item["target"]: item["sha256"] for item in files}
    except (ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
        raise RuntimeError("PREVIOUS_MANIFEST_UNPROVEN") from exc



def plan_manifest_reconciliation(
    repo: Path, runtime_root: Path, *, trusted_head: str, ref: str = "HEAD"
) -> dict[str, Any]:
    """READ-ONLY proof for a stale installed manifest; never rewrite installation.

    trusted_head is an independently selected, immutable Git commit. This proof
    may be used in a separately authorized, backed-up migration, but is NOT
    permission to replace the installed manifest or bypass apply_runtime().
    """
    if (not isinstance(trusted_head, str) or len(trusted_head) != 40
            or any(c not in "0123456789abcdef" for c in trusted_head)):
        raise RuntimeError("TRUSTED_HEAD_NOT_PINNED")
    repo = repo.resolve()
    root = extended_path(Path(os.path.abspath(runtime_root)), force=True)
    with _DirectoryPins() as pins:
        pins.pin(root)
        manifest_path = root / MANIFEST_NAME
        if (manifest_path.is_symlink()
                or getattr(manifest_path, "is_junction", lambda: False)()
                or not manifest_path.is_file()):
            raise RuntimeError("PREVIOUS_MANIFEST_UNPROVEN")
        if (root / LOCK_NAME).exists() or (root / TX_DIR_NAME).exists():
            raise RuntimeError("RECONCILIATION_TRANSACTION_PRESENT")
        if os.name == "nt":
            with _windows_plain_handle(manifest_path):
                previous_bytes = manifest_path.read_bytes()
        else:
            previous_bytes = manifest_path.read_bytes()
        try:
            previous = json.loads(previous_bytes.decode("utf-8-sig"))
            previous_head = previous["source_head"]
            if (not isinstance(previous_head, str) or len(previous_head) != 40
                    or any(c not in "0123456789abcdef" for c in previous_head)):
                raise ValueError("old head not pinned")
            previous_plan = build_plan(repo, ref=previous_head)
            if any(previous.get(key) != previous_plan[key]
                   for key in ("schema", "source_head", "release_id", "files")):
                raise ValueError("manifest differs from exact Git history")
        except (KeyError, ValueError, TypeError, RuntimeError,
                UnicodeError, subprocess.SubprocessError) as exc:
            raise RuntimeError("PREVIOUS_MANIFEST_UNPROVEN") from exc

        trusted_plan = build_plan(repo, ref=trusted_head)
        candidate_plan = build_plan(repo, ref=ref)
        ancestry = subprocess.run(
            ["git", "-C", str(repo), "merge-base", "--is-ancestor",
             trusted_head, candidate_plan["source_head"]],
            capture_output=True, timeout=30, check=False,
        )
        if ancestry.returncode != 0:
            raise RuntimeError("TRUSTED_HEAD_NOT_ANCESTOR")
        prior_targets = {item["target"] for item in previous_plan["files"]}
        trusted_targets = {item["target"] for item in trusted_plan["files"]}
        candidate_targets = {item["target"] for item in candidate_plan["files"]}
        # No automatic retirement of unrelated owner files through reconciliation.
        if not prior_targets <= trusted_targets or not trusted_targets <= candidate_targets:
            raise RuntimeError("RECONCILIATION_RETIREMENT_UNSUPPORTED")

        for item in trusted_plan["files"]:
            target = _recovery_target(root, item["target"])
            pins.pin(target.parent)
            if not target.is_file():
                raise RuntimeError("TRUSTED_FILE_MISSING:" + item["target"])
            if os.name == "nt":
                with _windows_plain_handle(target):
                    actual = sha256_file(target)
            else:
                actual = sha256_file(target)
            if actual != item["sha256"]:
                raise RuntimeError("TRUSTED_FILE_MISMATCH:" + item["target"])
        # A future candidate might introduce a filename currently occupied by
        # an owner's unknown file. Never silently claim or overwrite that file.
        for name in candidate_targets - trusted_targets:
            target = _recovery_target(root, name)
            # A new candidate subdirectory may not exist yet. Pin the nearest
            # existing ancestor; never create directories during a dry run.
            ancestor = target.parent
            while not ancestor.exists() and ancestor != root:
                ancestor = ancestor.parent
            pins.pin(ancestor)
            if target.exists() or target.is_symlink():
                raise RuntimeError("CANDIDATE_TARGET_OCCUPIED:" + name)
        if manifest_path.read_bytes() != previous_bytes:
            raise RuntimeError("PREVIOUS_MANIFEST_CHANGED")
        return {
            "schema": "cua-runtime-provenance-reconciliation-plan/v1",
            "eligible": True,
            "old_head": previous_head,
            "trusted_head": trusted_head,
            "candidate_head": candidate_plan["source_head"],
            "verified_files": len(trusted_plan["files"]),
            "previous_manifest_sha256": sha256_bytes(previous_bytes),
            "trusted_manifest": trusted_plan,
            "production_modified": False,
        }


def stage_plan(repo: Path, plan: dict[str, Any], stage_root: Path) -> None:
    # Prefix the root before joining children: a short root can have a child
    # beyond MAX_PATH. This also covers mkdir/copy/rename and external parsers.
    stage_root = extended_path(stage_root, force=True)
    stage_root.mkdir(parents=True, exist_ok=True)
    head = str(plan["source_head"])
    for item in plan["files"]:
        raw = git_blob_bytes(repo, head, str(item["source"]))
        if sha256_bytes(raw) != item["sha256"]:
            raise RuntimeError(f"STAGE_SOURCE_HASH_MISMATCH:{item['source']}")
        dst = stage_root / str(item["target"])
        dst.parent.mkdir(parents=True, exist_ok=True)
        with dst.open("xb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        if sha256_file(dst) != item["sha256"]:
            raise RuntimeError(f"STAGE_WRITE_HASH_MISMATCH:{item['target']}")


def validate_stage(stage_root: Path, plan: dict[str, Any], *, strict_external: bool) -> dict[str, Any]:
    stage_root = extended_path(stage_root, force=True)
    py_count = json_count = ps_count = js_count = 0
    for item in plan["files"]:
        path = stage_root / str(item["target"])
        if not path.is_file() or sha256_file(path) != item["sha256"]:
            raise RuntimeError(f"STAGE_HASH_MISMATCH:{item['target']}")
        suffix = path.suffix.lower()
        if suffix == ".py":
            compile(path.read_bytes(), str(path), "exec")
            py_count += 1
        elif suffix == ".json":
            json.loads(path.read_text(encoding="utf-8-sig"))
            json_count += 1

    ps_files = [stage_root / str(x["target"]) for x in plan["files"] if str(x["target"]).lower().endswith(".ps1")]
    mjs_files = [stage_root / str(x["target"]) for x in plan["files"] if str(x["target"]).lower().endswith((".mjs", ".cjs"))]
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    node = shutil.which("node.exe") or shutil.which("node")

    if ps_files:
        if strict_external and not powershell:
            raise RuntimeError("POWERSHELL_VALIDATOR_MISSING")
        if powershell:
            script = (
                "$p=$env:CUA_VALIDATE_PATH;"
                "$tokens=$null;$errors=$null;"
                "[void][System.Management.Automation.Language.Parser]::ParseFile($p,[ref]$tokens,[ref]$errors);"
                "if($errors.Count){$errors|ForEach-Object{Write-Error $_};exit 2}"
            )
            for path in ps_files:
                env = os.environ.copy()
                env["CUA_VALIDATE_PATH"] = str(path)
                cp = subprocess.run([powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                                    capture_output=True, text=True, timeout=30, check=False, env=env)
                if cp.returncode != 0:
                    raise RuntimeError(f"POWERSHELL_PARSE_FAILED:{path.name}:{cp.stderr[-500:]}")
                ps_count += 1

    if mjs_files:
        if strict_external and not node:
            raise RuntimeError("NODE_VALIDATOR_MISSING")
        if node:
            for path in mjs_files:
                # Node's CLI realpath resolver rejects the extended prefix
                # (EISDIR on the drive). Its Win32 file I/O accepts long paths.
                node_path = str(path)
                if os.name == "nt" and node_path.startswith("\\\\?\\UNC\\"):
                    node_path = "\\\\" + node_path[8:]
                elif os.name == "nt" and node_path.startswith("\\\\?\\"):
                    node_path = node_path[4:]
                cp = subprocess.run([node, "--check", node_path], capture_output=True, text=True, timeout=30, check=False)
                if cp.returncode != 0:
                    raise RuntimeError(f"NODE_CHECK_FAILED:{path.name}:{cp.stderr[-500:]}")
                js_count += 1

    bridge_entry = stage_root / "cua_bridge_v3.py"
    import_smoke = False
    if bridge_entry.is_file():
        smoke = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sys; sys.path.insert(0, sys.argv[1]); import cua_bridge_v3",
                str(stage_root),
            ],
            # CreateProcess rejects an extended/long lpCurrentDirectory.
            # Import from the explicit stage path while inheriting the
            # caller's working directory, as the other validators do.
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if smoke.returncode != 0:
            detail = (smoke.stderr or smoke.stdout or "").strip()[-1000:]
            raise RuntimeError(f"PYTHON_IMPORT_SMOKE_FAILED:cua_bridge_v3:{detail}")
        import_smoke = True

    return {
        "python": py_count,
        "json": json_count,
        "powershell": ps_count,
        "mjs": js_count,
        "python_import_smoke": import_smoke,
    }


def _copy_replace(src: Path, dst: Path, txid: str, *, overwrite: bool = True) -> None:
    src, dst = extended_path(src, force=True), extended_path(dst, force=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    # Unique exclusive slots neither follow links nor collide with a temporary
    # file left by a crash during an earlier rollback attempt.
    # Sources live in this same-volume transaction's stage/backup directory;
    # a crash must leave scratch files there, not beside runnable modules.
    fd, name = tempfile.mkstemp(prefix=dst.name + f".{txid}.", suffix=".new", dir=src.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as output, src.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        if overwrite:
            _replace_with_retry(tmp, dst)
        else:
            # Win32 rename without REPLACE_EXISTING: recovery must not clobber
            # a new owner file at the name of a retired module.
            if os.name != "nt":
                raise RuntimeError("RETIRE_WINDOWS_REQUIRED")
            os.rename(tmp, dst)
    finally:
        tmp.unlink(missing_ok=True)


def _read_json(path: Path) -> dict[str, Any]:
    path = extended_path(path, force=True)
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _acquire_lock(lock_path: Path, payload: dict[str, Any]) -> None:
    lock_path = extended_path(lock_path, force=True)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    fd = os.open(lock_path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _recovery_target(root: Path, name: Any) -> Path:
    """Reject path traversal, reparse points and protected deployment metadata."""
    if (not isinstance(name, str) or not 0 < len(name) <= 512
            or "\\" in name or ":" in name or name.startswith("/")):
        raise RuntimeError("ROLLBACK_TARGET_UNSAFE")
    parts = name.split("/")
    devices = {"con", "prn", "aux", "nul", "conin$", "conout$"}
    devices.update(f"{prefix}{n}" for prefix in ("com", "lpt") for n in "123456789¹²³")
    if any(part in {"", ".", ".."} or part.endswith((".", " "))
           or any(ord(c) < 32 or c in '<>"|?*' for c in part)
           or part.split(".")[0].casefold() in devices for part in parts):
        raise RuntimeError("ROLLBACK_TARGET_UNSAFE")
    if parts[0].casefold() in {TX_DIR_NAME, LOCK_NAME, MANIFEST_NAME}:
        raise RuntimeError("ROLLBACK_TARGET_UNSAFE")
    cursor = root
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink() or getattr(cursor, "is_junction", lambda: False)():
            raise RuntimeError("ROLLBACK_TARGET_LINK_FORBIDDEN")
    return cursor


def _comparable_path(path: Path) -> str:
    """Normalize Win32 extended-length spellings for equality comparisons."""
    value = os.path.normcase(str(path.resolve()))
    if value.startswith("\\\\?\\UNC\\"):
        return "\\\\" + value[8:]
    if value.startswith("\\\\?\\"):
        return value[4:]
    return value


def _backup_at(expected: Path, supplied: Any, old_sha: Any) -> Path:
    if (not isinstance(supplied, str)
            or not isinstance(old_sha, str)
            or len(old_sha) != 64
            or any(char not in "0123456789abcdef" for char in old_sha)):
        raise RuntimeError("ROLLBACK_BACKUP_INVALID")
    actual = Path(supplied)
    if (not actual.is_absolute()
            or _comparable_path(actual) != _comparable_path(expected)):
        raise RuntimeError("ROLLBACK_BACKUP_PATH_INVALID")
    node = expected
    while True:
        if node.is_symlink() or getattr(node, "is_junction", lambda: False)():
            raise RuntimeError("ROLLBACK_BACKUP_LINK_FORBIDDEN")
        if node.parent == node:
            break
        node = node.parent
    if not expected.is_file() or sha256_file(expected) != old_sha:
        raise RuntimeError("ROLLBACK_BACKUP_INVALID")
    return expected


def _restore_journal(runtime_root: Path, journal: dict[str, Any]) -> None:
    with _DirectoryPins() as pins:
        pins.pin(runtime_root)
        _restore_journal_pinned(runtime_root, journal, pins)


def _restore_journal_pinned(runtime_root: Path, journal: dict[str, Any], pins: _DirectoryPins) -> None:
    """Prevalidate ALL recovery inputs before writing even the first target."""
    runtime_root = extended_path(runtime_root, force=True)
    if not isinstance(journal, dict) or journal.get("schema") not in {LOCK_SCHEMA + "/journal", JOURNAL_SCHEMA}:
        raise RuntimeError("ROLLBACK_JOURNAL_SCHEMA_INVALID")
    txid = journal.get("txid")
    if (not isinstance(txid, str) or len(txid) != 32
            or any(char not in "0123456789abcdef" for char in txid)):
        raise RuntimeError("ROLLBACK_TXID_INVALID")
    rows = journal.get("files")
    previous = journal.get("previous_manifest")
    if not isinstance(rows, list) or len(rows) > 500 or not isinstance(previous, dict):
        raise RuntimeError("ROLLBACK_JOURNAL_INVALID")
    backup_root = runtime_root / TX_DIR_NAME / txid / "backup"
    pins.pin(backup_root)
    prepared: list[tuple[Path, Path | None, str | None, bool]] = []
    seen: set[str] = set()
    for item in rows:
        if not isinstance(item, dict) or type(item.get("existed")) is not bool:
            raise RuntimeError("ROLLBACK_JOURNAL_INVALID")
        name = item.get("target")
        target = _recovery_target(runtime_root, name)
        pins.pin(target.parent)
        if name.casefold() in seen:
            raise RuntimeError("ROLLBACK_TARGET_DUPLICATE")
        seen.add(name.casefold())
        if item["existed"]:
            expected = backup_root.joinpath(*name.split("/"))
            pins.pin(expected.parent)
            backup = _backup_at(expected, item.get("backup"), item.get("old_sha256"))
            retired = "retired_sha256" in item
            if retired and (item["retired_sha256"] != item["old_sha256"]
                            or (target.exists() and sha256_file(target) != item["old_sha256"])):
                raise RuntimeError("ROLLBACK_RETIRED_CONFLICT")
            prepared.append((target, backup, item["old_sha256"], retired))
        else:
            if item.get("old_sha256") is not None or "retired_sha256" in item:
                raise RuntimeError("ROLLBACK_JOURNAL_INVALID")
            supplied_backup = item.get("backup")
            if supplied_backup not in (None, ""):
                # Releases before this fix recorded the *planned* backup
                # path even for a file that never existed. Accept only that
                # exact, absent, transaction-owned slot for crash recovery.
                expected = backup_root.joinpath(*name.split("/"))
                if (not isinstance(supplied_backup, str)
                        or not Path(supplied_backup).is_absolute()
                        or _comparable_path(Path(supplied_backup)) != _comparable_path(expected)
                        or expected.exists()):
                    raise RuntimeError("ROLLBACK_BACKUP_PATH_INVALID")
            prepared.append((target, None, None, False))
    manifest_target = runtime_root / MANIFEST_NAME
    if type(previous.get("existed")) is not bool:
        raise RuntimeError("ROLLBACK_JOURNAL_INVALID")
    if manifest_target.is_symlink() or getattr(manifest_target, "is_junction", lambda: False)():
        raise RuntimeError("ROLLBACK_TARGET_LINK_FORBIDDEN")
    if previous["existed"]:
        manifest_backup = _backup_at(backup_root / MANIFEST_NAME,
                                     previous.get("backup"), previous.get("old_sha256"))
    else:
        if previous.get("backup") is not None or previous.get("old_sha256") is not None:
            raise RuntimeError("ROLLBACK_JOURNAL_INVALID")
        manifest_backup = None
    # Every input is now validated; an invalid later entry cannot cause a
    # partial earlier rollback (or delete arbitrary owner files).
    for target, backup, old_sha, retired in prepared:
        if backup is not None:
            if retired and target.exists():
                # Already restored (or never deleted). Do not overwrite it.
                with _windows_plain_handle(target):
                    if sha256_file(target) != old_sha:
                        raise RuntimeError("ROLLBACK_RETIRED_CONFLICT")
                continue
            _copy_replace(backup, target, txid + ".rollback", overwrite=not retired)
            if sha256_file(target) != old_sha:
                raise RuntimeError("ROLLBACK_HASH_MISMATCH")
        elif target.exists():
            target.unlink()
    if manifest_backup is not None:
        _copy_replace(manifest_backup, manifest_target, txid + ".manifest.rollback")
    elif manifest_target.exists():
        manifest_target.unlink()


def recover_stale(runtime_root: Path) -> dict[str, Any]:
    runtime_root = extended_path(Path(os.path.abspath(runtime_root)), force=True)
    with _DirectoryPins() as pins:
        pins.pin(runtime_root)
        return _recover_stale_pinned(runtime_root, pins)


def _recover_stale_pinned(runtime_root: Path, pins: _DirectoryPins) -> dict[str, Any]:
    lock_path = runtime_root / LOCK_NAME
    if lock_path.is_symlink() or getattr(lock_path, "is_junction", lambda: False)():
        raise RuntimeError("DEPLOY_LOCK_LINK_FORBIDDEN")
    if not lock_path.is_file():
        return {"recovered": False}
    lock = _read_json(lock_path)
    if not isinstance(lock, dict) or lock.get("schema") != LOCK_SCHEMA:
        raise RuntimeError("DEPLOY_LOCK_SCHEMA_INVALID")
    txid = lock.get("txid")
    if (not isinstance(txid, str) or len(txid) != 32
            or any(char not in "0123456789abcdef" for char in txid)):
        raise RuntimeError("DEPLOY_LOCK_TXID_INVALID")
    journal_path = runtime_root / TX_DIR_NAME / txid / "journal.json"
    recorded = lock.get("journal")
    if (not isinstance(recorded, str) or not Path(recorded).is_absolute()
            or _comparable_path(Path(recorded)) != _comparable_path(journal_path)):
        raise RuntimeError("DEPLOY_JOURNAL_PATH_INVALID")
    if (journal_path.is_symlink() or getattr(journal_path, "is_junction", lambda: False)()
            or journal_path.parent.is_symlink()
            or getattr(journal_path.parent, "is_junction", lambda: False)()):
        raise RuntimeError("DEPLOY_JOURNAL_LINK_FORBIDDEN")
    pid = int(lock.get("pid") or 0)
    started = lock.get("started_at")
    alive = (_process_alive(pid, created_before=datetime.fromisoformat(started).timestamp())
             if started else _process_alive(pid))
    if pid != os.getpid() and alive:
        raise RuntimeError(f"DEPLOY_BUSY:{pid}")
    if journal_path.parent.exists():
        pins.pin(journal_path.parent)
    if not journal_path.is_file():
        # Targets are not modified until the journal has been durably written.
        # A dead owner with no journal therefore means the transaction stopped
        # before commit began; clearing the stale lock is safe.
        lock_path.unlink()
        return {"recovered": True, "txid": lock.get("txid"), "phase": "precommit_no_journal"}
    journal = _read_json(journal_path)
    if journal.get("txid") != txid:
        raise RuntimeError("DEPLOY_JOURNAL_TXID_MISMATCH")
    _restore_journal(runtime_root, journal)
    lock_path.unlink()
    return {"recovered": True, "txid": journal.get("txid"), "phase": "rollback_from_journal"}


def verify_runtime(runtime_root: Path, *, allow_lock: bool = False) -> dict[str, Any]:
    runtime_root = extended_path(runtime_root.resolve(), force=True)
    lock_path = runtime_root / LOCK_NAME
    if lock_path.exists() and not allow_lock:
        return {"ok": False, "error": "DEPLOY_LOCK_PRESENT", "mismatches": []}
    manifest_path = runtime_root / MANIFEST_NAME
    if not manifest_path.is_file():
        return {"ok": False, "error": "INSTALLED_MANIFEST_MISSING", "mismatches": []}
    manifest = _read_json(manifest_path)
    if manifest.get("schema") != SCHEMA:
        return {"ok": False, "error": "INSTALLED_MANIFEST_SCHEMA_INVALID", "mismatches": []}
    mismatches = []
    for item in manifest.get("files", []):
        path = runtime_root / str(item["target"])
        actual = sha256_file(path) if path.is_file() else None
        if actual != item.get("sha256"):
            mismatches.append({"target": item.get("target"), "expected": item.get("sha256"), "actual": actual})
    return {
        "ok": not mismatches,
        "error": None if not mismatches else "RUNTIME_HASH_MISMATCH",
        "source_head": manifest.get("source_head"),
        "release_id": manifest.get("release_id"),
        "file_count": len(manifest.get("files", [])),
        "mismatches": mismatches,
    }


def apply_runtime(
    repo: Path,
    runtime_root: Path,
    *,
    ref: str = "HEAD",
    require_clean: bool = True,
    strict_external: bool = False,
    fail_after: int | None = None,
    before_replace: Callable[[], None] | None = None,
    after_install: Callable[[], None] | None = None,
) -> dict[str, Any]:
    # Do not resolve away a symlink/junction before checking the install root.
    runtime_root = extended_path(Path(os.path.abspath(runtime_root)), force=True)
    with _DirectoryPins() as pins:
        pins.pin(runtime_root, create=True)
        return _apply_runtime_pinned(
            repo, runtime_root, pins, ref=ref, require_clean=require_clean,
            strict_external=strict_external, fail_after=fail_after,
            before_replace=before_replace, after_install=after_install,
        )


def _apply_runtime_pinned(
    repo: Path, runtime_root: Path, pins: _DirectoryPins, *, ref: str,
    require_clean: bool, strict_external: bool, fail_after: int | None,
    before_replace: Callable[[], None] | None, after_install: Callable[[], None] | None,
) -> dict[str, Any]:
    repo = repo.resolve()
    if require_clean:
        cp = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True, timeout=20, check=False)
        if cp.returncode != 0 or cp.stdout.strip():
            raise RuntimeError("WORKTREE_DIRTY")
    runtime_root.mkdir(parents=True, exist_ok=True)
    recovered = recover_stale(runtime_root)
    plan = build_plan(repo, ref)
    manifest_target = runtime_root / MANIFEST_NAME
    if manifest_target.is_symlink() or getattr(manifest_target, "is_junction", lambda: False)():
        raise RuntimeError("PREVIOUS_MANIFEST_LINK_FORBIDDEN")
    if manifest_target.exists() and not manifest_target.is_file():
        raise RuntimeError("PREVIOUS_MANIFEST_UNPROVEN")
    previous_bytes = manifest_target.read_bytes() if manifest_target.is_file() else None
    if previous_bytes is None and any(p.name not in {TX_DIR_NAME, LOCK_NAME} for p in runtime_root.iterdir()):
        raise RuntimeError("PREVIOUS_MANIFEST_MISSING_NONEMPTY")
    previous_files: dict[str, str] = {}
    if previous_bytes is not None:
        try:
            previous_data = json.loads(previous_bytes.decode("utf-8-sig"))
        except (ValueError, UnicodeError) as exc:
            raise RuntimeError("PREVIOUS_MANIFEST_UNPROVEN") from exc
        previous_files = _previous_owned_files(repo, plan, previous_data)
    plan_targets = {str(item["target"]) for item in plan["files"]}
    retired_files = {name: digest for name, digest in previous_files.items() if name not in plan_targets}
    if retired_files and os.name != "nt":
        raise RuntimeError("RETIRE_WINDOWS_REQUIRED")
    # Validate every old/new target before creating stage/backup directories.
    seen: set[str] = set()
    for name in list(plan_targets) + list(retired_files):
        target = _recovery_target(runtime_root, name)
        if name.casefold() in seen:
            raise RuntimeError("DEPLOY_TARGET_DUPLICATE")
        seen.add(name.casefold())
        pins.pin(target.parent, create=True)
        if target.exists() and not target.is_file():
            raise RuntimeError("DEPLOY_TARGET_TYPE_INVALID")
        if name in retired_files and target.is_file() and sha256_file(target) != retired_files[name]:
            raise RuntimeError("RETIRED_FILE_UNPROVEN:" + name)
    txid = uuid.uuid4().hex
    tx_root = runtime_root / TX_DIR_NAME / txid
    stage_root = tx_root / "stage"
    backup_root = tx_root / "backup"
    pins.pin(stage_root, create=True)
    pins.pin(backup_root, create=True)
    for name in plan_targets:
        pins.pin((stage_root / name).parent, create=True)
    stage_plan(repo, plan, stage_root)
    validation = validate_stage(stage_root, plan, strict_external=strict_external)

    lock_path = runtime_root / LOCK_NAME
    journal_path = tx_root / "journal.json"
    lock = {
        "schema": LOCK_SCHEMA,
        "txid": txid,
        "pid": os.getpid(),
        "source_head": plan["source_head"],
        "journal": str(journal_path),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    _acquire_lock(lock_path, lock)

    journal_files = []
    previous_manifest = {"existed": manifest_target.is_file(), "backup": None, "old_sha256": None}
    try:
        if (manifest_target.is_symlink()
                or (manifest_target.read_bytes() if manifest_target.is_file() else None) != previous_bytes):
            raise RuntimeError("PREVIOUS_MANIFEST_CHANGED")
        managed_targets = list(dict.fromkeys(
            [str(item["target"]) for item in plan["files"]] + sorted(retired_files)
        ))
        for target_name in managed_targets:
            target = _recovery_target(runtime_root, target_name)
            existed = target.is_file()
            # An absent retired name grants no right to delete a later occupant.
            if target_name in retired_files and not existed:
                continue
            backup = backup_root / target_name
            old_sha = sha256_file(target) if existed else None
            if target_name in retired_files and old_sha != retired_files[target_name]:
                raise RuntimeError("RETIRED_FILE_UNPROVEN:" + target_name)
            if existed:
                pins.pin(backup.parent, create=True)
                with backup.open("xb") as output, target.open("rb") as input_file:
                    shutil.copyfileobj(input_file, output)
                    output.flush()
                    os.fsync(output.fileno())
                if sha256_file(backup) != old_sha:
                    raise RuntimeError(f"BACKUP_HASH_MISMATCH:{target_name}")
            journal_files.append({
                "target": target_name,
                "existed": existed,
                "backup": str(backup) if existed else None,
                "old_sha256": old_sha,
                **({"retired_sha256": old_sha} if target_name in retired_files else {}),
            })

        if manifest_target.is_file():
            mb = backup_root / MANIFEST_NAME
            with mb.open("xb") as output:
                output.write(previous_bytes)
                output.flush()
                os.fsync(output.fileno())
            previous_manifest = {"existed": True, "backup": str(mb), "old_sha256": sha256_bytes(previous_bytes)}

        # Older recovery code must reject these journals, rather than silently
        # ignoring the new retired-file conflict protection. We still read v1.
        journal = {"schema": JOURNAL_SCHEMA, "txid": txid, "files": journal_files, "previous_manifest": previous_manifest}
        atomic_json(journal_path, journal)

        # Local lifecycle controller stops the exact server only after backups
        # are durable and the keeper is paused by this transaction's lock.
        if before_replace is not None:
            before_replace()
        replaced = 0
        unchanged = 0
        for item in plan["files"]:
            target = _recovery_target(runtime_root, str(item["target"]))
            if target.is_file() and sha256_file(target) == item["sha256"]:
                unchanged += 1
                continue
            _copy_replace(stage_root / str(item["target"]), target, txid)
            replaced += 1
            if fail_after is not None and replaced >= fail_after:
                raise RuntimeError(f"INJECTED_FAILURE_AFTER:{replaced}")
        retired = 0
        for row in journal_files:
            if "retired_sha256" in row:
                target = _recovery_target(runtime_root, row["target"])
                _retire_file(target, row["retired_sha256"])
                retired += 1

        installed = dict(plan)
        installed["installed_at"] = datetime.now(timezone.utc).isoformat()
        installed["validation"] = validation
        atomic_json(manifest_target, installed)
        verified = verify_runtime(runtime_root, allow_lock=True)
        if not verified["ok"]:
            raise RuntimeError("POST_INSTALL_VERIFY_FAILED:" + json.dumps(verified, sort_keys=True))
        # Readiness must pass while rollback data and the keeper pause remain.
        if after_install is not None:
            after_install()
        lock_path.unlink()
        pins.release_tree(tx_root)
        shutil.rmtree(tx_root, ignore_errors=True)
        return {
            "ok": True,
            "recovered": recovered,
            "validation": validation,
            "files_replaced": replaced,
            "files_unchanged": unchanged,
            "files_retired": retired,
            **verified,
        }
    except Exception:
        try:
            if journal_path.is_file():
                _restore_journal(runtime_root, _read_json(journal_path))
                if lock_path.exists():
                    lock_path.unlink()
            else:
                lock_path.unlink(missing_ok=True)
        except Exception as rollback_exc:
            raise RuntimeError(f"ROLLBACK_FAILED:{rollback_exc}") from sys.exc_info()[1]
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description="Transactional, manifest-backed FF Bridge runtime deployment")
    sub = parser.add_subparsers(dest="command", required=True)
    apply_p = sub.add_parser("apply")
    apply_p.add_argument("--repo", type=Path, required=True)
    apply_p.add_argument("--runtime-root", type=Path, required=True)
    apply_p.add_argument("--ref", default="HEAD")
    apply_p.add_argument("--allow-dirty", action="store_true")
    apply_p.add_argument("--strict-external-validation", action="store_true")
    verify_p = sub.add_parser("verify")
    verify_p.add_argument("--runtime-root", type=Path, required=True)
    recover_p = sub.add_parser("recover")
    recover_p.add_argument("--runtime-root", type=Path, required=True)
    ns = parser.parse_args()
    try:
        if ns.command == "apply":
            result = apply_runtime(ns.repo, ns.runtime_root, ref=ns.ref, require_clean=not ns.allow_dirty,
                                   strict_external=ns.strict_external_validation)
        elif ns.command == "verify":
            result = verify_runtime(ns.runtime_root)
            if not result["ok"]:
                print(json.dumps(result, ensure_ascii=False))
                return 3
        else:
            result = recover_stale(ns.runtime_root)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
