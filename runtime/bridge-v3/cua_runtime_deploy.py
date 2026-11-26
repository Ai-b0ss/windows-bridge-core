from __future__ import annotations

import argparse
import ast
import ctypes
import hashlib
import json
import os
import re
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

from cua_release_manifest import (
    KNOWN_STALE_COMMITS,
    RUNTIME_SOURCE_MAP,
    compute_install_release_id,
    git_blob_bytes,
    git_commit_exists,
    is_hex40_commit,
    resolve_ref,
    validate_commit_sha,
)
from cua_windows_paths import extended_path

SCHEMA = "cua-runtime-install/v1"
LOCK_SCHEMA = "cua-runtime-deploy-lock/v1"
JOURNAL_SCHEMA = LOCK_SCHEMA + "/journal/v2"
ACTIVE_RELEASE_SCHEMA = "ff-bridge-active-release/v1"
ACTIVE_RELEASE_RELPATH = Path("state") / "active-release.json"
MANIFEST_NAME = "installed-runtime-manifest.json"
LOCK_NAME = ".cua-runtime-deploy-lock.json"
TX_DIR_NAME = ".cua-deploy"

_PLAYWRIGHT_FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("pw_connect_url_artifact", re.compile(rb"pw_connect_url\.txt", re.IGNORECASE)),
    ("chatgpt_audit_dir_ref", re.compile(rb"ChatGPT_Conversation_Audit", re.IGNORECASE)),
    (
        "write_file_sync_connect_href",
        re.compile(rb"writeFileSync\s*\([^)]*(?:connect|href|token|relay)", re.IGNORECASE),
    ),
    (
        "hardcoded_windows_user_path",
        re.compile(rb"""["'][A-Za-z]:[/\\]Users[/\\][^/\\"'`]+[/\\]""", re.IGNORECASE),
    ),
)


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
        if (root / LOCK_NAME).exists():
            raise RuntimeError("RECONCILIATION_TRANSACTION_PRESENT")
        # Historical journal/backup trees can remain without an active lock.
        # Report them as a rollout blocker, but still prove source bytes.
        transaction_root = root / TX_DIR_NAME
        if (transaction_root.is_symlink()
                or getattr(transaction_root, "is_junction", lambda: False)()
                or (transaction_root.exists() and not transaction_root.is_dir())):
            raise RuntimeError("RECONCILIATION_TRANSACTION_INVALID")
        pending_transactions = 0
        if transaction_root.is_dir():
            pins.pin(transaction_root)
            pending_transactions = sum(1 for _ in transaction_root.iterdir())
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
            "eligible": pending_transactions == 0,
            "provenance_verified": True,
            "unresolved_deploy_transactions": pending_transactions,
            "requires_transaction_review": pending_transactions > 0,
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


def _resolve_core_bundle_path(candidate: Path) -> Path:
    if candidate.is_file() and candidate.name.lower() == "corebundle.js":
        return candidate
    for rel in (
        Path("node_modules") / "playwright-core" / "lib" / "coreBundle.js",
        Path("playwright-core") / "lib" / "coreBundle.js",
        Path("lib") / "coreBundle.js",
    ):
        probe = candidate / rel
        if probe.is_file():
            return probe
    return candidate / "node_modules" / "playwright-core" / "lib" / "coreBundle.js"


def check_playwright_integrity(
    runtime_root: Path, *, playwright_root: Path | None = None
) -> dict[str, Any]:
    """Fail-closed integrity check for node_modules/playwright-core/lib/coreBundle.js.

    Delegates to runtime/bridge-v3/cua_playwright_integrity.py when available,
    falling back to an equivalent built-in pattern scan so standalone recovery
    kits and pre-merge branches remain fail-closed without extra dependencies.
    """
    explicit = playwright_root is not None
    base = Path(playwright_root) if explicit else Path(runtime_root)
    pw_dir = base / "node_modules" / "playwright-core"
    bundle_path = _resolve_core_bundle_path(base)
    if not explicit and not pw_dir.exists() and not bundle_path.is_file():
        return {"ok": True, "checked": False, "present": False, "scanner": "none"}
    if not bundle_path.is_file():
        return {
            "ok": False,
            "checked": True,
            "present": False,
            "error": "PLAYWRIGHT_CORE_BUNDLE_MISSING",
            "scanner": "builtin",
        }
    if bundle_path.is_symlink() or getattr(bundle_path, "is_junction", lambda: False)():
        return {
            "ok": False,
            "checked": True,
            "present": True,
            "error": "PLAYWRIGHT_CORE_BUNDLE_LINK_FORBIDDEN",
            "scanner": "builtin",
        }
    # Prefer Track D's canonical cua_playwright_integrity module when present.
    try:
        import cua_playwright_integrity as pw_integrity  # type: ignore[import-not-found]
    except ImportError:
        pw_integrity = None
    if pw_integrity is not None:
        raw_res = None
        scanner_name = "cua_playwright_integrity"
        if base.is_file() and base.name.lower() == "corebundle.js" and callable(getattr(pw_integrity, "scan_core_bundle", None)):
            raw_res = pw_integrity.scan_core_bundle(base)
            scanner_name = "cua_playwright_integrity.scan_core_bundle"
        elif callable(getattr(pw_integrity, "scan_playwright_root", None)):
            raw_res = pw_integrity.scan_playwright_root(base, require_present=explicit)
            scanner_name = "cua_playwright_integrity.scan_playwright_root"
        elif callable(getattr(pw_integrity, "scan_core_bundle", None)):
            raw_res = pw_integrity.scan_core_bundle(bundle_path)
            scanner_name = "cua_playwright_integrity.scan_core_bundle"
        if isinstance(raw_res, dict):
            status = str(raw_res.get("status") or ("clean" if raw_res.get("ok") else "tampered"))
            ok = bool(raw_res.get("ok"))
            findings = raw_res.get("findings") or []
            rules = [
                (f.get("rule") or f.get("code") or "violation")
                if isinstance(f, dict)
                else str(f)
                for f in findings
            ]
            return {
                "ok": ok,
                "status": status,
                "checked": status != "not_installed",
                "present": status not in {"missing", "not_installed"},
                "scanner": scanner_name,
                "error": None if ok else (raw_res.get("error_code") or raw_res.get("error") or "PLAYWRIGHT_CORE_BUNDLE_TAMPERED"),
                "matched_rules": rules,
                "finding_count": int(raw_res.get("finding_count", len(rules))),
                "playwright_core_version": raw_res.get("playwright_core_version"),
                "bundle_sha256": raw_res.get("sha256") or (sha256_file(bundle_path) if bundle_path.is_file() else None),
            }
    raw = bundle_path.read_bytes()
    matched = [name for name, pat in _PLAYWRIGHT_FORBIDDEN_PATTERNS if pat.search(raw)]
    if matched:
        return {
            "ok": False,
            "status": "tampered",
            "checked": True,
            "present": True,
            "scanner": "builtin",
            "error": "PLAYWRIGHT_CORE_BUNDLE_TAMPERED",
            "matched_rules": matched,
            "finding_count": len(matched),
            "bundle_sha256": sha256_bytes(raw),
        }
    return {
        "ok": True,
        "status": "clean",
        "checked": True,
        "present": True,
        "scanner": "builtin",
        "error": None,
        "matched_rules": [],
        "finding_count": 0,
        "bundle_sha256": sha256_bytes(raw),
    }


def verify_runtime(
    runtime_root: Path,
    *,
    allow_lock: bool = False,
    repo: Path | None = None,
    check_playwright: bool = False,
    playwright_root: Path | None = None,
) -> dict[str, Any]:
    runtime_root = extended_path(runtime_root.resolve(), force=True)
    lock_path = runtime_root / LOCK_NAME
    if lock_path.exists() and not allow_lock:
        return {"ok": False, "error": "DEPLOY_LOCK_PRESENT", "mismatches": []}
    manifest_path = runtime_root / MANIFEST_NAME
    if manifest_path.is_symlink() or getattr(manifest_path, "is_junction", lambda: False)():
        return {"ok": False, "error": "INSTALLED_MANIFEST_LINK_FORBIDDEN", "mismatches": []}
    if not manifest_path.is_file():
        return {"ok": False, "error": "INSTALLED_MANIFEST_MISSING", "mismatches": []}
    try:
        manifest = _read_json(manifest_path)
    except (OSError, ValueError, UnicodeError):
        return {"ok": False, "error": "INSTALLED_MANIFEST_INVALID_JSON", "mismatches": []}
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        return {"ok": False, "error": "INSTALLED_MANIFEST_SCHEMA_INVALID", "mismatches": []}
    source_head = manifest.get("source_head")
    if (
        not is_hex40_commit(source_head)
        or str(source_head).lower() in KNOWN_STALE_COMMITS
    ):
        return {
            "ok": False,
            "error": "INSTALLED_MANIFEST_PROVENANCE_INVALID",
            "source_head": source_head,
            "mismatches": [],
        }
    if repo is not None and (repo / ".git").exists() and not git_commit_exists(repo, source_head):
        return {
            "ok": False,
            "error": "INSTALLED_MANIFEST_COMMIT_UNKNOWN_IN_GIT",
            "source_head": source_head,
            "mismatches": [],
        }
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        return {"ok": False, "error": "INSTALLED_MANIFEST_FILES_INVALID", "mismatches": []}
    try:
        expected_release_id = compute_install_release_id(source_head, files)
    except (TypeError, ValueError):
        return {"ok": False, "error": "INSTALLED_MANIFEST_FILES_INVALID", "mismatches": []}
    if manifest.get("release_id") != expected_release_id:
        return {
            "ok": False,
            "error": "INSTALLED_MANIFEST_RELEASE_ID_MISMATCH",
            "source_head": source_head,
            "release_id": manifest.get("release_id"),
            "mismatches": [],
        }
    mismatches = []
    for item in files:
        if not isinstance(item, dict):
            return {"ok": False, "error": "INSTALLED_MANIFEST_FILES_INVALID", "mismatches": []}
        try:
            path = _recovery_target(runtime_root, item.get("target"))
        except RuntimeError as exc:
            return {"ok": False, "error": str(exc), "mismatches": []}
        actual = sha256_file(path) if path.is_file() else None
        if actual != item.get("sha256"):
            mismatches.append({"target": item.get("target"), "expected": item.get("sha256"), "actual": actual})
    pw_result = None
    should_check_pw = (
        check_playwright
        or playwright_root is not None
        or (runtime_root / "node_modules" / "playwright-core").exists()
    )
    if should_check_pw:
        pw_result = check_playwright_integrity(runtime_root, playwright_root=playwright_root)
    pw_failed = pw_result is not None and not pw_result.get("ok")
    error = None
    if mismatches:
        error = "RUNTIME_HASH_MISMATCH"
    elif pw_failed:
        error = pw_result.get("error") or "PLAYWRIGHT_INTEGRITY_FAILED"
    out = {
        "ok": (not mismatches) and (not pw_failed),
        "error": error,
        "source_head": source_head,
        "release_id": manifest.get("release_id"),
        "file_count": len(files),
        "mismatches": mismatches,
    }
    if pw_result is not None:
        out["playwright_integrity"] = pw_result
    return out


def _is_reparse(path: Path) -> bool:
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def _assert_no_reparse_relative(base_phys: Path, target: Path) -> Path:
    """Ensure target stays inside base_phys and introduces zero symlinks/junctions."""
    raw_target = Path(os.path.abspath(target))
    # Walk only the components under base_phys (the caller's base_phys may itself
    # come from resolving a known owner junction like LOCALAPPDATA\\FF-Windows-Bridge).
    resolved_target = raw_target.resolve()
    try:
        rel = resolved_target.relative_to(base_phys)
    except ValueError as exc:
        raise RuntimeError("ACTIVE_RELEASE_OUTSIDE_BRIDGE_ROOT") from exc
    cursor = base_phys
    for part in rel.parts:
        cursor = cursor / part
        if _is_reparse(cursor):
            raise RuntimeError("ACTIVE_RELEASE_LINK_FORBIDDEN")
    if _is_reparse(raw_target):
        raise RuntimeError("ACTIVE_RELEASE_LINK_FORBIDDEN")
    return resolved_target


def active_release_pointer_path(bridge_root: Path) -> Path:
    base_phys = Path(os.path.abspath(bridge_root)).resolve()
    return base_phys / ACTIVE_RELEASE_RELPATH


def _pointer_summary(pointer: dict[str, Any]) -> dict[str, Any]:
    return {
        "release_dir": pointer.get("release_dir"),
        "release_name": pointer.get("release_name"),
        "source_head": pointer.get("source_head"),
        "release_id": pointer.get("release_id"),
        "manifest_sha256": pointer.get("manifest_sha256"),
        "agent_entrypoint": pointer.get("agent_entrypoint", "ff_win_v3_main.py"),
        "agent_entrypoint_sha256": pointer.get("agent_entrypoint_sha256"),
        "playwright_root": pointer.get("playwright_root"),
    }


def _validate_release_dir_for_pointer(
    bridge_root: Path,
    release_dir: Path,
    *,
    repo: Path | None = None,
    playwright_root: Path | None = None,
    check_playwright: bool = True,
    agent_entrypoint: str = "ff_win_v3_main.py",
) -> dict[str, Any]:
    base_phys = Path(os.path.abspath(bridge_root)).resolve()
    rel_phys = _assert_no_reparse_relative(base_phys, release_dir)
    if not rel_phys.is_dir():
        raise RuntimeError("ACTIVE_RELEASE_DIR_MISSING")
    manifest_path = rel_phys / MANIFEST_NAME
    if _is_reparse(manifest_path) or not manifest_path.is_file():
        raise RuntimeError("ACTIVE_RELEASE_MANIFEST_MISSING")
    pw_root_phys: Path | None = None
    if playwright_root is not None:
        pw_raw = Path(os.path.abspath(playwright_root))
        if _is_reparse(pw_raw) or not pw_raw.exists():
            raise RuntimeError("PLAYWRIGHT_ROOT_INVALID")
        pw_root_phys = pw_raw.resolve()
    verified = verify_runtime(
        rel_phys,
        repo=repo,
        check_playwright=check_playwright,
        playwright_root=pw_root_phys,
    )
    if not verified.get("ok"):
        raise RuntimeError("ACTIVE_RELEASE_UNVERIFIED:" + str(verified.get("error")))
    manifest_bytes = manifest_path.read_bytes()
    manifest_data = json.loads(manifest_bytes.decode("utf-8-sig"))
    entry_path = _recovery_target(rel_phys, agent_entrypoint)
    if not entry_path.is_file():
        raise RuntimeError("ACTIVE_RELEASE_ENTRYPOINT_MISSING:" + agent_entrypoint)
    file_map = {str(item["target"]): str(item["sha256"]) for item in manifest_data["files"]}
    if agent_entrypoint not in file_map:
        raise RuntimeError("ACTIVE_RELEASE_ENTRYPOINT_UNTRACKED:" + agent_entrypoint)
    entry_sha = sha256_file(entry_path)
    if entry_sha != file_map[agent_entrypoint]:
        raise RuntimeError("ACTIVE_RELEASE_ENTRYPOINT_HASH_MISMATCH")
    resolved_pw = pw_root_phys
    if resolved_pw is None and (rel_phys / "node_modules" / "playwright-core").is_dir():
        resolved_pw = rel_phys
    return {
        "bridge_root": str(base_phys),
        "release_dir": str(rel_phys),
        "manifest_path": str(manifest_path),
        "manifest_sha256": sha256_bytes(manifest_bytes),
        "source_head": verified["source_head"],
        "release_id": verified["release_id"],
        "file_count": verified["file_count"],
        "agent_entrypoint": agent_entrypoint,
        "agent_path": str(entry_path),
        "agent_entrypoint_sha256": entry_sha,
        "hub_entrypoint": "ff_hub.py" if (rel_phys / "ff_hub.py").is_file() else None,
        "hub_path": str(rel_phys / "ff_hub.py") if (rel_phys / "ff_hub.py").is_file() else None,
        "browser_hub_entrypoint": "ff_browser_hub.mjs" if (rel_phys / "ff_browser_hub.mjs").is_file() else None,
        "browser_hub_path": str(rel_phys / "ff_browser_hub.mjs") if (rel_phys / "ff_browser_hub.mjs").is_file() else None,
        "playwright_root": str(resolved_pw) if resolved_pw is not None else None,
        "playwright_integrity": verified.get("playwright_integrity"),
    }


def verify_active_release_pointer(
    bridge_root: Path, *, repo: Path | None = None, check_playwright: bool = True
) -> dict[str, Any]:
    base_phys = Path(os.path.abspath(bridge_root)).resolve()
    pointer_path = base_phys / ACTIVE_RELEASE_RELPATH
    if not pointer_path.exists():
        return {"ok": False, "present": False, "error": "ACTIVE_RELEASE_POINTER_MISSING"}
    try:
        _assert_no_reparse_relative(base_phys, pointer_path)
    except RuntimeError as exc:
        return {"ok": False, "present": True, "error": str(exc)}
    if not pointer_path.is_file():
        return {"ok": False, "present": True, "error": "ACTIVE_RELEASE_POINTER_NOT_FILE"}
    try:
        pointer = _read_json(pointer_path)
    except (OSError, ValueError, UnicodeError):
        return {"ok": False, "present": True, "error": "ACTIVE_RELEASE_POINTER_INVALID_JSON"}
    if not isinstance(pointer, dict) or pointer.get("schema") != ACTIVE_RELEASE_SCHEMA:
        return {"ok": False, "present": True, "error": "ACTIVE_RELEASE_SCHEMA_INVALID"}
    release_dir_raw = pointer.get("release_dir")
    if not isinstance(release_dir_raw, str) or not release_dir_raw.strip():
        return {"ok": False, "present": True, "error": "ACTIVE_RELEASE_DIR_INVALID"}
    entry_name = pointer.get("agent_entrypoint") or "ff_win_v3_main.py"
    pw_raw = pointer.get("playwright_root")
    pw_path = Path(pw_raw) if isinstance(pw_raw, str) and pw_raw.strip() else None
    try:
        checked = _validate_release_dir_for_pointer(
            base_phys,
            Path(release_dir_raw),
            repo=repo,
            playwright_root=pw_path,
            check_playwright=check_playwright,
            agent_entrypoint=str(entry_name),
        )
    except RuntimeError as exc:
        return {"ok": False, "present": True, "error": str(exc)}
    if pointer.get("manifest_sha256") != checked["manifest_sha256"]:
        return {"ok": False, "present": True, "error": "ACTIVE_RELEASE_MANIFEST_SHA_MISMATCH"}
    if pointer.get("source_head") != checked["source_head"]:
        return {"ok": False, "present": True, "error": "ACTIVE_RELEASE_SOURCE_HEAD_MISMATCH"}
    if pointer.get("release_id") != checked["release_id"]:
        return {"ok": False, "present": True, "error": "ACTIVE_RELEASE_ID_MISMATCH"}
    if pointer.get("agent_entrypoint_sha256") != checked["agent_entrypoint_sha256"]:
        return {"ok": False, "present": True, "error": "ACTIVE_RELEASE_ENTRYPOINT_SHA_MISMATCH"}
    return {
        "ok": True,
        "present": True,
        "error": None,
        "pointer_path": str(pointer_path),
        "release_name": pointer.get("release_name"),
        "updated_at": pointer.get("updated_at"),
        "previous": pointer.get("previous"),
        "rolled_back_from": pointer.get("rolled_back_from"),
        **checked,
    }


def resolve_active_release(
    bridge_root: Path, *, repo: Path | None = None, check_playwright: bool = True
) -> dict[str, Any]:
    """Resolve active release pointer fail-closed when present, or legacy bridge-v3 when absent."""
    base_phys = Path(os.path.abspath(bridge_root)).resolve()
    pointer_path = base_phys / ACTIVE_RELEASE_RELPATH
    if pointer_path.exists() or _is_reparse(pointer_path):
        return verify_active_release_pointer(base_phys, repo=repo, check_playwright=check_playwright)
    legacy_dir = base_phys / "bridge-v3"
    return {
        "ok": (legacy_dir / "ff_win_v3_main.py").is_file(),
        "present": False,
        "mode": "legacy_bridge_v3",
        "release_dir": str(legacy_dir),
        "agent_path": str(legacy_dir / "ff_win_v3_main.py"),
        "hub_path": str(legacy_dir / "ff_hub.py") if (legacy_dir / "ff_hub.py").is_file() else None,
        "browser_hub_path": str(legacy_dir / "ff_browser_hub.mjs") if (legacy_dir / "ff_browser_hub.mjs").is_file() else None,
        "playwright_root": str(legacy_dir) if (legacy_dir / "node_modules" / "playwright-core").is_dir() else None,
    }


def stage_release_dir(
    repo: Path,
    release_dir: Path,
    *,
    ref: str = "HEAD",
    require_clean: bool = True,
    strict_external: bool = False,
    playwright_root: Path | None = None,
) -> dict[str, Any]:
    """Stage a provenance-verified versioned release directory from Git."""
    result = apply_runtime(
        repo,
        release_dir,
        ref=ref,
        require_clean=require_clean,
        strict_external=strict_external,
    )
    pw_res = check_playwright_integrity(release_dir, playwright_root=playwright_root)
    if not pw_res.get("ok"):
        raise RuntimeError("PLAYWRIGHT_INTEGRITY_FAILED:" + str(pw_res.get("error")))
    result["playwright_integrity"] = pw_res
    return result


def activate_release(
    bridge_root: Path,
    release_dir: Path,
    *,
    repo: Path | None = None,
    release_name: str | None = None,
    playwright_root: Path | None = None,
    check_playwright: bool = True,
    agent_entrypoint: str = "ff_win_v3_main.py",
) -> dict[str, Any]:
    """Atomically switch state/active-release.json to a verified release directory."""
    base_phys = Path(os.path.abspath(bridge_root)).resolve()
    state_dir = base_phys / "state"
    if _is_reparse(state_dir):
        raise RuntimeError("ACTIVE_RELEASE_STATE_LINK_FORBIDDEN")
    checked = _validate_release_dir_for_pointer(
        base_phys,
        release_dir,
        repo=repo,
        playwright_root=playwright_root,
        check_playwright=check_playwright,
        agent_entrypoint=agent_entrypoint,
    )
    pointer_path = base_phys / ACTIVE_RELEASE_RELPATH
    previous_summary = None
    if pointer_path.exists():
        _assert_no_reparse_relative(base_phys, pointer_path)
        try:
            existing = _read_json(pointer_path)
        except (OSError, ValueError, UnicodeError):
            existing = None
        if isinstance(existing, dict) and existing.get("schema") == ACTIVE_RELEASE_SCHEMA:
            existing_dir = existing.get("release_dir")
            if isinstance(existing_dir, str) and _comparable_path(Path(existing_dir)) != _comparable_path(Path(checked["release_dir"])):
                previous_summary = _pointer_summary(existing)
            else:
                previous_summary = existing.get("previous")
    rel_name = release_name or Path(checked["release_dir"]).parent.name or Path(checked["release_dir"]).name
    payload: dict[str, Any] = {
        "schema": ACTIVE_RELEASE_SCHEMA,
        "release_dir": checked["release_dir"],
        "release_name": rel_name,
        "source_head": checked["source_head"],
        "release_id": checked["release_id"],
        "manifest_path": checked["manifest_path"],
        "manifest_sha256": checked["manifest_sha256"],
        "agent_entrypoint": checked["agent_entrypoint"],
        "agent_entrypoint_sha256": checked["agent_entrypoint_sha256"],
        "hub_entrypoint": checked["hub_entrypoint"],
        "browser_hub_entrypoint": checked["browser_hub_entrypoint"],
        "playwright_root": checked["playwright_root"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "previous": previous_summary,
    }
    atomic_json(pointer_path, payload)
    verified = verify_active_release_pointer(base_phys, repo=repo, check_playwright=check_playwright)
    if not verified.get("ok"):
        raise RuntimeError("ACTIVE_RELEASE_POST_ACTIVATE_FAILED:" + str(verified.get("error")))
    return verified


def rollback_active_release(
    bridge_root: Path,
    *,
    target_release_dir: Path | None = None,
    repo: Path | None = None,
    check_playwright: bool = True,
) -> dict[str, Any]:
    """Safely roll back state/active-release.json to the previous verified release.

    Never touches unrelated processes or owner state (chat-permission.json,
    stop.flag, secret). Validates the target release before mutating the pointer.
    """
    base_phys = Path(os.path.abspath(bridge_root)).resolve()
    pointer_path = base_phys / ACTIVE_RELEASE_RELPATH
    if not pointer_path.is_file():
        raise RuntimeError("ACTIVE_RELEASE_POINTER_MISSING")
    _assert_no_reparse_relative(base_phys, pointer_path)
    current = _read_json(pointer_path)
    if not isinstance(current, dict) or current.get("schema") != ACTIVE_RELEASE_SCHEMA:
        raise RuntimeError("ACTIVE_RELEASE_SCHEMA_INVALID")
    prev = current.get("previous") if isinstance(current.get("previous"), dict) else None
    rolling_back_to_prev = target_release_dir is None
    if rolling_back_to_prev:
        if not prev or not isinstance(prev.get("release_dir"), str) or not prev["release_dir"].strip():
            raise RuntimeError("ROLLBACK_TARGET_UNAVAILABLE")
        target_dir = Path(prev["release_dir"])
        target_name = prev.get("release_name")
        target_pw = Path(prev["playwright_root"]) if isinstance(prev.get("playwright_root"), str) and prev["playwright_root"].strip() else None
        target_entry = str(prev.get("agent_entrypoint") or "ff_win_v3_main.py")
    else:
        target_dir = Path(target_release_dir)
        target_name = target_dir.parent.name or target_dir.name
        target_pw = None
        target_entry = str(current.get("agent_entrypoint") or "ff_win_v3_main.py")

    def _is_hex64(value: Any) -> bool:
        return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)

    # When rolling back to the recorded `previous` pointer, a live predecessor
    # may originate from a squash-merged branch whose exact commit SHA is not in
    # the public repo's linear history (while still cryptographically pinned by
    # all four SHA-256/commit fields recorded in active-release.json). Require
    # all four pins and fail closed on any stale commit, missing pin, or drift.
    effective_repo = repo
    git_commit_in_repo: bool | None = None
    if repo is not None and (repo / ".git").exists():
        if rolling_back_to_prev and prev is not None:
            prev_head = prev.get("source_head")
            git_commit_in_repo = bool(is_hex40_commit(prev_head) and git_commit_exists(repo, str(prev_head)))
            all_prev_pins_present = (
                is_hex40_commit(prev_head)
                and str(prev_head).lower() not in KNOWN_STALE_COMMITS
                and _is_hex64(prev.get("manifest_sha256"))
                and _is_hex64(prev.get("release_id"))
                and _is_hex64(prev.get("agent_entrypoint_sha256"))
            )
            if not git_commit_in_repo and all_prev_pins_present:
                effective_repo = None
        else:
            git_commit_in_repo = None

    checked = _validate_release_dir_for_pointer(
        base_phys,
        target_dir,
        repo=effective_repo,
        playwright_root=target_pw,
        check_playwright=check_playwright,
        agent_entrypoint=target_entry,
    )
    if prev and _comparable_path(Path(checked["release_dir"])) == _comparable_path(Path(str(prev.get("release_dir") or ""))):
        if prev.get("manifest_sha256") and prev["manifest_sha256"] != checked["manifest_sha256"]:
            raise RuntimeError("ROLLBACK_TARGET_MANIFEST_DRIFTED")
        if prev.get("source_head") and prev["source_head"] != checked["source_head"]:
            raise RuntimeError("ROLLBACK_TARGET_SOURCE_HEAD_DRIFTED")
        if prev.get("release_id") and prev["release_id"] != checked["release_id"]:
            raise RuntimeError("ROLLBACK_TARGET_RELEASE_ID_DRIFTED")
        if prev.get("agent_entrypoint_sha256") and prev["agent_entrypoint_sha256"] != checked["agent_entrypoint_sha256"]:
            raise RuntimeError("ROLLBACK_TARGET_ENTRYPOINT_DRIFTED")
    if repo is not None and (repo / ".git").exists() and git_commit_in_repo is None:
        git_commit_in_repo = git_commit_exists(repo, checked["source_head"])
    payload: dict[str, Any] = {
        "schema": ACTIVE_RELEASE_SCHEMA,
        "release_dir": checked["release_dir"],
        "release_name": target_name or Path(checked["release_dir"]).parent.name,
        "source_head": checked["source_head"],
        "release_id": checked["release_id"],
        "manifest_path": checked["manifest_path"],
        "manifest_sha256": checked["manifest_sha256"],
        "agent_entrypoint": checked["agent_entrypoint"],
        "agent_entrypoint_sha256": checked["agent_entrypoint_sha256"],
        "hub_entrypoint": checked["hub_entrypoint"],
        "browser_hub_entrypoint": checked["browser_hub_entrypoint"],
        "playwright_root": checked["playwright_root"],
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "previous": None,
        "rolled_back_from": _pointer_summary(current),
    }
    atomic_json(pointer_path, payload)
    verified = verify_active_release_pointer(base_phys, repo=effective_repo, check_playwright=check_playwright)
    if not verified.get("ok"):
        raise RuntimeError("ROLLBACK_POST_VERIFY_FAILED:" + str(verified.get("error")))
    if git_commit_in_repo is not None:
        verified["git_commit_in_repo"] = git_commit_in_repo
    verified["rollback_pin_verified"] = bool(rolling_back_to_prev)
    return verified


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
    verify_p.add_argument("--repo", type=Path)
    verify_p.add_argument("--playwright-root", type=Path)
    recover_p = sub.add_parser("recover")
    recover_p.add_argument("--runtime-root", type=Path, required=True)
    activate_p = sub.add_parser("activate")
    activate_p.add_argument("--bridge-root", type=Path, required=True)
    activate_p.add_argument("--release-dir", type=Path, required=True)
    activate_p.add_argument("--repo", type=Path)
    activate_p.add_argument("--release-name")
    activate_p.add_argument("--playwright-root", type=Path)
    rollback_p = sub.add_parser("rollback")
    rollback_p.add_argument("--bridge-root", type=Path, required=True)
    rollback_p.add_argument("--release-dir", type=Path)
    rollback_p.add_argument("--repo", type=Path)
    pointer_p = sub.add_parser("pointer-status")
    pointer_p.add_argument("--bridge-root", type=Path, required=True)
    pointer_p.add_argument("--repo", type=Path)
    ns = parser.parse_args()
    try:
        if ns.command == "apply":
            result = apply_runtime(ns.repo, ns.runtime_root, ref=ns.ref, require_clean=not ns.allow_dirty,
                                   strict_external=ns.strict_external_validation)
        elif ns.command == "verify":
            result = verify_runtime(ns.runtime_root, repo=ns.repo, playwright_root=ns.playwright_root)
            if not result["ok"]:
                print(json.dumps(result, ensure_ascii=False))
                return 3
        elif ns.command == "activate":
            result = activate_release(
                ns.bridge_root,
                ns.release_dir,
                repo=ns.repo,
                release_name=ns.release_name,
                playwright_root=ns.playwright_root,
            )
        elif ns.command == "rollback":
            result = rollback_active_release(ns.bridge_root, target_release_dir=ns.release_dir, repo=ns.repo)
        elif ns.command == "pointer-status":
            result = verify_active_release_pointer(ns.bridge_root, repo=ns.repo)
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
