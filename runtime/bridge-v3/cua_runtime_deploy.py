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
MANIFEST_NAME = "installed-runtime-manifest.json"
LOCK_NAME = ".cua-runtime-deploy-lock.json"
TX_DIR_NAME = ".cua-deploy"


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


def build_plan(repo: Path, ref: str = "HEAD") -> dict[str, Any]:
    repo = repo.resolve()
    head = resolve_ref(repo, ref)
    current_head = resolve_ref(repo, "HEAD")
    source_map = RUNTIME_SOURCE_MAP if head == current_head else _runtime_source_map_from_ref(repo, head)
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
        dst.write_bytes(raw)
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


def _copy_replace(src: Path, dst: Path, txid: str) -> None:
    src, dst = extended_path(src, force=True), extended_path(dst, force=True)
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_name(dst.name + f".{txid}.new")
    shutil.copy2(src, tmp)
    _replace_with_retry(tmp, dst)


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


def _restore_journal(runtime_root: Path, journal: dict[str, Any]) -> None:
    runtime_root = extended_path(runtime_root, force=True)
    txid = str(journal["txid"])
    for item in journal["files"]:
        target = runtime_root / str(item["target"])
        if item["existed"]:
            backup = extended_path(item["backup"], force=True)
            if not backup.is_file() or sha256_file(backup) != item["old_sha256"]:
                raise RuntimeError(f"ROLLBACK_BACKUP_INVALID:{item['target']}")
            _copy_replace(backup, target, txid + ".rollback")
            if sha256_file(target) != item["old_sha256"]:
                raise RuntimeError(f"ROLLBACK_HASH_MISMATCH:{item['target']}")
        elif target.exists():
            target.unlink()

    manifest_target = runtime_root / MANIFEST_NAME
    previous = journal["previous_manifest"]
    if previous["existed"]:
        backup = extended_path(previous["backup"], force=True)
        if not backup.is_file() or sha256_file(backup) != previous["old_sha256"]:
            raise RuntimeError("ROLLBACK_MANIFEST_BACKUP_INVALID")
        _copy_replace(backup, manifest_target, txid + ".manifest.rollback")
    elif manifest_target.exists():
        manifest_target.unlink()


def recover_stale(runtime_root: Path) -> dict[str, Any]:
    runtime_root = extended_path(runtime_root.resolve(), force=True)
    lock_path = runtime_root / LOCK_NAME
    if not lock_path.is_file():
        return {"recovered": False}
    lock = _read_json(lock_path)
    pid = int(lock.get("pid") or 0)
    started = lock.get("started_at")
    alive = (_process_alive(pid, created_before=datetime.fromisoformat(started).timestamp())
             if started else _process_alive(pid))
    if pid != os.getpid() and alive:
        raise RuntimeError(f"DEPLOY_BUSY:{pid}")
    journal_path = extended_path(str(lock.get("journal") or ""), force=True)
    if not journal_path.is_file():
        # Targets are not modified until the journal has been durably written.
        # A dead owner with no journal therefore means the transaction stopped
        # before commit began; clearing the stale lock is safe.
        lock_path.unlink()
        return {"recovered": True, "txid": lock.get("txid"), "phase": "precommit_no_journal"}
    journal = _read_json(journal_path)
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
    repo = repo.resolve()
    runtime_root = extended_path(runtime_root.resolve(), force=True)
    if require_clean:
        cp = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True, timeout=20, check=False)
        if cp.returncode != 0 or cp.stdout.strip():
            raise RuntimeError("WORKTREE_DIRTY")
    runtime_root.mkdir(parents=True, exist_ok=True)
    recovered = recover_stale(runtime_root)
    plan = build_plan(repo, ref)
    txid = uuid.uuid4().hex
    tx_root = runtime_root / TX_DIR_NAME / txid
    stage_root = tx_root / "stage"
    backup_root = tx_root / "backup"
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
    manifest_target = runtime_root / MANIFEST_NAME
    previous_manifest = {"existed": manifest_target.is_file(), "backup": None, "old_sha256": None}
    try:
        backup_root.mkdir(parents=True, exist_ok=True)
        previous_targets: set[str] = set()
        if manifest_target.is_file():
            previous_data = _read_json(manifest_target)
            previous_targets = {
                str(item["target"]) for item in previous_data.get("files", [])
                if isinstance(item, dict) and item.get("target")
            }
        plan_targets = {str(item["target"]) for item in plan["files"]}
        managed_targets = list(dict.fromkeys(
            [str(item["target"]) for item in plan["files"]] + sorted(previous_targets - plan_targets)
        ))
        for target_name in managed_targets:
            target = runtime_root / target_name
            existed = target.is_file()
            backup = backup_root / target_name
            old_sha = sha256_file(target) if existed else None
            if existed:
                backup.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(target, backup)
                if sha256_file(backup) != old_sha:
                    raise RuntimeError(f"BACKUP_HASH_MISMATCH:{target_name}")
            journal_files.append({
                "target": target_name,
                "existed": existed,
                "backup": str(backup),
                "old_sha256": old_sha,
            })

        if manifest_target.is_file():
            mb = backup_root / MANIFEST_NAME
            shutil.copy2(manifest_target, mb)
            previous_manifest = {"existed": True, "backup": str(mb), "old_sha256": sha256_file(manifest_target)}

        journal = {"schema": LOCK_SCHEMA + "/journal", "txid": txid, "files": journal_files, "previous_manifest": previous_manifest}
        atomic_json(journal_path, journal)

        # Local lifecycle controller stops the exact server only after backups
        # are durable and the keeper is paused by this transaction's lock.
        if before_replace is not None:
            before_replace()
        replaced = 0
        unchanged = 0
        for item in plan["files"]:
            target = runtime_root / str(item["target"])
            if target.is_file() and sha256_file(target) == item["sha256"]:
                unchanged += 1
                continue
            _copy_replace(stage_root / str(item["target"]), target, txid)
            replaced += 1
            if fail_after is not None and replaced >= fail_after:
                raise RuntimeError(f"INJECTED_FAILURE_AFTER:{replaced}")
        for target_name in sorted(previous_targets - plan_targets):
            target = runtime_root / target_name
            if target.exists():
                target.unlink()

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
        shutil.rmtree(tx_root, ignore_errors=True)
        return {
            "ok": True,
            "recovered": recovered,
            "validation": validation,
            "files_replaced": replaced,
            "files_unchanged": unchanged,
            **verified,
        }
    except Exception:
        try:
            if journal_path.is_file():
                _restore_journal(runtime_root, _read_json(journal_path))
                if lock_path.exists():
                    lock_path.unlink()
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
