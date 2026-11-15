"""Immutable, local-only rollback bundles for Windows Bridge cold upgrades.

This module NEVER stops services, restarts a session, deploys a candidate or
automatically restores a running installation. The rollback call requires the
caller to prove the server is already stopped. It preserves legacy journals.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime/bridge-v3"))
import cua_runtime_deploy as deploy

SCHEMA = "ff-bridge-cold-snapshot/v1"


def digest(path: Path) -> str:
    return deploy.sha256_file(path)


def _plain(path: Path, *, must_file: bool = False) -> None:
    node = path
    while True:
        if node.is_symlink() or getattr(node, "is_junction", lambda: False)():
            raise RuntimeError("SNAPSHOT_REPARSE_FORBIDDEN")
        if node.parent == node:
            break
        node = node.parent
    if must_file and (not path.is_file() or path.stat().st_nlink != 1):
        raise RuntimeError("SNAPSHOT_FILE_UNSAFE:" + path.name)


def legacy_journals(runtime: Path) -> list[dict]:
    """Verify every orphaned v1 backup without touching historic transactions."""
    if (runtime / deploy.LOCK_NAME).exists():
        raise RuntimeError("DEPLOY_LOCK_PRESENT")
    txroot = runtime / deploy.TX_DIR_NAME
    if not txroot.exists():
        return []
    _plain(txroot)
    if not txroot.is_dir():
        raise RuntimeError("LEGACY_TRANSACTION_ROOT_INVALID")
    result = []
    for tx in sorted(txroot.iterdir()):
        _plain(tx)
        if not tx.is_dir() or len(tx.name) != 32 or any(c not in "0123456789abcdef" for c in tx.name):
            raise RuntimeError("UNRECOGNIZED_DEPLOY_TRANSACTION")
        journal_path = tx / "journal.json"
        _plain(journal_path, must_file=True)
        journal = json.loads(journal_path.read_text(encoding="utf-8-sig"))
        if (journal.get("schema") != "cua-runtime-deploy-lock/v1/journal"
                or journal.get("txid") != tx.name
                or not isinstance(journal.get("files"), list)):
            raise RuntimeError("LEGACY_JOURNAL_UNPROVEN")
        verified = 0
        seen = set()
        for entry in journal["files"]:
            name = entry.get("target")
            expected_hash = entry.get("old_sha256")
            if (not isinstance(name, str) or name in seen
                    or not isinstance(expected_hash, str) or len(expected_hash) != 64
                    or any(ch not in "0123456789abcdef" for ch in expected_hash)):
                raise RuntimeError("LEGACY_JOURNAL_RECORD_INVALID")
            seen.add(name)
            expected_path = deploy._recovery_target(tx / "backup", name)
            supplied = entry.get("backup")
            if not isinstance(supplied, str) or deploy._comparable_path(Path(supplied)) != deploy._comparable_path(expected_path):
                raise RuntimeError("LEGACY_JOURNAL_BACKUP_PATH_INVALID")
            _plain(expected_path, must_file=True)
            if digest(expected_path) != expected_hash:
                raise RuntimeError("LEGACY_JOURNAL_BACKUP_HASH_INVALID")
            verified += 1
        prev = journal.get("previous_manifest")
        if not isinstance(prev, dict) or prev.get("existed") is not True:
            raise RuntimeError("LEGACY_MANIFEST_BACKUP_INVALID")
        manifest_path = tx / "backup" / deploy.MANIFEST_NAME
        if (not isinstance(prev.get("backup"), str)
                or deploy._comparable_path(Path(prev["backup"])) != deploy._comparable_path(manifest_path)):
            raise RuntimeError("LEGACY_MANIFEST_BACKUP_PATH_INVALID")
        _plain(manifest_path, must_file=True)
        if digest(manifest_path) != prev.get("old_sha256"):
            raise RuntimeError("LEGACY_MANIFEST_BACKUP_HASH_INVALID")
        result.append({"txid": tx.name, "journal_sha256": digest(journal_path), "backups_verified": verified,
                       "manifest_sha256": digest(manifest_path)})
    return result


def preflight(repo: Path, runtime: Path, *, trusted_head: str, candidate_ref: str = "HEAD") -> dict:
    runtime = Path(os.path.abspath(runtime))
    _plain(runtime)
    if not runtime.is_dir():
        raise RuntimeError("INSTALLED_RUNTIME_MISSING")
    if not (len(trusted_head) == 40 and all(c in "0123456789abcdef" for c in trusted_head)):
        raise RuntimeError("TRUSTED_HEAD_NOT_PINNED")
    proof = deploy.plan_manifest_reconciliation(repo, runtime, trusted_head=trusted_head, ref=candidate_ref)
    history = legacy_journals(runtime)
    if not proof.get("provenance_verified") or proof.get("unresolved_deploy_transactions") != len(history):
        raise RuntimeError("HISTORICAL_TRANSACTION_COUNT_CHANGED")
    # Check explicitly that the full trusted tree fits the current candidate.
    old_plan = proof["trusted_manifest"]
    candidate_plan = deploy.build_plan(repo, ref=candidate_ref)
    old = {entry["target"] for entry in old_plan["files"]}
    candidate = {entry["target"] for entry in candidate_plan["files"]}
    if not old <= candidate:
        raise RuntimeError("RETIREMENT_REQUIRES_EXPLICIT_REVIEW")
    return {"source_head": trusted_head, "candidate_head": candidate_plan["source_head"],
            "source_count": len(old), "candidate_count": len(candidate),
            "old_manifest_sha256": proof["previous_manifest_sha256"],
            "historical_journals": history,
            "historical_backup_file_count": sum(j["backups_verified"] for j in history),
            "preflight_verified": True, "no_live_changes": True,
            "_source_plan": old_plan, "_candidate_plan": candidate_plan}


def _atomic_write(path: Path, data: bytes) -> None:
    name = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with name.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        name.unlink(missing_ok=True)


def capture(repo: Path, runtime: Path, snapshot: Path, *, trusted_head: str,
            candidate_ref: str = "HEAD") -> dict:
    """Copy a bounded, verified source snapshot, no live install mutation."""
    runtime = Path(os.path.abspath(runtime))
    snapshot = Path(os.path.abspath(snapshot))
    proof = preflight(repo, runtime, trusted_head=trusted_head, candidate_ref=candidate_ref)
    if snapshot.exists() or snapshot.is_relative_to(runtime):
        raise RuntimeError("SNAPSHOT_DESTINATION_UNSAFE")
    _plain(snapshot.parent)
    if not snapshot.parent.is_dir():
        raise RuntimeError("SNAPSHOT_PARENT_MISSING")
    snapshot.mkdir(mode=0o700)
    records = []
    try:
        for item in proof["_source_plan"]["files"]:
            name = item["target"]
            src = deploy._recovery_target(runtime, name)
            _plain(src, must_file=True)
            if digest(src) != item["sha256"]:
                raise RuntimeError("SOURCE_CHANGED_DURING_SNAPSHOT:" + name)
            dst = deploy._recovery_target(snapshot / "files", name)
            dst.parent.mkdir(parents=True, exist_ok=True)
            with src.open("rb") as input_file, dst.open("xb") as output_file:
                shutil.copyfileobj(input_file, output_file)
                output_file.flush()
                os.fsync(output_file.fileno())
            if digest(dst) != item["sha256"]:
                raise RuntimeError("SNAPSHOT_COPY_HASH_INVALID:" + name)
            records.append({"target": name, "sha256": item["sha256"]})
        original = runtime / deploy.MANIFEST_NAME
        _plain(original, must_file=True)
        data = original.read_bytes()
        if hashlib.sha256(data).hexdigest() != proof["old_manifest_sha256"]:
            raise RuntimeError("MANIFEST_CHANGED_DURING_SNAPSHOT")
        _atomic_write(snapshot / "previous-manifest.json", data)
        record = {"schema": SCHEMA, "source_head": trusted_head,
                  "candidate_head": proof["candidate_head"],
                  "previous_manifest_sha256": proof["old_manifest_sha256"],
                  "source_files": records,
                  "candidate_files": [{"target": entry["target"], "sha256": entry["sha256"]}
                                      for entry in proof["_candidate_plan"]["files"]],
                  "historical_journals": proof["historical_journals"]}
        _atomic_write(snapshot / "bundle.json", (json.dumps(record, sort_keys=True, indent=2) + "\n").encode("utf-8"))
        verify_bundle(snapshot)
        # Before using the snapshot, confirm that no file changed since copy.
        for item in records:
            if digest(deploy._recovery_target(runtime, item["target"])) != item["sha256"]:
                raise RuntimeError("SOURCE_CHANGED_AFTER_SNAPSHOT")
        if digest(original) != record["previous_manifest_sha256"]:
            raise RuntimeError("MANIFEST_CHANGED_AFTER_SNAPSHOT")
        return {"ok": True, "bundle": str(snapshot), "source_files": len(records),
                "historical_journals_verified": len(record["historical_journals"]),
                "historical_files_verified": proof["historical_backup_file_count"],
                "source_head": trusted_head, "candidate_head": record["candidate_head"],
                "runtime_modified": False}
    except BaseException:
        # Preserve a partial backup for forensics; never present it as ready.
        raise


def verify_bundle(snapshot: Path) -> dict:
    snapshot = Path(os.path.abspath(snapshot))
    _plain(snapshot)
    path = snapshot / "bundle.json"
    _plain(path, must_file=True)
    record = json.loads(path.read_text(encoding="utf-8"))
    if record.get("schema") != SCHEMA:
        raise RuntimeError("SNAPSHOT_SCHEMA_INVALID")
    old = record.get("source_files")
    new = record.get("candidate_files")
    if not isinstance(old, list) or not isinstance(new, list) or not old:
        raise RuntimeError("SNAPSHOT_RECORD_INVALID")
    for item in old:
        p = deploy._recovery_target(snapshot / "files", item["target"])
        _plain(p, must_file=True)
        if digest(p) != item["sha256"]:
            raise RuntimeError("SNAPSHOT_FILE_CORRUPT:" + item["target"])
    manifest = snapshot / "previous-manifest.json"
    _plain(manifest, must_file=True)
    if digest(manifest) != record["previous_manifest_sha256"]:
        raise RuntimeError("SNAPSHOT_MANIFEST_CORRUPT")
    return record


def assert_runtime_quiescent(runtime: Path) -> None:
    """Fail closed if any Bridge agent/keeper uses this physical runtime.

    The caller's offline flag is not proof. Process discovery is independent
    and excludes the short-lived PowerShell query process itself.
    """
    runtime = Path(os.path.abspath(runtime)).resolve()
    if os.name != "nt":
        return
    command = (
        "$ErrorActionPreference='Stop'; "
        "$items=Get-CimInstance Win32_Process | "
        "Where-Object { $_.Name -in @('python.exe','powershell.exe','pwsh.exe') }; "
        "@($items | Select-Object ProcessId,Name,CommandLine) | ConvertTo-Json -Compress -Depth 3"
    )
    cp = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-Command", command],
                        capture_output=True, text=True, timeout=35, check=False)
    if cp.returncode != 0:
        raise RuntimeError("RESTORE_PROCESS_LIST_UNAVAILABLE")
    try:
        rows = json.loads(cp.stdout.strip() or "[]")
    except (ValueError, UnicodeError) as exc:
        raise RuntimeError("RESTORE_PROCESS_LIST_INVALID") from exc
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        raise RuntimeError("RESTORE_PROCESS_LIST_INVALID")
    names = ("ff_win_v3_main.py", "ff_win_v3_agent.py", "ff_win_v3_keeper.ps1")
    aliases = [str(runtime)]
    alias_root = Path(os.environ.get("LOCALAPPDATA") or "") / "FF-Windows-Bridge" / "bridge-v3"
    try:
        if alias_root.resolve() == runtime:
            aliases.append(str(alias_root))
    except (OSError, ValueError):
        pass
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("RESTORE_PROCESS_LIST_INVALID")
        cmd = str(row.get("CommandLine") or "").casefold().replace('"', "")
        exe = str(row.get("Name") or "").casefold()
        if exe in {"powershell.exe", "pwsh.exe"} and "get-ciminstance" in cmd:
            continue
        if exe not in {"python.exe", "powershell.exe", "pwsh.exe"}:
            continue
        for base in aliases:
            if any((str(Path(base) / name)).casefold() in cmd for name in names):
                raise RuntimeError("RESTORE_RUNTIME_STILL_RUNNING")
    # Also check PID files: an active PID without a discoverable command line
    # must never be interpreted as proof of a stopped server.
    for name in ("agent.pid", "keeper.pid"):
        file = runtime / name
        if file.is_file():
            try:
                value = file.read_text(encoding="ascii").strip()
                if value.isdigit() and deploy._process_alive(int(value)):
                    raise RuntimeError("RESTORE_PID_STILL_ACTIVE:" + name)
            except UnicodeError as exc:
                raise RuntimeError("RESTORE_PID_FILE_INVALID") from exc


def restore(snapshot: Path, runtime: Path, *, offline_confirmed: bool = False) -> dict:
    """Restore only verified tracked files; caller must ensure all agents stopped."""
    if not offline_confirmed:
        raise RuntimeError("RESTORE_OFFLINE_CONFIRMATION_REQUIRED")
    record = verify_bundle(snapshot)
    runtime = Path(os.path.abspath(runtime))
    _plain(runtime)
    if not runtime.is_dir():
        raise RuntimeError("RUNTIME_DESTINATION_MISSING")
    assert_runtime_quiescent(runtime)
    previous = {row["target"]: row["sha256"] for row in record["source_files"]}
    candidate = {row["target"]: row["sha256"] for row in record["candidate_files"]}
    # Validate ALL affected target identities before the first change.
    for name in candidate:
        path = deploy._recovery_target(runtime, name)
        if path.exists():
            _plain(path, must_file=True)
            actual = digest(path)
            if actual not in {previous.get(name), candidate[name]}:
                raise RuntimeError("RESTORE_UNEXPECTED_TARGET:" + name)
    manifest = runtime / deploy.MANIFEST_NAME
    if manifest.is_file():
        _plain(manifest, must_file=True)
        # The candidate's generated manifest varies in metadata: accept only
        # the same pinned candidate head and matching source file list.
        raw = json.loads(manifest.read_text(encoding="utf-8-sig"))
        if raw.get("source_head") not in {record["source_head"], record["candidate_head"]}:
            # The original stale manifest also has a different source_head;
            # allow it only when its entire byte hash still matches the backup.
            if digest(manifest) != record["previous_manifest_sha256"]:
                raise RuntimeError("RESTORE_UNRELATED_MANIFEST")
    for name in candidate.keys() - previous.keys():
        path = deploy._recovery_target(runtime, name)
        if path.is_file():
            path.unlink()
    for name in previous:
        src = deploy._recovery_target(snapshot / "files", name)
        dst = deploy._recovery_target(runtime, name)
        dst.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(dst, src.read_bytes())
    _atomic_write(manifest, (snapshot / "previous-manifest.json").read_bytes())
    for name, hash_value in previous.items():
        if digest(deploy._recovery_target(runtime, name)) != hash_value:
            raise RuntimeError("RESTORED_FILE_VERIFICATION_FAILED:" + name)
    if digest(manifest) != record["previous_manifest_sha256"]:
        raise RuntimeError("RESTORED_MANIFEST_VERIFICATION_FAILED")
    return {"ok": True, "restored_files": len(previous), "removed_candidate_only_files": len(candidate.keys() - previous.keys())}


# Explicitly pinned dependency closure for an independent recovery process.
# Do not import code from a runtime that is being overwritten during rollback.
RECOVERY_KIT_FILES = (
    "tools/cua_cold_rollback_bundle.py",
    "tools/cua_cold_recovery_watchdog.py",
    "runtime/bridge-v3/cua_runtime_deploy.py",
    "runtime/bridge-v3/cua_release_manifest.py",
    "runtime/bridge-v3/cua_windows_paths.py",
    "runtime/bridge-v3/cua_lifecycle.py",
    "runtime/bridge-v3/ff_win_process_identity.py",
)


def create_recovery_kit(repo: Path, destination: Path, ref: str = "HEAD") -> dict:
    repo = repo.resolve()
    dest = Path(os.path.abspath(destination))
    if dest.exists():
        raise RuntimeError("RECOVERY_KIT_DESTINATION_EXISTS")
    _plain(dest.parent)
    if not dest.parent.is_dir():
        raise RuntimeError("RECOVERY_KIT_PARENT_INVALID")
    commit = deploy.resolve_ref(repo, ref)
    dest.mkdir(mode=0o700)
    files = []
    for name in RECOVERY_KIT_FILES:
        raw = deploy.git_blob_bytes(repo, commit, name)
        target = dest / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        check = hashlib.sha256(raw).hexdigest()
        if digest(target) != check:
            raise RuntimeError("RECOVERY_KIT_COPY_CORRUPT:" + name)
        files.append({"path": name, "sha256": check, "bytes": len(raw)})
    record = {"schema": "ff-independent-recovery-kit/v1",
              "source_commit": commit, "files": files}
    _atomic_write(dest / "kit-manifest.json",
                  (json.dumps(record, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    verify_recovery_kit(dest)
    # A clean import from the copied paths must work without the owner's repo
    # and without importing modules from the installed runtime.
    args = [
        sys.executable, "-I", "-c",
        "import sys; sys.path.insert(0, sys.argv[1]); sys.path.insert(0, sys.argv[2]); "
        "import cua_cold_recovery_watchdog, cua_cold_rollback_bundle",
        str(dest / "tools"), str(dest / "runtime/bridge-v3"),
    ]
    cp = subprocess.run(args, cwd=dest, capture_output=True, timeout=25, check=False)
    if cp.returncode:
        raise RuntimeError("RECOVERY_KIT_IMPORT_SMOKE_FAILED")
    return {"ok": True, "kit": str(dest), "commit": commit,
            "file_count": len(files), "independent_import": True}


def verify_recovery_kit(path: Path) -> dict:
    root = Path(os.path.abspath(path))
    _plain(root)
    mf = root / "kit-manifest.json"
    _plain(mf, must_file=True)
    data = json.loads(mf.read_text(encoding="utf-8"))
    if (data.get("schema") != "ff-independent-recovery-kit/v1"
            or len(data.get("files", [])) != len(RECOVERY_KIT_FILES)
            or {row.get("path") for row in data["files"]} != set(RECOVERY_KIT_FILES)):
        raise RuntimeError("RECOVERY_KIT_MANIFEST_UNPROVEN")
    for row in data["files"]:
        item = deploy._recovery_target(root, row["path"])
        _plain(item, must_file=True)
        if digest(item) != row.get("sha256"):
            raise RuntimeError("RECOVERY_KIT_HASH_MISMATCH:" + row["path"])
    return {"ok": True, "kit": str(root), "files_verified": len(RECOVERY_KIT_FILES)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("preflight", "capture", "verify", "restore", "kit", "verify-kit"))
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--trusted-head")
    parser.add_argument("--candidate-ref", default="HEAD")
    parser.add_argument("--offline-confirmed", action="store_true")
    parser.add_argument("--kit-root", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "preflight":
            r = preflight(args.repo, args.runtime, trusted_head=args.trusted_head,
                          candidate_ref=args.candidate_ref)
            result = {k: v for k, v in r.items() if not k.startswith("_")}
        elif args.action == "capture":
            result = capture(args.repo, args.runtime, args.snapshot, trusted_head=args.trusted_head,
                             candidate_ref=args.candidate_ref)
        elif args.action == "verify":
            result = {"ok": True, "source_files": len(verify_bundle(args.snapshot)["source_files"])}
        elif args.action == "kit":
            result = create_recovery_kit(args.repo, args.kit_root, ref=args.candidate_ref)
        elif args.action == "verify-kit":
            result = verify_recovery_kit(args.kit_root)
        else:
            result = restore(args.snapshot, args.runtime, offline_confirmed=args.offline_confirmed)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__ + ":" + str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
