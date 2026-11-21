"""Read-only parity, provenance, and Playwright integrity check for an installed runtime.

Run from a checkout:
  python tools/runtime_parity.py --installed <bridge-v3 folder> [--ref origin/main] [--disk]

Compares the bytes `git show <ref>:path` returns with the installed files, hashing only.
When `installed-runtime-manifest.json` is present (or `--require-manifest` is passed),
verifies real 40-char Git provenance (rejecting stale commits like c034e527/abd6666) and
manifest file SHA-256 integrity. When `node_modules/playwright-core` is present (or
`--playwright-root` is passed), enforces Playwright `coreBundle.js` integrity fail-closed.
Report fields hold file names, hashes, and counts, never file contents or absolute paths.
Exit code 1 when any check fails.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

PREFIX = "runtime/bridge-v3/"
REPO_DEFAULT = Path(__file__).resolve().parents[1]
_RUNTIME_DIR = REPO_DEFAULT / "runtime" / "bridge-v3"
if str(_RUNTIME_DIR) not in sys.path:
    sys.path.insert(0, str(_RUNTIME_DIR))

import cua_runtime_deploy as _deploy  # noqa: E402


def git(repo: Path, *args: str) -> bytes:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if done.returncode:
        raise SystemExit("git failed: " + " ".join(args))
    return done.stdout


def resolve_commit(repo: Path, ref: str) -> str:
    return git(repo, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()


def compare(repo: Path, installed: Path, ref: str) -> dict:
    names = [n for n in git(repo, "ls-tree", "-r", "--name-only", ref, PREFIX).decode().split("\n") if n]
    same, different, missing = 0, [], []
    for name in names:
        target = installed / name[len(PREFIX):]
        if not target.is_file():
            missing.append(name[len(PREFIX):])
            continue
        stored = git(repo, "show", f"{ref}:{name}")
        if hashlib.sha256(stored).digest() == hashlib.sha256(target.read_bytes()).digest():
            same += 1
        else:
            different.append(name[len(PREFIX):])
    return {"ref": ref, "tracked": len(names), "identical": same,
            "different": different, "missing_in_installed": missing}


def check_installed_manifest(
    repo: Path, installed: Path, ref: str, *, required: bool = False
) -> dict:
    manifest_path = installed / _deploy.MANIFEST_NAME
    if not manifest_path.exists() and not required:
        return {"present": False, "skipped": True, "ok": True}
    verified = _deploy.verify_runtime(installed, repo=repo, check_playwright=False)
    expected_commit = resolve_commit(repo, ref)
    source_head = verified.get("source_head")
    commit_matches_ref = bool(source_head and source_head == expected_commit)
    ok = bool(verified.get("ok")) and commit_matches_ref
    error = verified.get("error")
    if not error and not commit_matches_ref:
        error = "INSTALLED_MANIFEST_REF_MISMATCH"
    return {
        "present": manifest_path.exists(),
        "skipped": False,
        "ok": ok,
        "error": error,
        "source_head": source_head,
        "expected_ref_commit": expected_commit,
        "commit_matches_ref": commit_matches_ref,
        "release_id": verified.get("release_id"),
        "file_count": verified.get("file_count", 0),
        "mismatch_count": len(verified.get("mismatches", [])),
    }


def check_playwright_integrity(
    installed: Path, *, playwright_root: Path | None = None
) -> dict:
    result = _deploy.check_playwright_integrity(installed, playwright_root=playwright_root)
    # Keep report privacy-safe: never emit raw file paths or file contents.
    return {
        "ok": bool(result.get("ok")),
        "checked": bool(result.get("checked")),
        "present": bool(result.get("present")),
        "scanner": result.get("scanner"),
        "error": result.get("error"),
        "matched_rules": list(result.get("matched_rules") or []),
        "bundle_sha256": result.get("bundle_sha256"),
    }


def check_active_release(
    bridge_root: Path, *, repo: Path | None = None, installed: Path | None = None
) -> dict:
    verified = _deploy.verify_active_release_pointer(
        bridge_root, repo=repo, check_playwright=False
    )
    matches_installed = None
    if verified.get("ok") and installed is not None:
        matches_installed = (
            _deploy._comparable_path(Path(verified["release_dir"]))
            == _deploy._comparable_path(installed)
        )
    ok = bool(verified.get("ok")) and (matches_installed is not False)
    error = verified.get("error")
    if not error and matches_installed is False:
        error = "ACTIVE_RELEASE_DIFFERS_FROM_INSTALLED"
    return {
        "ok": ok,
        "present": bool(verified.get("present")),
        "error": error,
        "release_name": verified.get("release_name"),
        "source_head": verified.get("source_head"),
        "release_id": verified.get("release_id"),
        "matches_installed": matches_installed,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--installed", required=True, type=Path)
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--repo", type=Path, default=REPO_DEFAULT)
    parser.add_argument("--disk", action="store_true", help="also report free space of the installed drive")
    parser.add_argument("--require-manifest", action="store_true",
                        help="fail closed if installed-runtime-manifest.json is absent")
    parser.add_argument("--playwright-root", type=Path,
                        help="explicit playwright-core root to verify fail-closed")
    parser.add_argument("--skip-playwright-integrity", action="store_true",
                        help="skip Playwright coreBundle.js scan (diagnostics only)")
    parser.add_argument("--bridge-root", type=Path,
                        help="also verify state/active-release.json under this bridge root")
    args = parser.parse_args(argv)
    if not args.installed.is_dir():
        raise SystemExit("installed folder not found")
    report = compare(args.repo, args.installed, args.ref)
    manifest_report = check_installed_manifest(
        args.repo, args.installed, args.ref, required=args.require_manifest
    )
    report["manifest_provenance"] = manifest_report
    pw_ok = True
    if not args.skip_playwright_integrity:
        pw_report = check_playwright_integrity(
            args.installed, playwright_root=args.playwright_root
        )
        report["playwright_integrity"] = pw_report
        pw_ok = bool(pw_report["ok"])
    pointer_ok = True
    if args.bridge_root is not None:
        pointer_report = check_active_release(
            args.bridge_root, repo=args.repo, installed=args.installed
        )
        report["active_release_pointer"] = pointer_report
        pointer_ok = bool(pointer_report["ok"])
    if args.disk:
        usage = shutil.disk_usage(args.installed)
        report["disk_free_gb"] = round(usage.free / 1e9, 1)
        report["disk_free_percent"] = round(100 * usage.free / usage.total, 1)
    report["parity"] = (
        not report["different"]
        and not report["missing_in_installed"]
        and bool(manifest_report["ok"])
        and pw_ok
        and pointer_ok
    )
    print(json.dumps(report, indent=2))
    return 0 if report["parity"] else 1


if __name__ == "__main__":
    sys.exit(main())
