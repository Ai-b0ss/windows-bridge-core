"""Parameterized, zero-PII workstation hygiene verification gates for Windows Bridge operators."""
from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path
from typing import Any


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junc = getattr(path, "is_junction", None)
        if callable(is_junc) and is_junc():
            return True
    except OSError:
        return True
    return False


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def verify_backup_dir_proven_duplicate(candidate_dir: Path, canonical_dir: Path) -> dict[str, Any]:
    """Prove every file in candidate_dir already exists with identical SHA-256 in canonical_dir."""
    cand = Path(candidate_dir)
    canon = Path(canonical_dir)
    if not cand.is_dir() or not canon.is_dir():
        return {"ok": False, "reason": "DIRECTORY_MISSING", "verified_files": 0}
    if _is_reparse_or_symlink(cand) or _is_reparse_or_symlink(canon):
        return {"ok": False, "reason": "REPARSE_ROOT_FORBIDDEN", "verified_files": 0}
    if cand.resolve() == canon.resolve():
        return {"ok": False, "reason": "SAME_DIRECTORY", "verified_files": 0}

    canonical_hashes: set[str] = set()
    for root, dirs, files in os.walk(canon, followlinks=False):
        root_p = Path(root)
        dirs[:] = [d for d in dirs if not _is_reparse_or_symlink(root_p / d)]
        for fname in files:
            fp = root_p / fname
            if _is_reparse_or_symlink(fp):
                continue
            canonical_hashes.add(_sha256_file(fp))

    verified = 0
    missing_proof: list[str] = []
    for root, dirs, files in os.walk(cand, followlinks=False):
        root_p = Path(root)
        for d in list(dirs):
            if _is_reparse_or_symlink(root_p / d):
                return {"ok": False, "reason": "CANDIDATE_CONTAINS_REPARSE", "verified_files": verified}
        for fname in files:
            fp = root_p / fname
            if _is_reparse_or_symlink(fp):
                return {"ok": False, "reason": "CANDIDATE_CONTAINS_REPARSE", "verified_files": verified}
            h = _sha256_file(fp)
            if h not in canonical_hashes:
                missing_proof.append(str(fp.relative_to(cand)))
            else:
                verified += 1

    if verified == 0 and not missing_proof:
        return {"ok": False, "reason": "EMPTY_CANDIDATE", "verified_files": 0}
    if missing_proof:
        return {
            "ok": False,
            "reason": "UNIQUE_CONTENT_PRESENT",
            "verified_files": verified,
            "unmatched_relative_paths": sorted(missing_proof)[:25],
        }
    return {"ok": True, "reason": "ALL_FILES_SHA256_PROVEN", "verified_files": verified}


def verify_git_worktree_fully_pushed(worktree_dir: Path) -> dict[str, Any]:
    """Prove a scratch git checkout has clean status, empty stash, remote(s), and 0 unpushed commits."""
    wt = Path(worktree_dir)
    if not wt.is_dir() or _is_reparse_or_symlink(wt):
        return {"ok": False, "reason": "WORKTREE_INVALID"}

    def _git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(wt), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            check=False,
        )

    inside = _git("rev-parse", "--is-inside-work-tree")
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        return {"ok": False, "reason": "NOT_A_GIT_WORKTREE"}

    status = _git("status", "--porcelain", "--untracked-files=all")
    if status.returncode != 0 or status.stdout.strip():
        return {"ok": False, "reason": "DIRTY_OR_UNTRACKED_FILES"}

    stash = _git("stash", "list")
    if stash.returncode != 0 or stash.stdout.strip():
        return {"ok": False, "reason": "STASH_NOT_EMPTY"}

    remotes = _git("remote")
    if remotes.returncode != 0 or not remotes.stdout.strip():
        return {"ok": False, "reason": "NO_GIT_REMOTE"}

    unpushed = _git("rev-list", "HEAD", "--branches", "--not", "--remotes")
    if unpushed.returncode != 0:
        return {"ok": False, "reason": "UNPUSHED_CHECK_FAILED"}
    commits = [c for c in unpushed.stdout.splitlines() if c.strip()]
    if commits:
        return {"ok": False, "reason": "UNPUSHED_COMMITS_PRESENT", "unpushed_count": len(commits)}

    return {"ok": True, "reason": "CLEAN_AND_FULLY_PUSHED"}
