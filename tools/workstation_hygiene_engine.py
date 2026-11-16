"""Dual-Drive, Junction-Aware Workstation Hygiene Engine."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

HARD_PROTECTED_SUBSTRINGS = (
    "фоточки",
    "фото icloud",
    "c-disk-archive",
    "ixbrowser_data",
    "nn-release-keys",
    "preservedbackups",
    "backup-recovery-keys",
    "staged-review-09e57035",
    "staged-rollout-1acf4f13",
    "ff-windows-bridge\\recovery",
    "eu-bridge-production-20261115",
    "chrome\\user data",
    "chromium\\user data",
    "bravesoftware\\brave-browser\\user data",
    ".ssh",
    ".gnupg",
    "secrets",
    "onedrive\\рисунки",
)


def is_reparse_point(path: Path) -> bool:
    try:
        st = path.lstat()
        if bool(getattr(path, "is_symlink", lambda: False)()):
            return True
        attrs = getattr(st, "st_file_attributes", 0)
        return bool(attrs & 0x0400)
    except OSError:
        return True


def is_hard_protected(path_str: str) -> bool:
    norm = path_str.replace("/", "\\").lower()
    if norm.endswith((".dpapi", ".pfx", ".jks", ".keystore", ".kdbx", ".enc")):
        return True
    return any(tok in norm for tok in HARD_PROTECTED_SUBSTRINGS)


def resolve_volume_drive(path: Path) -> str:
    try:
        real = os.path.realpath(str(path))
        if real.startswith("\\\\?\\"):
            real = real[4:]
        drive, _ = os.path.splitdrive(real)
        return drive.upper() or "UNKNOWN"
    except OSError:
        drive, _ = os.path.splitdrive(str(path))
        return drive.upper() or "UNKNOWN"


def safe_tree_bytes(path: Path, max_files: int = 80000) -> tuple[int, int]:
    if not path.exists():
        return 0, 0
    try:
        if is_reparse_point(path):
            return 0, 0
        if path.is_file():
            return path.lstat().st_size, 1
    except OSError:
        return 0, 0

    total = 0
    files = 0
    stack = [str(path)]
    while stack and files < max_files:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    try:
                        if e.is_symlink() or getattr(e, "is_junction", lambda: False)():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        elif e.is_file(follow_symlinks=False):
                            total += e.stat(follow_symlinks=False).st_size
                            files += 1
                    except OSError:
                        pass
        except OSError:
            pass
    return total, files


def select_ring_buffer_prune(files_with_mtime_and_size: list[dict[str, Any]], keep_newest: int = 2) -> list[dict[str, Any]]:
    if keep_newest < 1:
        raise ValueError("keep_newest must be >= 1")
    ordered = sorted(files_with_mtime_and_size, key=lambda x: (x["mtime"], x["name"]), reverse=True)
    return list(reversed(ordered[keep_newest:]))


def verify_extracted_zst_redundant(bundle_dir: Path) -> list[Path]:
    if not bundle_dir.is_dir() or is_reparse_point(bundle_dir):
        return []
    reclaimable: list[Path] = []
    pairs = [
        ("rootfs.vhdx.zst", "rootfs.vhdx", 500 * 1024 * 1024),
        ("initrd.zst", "initrd", 5 * 1024 * 1024),
        ("vmlinuz.zst", "vmlinuz", 5 * 1024 * 1024),
    ]
    for zst_name, raw_name, min_raw_bytes in pairs:
        zst_p = bundle_dir / zst_name
        raw_p = bundle_dir / raw_name
        if zst_p.is_file() and raw_p.is_file() and not is_reparse_point(zst_p) and not is_reparse_point(raw_p):
            try:
                raw_sz = raw_p.lstat().st_size
                zst_sz = zst_p.lstat().st_size
                if raw_sz >= min_raw_bytes and zst_sz > 0:
                    reclaimable.append(zst_p)
            except OSError:
                continue
    return reclaimable


def select_superseded_semver_dirs(root_dir: Path) -> list[Path]:
    if not root_dir.is_dir() or is_reparse_point(root_dir):
        return []
    parsed: list[tuple[tuple[int, ...], float, Path]] = []
    for child in root_dir.iterdir():
        if not child.is_dir() or is_reparse_point(child):
            continue
        m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", child.name)
        if not m:
            continue
        ver = tuple(int(g) for g in m.groups())
        try:
            mt = child.lstat().st_mtime
        except OSError:
            mt = 0.0
        parsed.append((ver, mt, child))
    if len(parsed) <= 1:
        return []
    parsed.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [item[2] for item in parsed[1:]]


def check_silent_cleanup_cooldown(state_data: dict[str, Any], now_ts: float, cooldown_seconds: int = 86400) -> bool:
    last_ts = state_data.get("last_silent_cleanup_epoch")
    if isinstance(last_ts, (int, float)) and (now_ts - float(last_ts)) < cooldown_seconds:
        return False
    return True
