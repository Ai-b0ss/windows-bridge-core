"""Bounded log tailer, log-quota circuit breaker, and orphan log GC logic."""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Callable

DEFAULT_DETACHED_LOG_MAX_BYTES = 256 * 1024 * 1024  # 256 MiB default cap
TAILER_RESUME_TAIL_BYTES = 2 * 1024 * 1024          # 2 MiB max replay on restart
TAILER_READ_CHUNK_BYTES = 64 * 1024                 # 64 KiB bounded read chunks
COMPACT_KEEP_HEAD_BYTES = 512 * 1024                # 512 KiB head preserved on breach
COMPACT_KEEP_TAIL_BYTES = 2 * 1024 * 1024           # 2 MiB tail preserved on breach


def compute_initial_tail_offset(log_path: Path, max_replay_bytes: int = TAILER_RESUME_TAIL_BYTES) -> tuple[int, int]:
    """Return (start_offset, skipped_bytes) so _log_tailer never OOMs on multi-GB logs."""
    try:
        size = log_path.stat().st_size
    except OSError:
        return 0, 0
    if size <= max_replay_bytes:
        return 0, 0
    target = size - max_replay_bytes
    try:
        with open(log_path, "rb") as f:
            f.seek(target)
            probe = f.read(4096)
            nl = probe.find(b"\n")
            if nl >= 0:
                target += nl + 1
    except OSError:
        pass
    return target, target


def read_bounded_lines(log_path: Path, pos: int, carry: bytes = b"",
                       chunk_size: int = TAILER_READ_CHUNK_BYTES,
                       max_chunks_per_tick: int = 8) -> tuple[list[bytes], int, bytes]:
    """Read up to chunk_size * max_chunks_per_tick bytes without unbounded readlines()."""
    lines: list[bytes] = []
    try:
        with open(log_path, "rb") as f:
            f.seek(pos)
            for _ in range(max_chunks_per_tick):
                data = f.read(chunk_size)
                if not data:
                    break
                pos = f.tell()
                buf = carry + data
                parts = buf.split(b"\n")
                carry = parts.pop()
                for p in parts:
                    lines.append(p + b"\n")
    except OSError:
        pass
    return lines, pos, carry


def compact_runaway_log_file(log_path: Path,
                             head_bytes: int = COMPACT_KEEP_HEAD_BYTES,
                             tail_bytes: int = COMPACT_KEEP_TAIL_BYTES) -> dict:
    """Compact an oversized detached log after its writer tree is terminated."""
    before = log_path.stat().st_size
    if before <= head_bytes + tail_bytes + 4096:
        return {"compacted": False, "before_bytes": before, "after_bytes": before}
    with open(log_path, "rb") as f:
        head = f.read(head_bytes)
        f.seek(max(head_bytes, before - tail_bytes))
        tail = f.read(tail_bytes)
    omitted = before - len(head) - len(tail)
    banner = (
        f"\n\n[FF-BRIDGE-LOG-QUOTA-GUARD: compacted oversized detached log; "
        f"original_bytes={before}, omitted_middle_bytes={omitted}, "
        f"utc={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}]\n\n"
    ).encode("utf-8")
    tmp = log_path.with_suffix(log_path.suffix + ".compact.tmp")
    with open(tmp, "wb") as out:
        out.write(head)
        out.write(banner)
        out.write(tail)
    os.replace(tmp, log_path)
    after = log_path.stat().st_size
    return {"compacted": True, "before_bytes": before, "after_bytes": after, "reclaimed_bytes": before - after}


def sweep_orphan_detached_logs(
    detached_logs_dir: Path,
    active_session_ids: set[str],
    persisted_session_ids: set[str],
    older_than_seconds: int = 3600,
    now_epoch: float | None = None,
    validator: Callable[[str, Path], Path | None] | None = None,
) -> list[str]:
    """Delete unreferenced [0-9a-f]{16}.log files older than cutoff."""
    if not detached_logs_dir.is_dir():
        return []
    now_ts = time.time() if now_epoch is None else now_epoch
    cutoff = now_ts - max(0, older_than_seconds)
    protected = active_session_ids | persisted_session_ids
    removed: list[str] = []
    try:
        entries = list(os.scandir(detached_logs_dir))
    except OSError:
        return []
    for entry in entries:
        try:
            if entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
                continue
            if not entry.is_file(follow_symlinks=False):
                continue
            m = re.fullmatch(r"([0-9a-f]{16})\.log", entry.name)
            if not m:
                continue
            sid = m.group(1)
            if sid in protected:
                continue
            st = entry.stat(follow_symlinks=False)
            if st.st_mtime > cutoff:
                continue
            p = Path(entry.path)
            if validator is not None and validator(sid, p) is None:
                continue
            p.unlink(missing_ok=True)
            removed.append(sid)
        except OSError:
            continue
    return sorted(removed)
