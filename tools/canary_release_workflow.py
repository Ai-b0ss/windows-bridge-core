"""Safe product canary staging, health-contract, and rollback workflow for C1 + C2.

Design invariants (fail-closed):
1. Mandatory pinned SHA-256 for every release archive and backup restoration;
   mandatory pinned 40-hex Git commit SHA for C2 staging. Empty pins hard-fail.
2. Controlled shadow state strictly isolated from production ports
   (20128, 21476, 21477, 39073, 39076, 39090) and production directories;
   symlinks, junctions, and reparse points are rejected before any write.
3. Real C2 staging from an immutable Git archive or pinned ZIP into an
   immutable release store + controlled staging slot with SQLite Online Backup
   API snapshots; never runs `git checkout` on production or mutates prod DBs.
4. Four-factor process identity verification (PID + 64-bit Windows kernel
   FILETIME creation time + physical executable/entrypoint path + owner-scoped
   lease) and strict prohibition on force-killing active sessions/jobs.
5. Persistent WAL SQLite receipts (`canary_receipts.sqlite3`) with idempotent
   `request_key` deduplication and an append-only SHA-256 receipt hash chain
   preserved across rollbacks.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import ctypes
import ctypes.wintypes
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import time
from typing import Any, Callable, Iterable
import urllib.error
import urllib.request
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BRIDGE_V3_DIR = ROOT / "runtime" / "bridge-v3"
if str(BRIDGE_V3_DIR) not in sys.path:
    sys.path.insert(0, str(BRIDGE_V3_DIR))

from ff_win_process_identity import process_creation_token  # noqa: E402

SCHEMA_OWNER = "ff-canary-shadow-owner-v1"
SCHEMA_LEASE = "ff-canary-process-lease-v1"
SCHEMA_C1_ACTIVE = "ff-canary-c1-active-v1"
SCHEMA_C2_ACTIVE = "ff-canary-c2-active-v1"
SCHEMA_C2_MANIFEST = "ff-canary-c2-stage-manifest-v1"
SCHEMA_BACKUP_MANIFEST = "ff-canary-sqlite-backup-manifest-v1"
SCHEMA_HEALTH = "ff-canary-health-report-v1"
SCHEMA_READINESS = "ff-canary-cutover-readiness-v1"
SCHEMA_OWNER_APPROVAL = "ff-canary-owner-approval-v1"
SCHEMA_ROLLBACK = "ff-canary-rollback-report-v1"
SCHEMA_RECEIPTS = "ff-canary-receipts-v1"

FORBIDDEN_SHADOW_PORTS = frozenset({20128, 21476, 21477, 39073, 39076, 39090})
DEFAULT_SHADOW_PORTS = {
    "c1_rpc_port": 39173,
    "c1_hub_port": 39190,
    "c2_gateway_port": 21587,
    "c2_unified_port": 21588,
}
DEFAULT_C2_OMNI_PORT = 20128

C2_REQUIRED_FILES = ("server.py", "unified_api.py")
C2_ACTIVE_JOB_STATES = ("queued", "running", "submitted", "needs_attention")
C2_ACTIVE_TURN_STATES = ("queued", "running", "in_progress", "pending", "submitted")
C2_PRESERVED_RUNTIME_FILES = frozenset({
    "gateway.db",
    "gateway.db-wal",
    "gateway.db-shm",
    "gateway.db-journal",
    "gateway.key",
    ".gateway_process.lock",
})

HEX64_RE = re.compile(r"^[0-9a-f]{64}\Z", re.ASCII)
HEX40_RE = re.compile(r"^[0-9a-f]{40}\Z", re.ASCII)
WINDOWS_RESERVED_RE = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|\Z)", re.IGNORECASE | re.ASCII)

MAX_ZIP_ENTRIES = 10000
MAX_ZIP_TOTAL_BYTES = 1024 * 1024 * 1024  # 1 GiB
MAX_C2_FILES = 4000
MAX_C2_TOTAL_BYTES = 128 * 1024 * 1024  # 128 MiB


class CanaryError(RuntimeError):
    """Structured fail-closed workflow error."""

    def __init__(self, code: str, message: str | None = None, **details: Any):
        super().__init__(code if not message else f"{code}: {message}")
        self.code = code
        self.message = message or code
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": False,
            "error_code": self.code,
            "message": self.message,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Basic crypto, canonical JSON, path, reparse, and boundary guards
# ---------------------------------------------------------------------------

def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_sha256(value: Any, label: str = "sha256") -> str:
    if not isinstance(value, str) or not value.strip():
        raise CanaryError("PINNED_SHA256_REQUIRED", f"{label} must be a non-empty 64-hex SHA-256", field=label)
    normalized = value.strip().lower()
    if value != value.strip() or not HEX64_RE.fullmatch(normalized):
        raise CanaryError("PINNED_SHA256_INVALID", f"{label} must be exact 64 lowercase/uppercase hex characters", field=label)
    return normalized


def validate_git_commit(value: Any, label: str = "commit") -> str:
    if not isinstance(value, str) or not value.strip():
        raise CanaryError("PINNED_COMMIT_REQUIRED", f"{label} must be a non-empty 40-hex Git commit SHA", field=label)
    normalized = value.strip().lower()
    if value != value.strip() or not HEX40_RE.fullmatch(normalized):
        raise CanaryError("PINNED_COMMIT_INVALID", f"{label} must be an exact 40-hex Git commit SHA", field=label)
    return normalized


def _is_reparse_point(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return True
        except OSError:
            return True
    if os.name == "nt":
        try:
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            if attrs != 0xFFFFFFFF and (attrs & 0x0400):
                return True
        except Exception:
            pass
    return False


def assert_no_reparse(path: Path, *, must_file: bool = False) -> None:
    cursor = Path(os.path.abspath(str(path)))
    while True:
        if cursor.exists() or cursor.is_symlink():
            if _is_reparse_point(cursor):
                raise CanaryError("REPARSE_POINT_FORBIDDEN", "Symlinks and NTFS junctions are forbidden", path=str(cursor))
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    if must_file:
        if not path.is_file():
            raise CanaryError("FILE_MISSING", "Expected regular file", path=str(path))
        try:
            if path.stat().st_nlink != 1:
                raise CanaryError("HARDLINK_FORBIDDEN", "Multi-linked file rejected", path=str(path))
        except OSError as exc:
            raise CanaryError("FILE_STAT_FAILED", str(exc)) from exc


def _norm_path(path: Path | str) -> str:
    return os.path.normcase(os.path.abspath(str(path))).replace("\\", "/").rstrip("/")


def _is_same_or_child(candidate: Path, forbidden: Path) -> bool:
    for c_str in {_norm_path(candidate), _norm_path(candidate.resolve()) if candidate.exists() else _norm_path(candidate)}:
        for f_str in {_norm_path(forbidden), _norm_path(forbidden.resolve()) if forbidden.exists() else _norm_path(forbidden)}:
            if c_str == f_str or c_str.startswith(f_str + "/"):
                return True
            if f_str.startswith(c_str + "/"):
                # Shadow root must never be an ancestor of a production directory either.
                return True
    return False


def _default_forbidden_production_roots() -> list[Path]:
    roots: list[Path] = []
    local_appdata = os.environ.get("LOCALAPPDATA")
    if local_appdata:
        roots.append(Path(local_appdata) / "FF-Windows-Bridge")
    userprofile = os.environ.get("USERPROFILE") or str(Path.home())
    if userprofile:
        roots.append(Path(userprofile) / "Documents" / "GeminiTaskGateway")
        roots.append(Path(userprofile) / "AppData" / "Local" / "FF-Windows-Bridge")
    # Also resolve junction target of %LOCALAPPDATA%\FF-Windows-Bridge if present.
    resolved_extra: list[Path] = []
    for item in roots:
        try:
            if item.exists():
                resolved_extra.append(item.resolve())
        except OSError:
            pass
    return roots + resolved_extra


def validate_shadow_ports(ports: dict[str, int]) -> dict[str, int]:
    validated: dict[str, int] = {}
    seen: dict[int, str] = {}
    for name, value in ports.items():
        if type(value) is not int or not (1024 <= value <= 65535):
            raise CanaryError("SHADOW_PORT_INVALID", f"Invalid shadow port for {name}", port_name=name, port=value)
        if value in FORBIDDEN_SHADOW_PORTS:
            raise CanaryError(
                "SHADOW_PORT_FORBIDDEN_PRODUCTION_PORT",
                f"Shadow port {name}={value} collides with a protected production port",
                port_name=name,
                port=value,
                forbidden_ports=sorted(FORBIDDEN_SHADOW_PORTS),
            )
        if value in seen:
            raise CanaryError(
                "SHADOW_PORT_COLLISION",
                f"Shadow ports {seen[value]} and {name} cannot share port {value}",
                first=seen[value],
                second=name,
                port=value,
            )
        seen[value] = name
        validated[name] = value
    return validated


def validate_shadow_root(shadow_root: Path, *, extra_forbidden_roots: Iterable[Path] = ()) -> Path:
    if not shadow_root or not str(shadow_root).strip():
        raise CanaryError("SHADOW_ROOT_INVALID", "ShadowRoot must be a non-empty absolute path")
    raw = Path(shadow_root)
    if not raw.is_absolute():
        raise CanaryError("SHADOW_ROOT_INVALID", "ShadowRoot must be an absolute path")
    abs_path = Path(os.path.abspath(str(raw)))
    if abs_path == abs_path.parent:
        raise CanaryError("SHADOW_ROOT_INVALID", "ShadowRoot cannot be a filesystem drive root")
    assert_no_reparse(abs_path)
    forbidden = list(_default_forbidden_production_roots()) + [Path(p) for p in extra_forbidden_roots]
    for prod_root in forbidden:
        if _is_same_or_child(abs_path, prod_root):
            raise CanaryError(
                "SHADOW_ROOT_FORBIDDEN_PRODUCTION_PATH",
                "ShadowRoot overlaps with a protected production directory",
            )
    return abs_path


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with tmp.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def _atomic_write_json(path: Path, value: Any) -> None:
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _atomic_write_bytes(path, payload)


def _read_json(path: Path) -> dict[str, Any]:
    assert_no_reparse(path, must_file=True)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise CanaryError("JSON_INVALID", f"Invalid JSON file {path.name}") from exc
    if not isinstance(data, dict):
        raise CanaryError("JSON_INVALID", f"Expected JSON object in {path.name}")
    return data


def ensure_shadow_owner(
    shadow_root: Path,
    *,
    create: bool = False,
    extra_forbidden_roots: Iterable[Path] = (),
) -> dict[str, Any]:
    root = validate_shadow_root(shadow_root, extra_forbidden_roots=extra_forbidden_roots)
    marker = root / "canary-shadow-owner.json"
    if not marker.exists():
        if not create:
            raise CanaryError("SHADOW_ROOT_NOT_OWNED", "Shadow root ownership marker missing")
        if root.exists() and any(root.iterdir()):
            raise CanaryError(
                "SHADOW_ROOT_NOT_OWNED",
                "Refusing to adopt a non-empty directory without canary-shadow-owner.json",
            )
        root.mkdir(parents=True, exist_ok=True)
        owner = {
            "schema": SCHEMA_OWNER,
            "owner_scope_id": "cso-" + secrets.token_hex(16),
            "created_at": time.time(),
            "forbidden_production_ports": sorted(FORBIDDEN_SHADOW_PORTS),
        }
        _atomic_write_json(marker, owner)
        return owner
    owner = _read_json(marker)
    if owner.get("schema") != SCHEMA_OWNER or not isinstance(owner.get("owner_scope_id"), str) or not owner["owner_scope_id"]:
        raise CanaryError("SHADOW_OWNER_INVALID", "Invalid canary-shadow-owner.json schema or owner_scope_id")
    return owner


# ---------------------------------------------------------------------------
# Safe archive entry validation
# ---------------------------------------------------------------------------

def _validate_archive_relpath(name: str) -> PurePosixPath:
    if not isinstance(name, str) or not name or "\\" in name or ":" in name or "\x00" in name:
        raise CanaryError("ARCHIVE_PATH_INVALID", "Unsafe archive entry path", entry=str(name)[:120])
    p = PurePosixPath(name)
    if p.is_absolute():
        raise CanaryError("ARCHIVE_PATH_INVALID", "Absolute archive entry path forbidden", entry=name[:120])
    parts = [part for part in name.rstrip("/").split("/")]
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise CanaryError("ARCHIVE_PATH_INVALID", "Path traversal in archive entry", entry=name[:120])
    for part in parts:
        if any(ch in '<>"|?*' or ord(ch) < 32 for ch in part) or part.endswith((".", " ")) or WINDOWS_RESERVED_RE.match(part):
            raise CanaryError("ARCHIVE_PATH_INVALID", "Windows-unsafe archive path component", entry=name[:120])
    return p


def _validate_zip_entries(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    if zf.testzip() is not None:
        raise CanaryError("ARCHIVE_CRC_FAILED", "ZIP CRC verification failed")
    infos = zf.infolist()
    if len(infos) > MAX_ZIP_ENTRIES:
        raise CanaryError("ARCHIVE_SIZE_LIMIT", "ZIP entry count exceeds safe limit")
    seen_ci: set[str] = set()
    files: list[zipfile.ZipInfo] = []
    total_size = 0
    for info in infos:
        # Reject symlinks (UNIX S_IFLNK = 0o120000).
        if ((info.external_attr >> 16) & 0o170000) == 0o120000:
            raise CanaryError("ARCHIVE_PATH_INVALID", "Symlink entry inside ZIP is forbidden", entry=info.filename[:120])
        if info.is_dir():
            if info.filename.rstrip("/"):
                _validate_archive_relpath(info.filename.rstrip("/"))
            continue
        _validate_archive_relpath(info.filename)
        key = info.filename.casefold()
        if key in seen_ci:
            raise CanaryError("ARCHIVE_PATH_INVALID", "Duplicate case-insensitive ZIP entry", entry=info.filename[:120])
        seen_ci.add(key)
        total_size += info.file_size
        if total_size > MAX_ZIP_TOTAL_BYTES:
            raise CanaryError("ARCHIVE_SIZE_LIMIT", "ZIP uncompressed size exceeds safe limit")
        files.append(info)
    return files


# ---------------------------------------------------------------------------
# Persistent SQLite Receipts Store (WAL + FULL + hash chain + idempotency)
# ---------------------------------------------------------------------------

_RECEIPTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS canary_runs (
    run_id TEXT PRIMARY KEY,
    request_key TEXT UNIQUE,
    request_digest TEXT,
    action TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    c1_zip_sha256 TEXT,
    c1_commit TEXT,
    c2_commit TEXT,
    c2_manifest_sha256 TEXT,
    started_at REAL NOT NULL,
    finished_at REAL,
    error_code TEXT,
    summary_json TEXT
);
CREATE TABLE IF NOT EXISTS canary_steps (
    step_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    component TEXT NOT NULL,
    step_name TEXT NOT NULL,
    status TEXT NOT NULL,
    at REAL NOT NULL,
    detail_json TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES canary_runs(run_id)
);
CREATE TABLE IF NOT EXISTS canary_backups (
    backup_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    component TEXT NOT NULL,
    db_name TEXT NOT NULL,
    source_sha256 TEXT NOT NULL,
    backup_path TEXT NOT NULL,
    backup_sha256 TEXT NOT NULL,
    integrity_ok INTEGER NOT NULL,
    row_counts_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    FOREIGN KEY(run_id) REFERENCES canary_runs(run_id)
);
CREATE TABLE IF NOT EXISTS canary_leases (
    lease_id TEXT PRIMARY KEY,
    run_id TEXT,
    owner_scope_id TEXT NOT NULL,
    role TEXT NOT NULL,
    pid INTEGER NOT NULL,
    create_time_filetime INTEGER NOT NULL,
    executable_path TEXT NOT NULL,
    entrypoint_path TEXT NOT NULL,
    port INTEGER NOT NULL,
    release_id TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS canary_receipt_chain (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id TEXT UNIQUE NOT NULL,
    run_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    receipt_hash TEXT NOT NULL,
    created_at REAL NOT NULL,
    FOREIGN KEY(run_id) REFERENCES canary_runs(run_id)
);
"""


class CanaryReceiptStore:
    """Durable SQLite WAL receipt journal preserved across rollbacks."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        assert_no_reparse(self.path.parent)
        self._init_schema()

    def _connect(self, *, readonly: bool = False) -> sqlite3.Connection:
        if readonly:
            conn = sqlite3.connect(self.path.resolve().as_uri() + "?mode=ro", uri=True, timeout=10)
            conn.row_factory = sqlite3.Row
            return conn
        conn = sqlite3.connect(str(self.path), isolation_level=None, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with closing(self._connect()) as conn:
            conn.executescript(_RECEIPTS_SCHEMA)
            conn.execute("INSERT OR IGNORE INTO schema_meta(key, value) VALUES('schema', ?)", (SCHEMA_RECEIPTS,))
            conn.execute("INSERT OR IGNORE INTO schema_meta(key, value) VALUES('version', '1')")

    def begin_run(
        self,
        action: str,
        mode: str,
        *,
        request_key: str | None = None,
        request_payload: dict[str, Any] | None = None,
        c1_zip_sha256: str | None = None,
        c1_commit: str | None = None,
        c2_commit: str | None = None,
        c2_manifest_sha256: str | None = None,
    ) -> tuple[str, dict[str, Any] | None]:
        req_key = request_key.strip() if isinstance(request_key, str) and request_key.strip() else None
        req_digest = sha256_bytes(_canonical_json(request_payload or {}).encode("utf-8")) if req_key else None
        now = time.time()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if req_key is not None:
                    row = conn.execute("SELECT * FROM canary_runs WHERE request_key=?", (req_key,)).fetchone()
                    if row is not None:
                        if row["request_digest"] != req_digest:
                            conn.execute("ROLLBACK")
                            raise CanaryError(
                                "REQUEST_KEY_CONFLICT",
                                "request_key was already used with a different request payload",
                                request_key=req_key,
                                existing_run_id=row["run_id"],
                            )
                        summary = json.loads(row["summary_json"]) if row["summary_json"] else {}
                        conn.execute("COMMIT")
                        return row["run_id"], {
                            "run_id": row["run_id"],
                            "request_key": req_key,
                            "action": row["action"],
                            "status": row["status"],
                            "error_code": row["error_code"],
                            "summary": summary,
                            "deduplicated": True,
                        }
                run_id = "crun-" + uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO canary_runs(run_id, request_key, request_digest, action, mode, status, "
                    "c1_zip_sha256, c1_commit, c2_commit, c2_manifest_sha256, started_at) "
                    "VALUES(?, ?, ?, ?, ?, 'started', ?, ?, ?, ?, ?)",
                    (run_id, req_key, req_digest, action, mode, c1_zip_sha256, c1_commit, c2_commit, c2_manifest_sha256, now),
                )
                conn.execute("COMMIT")
                return run_id, None
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def record_step(self, run_id: str, component: str, step_name: str, status: str, detail: dict[str, Any] | None = None) -> None:
        now = time.time()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                seq = conn.execute("SELECT COALESCE(MAX(seq), 0) + 1 FROM canary_steps WHERE run_id=?", (run_id,)).fetchone()[0]
                conn.execute(
                    "INSERT INTO canary_steps(step_id, run_id, seq, component, step_name, status, at, detail_json) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    ("cstep-" + uuid.uuid4().hex, run_id, seq, component, step_name, status, now, _canonical_json(detail or {})),
                )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def record_backup(self, run_id: str, component: str, db_name: str, backup_info: dict[str, Any]) -> str:
        backup_id = "cbkp-" + uuid.uuid4().hex
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO canary_backups(backup_id, run_id, component, db_name, source_sha256, "
                    "backup_path, backup_sha256, integrity_ok, row_counts_json, created_at) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        backup_id,
                        run_id,
                        component,
                        db_name,
                        str(backup_info["source_sha256"]),
                        str(backup_info["backup_path"]),
                        str(backup_info["backup_sha256"]),
                        1 if backup_info.get("integrity_ok") else 0,
                        _canonical_json(backup_info.get("row_counts") or {}),
                        time.time(),
                    ),
                )
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise
        return backup_id

    def record_lease(self, run_id: str | None, lease: dict[str, Any], state: str) -> None:
        now = time.time()
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                existing = conn.execute("SELECT lease_id FROM canary_leases WHERE lease_id=?", (lease["lease_id"],)).fetchone()
                if existing is None:
                    conn.execute(
                        "INSERT INTO canary_leases(lease_id, run_id, owner_scope_id, role, pid, "
                        "create_time_filetime, executable_path, entrypoint_path, port, release_id, "
                        "state, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            lease["lease_id"],
                            run_id,
                            lease["owner_scope_id"],
                            lease["role"],
                            int(lease["pid"]),
                            int(lease["create_time_filetime"]),
                            str(lease["executable_path"]),
                            str(lease["entrypoint_path"]),
                            int(lease["port"]),
                            str(lease["release_id"]),
                            state,
                            float(lease.get("issued_at") or now),
                            now,
                        ),
                    )
                else:
                    conn.execute("UPDATE canary_leases SET state=?, updated_at=? WHERE lease_id=?", (state, now, lease["lease_id"]))
                conn.execute("COMMIT")
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def finish_run(
        self,
        run_id: str,
        status: str,
        *,
        summary: dict[str, Any] | None = None,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        now = time.time()
        summary_data = summary or {}
        summary_json = _canonical_json(summary_data)
        with closing(self._connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT action, mode FROM canary_runs WHERE run_id=?", (run_id,)).fetchone()
                if row is None:
                    raise CanaryError("RECEIPT_RUN_NOT_FOUND", "Unknown canary run_id", run_id=run_id)
                conn.execute(
                    "UPDATE canary_runs SET status=?, finished_at=?, error_code=?, summary_json=? WHERE run_id=?",
                    (status, now, error_code, summary_json, run_id),
                )
                prev = conn.execute("SELECT receipt_hash FROM canary_receipt_chain ORDER BY seq DESC LIMIT 1").fetchone()
                prev_hash = prev["receipt_hash"] if prev is not None else ("0" * 64)
                receipt_id = "crcpt-" + uuid.uuid4().hex
                payload = {
                    "receipt_id": receipt_id,
                    "run_id": run_id,
                    "action": row["action"],
                    "mode": row["mode"],
                    "status": status,
                    "error_code": error_code,
                    "summary": summary_data,
                    "created_at": now,
                }
                payload_json = _canonical_json(payload)
                receipt_hash = sha256_bytes((prev_hash + "|" + payload_json).encode("utf-8"))
                conn.execute(
                    "INSERT INTO canary_receipt_chain(receipt_id, run_id, action, status, payload_json, prev_hash, receipt_hash, created_at) "
                    "VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    (receipt_id, run_id, row["action"], status, payload_json, prev_hash, receipt_hash, now),
                )
                conn.execute("COMMIT")
                return {
                    "receipt_id": receipt_id,
                    "run_id": run_id,
                    "receipt_hash": receipt_hash,
                    "prev_hash": prev_hash,
                    "status": status,
                }
            except BaseException:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                raise

    def verify_receipt_chain(self) -> dict[str, Any]:
        if not self.path.is_file():
            raise CanaryError("RECEIPT_CHAIN_CORRUPTED", "Receipts database file is missing")
        with closing(self._connect(readonly=True)) as conn:
            integrity = conn.execute("PRAGMA integrity_check").fetchall()
            if [tuple(r) for r in integrity] != [("ok",)]:
                raise CanaryError("RECEIPT_CHAIN_CORRUPTED", "SQLite PRAGMA integrity_check failed")
            rows = conn.execute("SELECT * FROM canary_receipt_chain ORDER BY seq ASC").fetchall()
            prev = "0" * 64
            for row in rows:
                if row["prev_hash"] != prev:
                    raise CanaryError("RECEIPT_CHAIN_CORRUPTED", "Broken prev_hash link", seq=row["seq"])
                payload_obj = json.loads(row["payload_json"])
                if payload_obj.get("status") != row["status"] or payload_obj.get("action") != row["action"] or payload_obj.get("run_id") != row["run_id"]:
                    raise CanaryError("RECEIPT_CHAIN_CORRUPTED", "Row column mismatch against chained payload", seq=row["seq"])
                expected = sha256_bytes((prev + "|" + row["payload_json"]).encode("utf-8"))
                if not hmac.compare_digest(expected, row["receipt_hash"]):
                    raise CanaryError("RECEIPT_CHAIN_CORRUPTED", "Receipt SHA-256 hash mismatch", seq=row["seq"])
                prev = row["receipt_hash"]
            runs_count = conn.execute("SELECT COUNT(*) FROM canary_runs").fetchone()[0]
            backups_count = conn.execute("SELECT COUNT(*) FROM canary_backups").fetchone()[0]
            leases_count = conn.execute("SELECT COUNT(*) FROM canary_leases").fetchone()[0]
        return {
            "ok": True,
            "schema": SCHEMA_RECEIPTS,
            "integrity_ok": True,
            "receipts_verified": len(rows),
            "runs_recorded": int(runs_count),
            "backups_recorded": int(backups_count),
            "leases_recorded": int(leases_count),
            "head_receipt_hash": prev,
        }

    def list_receipts(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 500))
        with closing(self._connect(readonly=True)) as conn:
            rows = conn.execute(
                "SELECT seq, receipt_id, run_id, action, status, prev_hash, receipt_hash, created_at "
                "FROM canary_receipt_chain ORDER BY seq DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in reversed(rows)]


# ---------------------------------------------------------------------------
# SQLite Online Backup API & read-only active session/job inspection
# ---------------------------------------------------------------------------

def sqlite_online_backup(
    src_db: Path,
    dst_db: Path,
    *,
    expected_tables: Iterable[str] = (),
) -> dict[str, Any]:
    """Snapshot a live SQLite DB strictly via SQLite Online Backup API (read-only source)."""
    src_db = Path(src_db)
    dst_db = Path(dst_db)
    assert_no_reparse(src_db, must_file=True)
    assert_no_reparse(dst_db.parent)
    dst_db.parent.mkdir(parents=True, exist_ok=True)

    source_sha = sha256_file(src_db)
    tmp_dst = dst_db.with_name(f".{dst_db.name}.{uuid.uuid4().hex}.bkp.tmp")
    src_uri = src_db.resolve().as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(src_uri, uri=True, timeout=10)) as src_conn:
            with closing(sqlite3.connect(str(tmp_dst), timeout=10)) as dst_conn:
                src_conn.backup(dst_conn, pages=128)
                dst_conn.execute("PRAGMA journal_mode=DELETE")
                dst_conn.commit()
                integrity = [tuple(r) for r in dst_conn.execute("PRAGMA integrity_check").fetchall()]
                if integrity != [("ok",)]:
                    raise CanaryError("SQLITE_BACKUP_INTEGRITY_FAILED", "Backup integrity_check failed", integrity=integrity)
                tables = sorted(
                    row[0]
                    for row in dst_conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    ).fetchall()
                )
                for req in expected_tables:
                    if req not in tables:
                        raise CanaryError("SQLITE_BACKUP_INTEGRITY_FAILED", f"Expected table missing: {req}", table=req)
                row_counts: dict[str, int] = {}
                for tbl in tables:
                    quoted = '"' + tbl.replace('"', '""') + '"'
                    row_counts[tbl] = int(dst_conn.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0])
        with tmp_dst.open("r+b") as stream:
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_dst, dst_db)
    except CanaryError:
        tmp_dst.unlink(missing_ok=True)
        raise
    except (sqlite3.Error, OSError) as exc:
        tmp_dst.unlink(missing_ok=True)
        raise CanaryError("SQLITE_BACKUP_INTEGRITY_FAILED", f"SQLite backup failed: {type(exc).__name__}") from exc

    backup_sha = sha256_file(dst_db)
    return {
        "source_sha256": source_sha,
        "backup_path": str(dst_db),
        "backup_sha256": backup_sha,
        "integrity_ok": True,
        "tables": tables,
        "row_counts": row_counts,
        "bytes": dst_db.stat().st_size,
    }


def sqlite_restore_from_backup(backup_db: Path, expected_sha256: str, target_db: Path) -> dict[str, Any]:
    """Restore a SQLite DB from a SHA-256-pinned backup via SQLite Online Backup API."""
    pinned = validate_sha256(expected_sha256, "backup_sha256")
    backup_db = Path(backup_db)
    target_db = Path(target_db)
    assert_no_reparse(backup_db, must_file=True)
    assert_no_reparse(target_db.parent)
    actual_sha = sha256_file(backup_db)
    if not hmac.compare_digest(actual_sha, pinned):
        raise CanaryError(
            "SQLITE_BACKUP_HASH_MISMATCH",
            "Backup SHA-256 does not match pinned value",
            expected=pinned,
            actual=actual_sha,
        )
    target_db.parent.mkdir(parents=True, exist_ok=True)
    tmp_target = target_db.with_name(f".{target_db.name}.{uuid.uuid4().hex}.restore.tmp")
    src_uri = backup_db.resolve().as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(src_uri, uri=True, timeout=10)) as src_conn:
            src_check = [tuple(r) for r in src_conn.execute("PRAGMA integrity_check").fetchall()]
            if src_check != [("ok",)]:
                raise CanaryError("SQLITE_BACKUP_INTEGRITY_FAILED", "Backup file failed PRAGMA integrity_check")
            with closing(sqlite3.connect(str(tmp_target), timeout=10)) as dst_conn:
                src_conn.backup(dst_conn, pages=128)
                dst_conn.execute("PRAGMA journal_mode=DELETE")
                dst_conn.commit()
                dst_check = [tuple(r) for r in dst_conn.execute("PRAGMA integrity_check").fetchall()]
                if dst_check != [("ok",)]:
                    raise CanaryError("SQLITE_BACKUP_INTEGRITY_FAILED", "Restored DB failed PRAGMA integrity_check")
        with tmp_target.open("r+b") as stream:
            stream.flush()
            os.fsync(stream.fileno())
        # Remove stale WAL/SHM sidecars only after verified idle state (caller guarantees idle).
        for suffix in ("-wal", "-shm"):
            sidecar = Path(str(target_db) + suffix)
            if sidecar.exists():
                sidecar.unlink()
        os.replace(tmp_target, target_db)
    except CanaryError:
        tmp_target.unlink(missing_ok=True)
        raise
    except (sqlite3.Error, OSError) as exc:
        tmp_target.unlink(missing_ok=True)
        raise CanaryError("SQLITE_BACKUP_INTEGRITY_FAILED", f"SQLite restore failed: {type(exc).__name__}") from exc

    return {
        "restored": True,
        "integrity_ok": True,
        "backup_sha256": actual_sha,
        "restored_sha256": sha256_file(target_db),
    }


def inspect_c2_gateway_active_jobs(db_path: Path) -> dict[str, Any]:
    """Read-only inspection of C2 gateway.db for any active jobs or agent turns."""
    db_path = Path(db_path)
    if not db_path.is_file():
        return {
            "db_exists": False,
            "active_jobs": 0,
            "active_turns": 0,
            "job_states": {},
            "p2_schema": False,
            "idle_verified": True,
        }
    assert_no_reparse(db_path, must_file=True)
    uri = db_path.resolve().as_uri() + "?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
            states: dict[str, int] = {}
            active_jobs = 0
            p2_schema = False
            if "jobs" in tables:
                states = {str(r[0]): int(r[1]) for r in conn.execute("SELECT status, COUNT(*) FROM jobs GROUP BY status").fetchall()}
                active_jobs = sum(states.get(name, 0) for name in C2_ACTIVE_JOB_STATES)
                cols = {row[1] for row in conn.execute("PRAGMA table_info(jobs)").fetchall()}
                p2_schema = all(
                    field in cols for field in ("browser_tab_tracked", "browser_tab_open", "browser_tab_cleanup_uncertain")
                )
            active_turns = 0
            if "agent_turns" in tables:
                t_cols = {row[1] for row in conn.execute("PRAGMA table_info(agent_turns)").fetchall()}
                if "status" in t_cols:
                    t_states = {
                        str(r[0]): int(r[1])
                        for r in conn.execute("SELECT status, COUNT(*) FROM agent_turns GROUP BY status").fetchall()
                    }
                    active_turns = sum(t_states.get(name, 0) for name in C2_ACTIVE_TURN_STATES)
        idle = (active_jobs == 0 and active_turns == 0)
        return {
            "db_exists": True,
            "active_jobs": active_jobs,
            "active_turns": active_turns,
            "job_states": states,
            "p2_schema": p2_schema,
            "idle_verified": idle,
            "reason": None if idle else "ACTIVE_C2_JOBS_PRESENT",
        }
    except (sqlite3.Error, OSError) as exc:
        return {
            "db_exists": True,
            "active_jobs": -1,
            "active_turns": -1,
            "idle_verified": False,
            "reason": "SESSION_STATE_UNKNOWN_REFUSE_KILL",
            "error": type(exc).__name__,
        }


def _loopback_opener() -> urllib.request.OpenerDirector:
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


def _hub_rpc_call(hub_state_dir: Path, op: str, args: dict[str, Any] | None = None, *, timeout: float = 5.0) -> dict[str, Any]:
    endpoint_file = hub_state_dir / "endpoint.json"
    key_file = hub_state_dir / "hub.key"
    if not endpoint_file.is_file() or not key_file.is_file():
        raise CanaryError("HUB_NOT_RUNNING", "Hub endpoint or key file missing")
    ep = _read_json(endpoint_file)
    port = ep.get("port")
    if type(port) is not int or not (1 <= port <= 65535):
        raise CanaryError("HUB_ENDPOINT_INVALID", "Invalid Hub endpoint port")
    key = key_file.read_text(encoding="ascii").strip()
    body = json.dumps({"op": op, "args": args or {}}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/rpc",
        data=body,
        headers={"Content-Type": "application/json", "X-FF-Hub-Key": key},
        method="POST",
    )
    try:
        with _loopback_opener().open(req, timeout=timeout) as resp:
            reply = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        reply = json.loads(exc.read())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise CanaryError("HUB_UNREACHABLE", f"Hub RPC unreachable: {type(exc).__name__}") from exc
    if not isinstance(reply, dict) or not reply.get("ok"):
        code = str((reply or {}).get("error_code") or "HUB_ERROR")
        raise CanaryError(code, str((reply or {}).get("message") or code), details=(reply or {}).get("details") or {})
    return reply["result"]


def inspect_c1_hub_active_sessions(hub_state_dir: Path, *, require_rpc_if_running: bool = True) -> dict[str, Any]:
    """Defense-in-depth active session check across live Hub RPC and read-only hub.db."""
    hub_state_dir = Path(hub_state_dir)
    rpc_reachable = False
    rpc_sessions = 0
    rpc_resources = 0
    rpc_pending = 0
    endpoint_exists = (hub_state_dir / "endpoint.json").is_file()
    if endpoint_exists:
        try:
            st = _hub_rpc_call(hub_state_dir, "hub_status", timeout=4.0)
            rpc_reachable = True
            rpc_sessions = len(st.get("sessions") or [])
            rpc_resources = len(st.get("resources") or [])
            rpc_pending = int(st.get("pending_owner_requests") or 0)
        except CanaryError as exc:
            if require_rpc_if_running:
                # Check if endpoint PID is still alive; if alive and unreachable -> fail closed!
                try:
                    ep = _read_json(hub_state_dir / "endpoint.json")
                    pid, ct = ep.get("pid"), ep.get("create_time")
                    if type(pid) is int and type(ct) is int and process_creation_token(pid) == ct:
                        return {
                            "idle_verified": False,
                            "reason": "SESSION_STATE_UNKNOWN_REFUSE_KILL",
                            "rpc_reachable": False,
                            "error": exc.code,
                        }
                except Exception:
                    return {
                        "idle_verified": False,
                        "reason": "SESSION_STATE_UNKNOWN_REFUSE_KILL",
                        "rpc_reachable": False,
                    }

    db_path = hub_state_dir / "hub.db"
    db_sessions = 0
    db_resources = 0
    db_exists = db_path.is_file()
    if db_exists:
        try:
            uri = db_path.resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True, timeout=5)) as conn:
                tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
                if "sessions" in tables:
                    db_sessions = int(conn.execute("SELECT COUNT(*) FROM sessions WHERE state='active'").fetchone()[0])
                if "resources" in tables:
                    db_resources = int(conn.execute("SELECT COUNT(*) FROM resources WHERE state='held'").fetchone()[0])
        except (sqlite3.Error, OSError) as exc:
            return {
                "idle_verified": False,
                "reason": "SESSION_STATE_UNKNOWN_REFUSE_KILL",
                "db_exists": True,
                "error": type(exc).__name__,
            }

    active_sessions = max(rpc_sessions, db_sessions)
    held_resources = max(rpc_resources, db_resources)
    idle = (active_sessions == 0 and held_resources == 0 and rpc_pending == 0)
    return {
        "idle_verified": idle,
        "active_sessions": active_sessions,
        "held_resources": held_resources,
        "pending_owner_requests": rpc_pending,
        "rpc_reachable": rpc_reachable,
        "db_exists": db_exists,
        "reason": None if idle else "ACTIVE_SESSIONS_PRESENT",
    }


def inspect_c1_rpc_active_sessions(shadow_root: Path, *, require_rpc_if_running: bool = True) -> dict[str, Any]:
    """Verify shadow C1 Bridge RPC has no active Hub sessions or active desktop grants."""
    hub_check = inspect_c1_hub_active_sessions(shadow_root / "state" / "c1" / "hub", require_rpc_if_running=False)
    if not hub_check["idle_verified"]:
        return hub_check
    runtime_dir = shadow_root / "state" / "c1" / "runtime"
    secret_file = runtime_dir / "bridge-v3" / "secret"
    active_cfg_path = shadow_root / "state" / "c1" / "active.json"
    rpc_alive = False
    rpc_lease_path = _lease_path(shadow_root, "c1_rpc")
    if rpc_lease_path.is_file():
        try:
            lp = _read_json(rpc_lease_path)
            pid, ct = lp.get("pid"), lp.get("create_time_filetime")
            if type(pid) is int and type(ct) is int and process_creation_token(pid) == ct:
                rpc_alive = True
        except Exception:
            if require_rpc_if_running:
                return {"idle_verified": False, "reason": "SESSION_STATE_UNKNOWN_REFUSE_KILL"}
    if active_cfg_path.is_file() and secret_file.is_file():
        active_cfg = _read_json(active_cfg_path)
        port = active_cfg.get("rpc_port")
        if type(port) is int:
            try:
                reply = _bridge_rpc_call(port, secret_file.read_text(encoding="ascii").strip(), "desktop_mode_status", {}, timeout=3.0)
                if not reply.get("ok"):
                    if rpc_alive and require_rpc_if_running:
                        return {"idle_verified": False, "reason": "SESSION_STATE_UNKNOWN_REFUSE_KILL"}
                else:
                    grants = (reply.get("result") or {}).get("grants") or []
                    if grants:
                        return {
                            "idle_verified": False,
                            "active_sessions": len(grants),
                            "reason": "ACTIVE_SESSIONS_PRESENT",
                        }
            except Exception as exc:
                if rpc_alive and require_rpc_if_running:
                    return {
                        "idle_verified": False,
                        "reason": "SESSION_STATE_UNKNOWN_REFUSE_KILL",
                        "error": type(exc).__name__,
                    }
    elif rpc_alive and require_rpc_if_running:
        return {"idle_verified": False, "reason": "SESSION_STATE_UNKNOWN_REFUSE_KILL"}
    return {"idle_verified": True, "active_sessions": 0, "reason": None}


# ---------------------------------------------------------------------------
# 4-factor Windows process identity & owner-scoped process leases
# ---------------------------------------------------------------------------

class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.wintypes.DWORD), ("high", ctypes.wintypes.DWORD)]


def _win32_kernel() -> Any:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
    kernel.OpenProcess.restype = ctypes.wintypes.HANDLE
    kernel.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    kernel.CloseHandle.restype = ctypes.wintypes.BOOL
    kernel.GetProcessTimes.argtypes = [ctypes.wintypes.HANDLE] + [ctypes.POINTER(_FileTime)] * 4
    kernel.GetProcessTimes.restype = ctypes.wintypes.BOOL
    kernel.QueryFullProcessImageNameW.argtypes = [
        ctypes.wintypes.HANDLE,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.LPWSTR,
        ctypes.POINTER(ctypes.wintypes.DWORD),
    ]
    kernel.QueryFullProcessImageNameW.restype = ctypes.wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
    kernel.WaitForSingleObject.restype = ctypes.wintypes.DWORD
    kernel.TerminateProcess.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.UINT]
    kernel.TerminateProcess.restype = ctypes.wintypes.BOOL
    return kernel


def _query_handle_identity(kernel: Any, handle: int) -> tuple[int, str] | None:
    start, exit_t, kern_t, user_t = _FileTime(), _FileTime(), _FileTime(), _FileTime()
    if not kernel.GetProcessTimes(handle, ctypes.byref(start), ctypes.byref(exit_t), ctypes.byref(kern_t), ctypes.byref(user_t)):
        return None
    if exit_t.high or exit_t.low:
        return None
    create_time = (int(start.high) << 32) | int(start.low)
    if create_time <= 0:
        return None
    size = ctypes.wintypes.DWORD(32768)
    buf = ctypes.create_unicode_buffer(size.value)
    if not kernel.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
        return None
    exe_path = buf.value
    if not exe_path:
        return None
    return create_time, exe_path


def query_process_identity_exact(pid: int) -> dict[str, Any] | None:
    """Query PID + 64-bit FILETIME creation time + physical exe path on ONE kernel handle."""
    if os.name != "nt" or type(pid) is not int or not (0 < pid <= 0xFFFFFFFF):
        return None
    kernel = _win32_kernel()
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        ident = _query_handle_identity(kernel, handle)
        if ident is None:
            return None
        create_time, exe_path = ident
        return {
            "pid": pid,
            "create_time_filetime": create_time,
            "executable_path": os.path.abspath(exe_path),
            "alive": True,
        }
    finally:
        kernel.CloseHandle(handle)


def query_process_cmdline(pid: int) -> str | None:
    """Read-only CIM query for a single exact PID command line on Windows."""
    if os.name != "nt" or type(pid) is not int or pid <= 0:
        return None
    cmd = (
        "$ErrorActionPreference='Stop'; "
        f"$p=Get-CimInstance Win32_Process -Filter 'ProcessId={pid}'; "
        "if($null -eq $p){exit 3}; "
        "$p | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"
    )
    cp = subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", cmd],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if cp.returncode != 0:
        return None
    try:
        data = json.loads(cp.stdout.strip())
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("ProcessId") != pid:
        return None
    raw = data.get("CommandLine")
    return str(raw) if isinstance(raw, str) else None


def _lease_path(shadow_root: Path, role: str) -> Path:
    if not re.fullmatch(r"[a-z0-9_]{2,32}", role):
        raise CanaryError("PROCESS_LEASE_INVALID", "Invalid lease role name", role=role)
    return shadow_root / "leases" / f"{role}.lease.json"


def write_process_lease(
    shadow_root: Path,
    *,
    role: str,
    pid: int,
    create_time_filetime: int,
    executable_path: str,
    entrypoint_path: str,
    port: int,
    release_id: str,
    owner_scope_id: str,
    receipt_store: CanaryReceiptStore | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    root = validate_shadow_root(shadow_root)
    owner = ensure_shadow_owner(root, create=False)
    if owner["owner_scope_id"] != owner_scope_id:
        raise CanaryError("PROCESS_LEASE_OWNER_MISMATCH", "owner_scope_id does not match shadow root owner")
    ep = Path(os.path.abspath(entrypoint_path))
    assert_no_reparse(ep)
    if not (_norm_path(ep).startswith(_norm_path(root) + "/") or _norm_path(ep.resolve()).startswith(_norm_path(root.resolve()) + "/")):
        raise CanaryError("PROCESS_PATH_OUTSIDE_SHADOW_ROOT", "Leased process entrypoint must reside inside shadow_root")
    lease = {
        "schema": SCHEMA_LEASE,
        "lease_id": "clse-" + uuid.uuid4().hex,
        "owner_scope_id": owner_scope_id,
        "role": role,
        "pid": int(pid),
        "create_time_filetime": int(create_time_filetime),
        "executable_path": os.path.abspath(executable_path),
        "entrypoint_path": str(ep.resolve()) if ep.exists() else str(ep),
        "expected_root": str(root.resolve()),
        "port": int(port),
        "release_id": str(release_id),
        "issued_at": time.time(),
    }
    path = _lease_path(root, role)
    _atomic_write_json(path, lease)
    if receipt_store is not None:
        receipt_store.record_lease(run_id, lease, "active")
    return lease


def _cmdline_contains_path(cmdline: str, target_path: str) -> bool:
    norm_cmd = cmdline.replace('"', "").replace("\\", "/").casefold()
    candidates = {_norm_path(target_path)}
    p = Path(target_path)
    try:
        if p.exists():
            candidates.add(_norm_path(p.resolve()))
    except OSError:
        pass
    return any(cand in norm_cmd for cand in candidates)


def verify_process_lease(
    shadow_root: Path,
    role: str,
    *,
    require_alive: bool = False,
    check_cmdline: bool = False,
) -> dict[str, Any]:
    """Verify 4-factor process identity: PID + creation FILETIME + exe/entrypoint path + owner lease."""
    root = validate_shadow_root(shadow_root)
    owner = ensure_shadow_owner(root, create=False)
    path = _lease_path(root, role)
    if not path.is_file():
        raise CanaryError("PROCESS_LEASE_MISSING", f"No process lease for role {role}", role=role)
    lease = _read_json(path)
    if lease.get("schema") != SCHEMA_LEASE or lease.get("role") != role:
        raise CanaryError("PROCESS_LEASE_INVALID", f"Invalid lease schema for role {role}", role=role)
    if lease.get("owner_scope_id") != owner["owner_scope_id"]:
        raise CanaryError("PROCESS_LEASE_OWNER_MISMATCH", "Lease owner_scope_id does not match shadow root", role=role)
    pid = lease.get("pid")
    create_time = lease.get("create_time_filetime")
    exe_expected = lease.get("executable_path")
    entry_expected = lease.get("entrypoint_path")
    if (
        type(pid) is not int
        or pid <= 0
        or type(create_time) is not int
        or create_time <= 0
        or not isinstance(exe_expected, str)
        or not exe_expected
        or not isinstance(entry_expected, str)
        or not entry_expected
    ):
        raise CanaryError("PROCESS_LEASE_INVALID", "Malformed fields in process lease", role=role)
    # Entrypoint MUST reside strictly within shadow_root.
    ep_norm = _norm_path(entry_expected)
    root_norms = {_norm_path(root), _norm_path(root.resolve())}
    if not any(ep_norm.startswith(rn + "/") for rn in root_norms):
        raise CanaryError("PROCESS_PATH_OUTSIDE_SHADOW_ROOT", "Lease entrypoint escapes shadow root", role=role)

    live = query_process_identity_exact(pid)
    if live is None:
        if require_alive:
            raise CanaryError("PROCESS_NOT_RUNNING", f"Leased process {role} (pid={pid}) is not running", role=role, pid=pid)
        return {"alive": False, "identity_matched": False, "reason": "PROCESS_EXITED", "lease": lease}

    if live["create_time_filetime"] != create_time:
        if require_alive:
            raise CanaryError(
                "PROCESS_IDENTITY_MISMATCH",
                "PID creation FILETIME mismatch (PID recycled)",
                role=role,
                pid=pid,
            )
        return {"alive": False, "identity_matched": False, "reason": "PID_REUSED_OR_EXITED_NO_KILL", "lease": lease}

    if _norm_path(live["executable_path"]) != _norm_path(exe_expected):
        raise CanaryError(
            "PROCESS_IDENTITY_MISMATCH",
            "Process executable image path does not match lease",
            role=role,
            pid=pid,
        )

    cmdline_verified = False
    if check_cmdline and os.name == "nt":
        cmdline = query_process_cmdline(pid)
        if not cmdline or not _cmdline_contains_path(cmdline, entry_expected):
            raise CanaryError(
                "PROCESS_IDENTITY_MISMATCH",
                "Process command line does not match leased shadow entrypoint",
                role=role,
                pid=pid,
            )
        cmdline_verified = True

    return {
        "alive": True,
        "identity_matched": True,
        "cmdline_verified": cmdline_verified,
        "pid": pid,
        "create_time_filetime": create_time,
        "executable_path": live["executable_path"],
        "entrypoint_path": entry_expected,
        "lease": lease,
    }


def stop_leased_process(
    shadow_root: Path,
    role: str,
    *,
    idle_checker: Callable[[], dict[str, Any]] | None = None,
    graceful_stop: Callable[[], None] | None = None,
    timeout_seconds: float = 15.0,
    receipt_store: CanaryReceiptStore | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Stop ONLY a 4-factor verified, owner-leased, verified-idle shadow process.

    Active sessions or unknown session state ALWAYS fail closed without killing.
    """
    root = validate_shadow_root(shadow_root)
    info = verify_process_lease(root, role, require_alive=False, check_cmdline=True)
    lease = info["lease"]
    if not info["alive"]:
        if receipt_store is not None:
            receipt_store.record_lease(run_id, lease, "exited_or_reused_no_kill")
        return {
            "stopped": True,
            "terminated": False,
            "role": role,
            "pid": lease["pid"],
            "reason": info.get("reason") or "PROCESS_EXITED",
        }

    # MANDATORY active-session / active-job guard BEFORE touching the process!
    if idle_checker is None:
        raise CanaryError(
            "SESSION_STATE_UNKNOWN_REFUSE_KILL",
            "An explicit idle_checker is mandatory before stopping any leased process",
            role=role,
        )
    idle = idle_checker()
    if not isinstance(idle, dict) or idle.get("idle_verified") is not True:
        code = str((idle or {}).get("reason") or "SESSION_STATE_UNKNOWN_REFUSE_KILL")
        if code not in {"ACTIVE_SESSIONS_PRESENT", "ACTIVE_C2_JOBS_PRESENT", "SESSION_STATE_UNKNOWN_REFUSE_KILL"}:
            code = "ACTIVE_SESSIONS_PRESENT"
        raise CanaryError(code, f"Refusing to stop {role}: active work or unknown state", role=role, idle_check=idle)

    pid = int(lease["pid"])
    expected_ct = int(lease["create_time_filetime"])
    expected_exe = _norm_path(lease["executable_path"])

    # Step 1: Cooperative graceful shutdown if available (e.g., Hub hub_shutdown_idle).
    if graceful_stop is not None:
        graceful_stop()
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            cur = query_process_identity_exact(pid)
            if cur is None or cur["create_time_filetime"] != expected_ct:
                if receipt_store is not None:
                    receipt_store.record_lease(run_id, lease, "stopped_idle")
                return {"stopped": True, "terminated": False, "graceful": True, "role": role, "pid": pid}
            time.sleep(0.1)
        raise CanaryError("IDLE_STOP_TIMEOUT", f"Graceful idle stop timed out for {role}", role=role, pid=pid)

    # Step 2: Re-verify active sessions immediately before exact-handle stop, then
    # verify PID + FILETIME + executable image on ONE Windows kernel handle!
    idle_recheck = idle_checker()
    if not isinstance(idle_recheck, dict) or idle_recheck.get("idle_verified") is not True:
        code = str((idle_recheck or {}).get("reason") or "ACTIVE_SESSIONS_PRESENT")
        raise CanaryError(code, f"Active work appeared before stop for {role}", role=role, idle_check=idle_recheck)

    if os.name != "nt":
        raise CanaryError("WINDOWS_REQUIRED", "Exact kernel handle stop requires Windows")

    kernel = _win32_kernel()
    # Open ONE handle with PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE
    handle = kernel.OpenProcess(0x0001 | 0x1000 | 0x100000, False, pid)
    if not handle:
        if receipt_store is not None:
            receipt_store.record_lease(run_id, lease, "exited_or_reused_no_kill")
        return {"stopped": True, "terminated": False, "role": role, "pid": pid, "reason": "PROCESS_EXITED"}
    try:
        ident = _query_handle_identity(kernel, handle)
        if ident is None:
            if receipt_store is not None:
                receipt_store.record_lease(run_id, lease, "exited_or_reused_no_kill")
            return {"stopped": True, "terminated": False, "role": role, "pid": pid, "reason": "PROCESS_EXITED"}
        actual_ct, actual_exe = ident
        if actual_ct != expected_ct:
            if receipt_store is not None:
                receipt_store.record_lease(run_id, lease, "identity_mismatch_no_kill")
            return {"stopped": True, "terminated": False, "role": role, "pid": pid, "reason": "PID_REUSED_OR_EXITED_NO_KILL"}
        if _norm_path(actual_exe) != expected_exe:
            raise CanaryError("PROCESS_IDENTITY_MISMATCH", "Handle executable path mismatch before stop", role=role, pid=pid)
        wait_state = kernel.WaitForSingleObject(handle, 0)
        if wait_state == 0:
            if receipt_store is not None:
                receipt_store.record_lease(run_id, lease, "stopped_idle")
            return {"stopped": True, "terminated": False, "role": role, "pid": pid, "reason": "PROCESS_EXITED"}
        if wait_state != 258 or not kernel.TerminateProcess(handle, 0):
            raise CanaryError("IDLE_STOP_FAILED", f"Failed to stop verified idle shadow process {role}", role=role, pid=pid)
        wait_after = kernel.WaitForSingleObject(handle, int(timeout_seconds * 1000))
        if wait_after != 0:
            raise CanaryError("IDLE_STOP_TIMEOUT", f"Timed out waiting for verified idle process {role} to exit", role=role, pid=pid)
    finally:
        kernel.CloseHandle(handle)

    if receipt_store is not None:
        receipt_store.record_lease(run_id, lease, "stopped_idle")
    return {"stopped": True, "terminated": True, "graceful": False, "role": role, "pid": pid}


# ---------------------------------------------------------------------------
# C1 Staging (pinned SHA-256 + internal manifest verification + SQLite backups)
# ---------------------------------------------------------------------------

def _c1_bridge_dir(release_dir: Path) -> Path:
    for candidate in (release_dir / "full-install" / "bridge-v3", release_dir / "runtime" / "bridge-v3", release_dir / "bridge-v3"):
        if candidate.is_dir():
            return candidate
    raise CanaryError("C1_RELEASE_LAYOUT_INVALID", "bridge-v3 directory missing in C1 release", release_dir=str(release_dir))


def _c1_python_exe(release_dir: Path) -> str:
    tools_dir = release_dir / "full-install" / "tools"
    if tools_dir.is_dir():
        for py in sorted(tools_dir.rglob("python.exe")):
            if py.is_file():
                return str(py)
    return sys.executable


def _verify_c1_release_dir_hashes(release_dir: Path) -> dict[str, Any]:
    mf = _read_json(release_dir / "install-manifest.json")
    files = mf.get("files")
    if not isinstance(files, dict) or not files:
        raise CanaryError("STAGED_FILE_HASH_MISMATCH", "C1 install-manifest.json is invalid")
    for rel, expected in files.items():
        _validate_archive_relpath(rel)
        target = release_dir.joinpath(*PurePosixPath(rel).parts)
        assert_no_reparse(target, must_file=True)
        if not hmac.compare_digest(sha256_file(target), str(expected).lower()):
            raise CanaryError("STAGED_FILE_HASH_MISMATCH", f"C1 staged file hash mismatch: {rel}", file=rel)
    return mf


def _backup_existing_c1_state(
    shadow_root: Path,
    run_id: str,
    store: CanaryReceiptStore,
) -> list[dict[str, Any]]:
    backups: list[dict[str, Any]] = []
    hub_dir = shadow_root / "state" / "c1" / "hub"
    for db_name in ("hub.db", "entry-grants.sqlite3"):
        src = hub_dir / db_name
        if src.is_file():
            dst = shadow_root / "backups" / run_id / f"c1_{db_name}"
            info = sqlite_online_backup(src, dst)
            store.record_backup(run_id, "c1", db_name, info)
            backups.append({"db_name": db_name, **info})
    return backups


def stage_c1_shadow(
    shadow_root: Path,
    *,
    c1_zip: Path,
    c1_zip_sha256: str,
    c1_expected_commit: str | None = None,
    rpc_port: int = DEFAULT_SHADOW_PORTS["c1_rpc_port"],
    hub_port: int = DEFAULT_SHADOW_PORTS["c1_hub_port"],
    run_full_installer: bool = False,
    receipt_store: CanaryReceiptStore | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Stage a pinned C1 candidate ZIP into an immutable shadow release directory."""
    root = validate_shadow_root(shadow_root)
    validate_shadow_ports({"c1_rpc_port": rpc_port, "c1_hub_port": hub_port})
    pinned_sha = validate_sha256(c1_zip_sha256, "c1_zip_sha256")
    pinned_commit = validate_git_commit(c1_expected_commit, "c1_expected_commit") if c1_expected_commit is not None else None

    c1_zip = Path(c1_zip)
    if not c1_zip.is_file():
        raise CanaryError("ARCHIVE_MISSING", "C1 candidate ZIP file does not exist")
    assert_no_reparse(c1_zip, must_file=True)
    actual_sha = sha256_file(c1_zip)
    if not hmac.compare_digest(actual_sha, pinned_sha):
        raise CanaryError("PINNED_SHA256_MISMATCH", "C1 ZIP SHA-256 mismatch", expected=pinned_sha, actual=actual_sha)

    # Validate ZIP archive structure, internal manifest, and every declared hash BEFORE any writes.
    with zipfile.ZipFile(c1_zip, "r") as zf:
        entries = _validate_zip_entries(zf)
        entry_map = {info.filename: info for info in entries}
        if "release-manifest.json" not in entry_map:
            raise CanaryError("ARCHIVE_MANIFEST_INVALID", "release-manifest.json missing from C1 ZIP")
        try:
            manifest = json.loads(zf.read("release-manifest.json"))
        except (ValueError, UnicodeError) as exc:
            raise CanaryError("ARCHIVE_MANIFEST_INVALID", "Invalid release-manifest.json in C1 ZIP") from exc
        if not isinstance(manifest, dict) or manifest.get("schema") != "ff-gh-release-v1":
            raise CanaryError("ARCHIVE_MANIFEST_INVALID", "Unrecognized C1 release-manifest.json schema")
        source_commit = validate_git_commit(manifest.get("source_commit"), "manifest.source_commit")
        if pinned_commit is not None and source_commit != pinned_commit:
            raise CanaryError(
                "PINNED_COMMIT_MISMATCH",
                "C1 ZIP source_commit does not match c1_expected_commit",
                expected=pinned_commit,
                actual=source_commit,
            )
        manifest_files = manifest.get("files")
        if not isinstance(manifest_files, dict) or not manifest_files:
            raise CanaryError("ARCHIVE_MANIFEST_INVALID", "release-manifest.json files map missing")

        verified_extract: dict[str, tuple[bytes, str]] = {}
        is_full_core = "install.ps1" in entry_map
        for name, expected_hash in sorted(manifest_files.items()):
            _validate_archive_relpath(name)
            expected_norm = validate_sha256(expected_hash, f"manifest.files[{name}]")
            if name not in entry_map:
                raise CanaryError("ARCHIVE_INTERNAL_HASH_MISMATCH", f"Manifest entry missing from ZIP: {name}", file=name)
            raw = zf.read(name)
            if not hmac.compare_digest(sha256_bytes(raw), expected_norm):
                raise CanaryError("ARCHIVE_INTERNAL_HASH_MISMATCH", f"Internal SHA-256 mismatch: {name}", file=name)
            # Compile every staged runtime/tool Python file before touching disk!
            if name.endswith(".py") and (name.startswith("runtime/") or name.startswith("tools/")):
                try:
                    compile(raw, name, "exec")
                except SyntaxError as exc:
                    raise CanaryError("C1_SYNTAX_COMPILE_FAILED", f"SyntaxError in {name}", file=name) from exc
            if not name.startswith("assets/"):
                verified_extract[name] = (raw, expected_norm)

        if "runtime/bridge-v3/ff_hub.py" not in verified_extract:
            raise CanaryError("ARCHIVE_MANIFEST_INVALID", "C1 ZIP missing runtime/bridge-v3/ff_hub.py")

    owner = ensure_shadow_owner(root, create=True)
    store = receipt_store or CanaryReceiptStore(root / "state" / "canary_receipts.sqlite3")

    # Refuse staging over active running shadow C1 sessions!
    hub_idle = inspect_c1_hub_active_sessions(root / "state" / "c1" / "hub", require_rpc_if_running=True)
    if not hub_idle["idle_verified"]:
        raise CanaryError(str(hub_idle.get("reason") or "ACTIVE_SESSIONS_PRESENT"), "Cannot stage C1 while shadow Hub has active sessions")

    # Backup existing shadow C1 SQLite DBs via SQLite Online Backup API before changing active pointer.
    pre_backups = _backup_existing_c1_state(root, run_id, store) if run_id else []

    release_id = f"{source_commit[:12]}-{actual_sha[:12]}"
    releases_root = root / "releases" / "c1"
    releases_root.mkdir(parents=True, exist_ok=True)
    target = releases_root / release_id

    if not target.exists():
        stage_dir = releases_root / (".stage-" + uuid.uuid4().hex)
        stage_dir.mkdir(parents=True, exist_ok=False)
        try:
            file_hashes: dict[str, str] = {}
            for rel, (raw, digest_hex) in sorted(verified_extract.items()):
                dst = stage_dir.joinpath(*PurePosixPath(rel).parts)
                dst.parent.mkdir(parents=True, exist_ok=True)
                _atomic_write_bytes(dst, raw)
                file_hashes[rel] = digest_hex
            if run_full_installer and is_full_core and os.name == "nt":
                full_extract = stage_dir / ".installer-src"
                full_extract.mkdir(parents=True, exist_ok=True)
                with zipfile.ZipFile(c1_zip, "r") as zf:
                    for info in entries:
                        dest_item = full_extract.joinpath(*PurePosixPath(info.filename).parts)
                        dest_item.parent.mkdir(parents=True, exist_ok=True)
                        dest_item.write_bytes(zf.read(info.filename))
                full_install_root = stage_dir / "full-install"
                cp = subprocess.run(
                    [
                        "powershell.exe",
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(full_extract / "install.ps1"),
                        "-InstallRoot",
                        str(full_install_root),
                        "-RpcPort",
                        str(rpc_port),
                        "-RuntimeOnly",
                        "-NoStartup",
                        "-NonInteractive",
                        "-Transport",
                        "Local",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
                shutil.rmtree(full_extract, ignore_errors=True)
                if cp.returncode != 0:
                    raise CanaryError("C1_FULL_INSTALL_FAILED", f"install.ps1 failed ({cp.returncode})", stderr=(cp.stderr or "")[-600:])
            _atomic_write_json(
                stage_dir / "install-manifest.json",
                {
                    "schema": "ff-canary-c1-install-manifest-v1",
                    "release_id": release_id,
                    "source_commit": source_commit,
                    "c1_zip_sha256": actual_sha,
                    "package_kind": "full_core_zip" if is_full_core else "source_archive_zip",
                    "full_installer_executed": bool(run_full_installer and is_full_core),
                    "owner_scope_id": owner["owner_scope_id"],
                    "files": file_hashes,
                },
            )
            os.replace(stage_dir, target)
        except BaseException:
            shutil.rmtree(stage_dir, ignore_errors=True)
            raise
    else:
        _verify_c1_release_dir_hashes(target)

    # Prepare controlled shadow state directories (never overwrite existing SQLite DBs!).
    c1_state_root = root / "state" / "c1"
    (c1_state_root / "runtime").mkdir(parents=True, exist_ok=True)
    hub_state = c1_state_root / "hub"
    hub_state.mkdir(parents=True, exist_ok=True)
    _atomic_write_json(hub_state / "config.json", {"port": hub_port})

    active_file = c1_state_root / "active.json"
    previous = _read_json(active_file) if active_file.is_file() else None
    prev_rel = previous.get("release_id") if previous and previous.get("release_id") != release_id else (
        previous.get("previous_release_id") if previous else None
    )
    active_cfg = {
        "schema": SCHEMA_C1_ACTIVE,
        "release_id": release_id,
        "previous_release_id": prev_rel,
        "source_commit": source_commit,
        "zip_sha256": actual_sha,
        "package_kind": "full_core_zip" if is_full_core else "source_archive_zip",
        "rpc_port": rpc_port,
        "hub_port": hub_port,
        "updated_at": time.time(),
    }
    _atomic_write_json(active_file, active_cfg)
    return {
        "ok": True,
        "release_id": release_id,
        "previous_release_id": prev_rel,
        "source_commit": source_commit,
        "zip_sha256": actual_sha,
        "package_kind": active_cfg["package_kind"],
        "verified_files": len(verified_extract),
        "rpc_port": rpc_port,
        "hub_port": hub_port,
        "pre_stage_backups": pre_backups,
    }


# ---------------------------------------------------------------------------
# C2 Staging (separate codebase, immutable release + controlled shadow slot)
# ---------------------------------------------------------------------------

def _export_c2_from_git(c2_repo: Path, pinned_commit: str, *, require_clean_head: bool = True) -> dict[str, bytes]:
    c2_repo = Path(c2_repo)
    assert_no_reparse(c2_repo)
    if not c2_repo.is_dir():
        raise CanaryError("C2_REPO_MISSING", "C2 repository path does not exist")
    # Never mutate c2_repo: run strictly read-only git commands.
    head_cp = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(c2_repo), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if head_cp.returncode != 0:
        raise CanaryError("C2_REPO_INVALID", "Path is not a valid Git repository")
    actual_head = head_cp.stdout.strip().lower()
    if require_clean_head:
        if actual_head != pinned_commit:
            raise CanaryError(
                "PINNED_COMMIT_MISMATCH",
                "C2 repo HEAD does not match pinned C2 commit",
                expected=pinned_commit,
                actual=actual_head,
            )
        status_cp = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(c2_repo), "status", "--porcelain=v1", "--untracked-files=no"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if status_cp.returncode != 0 or status_cp.stdout.strip():
            raise CanaryError("C2_REPO_DIRTY", "C2 repository has uncommitted modifications")

    verify_cp = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(c2_repo), "rev-parse", "--verify", f"{pinned_commit}^{{commit}}"],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    if verify_cp.returncode != 0 or verify_cp.stdout.strip().lower() != pinned_commit:
        raise CanaryError("PINNED_COMMIT_MISMATCH", "Pinned C2 commit object not found in C2 repository")

    arch_cp = subprocess.run(
        ["git", "--no-optional-locks", "-c", "core.autocrlf=false", "-c", "core.eol=lf",
         "-C", str(c2_repo), "archive", "--format=tar", pinned_commit],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if arch_cp.returncode != 0:
        raise CanaryError("C2_ARCHIVE_EXPORT_FAILED", "git archive failed for pinned C2 commit")

    files: dict[str, bytes] = {}
    total_bytes = 0
    with tarfile.open(fileobj=io.BytesIO(arch_cp.stdout), mode="r:") as tf:
        for member in tf.getmembers():
            if member.isdir() or member.name == "pax_global_header":
                continue
            if not member.isfile():
                raise CanaryError("ARCHIVE_PATH_INVALID", "Non-regular file in C2 archive", entry=member.name[:120])
            _validate_archive_relpath(member.name)
            # Never import host DBs, keys, locks, or test artifact folders into immutable code release.
            base_name = PurePosixPath(member.name).name.casefold()
            if base_name in C2_PRESERVED_RUNTIME_FILES or base_name.endswith((".db", ".sqlite", ".sqlite3", ".key", ".dpapi")):
                continue
            data = tf.extractfile(member).read()
            total_bytes += len(data)
            if len(files) >= MAX_C2_FILES or total_bytes > MAX_C2_TOTAL_BYTES:
                raise CanaryError("ARCHIVE_SIZE_LIMIT", "C2 archive exceeds safe file/byte limit")
            files[member.name] = data
    return files


def _export_c2_from_zip(c2_zip: Path, pinned_sha256: str) -> tuple[dict[str, bytes], str]:
    pinned = validate_sha256(pinned_sha256, "c2_zip_sha256")
    c2_zip = Path(c2_zip)
    if not c2_zip.is_file():
        raise CanaryError("ARCHIVE_MISSING", "C2 ZIP archive missing")
    assert_no_reparse(c2_zip, must_file=True)
    actual_sha = sha256_file(c2_zip)
    if not hmac.compare_digest(actual_sha, pinned):
        raise CanaryError("PINNED_SHA256_MISMATCH", "C2 ZIP SHA-256 mismatch", expected=pinned, actual=actual_sha)
    files: dict[str, bytes] = {}
    total_bytes = 0
    with zipfile.ZipFile(c2_zip, "r") as zf:
        for info in _validate_zip_entries(zf):
            base_name = PurePosixPath(info.filename).name.casefold()
            if base_name in C2_PRESERVED_RUNTIME_FILES or base_name.endswith((".db", ".sqlite", ".sqlite3", ".key", ".dpapi")):
                continue
            data = zf.read(info.filename)
            total_bytes += len(data)
            if len(files) >= MAX_C2_FILES or total_bytes > MAX_C2_TOTAL_BYTES:
                raise CanaryError("ARCHIVE_SIZE_LIMIT", "C2 ZIP exceeds safe limits")
            files[info.filename] = data
    return files, actual_sha


def _verify_c2_dir_against_manifest(directory: Path, manifest: dict[str, Any]) -> None:
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise CanaryError("STAGED_FILE_HASH_MISMATCH", "Invalid C2 stage manifest")
    for rel, expected in sorted(files.items()):
        _validate_archive_relpath(rel)
        target = directory.joinpath(*PurePosixPath(rel).parts)
        assert_no_reparse(target, must_file=True)
        if not hmac.compare_digest(sha256_file(target), str(expected).lower()):
            raise CanaryError("STAGED_FILE_HASH_MISMATCH", f"C2 staged file hash mismatch: {rel}", file=rel)


def _sync_c2_runtime_slot(release_dir: Path, runtime_slot: Path, *, previous_manifest: dict[str, Any] | None = None) -> None:
    """Materialize verified immutable C2 release into controlled runtime slot, preserving DB/key."""
    manifest = _read_json(release_dir / "c2-stage-manifest.json")
    _verify_c2_dir_against_manifest(release_dir, manifest)
    runtime_slot.mkdir(parents=True, exist_ok=True)
    assert_no_reparse(runtime_slot)

    new_files = manifest["files"]
    if previous_manifest and isinstance(previous_manifest.get("files"), dict):
        retired = set(previous_manifest["files"].keys()) - set(new_files.keys())
        for rel in sorted(retired):
            _validate_archive_relpath(rel)
            if PurePosixPath(rel).name.casefold() in C2_PRESERVED_RUNTIME_FILES:
                continue
            old_target = runtime_slot.joinpath(*PurePosixPath(rel).parts)
            if old_target.is_file() and not _is_reparse_point(old_target):
                old_target.unlink()

    for rel, expected_sha in sorted(new_files.items()):
        src = release_dir.joinpath(*PurePosixPath(rel).parts)
        dst = runtime_slot.joinpath(*PurePosixPath(rel).parts)
        dst.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_bytes(dst, src.read_bytes())
        if not hmac.compare_digest(sha256_file(dst), expected_sha):
            raise CanaryError("STAGED_FILE_HASH_MISMATCH", f"C2 slot copy verification failed: {rel}", file=rel)

    _atomic_write_json(runtime_slot / "c2-stage-manifest.json", manifest)


def stage_c2_shadow(
    shadow_root: Path,
    *,
    c2_repo: Path | None = None,
    c2_commit: str | None = None,
    c2_zip: Path | None = None,
    c2_zip_sha256: str | None = None,
    c2_source_db: Path | None = None,
    c2_expected_manifest_sha256: str | None = None,
    gateway_port: int = DEFAULT_SHADOW_PORTS["c2_gateway_port"],
    unified_port: int = DEFAULT_SHADOW_PORTS["c2_unified_port"],
    omni_port: int = DEFAULT_C2_OMNI_PORT,
    require_clean_head: bool = True,
    receipt_store: CanaryReceiptStore | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Stage a separate C2 codebase into an immutable shadow release + isolated staging slot."""
    root = validate_shadow_root(shadow_root)
    validate_shadow_ports({"c2_gateway_port": gateway_port, "c2_unified_port": unified_port})
    if type(omni_port) is not int or not (1024 <= omni_port <= 65535):
        raise CanaryError("SHADOW_PORT_INVALID", "Invalid OmniRoute upstream port", port=omni_port)

    if c2_repo is not None and c2_zip is not None:
        raise CanaryError("C2_SOURCE_AMBIGUOUS", "Specify either c2_repo or c2_zip, not both")
    if c2_repo is None and c2_zip is None:
        raise CanaryError("C2_SOURCE_REQUIRED", "C2 staging requires --c2-repo + --c2-commit or --c2-zip + --c2-zip-sha256")

    source_zip_sha: str | None = None
    if c2_repo is not None:
        pinned_commit = validate_git_commit(c2_commit, "c2_commit")
        files = _export_c2_from_git(c2_repo, pinned_commit, require_clean_head=require_clean_head)
        source_kind = "git_archive"
    else:
        pinned_commit = validate_git_commit(c2_commit, "c2_commit") if c2_commit is not None else ("0" * 40)
        files, source_zip_sha = _export_c2_from_zip(Path(c2_zip), str(c2_zip_sha256 or ""))
        source_kind = "pinned_zip"

    # Verify required C2 entrypoints and Python compilation BEFORE touching shadow slot!
    for req in C2_REQUIRED_FILES:
        if req not in files:
            raise CanaryError("C2_REQUIRED_FILE_MISSING", f"Required C2 file missing: {req}", file=req)
    for rel, raw in sorted(files.items()):
        if rel.endswith(".py"):
            try:
                compile(raw, rel, "exec")
            except SyntaxError as exc:
                raise CanaryError("C2_SYNTAX_COMPILE_FAILED", f"SyntaxError in C2 {rel}", file=rel) from exc

    file_hashes = {rel: sha256_bytes(raw) for rel, raw in sorted(files.items())}
    manifest_core = {
        "schema": SCHEMA_C2_MANIFEST,
        "source_kind": source_kind,
        "source_commit": pinned_commit,
        "source_zip_sha256": source_zip_sha,
        "files": file_hashes,
    }
    manifest_sha = sha256_bytes(_canonical_json(manifest_core).encode("utf-8"))
    if c2_expected_manifest_sha256 is not None:
        pinned_mf = validate_sha256(c2_expected_manifest_sha256, "c2_expected_manifest_sha256")
        if not hmac.compare_digest(manifest_sha, pinned_mf):
            raise CanaryError("PINNED_SHA256_MISMATCH", "C2 manifest SHA-256 mismatch", expected=pinned_mf, actual=manifest_sha)

    owner = ensure_shadow_owner(root, create=True)
    store = receipt_store or CanaryReceiptStore(root / "state" / "canary_receipts.sqlite3")

    # Refuse staging over active running C2 jobs!
    runtime_slot = root / "state" / "c2" / "runtime"
    c2_idle = inspect_c2_gateway_active_jobs(runtime_slot / "gateway.db")
    if not c2_idle["idle_verified"]:
        raise CanaryError(
            str(c2_idle.get("reason") or "ACTIVE_C2_JOBS_PRESENT"),
            "Refusing to stage C2 while shadow gateway.db has active jobs",
            c2_idle=c2_idle,
        )

    release_id = f"{pinned_commit[:12]}-{manifest_sha[:12]}"
    releases_root = root / "releases" / "c2"
    releases_root.mkdir(parents=True, exist_ok=True)
    target = releases_root / release_id
    full_manifest = {
        **manifest_core,
        "release_id": release_id,
        "manifest_sha256": manifest_sha,
        "owner_scope_id": owner["owner_scope_id"],
    }

    if not target.exists():
        stage_dir = releases_root / (".stage-" + uuid.uuid4().hex)
        stage_dir.mkdir(parents=True, exist_ok=False)
        try:
            for rel, raw in sorted(files.items()):
                dst = stage_dir.joinpath(*PurePosixPath(rel).parts)
                dst.parent.mkdir(parents=True, exist_ok=True)
                _atomic_write_bytes(dst, raw)
            _atomic_write_json(stage_dir / "c2-stage-manifest.json", full_manifest)
            os.replace(stage_dir, target)
        except BaseException:
            shutil.rmtree(stage_dir, ignore_errors=True)
            raise
    else:
        _verify_c2_dir_against_manifest(target, full_manifest)

    # Backup existing shadow gateway.db via SQLite Online Backup API before changing runtime slot.
    pre_stage_db_backup: dict[str, Any] | None = None
    existing_shadow_db = runtime_slot / "gateway.db"
    if existing_shadow_db.is_file():
        bkp_run = run_id or ("ad-hoc-" + uuid.uuid4().hex[:12])
        bkp_path = root / "backups" / bkp_run / "c2_gateway_pre_stage.db"
        pre_stage_db_backup = sqlite_online_backup(existing_shadow_db, bkp_path)
        if run_id:
            store.record_backup(run_id, "c2", "gateway.db", pre_stage_db_backup)

    # Optionally seed shadow gateway.db from a read-only source DB via SQLite Online Backup API.
    seeded_db_backup: dict[str, Any] | None = None
    if c2_source_db is not None:
        src_db = Path(c2_source_db)
        if not src_db.is_file():
            raise CanaryError("SQLITE_SOURCE_MISSING", "c2_source_db file does not exist")
        bkp_run = run_id or ("seed-" + uuid.uuid4().hex[:12])
        seed_snapshot = root / "backups" / bkp_run / "c2_gateway_seed_snapshot.db"
        seeded_db_backup = sqlite_online_backup(src_db, seed_snapshot)
        if run_id:
            store.record_backup(run_id, "c2", "gateway_seed.db", seeded_db_backup)
        sqlite_restore_from_backup(seed_snapshot, seeded_db_backup["backup_sha256"], runtime_slot / "gateway.db")

    # Sync immutable release code into runtime slot while preserving shadow gateway.db & gateway.key.
    active_file = root / "state" / "c2" / "active.json"
    previous = _read_json(active_file) if active_file.is_file() else None
    prev_manifest = None
    if previous and previous.get("release_id"):
        prev_mf_path = releases_root / previous["release_id"] / "c2-stage-manifest.json"
        if prev_mf_path.is_file():
            prev_manifest = _read_json(prev_mf_path)
    _sync_c2_runtime_slot(target, runtime_slot, previous_manifest=prev_manifest)

    # Always use an isolated shadow bearer key (never reuse or mutate production gateway.key!).
    shadow_key_file = runtime_slot / "gateway.key"
    if not shadow_key_file.is_file():
        _atomic_write_bytes(shadow_key_file, (secrets.token_urlsafe(32) + "\n").encode("ascii"))

    prev_rel = previous.get("release_id") if previous and previous.get("release_id") != release_id else (
        previous.get("previous_release_id") if previous else None
    )
    active_cfg = {
        "schema": SCHEMA_C2_ACTIVE,
        "release_id": release_id,
        "previous_release_id": prev_rel,
        "source_commit": pinned_commit,
        "source_kind": source_kind,
        "source_zip_sha256": source_zip_sha,
        "manifest_sha256": manifest_sha,
        "gateway_port": gateway_port,
        "unified_port": unified_port,
        "omni_port": omni_port,
        "pre_stage_db_backup": pre_stage_db_backup,
        "seeded_db_backup": seeded_db_backup,
        "updated_at": time.time(),
    }
    _atomic_write_json(active_file, active_cfg)
    return {
        "ok": True,
        "release_id": release_id,
        "previous_release_id": prev_rel,
        "source_commit": pinned_commit,
        "manifest_sha256": manifest_sha,
        "verified_files": len(files),
        "gateway_port": gateway_port,
        "unified_port": unified_port,
        "omni_port": omni_port,
        "pre_stage_db_backup": pre_stage_db_backup,
        "seeded_db_backup": seeded_db_backup,
    }


# ---------------------------------------------------------------------------
# Shadow Service Lifecycle & Health Contract Verification
# ---------------------------------------------------------------------------

def _bridge_rpc_call(port: int, secret: str, op: str, args: dict[str, Any], *, timeout: float = 5.0) -> dict[str, Any]:
    body = json.dumps({"op": op, "args": args}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/rpc",
        data=body,
        headers={"Content-Type": "application/json", "X-FF3-Key": secret},
        method="POST",
    )
    try:
        with _loopback_opener().open(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())


def _http_get_json(
    port: int,
    path: str,
    *,
    timeout: float = 3.0,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any] | None]:
    req_headers = {"Accept": "application/json", "Connection": "close"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        headers=req_headers,
        method="GET",
    )
    try:
        with _loopback_opener().open(req, timeout=timeout) as resp:
            status = int(resp.status)
            raw = resp.read(65536)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw = exc.read(65536)
    except (urllib.error.URLError, OSError, TimeoutError):
        return 0, None
    try:
        parsed = json.loads(raw.decode("utf-8", "replace"))
        return status, parsed if isinstance(parsed, dict) else None
    except ValueError:
        return status, None


def _read_log_tail(log_path: Path, max_bytes: int = 500) -> str:
    try:
        raw = log_path.read_bytes()[-max_bytes:]
        return raw.decode("utf-8", "replace").strip()
    except OSError:
        return ""


def _detach_popen(proc: subprocess.Popen) -> None:
    """Release parent's handle to an intentionally detached shadow daemon cleanly."""
    handle = getattr(proc, "_handle", None)
    if handle is not None and hasattr(handle, "Close"):
        try:
            handle.Close()
        except OSError:
            pass
    proc._child_created = False


def _spawn_shadow_process(
    argv: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    log_path: Path,
) -> subprocess.Popen:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    with log_path.open("ab", buffering=0) as log_handle:
        return subprocess.Popen(
            argv,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_handle,
            stderr=log_handle,
            creationflags=flags,
            close_fds=True,
        )


def start_shadow_services(
    shadow_root: Path,
    *,
    start_c1_rpc: bool = False,
    start_c1_hub: bool = True,
    start_c2_gateway: bool = True,
    start_c2_unified: bool = True,
    startup_timeout: float = 25.0,
    request_key: str | None = None,
) -> dict[str, Any]:
    """Start shadow C1/C2 services on non-production ports and record 4-factor leases."""
    root = validate_shadow_root(shadow_root)
    owner = ensure_shadow_owner(root, create=False)
    store = CanaryReceiptStore(root / "state" / "canary_receipts.sqlite3")
    run_id, cached = store.begin_run(
        "start_shadow",
        "shadow",
        request_key=request_key,
        request_payload={
            "shadow_root": str(root),
            "start_c1_rpc": start_c1_rpc,
            "start_c1_hub": start_c1_hub,
            "start_c2_gateway": start_c2_gateway,
            "start_c2_unified": start_c2_unified,
        },
    )
    if cached is not None:
        return {"ok": cached["status"] == "succeeded", **cached}

    started: dict[str, Any] = {}
    logs_dir = root / "state" / "logs"
    try:
        c1_active_path = root / "state" / "c1" / "active.json"
        c2_active_path = root / "state" / "c2" / "active.json"
        c1_cfg = _read_json(c1_active_path) if c1_active_path.is_file() else None
        c2_cfg = _read_json(c2_active_path) if c2_active_path.is_file() else None

        ports_to_check: dict[str, int] = {}
        if c1_cfg and (start_c1_hub or start_c1_rpc):
            if start_c1_rpc:
                ports_to_check["c1_rpc_port"] = int(c1_cfg["rpc_port"])
            if start_c1_hub:
                ports_to_check["c1_hub_port"] = int(c1_cfg["hub_port"])
        if c2_cfg and (start_c2_gateway or start_c2_unified):
            if start_c2_gateway:
                ports_to_check["c2_gateway_port"] = int(c2_cfg["gateway_port"])
            if start_c2_unified:
                ports_to_check["c2_unified_port"] = int(c2_cfg["unified_port"])
        validate_shadow_ports(ports_to_check)

        c1_runtime_env = str(root / "state" / "c1" / "runtime")
        c1_hub_env = str(root / "state" / "c1" / "hub")

        if start_c1_hub:
            if c1_cfg is None:
                raise CanaryError("C1_NOT_STAGED", "C1 shadow release must be staged before starting Hub")
            rel_dir = root / "releases" / "c1" / c1_cfg["release_id"]
            _verify_c1_release_dir_hashes(rel_dir)
            bridge_dir = _c1_bridge_dir(rel_dir)
            hub_entry = bridge_dir / "ff_hub.py"
            py_exe = _c1_python_exe(rel_dir)
            hub_port = int(c1_cfg["hub_port"])
            hub_state = root / "state" / "c1" / "hub"
            _atomic_write_json(hub_state / "config.json", {"port": hub_port})
            env = {**os.environ, "FF_BRIDGE_ROOT": c1_runtime_env, "FF_HUB_STATE": c1_hub_env}
            proc = _spawn_shadow_process(
                [py_exe, str(hub_entry), "serve", "--state-dir", str(hub_state), "--port", str(hub_port)],
                cwd=bridge_dir,
                env=env,
                log_path=logs_dir / "c1_hub.log",
            )
            deadline = time.monotonic() + startup_timeout
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise CanaryError(
                        "C1_HUB_START_FAILED",
                        f"Shadow Hub exited early ({proc.returncode})",
                        log_tail=_read_log_tail(logs_dir / "c1_hub.log"),
                    )
                try:
                    st = _hub_rpc_call(hub_state, "hub_status", timeout=2.0)
                    if st.get("pid") == proc.pid:
                        break
                except CanaryError:
                    time.sleep(0.15)
            else:
                proc.terminate()
                raise CanaryError("C1_HUB_START_FAILED", "Shadow Hub did not become ready before timeout")
            ident = query_process_identity_exact(proc.pid)
            if ident is None:
                raise CanaryError("PROCESS_IDENTITY_UNAVAILABLE", "Could not query shadow Hub kernel identity")
            lease = write_process_lease(
                root,
                role="c1_hub",
                pid=proc.pid,
                create_time_filetime=ident["create_time_filetime"],
                executable_path=ident["executable_path"],
                entrypoint_path=str(hub_entry),
                port=hub_port,
                release_id=c1_cfg["release_id"],
                owner_scope_id=owner["owner_scope_id"],
                receipt_store=store,
                run_id=run_id,
            )
            _detach_popen(proc)
            started["c1_hub"] = lease
            store.record_step(run_id, "c1", "start_c1_hub", "succeeded", {"pid": proc.pid, "port": hub_port})

        if start_c1_rpc:
            if c1_cfg is None:
                raise CanaryError("C1_NOT_STAGED", "C1 shadow release must be staged before starting RPC")
            rel_dir = root / "releases" / "c1" / c1_cfg["release_id"]
            _verify_c1_release_dir_hashes(rel_dir)
            bridge_dir = _c1_bridge_dir(rel_dir)
            rpc_entry = bridge_dir / "ff_win_v3_main.py"
            if not rpc_entry.is_file():
                raise CanaryError("C1_RPC_ENTRY_MISSING", "ff_win_v3_main.py missing in C1 release")
            py_exe = _c1_python_exe(rel_dir)
            rpc_port = int(c1_cfg["rpc_port"])
            env = {**os.environ, "FF_BRIDGE_ROOT": c1_runtime_env, "FF_HUB_STATE": c1_hub_env}
            proc = _spawn_shadow_process(
                [py_exe, str(rpc_entry), "serve", "--host", "127.0.0.1", "--port", str(rpc_port)],
                cwd=bridge_dir,
                env=env,
                log_path=logs_dir / "c1_rpc.log",
            )
            secret_file = root / "state" / "c1" / "runtime" / "bridge-v3" / "secret"
            deadline = time.monotonic() + startup_timeout
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise CanaryError(
                        "C1_RPC_START_FAILED",
                        f"Shadow Bridge RPC exited early ({proc.returncode})",
                        log_tail=_read_log_tail(logs_dir / "c1_rpc.log"),
                    )
                if secret_file.is_file():
                    try:
                        reply = _bridge_rpc_call(rpc_port, secret_file.read_text(encoding="ascii").strip(), "ping", {}, timeout=2.0)
                        if reply.get("ok"):
                            break
                    except Exception:
                        pass
                time.sleep(0.15)
            else:
                proc.terminate()
                raise CanaryError("C1_RPC_START_FAILED", "Shadow Bridge RPC did not become ready before timeout")
            ident = query_process_identity_exact(proc.pid)
            if ident is None:
                raise CanaryError("PROCESS_IDENTITY_UNAVAILABLE", "Could not query shadow RPC kernel identity")
            lease = write_process_lease(
                root,
                role="c1_rpc",
                pid=proc.pid,
                create_time_filetime=ident["create_time_filetime"],
                executable_path=ident["executable_path"],
                entrypoint_path=str(rpc_entry),
                port=rpc_port,
                release_id=c1_cfg["release_id"],
                owner_scope_id=owner["owner_scope_id"],
                receipt_store=store,
                run_id=run_id,
            )
            _detach_popen(proc)
            started["c1_rpc"] = lease
            store.record_step(run_id, "c1", "start_c1_rpc", "succeeded", {"pid": proc.pid, "port": rpc_port})

        if start_c2_gateway:
            if c2_cfg is None:
                raise CanaryError("C2_NOT_STAGED", "C2 shadow release must be staged before starting Gateway")
            c2_slot = root / "state" / "c2" / "runtime"
            c2_rel_mf = _read_json(root / "releases" / "c2" / c2_cfg["release_id"] / "c2-stage-manifest.json")
            _verify_c2_dir_against_manifest(c2_slot, c2_rel_mf)
            gw_entry = c2_slot / "server.py"
            gw_port = int(c2_cfg["gateway_port"])
            env = {
                **os.environ,
                "GEMINI_GATEWAY_PORT": str(gw_port),
                "FF_BRIDGE_ROOT": c1_runtime_env,
                "FF_HUB_STATE": c1_hub_env,
            }
            if c1_cfg:
                env["FF_WIN_RPC_PORT"] = str(int(c1_cfg["rpc_port"]))
            proc = _spawn_shadow_process(
                [sys.executable, str(gw_entry)],
                cwd=c2_slot,
                env=env,
                log_path=logs_dir / "c2_gateway.log",
            )
            deadline = time.monotonic() + startup_timeout
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise CanaryError(
                        "C2_GATEWAY_START_FAILED",
                        f"Shadow C2 Gateway exited early ({proc.returncode})",
                        log_tail=_read_log_tail(logs_dir / "c2_gateway.log"),
                    )
                code, _ = _http_get_json(gw_port, "/health", timeout=2.0)
                if code == 200:
                    break
                time.sleep(0.15)
            else:
                proc.terminate()
                raise CanaryError("C2_GATEWAY_START_FAILED", "Shadow C2 Gateway did not become ready before timeout")
            ident = query_process_identity_exact(proc.pid)
            if ident is None:
                raise CanaryError("PROCESS_IDENTITY_UNAVAILABLE", "Could not query C2 Gateway kernel identity")
            lease = write_process_lease(
                root,
                role="c2_gateway",
                pid=proc.pid,
                create_time_filetime=ident["create_time_filetime"],
                executable_path=ident["executable_path"],
                entrypoint_path=str(gw_entry),
                port=gw_port,
                release_id=c2_cfg["release_id"],
                owner_scope_id=owner["owner_scope_id"],
                receipt_store=store,
                run_id=run_id,
            )
            _detach_popen(proc)
            started["c2_gateway"] = lease
            store.record_step(run_id, "c2", "start_c2_gateway", "succeeded", {"pid": proc.pid, "port": gw_port})

        if start_c2_unified:
            if c2_cfg is None:
                raise CanaryError("C2_NOT_STAGED", "C2 shadow release must be staged before starting Unified API")
            c2_slot = root / "state" / "c2" / "runtime"
            uni_entry = c2_slot / "unified_api.py"
            uni_port = int(c2_cfg["unified_port"])
            gw_port = int(c2_cfg["gateway_port"])
            omni_port = int(c2_cfg.get("omni_port", DEFAULT_C2_OMNI_PORT))
            env = {
                **os.environ,
                "UNIFIED_API_PORT": str(uni_port),
                "UNIFIED_GATEWAY_PORT": str(gw_port),
                "UNIFIED_OMNI_PORT": str(omni_port),
                "UNIFIED_API_KEY_FILE": str(c2_slot / "gateway.key"),
            }
            proc = _spawn_shadow_process(
                [sys.executable, str(uni_entry)],
                cwd=c2_slot,
                env=env,
                log_path=logs_dir / "c2_unified.log",
            )
            deadline = time.monotonic() + startup_timeout
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise CanaryError(
                        "C2_UNIFIED_START_FAILED",
                        f"Shadow C2 Unified API exited early ({proc.returncode})",
                        log_tail=_read_log_tail(logs_dir / "c2_unified.log"),
                    )
                code, _ = _http_get_json(uni_port, "/health", timeout=2.0)
                if code == 200:
                    break
                time.sleep(0.15)
            else:
                proc.terminate()
                raise CanaryError("C2_UNIFIED_START_FAILED", "Shadow C2 Unified API did not become ready before timeout")
            ident = query_process_identity_exact(proc.pid)
            if ident is None:
                raise CanaryError("PROCESS_IDENTITY_UNAVAILABLE", "Could not query C2 Unified API kernel identity")
            lease = write_process_lease(
                root,
                role="c2_unified",
                pid=proc.pid,
                create_time_filetime=ident["create_time_filetime"],
                executable_path=ident["executable_path"],
                entrypoint_path=str(uni_entry),
                port=uni_port,
                release_id=c2_cfg["release_id"],
                owner_scope_id=owner["owner_scope_id"],
                receipt_store=store,
                run_id=run_id,
            )
            _detach_popen(proc)
            started["c2_unified"] = lease
            store.record_step(run_id, "c2", "start_c2_unified", "succeeded", {"pid": proc.pid, "port": uni_port})

        summary = {"ok": True, "run_id": run_id, "services": started}
        receipt = store.finish_run(run_id, "succeeded", summary={"services": sorted(started.keys())})
        summary["receipt"] = receipt
        return summary
    except CanaryError as exc:
        store.finish_run(run_id, "failed", error_code=exc.code, summary=exc.to_dict())
        raise
    except Exception as exc:
        store.finish_run(run_id, "failed", error_code=type(exc).__name__)
        raise


def _probe_hub_entry_v1(hub_state_dir: Path, hub_port: int, release_dir: Path) -> dict[str, Any]:
    """Authenticated /agent/v1 probe (capabilities + route_plan) with clean grant revoke."""
    bridge_dir = _c1_bridge_dir(release_dir)
    if str(bridge_dir) not in sys.path:
        sys.path.insert(0, str(bridge_dir))
    from ff_agent_entry import ENTRY_PATH, EntryAuthority  # noqa: E402

    auth = EntryAuthority(hub_state_dir)
    task_id = "canary-health-" + uuid.uuid4().hex[:12]
    grant, token = auth.issue(
        client_id="canary-health",
        agent_id="canary-health",
        task_id=task_id,
        scopes=["locks"],
        apps=[],
        ttl=120,
    )
    try:
        def post_entry(op: str, args: dict[str, Any]) -> dict[str, Any]:
            req = urllib.request.Request(
                f"http://127.0.0.1:{hub_port}{ENTRY_PATH}",
                data=json.dumps({"op": op, "args": args}).encode("utf-8"),
                headers={
                    "Authorization": "Bearer " + token,
                    "Content-Type": "application/json",
                    "Host": f"127.0.0.1:{hub_port}",
                },
                method="POST",
            )
            with _loopback_opener().open(req, timeout=10) as resp:
                return json.loads(resp.read())

        caps = post_entry("capabilities", {})
        route = post_entry("route_plan", {"goal": "canary_health_probe"})
        caps_ok = bool(caps.get("ok") and (caps.get("result") or {}).get("schema") == "ff-agent-entry-v1")
        route_ok = bool(route.get("ok"))
        return {
            "ok": caps_ok and route_ok,
            "grant_id": grant["grant_id"],
            "capabilities_ok": caps_ok,
            "route_plan_ok": route_ok,
        }
    finally:
        auth.revoke(grant["grant_id"])


def verify_shadow_health(
    shadow_root: Path,
    *,
    check_c1_rpc: bool = False,
    check_c1_hub: bool = True,
    check_c2_gateway: bool = True,
    check_c2_unified: bool = True,
    consecutive_passes: int = 2,
    require_upstream_omniroute: bool = False,
    request_key: str | None = None,
) -> dict[str, Any]:
    """Run strict, honest health contracts across staged C1 and C2 shadow components."""
    if type(consecutive_passes) is not int or not (1 <= consecutive_passes <= 10):
        raise CanaryError("HEALTH_CONTRACT_INVALID", "consecutive_passes must be between 1 and 10")
    root = validate_shadow_root(shadow_root)
    ensure_shadow_owner(root, create=False)
    store = CanaryReceiptStore(root / "state" / "canary_receipts.sqlite3")
    run_id, cached = store.begin_run(
        "health_check",
        "shadow",
        request_key=request_key,
        request_payload={
            "shadow_root": str(root),
            "check_c1_rpc": check_c1_rpc,
            "check_c1_hub": check_c1_hub,
            "check_c2_gateway": check_c2_gateway,
            "check_c2_unified": check_c2_unified,
            "consecutive_passes": consecutive_passes,
        },
    )
    if cached is not None:
        return {"ok": cached["status"] == "succeeded", **cached}

    checks: dict[str, Any] = {}
    upstream_omniroute_ok = False
    try:
        c1_active_path = root / "state" / "c1" / "active.json"
        c2_active_path = root / "state" / "c2" / "active.json"
        c1_cfg = _read_json(c1_active_path) if c1_active_path.is_file() else None
        c2_cfg = _read_json(c2_active_path) if c2_active_path.is_file() else None

        if c1_cfg is not None:
            rel_dir = root / "releases" / "c1" / c1_cfg["release_id"]
            _verify_c1_release_dir_hashes(rel_dir)
            checks["c1_disk"] = {"ok": True, "release_id": c1_cfg["release_id"], "source_commit": c1_cfg["source_commit"]}

            if check_c1_hub:
                lease_v = verify_process_lease(root, "c1_hub", require_alive=True, check_cmdline=True)
                hub_state = root / "state" / "c1" / "hub"
                hub_port = int(c1_cfg["hub_port"])
                passes = 0
                last_status: dict[str, Any] = {}
                for _ in range(consecutive_passes):
                    st = _hub_rpc_call(hub_state, "hub_status", timeout=4.0)
                    if st.get("pid") != lease_v["pid"]:
                        raise CanaryError("HEALTH_CONTRACT_FAILED", "Hub status PID disagrees with verified lease")
                    last_status = st
                    passes += 1
                    if passes < consecutive_passes:
                        time.sleep(0.15)
                entry_probe = _probe_hub_entry_v1(hub_state, hub_port, rel_dir)
                checks["c1_hub"] = {
                    "ok": passes == consecutive_passes and entry_probe["ok"],
                    "consecutive_passes": passes,
                    "required_passes": consecutive_passes,
                    "pid": lease_v["pid"],
                    "create_time_filetime": lease_v["create_time_filetime"],
                    "identity_verified": True,
                    "active_sessions": len(last_status.get("sessions") or []),
                    "entry_v1_authenticated_ok": entry_probe["ok"],
                    "entry_probe": entry_probe,
                }
                store.record_step(run_id, "health", "c1_hub", "succeeded" if checks["c1_hub"]["ok"] else "failed", checks["c1_hub"])

            if check_c1_rpc:
                lease_v = verify_process_lease(root, "c1_rpc", require_alive=True, check_cmdline=True)
                rpc_port = int(c1_cfg["rpc_port"])
                secret = (root / "state" / "c1" / "runtime" / "bridge-v3" / "secret").read_text(encoding="ascii").strip()
                expected_agent_sha = sha256_file(_c1_bridge_dir(rel_dir) / "ff_win_v3_agent.py")
                passes = 0
                for _ in range(consecutive_passes):
                    ping = _bridge_rpc_call(rpc_port, secret, "ping", {}, timeout=4.0)
                    caps = _bridge_rpc_call(rpc_port, secret, "capabilities", {}, timeout=4.0)
                    agent_sha = ((caps.get("result") or {}).get("agent_sha256") or "").lower()
                    if ping.get("ok") and caps.get("ok") and hmac.compare_digest(agent_sha, expected_agent_sha):
                        passes += 1
                    else:
                        break
                    if passes < consecutive_passes:
                        time.sleep(0.15)
                checks["c1_rpc"] = {
                    "ok": passes == consecutive_passes,
                    "consecutive_passes": passes,
                    "required_passes": consecutive_passes,
                    "pid": lease_v["pid"],
                    "create_time_filetime": lease_v["create_time_filetime"],
                    "identity_verified": True,
                    "expected_agent_sha256": expected_agent_sha,
                }
                store.record_step(run_id, "health", "c1_rpc", "succeeded" if checks["c1_rpc"]["ok"] else "failed", checks["c1_rpc"])

        if c2_cfg is not None:
            c2_slot = root / "state" / "c2" / "runtime"
            c2_rel_mf = _read_json(root / "releases" / "c2" / c2_cfg["release_id"] / "c2-stage-manifest.json")
            _verify_c2_dir_against_manifest(c2_slot, c2_rel_mf)
            c2_db_status = inspect_c2_gateway_active_jobs(c2_slot / "gateway.db")
            checks["c2_disk"] = {
                "ok": True,
                "release_id": c2_cfg["release_id"],
                "source_commit": c2_cfg["source_commit"],
                "manifest_sha256": c2_cfg["manifest_sha256"],
                "db_status": c2_db_status,
            }

            if check_c2_gateway:
                lease_v = verify_process_lease(root, "c2_gateway", require_alive=True, check_cmdline=True)
                gw_port = int(c2_cfg["gateway_port"])
                passes = 0
                last_body: dict[str, Any] | None = None
                for _ in range(consecutive_passes):
                    code, body = _http_get_json(gw_port, "/health", timeout=3.0)
                    if code == 200 and isinstance(body, dict) and (body.get("ok") is True or body.get("status") == "ok"):
                        passes += 1
                        last_body = body
                    else:
                        break
                    if passes < consecutive_passes:
                        time.sleep(0.15)
                checks["c2_gateway"] = {
                    "ok": passes == consecutive_passes,
                    "consecutive_passes": passes,
                    "required_passes": consecutive_passes,
                    "pid": lease_v["pid"],
                    "create_time_filetime": lease_v["create_time_filetime"],
                    "identity_verified": True,
                    "port": gw_port,
                    "active_jobs": c2_db_status["active_jobs"],
                    "health_payload": last_body,
                }
                store.record_step(run_id, "health", "c2_gateway", "succeeded" if checks["c2_gateway"]["ok"] else "failed", checks["c2_gateway"])

            if check_c2_unified:
                lease_v = verify_process_lease(root, "c2_unified", require_alive=True, check_cmdline=True)
                uni_port = int(c2_cfg["unified_port"])
                gw_port = int(c2_cfg["gateway_port"])
                shadow_key_file = c2_slot / "gateway.key"
                auth_headers: dict[str, str] = {}
                if shadow_key_file.is_file():
                    shadow_key = shadow_key_file.read_text(encoding="ascii").strip()
                    if shadow_key:
                        auth_headers["Authorization"] = "Bearer " + shadow_key
                passes = 0
                observed_gw_port: int | None = None
                ready_http = 0
                gateway_upstream_ok = False
                for _ in range(consecutive_passes):
                    code, body = _http_get_json(uni_port, "/health", timeout=3.0)
                    r_code, r_body = _http_get_json(uni_port, "/ready", timeout=3.0, headers=auth_headers)
                    ready_http = r_code
                    observed_gw_port = body.get("gateway_port") if isinstance(body, dict) else None
                    # Support real C2 Unified API contract: {"ready": bool, "services": {"gateway": {"reachable": bool}, "omniroute": {"reachable": bool}}}
                    services_map = (r_body or {}).get("services") if isinstance(r_body, dict) else None
                    gw_section = (
                        services_map.get("gateway")
                        if isinstance(services_map, dict)
                        else ((r_body or {}).get("gateway") if isinstance(r_body, dict) else None)
                    )
                    omni_section = (
                        services_map.get("omniroute")
                        if isinstance(services_map, dict)
                        else ((r_body or {}).get("omniroute") if isinstance(r_body, dict) else None)
                    )
                    if isinstance(gw_section, dict):
                        gw_up = bool(gw_section.get("reachable") if "reachable" in gw_section else gw_section.get("ok"))
                    else:
                        gw_up = (r_code == 200)
                    if isinstance(omni_section, dict):
                        omni_up = bool(omni_section.get("reachable") if "reachable" in omni_section else omni_section.get("ok"))
                    else:
                        omni_up = (r_code == 200)
                    gateway_upstream_ok = gw_up
                    upstream_omniroute_ok = omni_up
                    if code == 200 and observed_gw_port == gw_port and r_code in (200, 503) and gw_up:
                        passes += 1
                    else:
                        break
                    if passes < consecutive_passes:
                        time.sleep(0.15)
                degraded_warnings = [] if upstream_omniroute_ok else ["UPSTREAM_OMNIROUTE_UNAVAILABLE"]
                uni_ok = (passes == consecutive_passes) and (upstream_omniroute_ok or not require_upstream_omniroute)
                checks["c2_unified"] = {
                    "ok": uni_ok,
                    "consecutive_passes": passes,
                    "required_passes": consecutive_passes,
                    "pid": lease_v["pid"],
                    "create_time_filetime": lease_v["create_time_filetime"],
                    "identity_verified": True,
                    "port": uni_port,
                    "gateway_port": observed_gw_port,
                    "ready_authenticated": bool(auth_headers),
                    "gateway_upstream_ok": gateway_upstream_ok,
                    "upstream_omniroute_ok": upstream_omniroute_ok,
                    "ready_http_status": ready_http,
                    "degraded_warnings": degraded_warnings,
                }
                store.record_step(run_id, "health", "c2_unified", "succeeded" if uni_ok else "failed", checks["c2_unified"])

        shadow_health_ok = bool(checks) and all(bool(item.get("ok")) for item in checks.values())
        remaining_gates = [
            "fresh_live_process_and_session_inventory",
            "live_authenticated_a1_a7_and_omniroute_acceptance",
            "explicit_owner_approval_and_manual_cutover_execution",
        ]
        if not upstream_omniroute_ok:
            remaining_gates.insert(0, "upstream_omniroute_health_not_verified_in_isolated_shadow")
        report = {
            "schema": SCHEMA_HEALTH,
            "ok": shadow_health_ok,
            "shadow_health_ok": shadow_health_ok,
            "upstream_omniroute_ok": upstream_omniroute_ok,
            "live_production_cutover_executed": False,
            "checks": checks,
            "remaining_release_gates": remaining_gates,
            "run_id": run_id,
        }
        receipt = store.finish_run(
            run_id,
            "succeeded" if shadow_health_ok else "failed",
            error_code=None if shadow_health_ok else "HEALTH_CONTRACT_FAILED",
            summary={
                "shadow_health_ok": shadow_health_ok,
                "upstream_omniroute_ok": upstream_omniroute_ok,
                "checked": sorted(checks.keys()),
            },
        )
        report["receipt"] = receipt
        return report
    except CanaryError as exc:
        store.finish_run(run_id, "failed", error_code=exc.code, summary=exc.to_dict())
        raise
    except Exception as exc:
        store.finish_run(run_id, "failed", error_code=type(exc).__name__)
        raise


def stop_shadow_services(
    shadow_root: Path,
    *,
    ignore_missing: bool = True,
    receipt_store: CanaryReceiptStore | None = None,
    run_id: str | None = None,
) -> dict[str, Any]:
    """Stop all owned shadow services in safe order after verifying zero active sessions/jobs."""
    root = validate_shadow_root(shadow_root)
    ensure_shadow_owner(root, create=False)
    store = receipt_store or CanaryReceiptStore(root / "state" / "canary_receipts.sqlite3")

    c2_db = root / "state" / "c2" / "runtime" / "gateway.db"
    hub_state = root / "state" / "c1" / "hub"

    # Pre-check ALL active sessions/jobs BEFORE stopping ANY process so a busy service
    # never gets partially torn down.
    roles_order = ("c2_unified", "c2_gateway", "c1_rpc", "c1_hub")
    active_roles: list[str] = []
    for role in roles_order:
        lp = _lease_path(root, role)
        if not lp.is_file():
            if not ignore_missing:
                raise CanaryError("PROCESS_LEASE_MISSING", f"Missing lease for {role}", role=role)
            continue
        v = verify_process_lease(root, role, require_alive=False, check_cmdline=True)
        if v["alive"]:
            active_roles.append(role)

    if any(r in active_roles for r in ("c1_hub", "c1_rpc")):
        hub_idle = inspect_c1_hub_active_sessions(hub_state, require_rpc_if_running="c1_hub" in active_roles)
        if not hub_idle["idle_verified"]:
            raise CanaryError(
                str(hub_idle.get("reason") or "ACTIVE_SESSIONS_PRESENT"),
                "Refusing to stop shadow C1 while active sessions exist",
                idle_check=hub_idle,
            )
    if any(r in active_roles for r in ("c2_gateway", "c2_unified")):
        c2_idle = inspect_c2_gateway_active_jobs(c2_db)
        if not c2_idle["idle_verified"]:
            raise CanaryError(
                str(c2_idle.get("reason") or "ACTIVE_C2_JOBS_PRESENT"),
                "Refusing to stop shadow C2 while active jobs exist",
                idle_check=c2_idle,
            )

    stopped: dict[str, Any] = {}
    for role in roles_order:
        lp = _lease_path(root, role)
        if not lp.is_file():
            continue
        if role == "c1_hub":
            res = stop_leased_process(
                root,
                role,
                idle_checker=lambda: inspect_c1_hub_active_sessions(hub_state, require_rpc_if_running=True),
                graceful_stop=lambda: _hub_rpc_call(hub_state, "hub_shutdown_idle", timeout=5.0),
                receipt_store=store,
                run_id=run_id,
            )
        elif role == "c1_rpc":
            res = stop_leased_process(
                root,
                role,
                idle_checker=lambda: inspect_c1_rpc_active_sessions(root),
                receipt_store=store,
                run_id=run_id,
            )
        else:
            res = stop_leased_process(
                root,
                role,
                idle_checker=lambda: inspect_c2_gateway_active_jobs(c2_db),
                receipt_store=store,
                run_id=run_id,
            )
        stopped[role] = res
    return {"ok": True, "stopped": stopped}


# ---------------------------------------------------------------------------
# Combined Stage, Rollback, and Owner Cutover Gate Orchestrators
# ---------------------------------------------------------------------------

def run_shadow_stage(
    *,
    shadow_root: Path,
    c1_zip: Path,
    c1_zip_sha256: str,
    c1_expected_commit: str | None = None,
    c2_repo: Path | None = None,
    c2_commit: str | None = None,
    c2_zip: Path | None = None,
    c2_zip_sha256: str | None = None,
    c2_source_db: Path | None = None,
    c1_rpc_port: int = DEFAULT_SHADOW_PORTS["c1_rpc_port"],
    c1_hub_port: int = DEFAULT_SHADOW_PORTS["c1_hub_port"],
    c2_gateway_port: int = DEFAULT_SHADOW_PORTS["c2_gateway_port"],
    c2_unified_port: int = DEFAULT_SHADOW_PORTS["c2_unified_port"],
    c2_omni_port: int = DEFAULT_C2_OMNI_PORT,
    skip_c2: bool = False,
    run_full_installer: bool = False,
    require_clean_c2_head: bool = True,
    request_key: str | None = None,
) -> dict[str, Any]:
    """Orchestrate pinned C1 + C2 shadow staging with durable SQLite receipts."""
    root = validate_shadow_root(shadow_root)
    ports = {"c1_rpc_port": c1_rpc_port, "c1_hub_port": c1_hub_port}
    if not skip_c2:
        ports.update({"c2_gateway_port": c2_gateway_port, "c2_unified_port": c2_unified_port})
    validate_shadow_ports(ports)
    pinned_c1_sha = validate_sha256(c1_zip_sha256, "c1_zip_sha256")
    pinned_c2_commit = validate_git_commit(c2_commit, "c2_commit") if (not skip_c2 and c2_repo is not None) else (
        validate_git_commit(c2_commit, "c2_commit") if (not skip_c2 and c2_commit is not None) else None
    )

    ensure_shadow_owner(root, create=True)
    store = CanaryReceiptStore(root / "state" / "canary_receipts.sqlite3")
    req_payload = {
        "shadow_root": str(root),
        "c1_zip_sha256": pinned_c1_sha,
        "c1_expected_commit": c1_expected_commit,
        "c2_commit": pinned_c2_commit,
        "c2_zip_sha256": c2_zip_sha256,
        "skip_c2": skip_c2,
        "ports": ports,
    }
    run_id, cached = store.begin_run(
        "stage_shadow",
        "shadow",
        request_key=request_key,
        request_payload=req_payload,
        c1_zip_sha256=pinned_c1_sha,
        c1_commit=c1_expected_commit,
        c2_commit=pinned_c2_commit,
    )
    if cached is not None:
        return {"ok": cached["status"] == "succeeded", **cached}

    try:
        c1_res = stage_c1_shadow(
            root,
            c1_zip=c1_zip,
            c1_zip_sha256=pinned_c1_sha,
            c1_expected_commit=c1_expected_commit,
            rpc_port=c1_rpc_port,
            hub_port=c1_hub_port,
            run_full_installer=run_full_installer,
            receipt_store=store,
            run_id=run_id,
        )
        store.record_step(run_id, "c1", "stage_c1", "succeeded", {"release_id": c1_res["release_id"]})

        c2_res: dict[str, Any] | None = None
        if not skip_c2:
            c2_res = stage_c2_shadow(
                root,
                c2_repo=c2_repo,
                c2_commit=c2_commit,
                c2_zip=c2_zip,
                c2_zip_sha256=c2_zip_sha256,
                c2_source_db=c2_source_db,
                gateway_port=c2_gateway_port,
                unified_port=c2_unified_port,
                omni_port=c2_omni_port,
                require_clean_head=require_clean_c2_head,
                receipt_store=store,
                run_id=run_id,
            )
            store.record_step(run_id, "c2", "stage_c2", "succeeded", {"release_id": c2_res["release_id"]})

        summary = {
            "ok": True,
            "run_id": run_id,
            "deduplicated": False,
            "shadow_root": str(root),
            "c1": c1_res,
            "c2": c2_res,
            "live_production_mutated": False,
        }
        receipt = store.finish_run(
            run_id,
            "succeeded",
            summary={
                "c1_release_id": c1_res["release_id"],
                "c1_commit": c1_res["source_commit"],
                "c2_release_id": c2_res["release_id"] if c2_res else None,
                "c2_commit": c2_res["source_commit"] if c2_res else None,
            },
        )
        summary["receipt"] = receipt
        return summary
    except CanaryError as exc:
        store.finish_run(run_id, "failed", error_code=exc.code, summary=exc.to_dict())
        raise
    except Exception as exc:
        store.finish_run(run_id, "failed", error_code=type(exc).__name__)
        raise


def rollback_canary(
    shadow_root: Path,
    *,
    confirm_shadow_rollback: bool = False,
    c1_target_release_id: str | None = None,
    c1_baseline_zip: Path | None = None,
    c1_baseline_zip_sha256: str | None = None,
    c2_target_release_id: str | None = None,
    restore_c2_db_backup: Path | None = None,
    restore_c2_db_backup_sha256: str | None = None,
    private_runtime_home: Path | None = None,
    request_key: str | None = None,
) -> dict[str, Any]:
    """Safe idle-verified, lease-verified, receipt-preserving rollback for C1 + C2 shadow state.

    Never force-kills active sessions; never runs `git checkout` on live production;
    never deletes or truncates SQLite receipts (`canary_receipts.sqlite3`,
    `entry-grants.sqlite3`, `hub.db`).
    """
    root = validate_shadow_root(shadow_root)
    ensure_shadow_owner(root, create=False)
    store = CanaryReceiptStore(root / "state" / "canary_receipts.sqlite3")

    if not confirm_shadow_rollback:
        c1_active = _read_json(root / "state" / "c1" / "active.json") if (root / "state" / "c1" / "active.json").is_file() else None
        c2_active = _read_json(root / "state" / "c2" / "active.json") if (root / "state" / "c2" / "active.json").is_file() else None
        return {
            "schema": SCHEMA_ROLLBACK,
            "mode": "DRY_RUN_ONLY",
            "executed": False,
            "shadow_root": str(root),
            "c1_current_release": c1_active.get("release_id") if c1_active else None,
            "c1_rollback_target": c1_target_release_id or (c1_active.get("previous_release_id") if c1_active else None),
            "c2_current_release": c2_active.get("release_id") if c2_active else None,
            "c2_rollback_target": c2_target_release_id or (c2_active.get("previous_release_id") if c2_active else None),
            "c2_db_restore_requested": restore_c2_db_backup is not None,
            "live_production_mutated": False,
        }

    # Validate pinned baseline ZIP / DB backup SHA-256 upfront BEFORE stopping anything!
    if c1_baseline_zip is not None:
        pinned_base = validate_sha256(c1_baseline_zip_sha256, "c1_baseline_zip_sha256")
        assert_no_reparse(Path(c1_baseline_zip), must_file=True)
        if not hmac.compare_digest(sha256_file(Path(c1_baseline_zip)), pinned_base):
            raise CanaryError("PINNED_SHA256_MISMATCH", "C1 baseline ZIP SHA-256 mismatch")
    if restore_c2_db_backup is not None:
        pinned_bkp = validate_sha256(restore_c2_db_backup_sha256, "restore_c2_db_backup_sha256")
        assert_no_reparse(Path(restore_c2_db_backup), must_file=True)
        if not hmac.compare_digest(sha256_file(Path(restore_c2_db_backup)), pinned_bkp):
            raise CanaryError("SQLITE_BACKUP_HASH_MISMATCH", "C2 DB backup SHA-256 mismatch")

    run_id, cached = store.begin_run(
        "rollback",
        "shadow",
        request_key=request_key,
        request_payload={
            "shadow_root": str(root),
            "c1_target_release_id": c1_target_release_id,
            "c2_target_release_id": c2_target_release_id,
            "restore_c2_db_backup_sha256": restore_c2_db_backup_sha256,
        },
    )
    if cached is not None:
        return {"ok": cached["status"] == "succeeded", **cached}

    try:
        # 1) Mandatory active-session / active-job guard & verified idle stop!
        stop_res = stop_shadow_services(root, ignore_missing=True, receipt_store=store, run_id=run_id)
        store.record_step(run_id, "lease", "stop_verified_idle_shadow", "succeeded", stop_res["stopped"])

        # 2) Capture pre-rollback SQLite Online Backup API snapshots (preserve forensic state!).
        pre_c1_backups = _backup_existing_c1_state(root, run_id, store)
        c2_slot = root / "state" / "c2" / "runtime"
        pre_c2_backup = None
        if (c2_slot / "gateway.db").is_file():
            pre_c2_backup = sqlite_online_backup(
                c2_slot / "gateway.db",
                root / "backups" / run_id / "c2_gateway_pre_rollback.db",
            )
            store.record_backup(run_id, "c2", "gateway_pre_rollback.db", pre_c2_backup)

        # 3) Optional PrivateRuntimeHome rollback (uses C1 idle-verified private_desktop_runtime.py).
        private_rt_result = None
        if private_runtime_home is not None:
            pr_home = validate_shadow_root(Path(private_runtime_home))
            rt_tool = ROOT / "tools" / "private_desktop_runtime.py"
            cp = subprocess.run(
                [sys.executable, "-X", "utf8", str(rt_tool), "--home", str(pr_home), "rollback"],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if cp.returncode != 0:
                raise CanaryError("PRIVATE_RUNTIME_ROLLBACK_FAILED", (cp.stdout or cp.stderr or "")[-400:])
            private_rt_result = json.loads(cp.stdout)

        # 4) Roll back C1 shadow release pointer to immutable previous/target release.
        c1_result = None
        c1_active_file = root / "state" / "c1" / "active.json"
        if c1_active_file.is_file():
            c1_active = _read_json(c1_active_file)
            target_c1 = c1_target_release_id or c1_active.get("previous_release_id")
            if not target_c1:
                raise CanaryError("NO_PREVIOUS_RELEASE", "No previous C1 shadow release recorded")
            target_dir = root / "releases" / "c1" / target_c1
            if not target_dir.is_dir():
                raise CanaryError("TARGET_RELEASE_NOT_FOUND", f"C1 target release missing: {target_c1}")
            target_mf = _verify_c1_release_dir_hashes(target_dir)
            new_c1_active = {
                **c1_active,
                "release_id": target_c1,
                "previous_release_id": c1_active.get("release_id"),
                "source_commit": target_mf["source_commit"],
                "zip_sha256": target_mf["c1_zip_sha256"],
                "updated_at": time.time(),
            }
            _atomic_write_json(c1_active_file, new_c1_active)
            c1_result = {
                "restored_release_id": target_c1,
                "rolled_back_from": c1_active.get("release_id"),
                "source_commit": target_mf["source_commit"],
                "zip_sha256": target_mf["c1_zip_sha256"],
                "hashes_verified": True,
                "pre_rollback_backups": pre_c1_backups,
            }
            store.record_step(run_id, "c1", "rollback_c1_release", "succeeded", {"restored_release_id": target_c1})

        # 5) Roll back C2 shadow runtime slot from immutable previous/target release (NEVER git checkout!).
        c2_result = None
        c2_active_file = root / "state" / "c2" / "active.json"
        if c2_active_file.is_file():
            c2_active = _read_json(c2_active_file)
            target_c2 = c2_target_release_id or c2_active.get("previous_release_id")
            if not target_c2:
                raise CanaryError("NO_PREVIOUS_RELEASE", "No previous C2 shadow release recorded")
            target_dir = root / "releases" / "c2" / target_c2
            if not target_dir.is_dir():
                raise CanaryError("TARGET_RELEASE_NOT_FOUND", f"C2 target release missing: {target_c2}")
            current_mf_path = root / "releases" / "c2" / c2_active["release_id"] / "c2-stage-manifest.json"
            current_mf = _read_json(current_mf_path) if current_mf_path.is_file() else None
            target_mf = _read_json(target_dir / "c2-stage-manifest.json")
            _sync_c2_runtime_slot(target_dir, c2_slot, previous_manifest=current_mf)

            db_restore_info = None
            if restore_c2_db_backup is not None:
                db_restore_info = sqlite_restore_from_backup(
                    Path(restore_c2_db_backup),
                    str(restore_c2_db_backup_sha256),
                    c2_slot / "gateway.db",
                )
                store.record_step(run_id, "c2", "restore_c2_db_backup", "succeeded", db_restore_info)

            new_c2_active = {
                **c2_active,
                "release_id": target_c2,
                "previous_release_id": c2_active.get("release_id"),
                "source_commit": target_mf["source_commit"],
                "manifest_sha256": target_mf["manifest_sha256"],
                "updated_at": time.time(),
            }
            _atomic_write_json(c2_active_file, new_c2_active)
            c2_result = {
                "restored_release_id": target_c2,
                "rolled_back_from": c2_active.get("release_id"),
                "source_commit": target_mf["source_commit"],
                "manifest_sha256": target_mf["manifest_sha256"],
                "hashes_verified": True,
                "db_restored": db_restore_info is not None,
                "db_restore_info": db_restore_info,
                "pre_rollback_backup": pre_c2_backup,
                "git_checkout_used": False,
            }
            store.record_step(run_id, "c2", "rollback_c2_release", "succeeded", {"restored_release_id": target_c2})

        # 6) Verify SQLite integrity of preserved hub/entry/gateway DBs and receipt hash chain.
        preserved_integrity: dict[str, bool] = {}
        for label, dbp in (
            ("c1_hub_db", root / "state" / "c1" / "hub" / "hub.db"),
            ("c1_entry_grants_db", root / "state" / "c1" / "hub" / "entry-grants.sqlite3"),
            ("c2_gateway_db", c2_slot / "gateway.db"),
        ):
            if dbp.is_file():
                with closing(sqlite3.connect(dbp.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as conn:
                    preserved_integrity[label] = ([tuple(r) for r in conn.execute("PRAGMA integrity_check").fetchall()] == [("ok",)])
                    if not preserved_integrity[label]:
                        raise CanaryError("SQLITE_BACKUP_INTEGRITY_FAILED", f"Preserved DB failed integrity check: {label}")

        receipt = store.finish_run(
            run_id,
            "rolled_back",
            summary={
                "c1_restored": c1_result["restored_release_id"] if c1_result else None,
                "c2_restored": c2_result["restored_release_id"] if c2_result else None,
                "preserved_integrity": preserved_integrity,
            },
        )
        chain = store.verify_receipt_chain()
        return {
            "schema": SCHEMA_ROLLBACK,
            "ok": True,
            "executed": True,
            "run_id": run_id,
            "c1": c1_result,
            "c2": c2_result,
            "private_runtime": private_rt_result,
            "preserved_sqlite_integrity": preserved_integrity,
            "receipt_chain_ok": chain["ok"],
            "receipt": receipt,
            "live_production_mutated": False,
        }
    except CanaryError as exc:
        store.finish_run(run_id, "denied" if "ACTIVE_" in exc.code else "failed", error_code=exc.code, summary=exc.to_dict())
        raise
    except Exception as exc:
        store.finish_run(run_id, "failed", error_code=type(exc).__name__)
        raise


def prepare_cutover_readiness(shadow_root: Path, output_path: Path) -> dict[str, Any]:
    """Emit a verifiable readiness manifest from verified shadow state & receipt chain."""
    root = validate_shadow_root(shadow_root)
    ensure_shadow_owner(root, create=False)
    store = CanaryReceiptStore(root / "state" / "canary_receipts.sqlite3")
    chain = store.verify_receipt_chain()
    c1_active = _read_json(root / "state" / "c1" / "active.json")
    c2_active = _read_json(root / "state" / "c2" / "active.json") if (root / "state" / "c2" / "active.json").is_file() else None
    with closing(store._connect(readonly=True)) as conn:
        last_health = conn.execute(
            "SELECT * FROM canary_runs WHERE action='health_check' ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
    health_summary = json.loads(last_health["summary_json"]) if (last_health and last_health["summary_json"]) else {}
    readiness = {
        "schema": SCHEMA_READINESS,
        "generated_at": time.time(),
        "c1_release_id": c1_active["release_id"],
        "c1_commit": c1_active["source_commit"],
        "c1_zip_sha256": c1_active["zip_sha256"],
        "c2_release_id": c2_active["release_id"] if c2_active else None,
        "c2_commit": c2_active["source_commit"] if c2_active else None,
        "c2_manifest_sha256": c2_active["manifest_sha256"] if c2_active else None,
        "shadow_health_ok": bool(health_summary.get("shadow_health_ok")),
        "upstream_omniroute_ok": bool(health_summary.get("upstream_omniroute_ok")),
        "receipt_chain_verified": chain["ok"],
        "head_receipt_hash": chain["head_receipt_hash"],
        "live_production_cutover_executed": False,
        "manual_cutover_playbook": "docs/CANARY_MANUAL_CUTOVER_PLAYBOOK_RU.md",
    }
    _atomic_write_json(Path(output_path), readiness)
    return readiness


def verify_owner_cutover_gate(
    *,
    readiness_path: Path | None,
    approval_path: Path | None,
    expected_c1_zip_sha256: str,
    expected_c2_commit: str | None = None,
) -> dict[str, Any]:
    """Fail-closed verifier for owner cutover readiness + unexpired owner approval.

    Even when valid, this gate authorizes ONLY manual playbook execution and
    never silently restarts live production services.
    """
    pinned_c1 = validate_sha256(expected_c1_zip_sha256, "expected_c1_zip_sha256")
    pinned_c2 = validate_git_commit(expected_c2_commit, "expected_c2_commit") if expected_c2_commit else None
    if readiness_path is None or approval_path is None:
        raise CanaryError(
            "OWNER_CUTOVER_READINESS_REQUIRED",
            "Production cutover requires both a verified readiness manifest and an unexpired owner approval file",
        )
    readiness = _read_json(Path(readiness_path))
    approval = _read_json(Path(approval_path))
    if (
        readiness.get("schema") != SCHEMA_READINESS
        or readiness.get("shadow_health_ok") is not True
        or readiness.get("receipt_chain_verified") is not True
    ):
        raise CanaryError("OWNER_CUTOVER_READINESS_REQUIRED", "Readiness manifest is invalid or shadow health is not passing")
    if not hmac.compare_digest(str(readiness.get("c1_zip_sha256") or "").lower(), pinned_c1):
        raise CanaryError("OWNER_APPROVAL_ARTIFACT_MISMATCH", "Readiness manifest c1_zip_sha256 mismatch")
    if pinned_c2 and str(readiness.get("c2_commit") or "").lower() != pinned_c2:
        raise CanaryError("OWNER_APPROVAL_ARTIFACT_MISMATCH", "Readiness manifest c2_commit mismatch")

    if (
        approval.get("schema") != SCHEMA_OWNER_APPROVAL
        or approval.get("approved") is not True
        or approval.get("active_sessions_drain_acknowledged") is not True
        or not isinstance(approval.get("owner_statement"), str)
        or not approval["owner_statement"].strip()
    ):
        raise CanaryError("OWNER_APPROVAL_INVALID", "Owner approval record is incomplete or not approved")
    expires = approval.get("expires_epoch")
    if not isinstance(expires, (int, float)) or float(expires) <= time.time():
        raise CanaryError("OWNER_APPROVAL_EXPIRED", "Owner approval has expired; request fresh approval")
    if not hmac.compare_digest(str(approval.get("c1_zip_sha256") or "").lower(), pinned_c1):
        raise CanaryError("OWNER_APPROVAL_ARTIFACT_MISMATCH", "Owner approval c1_zip_sha256 mismatch")
    if pinned_c2 and str(approval.get("c2_commit") or "").lower() != pinned_c2:
        raise CanaryError("OWNER_APPROVAL_ARTIFACT_MISMATCH", "Owner approval c2_commit mismatch")

    return {
        "ok": True,
        "gate_verified": True,
        "automatic_production_restart_allowed": False,
        "live_production_mutated": False,
        "next_step": "Follow docs/CANARY_MANUAL_CUTOVER_PLAYBOOK_RU.md with fresh live session inventory and maintenance lock.",
    }


# ---------------------------------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)

    plan = sub.add_parser("plan", help="Read-only dry-run validation of inputs, pins, ports, and shadow boundaries")
    for cmd in (plan,):
        cmd.add_argument("--shadow-root", type=Path, required=True)
        cmd.add_argument("--c1-zip", type=Path, required=True)
        cmd.add_argument("--c1-zip-sha256", required=True)
        cmd.add_argument("--c1-expected-commit", default=None)
        cmd.add_argument("--c2-repo", type=Path, default=None)
        cmd.add_argument("--c2-commit", default=None)
        cmd.add_argument("--c2-zip", type=Path, default=None)
        cmd.add_argument("--c2-zip-sha256", default=None)
        cmd.add_argument("--c1-rpc-port", type=int, default=DEFAULT_SHADOW_PORTS["c1_rpc_port"])
        cmd.add_argument("--c1-hub-port", type=int, default=DEFAULT_SHADOW_PORTS["c1_hub_port"])
        cmd.add_argument("--c2-gateway-port", type=int, default=DEFAULT_SHADOW_PORTS["c2_gateway_port"])
        cmd.add_argument("--c2-unified-port", type=int, default=DEFAULT_SHADOW_PORTS["c2_unified_port"])
        cmd.add_argument("--c2-omni-port", type=int, default=DEFAULT_C2_OMNI_PORT)
        cmd.add_argument("--skip-c2", action="store_true")

    stage = sub.add_parser("stage", help="Stage pinned C1 + C2 candidate releases into isolated shadow root")
    stage.add_argument("--shadow-root", type=Path, required=True)
    stage.add_argument("--c1-zip", type=Path, required=True)
    stage.add_argument("--c1-zip-sha256", required=True)
    stage.add_argument("--c1-expected-commit", default=None)
    stage.add_argument("--c2-repo", type=Path, default=None)
    stage.add_argument("--c2-commit", default=None)
    stage.add_argument("--c2-zip", type=Path, default=None)
    stage.add_argument("--c2-zip-sha256", default=None)
    stage.add_argument("--c2-source-db", type=Path, default=None)
    stage.add_argument("--c1-rpc-port", type=int, default=DEFAULT_SHADOW_PORTS["c1_rpc_port"])
    stage.add_argument("--c1-hub-port", type=int, default=DEFAULT_SHADOW_PORTS["c1_hub_port"])
    stage.add_argument("--c2-gateway-port", type=int, default=DEFAULT_SHADOW_PORTS["c2_gateway_port"])
    stage.add_argument("--c2-unified-port", type=int, default=DEFAULT_SHADOW_PORTS["c2_unified_port"])
    stage.add_argument("--c2-omni-port", type=int, default=DEFAULT_C2_OMNI_PORT)
    stage.add_argument("--skip-c2", action="store_true")
    stage.add_argument("--run-full-installer", action="store_true")
    stage.add_argument("--allow-non-head-c2-commit", action="store_true")
    stage.add_argument("--request-key", default=None)

    start = sub.add_parser("start-shadow", help="Start staged shadow services under owner-scoped process leases")
    start.add_argument("--shadow-root", type=Path, required=True)
    start.add_argument("--c1-rpc", action="store_true")
    start.add_argument("--no-c1-hub", action="store_true")
    start.add_argument("--no-c2-gateway", action="store_true")
    start.add_argument("--no-c2-unified", action="store_true")
    start.add_argument("--request-key", default=None)

    health = sub.add_parser("health", help="Verify shadow health contracts across C1 and C2")
    health.add_argument("--shadow-root", type=Path, required=True)
    health.add_argument("--c1-rpc", action="store_true")
    health.add_argument("--no-c1-hub", action="store_true")
    health.add_argument("--no-c2-gateway", action="store_true")
    health.add_argument("--no-c2-unified", action="store_true")
    health.add_argument("--consecutive-passes", type=int, default=2)
    health.add_argument("--require-upstream-omniroute", action="store_true")
    health.add_argument("--request-key", default=None)

    stop = sub.add_parser("stop-shadow", help="Gracefully stop verified idle leased shadow services")
    stop.add_argument("--shadow-root", type=Path, required=True)

    rb = sub.add_parser("rollback", help="Safe idle-verified rollback of shadow C1 + C2 preserving SQLite receipts")
    rb.add_argument("--shadow-root", type=Path, required=True)
    rb.add_argument("--confirm-shadow-rollback", action="store_true")
    rb.add_argument("--c1-target-release", default=None)
    rb.add_argument("--c1-baseline-zip", type=Path, default=None)
    rb.add_argument("--c1-baseline-zip-sha256", default=None)
    rb.add_argument("--c2-target-release", default=None)
    rb.add_argument("--restore-c2-db-backup", type=Path, default=None)
    rb.add_argument("--restore-c2-db-backup-sha256", default=None)
    rb.add_argument("--private-runtime-home", type=Path, default=None)
    rb.add_argument("--request-key", default=None)

    rcpt = sub.add_parser("verify-receipts", help="Verify SQLite receipt DB integrity and SHA-256 hash chain")
    rcpt.add_argument("--shadow-root", type=Path, required=True)
    rcpt.add_argument("--limit", type=int, default=20)

    rdy = sub.add_parser("prepare-readiness", help="Write a verified shadow readiness manifest for manual cutover")
    rdy.add_argument("--shadow-root", type=Path, required=True)
    rdy.add_argument("--output", type=Path, required=True)

    gate = sub.add_parser("verify-owner-gate", help="Verify readiness manifest + owner approval for manual cutover")
    gate.add_argument("--readiness", type=Path, default=None)
    gate.add_argument("--approval", type=Path, default=None)
    gate.add_argument("--c1-zip-sha256", required=True)
    gate.add_argument("--c2-commit", default=None)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            root = validate_shadow_root(args.shadow_root)
            ports = {"c1_rpc_port": args.c1_rpc_port, "c1_hub_port": args.c1_hub_port}
            if not args.skip_c2:
                ports.update({"c2_gateway_port": args.c2_gateway_port, "c2_unified_port": args.c2_unified_port})
            validate_shadow_ports(ports)
            pinned_sha = validate_sha256(args.c1_zip_sha256, "c1_zip_sha256")
            if args.c1_expected_commit:
                validate_git_commit(args.c1_expected_commit, "c1_expected_commit")
            if not args.skip_c2:
                if args.c2_repo is not None:
                    validate_git_commit(args.c2_commit, "c2_commit")
                elif args.c2_zip is not None:
                    validate_sha256(args.c2_zip_sha256, "c2_zip_sha256")
                else:
                    raise CanaryError("C2_SOURCE_REQUIRED", "C2 source (--c2-repo or --c2-zip) is required unless --skip-c2")
            result = {
                "ok": True,
                "mode": "DRY_RUN_ONLY",
                "executed": False,
                "shadow_root": str(root),
                "c1_zip_sha256": pinned_sha,
                "c2_commit": args.c2_commit,
                "shadow_ports": ports,
                "forbidden_production_ports": sorted(FORBIDDEN_SHADOW_PORTS),
                "live_production_mutated": False,
            }
        elif args.command == "stage":
            result = run_shadow_stage(
                shadow_root=args.shadow_root,
                c1_zip=args.c1_zip,
                c1_zip_sha256=args.c1_zip_sha256,
                c1_expected_commit=args.c1_expected_commit,
                c2_repo=args.c2_repo,
                c2_commit=args.c2_commit,
                c2_zip=args.c2_zip,
                c2_zip_sha256=args.c2_zip_sha256,
                c2_source_db=args.c2_source_db,
                c1_rpc_port=args.c1_rpc_port,
                c1_hub_port=args.c1_hub_port,
                c2_gateway_port=args.c2_gateway_port,
                c2_unified_port=args.c2_unified_port,
                c2_omni_port=args.c2_omni_port,
                skip_c2=args.skip_c2,
                run_full_installer=args.run_full_installer,
                require_clean_c2_head=not args.allow_non_head_c2_commit,
                request_key=args.request_key,
            )
        elif args.command == "start-shadow":
            result = start_shadow_services(
                args.shadow_root,
                start_c1_rpc=args.c1_rpc,
                start_c1_hub=not args.no_c1_hub,
                start_c2_gateway=not args.no_c2_gateway,
                start_c2_unified=not args.no_c2_unified,
                request_key=args.request_key,
            )
        elif args.command == "health":
            result = verify_shadow_health(
                args.shadow_root,
                check_c1_rpc=args.c1_rpc,
                check_c1_hub=not args.no_c1_hub,
                check_c2_gateway=not args.no_c2_gateway,
                check_c2_unified=not args.no_c2_unified,
                consecutive_passes=args.consecutive_passes,
                require_upstream_omniroute=args.require_upstream_omniroute,
                request_key=args.request_key,
            )
        elif args.command == "stop-shadow":
            result = stop_shadow_services(args.shadow_root, ignore_missing=True)
        elif args.command == "rollback":
            result = rollback_canary(
                args.shadow_root,
                confirm_shadow_rollback=args.confirm_shadow_rollback,
                c1_target_release_id=args.c1_target_release,
                c1_baseline_zip=args.c1_baseline_zip,
                c1_baseline_zip_sha256=args.c1_baseline_zip_sha256,
                c2_target_release_id=args.c2_target_release,
                restore_c2_db_backup=args.restore_c2_db_backup,
                restore_c2_db_backup_sha256=args.restore_c2_db_backup_sha256,
                private_runtime_home=args.private_runtime_home,
                request_key=args.request_key,
            )
        elif args.command == "verify-receipts":
            root = validate_shadow_root(args.shadow_root)
            ensure_shadow_owner(root, create=False)
            store = CanaryReceiptStore(root / "state" / "canary_receipts.sqlite3")
            chain = store.verify_receipt_chain()
            result = {**chain, "recent_receipts": store.list_receipts(limit=args.limit)}
        elif args.command == "prepare-readiness":
            result = prepare_cutover_readiness(args.shadow_root, args.output)
        else:
            result = verify_owner_cutover_gate(
                readiness_path=args.readiness,
                approval_path=args.approval,
                expected_c1_zip_sha256=args.c1_zip_sha256,
                expected_c2_commit=args.c2_commit,
            )
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return 0 if result.get("ok", True) else 1
    except CanaryError as exc:
        print(json.dumps(exc.to_dict(), ensure_ascii=False, indent=2, default=str), file=sys.stderr)
        return 2
    except Exception as exc:
        print(json.dumps({"ok": False, "error_code": type(exc).__name__, "message": str(exc)}), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
