"""Reversible, OFFLINE, SHA-pinned addons for the portable Windows Bridge Core.

No network access or elevation. Never modifies an unrelated Bridge installation.
Ships no proprietary browser/model binaries; those must be supplied separately.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
import zipfile

SPEC = {
    "browser": {
        "sha256": "2a29191d66c9fc08a5d62363875b683ab0e4e94f71bea3620fe60730a2a0a45f",
        "bytes": 331067576,
        "members": 809,
        "roots": ("node_modules", "browsers"),
        "max_unpacked": 900_000_000,
    },
    "visual": {
        "sha256": "a79c9402e78fcf6513468f8868c9b315111c3bac7de07f1d36c40e2b3a1308ef",
        "bytes": 443752886,
        "members": 6557,
        "roots": ("native",),
        "max_unpacked": 1_000_000_000,
    },
}
WINDOWS_RESERVED = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", re.I)
MANIFEST_DIR = ".bridge-optional-addons"


class AddonError(RuntimeError):
    pass


def hash_file(path: Path) -> str:
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def is_linked(path: Path) -> bool:
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def ensure_root(root: Path) -> Path:
    root = root.resolve(strict=True)
    bridge = root / "bridge-v3"
    if not (bridge / "ff_win_v3_main.py").is_file():
        raise AddonError("CORE_NOT_INSTALLED: expected bridge-v3/ff_win_v3_main.py")
    if is_linked(bridge):
        raise AddonError("SYMLINK_BRIDGE_ROOT_REJECTED")
    return bridge


def checked_name(raw: str, roots: tuple[str, ...]) -> tuple[str, ...]:
    if not raw or "\\" in raw or raw.startswith("/") or ":" in raw or "\x00" in raw:
        raise AddonError("ARCHIVE_UNSAFE_PATH")
    val = raw.rstrip("/")
    p = PurePosixPath(val)
    parts = p.parts
    if not parts or parts[0] not in roots or any(x in ("", ".", "..") for x in parts):
        raise AddonError("ARCHIVE_FOREIGN_OR_TRAVERSAL")
    if any(x.endswith((".", " ")) or WINDOWS_RESERVED.fullmatch(x) for x in parts):
        raise AddonError("ARCHIVE_WINDOWS_UNSAFE_NAME")
    if not all(x.isascii() for x in parts):
        # Unicode is valid, but avoid path case-folding surprises in bundled binaries.
        raise AddonError("ARCHIVE_NONASCII_PATH_UNEXPECTED")
    return parts


def verify_archive(archive: Path, spec: dict) -> list[tuple[zipfile.ZipInfo, tuple[str, ...]]]:
    if not archive.is_file() or archive.stat().st_size != spec["bytes"]:
        raise AddonError("ADDON_ARCHIVE_SIZE_MISMATCH")
    if hash_file(archive) != spec["sha256"]:
        raise AddonError("ADDON_SHA256_MISMATCH")
    validated = []
    seen = set()
    total = 0
    with zipfile.ZipFile(archive) as z:
        members = z.infolist()
        if len(members) != spec["members"]:
            raise AddonError("ADDON_MEMBER_COUNT_MISMATCH")
        for member in members:
            parts = checked_name(member.filename, tuple(spec["roots"]))
            folded = "/".join(parts).casefold()
            if folded in seen:
                raise AddonError("ADDON_DUPLICATE_CASEFOLDED_PATH")
            seen.add(folded)
            mode = (member.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise AddonError("ADDON_SYMLINK_NOT_SUPPORTED")
            if not (member.is_dir() or mode in (0, stat.S_IFREG, stat.S_IFDIR)):
                raise AddonError("ADDON_NONREGULAR_FILE")
            if not member.is_dir():
                total += member.file_size
            if total > spec["max_unpacked"]:
                raise AddonError("ADDON_UNPACKED_SIZE_EXCEEDED")
            validated.append((member, parts))
    return validated


@contextmanager
def exclusive_lock(root: Path):
    # Prevent two addon operations from modifying the same runtime at once.
    lock = root / ".bridge-optional-addons.lock"
    try:
        fd = os.open(str(lock), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise AddonError("ADDON_OPERATION_ALREADY_RUNNING") from exc
    try:
        os.close(fd)
        yield
    finally:
        lock.unlink(missing_ok=True)


def marker_path(bridge: Path, name: str) -> Path:
    return bridge / MANIFEST_DIR / f"{name}.json"


def install(root: Path, name: str, archive: Path, spec: dict | None = None) -> dict:
    if name not in SPEC and spec is None:
        raise AddonError("UNKNOWN_ADDON")
    cfg = spec or SPEC[name]
    bridge = ensure_root(root)
    validated = verify_archive(archive, cfg)
    marker = marker_path(bridge, name)
    with exclusive_lock(root):
        if marker.exists():
            raise AddonError("ADDON_ALREADY_INSTALLED")
        for top in cfg["roots"]:
            dest = bridge / top
            if dest.exists() or is_linked(dest):
                raise AddonError(f"ADDON_TARGET_EXISTS_NOT_OWNED: {top}")
        root.mkdir(parents=True, exist_ok=True)
        stage = Path(tempfile.mkdtemp(prefix=".addon-stage-", dir=root))
        moved = []
        try:
            file_records = {}
            with zipfile.ZipFile(archive) as z:
                for member, parts in validated:
                    target = stage.joinpath(*parts)
                    if member.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    h = hashlib.sha256()
                    with z.open(member) as src, target.open("xb") as dest:
                        while chunk := src.read(1024 * 1024):
                            dest.write(chunk)
                            h.update(chunk)
                    file_records["/".join(parts)] = {"sha256": h.hexdigest(), "bytes": member.file_size}
            # Commit only after complete extraction and per-file verification.
            for top in cfg["roots"]:
                payload = stage / top
                if not payload.is_dir():
                    raise AddonError(f"ADDON_REQUIRED_ROOT_MISSING: {top}")
            for top in cfg["roots"]:
                os.replace(stage / top, bridge / top)
                moved.append(bridge / top)
            manifest = {
                "schema": "ff-optional-addon-v1",
                "addon": name,
                "archive_sha256": cfg["sha256"],
                "roots": list(cfg["roots"]),
                "files": file_records,
            }
            marker.parent.mkdir(exist_ok=True)
            temp_marker = marker.with_suffix(".part")
            temp_marker.write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
            os.replace(temp_marker, marker)
            return {"ok": True, "addon": name, "files": len(file_records),
                    "archive_sha256": cfg["sha256"], "install_root": str(root)}
        except BaseException:
            if not marker.exists():
                # Only directories created by this transaction are eligible.
                for dest in reversed(moved):
                    shutil.rmtree(dest)
            raise
        finally:
            shutil.rmtree(stage, ignore_errors=True)


def read_marker(bridge: Path, name: str) -> dict:
    path = marker_path(bridge, name)
    if not path.is_file():
        raise AddonError("ADDON_OWNERSHIP_MARKER_MISSING")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise AddonError("ADDON_OWNERSHIP_MARKER_INVALID") from exc
    cfg = SPEC[name]
    if (data.get("schema") != "ff-optional-addon-v1" or data.get("addon") != name
        or data.get("archive_sha256") != cfg["sha256"]
        or data.get("roots") != list(cfg["roots"])
        or not isinstance(data.get("files"), dict)):
        raise AddonError("ADDON_OWNERSHIP_MARKER_MISMATCH")
    return data


def verify_owned_tree(bridge: Path, name: str, manifest: dict) -> None:
    expected = manifest["files"]
    actual = {}
    for top in SPEC[name]["roots"]:
        folder = bridge / top
        if is_linked(folder) or not folder.is_dir():
            raise AddonError("ADDON_OWNED_DIRECTORY_MISSING_OR_LINK")
        for path in folder.rglob("*"):
            if is_linked(path):
                raise AddonError("ADDON_OWNED_CONTENT_SYMLINK")
            if not path.is_file():
                continue
            key = path.relative_to(bridge).as_posix()
            actual[key] = path
    # PyTorch/TorchVision can compile Python 3.13 cache files inside its own
    # vendored site-packages after a legitimate import. These are regenerated
    # artifacts, NOT part of the immutable original payload. All other files
    # remain protected, including arbitrary user-added Python scripts.
    extras = set(actual) - set(expected)
    for key in extras:
        parts = PurePosixPath(key).parts
        is_generated_cache = (
            name == "visual"
            and len(parts) >= 6
            and parts[:4] == ("native", "detector", "python", "site-packages")
            and "__pycache__" in parts[4:-1]
            and re.fullmatch(r"[A-Za-z0-9_.-]+\.cpython-313(?:\.opt-[12])?\.pyc", parts[-1]) is not None
        )
        if not is_generated_cache:
            raise AddonError("ADDON_CONTENT_MODIFIED_OR_FOREIGN_FILES")
    if set(expected) - set(actual):
        raise AddonError("ADDON_CONTENT_MODIFIED_OR_FOREIGN_FILES")
    for key in expected:
        path = actual[key]
        if path.stat().st_size != expected[key]["bytes"] or hash_file(path) != expected[key]["sha256"]:
            raise AddonError("ADDON_CONTENT_MODIFIED_OR_FOREIGN_FILES")


def remove(root: Path, name: str) -> dict:
    if name not in SPEC:
        raise AddonError("UNKNOWN_ADDON")
    bridge = ensure_root(root)
    with exclusive_lock(root):
        manifest = read_marker(bridge, name)
        verify_owned_tree(bridge, name, manifest)
        # Unlink the ownership record only once the exact installed files are verified.
        # Rename owned directories before deletion, keeping originals untouched on validation failure.
        moved = []
        try:
            for top in manifest["roots"]:
                folder = bridge / top
                trash = root / (".addon-trash-" + name + "-" + top)
                if trash.exists():
                    raise AddonError("ADDON_TRASH_COLLISION")
                os.replace(folder, trash)
                moved.append((folder, trash))
        except BaseException:
            for original, trash in reversed(moved):
                if trash.exists():
                    os.replace(trash, original)
            raise
        marker_path(bridge, name).unlink()
        for _, trash in moved:
            shutil.rmtree(trash)
        return {"ok": True, "addon": name, "removed": True}


def status(root: Path) -> dict:
    bridge = ensure_root(root)
    out = {}
    for name, cfg in SPEC.items():
        marker = marker_path(bridge, name)
        roots = [bridge / top for top in cfg["roots"]]
        if marker.is_file():
            state = "installed_marker_present_not_deep_verified"
        elif any(p.exists() or is_linked(p) for p in roots):
            state = "foreign_or_incomplete_do_not_overwrite"
        else:
            state = "missing_optional_dependency"
        out[name] = state
    return {"core_installed": True, "addons": out}


def main(args=None) -> int:
    parser = argparse.ArgumentParser(description="Offline optional browser/vision addon manager")
    parser.add_argument("action", choices=("status", "install", "remove"))
    parser.add_argument("--install-root", required=True, type=Path)
    parser.add_argument("--name", choices=tuple(SPEC))
    parser.add_argument("--archive", type=Path)
    opts = parser.parse_args(args)
    try:
        if opts.action == "status":
            result = status(opts.install_root)
        elif opts.action == "install":
            if not opts.name or not opts.archive:
                parser.error("install requires --name and --archive")
            result = install(opts.install_root, opts.name, opts.archive)
        else:
            if not opts.name:
                parser.error("remove requires --name")
            result = remove(opts.install_root, opts.name)
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0
    except (AddonError, OSError, zipfile.BadZipFile, RuntimeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

