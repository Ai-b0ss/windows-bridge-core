"""Read-only P0 inventory: compare public source, release ZIP and live runtime.

Never collect private configs, keys, logs, tokens, or host paths in reports.
The caller supplies roots and pin-listed modules; no path discovery or writes.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import zipfile

TRACKED = (
    "ff_win_v3_main.py", "ff_win_v3_security.py", "cua_router.py",
    "cua_task_authority.py", "cua_programmatic_discovery.py",
    "cua_tool_preparation.py", "cua_cli_first_policy.py",
    "cua_hidden_desktop.py", "cua_lifecycle.py",
    "ff_win_v3_agent.py", "ff_win_process_identity.py",
    "ff_win_request_journal.py", "cua_restricted_rpc.py",
    "cua_durable_recovery.py", "cua_agent_workflows.py",
    "ff_win_owned_job.py",
)
MAX_MODULE_BYTES = 8 * 1024 * 1024


def record(data: bytes | None):
    return None if data is None else {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def compare(source: Path, installed: Path, archive: Path, names=TRACKED):
    if not source.is_dir() or not installed.is_dir() or not archive.is_file():
        raise ValueError("Runtime inventory source/install/archive missing")
    names = tuple(names)
    if any(not isinstance(name, str) or name not in TRACKED for name in names):
        raise ValueError("Refusing non-allowlisted module path")
    if not names or len(set(names)) != len(names):
        raise ValueError("Module selection must be nonempty and unique")
    rows = []
    package_hash = hashlib.sha256()
    with archive.open("rb") as package_stream:
        package_size = 0
        for chunk in iter(lambda: package_stream.read(1024 * 1024), b""):
            package_hash.update(chunk)
            package_size += len(chunk)
        package_stream.seek(0)
        z = zipfile.ZipFile(package_stream)
        with z:
            counts = Counter(z.namelist())
            for name in names:
                packed = "runtime/bridge-v3/" + name
                if counts[packed] > 1:
                    raise ValueError("Ambiguous duplicate package module")
                if counts[packed] and z.getinfo(packed).file_size > MAX_MODULE_BYTES:
                    raise ValueError("Package module exceeds inventory size limit")
                def read(root):
                    f = root / name
                    if not f.is_file() or f.is_symlink():
                        return None
                    if f.stat().st_size > MAX_MODULE_BYTES:
                        raise ValueError("Runtime module exceeds inventory size limit")
                    return f.read_bytes()
                src = read(source)
                live = read(installed)
                data = z.read(packed) if counts[packed] else None
                entries = {
                    "public_source": record(src), "package": record(data),
                    "live_runtime": record(live),
                }
                matches = {
                    "source_equals_package": src is not None and src == data,
                    "source_equals_live": src is not None and src == live,
                    "package_equals_live": data is not None and data == live,
                }
                rows.append({"file": name, "versions": entries, "matches": matches})
    return {
        "schema": "ff-bridge-runtime-inventory-v1",
        "read_only": True,
        "sensitive_paths_included": False,
        "inventory_scope": "allowlisted_installed_files_only",
        "running_process_verified": False,
        "package": {"sha256": package_hash.hexdigest(), "size": package_size},
        "modules": rows,
        "all_installed_equal_source": all(row["matches"]["source_equals_live"] for row in rows),
        "all_installed_equal_package": all(row["matches"]["package_equals_live"] for row in rows),
        # Legacy aliases describe disk bytes, never evidence of the active PID.
        "all_live_equal_source": all(row["matches"]["source_equals_live"] for row in rows),
        "all_live_equal_package": all(row["matches"]["package_equals_live"] for row in rows),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Compare pinned module hashes without sensitive file enumeration")
    parser.add_argument("--source", type=Path, required=True,
                        help="public source runtime/bridge-v3 folder")
    parser.add_argument("--installed", type=Path, required=True,
                        help="live runtime/bridge-v3 folder; never modified")
    parser.add_argument("--archive", type=Path, required=True,
                        help="portable release ZIP")
    opts = parser.parse_args(argv)
    print(json.dumps(compare(opts.source, opts.installed, opts.archive), sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        # No absolute host paths or binary content in diagnostics.
        print(json.dumps({"ok": False, "error": type(exc).__name__}), file=sys.stderr)
        sys.exit(2)
