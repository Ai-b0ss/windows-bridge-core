"""Read-only P0 inventory: compare public source, release ZIP and live runtime.

Never collect private configs, keys, logs, tokens, or host paths in reports.
The caller supplies roots and pin-listed modules; no path discovery or writes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import zipfile

TRACKED = (
    "ff_win_v3_main.py", "ff_win_v3_security.py", "cua_router.py",
    "cua_task_authority.py", "cua_programmatic_discovery.py",
    "cua_tool_preparation.py", "cua_cli_first_policy.py",
    "cua_hidden_desktop.py", "cua_lifecycle.py",
)


def record(data: bytes | None):
    return None if data is None else {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def compare(source: Path, installed: Path, archive: Path, names=TRACKED):
    if not source.is_dir() or not installed.is_dir() or not archive.is_file():
        raise ValueError("Runtime inventory source/install/archive missing")
    rows = []
    with zipfile.ZipFile(archive) as z:
        for name in names:
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*\.py", name):
                raise ValueError("Refusing non-allowlisted module path")
            def read(root):
                f = root / name
                return f.read_bytes() if f.is_file() and not f.is_symlink() else None
            src = read(source)
            live = read(installed)
            packed = "runtime/bridge-v3/" + name
            data = z.read(packed) if packed in z.namelist() else None
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
        "modules": rows,
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
