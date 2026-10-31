"""Read-only parity check: bytes Git stores for runtime/bridge-v3 vs an installed runtime.

Run from a checkout:  python tools/runtime_parity.py --installed <bridge-v3 folder> [--ref origin/main]

Compares the bytes `git show <ref>:path` returns with the installed files, hashing only.
Report fields hold file names and counts, never file contents or absolute paths. Optionally
reports free space of the installed drive. Exit code 1 when any tracked file differs.
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


def git(repo: Path, *args: str) -> bytes:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if done.returncode:
        raise SystemExit("git failed: " + " ".join(args))
    return done.stdout


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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--installed", required=True, type=Path)
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--disk", action="store_true", help="also report free space of the installed drive")
    args = parser.parse_args(argv)
    if not args.installed.is_dir():
        raise SystemExit("installed folder not found")
    report = compare(args.repo, args.installed, args.ref)
    if args.disk:
        usage = shutil.disk_usage(args.installed)
        report["disk_free_gb"] = round(usage.free / 1e9, 1)
        report["disk_free_percent"] = round(100 * usage.free / usage.total, 1)
    report["parity"] = not report["different"] and not report["missing_in_installed"]
    print(json.dumps(report, indent=2))
    return 0 if report["parity"] else 1


if __name__ == "__main__":
    sys.exit(main())
