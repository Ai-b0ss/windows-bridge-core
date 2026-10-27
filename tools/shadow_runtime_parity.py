"""Read-only full-runtime parity gate for a staged Windows Bridge release.

Compare only PUBLIC runtime paths declared by a pinned candidate manifest.
Never enumerate/serialize live private files, secrets, configs or logs. Disk
parity is distinct from loaded process provenance and cutover authorization.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import zipfile

MAX_MODULE_BYTES = 8 * 1024 * 1024
MAX_FILES = 400
MAX_TOTAL_BYTES = 120 * 1024 * 1024
PUBLIC_SUFFIXES = frozenset({".py", ".ps1", ".cmd", ".cs", ".csproj", ".js", ".cjs", ".mjs", ".json", ".md", ".txt"})
PREFIX = ("runtime", "bridge-v3")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_relative(name: str) -> str | None:
    if not isinstance(name, str) or "\\" in name or ":" in name:
        return None
    p = PurePosixPath(name)
    if p.is_absolute() or any(x in {".", "..", ""} for x in name.split("/")):
        return None
    if len(p.parts) < 3 or p.parts[:2] != PREFIX or p.suffix.casefold() not in PUBLIC_SUFFIXES:
        return None
    if p.name in {"config.json", "secret", "audit.jsonl"}:
        return None
    return "/".join(p.parts[2:])


def _read_file(root: Path, rel: str) -> bytes | None:
    path = root.joinpath(*PurePosixPath(rel).parts)
    # Reject traversals and nonregular destinations, including ancestor reparse
    # points. Never follow a symlink into owner profiles or private configs.
    node = path
    while True:
        if node.is_symlink() or getattr(node, "is_junction", lambda: False)():
            return None
        if node == root or node.parent == node:
            break
        node = node.parent
    if not path.is_file():
        return None
    if path.stat().st_size > MAX_MODULE_BYTES:
        raise ValueError("RUNTIME_FILE_TOO_LARGE")
    return path.read_bytes()


def _ast_equal(a: bytes, b: bytes) -> bool | None:
    try:
        return ast.dump(ast.parse(a.decode("utf-8-sig")), include_attributes=False) == (
            ast.dump(ast.parse(b.decode("utf-8-sig")), include_attributes=False)
        )
    except (UnicodeError, SyntaxError, ValueError):
        return None


def compare_full_runtime(source_repo: Path, archive: Path, shadow_install: Path,
                         live_install: Path, *, observed_live_agent_sha: str | None = None) -> dict:
    """Three disk byte sets plus advisory loaded SHA. No execution/mutations."""
    source_repo, archive = Path(source_repo), Path(archive)
    shadow_install, live_install = Path(shadow_install), Path(live_install)
    if not (source_repo / "runtime" / "bridge-v3").is_dir() or not archive.is_file():
        raise ValueError("SOURCE_OR_PACKAGE_MISSING")
    if not shadow_install.is_dir() or not live_install.is_dir():
        raise ValueError("INSTALLED_RUNTIME_ROOT_MISSING")
    if observed_live_agent_sha is not None and not re.fullmatch(r"[0-9a-f]{64}", observed_live_agent_sha):
        raise ValueError("LIVE_AGENT_SHA_INVALID")
    # A source label is NOT proof of what the owner's active process loaded.
    try:
        head = subprocess.run(["git", "-C", str(source_repo), "rev-parse", "HEAD"],
                              check=True, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("SOURCE_COMMIT_UNAVAILABLE") from exc

    with zipfile.ZipFile(archive) as z:
        names = Counter(z.namelist())
        if names["release-manifest.json"] != 1 or z.getinfo("release-manifest.json").file_size > 2 * 1024 * 1024:
            raise ValueError("MANIFEST_MISSING_OR_AMBIGUOUS")
        try:
            manifest = json.loads(z.read("release-manifest.json"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError("MANIFEST_INVALID") from exc
        entries = manifest.get("files")
        if not isinstance(entries, dict) or manifest.get("schema") != "ff-gh-release-v1":
            raise ValueError("MANIFEST_INVALID")
        if (manifest.get("source_bytes_verified_against_commit") is not True
                or manifest.get("source_commit") != head
                or manifest.get("public_source_commit") != head):
            raise ValueError("SOURCE_COMMIT_IDENTITY_MISMATCH")
        paths: list[tuple[str, str, str]] = []
        seen = set()
        total = 0
        for name, expected in sorted(entries.items()):
            if not isinstance(name, str) or not name.startswith("runtime/bridge-v3/"):
                continue
            rel = _safe_relative(name)
            if rel is None or rel.casefold() in seen:
                raise ValueError("UNSAFE_OR_DUPLICATE_RUNTIME_PATH")
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError("MANIFEST_RUNTIME_HASH_INVALID")
            if names[name] != 1:
                raise ValueError("CANDIDATE_RUNTIME_ENTRY_MISSING_OR_DUPLICATED")
            info = z.getinfo(name)
            if info.file_size > MAX_MODULE_BYTES:
                raise ValueError("CANDIDATE_RUNTIME_ENTRY_TOO_LARGE")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError("CANDIDATE_RUNTIME_BUDGET_EXCEEDED")
            seen.add(rel.casefold())
            paths.append((name, rel, expected))
        if not paths or len(paths) > MAX_FILES:
            raise ValueError("CANDIDATE_RUNTIME_FILE_COUNT_INVALID")
        # Validate all packaged bytes and local source before inspecting the
        # existing Windows runtime. No secrets/configs are read from production.
        for name, rel, expected in paths:
            published = z.read(name)
            source = _read_file(source_repo / "runtime" / "bridge-v3", rel)
            if _sha(published) != expected or source is None or _sha(source) != expected:
                raise ValueError("CANDIDATE_AND_SOURCE_BYTES_MISMATCH")

        rows = []
        candidate_agent_hash = None
        for name, rel, expected in paths:
            if rel == "ff_win_v3_agent.py":
                candidate_agent_hash = expected
            shadow = _read_file(shadow_install / "bridge-v3", rel)
            live = _read_file(live_install / "bridge-v3", rel)
            source = _read_file(source_repo / "runtime" / "bridge-v3", rel)
            rows.append({
                "module": rel,
                "candidate_sha256": expected,
                "shadow_equal_candidate": shadow is not None and _sha(shadow) == expected,
                "live_equal_candidate": live is not None and _sha(live) == expected,
                "live_present": live is not None,
                "live_python_ast_equal_candidate": (
                    _ast_equal(source, live) if rel.endswith(".py") and live is not None else None
                ),
            })

    if candidate_agent_hash is None:
        raise ValueError("CORE_AGENT_MISSING")
    shadow_matches = all(x["shadow_equal_candidate"] for x in rows)
    live_matches = all(x["live_equal_candidate"] for x in rows)
    live_sha_consistent = (observed_live_agent_sha == candidate_agent_hash
                           if observed_live_agent_sha is not None else None)
    return {
        "schema": "ff-shadow-full-runtime-parity-v1",
        "read_only": True,
        "source_commit": head,
        "candidate_zip_sha256": _sha(archive.read_bytes()),
        "candidate_agent_sha256": candidate_agent_hash,
        "runtime_modules": len(rows),
        "shadow_disk_matches_candidate": shadow_matches,
        "live_disk_matches_candidate": live_matches,
        "live_same_python_ast_modules": sum(x["live_python_ast_equal_candidate"] is True for x in rows),
        "live_loaded_agent_sha_supplied": observed_live_agent_sha is not None,
        "live_reported_agent_sha_equals_candidate": live_sha_consistent,
        "live_process_identity_independently_verified": False,
        "shadow_process_identity_independently_verified": False,
        "safe_to_replace_running_runtime": False,
        "production_changes_made": False,
        "unknown_private_files_enumerated": False,
        "modules": rows,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only candidate / shadow / owner runtime parity")
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--shadow-install", type=Path, required=True)
    parser.add_argument("--live-install", type=Path, required=True)
    parser.add_argument("--observed-live-agent-sha")
    args = parser.parse_args(argv)
    try:
        report = compare_full_runtime(args.source_repo, args.candidate,
                                      args.shadow_install, args.live_install,
                                      observed_live_agent_sha=args.observed_live_agent_sha)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        # Never include absolute owner paths in diagnostic output.
        print(json.dumps({"ok": False, "code": str(exc) if isinstance(exc, ValueError) else type(exc).__name__}),
              file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
