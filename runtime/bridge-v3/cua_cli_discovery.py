from __future__ import annotations

import hashlib
import json
import secrets
import os
import re
import time
from pathlib import Path
import subprocess
from typing import Any


def _commands(app: str) -> list[str]:
    words = [
        item.casefold()
        for item in re.findall(r"[A-Za-z0-9]+", str(app or ""))
        if len(item) >= 2
    ]
    commands: list[str] = []
    compact = "".join(words)
    if compact:
        commands.append(compact)
    for word in reversed(words):
        if len(word) >= 3 and word not in commands:
            commands.append(word)
    if len(words) >= 2:
        acronym = "".join(word[0] for word in words if word)
        if len(acronym) >= 2 and acronym not in commands:
            commands.append(acronym)

    aliases = {
        "antigravity": ["agy", "antigravity"],
        "visualstudiocode": ["code"],
        "vscode": ["code"],
        "windowsmcp": ["windows-mcp"],
        "cursor": ["cursor-agent", "agent", "cursor"],
    }
    for command in aliases.get(compact, []):
        if command not in commands:
            commands.insert(0, command)
    return commands[:12]


def _installation_dirs(commands: list[str]) -> list[Path]:
    """Bounded vendor/app lookup. Never walk the entire user profile."""
    roots = [Path(os.environ.get("LOCALAPPDATA", "")),
             Path(os.environ.get("LOCALAPPDATA", "")) / "Programs"]
    roots += [Path(os.environ[x]) for x in ("ProgramFiles", "ProgramFiles(x86)") if os.environ.get(x)]
    matches = []
    for root in roots:
        if not root.is_absolute() or not root.is_dir():
            continue
        try:
            vendors = [p for p in root.iterdir() if p.is_dir()][:250]
            for vendor in vendors:
                if vendor.name.casefold() in commands:
                    matches.append(vendor)
                for command in commands:
                    app_dir = vendor / command
                    if app_dir.is_dir():
                        matches.append(app_dir)
        except OSError:
            continue
    prepared = Path(os.environ.get("LOCALAPPDATA", "")) / "FFWindowsBridge" / "tools"
    if prepared.is_absolute() and prepared.is_dir():
        for directory in list(prepared.iterdir())[:100]:
            if directory.is_dir() and any(directory.name.casefold().startswith(command) for command in commands):
                matches.append(directory)
                matches.append(directory / "Scripts")
    return matches


def discover_cli_candidates(app: str, *, install_dirs=()) -> list[dict[str, Any]]:
    """File existence is a candidate, never health or task compatibility proof."""
    commands = _commands(app)
    out = []
    seen = set()
    extensions = [".exe", ".cmd", ".bat", ".com"] if os.name == "nt" else [""]
    def add(path, command, evidence):
        if not path.is_file(): return
        canonical = str(path.resolve()); key = os.path.normcase(canonical)
        if key in seen: return
        seen.add(key)
        out.append({"kind": "cli_command", "status": "candidate", "verified": False,
                    "command": command, "path": canonical, "evidence": evidence,
                    "health": "unprobed", "task_compatibility": "unknown"})
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        path = Path(directory.strip('"'))
        if not directory or not path.is_absolute(): continue
        for command in commands:
            for ext in extensions: add(path / (command + ext), command, "path_inventory")
    for directory in [*map(Path, install_dirs), *_installation_dirs(commands)]:
        if not directory.is_absolute() or not directory.is_dir(): continue
        for command in commands:
            for ext in extensions:
                name = command + ext
                add(directory / name, command, "install_directory")
                add(directory / "bin" / name, command, "install_directory")
                for pattern in ("bin/*/" + name, "*/bin/" + name):
                    for path in list(directory.glob(pattern))[:50]:
                        add(path, command, "versioned_install_directory")
    return out[:100]


def probe_cli_versions(candidates, *, timeout_s=3.0):
    """Explicit opt-in execution of --version; discovery alone never executes."""
    out = []
    for item in candidates:
        row = dict(item); path = row["path"]; argv = [path, "--version"]
        # These GUI entrypoints do not implement a version-only CLI. Launching
        # them as a health probe can open owner-desktop windows even with
        # CREATE_NO_WINDOW. Inventory is sufficient until a task-specific
        # programmatic API or documented CLI is chosen.
        if Path(path).name.casefold() in {"excel.exe", "winword.exe", "powerpnt.exe",
                                           "notepad.exe", "wordpad.exe", "mspaint.exe", "cursor.exe"}:
            row["health"] = "gui_executable_not_cli"
            out.append(row)
            continue
        if Path(path).suffix.casefold() in {".cmd", ".bat"}:
            if any(c in path for c in '\r\n"%'):
                row["health"] = "unsafe_shim_path"; out.append(row); continue
            argv = subprocess.list2cmdline([os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c"]) + f' ""{path}" --version"'
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout_s,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            text = proc.stdout.decode("utf-8", errors="replace")[:1000]
            match = re.search(r"(?<!\d)(\d+\.\d+(?:\.\d+)?)(?!\d)", text)
            if proc.returncode != 0:
                help_argv = [path, "--help"] if isinstance(argv, list) else argv.replace("--version", "--help")
                help_proc = subprocess.run(help_argv, capture_output=True, timeout=timeout_s,
                                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                row["help_exit_code"] = help_proc.returncode
                row["health"] = "healthy" if help_proc.returncode == 0 else "failed"
            else:
                row["health"] = "healthy"
            row["version"] = match.group(1) if match else None
            row["version_exit_code"] = proc.returncode
        except (OSError, subprocess.TimeoutExpired) as exc: row["health"] = type(exc).__name__
        out.append(row)
    return out


def rank_cli_candidates(candidates):
    """Task-compatible evidence outranks version; newest healthy otherwise."""
    eligible = [dict(c) for c in candidates if c.get("health") == "healthy"
                and c.get("task_compatibility") not in {"incompatible", "failed"}]
    def key(c):
        version = tuple(int(x) for x in str(c.get("version") or "0").split('.'))
        return (c.get("task_compatibility") == "compatible", version)
    return sorted(eligible, key=key, reverse=True)


_GUI_DIAGNOSTICS: dict[str, dict[str, Any]] = {}

def _candidate_identity(candidates):
    rows = []
    for candidate in candidates:
        record = {key: candidate.get(key) for key in
                  ("kind", "command", "pid", "port", "page_id", "source")}
        raw_path = candidate.get("path")
        if raw_path:
            path = Path(raw_path)
            record["path"] = os.path.normcase(str(path.resolve()))
            try:
                with path.open("rb") as handle:
                    record["sha256"] = hashlib.file_digest(handle, "sha256").hexdigest()
            except OSError:
                record["sha256"] = None
        rows.append(json.dumps(record, sort_keys=True, separators=(",", ":")))
    return hashlib.sha256(json.dumps(sorted(rows), separators=(",", ":")).encode()).hexdigest()

def issue_gui_fallback_receipt(candidates, *, app=None, ttl_s=300):
    """A failed local probe is bounded evidence, never global GUI permission."""
    if not candidates or any(c.get("health") != "failed" for c in candidates):
        return None
    if type(ttl_s) not in {int, float} or not 0 < ttl_s <= 300:
        raise ValueError("GUI_RECEIPT_TTL_INVALID")
    token = secrets.token_urlsafe(24)
    if len(_GUI_DIAGNOSTICS) >= 256:
        _GUI_DIAGNOSTICS.pop(next(iter(_GUI_DIAGNOSTICS)))
    _GUI_DIAGNOSTICS[token] = {
        "identity": _candidate_identity(candidates),
        "app": str(app).strip().casefold() if app is not None else None,
        "expires": time.monotonic()+ttl_s,
    }
    return token

def gui_escalation_allowed(discovered, fallback):
    """Absence of a CLI never proves absence of an API/SDK/MCP route.

    This is the automatic fallback gate, not an OS boundary around ordinary
    user scripts. A task-specific planner still has to research non-CLI paths.
    """
    if not discovered.get("programmatic_discovery_complete", False):
        return False
    candidates = discovered.get("programmatic_candidates", [])
    if not isinstance(candidates, list) or not candidates:
        return False
    # Do not discard an API, MCP, CDP or listener candidate merely because a
    # failed CLI receipt exists. It needs its own task-specific examination.
    if any(c.get("kind") != "cli_command" for c in candidates):
        return False
    if not isinstance(fallback, dict):
        return False
    token = fallback.get("diagnostic_receipt")
    record = _GUI_DIAGNOSTICS.get(token) if isinstance(token, str) else None
    if not record:
        return False
    if record["expires"] <= time.monotonic():
        _GUI_DIAGNOSTICS.pop(token, None)
        return False
    if record["app"] is not None and record["app"] != str(discovered.get("app", "")).strip().casefold():
        return False
    return record["identity"] == _candidate_identity(candidates)
