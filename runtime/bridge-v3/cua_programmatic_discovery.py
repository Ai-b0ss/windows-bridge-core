from __future__ import annotations

import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping

from cua_cli_discovery import discover_cli_candidates


_EXEC_HINTS = ("cli", "cmd", "console", "core", "service", "server", "daemon", "agent", "helper")


def _safe_creationflags() -> int:
    return int(getattr(subprocess, "CREATE_NO_WINDOW", 0)) if os.name == "nt" else 0


def _netstat_text(timeout_s: float = 0.8) -> str:
    if os.name != "nt":
        return ""
    try:
        completed = subprocess.run(
            ["netstat.exe", "-ano", "-p", "tcp"],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=max(0.1, float(timeout_s)),
            creationflags=_safe_creationflags(),
            check=False,
        )
    except Exception:
        return ""
    return completed.stdout or ""


def _parse_local_endpoint(value: str) -> tuple[str, int] | None:
    value = str(value or "").strip()
    if value.startswith("["):
        match = re.match(r"^\[(.+)\]:(\d+)$", value)
        if not match:
            return None
        host, port_text = match.group(1), match.group(2)
    else:
        if ":" not in value:
            return None
        host, port_text = value.rsplit(":", 1)
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return host, port


def owned_tcp_listeners(pid: int, *, netstat_text: str | None = None) -> list[dict[str, Any]]:
    if pid <= 0:
        return []
    text = _netstat_text() if netstat_text is None else str(netstat_text)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 5 or parts[0].upper() != "TCP" or parts[3].upper() != "LISTENING":
            continue
        try:
            owner = int(parts[4])
        except ValueError:
            continue
        if owner != pid:
            continue
        parsed = _parse_local_endpoint(parts[1])
        if parsed is None:
            continue
        host, port = parsed
        if host not in {"127.0.0.1", "0.0.0.0", "::", "::1"}:
            continue
        key = (host, port)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "kind": "tcp_listener",
            "status": "candidate",
            "verified": False,
            "pid": pid,
            "address": host,
            "port": port,
            "scope": "loopback" if host in {"127.0.0.1", "::1"} else "wildcard",
            "evidence": "netstat_pid_owner",
        })
    return sorted(out, key=lambda item: (item["scope"] != "loopback", item["port"]))


def sibling_executables(exe: str) -> list[dict[str, Any]]:
    path = Path(str(exe or ""))
    if not path.is_file():
        return []
    try:
        children = list(path.parent.glob("*.exe"))
    except OSError:
        return []
    current = os.path.normcase(str(path))
    out: list[dict[str, Any]] = []
    for child in children:
        if os.path.normcase(str(child)) == current:
            continue
        stem = child.stem.casefold()
        hint = next((item for item in _EXEC_HINTS if item in stem), None)
        if hint is None:
            continue
        out.append({
            "kind": "sibling_executable",
            "status": "candidate",
            "verified": False,
            "path": str(child),
            "hint": hint,
            "evidence": "install_directory",
        })
    return sorted(out, key=lambda item: item["path"].casefold())[:20]


def discover_programmatic_surfaces(
    app: str,
    window: Mapping[str, Any] | None = None,
    *,
    cdp: Mapping[str, Any] | None = None,
    netstat_text: str | None = None,
) -> list[dict[str, Any]]:
    """Return read-only evidence for possible programmatic control surfaces.

    Window-independent evidence is collected first so a headless/background app
    can still expose a stronger route than GUI automation.
    """
    out: list[dict[str, Any]] = []
    exe = str(window.get("exe") or "") if isinstance(window, Mapping) else ""
    out.extend(discover_cli_candidates(app, install_dirs=[Path(exe).parent] if exe else []))
    if isinstance(cdp, Mapping):
        out.append({
            "kind": "cdp",
            "status": "verified",
            "verified": True,
            "port": cdp.get("port"),
            "source": cdp.get("source"),
            "page_id": cdp.get("page_id"),
            "evidence": "devtools_active_port",
        })
    if isinstance(window, Mapping):
        try:
            pid = int(window.get("pid") or 0)
        except Exception:
            pid = 0
        out.extend(owned_tcp_listeners(pid, netstat_text=netstat_text))
        out.extend(sibling_executables(str(window.get("exe") or "")))
    return sorted(out, key=lambda candidate: candidate.get("verified") is not True)
