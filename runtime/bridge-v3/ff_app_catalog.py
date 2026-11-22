"""Policy-controlled application catalog for scoped entry and private desktop execution.

Only owner-approved built-in applications (with verified installation paths) or
explicitly owner-enrolled executables/AUMIDs stored in local state (`app-catalog.json`)
can be authorized for task-scoped agents. Arbitrary binaries and bare script
interpreters are rejected fail-closed.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from ff_hub_store import HubError

APP_ID_RE = re.compile(r"[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?\Z", re.ASCII)

DISALLOWED_INTERPRETER_EXES = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe", "python.exe", "pythonw.exe", "python3.exe",
    "node.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
    "bash.exe", "sh.exe", "wsl.exe", "wt.exe", "conhost.exe",
})

BUILTIN_CATALOG: dict[str, dict[str, Any]] = {
    "charmap": {
        "app_id": "charmap",
        "exe": "charmap.exe",
        "kind": "win32",
        "route": "hidden_desktop_uia",
    },
    "notepad": {
        "app_id": "notepad",
        "exe": "notepad.exe",
        "kind": "win32",
        "route": "hidden_desktop_uia",
    },
    "wordpad": {
        "app_id": "wordpad",
        "exe": "wordpad.exe",
        "kind": "win32",
        "route": "hidden_desktop_uia",
    },
    "paint": {
        "app_id": "paint",
        "exe": "mspaint.exe",
        "kind": "win32",
        "route": "hidden_desktop_uia",
    },
    "word": {
        "app_id": "word",
        "exe": "WINWORD.EXE",
        "kind": "office",
        "route": "hidden_desktop_office",
        "office_app": "word",
    },
    "excel": {
        "app_id": "excel",
        "exe": "EXCEL.EXE",
        "kind": "office",
        "route": "hidden_desktop_office",
        "office_app": "excel",
    },
    "powerpoint": {
        "app_id": "powerpoint",
        "exe": "POWERPNT.EXE",
        "kind": "office",
        "route": "hidden_desktop_office",
        "office_app": "powerpoint",
    },
    "vscode": {
        "app_id": "vscode",
        "exe": "Code.exe",
        "kind": "electron_editor",
        "route": "hidden_desktop_electron_isolated",
        "editor_app": "vscode",
    },
    "cursor": {
        "app_id": "cursor",
        "exe": "Cursor.exe",
        "kind": "electron_editor",
        "route": "hidden_desktop_electron_isolated",
        "editor_app": "cursor",
    },
    "antigravity": {
        "app_id": "antigravity",
        "exe": "Antigravity.exe",
        "kind": "electron",
        "route": "hidden_desktop_electron_isolated",
        "editor_app": "antigravity",
    },
    "claude": {
        "app_id": "claude",
        "exe": "claude-desktop.exe",
        "kind": "msix_fulltrust_electron",
        "route": "hidden_desktop_msix_alias",
        "aumid": "Claude_pzs8sxrjxfjjc!Claude",
    },
}

BUILTIN_ALIASES: dict[str, str] = {
    "charmap.exe": "charmap",
    "notepad.exe": "notepad",
    "wordpad.exe": "wordpad",
    "mspaint": "paint",
    "mspaint.exe": "paint",
    "winword": "word",
    "winword.exe": "word",
    "ms word": "word",
    "excel.exe": "excel",
    "ms excel": "excel",
    "powerpnt": "powerpoint",
    "powerpnt.exe": "powerpoint",
    "code": "vscode",
    "code.exe": "vscode",
    "visual studio code": "vscode",
    "cursor.exe": "cursor",
    "agy": "antigravity",
    "antigravity.exe": "antigravity",
    "claude-desktop": "claude",
    "claude desktop": "claude",
    "claude-desktop.exe": "claude",
    "claude_pzs8sxrjxfjjc!claude": "claude",
}

DEFAULT_SAFE_APPS = frozenset({"charmap", "word", "excel", "powerpoint"})


def _is_reparse(path: Path) -> bool:
    if path.is_symlink() or getattr(path, "is_junction", lambda: False)():
        return True
    if os.name == "nt":
        try:
            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
            if attrs != -1 and (attrs & 0x400):
                return True
        except Exception:
            pass
    return False


def _file_sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _authenticode_info(path: Path) -> dict[str, Any]:
    if os.name != "nt" or not path.is_file():
        return {"status": "NotApplicable", "signed": False, "subject": None}
    ps = (
        "$ErrorActionPreference='Stop';"
        "$p=$env:FF_SIG_PROBE_PATH;"
        "$s=Get-AuthenticodeSignature -LiteralPath $p;"
        "[pscustomobject]@{status=[string]$s.Status;"
        "subject=if($s.SignerCertificate){[string]$s.SignerCertificate.Subject}else{$null}}|"
        "ConvertTo-Json -Compress"
    )
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps],
            env={**os.environ, "FF_SIG_PROBE_PATH": str(path)},
            capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout)
            status = str(data.get("status") or "Unknown")
            return {
                "status": status,
                "signed": status == "Valid",
                "subject": data.get("subject"),
            }
    except Exception:
        pass
    return {"status": "ProbeUnavailable", "signed": False, "subject": None}


class AppCatalog:
    """Owner-controlled application allowlist and provenance catalog."""

    SCHEMA = "ff-app-catalog-v1"

    def __init__(self, state_dir: str | Path | None):
        self.state_dir = Path(state_dir) if state_dir is not None else None
        self.path = (self.state_dir / "app-catalog.json") if self.state_dir is not None else None

    def _load_enrolled(self) -> dict[str, dict[str, Any]]:
        if self.path is None or not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise HubError("APP_CATALOG_INVALID", cause=type(exc).__name__) from None
        if not isinstance(data, dict) or data.get("schema") != self.SCHEMA or not isinstance(data.get("apps"), dict):
            raise HubError("APP_CATALOG_INVALID")
        return {k: v for k, v in data["apps"].items() if isinstance(v, dict)}

    def _save_enrolled(self, apps: dict[str, dict[str, Any]]) -> None:
        if self.path is None:
            raise HubError("APP_CATALOG_STATE_REQUIRED")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema": self.SCHEMA, "apps": dict(sorted(apps.items()))}
        tmp = self.path.with_name(f".app-catalog.{uuid.uuid4().hex}.tmp")
        try:
            tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
            os.replace(tmp, self.path)
        finally:
            tmp.unlink(missing_ok=True)

    def canonical_id(self, app_name: Any) -> str | None:
        if not isinstance(app_name, str):
            return None
        key = app_name.strip().strip('"').lower()
        if not key:
            return None
        mapped = BUILTIN_ALIASES.get(key, key)
        if mapped in BUILTIN_CATALOG:
            return mapped
        enrolled = self._load_enrolled()
        entry = enrolled.get(key)
        if entry and not entry.get("revoked"):
            return key
        for app_id, row in enrolled.items():
            if row.get("revoked"):
                continue
            exe = str(row.get("executable") or "").lower()
            aumid = str(row.get("aumid") or "").lower()
            if key in {app_id, exe, Path(exe).name.lower() if exe else "", aumid} - {""}:
                return app_id
        return None

    def validate_entry_apps(self, apps: list[str]) -> list[str]:
        normalized: list[str] = []
        for item in apps:
            cid = self.canonical_id(item)
            if cid is None:
                raise HubError("ENTRY_SCOPE_INVALID", app=item)
            if cid not in normalized:
                normalized.append(cid)
        return normalized

    def get(self, app_name: str, *, verify_integrity: bool = False) -> dict[str, Any] | None:
        cid = self.canonical_id(app_name)
        if cid is None:
            return None
        if cid in BUILTIN_CATALOG:
            return dict(BUILTIN_CATALOG[cid], source="builtin")
        enrolled = self._load_enrolled()
        entry = enrolled.get(cid)
        if not entry or entry.get("revoked"):
            return None
        if verify_integrity and entry.get("executable") and entry.get("sha256"):
            exe_path = Path(entry["executable"])
            if not exe_path.is_file():
                raise HubError("APP_CATALOG_EXECUTABLE_MISSING", app=cid)
            if _is_reparse(exe_path):
                raise HubError("APP_CATALOG_LINK_FORBIDDEN", app=cid)
            actual = _file_sha256(exe_path)
            if actual != entry["sha256"]:
                raise HubError("APP_CATALOG_INTEGRITY_MISMATCH", app=cid)
        return {**entry, "source": "enrolled"}

    def enroll(
        self,
        *,
        app_id: str,
        executable: str,
        aumid: str | None = None,
        allow_electron: bool = False,
        require_signed: bool = False,
        note: str = "",
    ) -> dict[str, Any]:
        if not isinstance(app_id, str) or not APP_ID_RE.fullmatch(app_id):
            raise HubError("APP_CATALOG_ID_INVALID")
        if app_id in BUILTIN_CATALOG or app_id in BUILTIN_ALIASES:
            raise HubError("APP_CATALOG_BUILTIN_IMMUTABLE")
        if not isinstance(executable, str) or not Path(executable).is_absolute():
            raise HubError("APP_CATALOG_EXECUTABLE_INVALID")
        exe_path = Path(executable)
        if exe_path.suffix.casefold() != ".exe" or not exe_path.is_file():
            raise HubError("APP_CATALOG_EXECUTABLE_INVALID")
        if exe_path.name.casefold() in DISALLOWED_INTERPRETER_EXES:
            raise HubError("APP_CATALOG_INTERPRETER_FORBIDDEN", executable=exe_path.name)
        in_windows_apps = "windowsapps" in {p.casefold() for p in exe_path.parts}
        if not in_windows_apps and _is_reparse(exe_path):
            raise HubError("APP_CATALOG_LINK_FORBIDDEN")
        resolved = exe_path if in_windows_apps else exe_path.resolve()
        directory = resolved.parent
        is_electron = (
            (directory / "resources" / "app.asar").is_file()
            or (directory / "resources" / "app").is_dir()
            or (directory / "chrome_elf.dll").is_file()
            or any(directory.glob("chrome_*.pak"))
        )
        if is_electron and not allow_electron:
            raise HubError("APP_CATALOG_ELECTRON_REQUIRES_ISOLATION_OPT_IN")
        if in_windows_apps and not aumid:
            raise HubError("APP_CATALOG_AUMID_REQUIRED")
        digest = None if in_windows_apps else _file_sha256(resolved)
        sig = _authenticode_info(resolved)
        if require_signed and not sig.get("signed"):
            raise HubError("APP_CATALOG_SIGNATURE_REQUIRED", status=sig.get("status"))
        kind = "msix_packaged" if in_windows_apps else ("electron" if is_electron else "win32")
        route = "hidden_desktop_electron_isolated" if is_electron else "hidden_desktop_uia"
        record = {
            "app_id": app_id,
            "executable": str(resolved),
            "name": resolved.name,
            "kind": kind,
            "route": route,
            "sha256": digest,
            "aumid": aumid,
            "signature": sig,
            "enrolled_at": time.time(),
            "revoked": False,
            "note": str(note or "")[:300],
        }
        apps = self._load_enrolled()
        apps[app_id] = record
        self._save_enrolled(apps)
        return record

    def revoke(self, app_id: str) -> bool:
        apps = self._load_enrolled()
        entry = apps.get(app_id)
        if not entry or entry.get("revoked"):
            return False
        entry["revoked"] = True
        entry["revoked_at"] = time.time()
        self._save_enrolled(apps)
        return True

    def list_apps(self) -> dict[str, Any]:
        enrolled = self._load_enrolled()
        return {
            "schema": self.SCHEMA,
            "builtin": sorted(BUILTIN_CATALOG),
            "enrolled": {k: v for k, v in sorted(enrolled.items()) if not v.get("revoked")},
            "revoked": sorted(k for k, v in enrolled.items() if v.get("revoked")),
        }
