"""Bounded vendor CLI contract checks; no model call, GUI launch or raw credential output.

This is NOT an entitlement check. A present flag or successful login-status
request never proves that an actual AI task can be completed without charges.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable

def official_git_for_windows() -> Path | None:
    """Find official installed Git without executing an untrusted PATH candidate.

    Exact machine-wide location + valid Authenticode signature by the Git for
    Windows publisher are required. The version/task still need independent
    proof; this is only executable provenance for a bounded Git operation.
    """
    if os.name != "nt":
        return None
    for key in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(key)
        if not base:
            continue
        root = Path(base)
        path = root / "Git" / "cmd" / "git.exe"
        try:
            if not root.is_absolute() or root.is_symlink() or not path.is_file():
                continue
            if any(p.is_symlink() or getattr(p, "is_junction", lambda: False)()
                   for p in (root / "Git", root / "Git" / "cmd", path)):
                continue
            if root.resolve(strict=True) not in path.resolve(strict=True).parents:
                continue
            # Argument never comes from task input. Double single quotes for
            # PowerShell's literal string syntax; never run via cmd or shell.
            literal = str(path).replace("'", "''")
            statement = ("$s = Get-AuthenticodeSignature -LiteralPath '" + literal +
                         "'; if ($s.Status -eq 'Valid' -and " +
                         "$s.SignerCertificate.Subject -match 'CN=Johannes Schindelin') " +
                         "{ exit 0 } else { exit 7 }")
            # GitHub-hosted pwsh and some user shells inherit a PSModulePath
            # rooted in PowerShell 7. Windows PowerShell 5.1 must load its own
            # built-in security module or signature checks fail spuriously.
            native = Path(os.environ.get("WINDIR") or "C:/Windows")
            windows_modules = native / "System32" / "WindowsPowerShell" / "v1.0" / "Modules"
            environment = dict(os.environ)
            environment["PSModulePath"] = str(windows_modules)
            result = subprocess.run(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                 "-Command", statement],
                capture_output=True, timeout=12, env=environment,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                check=False,
            )
            if result.returncode == 0:
                return path
        except (OSError, subprocess.TimeoutExpired, ValueError):
            continue
    return None


BANNED_PATH_CHARS='\\r\\n"%!^&|<>'
_ALLOWED = {
    "cursor": ("cursor-agent", "agent.cmd"),
    "antigravity": ("agy", "bin/agy.exe"),
}


def _vendor_target(app: str, local_appdata: Path) -> tuple[str, Path] | None:
    # Only known official CLI entrypoints; unknown app names are not executable.
    key=str(app or "").strip().casefold()
    if "cursor" in key:
        return "cursor", local_appdata / "cursor-agent" / "agent.cmd"
    if "antigravity" in key or key=="agy":
        return "antigravity",local_appdata / "agy" / "bin" / "agy.exe"
    return None


def _allowed_path(root: Path, file: Path, kind: str) -> bool:
    if not root.is_absolute() or not file.is_file():
        return False
    if any(char in str(file) for char in '\r\n"%!^&|<>'):
        return False
    if file.suffix.casefold()!=(".cmd" if kind=="cursor" else ".exe"):
        return False
    try:
        real_root=root.resolve(strict=True)
        real_file=file.resolve(strict=True)
        if real_root not in real_file.parents:
            return False
        walk=file
        while walk!=root and walk!=walk.parent:
            if walk.is_symlink() or getattr(walk,"is_junction",lambda:False)():
                return False
            walk=walk.parent
        return walk==root and not root.is_symlink()
    except (OSError,RuntimeError,ValueError):
        return False


def _invoke(path: Path, kind: str, options: tuple[str,...],
            *, runner: Callable[..., Any], timeout_s: float) -> tuple[bool,str]:
    # Explicit safe command/argument set; no arbitrary user-supplied prompt.
    if options not in {
        ("--version",), ("--help",), ("status",), ("models",), ("models","--help"),
    }:
        return False,""
    if kind=="cursor":
        if options not in {("--version",),("--help",),("status",),("models",)}:
            return False,""
        # Trusted vendor-owned .cmd shim, bounded safe cmd.exe invocation.
        # Python on Windows invokes trusted .cmd shims correctly. The
        # fixed official path and fixed nonprompt arguments rule out arbitrary
        # shell fragments or attacker-chosen scripts.
        argv=[str(path),*options]
    else:
        argv=[str(path),*options]
    try:
        proc=runner(argv,capture_output=True,timeout=timeout_s,
                    creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0),
                    stdin=subprocess.DEVNULL,check=False)
        if proc.returncode!=0:
            return False,""
        # Some CLIs (notably Go's flag parser) print --help to stderr.
        # Never expose this raw text outside this module: status output may
        # include account email, workspace or organization names.
        stdout=proc.stdout if isinstance(proc.stdout,(bytes,bytearray)) else str(proc.stdout).encode()
        stderr=proc.stderr if isinstance(proc.stderr,(bytes,bytearray)) else str(proc.stderr).encode()
        output=(bytes(stdout)+b"\n"+bytes(stderr))[:32000]
        return True,output.decode("utf-8",errors="replace")
    except (OSError,subprocess.TimeoutExpired,ValueError):
        return False,""


def probe_vendor_cli(app: str, *, runner: Callable[...,Any]=subprocess.run,
                     local_appdata: Path | None=None,
                     timeout_s:float=6.0, include_auth_status:bool=False,
                     include_model_listing:bool=False) -> dict[str,Any]:
    """Safe, opt-in source and CLI capability evidence, no AI inference."""
    result:dict[str,Any]={
        "schema":"ff-cli-contract-v1","app_family":"unknown",
        "path_verified":False,"version":None,
        "help_checked":False,"service_auth":"not_checked",
        "models_list_checked":False,"observed_cursor_models":[],
        "observed_flags":[],"supported_by_help":[],
        "task_completed":False,"model_called":False,"paid_api_invoked":False,
        "authenticated_task_execution_verified":False,
        "quota_and_pricing_verified":False,
        "next_gate":"research_task_eligibility_and_entitlement",
    }
    root=local_appdata if local_appdata is not None else Path(os.environ.get("LOCALAPPDATA",""))
    if not isinstance(root,Path):root=Path(root)
    target=_vendor_target(app,root)
    if target is None:return result
    kind,path=target
    result["app_family"]=kind
    if not _allowed_path(root,path,kind):
        result["next_gate"]="official_cli_missing_or_untrusted_path"
        return result
    result["path_verified"]=True
    version_ok,version=_invoke(path,kind,("--version",),runner=runner,timeout_s=timeout_s)
    if version_ok:
        match=re.search(r"(?<!\d)(\d{1,4}\.\d{1,4}(?:\.\d{1,6})?)(?!\d)",version)
        result["version"]=match.group(1) if match else None
    help_ok,help_text=_invoke(path,kind,("--help",),runner=runner,timeout_s=timeout_s)
    result["help_checked"]=help_ok
    if help_ok:
        known={
            "headless_print":"--print",
            "plan_mode":"--mode",
            "output_json":"--output-format",
            "sandbox":"--sandbox",
        }
        result["supported_by_help"]=[key for key,flag in known.items() if flag in help_text]
        result["observed_flags"]=[flag for flag in known.values() if flag in help_text]
        if kind=="cursor":
            result["next_gate"]="verify_cursor_auth_model_entitlement_then_test_task"
        else:
            result["next_gate"]="verify_agy_auth_windows_sandbox_and_quota_then_test_task"
    if include_auth_status and kind=="cursor" and help_ok:
        status_ok,status=_invoke(path,kind,("status",),runner=runner,timeout_s=timeout_s)
        # Negative phrases MUST take precedence: "Not logged in" contains
        # "logged in" as a substring. Never infer positive auth from that.
        if status_ok and re.search(
                r"(?i)not\s+logged\s+in|unauthenticated|sign\s+in|login\s+required",status):
            result["service_auth"]="not_authenticated"
        elif status_ok and re.search(
                r"(?i)\blogged\s+in\b|\bauthenticated\b|\bsigned\s+in\b",status):
            result["service_auth"]="authenticated"
        else:
            result["service_auth"]="unknown"
        # Never return status stdout: it can contain personal email/team data.
    if include_model_listing and kind=="cursor" and help_ok:
        # This command enumerates vendor model names, not account quota. Its
        # raw output may contain personal metadata: return a tiny allowlist only.
        listed, output = _invoke(path, kind, ("models",), runner=runner,
                                 timeout_s=min(30.0, max(20.0, timeout_s)))
        result["models_list_checked"] = listed
        if listed:
            models = (
                ("composer-2.5", r"(?<![A-Za-z0-9_.-])composer[ .-]2[.]5(?![A-Za-z0-9_.-])"),
                ("grok-4.7", r"(?<![A-Za-z0-9_.-])grok[ .-]4[.]7(?![A-Za-z0-9_.-])"),
            )
            result["observed_cursor_models"] = [
                name for name, pattern in models if re.search(pattern, output, re.I)
            ]
    return result
