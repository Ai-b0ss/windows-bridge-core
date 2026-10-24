"""Pinned preparation recipes with health checks and resumable installation."""
from __future__ import annotations
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
from cua_global_resources import _StateLock, GlobalResourceError

VERSION = "0.8.5"
class ToolPreparationError(RuntimeError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code

def _run(argv, *, timeout, code, env=None):
    try:
        return subprocess.run(argv, capture_output=True, text=True,
                              errors="replace", timeout=timeout, env=env,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired as exc:
        raise ToolPreparationError(code + "_TIMEOUT") from exc
    except OSError as exc:
        raise ToolPreparationError(code + "_UNAVAILABLE") from exc

def _health(root):
    python = root / "Scripts" / "python.exe"
    exe = root / "Scripts" / "windows-mcp.exe"
    if not python.is_file() or not exe.is_file():
        return False
    env = dict(os.environ, ANONYMIZED_TELEMETRY="false", WINDOWS_MCP_WATCHDOG="off")
    try:
        metadata = _run([str(python), "-I", "-c",
                        "import json,sys;from importlib.metadata import version;"
                        "print(json.dumps({'version':version('windows-mcp'),"
                        "'python':list(sys.version_info[:2])}))"],
                        timeout=10, code="TOOL_HEALTHCHECK", env=env)
        if metadata.returncode != 0:
            return False
        info = json.loads(metadata.stdout)
        if info != {"version": VERSION, "python": [3, 13]}:
            return False
        probe = _run([str(exe), "--help"], timeout=20, code="TOOL_HEALTHCHECK", env=env)
        return probe.returncode == 0 and "serve" in probe.stdout
    except (ToolPreparationError, ValueError):
        return False

def _python_health(python):
    if not python.is_file():
        return False
    try:
        probe = _run([str(python), "-I", "-c",
                      "import sys;print('.'.join(map(str,sys.version_info[:2])))"],
                     timeout=10, code="PYTHON_HEALTHCHECK")
        return probe.returncode == 0 and probe.stdout.strip() == "3.13"
    except ToolPreparationError:
        return False

def _quarantine(root):
    if root.is_symlink() or (getattr(root, "is_junction", lambda: False)()):
        raise ToolPreparationError("TOOL_ENVIRONMENT_LINK_FORBIDDEN")
    if not root.exists():
        return None
    saved = root.with_name(root.name + ".quarantine-" + uuid.uuid4().hex)
    root.rename(saved)
    return str(saved)

def _source_python():
    python = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Python" / "Python313" / "python.exe"
    if not python.is_file():
        launcher = shutil.which("py")
        if not launcher:
            raise ToolPreparationError("PYTHON_313_NOT_INSTALLED")
        result = _run([launcher, "-3.13", "-c", "import sys;print(sys.executable)"],
                      timeout=10, code="PYTHON_DISCOVERY")
        if result.returncode != 0:
            raise ToolPreparationError("PYTHON_313_NOT_INSTALLED")
        python = Path(result.stdout.strip())
        if not python.is_file():
            raise ToolPreparationError("PYTHON_313_NOT_INSTALLED")
    return python

def prepare_windows_mcp(base: str | Path | None = None):
    base = Path(base) if base else Path(os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")) / "FFWindowsBridge" / "tools"
    root = base / ("windows-mcp-" + VERSION)
    try:
        # Dedicated kernel lock also releases after the installer process dies.
        with _StateLock(base / "windows-mcp-preparation.lock"):
            healthy = _health(root)
            repaired = False
            recovery_steps = []
            quarantined = None
            if not healthy:
                uv = shutil.which("uv")
                if not uv:
                    raise ToolPreparationError("UV_NOT_INSTALLED")
                python = root / "Scripts" / "python.exe"
                if not _python_health(python):
                    # Discover a usable source before preserving the broken environment.
                    source = _source_python()
                    if not _python_health(source):
                        raise ToolPreparationError("PYTHON_313_UNHEALTHY")
                    quarantined = _quarantine(root)
                    recovery_steps.append("interpreter_rebuilt" if quarantined else "fresh_environment")
                    proc = _run([uv, "--no-config", "venv", "--python", str(source), str(root)],
                                timeout=180, code="TOOL_VENV")
                    if proc.returncode != 0:
                        raise ToolPreparationError("TOOL_VENV_FAILED")
                install = [uv, "--no-config", "pip", "install", "--python", str(python),
                           "--index-url", "https://pypi.org/simple", "--link-mode", "copy"]
                proc = _run([*install, "--reinstall-package", "windows-mcp", "windows-mcp==" + VERSION],
                            timeout=180, code="TOOL_INSTALL")
                if proc.returncode != 0:
                    raise ToolPreparationError("TOOL_INSTALL_FAILED")
                if not _health(root):
                    # A valid interpreter can still have damaged files in dependencies.
                    proc = _run([*install, "--reinstall", "windows-mcp==" + VERSION],
                                timeout=180, code="TOOL_DEPENDENCY_REPAIR")
                    if proc.returncode != 0:
                        raise ToolPreparationError("TOOL_DEPENDENCY_REPAIR_FAILED")
                    recovery_steps.append("dependencies_reinstalled")
                    if not _health(root):
                        raise ToolPreparationError("TOOL_HEALTHCHECK_FAILED")
                repaired = True
    except GlobalResourceError as exc:
        raise ToolPreparationError("TOOL_PREPARATION_BUSY") from exc
    except OSError as exc:
        raise ToolPreparationError("TOOL_STORAGE_UNAVAILABLE") from exc
    return {"tool": "windows-mcp", "version": VERSION,
            "path": str(root / "Scripts" / "windows-mcp.exe"), "health": "healthy",
            "reused": healthy, "installed_or_repaired": repaired,
            "recovery_steps": recovery_steps, "preserved_environment": quarantined,
            "installation_scope": "isolated_venv", "autostart_installed": False,
            "server_started": False, "recommended_tools": ["FileSystem", "Snapshot", "WaitFor"],
            "official_source": "https://github.com/CursorTouch/Windows-MCP"}

APP_DOCUMENTATION = {
    "cursor": {"cli_aliases": ["agent", "cursor-agent", "cursor"],
               "official_docs": ["https://cursor.com/docs/cli/installation", "https://cursor.com/docs/cli/headless"],
               "native_windows_cli_available": True, "auth_required_for_agent": True},
    "excel": {"official_docs": ["https://support.microsoft.com/en-us/excel/copilot/frequently-asked-questions-about-copilot-in-excel"],
              "assistant_requires_installed_session_and_entitlement": True, "com_is_not_assistant": True},
    "antigravity": {"cli_aliases": ["agy", "antigravity"],
                   "official_docs": ["https://antigravity.google/docs/cli/headless/", "https://antigravity.google/docs/cli/install/"],
                   "preferred_mode": "headless_cli"},
    "windowsmcp": {"cli_aliases": ["windows-mcp"],
                  "official_docs": ["https://github.com/CursorTouch/Windows-MCP"],
                  "preparation_recipe": "windows-mcp-0.8.5"},
}
def documentation_for(app):
    key = "".join(c for c in app.casefold() if c.isalnum())
    return APP_DOCUMENTATION.get(key, {"official_docs": [], "next_step": "research_official_documentation_before_gui"})
