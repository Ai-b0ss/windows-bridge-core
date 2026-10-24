from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import re
import subprocess
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

TASK_NAME = r"\FF-Windows-Bridge-V3-Supervisor"
ACCEPTED_TASK_NAME = r"\FF-Bridge-V3-Keeper"
TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
ROOT = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "FF-Windows-Bridge" / "bridge-v3"
KEEPER = ROOT / "ff_win_v3_keeper.ps1"
LAUNCHER = ROOT / "cua-lifecycle-start.ps1"
SECRET = ROOT / "secret"
PORT = 39073
STARTUP_FALLBACK_FILENAME = "FF-Windows-Bridge-V3-Task.vbs"

LAUNCHER_TEMPLATE = r'''Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:LOCALAPPDATA 'FF-Windows-Bridge\bridge-v3'
$keeper = Join-Path $root 'ff_win_v3_keeper.ps1'
$keeperPidPath = Join-Path $root 'keeper.pid'
$secretPath = Join-Path $root 'secret'
$port = 39073

function Test-FF3KeeperAlive {
    if (-not (Test-Path -LiteralPath $keeperPidPath -PathType Leaf)) { return $false }
    try {
        $raw = (Get-Content -LiteralPath $keeperPidPath -Raw).Trim()
        if ($raw -notmatch '^\d+$') { return $false }
        $process = Get-CimInstance Win32_Process -Filter ("ProcessId = {0}" -f ([int]$raw)) -ErrorAction SilentlyContinue
        if ($null -eq $process -or -not $process.CommandLine) { return $false }
        if ([string]$process.Name -notmatch '(?i)^powershell(?:\.exe)?$') { return $false }
        $keeperPattern = '(?i)(?:^|\s)-File\s+"?' + [regex]::Escape($keeper) + '"?(?:\s|$)'
        return [bool]([string]$process.CommandLine -match $keeperPattern)
    } catch { return $false }
}

function Test-FF3Health {
    if (-not (Test-Path -LiteralPath $secretPath -PathType Leaf)) { return $false }
    try {
        $secret = (Get-Content -LiteralPath $secretPath -Raw).Trim()
        if (-not $secret) { return $false }
        $headers = @{ 'X-FF3-Key' = $secret }
        $response = Invoke-RestMethod -UseBasicParsing -Uri "http://127.0.0.1:$port/health" -Headers $headers -Method Get -TimeoutSec 2
        return [bool]$response.ok
    } catch { return $false }
}

if (-not (Test-Path -LiteralPath $keeper -PathType Leaf)) { throw "FF3_KEEPER_MISSING:$keeper" }

# Startup-folder launch remains a fallback. The scheduled task is delayed, so if
# Startup already produced a live keeper we exit harmlessly instead of spawning a
# duplicate watchdog.
if (Test-FF3KeeperAlive) { exit 0 }

Start-Process -FilePath 'powershell.exe' -ArgumentList @(
    '-NoLogo','-NoProfile','-WindowStyle','Hidden','-ExecutionPolicy','Bypass','-File',('"' + $keeper + '"')
) -WindowStyle Hidden

for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Seconds 1
    if ((Test-FF3KeeperAlive) -and (Test-FF3Health)) { exit 0 }
}
throw 'FF3_LIFECYCLE_HEALTH_TIMEOUT'
'''


def build_startup_fallback_vbs(task_name: str) -> str:
    if not task_name or any(ch in task_name for ch in ('"', "\r", "\n")):
        raise ValueError("INVALID_TASK_NAME")
    return (
        'Set shell = CreateObject("WScript.Shell")\r\n'
        f'shell.Run "schtasks.exe /Run /TN ""{task_name}""", 0, False\r\n'
    )


def startup_fallback_path() -> Path:
    appdata = os.environ.get("APPDATA", "").strip()
    if not appdata:
        appdata = str(Path.home() / "AppData" / "Roaming")
    return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / STARTUP_FALLBACK_FILENAME


def probe_startup_fallback(task_name: str, path: Path | None = None) -> dict[str, Any]:
    target = path or startup_fallback_path()
    expected = build_startup_fallback_vbs(task_name)
    try:
        ok = target.is_file() and target.read_bytes().decode("utf-8-sig") == expected
    except OSError:
        ok = False
    return {"ok": ok, "path": str(target), "task": task_name}


def ensure_startup_fallback(task_name: str, path: Path | None = None) -> dict[str, Any]:
    target = path or startup_fallback_path()
    before = probe_startup_fallback(task_name, target)
    if not before["ok"]:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(build_startup_fallback_vbs(task_name), encoding="utf-8", newline="")
    result = probe_startup_fallback(task_name, target)
    result["changed"] = not before["ok"]
    return result


def _windows_user() -> str:
    domain = os.environ.get("USERDOMAIN", "").strip()
    user = os.environ.get("USERNAME", "").strip() or getpass.getuser()
    if not user:
        raise RuntimeError("WINDOWS_USER_UNAVAILABLE")
    return f"{domain}\\{user}" if domain else user


def build_task_xml(user_id: str, launcher_path: Path = LAUNCHER) -> str:
    ET.register_namespace("", TASK_NS)
    task = ET.Element(f"{{{TASK_NS}}}Task", {"version": "1.4"})
    registration = ET.SubElement(task, f"{{{TASK_NS}}}RegistrationInfo")
    ET.SubElement(registration, f"{{{TASK_NS}}}Description").text = (
        "Persistent FF Windows Bridge v3 keeper supervisor. Starts after interactive logon and restarts on failure."
    )
    triggers = ET.SubElement(task, f"{{{TASK_NS}}}Triggers")
    logon = ET.SubElement(triggers, f"{{{TASK_NS}}}LogonTrigger")
    ET.SubElement(logon, f"{{{TASK_NS}}}Enabled").text = "true"
    ET.SubElement(logon, f"{{{TASK_NS}}}Delay").text = "PT10S"
    ET.SubElement(logon, f"{{{TASK_NS}}}UserId").text = user_id

    principals = ET.SubElement(task, f"{{{TASK_NS}}}Principals")
    principal = ET.SubElement(principals, f"{{{TASK_NS}}}Principal", {"id": "Author"})
    ET.SubElement(principal, f"{{{TASK_NS}}}UserId").text = user_id
    ET.SubElement(principal, f"{{{TASK_NS}}}LogonType").text = "InteractiveToken"
    ET.SubElement(principal, f"{{{TASK_NS}}}RunLevel").text = "HighestAvailable"

    settings = ET.SubElement(task, f"{{{TASK_NS}}}Settings")
    for key, value in (
        ("MultipleInstancesPolicy", "IgnoreNew"),
        ("DisallowStartIfOnBatteries", "false"),
        ("StopIfGoingOnBatteries", "false"),
        ("AllowHardTerminate", "true"),
        ("StartWhenAvailable", "true"),
        ("RunOnlyIfNetworkAvailable", "false"),
        ("AllowStartOnDemand", "true"),
        ("Enabled", "true"),
        ("Hidden", "true"),
        ("RunOnlyIfIdle", "false"),
        ("WakeToRun", "false"),
        ("ExecutionTimeLimit", "PT0S"),
        ("Priority", "6"),
    ):
        ET.SubElement(settings, f"{{{TASK_NS}}}{key}").text = value
    restart = ET.SubElement(settings, f"{{{TASK_NS}}}RestartOnFailure")
    ET.SubElement(restart, f"{{{TASK_NS}}}Interval").text = "PT1M"
    ET.SubElement(restart, f"{{{TASK_NS}}}Count").text = "999"

    actions = ET.SubElement(task, f"{{{TASK_NS}}}Actions", {"Context": "Author"})
    exec_node = ET.SubElement(actions, f"{{{TASK_NS}}}Exec")
    ET.SubElement(exec_node, f"{{{TASK_NS}}}Command").text = "powershell.exe"
    ET.SubElement(exec_node, f"{{{TASK_NS}}}Arguments").text = (
        f'-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{launcher_path}"'
    )
    ET.SubElement(exec_node, f"{{{TASK_NS}}}WorkingDirectory").text = str(launcher_path.parent)
    return ET.tostring(task, encoding="unicode", xml_declaration=False)


def _text(root: ET.Element, path: str) -> str | None:
    ns = {"t": TASK_NS}
    node = root.find(path, ns)
    return node.text if node is not None else None


def validate_task_xml(xml_text: str, expected_user: str, expected_launcher: Path = LAUNCHER) -> dict[str, Any]:
    root = ET.fromstring(xml_text.lstrip("\ufeff"))
    checks = {
        "trigger_user": _text(root, "./t:Triggers/t:LogonTrigger/t:UserId") == expected_user,
        "trigger_enabled": _text(root, "./t:Triggers/t:LogonTrigger/t:Enabled") in (None, "true"),
        "interactive_token": _text(root, "./t:Principals/t:Principal/t:LogonType") == "InteractiveToken",
        "highest_available": _text(root, "./t:Principals/t:Principal/t:RunLevel") == "HighestAvailable",
        "ignore_new": _text(root, "./t:Settings/t:MultipleInstancesPolicy") == "IgnoreNew",
        "start_when_available": _text(root, "./t:Settings/t:StartWhenAvailable") == "true",
        "no_execution_limit": _text(root, "./t:Settings/t:ExecutionTimeLimit") == "PT0S",
        "restart_interval": _text(root, "./t:Settings/t:RestartOnFailure/t:Interval") == "PT1M",
        "restart_count": _text(root, "./t:Settings/t:RestartOnFailure/t:Count") == "999",
        "command": (_text(root, "./t:Actions/t:Exec/t:Command") or "").lower() == "powershell.exe",
        "launcher": f'-File "{expected_launcher}"' in (_text(root, "./t:Actions/t:Exec/t:Arguments") or ""),
    }
    return {"ok": all(checks.values()), "checks": checks}


def _run(argv: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, timeout=timeout, check=False)


def _require_windows() -> None:
    if platform.system().lower() != "windows":
        raise RuntimeError("WINDOWS_ONLY")


def query_task_xml(task_name: str = TASK_NAME) -> str:
    _require_windows()
    cp = _run(["schtasks.exe", "/Query", "/TN", task_name, "/XML", "ONE"], timeout=20)
    if cp.returncode != 0:
        raise RuntimeError(f"TASK_QUERY_FAILED:{cp.stderr.strip()[:500]}")
    return cp.stdout


def validate_accepted_task_xml(xml_text: str, expected_user: str) -> dict[str, Any]:
    root = ET.fromstring(xml_text.lstrip("\ufeff"))
    restart_count = _text(root, "./t:Settings/t:RestartOnFailure/t:Count")
    try:
        restart_count_ok = int(restart_count or "0") >= 1
    except ValueError:
        restart_count_ok = False
    arguments = _text(root, "./t:Actions/t:Exec/t:Arguments") or ""
    checks = {
        "trigger_user": _text(root, "./t:Triggers/t:LogonTrigger/t:UserId") == expected_user,
        "trigger_enabled": _text(root, "./t:Triggers/t:LogonTrigger/t:Enabled") in (None, "true"),
        "interactive_token": _text(root, "./t:Principals/t:Principal/t:LogonType") == "InteractiveToken",
        "highest_available": _text(root, "./t:Principals/t:Principal/t:RunLevel") == "HighestAvailable",
        "ignore_new": _text(root, "./t:Settings/t:MultipleInstancesPolicy") == "IgnoreNew",
        "start_when_available": _text(root, "./t:Settings/t:StartWhenAvailable") == "true",
        "no_execution_limit": _text(root, "./t:Settings/t:ExecutionTimeLimit") == "PT0S",
        "restart_interval": bool(_text(root, "./t:Settings/t:RestartOnFailure/t:Interval")),
        "restart_count": restart_count_ok,
        "command": (_text(root, "./t:Actions/t:Exec/t:Command") or "").lower() == "powershell.exe",
        "keeper_launcher": "bridge-v3-keeper-launch.ps1" in arguments.lower(),
    }
    return {"ok": all(checks.values()), "checks": checks}


def accepted_task_launcher_path(xml_text: str) -> Path | None:
    root = ET.fromstring(xml_text.lstrip("\ufeff"))
    arguments = _text(root, "./t:Actions/t:Exec/t:Arguments") or ""
    match = re.search(r'(?i)(?:^|\s)-File\s+(?:"([^"]+)"|(\S+))', arguments)
    if not match:
        return None
    raw = match.group(1) or match.group(2)
    if not raw:
        return None
    return Path(os.path.expandvars(raw))


def probe_powershell_script(path: Path) -> dict[str, Any]:
    exists = path.is_file()
    result: dict[str, Any] = {"ok": False, "exists": exists, "parse_ok": False, "path": str(path)}
    if not exists or platform.system().lower() != "windows":
        return result
    path_literal = str(path).replace("'", "''")
    command = (
        f"$path='{path_literal}';"
        "$tokens=$null;$errors=$null;"
        "[void][System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors);"
        "if(@($errors).Count -eq 0){exit 0}else{exit 2}"
    )
    cp = _run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
        timeout=15,
    )
    result["parse_ok"] = cp.returncode == 0
    result["ok"] = bool(result["exists"] and result["parse_ok"])
    return result


def probe_accepted_task(user: str) -> dict[str, Any] | None:
    try:
        xml_text = query_task_xml(ACCEPTED_TASK_NAME)
    except Exception:
        return None
    contract = validate_accepted_task_xml(xml_text, user)
    if not contract["ok"]:
        return None
    launcher_path = accepted_task_launcher_path(xml_text)
    if launcher_path is None:
        return None
    launcher = probe_powershell_script(launcher_path)
    if not launcher["ok"]:
        return None
    return {"task": ACCEPTED_TASK_NAME, "contract": contract, "launcher": launcher}


def probe_health(timeout: float = 2.0) -> bool:
    if not SECRET.is_file():
        return False
    try:
        secret = SECRET.read_text(encoding="ascii").strip()
        if not secret:
            return False
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}/health", headers={"X-FF3-Key": secret})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
        return bool(payload.get("ok"))
    except Exception:
        return False


def install(wait_seconds: int = 35) -> dict[str, Any]:
    _require_windows()
    if not KEEPER.is_file():
        raise RuntimeError(f"KEEPER_MISSING:{KEEPER}")
    ROOT.mkdir(parents=True, exist_ok=True)
    user = _windows_user()
    accepted = probe_accepted_task(user)
    if accepted is not None and probe_health():
        startup = ensure_startup_fallback(accepted["task"])
        return {
            "ok": bool(startup["ok"]),
            "task": accepted["task"],
            "health": True,
            "contract": accepted["contract"],
            "startup_fallback": startup,
            "adopted_existing": True,
            "created": False,
        }
    LAUNCHER.write_text(LAUNCHER_TEMPLATE, encoding="utf-8", newline="\r\n")
    xml_text = build_task_xml(user)
    with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-16", newline="") as handle:
        temp_path = Path(handle.name)
        handle.write(xml_text)
    try:
        cp = _run(["schtasks.exe", "/Create", "/TN", TASK_NAME, "/XML", str(temp_path), "/F"], timeout=30)
        if cp.returncode != 0:
            raise RuntimeError(f"TASK_CREATE_FAILED:{cp.stderr.strip()[:1000]}")
    finally:
        temp_path.unlink(missing_ok=True)

    contract = validate_task_xml(query_task_xml(), user)
    if not contract["ok"]:
        raise RuntimeError(f"TASK_CONTRACT_MISMATCH:{json.dumps(contract['checks'], sort_keys=True)}")
    startup = ensure_startup_fallback(TASK_NAME)
    if not startup["ok"]:
        raise RuntimeError("STARTUP_FALLBACK_INSTALL_FAILED")

    run = _run(["schtasks.exe", "/Run", "/TN", TASK_NAME], timeout=20)
    if run.returncode != 0:
        raise RuntimeError(f"TASK_RUN_FAILED:{run.stderr.strip()[:1000]}")
    deadline = time.monotonic() + max(0, wait_seconds)
    while time.monotonic() < deadline:
        if probe_health():
            return {"ok": True, "task": TASK_NAME, "health": True, "contract": contract, "startup_fallback": startup}
        time.sleep(1)
    return {"ok": True, "task": TASK_NAME, "health": False, "contract": contract, "startup_fallback": startup, "status": "INSTALLED_HEALTH_UNPROVEN"}


def status() -> dict[str, Any]:
    _require_windows()
    user = _windows_user()
    health = probe_health()
    accepted = probe_accepted_task(user)
    if accepted is not None:
        startup = probe_startup_fallback(accepted["task"])
        return {
            "ok": bool(health and startup["ok"]),
            "task_exists": True,
            "task": accepted["task"],
            "health": health,
            "contract": accepted["contract"],
            "startup_fallback": startup,
            "adopted_existing": True,
        }
    try:
        contract = validate_task_xml(query_task_xml(), user)
        exists = True
    except Exception as exc:
        return {"ok": False, "task_exists": False, "health": health, "error": str(exc)}
    startup = probe_startup_fallback(TASK_NAME)
    return {
        "ok": bool(contract["ok"] and health and startup["ok"]),
        "task_exists": exists,
        "task": TASK_NAME,
        "health": health,
        "contract": contract,
        "startup_fallback": startup,
        "adopted_existing": False,
    }


def uninstall() -> dict[str, Any]:
    _require_windows()
    cp = _run(["schtasks.exe", "/Delete", "/TN", TASK_NAME, "/F"], timeout=20)
    # Deleting an already absent task is idempotent from the operator's perspective.
    LAUNCHER.unlink(missing_ok=True)
    startup_fallback_path().unlink(missing_ok=True)
    return {"ok": cp.returncode == 0, "returncode": cp.returncode, "stderr": cp.stderr.strip()[:500]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Install/verify persistent FF Bridge v3 interactive-logon lifecycle task")
    sub = parser.add_subparsers(dest="cmd", required=True)
    install_p = sub.add_parser("install")
    install_p.add_argument("--wait-seconds", type=int, default=35)
    sub.add_parser("status")
    sub.add_parser("uninstall")
    ns = parser.parse_args()
    try:
        result = install(ns.wait_seconds) if ns.cmd == "install" else status() if ns.cmd == "status" else uninstall()
    except Exception as exc:
        result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
