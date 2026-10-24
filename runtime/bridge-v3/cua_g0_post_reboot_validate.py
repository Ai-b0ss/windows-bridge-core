from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# The installed runtime uses embedded Python with a python313._pth file. In that
# mode the script directory is not automatically importable, so make the sibling
# runtime modules explicit before importing cua_release_manifest.
_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

try:
    from cua_release_manifest import RUNTIME_SOURCE_MAP
except ModuleNotFoundError:
    from tools.cua_release_manifest import RUNTIME_SOURCE_MAP

SCHEMA = "ff3-g0-post-reboot-validator/v1"
PORT = 39073
TASK_NAME = r"\FF-Bridge-V3-Keeper"
ROOT = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "FF-Windows-Bridge" / "bridge-v3"
BASELINE_PATH = ROOT / "G0_PRE_REBOOT_BASELINE.json"
REPORT_JSON = ROOT / "G0_POST_REBOOT_VALIDATION.json"
REPORT_TXT = ROOT / "G0_POST_REBOOT_VALIDATION.txt"

BINARY_GLOBS = {
    "browser_companion_host": "cua_browser_companion_host.exe",
    "uia3_sidecar": "cua_native_uia3_sidecar.exe",
    "wgc_probe": "**/cua_wgc_native_probe.exe",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git_blob_sha256(repo: Path, head: str, rel: str) -> str:
    cp = subprocess.run(
        ["git", "show", f"{head}:{rel}"],
        cwd=repo,
        capture_output=True,
        timeout=20,
        check=False,
    )
    if cp.returncode != 0:
        raise RuntimeError(f"GIT_BLOB_UNAVAILABLE:{rel}")
    return hashlib.sha256(cp.stdout).hexdigest()


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def run(argv: list[str], *, timeout: int = 30, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, text=True, encoding="utf-8", errors="replace",
                          capture_output=True, timeout=timeout, check=False)


def powershell_snapshot() -> dict[str, Any]:
    ps = r'''
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$ErrorActionPreference='Stop'
$os=Get-CimInstance Win32_OperatingSystem
$task=Get-ScheduledTask -TaskName 'FF-Bridge-V3-Keeper' -ErrorAction Stop
$info=Get-ScheduledTaskInfo -TaskName 'FF-Bridge-V3-Keeper' -ErrorAction Stop
$action=@($task.Actions)[0]
$triggers=@($task.Triggers | ForEach-Object {$_.CimClass.CimClassName})
$allProcesses=@(Get-CimInstance Win32_Process)
$activePids=@($allProcesses | ForEach-Object {[int]$_.ProcessId})
$processes=@($allProcesses | Where-Object {
  $_.Name -match '^(powershell|python|python3|node|explorer|cua_browser_companion_host|cua_native_uia3_sidecar|cua_wgc_native_probe)(\.exe)?$'
} | ForEach-Object {
  [pscustomobject]@{
    pid=[int]$_.ProcessId; ppid=[int]$_.ParentProcessId; name=[string]$_.Name;
    session_id=[int]$_.SessionId;
    created=if($_.CreationDate){$_.CreationDate.ToString('o')}else{$null};
    command_line=[string]$_.CommandLine
  }
})
$listener=Get-NetTCPConnection -State Listen -LocalPort 39073 -ErrorAction SilentlyContinue | Select-Object -First 1
$schedule=Get-Service Schedule
$result=[ordered]@{
  boot_time=$os.LastBootUpTime.ToString('o')
  user="$env:USERDOMAIN\$env:USERNAME"
  schedule_service=[string]$schedule.Status
  listener_pid=if($listener){[int]$listener.OwningProcess}else{$null}
  task=[ordered]@{
    state=[string]$task.State; enabled=[bool]$task.Settings.Enabled;
    user=[string]$task.Principal.UserId; logon_type=[string]$task.Principal.LogonType;
    run_level=[string]$task.Principal.RunLevel; multiple_instances=[string]$task.Settings.MultipleInstances;
    execution_time_limit=[string]$task.Settings.ExecutionTimeLimit;
    restart_count=[int]$task.Settings.RestartCount; restart_interval=[string]$task.Settings.RestartInterval;
    execute=[string]$action.Execute; arguments=[string]$action.Arguments;
    working_directory=[string]$action.WorkingDirectory;
    triggers=$triggers; last_run=if($info.LastRunTime){$info.LastRunTime.ToString('o')}else{$null};
    last_result=[uint32]$info.LastTaskResult
  }
  processes=$processes
  active_pids=$activePids
}
$result | ConvertTo-Json -Depth 8 -Compress
'''
    cp = run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=30)
    if cp.returncode != 0:
        raise RuntimeError("POWERSHELL_SNAPSHOT_FAILED:" + cp.stderr[-1000:])
    return json.loads(cp.stdout)


def request_json(path: str, *, key: str | None = None, payload: dict[str, Any] | None = None,
                 timeout: float = 6.0) -> tuple[int, dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    if key is not None:
        headers["X-FF3-Key"] = key
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=data, headers=headers,
                                 method="GET" if payload is None else "POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            body = {"raw": raw.decode("utf-8", "replace")}
        return exc.code, body


def rpc(key: str, op: str, args: dict[str, Any]) -> dict[str, Any]:
    status, body = request_json("/rpc", key=key, payload={"op": op, "target_device": platform.node(), "args": args})
    if status != 200:
        return {"ok": False, "http_status": status, "body": body}
    return body


def active_console_session_id() -> int | None:
    if os.name != "nt":
        return None
    value = int(ctypes.windll.kernel32.WTSGetActiveConsoleSessionId())
    return None if value == 0xFFFFFFFF else value


def process_groups(snapshot: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    groups = {"keeper": [], "agent": [], "relay": [], "launcher": [], "explorer": [], "fixture": []}
    for p in snapshot.get("processes", []):
        name = str(p.get("name") or "").lower()
        cmd = str(p.get("command_line") or "")
        low = cmd.lower()
        if name.startswith("powershell") and re.search(r'(?i)(?:^|\s)-File\s+"?[^"]*ff_win_v3_keeper[.]ps1"?(?:\s|$)', cmd):
            groups["keeper"].append(p)
        if name.startswith("python") and re.search(r'(?i)(?:^|\s)"?[^"]*ff_win_v3_main[.]py"?(?:\s|$)', cmd):
            groups["agent"].append(p)
        if name.startswith("node") and r"@wonderwhy-er\desktop-commander\dist\index.js" in low and re.search(r'(?i)(?:^|\s)remote(?:\s|$)', cmd):
            groups["relay"].append(p)
        if name.startswith("powershell") and re.search(r'(?i)(?:^|\s)-File\s+"?[^"]*bridge-v3-keeper-launch[.]ps1"?(?:\s|$)', cmd):
            groups["launcher"].append(p)
        if name == "explorer.exe":
            groups["explorer"].append(p)
        if any(mark in low for mark in ("ff3-legacy-parity-live", "cua_g5_vision_fixture", "cua_g2_uia_bounds")):
            groups["fixture"].append(p)
    return groups


def check_runtime_hashes(baseline: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    mismatches = []
    missing = []
    for rel, expected in baseline.get("runtime_files", {}).items():
        path = ROOT / rel
        if not path.is_file():
            missing.append(rel)
            continue
        actual = sha256(path)
        if actual != expected:
            mismatches.append({"path": rel, "expected": expected, "actual": actual})
    return not missing and not mismatches, {"checked": len(baseline.get("runtime_files", {})), "missing": missing, "mismatches": mismatches}


def find_binary(pattern: str) -> Path | None:
    hits = sorted(ROOT.glob(pattern))
    return next((p for p in hits if p.is_file()), None)


def probe_browser_companion(root: Path = ROOT) -> dict[str, Any]:
    module_path = root / "cua_browser_companion.py"
    if not module_path.is_file():
        return {"ok": False, "error": "BROWSER_COMPANION_MODULE_MISSING"}
    try:
        spec = importlib.util.spec_from_file_location("ff3_g0_browser_companion_probe", module_path)
        if spec is None or spec.loader is None:
            return {"ok": False, "error": "BROWSER_COMPANION_IMPORT_SPEC_FAILED"}
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        capabilities = module.BrowserCompanionClient(root).capabilities()
        ok = (
            capabilities.get("protocol_version") == 1
            and capabilities.get("downloads") is True
            and capabilities.get("native_messaging") is True
            and capabilities.get("physical_input") is False
        )
        return {"ok": bool(ok), "capabilities": capabilities}
    except Exception as exc:
        return {
            "ok": False,
            "error": str(getattr(exc, "code", None) or type(exc).__name__),
            "message": str(exc)[:500],
            "details": getattr(exc, "details", None),
        }


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def boot_changed(previous: str, current: str) -> bool:
    try:
        return parse_time(current) > parse_time(previous)
    except Exception:
        return current != previous


def classify_stale_sessions(session_items: list[dict[str, Any]], boot_time: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    boot_ms = int(parse_time(boot_time).timestamp() * 1000)
    stale: list[dict[str, Any]] = []
    unknown: list[dict[str, Any]] = []
    for item in session_items:
        created = item.get("created_at")
        if isinstance(created, bool) or not isinstance(created, (int, float)):
            unknown.append(item)
            continue
        if int(created) < boot_ms:
            stale.append(item)
    return stale, unknown


def task_result_acceptable(task: dict[str, Any], healthy_family: bool) -> tuple[bool, str]:
    result = int(task.get("last_result") or 0)
    state = str(task.get("state") or "")
    if result in (0, 267009):
        return True, "success_or_running"
    if result == 0x800710E0 and state.lower() == "running" and healthy_family:
        return True, "duplicate_start_refused_while_existing_instance_healthy"
    return False, f"unexpected_0x{result:08X}"


def analyze_launcher_log(
    lines: list[str],
    boot_time: str,
    *,
    window_seconds: int = 300,
    burst_threshold: int = 3,
) -> dict[str, Any]:
    boot = parse_time(boot_time)
    relevant: list[str] = []
    exit_times = []
    for line in lines:
        first = line.split(" ", 1)[0]
        try:
            stamp = parse_time(first)
        except Exception:
            continue
        if stamp < boot:
            continue
        relevant.append(line)
        if "keeper_exited" in line:
            exit_times.append(stamp)

    max_burst = 0
    left = 0
    for right, stamp in enumerate(exit_times):
        while left <= right and (stamp - exit_times[left]).total_seconds() > window_seconds:
            left += 1
        max_burst = max(max_burst, right - left + 1)

    return {
        "exit_count": len(exit_times),
        "max_burst": max_burst,
        "window_seconds": window_seconds,
        "burst_threshold": burst_threshold,
        "loop_detected": max_burst >= burst_threshold,
        "log_tail": relevant[-20:],
    }


def launcher_log_crash_profile(boot_time: str) -> dict[str, Any]:
    path = Path(r"C:\ProgramData\FF-Windows-Bridge\bridge-v3-keeper-launch.log")
    if not path.is_file():
        return {
            "exit_count": 0,
            "max_burst": 0,
            "window_seconds": 300,
            "burst_threshold": 3,
            "loop_detected": False,
            "log_tail": [],
        }
    lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    return analyze_launcher_log(lines, boot_time)


def prepare_baseline(repo: Path, output: Path) -> dict[str, Any]:
    repo = repo.resolve()
    head_cp = run(["git", "rev-parse", "HEAD"], cwd=repo)
    if head_cp.returncode != 0:
        raise RuntimeError("GIT_HEAD_UNAVAILABLE")
    head = head_cp.stdout.strip()
    dirty = run(["git", "status", "--porcelain"], cwd=repo).stdout.strip()
    if dirty:
        raise RuntimeError("WORKTREE_DIRTY")
    snap = powershell_snapshot()
    runtime_files: dict[str, str] = {}
    missing_source = []
    for src_rel, runtime_rel in RUNTIME_SOURCE_MAP.items():
        try:
            runtime_files[runtime_rel] = git_blob_sha256(repo, head, src_rel)
        except RuntimeError:
            missing_source.append(src_rel)
    if missing_source:
        raise RuntimeError("BASELINE_SOURCE_MISSING:" + ",".join(missing_source))
    binaries = {}
    for name, pattern in BINARY_GLOBS.items():
        path = find_binary(pattern)
        binaries[name] = None if path is None else {"path": str(path.relative_to(ROOT)), "sha256": sha256(path)}
    baseline = {
        "schema": SCHEMA + "/baseline",
        "prepared_at": datetime.now(timezone.utc).isoformat(),
        "boot_time": snap["boot_time"],
        "expected_head": head,
        "expected_protocol_version": 1,
        "runtime_files": runtime_files,
        "runtime_binaries": binaries,
    }
    atomic_json(output, baseline)
    return baseline


def refresh_runtime_baseline(repo: Path, baseline_path: Path) -> dict[str, Any]:
    repo = repo.resolve()
    baseline = json.loads(baseline_path.read_text(encoding="utf-8-sig"))
    if not baseline.get("boot_time"):
        raise RuntimeError("BASELINE_BOOT_TIME_MISSING")
    head_cp = run(["git", "rev-parse", "HEAD"], cwd=repo)
    if head_cp.returncode != 0:
        raise RuntimeError("GIT_HEAD_UNAVAILABLE")
    head = head_cp.stdout.strip()
    if run(["git", "status", "--porcelain"], cwd=repo).stdout.strip():
        raise RuntimeError("WORKTREE_DIRTY")
    runtime_files: dict[str, str] = {}
    missing_source: list[str] = []
    missing_runtime: list[str] = []
    mismatches: list[dict[str, str]] = []
    for src_rel, runtime_rel in RUNTIME_SOURCE_MAP.items():
        try:
            expected = git_blob_sha256(repo, head, src_rel)
        except RuntimeError:
            missing_source.append(src_rel)
            continue
        runtime_files[runtime_rel] = expected
        path = ROOT / runtime_rel
        if not path.is_file():
            missing_runtime.append(runtime_rel)
            continue
        actual = sha256(path)
        if actual != expected:
            mismatches.append({"path": runtime_rel, "expected": expected, "actual": actual})
    if missing_source:
        raise RuntimeError("BASELINE_SOURCE_MISSING:" + ",".join(missing_source))
    if missing_runtime or mismatches:
        details = {"missing": missing_runtime, "mismatches": mismatches}
        raise RuntimeError("RUNTIME_NOT_AT_HEAD:" + json.dumps(details, sort_keys=True))
    refreshed = dict(baseline)
    refreshed["expected_head"] = head
    refreshed["runtime_files"] = runtime_files
    refreshed["runtime_refreshed_at"] = datetime.now(timezone.utc).isoformat()
    atomic_json(baseline_path, refreshed)
    return refreshed


def validate(baseline_path: Path) -> dict[str, Any]:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8-sig"))
    snap = powershell_snapshot()
    groups = process_groups(snap)
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, details: Any = None) -> None:
        checks.append({"name": name, "ok": bool(ok), "details": details})

    add("boot_time_changed", boot_changed(str(baseline.get("boot_time")), str(snap.get("boot_time"))),
        {"before": baseline.get("boot_time"), "after": snap.get("boot_time")})

    active_session = active_console_session_id()
    explorer_sessions = {int(p.get("session_id", -1)) for p in groups["explorer"]}
    add("interactive_logon_present", active_session is not None and active_session in explorer_sessions,
        {"active_console_session": active_session, "explorer_sessions": sorted(explorer_sessions)})

    secret_path = ROOT / "secret"
    secret = secret_path.read_text(encoding="ascii").strip() if secret_path.is_file() else ""
    status, health = request_json("/health", key=secret or None)
    health_ok = status == 200 and bool(health.get("ok"))
    add("bridge_health", health_ok, {"http_status": status, "pid": health.get("pid")})

    missing_status, missing_auth = request_json("/health")
    wrong_status, wrong_auth = request_json("/health", key="g0-invalid-key")
    add("auth_fail_closed", missing_status == 403 and wrong_status == 403,
        {"missing": missing_status, "wrong": wrong_status,
         "missing_code": missing_auth.get("error_code"), "wrong_code": wrong_auth.get("error_code")})

    protocol_ok = health_ok and int(health.get("protocol_version", -1)) == int(baseline.get("expected_protocol_version", -2))
    add("protocol_version", protocol_ok, {"actual": health.get("protocol_version"), "expected": baseline.get("expected_protocol_version")})

    family_ok = len(groups["keeper"]) == 1 and len(groups["agent"]) == 1
    add("exactly_one_keeper_agent", family_ok,
        {"keeper_pids": [p["pid"] for p in groups["keeper"]], "agent_pids": [p["pid"] for p in groups["agent"]]})

    relay_ok = len(groups["relay"]) == 1
    add("relay_singleton", relay_ok, {"relay_pids": [p["pid"] for p in groups["relay"]]})

    listener_pid = snap.get("listener_pid")
    agent_pid = groups["agent"][0]["pid"] if len(groups["agent"]) == 1 else None
    add("listener_owned_by_agent", health_ok and listener_pid == agent_pid == health.get("pid"),
        {"listener_pid": listener_pid, "agent_pid": agent_pid, "health_pid": health.get("pid")})

    parent_ok = False
    parent_mode = "unresolved"
    if family_ok:
        keeper_pid = int(groups["keeper"][0]["pid"])
        agent_ppid = int(groups["agent"][0]["ppid"])
        keeper_ppid = int(groups["keeper"][0]["ppid"])
        launcher_pids = {int(p["pid"]) for p in groups["launcher"]}
        active_pids = {int(pid) for pid in snap.get("active_pids", [])}
        keeper_parent_ok = not launcher_pids or keeper_ppid in launcher_pids
        if agent_ppid == keeper_pid:
            parent_ok = keeper_parent_ok
            parent_mode = "agent_child_of_current_keeper"
        elif agent_ppid not in active_pids and health_ok:
            parent_ok = keeper_parent_ok
            parent_mode = "healthy_agent_survived_keeper_refresh"
    add("parent_ownership_reasonable", parent_ok, {"mode": parent_mode})

    task = snap.get("task", {})
    task_contract = (
        str(task.get("state", "")).lower() == "running"
        and bool(task.get("enabled"))
        and str(task.get("logon_type", "")).lower() == "interactive"
        and str(task.get("multiple_instances", "")).lower() == "ignorenew"
        and "bridge-v3-keeper-launch.ps1" in str(task.get("arguments", "")).lower()
        and str(snap.get("schedule_service", "")).lower() == "running"
    )
    add("scheduled_task_contract", task_contract, task)

    task_result_ok, task_result_reason = task_result_acceptable(task, family_ok and health_ok)
    add("scheduled_task_last_result", task_result_ok,
        {"value": task.get("last_result"), "hex": f"0x{int(task.get('last_result') or 0):08X}", "reason": task_result_reason})

    runtime_ok, runtime_details = check_runtime_hashes(baseline)
    add("runtime_source_sha_parity", runtime_ok, runtime_details)

    binary_details = {}
    binary_ok = True
    for name, expected in baseline.get("runtime_binaries", {}).items():
        if expected is None:
            binary_details[name] = {"ok": False, "reason": "missing_at_baseline"}
            binary_ok = False
            continue
        path = ROOT / expected["path"]
        ok = path.is_file() and sha256(path) == expected["sha256"]
        binary_details[name] = {"ok": ok, "path": expected["path"]}
        binary_ok = binary_ok and ok
    add("helper_binary_sha_parity", binary_ok, binary_details)

    cap = rpc(secret, "capabilities", {}) if secret else {"ok": False}
    ops = (cap.get("result") or {}).get("operations", []) if isinstance(cap.get("result"), dict) else []
    features = (cap.get("result") or {}).get("features", {}) if isinstance(cap.get("result"), dict) else {}
    add("capabilities_truthful", bool(cap.get("ok")) and "computer_use" in ops and bool(features.get("cua_semantic_control_plane")),
        {"ok": cap.get("ok"), "operation_count": len(ops), "semantic": features.get("cua_semantic_control_plane"),
         "legacy_physical_opt_in": features.get("legacy_physical_requires_explicit_opt_in")})

    companion = probe_browser_companion(ROOT)
    add("owner_chrome_companion_readiness", bool(companion.get("ok")), companion)

    sessions = rpc(secret, "list_sessions", {}) if secret else {"ok": False}
    session_items = (sessions.get("result") or {}).get("sessions", []) if isinstance(sessions.get("result"), dict) else []
    stale_sessions, unknown_sessions = classify_stale_sessions(session_items, str(snap.get("boot_time")))
    safe_session_details = [
        {
            "session_id": str(item.get("session_id") or ""),
            "running": bool(item.get("running")),
            "created_at": item.get("created_at"),
            "closed_at": item.get("closed_at"),
        }
        for item in stale_sessions + unknown_sessions
    ]
    add(
        "no_stale_sessions",
        bool(sessions.get("ok")) and not stale_sessions and not unknown_sessions,
        {
            "total_count": len(session_items),
            "pre_reboot_stale_count": len(stale_sessions),
            "unknown_timestamp_count": len(unknown_sessions),
            "problem_sessions": safe_session_details,
        },
    )

    streams = rpc(secret, "list_file_streams", {}) if secret else {"ok": False}
    stream_items = (streams.get("result") or {}).get("streams", []) if isinstance(streams.get("result"), dict) else []
    add("no_stale_streams", bool(streams.get("ok")) and len(stream_items) == 0,
        {"count": len(stream_items)})

    add("no_owned_fixture_leaks", len(groups["fixture"]) == 0,
        {"pids": [p["pid"] for p in groups["fixture"]]})

    crash_profile = launcher_log_crash_profile(str(snap.get("boot_time")))
    add(
        "no_startup_crash_loop",
        not bool(crash_profile["loop_detected"]),
        {
            "keeper_exits_since_boot": crash_profile["exit_count"],
            "max_exit_burst": crash_profile["max_burst"],
            "window_seconds": crash_profile["window_seconds"],
            "burst_threshold": crash_profile["burst_threshold"],
            "log_tail": crash_profile["log_tail"],
        },
    )

    overall = all(item["ok"] for item in checks)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall": "PASS" if overall else "FAIL",
        "expected_head": baseline.get("expected_head"),
        "current_boot_time": snap.get("boot_time"),
        "checks": checks,
    }


def write_report(result: dict[str, Any], json_path: Path, txt_path: Path) -> None:
    atomic_json(json_path, result)
    lines = [
        "G0 POST-REBOOT VALIDATION",
        f"generated_at: {result['generated_at']}",
        f"expected_head: {result.get('expected_head')}",
        f"current_boot_time: {result.get('current_boot_time')}",
        "",
    ]
    for item in result["checks"]:
        lines.append(f"{'PASS' if item['ok'] else 'FAIL'}  {item['name']}  {json.dumps(item.get('details'), ensure_ascii=False, sort_keys=True)}")
    lines.extend(["", f"OVERALL: {result['overall']}", ""])
    txt_path.parent.mkdir(parents=True, exist_ok=True)
    txt_path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="FF Bridge G0 validator with guarded baseline maintenance; never reboots or signs out.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--prepare-baseline", action="store_true")
    modes.add_argument("--refresh-runtime-baseline", action="store_true")
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--baseline", type=Path, default=BASELINE_PATH)
    parser.add_argument("--json-output", type=Path, default=REPORT_JSON)
    parser.add_argument("--text-output", type=Path, default=REPORT_TXT)
    ns = parser.parse_args()
    if platform.system().lower() != "windows":
        print(json.dumps({"ok": False, "error": "WINDOWS_ONLY"}))
        return 2
    try:
        if ns.prepare_baseline:
            if ns.repo is None:
                raise RuntimeError("--repo is required with --prepare-baseline")
            baseline = prepare_baseline(ns.repo, ns.baseline)
            print(json.dumps({"ok": True, "mode": "prepare-baseline", "path": str(ns.baseline),
                              "expected_head": baseline["expected_head"], "boot_time": baseline["boot_time"],
                              "runtime_files": len(baseline["runtime_files"])}, ensure_ascii=False))
            return 0
        if ns.refresh_runtime_baseline:
            if ns.repo is None:
                raise RuntimeError("--repo is required with --refresh-runtime-baseline")
            baseline = refresh_runtime_baseline(ns.repo, ns.baseline)
            print(json.dumps({"ok": True, "mode": "refresh-runtime-baseline", "path": str(ns.baseline),
                              "expected_head": baseline["expected_head"], "boot_time": baseline["boot_time"],
                              "runtime_files": len(baseline["runtime_files"])}, ensure_ascii=False))
            return 0
        result = validate(ns.baseline)
        write_report(result, ns.json_output, ns.text_output)
        print(json.dumps({"ok": result["overall"] == "PASS", "overall": result["overall"],
                          "json": str(ns.json_output), "text": str(ns.text_output),
                          "failed": [x["name"] for x in result["checks"] if not x["ok"]]}, ensure_ascii=False))
        return 0 if result["overall"] == "PASS" else 3
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

