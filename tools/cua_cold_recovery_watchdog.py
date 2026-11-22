"""Independent, fail-closed local watchdog for a previously authorized cold rollout.

Requires an explicit, immutable on-disk plan. Never silently authorizes an
upgrade or deletes a historical journal. On a failed candidate, it terminates
only the EXACT PID/creation-token pair from the plan, then restores the
verified snapshot IF no other runtime process is active.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "runtime/bridge-v3"))
import cua_cold_rollback_bundle as bundle
import ff_win_process_identity as identity

SCHEMA = "ff-bridge-rollback-watchdog/v1"
MAX_WAIT_SECONDS = 300
MAINTENANCE_LOCK_NAME = ".cua-cold-maintenance.lock"
MAINTENANCE_LOCK_TTL_SECONDS = 300
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _state(path: Path) -> dict:
    bundle._plain(path, must_file=True)
    if path.stat().st_size > 8192:
        raise RuntimeError("WATCH_STATE_OVERSIZED")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise RuntimeError("WATCH_STATE_INVALID") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise RuntimeError("WATCH_STATE_INVALID")
    if data.get("authorized_cold_rollout") is not True:
        raise RuntimeError("WATCH_NOT_AUTHORIZED")
    try:
        deadline = float(data["deadline_epoch"])
        port = data["port"]
        target = Path(data["runtime"])
        backup = Path(data["snapshot"])
        expected = data["candidate_agent_sha256"]
        old_expected = data["old_agent_sha256"]
    except (ValueError, TypeError, KeyError) as exc:
        raise RuntimeError("WATCH_STATE_INVALID") from exc
    isolated_drill = data.get("isolated_drill") is True
    if isolated_drill:
        live_default = Path(os.environ.get("LOCALAPPDATA", "")) / "FF-Windows-Bridge" / "bridge-v3"
        if port in (39073, 39076) or (live_default.exists() and target.resolve() == live_default.resolve()):
            raise RuntimeError("WATCH_DRILL_MUST_BE_ISOLATED")
        if type(data.get("peer_port")) is not int or data["peer_port"] == port:
            raise RuntimeError("WATCH_PEER_PORT_SCOPE_INVALID")
    elif (type(data.get("peer_port")) is not int
            or (port, data["peer_port"]) != (39073, 39076)):
        raise RuntimeError("WATCH_PEER_PORT_SCOPE_INVALID")
    if (type(port) is not int or not 1024 <= port <= 65535
            or not isinstance(expected, str) or len(expected) != 64
            or not isinstance(old_expected, str) or len(old_expected) != 64
            or any(c not in "0123456789abcdef" for c in expected + old_expected)
            or not target.is_absolute() or not backup.is_absolute()):
        raise RuntimeError("WATCH_STATE_INVALID")
    if (deadline < time.time() - MAX_WAIT_SECONDS
            or deadline > time.time() + MAX_WAIT_SECONDS):
        raise RuntimeError("WATCH_DEADLINE_OUT_OF_BOUNDS")
    bundle._plain(target)
    bundle._plain(backup)
    saved = bundle.verify_bundle(backup)
    if (data.get("source_head") != saved.get("source_head")
            or data.get("candidate_head") != saved.get("candidate_head")):
        raise RuntimeError("WATCH_SOURCE_IDENTITY_INVALID")
    if (str(data.get("source_head") or "").lower() in bundle.deploy.KNOWN_STALE_COMMITS
            or str(data.get("candidate_head") or "").lower() in bundle.deploy.KNOWN_STALE_COMMITS):
        raise RuntimeError("WATCH_SOURCE_COMMIT_STALE")
    old_agents = [x for x in saved["source_files"] if x["target"] == "ff_win_v3_agent.py"]
    candidate_agents = [x for x in saved["candidate_files"] if x["target"] == "ff_win_v3_agent.py"]
    if (len(old_agents) != 1 or len(candidate_agents) != 1
            or old_agents[0]["sha256"] != old_expected
            or candidate_agents[0]["sha256"] != expected):
        raise RuntimeError("WATCH_AGENT_HASH_UNPROVEN")
    if target.resolve() == backup.resolve() or backup.is_relative_to(target):
        raise RuntimeError("WATCH_PATHS_CONFLICT")
    for role in ("candidate", "keeper", "keeper_launcher"):
        _live_identity(data, role)
    return data


def _live_identity(state: dict, name: str) -> tuple[int, int] | None:
    pid, token = state.get(name + "_pid"), state.get(name + "_token")
    if pid is None and token is None:
        return None
    if type(pid) is not int or type(token) is not int or pid <= 0 or token <= 0:
        raise RuntimeError("WATCH_PROCESS_IDENTITY_INVALID:" + name)
    return pid, token


def _known_process_commandline(state: dict, name: str, pid: int) -> bool:
    """Independently prove the named PID launches the expected runtime file."""
    runtime = Path(state["runtime"]).resolve()
    aliases, _ = bundle.runtime_aliases(runtime, Path(state["runtime"]))
    command = (
        "$ErrorActionPreference='Stop'; "
        "$p=Get-CimInstance Win32_Process -Filter 'ProcessId=" + str(pid) + "'; "
        "if($null -eq $p){exit 3}; "
        "$p | Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress"
    )
    cp = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-Command", command],
                        capture_output=True, text=True, timeout=20, check=False)
    if cp.returncode != 0:
        raise RuntimeError("WATCH_PROCESS_COMMANDLINE_UNVERIFIABLE")
    try:
        result = json.loads(cp.stdout)
    except ValueError as exc:
        raise RuntimeError("WATCH_PROCESS_COMMANDLINE_UNVERIFIABLE") from exc
    if type(result.get("ProcessId")) is not int or result["ProcessId"] != pid:
        raise RuntimeError("WATCH_PROCESS_IDENTITY_UNVERIFIABLE")
    cmd = str(result.get("CommandLine") or "").casefold().replace('"', "").replace(chr(92), "/")
    exe = str(result.get("Name") or "").casefold()
    if name == "keeper_launcher":
        return (exe in {"powershell.exe", "pwsh.exe"}
                and "programdata/ff-windows-bridge/bridge-v3-keeper-launch.ps1" in cmd)
    script_names = ("ff_win_v3_main.py", "ff_win_v3_agent.py") if name == "candidate" else (
        "ff_win_v3_keeper.ps1",)
    expected_exe = {"python.exe"} if name == "candidate" else {"powershell.exe", "pwsh.exe"}
    return exe in expected_exe and any(
        (base + "/" + script_name) in cmd
        for base in aliases for script_name in script_names
    )


def _safe_terminate_known(state: dict, name: str) -> bool:
    """Terminate by the kernel object, never by a recycled PID."""
    pair = _live_identity(state, name)
    if pair is None:
        return False
    pid, token = pair
    if not identity.process_identity_matches(pid, token):
        return False  # Already exited or PID reused: do not kill a new process.
    if not _known_process_commandline(state, name, pid):
        raise RuntimeError("WATCH_PROCESS_PATH_NOT_OWNED:" + name)
    # Re-check the token after command-line inspection before acquiring handle.
    if not identity.process_identity_matches(pid, token):
        return False
    handle = identity.ProcessReference(pid, token)
    try:
        handle.terminate()
        for _ in range(30):
            if handle.poll() is not None:
                return True
            time.sleep(.1)
        raise RuntimeError("WATCH_TARGET_DID_NOT_EXIT:" + name)
    finally:
        handle.close()


def probe_agent(runtime: Path, port: int) -> dict | None:
    secret_file = runtime / "secret"
    bundle._plain(secret_file, must_file=True)
    secret = secret_file.read_text(encoding="utf-8").strip()
    if not secret:
        raise RuntimeError("WATCH_SECRET_MISSING")
    body = json.dumps({"op": "ping", "args": {}}).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:" + str(port) + "/rpc",
        data=body, headers={"Content-Type": "application/json", "X-FF3-Key": secret},
        method="POST",
    )
    try:
        with OPENER.open(req, timeout=2) as response:
            result = json.loads(response.read(65536))
            return result["result"] if result.get("ok") is True else None
    except (OSError, ValueError, TypeError, KeyError, urllib.error.URLError):
        return None


def _check_candidate(state: dict) -> bool:
    live = probe_agent(Path(state["runtime"]), state["port"])
    if live is None or live.get("agent_sha256") != state["candidate_agent_sha256"]:
        return False
    pair = _live_identity(state, "candidate")
    if pair is None or live.get("pid") != pair[0]:
        return False
    return identity.process_identity_matches(*pair)


def _write_maintenance_lock(runtime: Path, ttl_seconds: int = MAINTENANCE_LOCK_TTL_SECONDS) -> Path:
    lock_path = runtime / MAINTENANCE_LOCK_NAME
    now = int(time.time())
    payload = {
        "schema": "ff-cold-maintenance-lock/v1",
        "created_epoch": now,
        "expires_epoch": now + ttl_seconds,
        "ttl_seconds": ttl_seconds,
        "owner": "cua_cold_recovery_watchdog",
    }
    bundle._atomic_write(lock_path, (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
    return lock_path


def _clear_maintenance_lock(runtime: Path) -> None:
    lock_path = runtime / MAINTENANCE_LOCK_NAME
    try:
        if lock_path.is_file() and not lock_path.is_symlink():
            lock_path.unlink(missing_ok=True)
    except OSError:
        pass


def _start_original_keeper(state: dict) -> None:
    if state.get("isolated_drill") is True and state.get("keeper_task") is None:
        return
    task = state.get("keeper_task")
    if task != "FF-Bridge-V3-Keeper":
        raise RuntimeError("WATCH_KEEPER_TASK_NOT_ALLOWED")
    # Existing scheduled task is independent of the replaced runtime source.
    p = subprocess.run(["schtasks.exe", "/Run", "/TN", task],
                       capture_output=True, timeout=20, check=False)
    if p.returncode != 0:
        raise RuntimeError("WATCH_KEEPER_RESTART_FAILED")


def recover_failed_rollout(state: dict, *,
                           terminate=_safe_terminate_known,
                           restore=bundle.restore,
                           restart=_start_original_keeper) -> dict:
    """Fail closed on foreign processes, then restore verified source bytes."""
    runtime, snapshot = Path(state["runtime"]), Path(state["snapshot"])
    current = probe_agent(runtime, state["port"])
    if current and current.get("agent_sha256") == state["candidate_agent_sha256"]:
        raise RuntimeError("WATCH_CANDIDATE_ALREADY_HEALTHY")
    pair = _live_identity(state, "candidate")
    if current and (pair is None or current.get("pid") != pair[0]):
        raise RuntimeError("WATCH_UNKNOWN_AGENT_OWNS_PORT")
    _write_maintenance_lock(runtime)
    try:
        if state.get("keeper_launcher_pid") is not None or state.get("keeper_launcher_token") is not None:
            terminate(state, "keeper_launcher")
        terminate(state, "candidate")
        terminate(state, "keeper")
        # Even a correctly terminated planned PID is not proof that no unrelated
        # agent uses the shared installed directory.
        tp = None if state.get("isolated_drill") is True else state["port"]
        pp = None if state.get("isolated_drill") is True else state["peer_port"]
        bundle.assert_runtime_quiescent(runtime, target_port=tp,
                                        peer_port=pp)
        restored = restore(snapshot, runtime, offline_confirmed=True,
                           target_port=tp, peer_port=pp)
    finally:
        _clear_maintenance_lock(runtime)
    restart(state)
    return {"ok": True, "rollback": "restored", "rollback_executed": True,
            "files": restored["restored_files"],
            "pending_external_health_confirmation": True}


def _write_receipt(path: Path, data: dict) -> None:
    # Do not overwrite the immutable armed plan; store a separate receipt.
    receipt = path.with_suffix(".receipt.json")
    bundle._plain(receipt.parent)
    bundle._atomic_write(receipt, (json.dumps(data, sort_keys=True) + "\n").encode("utf-8"))


def run(path: Path, *, clock=time.time, sleep=time.sleep,
        ready=_check_candidate, recover=recover_failed_rollout) -> dict:
    state = _state(path)
    deadline = state["deadline_epoch"]
    streak = 0
    while clock() < deadline:
        if ready(state):
            streak += 1
            if streak >= 3:
                result = {"ok": True, "status": "candidate_ready", "rollback": False}
                _write_receipt(path, result)
                return result
        else:
            streak = 0
        sleep(1)
    # One last check before any destructive rollback action.
    if ready(state):
        result = {"ok": True, "status": "candidate_ready", "rollback": False}
        _write_receipt(path, result)
        return result
    try:
        recovery = recover(state)
        result = {"ok": True, "status": "rollback_performed", **recovery}
    except Exception as exc:
        result = {"ok": False, "status": "rollback_blocked",
                  "error": type(exc).__name__ + ":" + str(exc)}
    _write_receipt(path, result)
    return result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=("inspect", "watch"))
    p.add_argument("--state", required=True, type=Path)
    args = p.parse_args(argv)
    try:
        data = _state(args.state)
        if args.command == "inspect":
            result = {"ok": True, "schema": SCHEMA,
                      "deadline_epoch": data["deadline_epoch"],
                      "candidate_head": bundle.verify_bundle(Path(data["snapshot"]))["candidate_head"],
                      "no_effects": True}
        else:
            result = run(args.state)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["ok"] else 2
    except Exception as exc:
        print(json.dumps({"ok": False, "error": type(exc).__name__ + ":" + str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
