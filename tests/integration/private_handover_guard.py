"""Verify the private Desktop handover guard on disposable loopback instances.

The optional --legacy-script runs the regression against an older source copy.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from seamless_handover import SERVER, free_port, rpc, verify, wait_ready

sys.path.insert(0, str(SERVER.parent))
from ff_win_process_identity import process_creation_token, process_identity_matches


def run(root, legacy):
    ports = set()
    while len(ports) < 3:
        ports.add(free_port())
    public, old_check, new_check = ports
    processes = []
    owned = []
    result = {"probe_completed": False, "production_touched": False, "source_sha256": {}}

    def launch(script, check_port, standby=False):
        cmd = [sys.executable, str(script), "serve", "--host", "127.0.0.1", "--port", str(public),
               "--also-listen", str(check_port)]
        if standby:
            cmd.append("--standby")
        proc = subprocess.Popen(cmd, env={**os.environ, "FF_BRIDGE_ROOT": str(root), "FF_DRAIN_LINGER_SECONDS": "3",
                                          "PYTHONDONTWRITEBYTECODE": "1"},
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        processes.append(proc)
        return proc

    def save_worker(reply):
        verify(reply.get("ok"), "HIDDEN_TEST_SESSION_NOT_OPEN")
        session = reply["result"]
        pid = session["worker_pid"]
        token = process_creation_token(pid)
        verify(token is not None, "WORKER_BIRTH_UNATTESTED")
        owned.append((pid, token))
        return session

    try:
        old_script = legacy or SERVER
        result["source_sha256"] = {"old_main": hashlib.sha256(old_script.read_bytes()).hexdigest(),
                                   "standby_main": hashlib.sha256(SERVER.read_bytes()).hexdigest()}
        old = launch(old_script, old_check)
        secret_file = root / "bridge-v3/secret"
        wait_ready(old, old_check, secret_file, "old")
        secret = secret_file.read_text().strip()
        start = {"command": "hidden_start", "worker_integrity": "medium"}
        session = save_worker(rpc(public, secret, "computer_use", start))
        health = {"command": "hidden_request", "session_id": session["session_id"], "request": {"command": "health"}}
        new = launch(SERVER, new_check, True)
        wait_ready(new, new_check, secret_file, "standby")

        if not legacy:
            standby_start = rpc(new_check, secret, "computer_use", start)
            verify(standby_start.get("error_code") == "HIDDEN_START_STANDBY", "STANDBY_ACCEPTED_HIDDEN_SESSION")
            caps = rpc(old_check, secret, "capabilities", {})["result"]["features"]["hidden_desktop_handover_guard"]
            verify(caps == {"version": 1, "active_hidden_sessions": 1, "requires_idle": True}, "HANDOVER_GUARD_NOT_ADVERTISED")
        drain = rpc(public, secret, "drain", {"standby_port": new_check})
        if legacy:
            verify(drain.get("ok"), "LEGACY_HANDOVER_FAILED")
            time.sleep(0.8)
            hidden = rpc(public, secret, "computer_use", health)
            deadline = time.monotonic() + 8
            while old.poll() is None and time.monotonic() < deadline:
                time.sleep(0.1)
            old_alive = process_identity_matches(*owned[0])
            result.update(probe_completed=True, deployment_safe=bool(hidden.get("ok") and old.poll() is None and old_alive),
                          hidden_request_error=hidden.get("error_code"), old_exited_with_private_session=old.poll() is not None,
                          old_worker_alive=old_alive)
        else:
            verify(drain.get("error_code") == "DRAIN_HIDDEN_SESSIONS_ACTIVE", "ACTIVE_PRIVATE_SESSION_NOT_PROTECTED")
            verify(drain["details"]["active_hidden_sessions"] == 1, "ACTIVE_PRIVATE_SESSION_COUNT")
            verify(rpc(new_check, secret, "ping", {})["result"]["standby_waiting"], "STANDBY_UNEXPECTEDLY_ADOPTED")
            verify(rpc(public, secret, "ping", {})["result"]["pid"] == old.pid, "OLD_LISTENER_MOVED_ON_DENIAL")
            verify(rpc(public, secret, "computer_use", health)["ok"] and process_identity_matches(*owned[0]),
                   "TASK_LOST_ON_DRAIN_DENIAL")
            close = {"command": "hidden_close", "session_id": session["session_id"]}
            closed = rpc(public, secret, "computer_use", close)
            verify(closed.get("ok") and closed["result"]["cleanup_verified"], "PRIVATE_SESSION_CLOSE_FAILED")
            verify(not process_identity_matches(*owned[0]), "CLOSED_PRIVATE_WORKER_ALIVE")
            idle_caps = rpc(old_check, secret, "capabilities", {})["result"]["features"]["hidden_desktop_handover_guard"]
            verify(idle_caps["active_hidden_sessions"] == 0, "HANDOVER_GUARD_IDLE_COUNT")

            idle = rpc(public, secret, "drain", {"standby_port": new_check})
            verify(idle.get("ok"), "IDLE_HANDOVER_REFUSED")
            old_after_drain = rpc(idle["result"]["private_port"], secret, "computer_use", start)
            verify(old_after_drain.get("error_code") == "HIDDEN_START_DRAINING", "DRAINING_CORE_ACCEPTED_HIDDEN_SESSION")
            deadline = time.monotonic() + 5
            while True:
                new_ping = rpc(public, secret, "ping", {})
                if new_ping["result"]["pid"] == new.pid:
                    break
                verify(time.monotonic() < deadline, "STANDBY_DID_NOT_TAKE_LISTENER")
                time.sleep(0.1)
            replacement = save_worker(rpc(public, secret, "computer_use", start))
            verify(replacement["session_id"] != session["session_id"], "HIDDEN_SESSION_REUSED_ACROSS_HANDOVER")
            close = {"command": "hidden_close", "session_id": replacement["session_id"]}
            closed = rpc(public, secret, "computer_use", close)
            verify(closed.get("ok") and closed["result"]["cleanup_verified"], "NEW_PRIVATE_SESSION_CLOSE_FAILED")
            result.update(probe_completed=True, active_handover_denied=True, active_session_preserved_on_denial=True,
                          idle_handover_succeeded=True, standby_and_draining_admission_denied=True, new_hidden_session_works=True)
    except Exception as exc:
        result["error"] = str(exc).replace(str(root), "<isolated>")
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=8)
        deadline = time.monotonic() + 5
        while any(process_identity_matches(*item) for item in owned) and time.monotonic() < deadline:
            time.sleep(0.1)
        result["owned_workers_closed"] = not any(process_identity_matches(*item) for item in owned)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-script", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    options.output.mkdir(exist_ok=False, parents=True)
    with tempfile.TemporaryDirectory(prefix="ff-private-handover-") as sandbox:
        result = run(Path(sandbox), options.legacy_script.resolve() if options.legacy_script else None)
    (options.output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return 0 if result["probe_completed"] and result["owned_workers_closed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
