"""Two agents on one isolated Windows Bridge: cleanup cannot kill foreign work.

Real loopback RPC, actual nested Job Object child PIDs, independent birth-bound
process references. Never contacts, restarts, inspects or kills the user's
production agent, other apps, desktop or network services.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from isolated_rpc_smoke import free_port, rpc, verify

RUNTIME = Path(__file__).resolve().parents[2] / "runtime/bridge-v3"
sys.path.insert(0, str(RUNTIME))
from ff_win_process_identity import ProcessReference, process_creation_token


def wait_until(fn, failure, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(.05)
    raise RuntimeError(failure)


def main():
    verify(os.name == "nt", "WINDOWS_REQUIRED")
    with TemporaryDirectory(prefix="ff-2agents-owned-") as tmp:
        root = Path(tmp)
        bridge_root = root / "isolated-bridge"
        bridge_root.mkdir()
        fixture = root / "spawn_child.py"
        fixture.write_text(
            "import pathlib,subprocess,sys\n"
            "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(45)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='ascii')\n",
            encoding="utf-8",
        )
        port = free_port()
        env = {**os.environ, "FF_BRIDGE_ROOT": str(bridge_root)}
        server = subprocess.Popen(
            [sys.executable, str(RUNTIME / "ff_win_v3_main.py"),
             "serve", "--host", "127.0.0.1", "--port", str(port)],
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        owned_children = []
        try:
            secret_path = bridge_root / "bridge-v3/secret"
            def ready():
                verify(server.poll() is None, "ISOLATED_SERVER_EXITED")
                if not secret_path.is_file():
                    return False
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.25):
                        return True
                except OSError:
                    return False
            wait_until(ready, "ISOLATED_SERVER_NOT_READY")
            secret = secret_path.read_text("ascii").strip()
            device = platform.node()
            sessions = []
            for agent_id, task_id in (("agent-one", "job-one"), ("agent-two", "job-two")):
                marker = root / (agent_id + ".pid")
                # A constant executable and owned throwaway script, never a
                # model-supplied command and never a user desktop.
                command = f'& "{sys.executable}" "{fixture}" "{marker}"'
                started = rpc(port, secret, "start_process", {
                    "agent_id": agent_id, "task_id": task_id,
                    "command": command, "cwd": str(root), "shell": "powershell.exe",
                    "wait_ms": 200,
                }, "ci-start-" + agent_id)
                verify(started.get("ok") is True,
                       "SCOPED_SESSION_START_FAILED_" + agent_id)
                session_id = (started.get("result") or {}).get("session_id")
                verify(isinstance(session_id, str), "SCOPED_SESSION_ID_MISSING")
                # File existence precedes a finished write on Windows. A CI
                # runner may see the empty file for a few milliseconds, making
                # int("") raise ValueError despite a healthy child. Wait for
                # complete numeric contents and a real birth-bound handle.
                def child_reference():
                    try:
                        raw = marker.read_text(encoding="ascii").strip()
                        if not raw.isdecimal():
                            return None
                        pid = int(raw)
                        token = process_creation_token(pid)
                        if token is None:
                            return None
                        return ProcessReference(pid, token)
                    except (FileNotFoundError, PermissionError, ValueError, OSError):
                        return None
                child = wait_until(child_reference, "OWNED_CHILD_IDENTITY_NOT_READY")
                owned_children.append(child)
                sessions.append((agent_id, task_id, session_id, child))

            # Wait until both roots exit; direct non-detached descendants must
            # stay running until their own registered cleanup request.
            for agent_id, task_id, session_id, child in sessions:
                def completed():
                    response = rpc(port, secret, "read_process_output", {
                        "session_id": session_id, "agent_id": agent_id,
                        "task_id": task_id, "max_chars": 500,
                    }, "ci-read-" + agent_id)
                    verify(response.get("ok") is True, "SCOPED_ROOT_OUTPUT_FAILED")
                    result = response.get("result") or {}
                    return result.get("exit_code") == 0
                wait_until(completed, "SCOPED_ROOT_NOT_COMPLETED")
                verify(child.poll() is None, "OWNED_CHILD_NOT_ALIVE_BEFORE_CLEANUP")

            first = sessions[0]
            second = sessions[1]
            receipt_a = rpc(port, secret, "cleanup_sessions", {
                "agent_id": first[0], "task_id": first[1],
                "older_than_seconds": 0,
            }, "ci-clean-agent-one")
            verify(receipt_a.get("ok") is True, "AGENT_ONE_CLEANUP_FAILED")
            removed_a = (receipt_a.get("result") or {}).get("removed") or []
            verify(first[2] in removed_a and second[2] not in removed_a,
                   "CROSS_AGENT_SESSION_REMOVED")
            wait_until(lambda: first[3].poll() is not None,
                       "AGENT_ONE_CHILD_SURVIVED_CLEANUP")
            verify(second[3].poll() is None, "AGENT_TWO_CHILD_KILLED_BY_AGENT_ONE")
            receipt_b = rpc(port, secret, "cleanup_sessions", {
                "agent_id": second[0], "task_id": second[1],
                "older_than_seconds": 0,
            }, "ci-clean-agent-two")
            verify(receipt_b.get("ok") is True, "AGENT_TWO_CLEANUP_FAILED")
            removed_b = (receipt_b.get("result") or {}).get("removed") or []
            verify(second[2] in removed_b, "AGENT_TWO_SESSION_NOT_CLEANED")
            wait_until(lambda: second[3].poll() is not None,
                       "AGENT_TWO_CHILD_SURVIVED_CLEANUP")
            verify((receipt_a["result"]).get("scope_enforced") is True
                   and (receipt_b["result"]).get("scope_enforced") is True,
                   "CLEANUP_SCOPE_NOT_ENFORCED")
            print(json.dumps({
                "schema": "ff-two-agent-real-owned-job-v1", "all_passed": True,
                "independent_agent_job_scopes": 2,
                "foreign_child_preserved_until_owner_cleanup": True,
                "task_owned_children_terminated": 2,
                "no_user_desktop": True, "no_model_calls": True,
                "production_runtime_modified": False,
            }, sort_keys=True))
        finally:
            for child in owned_children:
                try:
                    if child.poll() is None:
                        child.terminate()  # exact PID+creation-time handle
                finally:
                    child.close()
            if server.poll() is None:
                server.terminate()  # only our own exact child process HANDLE
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("TWO_AGENT_JOB_SMOKE_FAILED:" + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
