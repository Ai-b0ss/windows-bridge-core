"""Actual isolated Bridge crash/restart, detached output, durable no-replay.

Only disposable loopback servers and one bounded PowerShell task are started.
No live installation, credentials, GUI, model, or remote transport is used.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from isolated_rpc_smoke import REPO, SERVER, free_port, rpc, verify


def start_bridge(root, port):
    process = subprocess.Popen(
        [sys.executable, str(SERVER), "serve", "--host", "127.0.0.1", "--port", str(port)],
        cwd=REPO, env={**os.environ, "FF_BRIDGE_ROOT": str(root)},
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        deadline = time.monotonic() + 20
        secret_path = root / "bridge-v3/secret"
        while time.monotonic() < deadline:
            verify(process.poll() is None, "TEST_BRIDGE_EXITED")
            if secret_path.is_file():
                try:
                    secret = secret_path.read_text(encoding="ascii").strip()
                    response = rpc(port, secret, "ping", {}, "restart-readiness")
                    if response.get("ok") is True:
                        return process, secret
                except (OSError, ValueError):
                    pass
            time.sleep(.1)
        raise RuntimeError("TEST_BRIDGE_NOT_READY")
    except BaseException:
        stop_bridge(process)
        raise


def stop_bridge(process):
    if process is None:
        return
    if process.poll() is None:
        process.kill()  # Popen retains the exact owned Windows process handle.
    process.wait(timeout=10)


def wait_file(path, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(.1)
    raise RuntimeError("OWNED_TASK_FILE_TIMEOUT")


def main():
    if os.name != "nt":
        print("Requires Windows", file=sys.stderr)
        return 2
    with TemporaryDirectory(prefix="ff-detached-restart-") as td:
        root = Path(td) / "agent"
        root.mkdir()
        effect, release, done = (Path(td) / name for name in ("effect.txt", "release", "done"))
        # Inline constant scriptblock uses the ordinary supported shell route;
        # an external .ps1 would depend on the runner's execution policy.
        # Data paths travel as quoted parameters, never interpolated source.
        script = (
            "param($Effect,$Release,$Done); "
            "$ErrorActionPreference='Stop'; "
            "Add-Content -LiteralPath $Effect -Value 'ONCE'; "
            "Write-Output 'BEFORE_RESTART'; "
            "$timer=[Diagnostics.Stopwatch]::StartNew(); "
            "while (-not (Test-Path -LiteralPath $Release) -and $timer.Elapsed.TotalSeconds -lt 40) "
            "{ Start-Sleep -Milliseconds 100 }; "
            "Write-Output 'AFTER_RESTART'; "
            "Set-Content -LiteralPath $Done -Value 'DONE'; exit 37"
        )
        quote = lambda path: "'" + str(path).replace("'", "''") + "'"
        command = "& { " + script + " } " + " ".join(quote(p) for p in (effect, release, done))
        request = {
            "request_key": "ci-detached-once",
            "op": "start_process",
            "args": {"command": command, "cwd": td, "shell": "powershell.exe",
                     "detached": True, "wait_ms": 100,
                     "agent_id": "ci-restart-agent", "task_id": "ci-restart-task"},
            "agent_id": "ci-restart-agent", "task_id": "ci-restart-task",
        }
        server = None
        child_started = False
        try:
            port = free_port()
            server, secret = start_bridge(root, port)
            response = rpc(port, secret, "durable_call", request, "restart-initial")
            verify(response.get("ok") is True, "INITIAL_DURABLE_RPC_FAILED")
            journal = response.get("result") or {}
            inner = journal.get("response") or {}
            verify(inner.get("ok") is True, "INITIAL_PROCESS_FAILED")
            started = inner.get("result") or {}
            sid = started.get("session_id")
            verify(isinstance(sid, str), "NO_SESSION_ID")
            child_started = True
            try:
                wait_file(effect)
            except RuntimeError:
                # This is ONLY this constant synthetic task's disposable log.
                # No user command, host config, or live log is read.
                log = root / "bridge-v3/state/detached_logs" / (sid + ".log")
                diagnostic = log.read_bytes()[-4000:].decode("utf-8", errors="replace") if log.is_file() else "MISSING_TEST_LOG"
                print(json.dumps({"owned_fixture_diagnostic": diagnostic.replace(td, "<TEST_ROOT>"),
                                  "initial_running": started.get("running"),
                                  "initial_exit_code": started.get("exit_code")}), file=sys.stderr)
                raise
            state_path = root / "bridge-v3/state/detached_sessions.json"
            state = json.loads(state_path.read_text(encoding="utf-8"))
            verify(type(state[sid].get("pid_creation_token")) is int, "NO_PERSISTED_BIRTH")
            original_pid = started["pid"]

            stop_bridge(server)
            server = None
            port = free_port()
            server, secret = start_bridge(root, port)
            output = rpc(port, secret, "read_process_output", {"session_id": sid}, "restart-read")
            restored = output.get("result") or {}
            verify(output.get("ok") is True and restored.get("pid") == original_pid
                   and restored.get("running") is True, "SESSION_NOT_RESTORED")

            duplicate = rpc(port, secret, "durable_call", request, "restart-duplicate")
            cached = duplicate.get("result") or {}
            verify(duplicate.get("ok") is True and cached.get("cached") is True,
                   "DURABLE_REQUEST_REPLAYED")
            verify((((cached.get("response") or {}).get("result") or {}).get("session_id")) == sid,
                   "DUPLICATE_STARTED_NEW_SESSION")
            verify(effect.read_text(encoding="utf-8-sig").splitlines() == ["ONCE"],
                   "EXTERNAL_EFFECT_REPEATED")
            release.write_text("release", encoding="ascii")
            wait_file(done)
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                response = rpc(port, secret, "read_process_output", {"session_id": sid}, "restart-final")
                result = response.get("result") or {}
                events = "".join(x["text"] for x in result.get("events", []))
                if not result.get("running", True) and "AFTER_RESTART" in events:
                    break
                time.sleep(.1)
            else:
                raise RuntimeError("RESTORED_OUTPUT_NOT_RECONCILED")
            verify("BEFORE_RESTART" in events, "EARLIER_OUTPUT_LOST")
            verify(result.get("exit_code") == 37 and result.get("exit_code_known") is True,
                   "RESTORED_NONZERO_EXIT_CODE_LOST")
            verify(effect.read_text(encoding="utf-8-sig").splitlines() == ["ONCE"],
                   "FINAL_EFFECT_NOT_ONCE")
            print(json.dumps({"schema": "ff-detached-restart-smoke-v1", "all_passed": True,
                              "real_bridge_restart": True, "same_process_restored": True,
                              "output_before_and_after_verified": True,
                              "actual_nonzero_exit_code_preserved": True,
                              "durable_duplicate_one_effect": True,
                              "scope": "isolated synthetic task; no host consent or GUI proof"}))
        finally:
            try:
                release.write_text("release", encoding="ascii")
                if child_started and effect.is_file():
                    wait_file(done, seconds=45)
                    # Give the bounded owned PowerShell time to close its log.
                    time.sleep(.5)
            finally:
                stop_bridge(server)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        code = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        print("DETACHED_RESTART_SMOKE_FAILED:" + code, file=sys.stderr)
        raise SystemExit(1)
