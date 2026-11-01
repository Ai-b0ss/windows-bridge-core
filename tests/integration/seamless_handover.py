"""REAL local proof of a seamless Bridge handover, entirely on throw-away loopback instances.

Run with: python tests/integration/seamless_handover.py

Old instance A owns the public port and a running session. Standby B shares the public port
(SO_REUSEADDR: the first listener keeps receiving) and answers on its own check port.
While 24 clients hammer the public port, A is told to `drain`: the public listener closes,
B takes every new connection, and A keeps serving its session through B's forwarding.
Fails if one request is lost, if the session output is not reachable, or if A leaves early.
Never touches a live user's Bridge.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import threading
from tempfile import TemporaryDirectory
import time
import urllib.error
import urllib.request

REPO = Path(__file__).resolve().parents[2]
SERVER = REPO / "runtime/bridge-v3/ff_win_v3_main.py"


def verify(check: bool, code: str):
    if not check:
        raise RuntimeError(code)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def rpc(port: int, secret: str, op: str, args: dict, timeout: float = 15) -> dict:
    body = json.dumps({"task_id": "handover", "target_device": platform.node(), "op": op, "args": args}).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}/rpc", data=body, method="POST",
                                     headers={"X-FF3-Key": secret, "Content-Type": "application/json"})
    try:
        with OPENER.open(request, timeout=timeout) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())


def launch(root: Path, public: int, also: list[int], linger: str) -> subprocess.Popen:
    env = {**os.environ, "FF_BRIDGE_ROOT": str(root), "FF_DRAIN_LINGER_SECONDS": linger}
    cmd = [sys.executable, str(SERVER), "serve", "--host", "127.0.0.1", "--port", str(public)]
    for port in also:
        cmd += ["--also-listen", str(port)]
    return subprocess.Popen(cmd, cwd=str(REPO), env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def wait_ready(proc: subprocess.Popen, port: int, secret_file: Path, name: str):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        verify(proc.poll() is None, name + "_EXITED_EARLY")
        if secret_file.is_file():
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                    return
            except OSError:
                pass
        time.sleep(.1)
    raise RuntimeError(name + "_NOT_READY")


def main() -> int:
    if os.name != "nt":
        print("Requires Windows", file=sys.stderr)
        return 2
    checks: list[str] = []
    with TemporaryDirectory(prefix="ff-handover-") as td:
        root = Path(td) / "agent"
        root.mkdir()
        secret_file = root / "bridge-v3/secret"
        public, a_check, b_check = free_port(), free_port(), free_port()
        a = launch(root, public, [a_check], "3")
        b = None
        try:
            wait_ready(a, public, secret_file, "A")
            secret = secret_file.read_text(encoding="utf-8").strip()
            pid_a = rpc(public, secret, "ping", {})["result"]["pid"]
            started = rpc(public, secret, "start_process", {
                "command": "Start-Sleep -Seconds 9; Write-Output SESSION-FINISHED", "cwd": str(REPO),
                "shell": "powershell.exe", "wait_ms": 200, "detached": False,
                "agent_id": "handover-agent", "task_id": "handover-long"})
            verify(started.get("ok") is True, "A_SESSION_START_FAILED_" + str(started.get("error_code")))
            session_id = started["result"]["session_id"]
            checks.append("old_instance_runs_session")

            # Standby shares the public port; the first listener (A) must keep every connection.
            b = launch(root, public, [b_check], "3")
            wait_ready(b, b_check, secret_file, "B")
            pid_b = rpc(b_check, secret, "ping", {})["result"]["pid"]
            verify(pid_b != pid_a, "STANDBY_NOT_SEPARATE_PROCESS")
            seen = {rpc(public, secret, "ping", {})["result"]["pid"] for _ in range(20)}
            verify(seen == {pid_a}, "STANDBY_STOLE_TRAFFIC_BEFORE_DRAIN")
            checks.append("standby_shares_port_without_taking_traffic")

            # Refusals: no standby / wrong standby / self.
            for bad, code in (({}, "DRAIN_STANDBY_PORT_REQUIRED"), ({"standby_port": free_port()}, "DRAIN_STANDBY_NOT_READY"),
                              ({"standby_port": a_check}, "DRAIN_STANDBY_NOT_READY")):
                answer = rpc(public, secret, "drain", bad)
                verify(answer.get("error_code") == code, "DRAIN_GUARD_" + code + "_" + str(answer.get("error_code")))
            verify(rpc(public, secret, "ping", {})["result"]["pid"] == pid_a, "REFUSED_DRAIN_CHANGED_OWNER")
            checks.append("drain_refused_without_a_verified_standby")

            # Hammer the public port across the handover; every request must succeed.
            stop = threading.Event()
            tally = {"ok": 0, "fail": [], "pids": set()}
            lock = threading.Lock()

            def hammer():
                while not stop.is_set():
                    try:
                        answer = rpc(public, secret, "ping", {}, timeout=10)
                        with lock:
                            if answer.get("ok") is True:
                                tally["ok"] += 1
                                tally["pids"].add(answer["result"]["pid"])
                            else:
                                tally["fail"].append(str(answer)[:120])
                    except Exception as exc:
                        with lock:
                            tally["fail"].append(type(exc).__name__ + ":" + str(exc)[:100])

            threads = [threading.Thread(target=hammer, daemon=True) for _ in range(24)]
            for thread in threads:
                thread.start()
            time.sleep(1.0)
            drained = rpc(public, secret, "drain", {"standby_port": b_check})
            verify(drained.get("ok") is True, "DRAIN_FAILED_" + str(drained))
            time.sleep(3.0)
            stop.set()
            for thread in threads:
                thread.join(15)
            verify(not tally["fail"], "REQUESTS_LOST_" + str(tally["fail"][:3]))
            verify(tally["ok"] > 100, "TOO_FEW_REQUESTS_" + str(tally["ok"]))
            verify(tally["pids"] == {pid_a, pid_b}, "HANDOVER_OWNERS_" + str(tally["pids"]) + " a=%s b=%s drained=%s a_alive=%s" % (pid_a, pid_b, drained, a.poll() is None))
            after = {rpc(public, secret, "ping", {})["result"]["pid"] for _ in range(20)}
            verify(after == {pid_b}, "NEW_CONNECTIONS_NOT_ON_STANDBY")
            checks.append("zero_lost_requests_%d_across_handover" % tally["ok"])
            checks.append("new_connections_go_to_standby")

            # The old session is still reachable through the public port (B forwards to A).
            verify(a.poll() is None, "OLD_INSTANCE_EXITED_WITH_LIVE_SESSION")
            first = rpc(public, secret, "read_process_output", {"session_id": session_id, "agent_id": "handover-agent", "task_id": "handover-long"})
            verify(first.get("ok") is True, "FORWARDED_READ_FAILED_" + str(first.get("error_code")))
            deadline = time.monotonic() + 30
            text = ""
            while time.monotonic() < deadline and "SESSION-FINISHED" not in text:
                answer = rpc(public, secret, "read_process_output", {"session_id": session_id, "agent_id": "handover-agent", "task_id": "handover-long"})
                text = json.dumps(answer)
                time.sleep(.5)
            verify("SESSION-FINISHED" in text, "SESSION_OUTPUT_LOST")
            checks.append("running_session_survives_and_is_readable_via_new_instance")

            # Unknown sessions stay a clean error, and the old instance leaves once idle.
            unknown = rpc(public, secret, "read_process_output", {"session_id": "0123456789abcdef", "agent_id": "handover-agent", "task_id": "handover-long"})
            verify(unknown.get("error_code") == "SESSION_NOT_FOUND", "UNKNOWN_SESSION_NOT_CLEAN")
            deadline = time.monotonic() + 30
            while a.poll() is None and time.monotonic() < deadline:
                time.sleep(.5)
            verify(a.poll() == 0, "OLD_INSTANCE_DID_NOT_EXIT_CLEANLY_%s" % a.poll())
            verify(rpc(public, secret, "ping", {})["result"]["pid"] == pid_b, "STANDBY_NOT_SERVING_AFTER_OLD_EXIT")
            checks.append("old_instance_exits_when_idle_and_standby_keeps_serving")
        finally:
            for proc in (a, b):
                if proc is not None and proc.poll() is None:
                    proc.kill()
    print(json.dumps({"all_passed": True, "checks": checks}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
