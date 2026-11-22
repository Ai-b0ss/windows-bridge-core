"""Real disposable Bridge + Hub HTTP processes, three agents, crash recovery.

Uses random loopback ports and a temporary root. No browser, GUI, installed
runtime, owner policy, credentials, external network or paid model is accessed.
Only Popen handles created by this test are terminated.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
PACKAGE = REPO / "runtime/bridge-v3"
sys.path.insert(0, str(PACKAGE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ff_hub import HubClient, HubError
from isolated_rpc_smoke import rpc


def verify(condition, code):
    if not condition:
        raise RuntimeError(code)


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=8)


def start(script, args, root):
    return subprocess.Popen([sys.executable, str(PACKAGE / script), *args], cwd=REPO,
                            env={**os.environ, "FF_BRIDGE_ROOT": str(root)},
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def start_hub(root):
    state = root / "state/hub"
    process = start("ff_hub.py", ["serve", "--port", "0", "--state-dir", str(state)], root)
    deadline = time.monotonic() + 25
    client = HubClient(state, timeout=2)
    while time.monotonic() < deadline:
        verify(process.poll() is None, "OWNED_HUB_EXITED")
        try:
            if client.endpoint()["pid"] == process.pid and client.call("capabilities"):
                return process
        except (HubError, OSError, ValueError):
            time.sleep(.1)
    stop(process)
    raise RuntimeError("OWNED_HUB_NOT_READY")


def main():
    if os.name != "nt":
        print("NOT_RUN: Windows Bridge process required")
        return 2
    with tempfile.TemporaryDirectory(prefix="ff-hub-bridge-test-") as directory:
        root = Path(directory)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        bridge = hub = None
        checks = []

        def start_bridge():
            process = start("ff_win_v3_main.py", ["serve", "--host", "127.0.0.1", "--port", str(port)], root)
            secret_file = root / "bridge-v3/secret"
            deadline = time.monotonic() + 25
            while time.monotonic() < deadline:
                verify(process.poll() is None, "OWNED_BRIDGE_EXITED")
                try:
                    if secret_file.is_file():
                        secret = secret_file.read_text(encoding="ascii").strip()
                        if rpc(port, secret, "ping", {}, "hub-smoke-ping").get("ok"):
                            return process, secret
                except (OSError, ValueError):
                    pass
                time.sleep(.1)
            stop(process)
            raise RuntimeError("OWNED_BRIDGE_NOT_READY")

        try:
            bridge, secret = start_bridge()
            disabled = rpc(port, secret, "hub", {"op": "capabilities"}, "hub-default-off")
            verify(disabled.get("error_code") == "HUB_FEATURE_DISABLED", "HUB_NOT_OFF_BY_DEFAULT")
            verify(not (root / "state/hub/endpoint.json").exists(), "DEFAULT_DISCOVERY_STARTED_HUB")
            checks.append("default_off_no_hub_process")
            # Local test fixture only; this never enables an installed runtime.
            (root / "state").mkdir(parents=True, exist_ok=True)
            (root / "state/universal-agent-runtime.json").write_text(
                json.dumps({"version": 1, "enabled": True}), encoding="utf-8")
            hub = start_hub(root)

            def call(op, args=None, session=None, key=None, expected=None):
                request = {"op": op, "args": args or {}}
                if session:
                    request.update(session_id=session["session_id"], session_secret=session["session_secret"])
                if key:
                    request["request_key"] = key
                response = rpc(port, secret, "hub", request, "hub-smoke-rpc")
                if expected:
                    verify(response.get("error_code") == expected, "EXPECTED_" + expected + "_GOT_" + str(response.get("error_code")))
                    return response
                verify(response.get("ok") is True, "HUB_RPC_" + op + "_" + str(response.get("error_code")))
                return response["result"]

            caps = rpc(port, secret, "capabilities", {}, "hub-live-discovery")["result"]
            verify(caps["features"]["universal_agent_runtime"]["enabled"] is True and "hub" in caps["operations"], "LIVE_HUB_DISCOVERY_MISSING")
            verify(call("capabilities")["schema"] == "ff-agent-hub-capabilities-v1", "HUB_CAPABILITIES_INVALID")
            checks.append("real_bridge_gateway_and_hub_discovery")
            sessions = [call("session_open", {"agent_id": name, "task_id": "isolated-hub-test"})
                        for name in ("agent-a", "agent-b", "agent-c")]
            with ThreadPoolExecutor(3) as pool:
                resources = list(pool.map(lambda item: call("resource_claim", {
                    "kind": "file", "key": str(root / ("agent-" + str(item[0]) + ".txt"))}, item[1], "claim-own-resource"), enumerate(sessions)))
            verify(len({resource["resource_id"] for resource in resources}) == 3, "AGENT_RESOURCES_COLLIDED")
            marker = "written-by-isolated-agent-c\n"
            written = rpc(port, secret, "write_file", {"path": resources[2]["key"], "content": marker,
                          "agent_id": "agent-c", "task_id": "isolated-hub-test"}, "hub-file-agent")
            verify(written.get("ok") is True and Path(resources[2]["key"]).read_bytes() == marker.encode(),
                   "FILE_AGENT_INDEPENDENT_READBACK_FAILED")
            call("resource_release", {"resource_id": resources[0]["resource_id"]}, sessions[1], "foreign-release-test", "RESOURCE_NOT_OWNED")
            call("resource_claim", {"kind": "file", "key": resources[0]["key"]}, sessions[1], "foreign-lock-test", "RESOURCE_BUSY")
            verify(call("resource_list", session=sessions[0])["resources"][0]["resource_id"] == resources[0]["resource_id"], "FOREIGN_ATTEMPT_CHANGED_OWNER")
            repeat = call("resource_claim", {"kind": "file", "key": resources[0]["key"]}, sessions[0], "claim-own-resource")
            verify(repeat.get("deduplicated") is True, "SAME_KEY_NOT_DEDUPLICATED")
            call("resource_claim", {"kind": "file", "key": str(root / "changed.txt")}, sessions[0], "claim-own-resource", "REQUEST_KEY_REUSED")
            checks.append("three_agent_ownership_negative_targets_and_deduplication")
            checks.append("file_agent_real_write_and_independent_bytes")
            original_hub_pid = hub.pid
            stop(bridge)
            bridge, secret = start_bridge()
            verify(call("hub_status")["pid"] == original_hub_pid, "BRIDGE_RESTART_REPLACED_HUB")
            verify(len(call("resource_list", session=sessions[0])["resources"]) == 1, "BRIDGE_RESTART_LOST_OWNERSHIP")
            checks.append("hub_survives_real_bridge_restart")
            # A waiting claim has a durable started entry. Kill ONLY this test's
            # Hub, then verify conservative unknown outcome with no replay.
            with ThreadPoolExecutor(1) as pool:
                pending = pool.submit(call, "resource_claim", {"kind": "file", "key": resources[0]["key"], "wait_seconds": 20}, sessions[1], "crash-during-wait")
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    state = call("request_status", {"request_key": "crash-during-wait"}, sessions[1])
                    if state["state"] == "started":
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError("WAITING_REQUEST_NOT_STARTED")
                stop(hub)
                try:
                    pending.result(timeout=15)
                    raise RuntimeError("LOST_REPLY_WAS_SUCCESS")
                except RuntimeError as exc:
                    verify("HUB_UNREACHABLE" in str(exc), "LOST_REPLY_NOT_REPORTED")
            hub = start_hub(root)
            state = call("request_status", {"request_key": "crash-during-wait"}, sessions[1])
            verify(state["state"] == "unknown" and state["automatic_replay"] is False, "CRASH_OUTCOME_NOT_UNKNOWN")
            call("resource_claim", {"kind": "file", "key": resources[0]["key"], "wait_seconds": 20}, sessions[1], "crash-during-wait", "REQUEST_OUTCOME_UNKNOWN")
            verify(call("resource_list", session=sessions[1])["resources"][0]["key"] == resources[1]["key"], "CRASH_REPLAY_ACQUIRED_FOREIGN_RESOURCE")
            checks.append("real_hub_crash_persistent_unknown_outcome_no_replay")
            for session in sessions:
                call("session_close", session=session, key="close-own-session")
            verify(call("hub_status")["sessions"] == [], "SESSION_CLEANUP_INCOMPLETE")
            checks.append("own_session_cleanup_after_recovery")
            print(json.dumps({"all_passed": True, "checks": checks, "no_user_desktop": True,
                              "browser_and_gui": "NOT_RUN"}, sort_keys=True))
        finally:
            stop(bridge)
            stop(hub)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("HUB_BRIDGE_SMOKE_FAILED: " + type(exc).__name__ + ": " + str(exc)[:180], file=sys.stderr)
        raise SystemExit(1)
