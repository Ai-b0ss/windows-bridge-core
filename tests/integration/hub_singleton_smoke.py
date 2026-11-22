"""Real concurrent ensure_running starts against one disposable state root.

Uses port 0 and retained exact process identities. No Bridge, browser, GUI,
credentials, installed state, external network or paid service is accessed.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "runtime" / "bridge-v3"))
import ff_hub
from ff_win_process_identity import ProcessReference, process_creation_token


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def main():
    if os.name != "nt":
        print("NOT_RUN: exact Windows process identities required")
        return 2
    processes, references = [], []
    captured = threading.Lock()
    launch = subprocess.Popen
    barrier = threading.Barrier(3)

    def retain_launch(*args, **kwargs):
        process = launch(*args, **kwargs)
        with captured:
            processes.append(process)
        return process

    with tempfile.TemporaryDirectory(prefix="ff-hub-singleton-") as directory:
        state = Path(directory) / "isolated-state"
        state.mkdir()
        (state / "config.json").write_text(json.dumps({"port": 0}), encoding="utf-8")

        def start(_):
            barrier.wait(timeout=10)
            return ff_hub.ensure_running(state, wait_seconds=25)

        try:
            with patch.object(ff_hub.subprocess, "Popen", retain_launch):
                with ThreadPoolExecutor(max_workers=3) as pool:
                    endpoints = list(pool.map(start, range(3)))
            identities = {(item["pid"], item["create_time"], item["port"]) for item in endpoints}
            require(len(identities) == 1, "CONCURRENT_CALLS_SELECTED_DIFFERENT_HUBS")
            endpoint = endpoints[0]
            require(0 < endpoint["port"] <= 65535 and endpoint["port"] not in {39073, 39076, 39090}, "NOT_RANDOM_ISOLATED_PORT")
            require(any(process.pid == endpoint["pid"] for process in processes), "ENDPOINT_IS_NOT_OWNED_CHILD")
            reference = ProcessReference(endpoint["pid"], endpoint["create_time"])
            references.append(reference)
            require(reference.poll() is None, "OWNED_HUB_NOT_LIVE")
            # Retain each exact child and wait for the competing startup attempts to exit.
            for process in processes:
                if process.pid != endpoint["pid"]:
                    require(process.wait(timeout=10) == 3, "COMPETING_HUB_DID_NOT_EXIT_AS_SINGLETON")
            require(sum(process.poll() is None for process in processes) == 1, "MULTIPLE_LIVE_HUBS")
            client = ff_hub.HubClient(state, timeout=5)
            require(client.call("capabilities")["schema"] == "ff-agent-hub-capabilities-v1", "HUB_CAPABILITIES_FAILED")
            require(client.call("hub_status")["browser_manager"]["running"] is False, "BROWSER_WAS_STARTED")
            with patch.object(ff_hub.subprocess, "Popen", retain_launch):
                require(ff_hub.ensure_running(state)["pid"] == endpoint["pid"], "HEALTHY_HUB_WAS_REPLACED")
            report = {"status": "PASS", "concurrent_calls": 3, "owned_start_attempts": len(processes),
                      "live_hubs": 1, "random_port": True, "capabilities": True, "browser_started": False}
        finally:
            # Never terminate by process name or a PID lookup. The retained reference verifies
            # the birth token and terminates on the same kernel object handle.
            for process in processes:
                if process.poll() is not None:
                    continue
                reference = next((item for item in references if item.pid == process.pid), None)
                if reference is None:
                    token = process_creation_token(process.pid)
                    require(token is not None, "OWNED_PROCESS_BIRTH_UNAVAILABLE")
                    reference = ProcessReference(process.pid, token)
                    references.append(reference)
                reference.terminate()
                process.wait(timeout=10)
            for reference in references:
                reference.close()
        require(all(process.poll() is not None for process in processes), "OWNED_PROCESS_LEFT_RUNNING")
        print(json.dumps({**report, "owned_processes_cleaned_up": True}))


if __name__ == "__main__":
    raise SystemExit(main())
