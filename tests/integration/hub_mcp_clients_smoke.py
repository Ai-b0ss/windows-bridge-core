"""Three independent stdio clients, real Hub/terminal crash recovery.

This is a protocol test, NOT three model providers. Uses only owned processes,
random ports and test files. No production Bridge, browser or desktop changes.
"""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from hub_bridge_rpc_smoke import PACKAGE, start_hub, stop, verify
sys.path.insert(0, str(PACKAGE))
from ff_hub_permissions import Policy


class MCP:
    def __init__(self, state, agent):
        self.process = subprocess.Popen([sys.executable, str(PACKAGE / "ff_hub_mcp.py"),
                                         "--state-dir", str(state), "--agent", agent],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, encoding="utf-8")
        self.sequence = 0
        self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "protocol-smoke", "version": "1"}})
        verify(self.rpc("tools/list")["result"]["tools"][0]["name"] == "hub", "TOOL_NOT_DISCOVERED")

    def rpc(self, method, params=None):
        self.sequence += 1
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.sequence, "method": method,
                                            "params": params or {}}) + "\n")
        self.process.stdin.flush()
        return json.loads(self.process.stdout.readline())

    def call(self, op, args=None, key=None, expect=None):
        result = self.rpc("tools/call", {"name": "hub", "arguments": {"op": op, "args": args or {},
                                           "task_id": "mcp-smoke", **({"request_key": key} if key else {})}})["result"]
        value = json.loads(result["content"][0]["text"])
        if expect:
            verify(result["isError"] and value.get("error_code") == expect, "EXPECTED_" + expect + "_GOT_" + str(value))
        else:
            verify(not result["isError"], str(value))
        return value

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                stop(self.process)
        self.process.stdout.close()
        self.process.stderr.close()


def main():
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="ff-hub-mcp-") as directory:
        root = Path(directory)
        state = root / "state/hub"
        hub = start_hub(root)
        clients = []
        try:
            policy = Policy(state / "policy.json")
            policy.add_grant(["project_write"], agents=["mcp-a", "mcp-b", "mcp-c"], paths=[str(root)])
            grant = policy.add_grant(["terminal_execute"], agents=["mcp-a", "mcp-b", "mcp-c"],
                                     paths=[str(root)], apps=[sys.executable])
            clients = [MCP(state, "mcp-" + name) for name in ("a", "b", "c")]
            def work(index):
                client = clients[index]
                client.call("session_open")
                path = root / (str(index) + ".txt")
                write = {"command": "write", "path": str(path), "text": str(index), "expected_sha256": None}
                client.call("files", write, "file-write-0001")
                verify(client.call("files", write, "file-write-0001")["deduplicated"], "FILE_NOT_DEDUPED")
                job = client.call("terminal", {"command": "start", "argv": [sys.executable, "-c",
                    "import time;from pathlib import Path;time.sleep(2);p=Path('effect-" + str(index) + "');p.write_text('once');print('done')"],
                    "cwd": str(root)}, "terminal-start-0001")
                return job["terminal_id"]
            with ThreadPoolExecutor(max_workers=3) as pool:
                jobs = list(pool.map(work, range(3)))
            clients[1].call("files", {"command": "read", "path": str(root / "0.txt")}, expect="RESOURCE_BUSY")
            clients[1].call("terminal", {"command": "cancel", "terminal_id": jobs[0]}, "foreign-cancel-0001", expect="RESOURCE_NOT_OWNED")
            old_pid = hub.pid
            hub.kill()
            hub.wait(timeout=10)
            hub = start_hub(root)
            verify(hub.pid != old_pid, "HUB_NOT_RESTARTED")
            for index, client in enumerate(clients):
                client.call("session_resume")
                deadline = time.monotonic() + 15
                while True:
                    status = client.call("terminal", {"command": "status", "terminal_id": jobs[index]})
                    if status["state"] == "completed":
                        break
                    verify(time.monotonic() < deadline, "TERMINAL_NOT_RECOVERED")
                    time.sleep(.05)
                verify(status["cleanup_verified"] and status["exit_code"] == 0, "TERMINAL_EFFECT_FAILED")
                verify((root / ("effect-" + str(index))).read_text() == "once", "SIDE_EFFECT_NOT_EXACTLY_ONCE")
                replay = client.call("terminal", {"command": "start", "argv": [sys.executable, "-c",
                    "import time;from pathlib import Path;time.sleep(2);p=Path('effect-" + str(index) + "');p.write_text('once');print('done')"],
                    "cwd": str(root)}, "terminal-start-0001")
                verify(replay["deduplicated"] and replay["terminal_id"] == jobs[index], "REPLAY_CREATED_DUPLICATE")
            policy.revoke(grant["grant_id"])
            clients[0].call("terminal", {"command": "start", "argv": [sys.executable, "-c", "print('denied')"],
                           "cwd": str(root)}, "revoked-terminal-0001", expect="PERMISSION_REQUIRED")
            for client in clients:
                verify(client.call("session_close")["cleanup_verified"], "CLEANUP_UNCONFIRMED")
            print(json.dumps({"all_passed": True, "independent_mcp_clients": 3, "model_providers": 0,
                              "file_and_terminal_isolation": True, "hard_hub_crash_recovery": True,
                              "same_key_no_duplicate": True, "revocation_after_restart": True,
                              "elapsed_seconds": round(time.monotonic() - started, 3), "completed_terminal_jobs": 3}))
        finally:
            for client in clients:
                try:
                    client.call("session_close")
                except Exception:
                    pass
                client.close()
            stop(hub)


if __name__ == "__main__":
    main()
