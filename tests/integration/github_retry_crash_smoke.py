"""Hard exits in the comment worker: exact identity survives, effect never replays.

Only an owned temporary transport home and a synthetic marker are used. No
GitHub connection, credentials, installed Bridge, or desktop is accessed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def child(home, phase):
    os.environ["FF_GH_HOME"] = str(home)
    os.environ["FF_BRIDGE_ROOT"] = str(home)
    os.environ["FF_GH_TRACE"] = "0"
    sys.path.insert(0, str(ROOT / "runtime/github-transport"))
    import ff_win_github_comment_daemon as daemon
    import ff_win_transport_core as core

    marker = home / "effect-count"

    def rpc(task, timeout):
        with marker.open("ab") as stream:
            stream.write(b"X")
            stream.flush()
            os.fsync(stream.fileno())
        if phase == "ambiguous":
            os._exit(17)
        return 200, {"ok": True, "exact_result": "durable-mutation-result"}

    comment = {"id": 123, "node_id": "ISOLATED_NODE_123",
               "user": {"login": daemon.OWNER},
               "body": json.dumps({"schema": daemon.SCHEMA, "client_id": "crash-client",
                                   "task_id": "crash-task", "target_device": daemon.DEVICE,
                                    "op": "write_file", "args": {}})}
    with patch.object(daemon, "get_token", return_value="isolated-test-token"), \
         patch.object(daemon.threading.Thread, "start"):
        transport = daemon.CommentTransport()
    save = transport.save_retry

    def crash_after_done(cid, state):
        if phase == "completed" and "completed_result" in state:
            # Core journal committed; daemon checkpoint/outbox not yet written.
            os._exit(18)
        save(cid, state)

    with patch.object(core, "_rpc", rpc), patch.object(transport, "save_retry", crash_after_done):
        if phase in {"ambiguous", "completed"}:
            transport.submit(comment)
        else:
            transport.last_recover_at = -100
            transport.recover_requests()
        transport.pool.shutdown(wait=True)
    if phase == "recover":
        item = json.loads((transport.outbox / "123.json").read_text(encoding="utf-8"))
        result = json.loads(item["body"])
        assert result["comment_id"] == 123 and result["task"] == json.loads(comment["body"])
        assert item["node_id"] == comment["node_id"]
        assert marker.read_bytes() == b"X", "mutation replayed after crash"
        transport.mark_published(item)
        transport.active.discard(123)
        transport.submit(comment)
        assert transport.active == set(), "cached outbox retained active ownership"
        assert not list(transport.requests.glob("*.json"))
        print(json.dumps({"http_status": result["http_status"],
                          "code": result["result"].get("error_code"),
                          "route": result["route"]["route"], "effects": 1}))


def main():
    results = {}
    with tempfile.TemporaryDirectory(prefix="ff-gh-retry-crash-") as td:
        for phase, exit_code in (("ambiguous", 17), ("completed", 18)):
            home = Path(td) / phase
            home.mkdir()
            def run(mode):
                return subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                       "--child", str(home), mode], cwd=ROOT,
                                      capture_output=True, text=True, timeout=20)
            crashed = run(phase)
            assert crashed.returncode == exit_code, crashed.stdout + crashed.stderr
            state = json.loads((home / "request-retries/123.json").read_text(encoding="utf-8"))
            assert state["attempts"] == 1 and state["status"] == "running"
            assert (home / "pending-requests/123.json").exists()
            recovered = run("recover")
            assert recovered.returncode == 0, recovered.stdout + recovered.stderr
            outcome = json.loads(recovered.stdout)
            if phase == "ambiguous":
                assert outcome["code"] == "TASK_OUTCOME_UNKNOWN"
            else:
                assert outcome["http_status"] == 200 and outcome["route"] == "journal-cache"
            results[phase] = outcome
    print(json.dumps({"status": "PASS", "isolated": True, "hard_exits": 2, "results": results}))


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--child":
        child(Path(sys.argv[2]), sys.argv[3])
    else:
        main()
