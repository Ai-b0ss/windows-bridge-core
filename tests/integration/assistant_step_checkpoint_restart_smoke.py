"""Real Bridge-process restart recovers assistant step and refuses re-send.

The fixture simulates the non-idempotent external effect by one write to an
OWNED scratch file. It does not claim to test a real Cursor/Excel assistant UI.
The startup, RPC, SQLite checkpoints and process restart are all real Windows.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from isolated_rpc_smoke import REPO, SERVER, free_port, rpc, verify

sys.path.insert(0, str(REPO / "runtime" / "bridge-v3"))
from cua_assistant_step_ledger import AssistantStepLedger, WorkflowLedgerError


def spawn_bridge(root, port):
    child = subprocess.Popen([
        sys.executable, str(SERVER), "serve", "--host", "127.0.0.1",
        "--port", str(port),
    ], cwd=str(REPO), env={**os.environ, "FF_BRIDGE_ROOT": str(root)},
       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
       creationflags=subprocess.CREATE_NO_WINDOW)
    secret_file = root / "bridge-v3" / "secret"
    until = time.monotonic() + 15
    while time.monotonic() < until:
        verify(child.poll() is None, "ISOLATED_AGENT_TERMINATED_ON_START")
        if secret_file.is_file():
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=.3):
                    return child, secret_file.read_text("ascii").strip()
            except OSError:
                pass
        time.sleep(.05)
    child.terminate()
    child.wait(timeout=10)
    raise RuntimeError("ISOLATED_AGENT_START_TIMEOUT")


def stop_bridge(child):
    if child is None:
        return
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(timeout=8)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=8)


def main():
    verify(os.name == "nt", "WINDOWS_REQUIRED")
    with TemporaryDirectory(prefix="ff-assistant-reboot-scope-") as directory:
        root = Path(directory) / "owned-bridge"
        root.mkdir()
        store = AssistantStepLedger(root / "state" / "assistant-checkpoints")
        args = {
            "command": "assistant_task", "app": "Cursor",
            "agent_id": "ci-assistant-agent", "task_id": "ci-restart-once",
            "prompt": "PRIVATELY_OWNED_UNLOGGED_PROMPT",
            "steps": [
                {"stage": item, "route": "native"} for item in (
                    "open_panel", "set_prompt", "send", "read_reply",
                    "save", "verify_artifact",
                )
            ],
        }
        store.reserve(args)
        for idx, stage in enumerate(("open_panel", "set_prompt")):
            store.before(args["agent_id"], args["task_id"], idx, stage)
            store.after(args["agent_id"], args["task_id"], idx, stage,
                        {"stage": stage, "ok": True, "verified": True})
        store.before(args["agent_id"], args["task_id"], 2, "send")
        # Simulate the exact non-idempotent effect and then lose the ACK
        # before any step.after call; no assistant or owner's files are touched.
        sink = Path(directory) / "owned-effect.log"
        sink.write_text("SEND_EXECUTED_ONCE\n", encoding="utf-8")
        first_port = free_port()
        child = None
        try:
            child, secret = spawn_bridge(root, first_port)
            one = rpc(first_port, secret, "computer_use", {
                "command": "assistant_task_status",
                "agent_id": args["agent_id"], "task_id": args["task_id"],
            }, "ci-state-before-restart")
            verify(one.get("ok") is True, "RECOVERY_STATUS_FIRST_RPC_FAILED")
            snap = one.get("result") or {}
            verify(snap.get("state") == "DISPATCHING"
                   and snap.get("last_checkpoint_stage") == "send"
                   and snap.get("verified_steps") == 2
                   and snap.get("automatic_replay_allowed") is False,
                   "FIRST_STATUS_FALSE_EFFECT_RETRY")
            stop_bridge(child)
            child = None
            second_port = free_port()
            child, secret_again = spawn_bridge(root, second_port)
            verify(secret_again == secret, "BRIDGE_AUTH_SECRET_REPLACED_ON_RESTART")
            two = rpc(second_port, secret_again, "computer_use", {
                "command": "assistant_task_status",
                "agent_id": args["agent_id"], "task_id": args["task_id"],
            }, "ci-state-after-restart")
            verify(two.get("ok") is True, "RECOVERY_STATUS_RESTART_RPC_FAILED")
            resumed = two.get("result") or {}
            verify(resumed == snap, "CHECKPOINT_CHANGED_AFTER_REAL_AGENT_RESTART")
            try:
                AssistantStepLedger(store.root).reserve(args)
            except WorkflowLedgerError as exc:
                verify(exc.code == "ASSISTANT_WORKFLOW_ALREADY_RECORDED",
                       "RESTART_RESERVATION_UNEXPECTED_ERROR")
            else:
                raise RuntimeError("RESTART_DUPLICATE_ACTION_NOT_BLOCKED")
            verify(sink.read_text("utf-8") == "SEND_EXECUTED_ONCE\n",
                   "SIMULATED_EXTERNAL_EFFECT_DUPLICATED")
            # Ensure the durable SQLite store never retains prompt text.
            verify(b"PRIVATELY_OWNED_UNLOGGED_PROMPT" not in store.path.read_bytes(),
                   "PROMPT_LEAKED_IN_STEP_CHECKPOINTS")
            print(json.dumps({
                "schema": "ff-assistant-task-step-restart-v1",
                "all_passed": True,
                "real_bridge_process_restart": True,
                "status_persisted_across_restart": True,
                "last_verified_steps": 2,
                "pending_stage": "send",
                "auto_retry_blocked": True,
                "simulated_effect_count": 1,
                "owner_files_modified": False,
                "model_called": False,
            }, sort_keys=True))
        finally:
            stop_bridge(child)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("ASSISTANT_STEP_RESTART_SMOKE_FAILED:" + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
