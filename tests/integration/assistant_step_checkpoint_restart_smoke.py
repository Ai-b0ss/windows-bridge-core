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
            # Second task: all assistant effects recorded VERIFIED; only
            # final read-only artifact verification lost its ACK.
            import hashlib
            output_dir=Path(directory)/"task-artifacts"
            output_dir.mkdir()
            artifact=output_dir/"saved.txt"
            artifact.write_text("independently persisted result\n",encoding="utf-8")
            expected=hashlib.sha256(artifact.read_bytes()).hexdigest()
            task_args={
                "command":"assistant_task","app":"Cursor",
                "agent_id":"ci-assistant-agent",
                "task_id":"ci-final-verification-recovery",
                "artifact_root":str(output_dir),"path":str(artifact),
                "expected_sha256":expected,
                "steps":[{"stage":st,"route":"native"} for st in (
                    "open_panel","set_prompt","send","read_reply","save","verify_artifact")],
            }
            store.reserve(task_args)
            for idx, entry in enumerate(task_args["steps"][:-1]):
                stage=entry["stage"]
                store.before(task_args["agent_id"],task_args["task_id"],idx,stage)
                store.after(task_args["agent_id"],task_args["task_id"],idx,stage,
                            {"stage":stage,"ok":True,"verified":True})
            store.before(task_args["agent_id"],task_args["task_id"],5,"verify_artifact")
            final_rpc=rpc(second_port,secret_again,"computer_use",{
                **task_args,"command":"assistant_task_reconcile",
            },"ci-final-readonly-reconcile")
            verify(final_rpc.get("ok") is True,
                   "FINAL_ARTIFACT_RECONCILE_RPC_FAILED_"+str(final_rpc.get("error_code")))
            final=final_rpc.get("result") or {}
            verify(final.get("verified") is True
                   and final.get("reconciled_without_replay") is True
                   and final.get("any_mutation_replayed") is False
                   and (final.get("result") or {}).get("state")=="COMPLETED",
                   "INDEPENDENT_ARTIFACT_RECONCILE_FAILED")
            verify(store.status("ci-assistant-agent","ci-final-verification-recovery")["state"]=="COMPLETED"
                   and hashlib.sha256(artifact.read_bytes()).hexdigest()==expected,
                   "RECONCILED_ARTIFACT_INVALID")
            retry=rpc(second_port,secret_again,"computer_use",{
                **task_args,"command":"assistant_task_reconcile",
            },"ci-final-readonly-reconcile-duplicate")
            verify(retry.get("ok") is False,"FINAL_RECONCILE_DUPLICATE_NOT_BLOCKED")
            verify(sink.read_text("utf-8")=="SEND_EXECUTED_ONCE\n",
                   "FINAL_RECONCILE_REPLAYED_OLD_SEND")
            print(json.dumps({
                "schema": "ff-assistant-task-step-restart-v1",
                "all_passed": True,
                "real_bridge_process_restart": True,
                "status_persisted_across_restart": True,
                "last_verified_steps": 2,
                "pending_stage": "send",
                "auto_retry_blocked": True,
                "simulated_effect_count": 1,
                "independent_saved_artifact_reconciled": True,
                "no_mutating_stage_replayed_on_final_reconciliation": True,
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
