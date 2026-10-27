"""Opt-in actual Antigravity model task over a fresh authenticated Bridge RPC.

Not run automatically in public CI: a user's own baseline model quota is
consumed. Requires FF_ENABLE_AGY_FREE_BASELINE_SMOKE=1 and hardened billing
settings. Only the task-owned ephemeral challenge and loopback RPC are touched.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import urllib.error
import urllib.request

from isolated_rpc_smoke import REPO, SERVER, free_port, verify

sys.path.insert(0, str(REPO / "runtime" / "bridge-v3"))
from cua_antigravity_task import _subscription_gate, VendorTaskError


def slow_rpc(port, secret, args):
    payload = json.dumps({
        "task_id": "ci-owned-agi-headless-001",
        "target_device": os.environ.get("COMPUTERNAME", ""),
        "op": "computer_use", "args": args,
    }, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/rpc",
        data=payload, method="POST",
        headers={"X-FF3-Key": secret, "Content-Type": "application/json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=125) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())


def main():
    verify(os.name == "nt", "WINDOWS_REQUIRED")
    verify(os.environ.get("FF_ENABLE_AGY_FREE_BASELINE_SMOKE") == "1",
           "EXPLICIT_QUOTA_TEST_OPT_IN_REQUIRED")
    _subscription_gate(Path.home(), Path(os.environ.get("LOCALAPPDATA", "")))
    with TemporaryDirectory(prefix="ff-agi-remote-task-") as td:
        root = Path(td) / "isolated-bridge"
        root.mkdir()
        marker = secrets.token_hex(12)
        request = {
            "command": "task_execute", "app": "Antigravity",
            "task": "antigravity.assistant", "operation": "headless.answer",
            "agent_id": "test-only-agent", "task_id": "test-only-headless-run",
            "context": "The requested verification token is " + marker + "\n",
            "prompt": (
                "Read context.txt in the current workspace. Return one line ONLY "
                "in this exact format: TOKEN:<marker> where <marker> is the complete "
                "token found in the file. Do not guess or edit files or run shell commands."
            ),
            "expected_response": "TOKEN:" + marker,
        }
        port = free_port()
        child = subprocess.Popen(
            [sys.executable, str(SERVER), "serve", "--host", "127.0.0.1", "--port", str(port)],
            cwd=str(REPO), env={**os.environ, "FF_BRIDGE_ROOT": str(root)},
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            secret_file = root / "bridge-v3" / "secret"
            until = time.monotonic() + 18
            while time.monotonic() < until:
                verify(child.poll() is None, "BRIDGE_ISOLATED_SERVER_EXITED")
                if secret_file.exists():
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            break
                    except OSError:
                        pass
                time.sleep(.1)
            else:
                raise RuntimeError("BRIDGE_ISOLATED_SERVER_NOT_READY")
            secret = secret_file.read_text(encoding="ascii").strip()
            observed = slow_rpc(port, secret, request)
            verify(observed.get("ok") is True, "AGI_REAL_RPC_FAILED_" + str(observed.get("error_code")))
            result = observed.get("result") or {}
            verify(result.get("schema") == "ff-vendor-task-result-v1",
                   "AGI_TASK_RECEIPT_WRONG_SCHEMA")
            verify(result.get("state") == "COMPLETED" and
                   result.get("response") == "TOKEN:" + marker,
                   "AGI_REAL_MODEL_RESULT_DID_NOT_MATCH_FILE")
            verify(result.get("model_called") is True and
                   (result.get("result_verification") or {}).get("sandbox_context_unchanged") is True and
                   (result.get("result_verification") or {}).get("owned_process_descendants_cleaned") is True,
                   "AGI_MODEL_EXECUTION_NOT_INDEPENDENTLY_VERIFIED")
            billing = result.get("billing") or {}
            verify(billing.get("no_new_paid_credits_configured") is True and
                   billing.get("external_api_key_provider_used") is False and
                   billing.get("no_charge_guarantee_from_vendor") is False,
                   "AGI_BILLING_GATE_MISSING")
            owned = root / "bridge-v3" / "owned-agent-tasks"
            # Root normalization can differ between installed and source.
            roots = list(root.glob("**/owned-agent-tasks"))
            verify(len(roots) == 1 and not list(roots[0].iterdir()),
                   "AGI_OWNED_WORKSPACE_NOT_CLEANED")
            print(json.dumps({
                "schema": "ff-real-agi-bridge-rpc-v1",
                "status": "PASS", "real_model_prompt_completed": True,
                "actual_file_based_random_challenge_verified": True,
                "isolated_authenticated_rpc_used": True,
                "model_used": result.get("model"),
                "no_additional_paid_credits_configured": True,
                "workspace_cleaned": True,
                "owner_production_bridge_changed": False,
            }, sort_keys=True))
        finally:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=8)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=8)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        code = str(exc)
        if not (code.isascii() and 1 <= len(code) <= 128 and
                all(ch.isupper() or ch.isdigit() or ch in "_-" for ch in code)):
            code = type(exc).__name__
        print("AGI_RPC_REAL_SMOKE_FAILED:" + code, file=sys.stderr)
        raise SystemExit(1)
