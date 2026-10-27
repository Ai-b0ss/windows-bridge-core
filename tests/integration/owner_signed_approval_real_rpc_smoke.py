"""Real Windows Bridge authenticated RPC: exact signed owner approval and real owned-file effect.

Uses a fresh isolated Bridge, disposable RSA-2048 signer and test-owned files.
This does NOT prove ChatGPT host approval attestation, production deployment,
or that user chat text by itself can become a cryptographic grant.
"""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

REPO = Path(__file__).resolve().parents[2]
RUNTIME = REPO / "runtime/bridge-v3"
sys.path.insert(0, str(RUNTIME))
from cua_task_authority import AuthorityStore, canonical
from isolated_rpc_smoke import free_port, rpc, verify


def main():
    verify(os.name == "nt", "WINDOWS_REQUIRED")
    with TemporaryDirectory(prefix="ff-owner-signed-rpc-") as tmp:
        root = Path(tmp)
        bridge = root / "isolated-agent"
        auth = bridge / "state/task-authority"
        auth.mkdir(parents=True)
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = private.public_key().public_numbers()
        (auth / "owner-approval-public.json").write_text(
            json.dumps({"n": format(public.n, "x"), "e": str(public.e)}), encoding="ascii"
        )
        allowed = root / "only-approved-file.txt"
        other = root / "must-stay.txt"
        allowed.write_text("one task-owned file", encoding="ascii")
        other.write_text("must not be deleted", encoding="ascii")
        agent, task = "ci-signer-agent", "ci-owner-task"

        def request(path):
            return {
                "path": str(path),
                "agent_id": agent,
                "task_id": task,
                "consequences": {
                    "kind": "destructive",
                    "purpose": "remove one disposable test-owned file",
                    "targets": [path.name],
                    "risk": "isolated test fixture only",
                },
            }

        def sign_for(path, nonce, *, device=None):
            payload = {
                "schema": "ff-owner-approval-v1",
                "device": device or platform.node(),
                "agent": agent,
                "task": task,
                "request": {"op": "delete_path", "args": request(path)},
                "approval_reference": "ephemeral-authorized-test-controller",
                "nonce": nonce,
                "expires": time.time() + 120,
                "uses": 1,
            }
            signature = private.sign(
                canonical(payload).encode("utf-8"), padding.PKCS1v15(), hashes.SHA256()
            )
            return {**payload, "signature": base64.b64encode(signature).decode("ascii")}

        port = free_port()
        env = {**os.environ, "FF_BRIDGE_ROOT": str(bridge)}
        server = subprocess.Popen(
            [sys.executable, str(RUNTIME / "ff_win_v3_main.py"),
             "serve", "--host", "127.0.0.1", "--port", str(port)],
            cwd=str(REPO), env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        checks = []
        try:
            secret = bridge / "bridge-v3/secret"
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                verify(server.poll() is None, "ISOLATED_SERVER_EXITED")
                if secret.is_file():
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.2):
                            break
                    except OSError:
                        pass
                time.sleep(.1)
            else:
                raise RuntimeError("ISOLATED_SERVER_NOT_READY")
            key = secret.read_text("ascii").strip()

            def invoke(args, tag):
                return rpc(port, key, "delete_path", args, "ci-" + tag)

            no_grant = invoke(request(allowed), "without-grant")
            verify(no_grant.get("ok") is False and allowed.exists(), "UNSIGNED_EFFECT_ALLOWED")
            checks.append("unsigned_mutation_denied")

            fake = invoke({**request(allowed), "approved": True,
                           "user_chat_text": "yes"}, "fake-chat")
            verify(fake.get("ok") is False and allowed.exists(), "FORGED_CHAT_ALLOWED")
            checks.append("model_claimed_chat_consent_denied")

            signed = sign_for(allowed, "one")
            wrong = invoke({**request(other), "signed_approval": signed}, "wrong-target")
            verify(wrong.get("ok") is False and allowed.exists() and other.exists(),
                   "CROSS_TARGET_ALLOWED")
            checks.append("exact_target_enforced")

            cross_device = sign_for(allowed, "wrong-device", device="WIN-OTHER-DEVICE")
            wrong_device = invoke({**request(allowed), "signed_approval": cross_device},
                                  "wrong-device")
            verify(wrong_device.get("ok") is False and allowed.exists(),
                   "CROSS_DEVICE_ALLOWED")
            checks.append("device_bound_grant_enforced")

            completed = invoke({**request(allowed), "signed_approval": signed}, "correct")
            verify(completed.get("ok") is True and not allowed.exists() and other.exists(),
                   "EXACT_SIGNED_EFFECT_NOT_COMPLETED")
            checks.append("real_owned_file_deleted_once")

            replay = invoke({**request(allowed), "signed_approval": signed}, "replay")
            verify(replay.get("ok") is False and other.exists(), "GRANT_REPLAY_ALLOWED")
            checks.append("replay_denied")

            to_revoke = sign_for(other, "revoke-before-action")
            controller = AuthorityStore(auth, device_id=platform.node())
            grant = controller.provision(signed_approval=to_revoke)
            verify(controller.revoke(grant), "REVOCATION_NOT_STORED")
            blocked = invoke({**request(other), "authorization_id": grant}, "revoked")
            verify(blocked.get("ok") is False and other.exists(), "REVOKED_GRANT_ALLOWED")
            checks.append("revocation_enforced")

            print(json.dumps({
                "schema": "ff-owner-signed-real-rpc-smoke-v1",
                "all_passed": True, "checks": checks,
                "real_authenticated_windows_rpc": True,
                "owned_effect_independently_verified": True,
                "foreign_test_file_preserved": True,
                "private_signer_only_in_test_memory": True,
                "owner_production_modified": False,
                "host_attested_chat_approval_proven": False,
                "foreground_used": False, "model_or_paid_api_used": False,
            }, sort_keys=True))
        finally:
            if server.poll() is None:
                server.terminate()
            try:
                server.wait(timeout=8)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=8)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        # Never output private receipt/signature/secret or an owner path.
        print("REAL_OWNER_APPROVAL_RPC_FAILED:" + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
