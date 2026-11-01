"""User-mode approval records. Local provisioning is outside the RPC registry.

This is a contract with the trusted owner/controller, not an OS sandbox around
arbitrary user code. A remote request cannot mint approval by asserting a bool.
Existing owner delegation can be recorded by the trusted local controller for
one exact desktop transition or visible app launch; Hello is optional.
"""
from __future__ import annotations
import argparse
import base64
from contextlib import closing, contextmanager
from contextvars import ContextVar
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import secrets
import sqlite3
import time

APPROVED_EFFECT = ContextVar("approved_effect", default=False)
DESKTOP_ACTION_EXPIRY = ContextVar("desktop_action_expiry", default=None)

class AuthorityError(RuntimeError):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)

def invocation(op, args):
    return {"op": op, "args": {k: v for k, v in args.items() if k not in {"authorization_id", "signed_approval"}}}

def identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value):
        raise AuthorityError("AUTHORITY_IDENTITY_INVALID")
    return value

class AuthorityStore:
    def __init__(self, root, *, public_key=None, device_id=None):
        self.root = Path(root)
        self.path = self.root / "owner-approvals.sqlite3"
        # The same trusted signer may authorize multiple owned machines, but
        # a signed decision for one device cannot be consumed on another.
        # Hostname is an operational device ID, NOT hardware attestation.
        # A later signed host device-identity scheme must strengthen this.
        self.device_id = identity(device_id if device_id is not None else platform.node())
        # Public verification key is captured at startup. The corresponding
        # signing key belongs to the authenticated owner/controller and must
        # never be present in the bridge, scripts, ZIP or logs.
        key_path = self.root / "owner-approval-public.json"
        self.public_key = public_key if public_key is not None else json.loads(key_path.read_bytes()) if key_path.is_file() else None

    def _verify_signature(self, approval):
        if not self.public_key:
            raise AuthorityError("OWNER_APPROVAL_VERIFIER_NOT_CONFIGURED")
        if not isinstance(approval,dict):
            raise AuthorityError("OWNER_APPROVAL_SIGNATURE_INVALID")
        try:
            payload = {k:v for k,v in approval.items() if k != "signature"}
            n, e = int(self.public_key["n"], 16), int(self.public_key["e"])
            if n.bit_length() < 2048 or e != 65537 or payload.get("schema") != "ff-owner-approval-v1":
                raise ValueError("invalid key or schema")
            width = (n.bit_length()+7)//8
            signature = base64.b64decode(approval["signature"], validate=True)
            if len(signature) != width or int.from_bytes(signature,"big") >= n:
                raise ValueError("invalid signature length")
            digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(canonical(payload).encode()).digest()
            expected = b'\x00\x01' + b'\xff'*(width-len(digest_info)-3) + b'\x00' + digest_info
            actual = pow(int.from_bytes(signature,"big"), e, n).to_bytes(width,"big")
            if not secrets.compare_digest(expected,actual): raise ValueError("invalid signature")
            return payload
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthorityError("OWNER_APPROVAL_SIGNATURE_INVALID") from exc

    def _connect(self):
        self.root.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(self.path, timeout=5)
        con.execute("PRAGMA synchronous=FULL")
        # Separate v2 records from legacy unbound approvals. Legacy rows are
        # deliberately not migrated or silently accepted after this upgrade.
        con.execute("CREATE TABLE IF NOT EXISTS approvals_v2 (id TEXT PRIMARY KEY, agent TEXT, task TEXT, digest TEXT, device TEXT NOT NULL, expires REAL, uses INTEGER, reference TEXT, revoked INTEGER NOT NULL DEFAULT 0)")
        return con

    def provision(self, *, signed_approval):
        """Import an authenticated controller's signed, exact owner decision.

        This may be transported by an agent; transport does not confer consent.
        An unsigned local/RPC assertion cannot provision an approval.
        """
        return self._record_approval(self._verify_signature(signed_approval))

    def provision_local_desktop(self, delegation):
        """Record an already given owner decision through the local controller.

        This is not an RPC operation and makes no claim of Windows Hello or
        independent human-presence verification. The trusted controller must
        obtain the real owner's instruction before calling this local API.
        Ordinary scripts already run as that same Windows user; this contract
        does not pretend to sandbox them.
        """
        if not isinstance(delegation, dict) or delegation.get("schema") != "ff-local-desktop-delegation-v1":
            raise AuthorityError("LOCAL_DESKTOP_DELEGATION_INVALID")
        request = delegation.get("request")
        args = request.get("args") if isinstance(request, dict) else None
        if (not isinstance(args, dict)
                or any(key in args for key in ("signed_approval", "authorization_id"))
                or args.get("agent_id") != delegation.get("agent")
                or args.get("task_id") != delegation.get("task")):
            raise AuthorityError("LOCAL_DESKTOP_DELEGATION_SCOPE_INVALID")
        if request.get("op") == "set_desktop_mode":
            if (args.get("mode") != "dedicated" or not isinstance(args.get("targets"), list)
                    or not 0 <= len(args["targets"]) <= 32):
                raise AuthorityError("LOCAL_DESKTOP_DELEGATION_SCOPE_INVALID")
        elif request.get("op") == "computer_use":
            expected = args.get("expected_app")
            if (args.get("command") not in {"launch_app", "ensure_app"}
                    or args.get("visible_launch_allowed") is not True
                    or type(args.get("mode_generation")) is not int or args["mode_generation"] < 1
                    or not isinstance(args.get("app"), str) or not args["app"].strip()
                    or not isinstance(expected, dict)
                    or not isinstance(expected.get("app_id"), str) or not expected["app_id"].strip()
                    or set(expected) - {"app_id", "sha256"}
                    or ("sha256" in expected and (not isinstance(expected["sha256"], str)
                        or not re.fullmatch(r"[0-9a-f]{64}", expected["sha256"])))):
                raise AuthorityError("LOCAL_DESKTOP_DELEGATION_SCOPE_INVALID")
        else:
            raise AuthorityError("LOCAL_DESKTOP_DELEGATION_SCOPE_INVALID")
        if delegation.get("uses") != 1 or type(delegation.get("uses")) is not int:
            raise AuthorityError("LOCAL_DESKTOP_DELEGATION_SINGLE_USE_REQUIRED")
        return self._record_approval(delegation)

    def _record_approval(self, payload):
        agent, task, request = payload.get("agent"), payload.get("task"), payload.get("request")
        if not isinstance(request, dict): raise AuthorityError("OWNER_APPROVAL_SCOPE_INVALID")
        # Device is covered by the exact signed payload (or trusted local
        # delegation). An omitted or forged agent-supplied device flag fails.
        device = payload.get("device")
        if not isinstance(device, str) or not device:
            raise AuthorityError("OWNER_APPROVAL_DEVICE_REQUIRED")
        identity(device)
        if device != self.device_id:
            raise AuthorityError("OWNER_APPROVAL_DEVICE_MISMATCH")
        approval_reference, expires, uses = payload.get("approval_reference"), payload.get("expires"), payload.get("uses")
        identity(agent); identity(task); identity(payload.get("nonce"))
        if not isinstance(approval_reference, str) or not approval_reference.strip():
            raise AuthorityError("OWNER_APPROVAL_REFERENCE_REQUIRED")
        now = time.time()
        not_before = payload.get("not_before", now)
        if (type(expires) not in {int, float} or not now < expires <= now + 3600
                or type(uses) is not int or not 1 <= uses <= 100
                or type(not_before) not in {int, float}
                or not_before > now or not_before > expires):
            raise AuthorityError("APPROVAL_LIMIT_INVALID")
        digest = hashlib.sha256(canonical(request).encode()).hexdigest()
        grant = hashlib.sha256(canonical(payload).encode()).hexdigest()
        with closing(self._connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("DELETE FROM approvals_v2 WHERE expires<?", (time.time()-86400,))
            if (con.execute("SELECT count(*) FROM approvals_v2").fetchone()[0] >= 10000
                    and not con.execute("SELECT 1 FROM approvals_v2 WHERE id=?", (grant,)).fetchone()):
                raise AuthorityError("OWNER_APPROVAL_CAPACITY_EXHAUSTED")
            # Conflict means this exact receipt was already provisioned:
            # no uses/expiry reset, even after full consumption or revocation.
            con.execute(
                "INSERT OR IGNORE INTO approvals_v2 "
                "(id,agent,task,digest,device,expires,uses,reference) VALUES (?,?,?,?,?,?,?,?)",
                (grant, agent, task, digest, device, expires, uses, approval_reference),
            )
            con.commit()
        return grant

    def consume(self, grant, *, agent, task, request):
        identity(agent); identity(task)
        digest = hashlib.sha256(canonical(request).encode()).hexdigest()
        with closing(self._connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT agent,task,digest,device,expires,uses,revoked FROM approvals_v2 WHERE id=?",
                (grant,),
            ).fetchone()
            if not row:
                raise AuthorityError("OWNER_APPROVAL_REQUIRED")
            if row[3] != self.device_id:
                raise AuthorityError("OWNER_APPROVAL_DEVICE_MISMATCH")
            if row[:3] != (agent, task, digest):
                raise AuthorityError("OWNER_APPROVAL_SCOPE_MISMATCH")
            if row[6]:
                raise AuthorityError("OWNER_APPROVAL_REVOKED")
            if row[4] <= time.time() or row[5] < 1:
                raise AuthorityError("OWNER_APPROVAL_EXPIRED_OR_CONSUMED")
            con.execute("UPDATE approvals_v2 SET uses=uses-1 WHERE id=?", (grant,))
            con.commit()
        return row[4]

    def revoke(self, grant):
        """Trusted local-controller revocation; intentionally not an RPC op."""
        if not isinstance(grant, str) or not re.fullmatch(r"[0-9a-f]{64}", grant):
            raise AuthorityError("OWNER_APPROVAL_ID_INVALID")
        with closing(self._connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "UPDATE approvals_v2 SET revoked=1, uses=0 "
                "WHERE id=? AND device=?",
                (grant, self.device_id),
            )
            changed = con.execute("SELECT changes()").fetchone()[0]
            con.commit()
        return bool(changed)

def guard_effect(core, store, op, original):
    def guarded(args):
        consequence = args.get("consequences")
        if consequence is not None and (not isinstance(consequence, dict) or consequence.get("kind") not in {"ordinary", "destructive", "irreversible"}):
            raise core.RPCError("CONSEQUENCES_INVALID")
        dangerous = isinstance(consequence, dict) and consequence["kind"] != "ordinary"
        # These checks are prompts for review, never evidence of human approval.
        hint = None
        if op in {"start_process", "interact_with_process"}:
            hint = core.command_blocked(args.get("command", args.get("input", "")))
        elif op == "run_code":
            hint = core.code_blocked(str(args.get("language", "python")).lower(), args.get("code", ""))
        if dangerous or hint or op in {"delete_path", "kill_process"}:
            if not consequence or not consequence.get("purpose") or not consequence.get("targets") or not consequence.get("risk"):
                raise core.RPCError("EFFECT_SCOPE_REQUIRED", details={"execution_started": False})
            try:
                grant = store.provision(signed_approval=args["signed_approval"]) if "signed_approval" in args else args.get("authorization_id")
                store.consume(grant, agent=args.get("agent_id"), task=args.get("task_id"), request=invocation(op, args))
            except (AuthorityError, sqlite3.Error, OSError, ValueError) as exc:
                raise core.RPCError(str(exc) if isinstance(exc, AuthorityError) else "APPROVAL_STORAGE_UNAVAILABLE", details={"execution_started": False}) from exc
            token = APPROVED_EFFECT.set(True)
            try:
                return original(args)
            finally:
                APPROVED_EFFECT.reset(token)
        return original(args)
    return guarded

class DesktopModes:
    """One machine-wide mode; transitions serialize with foreground dispatch.

    Scope contains exact hwnd/pid/process birth, not a caller supplied title.
    Dedicated mode expires and never follows mouse inactivity.
    """
    def __init__(self, root, store, target_fingerprint, stop_input=lambda: None, chat_permission=None):
        self.root, self.store = Path(root), store
        # Optional owner chat-permission policy; None keeps signed-only behaviour.
        self.chat_permission = chat_permission
        self.target_fingerprint, self.stop_input = target_fingerprint, stop_input
        self.path = self.root / "desktop-mode.json"
        self.lock_path = self.root / "desktop-mode.lock"

    def _grant_expiry(self, args, op):
        """Expiry from a signed grant, or from the owner's chat permission."""
        if "signed_approval" not in args and "authorization_id" not in args and "owner_chat_permission" in args:
            if self.chat_permission is None:
                raise AuthorityError("CHAT_PERMISSION_DISABLED")
            try:
                return self.chat_permission.authorize(args)
            except ValueError as exc:
                raise AuthorityError(str(exc)) from exc
        grant = self.store.provision(signed_approval=args["signed_approval"]) if "signed_approval" in args else args.get("authorization_id")
        return self.store.consume(grant, agent=args.get("agent_id"), task=args.get("task_id"), request=invocation(op, args))

    def _read(self):
        if not self.path.exists():
            return {"mode": "coexist", "generation": 0}
        state = json.loads(self.path.read_text(encoding="utf-8"))
        if state.get("mode") == "dedicated" and state["expires"] <= time.time():
            self.stop_input()
            state = {"mode": "coexist", "generation": state["generation"]+1}
            self._write(state)
        return state

    def _write(self, state):
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(canonical(state), encoding="utf-8")
        os.replace(tmp, self.path)

    def _resolve_target(self, target):
        """Build the exact window fingerprint from an hwnd and check anything else the caller states.

        Agents cannot list a process start time, so {"hwnd": N} is enough; a given pid or
        process_start_ns must still match the live window.
        """
        if not isinstance(target, dict) or "hwnd" not in target or set(target) - {"hwnd", "pid", "process_start_ns"}:
            raise AuthorityError("DESKTOP_TARGET_INVALID")
        try:
            actual = self.target_fingerprint(target["hwnd"])
        except Exception as exc:
            raise AuthorityError("DESKTOP_TARGET_INVALID") from exc
        if any(str(actual.get(key)) != str(value) for key, value in target.items()):
            raise AuthorityError("DESKTOP_TARGET_CHANGED")
        return actual

    def transition(self, args):
        from cua_global_resources import _StateLock
        mode = args.get("mode")
        if mode not in {"coexist", "dedicated"}:
            raise AuthorityError("DESKTOP_MODE_INVALID")
        with _StateLock(self.lock_path):
            state = self._read()
            if mode == "dedicated":
                if state["mode"] == "dedicated" and (state["agent_id"], state["task_id"]) != (args.get("agent_id"), args.get("task_id")):
                    raise AuthorityError("DESKTOP_MODE_BUSY")
                targets = args.get("targets")
                if not isinstance(targets, list) or not 0 <= len(targets) <= 32:
                    raise AuthorityError("DESKTOP_TARGET_SCOPE_REQUIRED")
                targets = [self._resolve_target(target) for target in targets]
                expires = self._grant_expiry(args, "set_desktop_mode")
                self.stop_input()
                state = {"mode": mode, "agent_id": args["agent_id"], "task_id": args["task_id"], "targets": targets, "expires": expires, "generation": state["generation"]+1}
            else:
                # Any client may request a safe return; no permission needed to stop input.
                self.stop_input()
                state = {"mode": mode, "generation": state["generation"]+1}
            self._write(state)
            return state

    @contextmanager
    def action(self, args, hwnd):
        from cua_global_resources import _StateLock
        with _StateLock(self.lock_path):
            state = self._read()
            if state["mode"] != "dedicated":
                raise AuthorityError("INTERACTIVE_FOREGROUND_DISABLED")
            if (state["agent_id"], state["task_id"], state["generation"]) != (args.get("agent_id"), args.get("task_id"), args.get("mode_generation")):
                raise AuthorityError("DESKTOP_MODE_SCOPE_MISMATCH")
            if self.target_fingerprint(hwnd) not in state["targets"]:
                raise AuthorityError("DESKTOP_TARGET_OUTSIDE_SCOPE")
            token = DESKTOP_ACTION_EXPIRY.set(state["expires"])
            try:
                yield state
                if state["expires"] <= time.time():
                    self._read() # stop input and invalidate the old generation
                    raise AuthorityError("DESKTOP_MODE_EXPIRED")
            finally:
                DESKTOP_ACTION_EXPIRY.reset(token)

    @contextmanager
    def launch_action(self, args):
        """Serialize one exact visible launch with desktop-mode transitions."""
        from cua_global_resources import _StateLock
        with _StateLock(self.lock_path):
            state = self._read()
            if state["mode"] != "dedicated":
                raise AuthorityError("INTERACTIVE_FOREGROUND_DISABLED")
            if (state["agent_id"], state["task_id"], state["generation"]) != (args.get("agent_id"), args.get("task_id"), args.get("mode_generation")):
                raise AuthorityError("DESKTOP_MODE_SCOPE_MISMATCH")
            if args.get("command") not in {"launch_app", "ensure_app"} or args.get("visible_launch_allowed") is not True:
                raise AuthorityError("VISIBLE_LAUNCH_SCOPE_INVALID")
            expires = self._grant_expiry(args, "computer_use")
            expiry = min(expires, state["expires"])
            token = DESKTOP_ACTION_EXPIRY.set(expiry)
            try:
                yield state
                if expiry <= time.time():
                    self._read()
                    raise AuthorityError("DESKTOP_LAUNCH_EXPIRED_AFTER_DISPATCH")
            finally:
                DESKTOP_ACTION_EXPIRY.reset(token)

    def status(self):
        from cua_global_resources import _StateLock
        with _StateLock(self.lock_path):
            return self._read()

def main():
    parser = argparse.ArgumentParser(description="Trusted LOCAL owner/controller approval provisioning; never an RPC operation")
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--device-id", help="Expected signed target device; defaults to this host")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--revoke", help="Revoke an existing exact grant ID, trusted local controller only")
    source.add_argument("--request", type=Path, help="JSON containing signed_approval from the authenticated owner/controller")
    source.add_argument("--local-desktop-delegation", type=Path,
                        help="Exact desktop transition or app launch already authorized by the owner; local trusted controller only")
    args = parser.parse_args()
    store = AuthorityStore(args.root, device_id=args.device_id)
    if args.revoke:
        print(json.dumps({"revoked": store.revoke(args.revoke)}))
        return
    path = args.local_desktop_delegation or args.request
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    grant = store.provision_local_desktop(data) if args.local_desktop_delegation else store.provision(**data)
    print(grant)

if __name__ == "__main__":
    main()
