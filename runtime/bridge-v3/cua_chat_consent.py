"""Challenge-bound owner approval, preparing for a trusted ChatGPT host issuer.

This module deliberately does not treat chat text, tool arguments or an OAuth
connection as an attested consent event. The issuer signs the existing
ff-owner-approval-v1 format with a key enrolled outside the agent and Bridge.
An absent verifier fails closed. No foreground action is executed here.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import time

from cua_task_authority import AuthorityError, AuthorityStore, canonical, identity, invocation

SCHEMA = "ff-chat-owner-consent-challenge-v1"
TTL_SECONDS = 300
ALLOWED_OPERATIONS = frozenset({
    "set_desktop_mode", "computer_use", "gui_mouse", "gui_keyboard",
    "gui_action_sequence", "gui_focus_window", "focus_window",
})


class ChatConsentError(ValueError):
    pass


class ChatConsentBroker:
    def __init__(self, root: Path, authority: AuthorityStore):
        self.root = Path(root)
        self.path = self.root / "challenges.sqlite3"
        self.authority = authority

    def _connect(self):
        self.root.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(self.path, timeout=10)
        con.execute("PRAGMA synchronous=FULL")
        con.execute("""CREATE TABLE IF NOT EXISTS requests(
            id TEXT PRIMARY KEY, device TEXT NOT NULL, agent TEXT NOT NULL,
            task TEXT NOT NULL, operation TEXT NOT NULL, digest TEXT NOT NULL,
            created REAL NOT NULL, expires REAL NOT NULL,
            committed INTEGER NOT NULL DEFAULT 0, grant TEXT
        )""")
        return con

    @staticmethod
    def _request(operation, action):
        if operation not in ALLOWED_OPERATIONS or not isinstance(action, dict):
            raise ChatConsentError("CHAT_CONSENT_OPERATION_INVALID")
        if any(k in action for k in ("signed_approval", "authorization_id",
                                     "approved", "owner_consented")):
            raise ChatConsentError("CHAT_CONSENT_CLAIMED_PERMISSION_FORBIDDEN")
        agent = identity(action.get("agent_id"))
        task = identity(action.get("task_id"))
        if operation == "set_desktop_mode":
            if action.get("mode") != "dedicated" or not isinstance(action.get("targets"), list):
                raise ChatConsentError("CHAT_CONSENT_DESKTOP_SCOPE_INVALID")
            if len(action["targets"]) > 32:
                raise ChatConsentError("CHAT_CONSENT_DESKTOP_SCOPE_INVALID")
        elif operation == "computer_use":
            if action.get("command") not in {"launch_app", "ensure_app", "act", "focus_target"}:
                raise ChatConsentError("CHAT_CONSENT_COMPUTER_USE_SCOPE_INVALID")
        if len(canonical(action).encode("utf-8")) > 16_384:
            raise ChatConsentError("CHAT_CONSENT_SCOPE_TOO_LARGE")
        return agent, task, invocation(operation, action)

    def prepare(self, operation, action):
        agent, task, request = self._request(operation, action)
        challenge_id = secrets.token_hex(24)
        created = time.time()
        expires = created + TTL_SECONDS
        digest = hashlib.sha256(canonical(request).encode("utf-8")).hexdigest()
        with closing(self._connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            con.execute("DELETE FROM requests WHERE expires<?", (created - 86400,))
            con.execute("INSERT INTO requests(id,device,agent,task,operation,digest,created,expires) VALUES (?,?,?,?,?,?,?,?)",
                        (challenge_id, self.authority.device_id, agent, task, operation, digest, created, expires))
            con.commit()
        return {
            "schema": SCHEMA, "challenge_id": challenge_id,
            "device": self.authority.device_id,
            "agent_id": agent, "task_id": task,
            "operation": operation, "request_digest": digest,
            "expires_at": expires, "approved": False,
            "authorization_id": None,
            "next_step": "TRUSTED_HOST_SIGNED_RECEIPT_REQUIRED",
        }

    def status(self, challenge_id):
        self._validate_id(challenge_id)
        with closing(self._connect()) as con:
            row = con.execute(
                "SELECT device,agent,task,operation,created,expires,committed FROM requests WHERE id=?",
                (challenge_id,)).fetchone()
        if row is None:
            raise ChatConsentError("CHAT_CONSENT_CHALLENGE_UNKNOWN")
        return {
            "schema": SCHEMA, "challenge_id": challenge_id,
            "device": row[0], "agent_id": row[1], "task_id": row[2],
            "operation": row[3], "expires_at": row[5],
            "status": "committed" if row[6] else "expired" if row[5] <= time.time() else "awaiting_attested_host_receipt",
            "approval_granted": bool(row[6]),
        }

    @staticmethod
    def _validate_id(challenge_id):
        if not isinstance(challenge_id, str) or len(challenge_id) != 48:
            raise ChatConsentError("CHAT_CONSENT_ID_INVALID")
        try:
            bytes.fromhex(challenge_id)
        except ValueError as exc:
            raise ChatConsentError("CHAT_CONSENT_ID_INVALID") from exc

    def commit(self, challenge_id, signed_approval):
        """Provision a single action grant only from a separately signed receipt.

        The signed approval's reference, nonce, exact request, device and time
        are bound to a pending challenge. No local key is minted or exposed.
        Replay of a committed challenge is rejected transactionally.
        """
        self._validate_id(challenge_id)
        with closing(self._connect()) as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT device,agent,task,operation,digest,expires,committed FROM requests WHERE id=?",
                (challenge_id,)).fetchone()
            if not row:
                raise ChatConsentError("CHAT_CONSENT_CHALLENGE_UNKNOWN")
            if row[6]:
                raise ChatConsentError("CHAT_CONSENT_CHALLENGE_REPLAY")
            if row[5] <= time.time():
                raise ChatConsentError("CHAT_CONSENT_CHALLENGE_EXPIRED")
            # _verify_signature requires the enrolled owner/host public key.
            # An agent-supplied 'approved' flag cannot satisfy this.
            if not isinstance(signed_approval, dict) or len(canonical(signed_approval).encode("utf-8")) > 32768:
                raise ChatConsentError("CHAT_CONSENT_RECEIPT_INVALID")
            signed = self.authority._verify_signature(signed_approval)
            if type(signed.get("expires")) not in (int, float):
                raise ChatConsentError("CHAT_CONSENT_RECEIPT_EXPIRY_INVALID")
            if (signed.get("device") != row[0]
                or signed.get("agent") != row[1]
                or signed.get("task") != row[2]
                or signed.get("nonce") != challenge_id
                or signed.get("approval_reference") != "host-chat:" + challenge_id
                or signed.get("uses") != 1
                or signed.get("expires", float("inf")) > row[5]
                or not isinstance(signed.get("request"), dict)
                or signed["request"].get("op") != row[3]
                or hashlib.sha256(canonical(signed["request"]).encode("utf-8")).hexdigest() != row[4]):
                raise ChatConsentError("CHAT_CONSENT_RECEIPT_SCOPE_MISMATCH")
            grant = self.authority.provision(signed_approval=signed_approval)
            con.execute("UPDATE requests SET committed=1,grant=? WHERE id=? AND committed=0",
                        (grant, challenge_id))
            con.commit()
            return {"schema": SCHEMA, "challenge_id": challenge_id,
                    "approval_granted": True, "authorization_id": grant,
                    "expires_at": signed["expires"], "uses": 1}
