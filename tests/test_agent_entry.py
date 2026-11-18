"""Regression coverage for separately granted task identities on the shared Hub."""
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import sys
import time
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"))
from ff_agent_entry import entry_call
from ff_hub import Hub
from ff_hub_store import HubError


class AgentEntryTest(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.hub = Hub(Path(self.temp.name))
        self.clock = 1000
        self.authority = self.hub.entry_authority
        self.authority.clock = lambda: self.clock
        self.grant, self.token = self.enroll("one")

    def tearDown(self):
        self.hub.shutdown()
        self.hub.store.close()
        self.temp.cleanup()

    def enroll(self, task, scopes=None, apps=None):
        return self.authority.issue(client_id=f"client-{task}", agent_id="shared-agent", task_id=task,
                                    scopes=scopes or ["locks"], apps=apps or [], ttl=30)

    def call(self, op, *, token=None, session=None, args=None, key=None):
        request = {"op": op, "args": args or {}}
        if session is not None:
            request["session_id"] = session
        if key:
            request["request_key"] = key
        return entry_call(self.hub, self.authority, f"Bearer {token or self.token}", request)

    def expect(self, code, op, **kwargs):
        with self.assertRaises(HubError) as raised:
            self.call(op, **kwargs)
        self.assertEqual(raised.exception.code, code)

    def test_enrollment_stores_digest_and_rejects_duplicate_identity(self):
        with closing(sqlite3.connect(self.authority.path)) as db:
            fields = db.execute("SELECT * FROM grants").fetchone()
            self.assertNotIn(self.token, fields)
        with self.assertRaisesRegex(HubError, "ENTRY_TASK_ALREADY_ENROLLED"):
            self.enroll("one")
        self.expect("ENTRY_UNAUTHORIZED", "capabilities", token=self.token + "X")
        self.expect("ENTRY_IDENTITY_FIXED", "session_open", args={"agent_id": "other"})
        self.expect("ENTRY_SCOPE_DENIED", "secret_list")

    def test_retry_open_has_stable_identity_and_no_extra_credentials(self):
        session = self.call("session_open")
        self.assertNotIn("session_secret", session)
        self.assertNotIn("resume_token", session)
        self.assertEqual(session["session_id"], self.call("session_open")["session_id"])
        self.assertTrue(self.call("session_open")["reused"])
        self.assertEqual(len(self.hub.store.sessions()), 1)
        self.call("task_cancel", session=session["session_id"], key="cancel-0001")
        self.assertEqual(self.call("session_open")["state"], "closed")
        self.assertEqual(self.call("request_status", session=session["session_id"],
                                   args={"request_key": "cancel-0001"})["state"], "completed")

    def test_cross_task_session_receipts_resources_and_audit(self):
        mine = self.call("session_open")["session_id"]
        _, token = self.enroll("two")
        other = self.call("session_open", token=token)["session_id"]
        args = {"kind": "custom", "key": "fixture"}
        self.call("resource_claim", session=mine, args=args, key="claim-0001")
        self.expect("SESSION_INVALID", "session_status", session=mine, token=token)
        receipt = self.call("request_status", token=token, session=other, args={"request_key": "claim-0001"})
        self.assertEqual(receipt["state"], "not_found")
        audit = self.call("audit_read", token=token, session=other, args={"task_id": "one"})
        self.assertTrue(audit["records"])
        self.assertEqual({record["task_id"] for record in audit["records"]}, {"two"})
        self.expect("REQUEST_KEY_REQUIRED", "resource_release", session=mine, args=args)
        self.call("resource_release", session=mine, args=args, key="release-0001")
        self.assertTrue(self.call("resource_release", session=mine, args=args, key="release-0001")["deduplicated"])
        self.assertEqual(self.call("resource_list", session=mine)["resources"], [])

    def test_revocation_and_expiry_clean_only_own_resources(self):
        mine = self.call("session_open")["session_id"]
        self.clock += 5
        _, token = self.enroll("two")
        other = self.call("session_open", token=token)["session_id"]
        for session, bearer in ((mine, self.token), (other, token)):
            self.call("resource_claim", token=bearer, session=session, key="claim-0001",
                      args={"kind": "custom", "key": session})
        self.clock += 25
        self.expect("ENTRY_UNAUTHORIZED", "session_status", session=mine)
        self.assertEqual(self.hub.maintain()["expired_sessions"], 1)
        self.assertEqual(self.hub.store.resources(session_id=mine), [])
        self.assertEqual(len(self.call("resource_list", token=token, session=other)["resources"]), 1)
        grant = self.authority.authorize(f"Bearer {token}")["grant_id"]
        self.assertTrue(self.authority.revoke(grant))
        self.expect("ENTRY_UNAUTHORIZED", "session_status", token=token, session=other)
        self.hub.maintain()
        self.assertEqual(self.hub.store.resources(), [])

    def test_scoped_route_cannot_be_overridden(self):
        _, token = self.enroll("browser", scopes=["private_browser"])
        route = self.call("route_plan", token=token)
        self.assertEqual(route["selected"], "private_cdp")
        self.assertFalse(route["foreground_fallback"])
        session = self.call("session_open", token=token)["session_id"]
        self.expect("ENTRY_BROWSER_COMMAND_DENIED", "private_browser", token=token, session=session,
                    args={"command": "evaluate"})
        self.expect("ENTRY_BROWSER_COMMAND_DENIED", "private_browser", token=token, session=session,
                    args={"command": "open", "foreground": True})
        self.expect("ENTRY_SCOPE_DENIED", "browser", token=token, session=session, args={"command": "open"})
        self.expect("PERMISSION_REQUIRED", "private_browser", token=token, session=session,
                    args={"command": "open"}, key="chrome-0001")

    def test_old_legacy_session_cannot_cancel_resumed_owner(self):
        old = self.hub.dispatch({"op": "session_open", "args": {"agent_id": "old", "task_id": "legacy"}})
        current = self.hub.dispatch({"op": "session_open", "args": {"agent_id": "old", "task_id": "legacy",
                                                                    "resume_token": old["resume_token"]}})
        with self.assertRaisesRegex(HubError, "SESSION_CLOSED"):
            self.hub.dispatch({"op": "task_cancel", "session_id": old["session_id"],
                               "session_secret": old["session_secret"], "request_key": "cancel-0001"})
        self.assertEqual([row["session_id"] for row in self.hub.store.sessions()], [current["session_id"]])

    def test_task_files_are_bounded_journaled_and_cleaned(self):
        _, token = self.enroll("files", scopes=["artifacts"])
        session = self.call("session_open", token=token)["session_id"]
        args = {"command": "put", "name": "report.txt", "content_base64": "ZmZicmlkZ2U="}
        result = self.call("task_file", session=session, token=token, args=args, key="file-0001")
        self.assertTrue(self.call("task_file", session=session, token=token, args=args, key="file-0001")["deduplicated"])
        readback = self.call("task_file", session=session, token=token, args={**args, "command": "read"})
        self.assertEqual(readback["sha256"], result["sha256"])
        self.assertEqual(readback["content_base64"], args["content_base64"])
        for name in ("../owned.txt", "con.txt", "lpt1.json", "report.txt:ads", "report."):
            self.expect("ENTRY_FILENAME_INVALID", "task_file", session=session, token=token,
                        args={**args, "name": name}, key=f"invalid-{name}")
        cancel = self.call("task_cancel", session=session, token=token, key="cancel-0001")
        self.assertEqual(cancel["task_files_removed"], 1)
        self.assertFalse((self.hub.entry_artifacts.root / session).exists())

    def test_revocation_while_queued_prevents_lock_admission(self):
        mine = self.call("session_open")["session_id"]
        other_grant, token = self.enroll("two")
        other = self.call("session_open", token=token)["session_id"]
        lock = {"kind": "custom", "key": "shared-queue"}
        self.call("resource_claim", session=mine, args=lock, key="mine-0001")
        with ThreadPoolExecutor(max_workers=1) as executor:
            queued = executor.submit(self.call, "resource_claim", token=token, session=other,
                                     args={**lock, "wait_seconds": 3}, key="queued-0001")
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline:
                receipt = self.call("request_status", token=token, session=other, args={"request_key": "queued-0001"})
                if receipt["state"] == "started":
                    break
                time.sleep(.02)
            else:
                self.fail("scoped request did not enter the queue")
            self.authority.revoke(other_grant["grant_id"])
            self.call("resource_release", session=mine, args=lock, key="release-0001")
            with self.assertRaisesRegex(HubError, "ENTRY_UNAUTHORIZED"):
                queued.result(timeout=3)
        self.assertEqual(self.hub.store.resources(session_id=other), [])
