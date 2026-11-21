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
        self.assertIn(route["selected"], {"persistent_playwright", "private_cdp"})
        self.assertNotIn(route["selected"], {"owner_chrome_extension", "owner_chrome_profile1_hidden_secondary"})
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

    def test_qa003_grant_renewal_preserves_identity_and_session_and_rejects_escalation(self):
        # Active grant: claim a lock, then renew and rotate token without changing task_id or session_id.
        sid = self.call("session_open")["session_id"]
        self.call("resource_claim", session=sid, args={"kind": "custom", "key": "steady-lock"}, key="lock-0001")
        self.clock += 20
        renewed, rotated_token = self.authority.renew(
            client_id="client-one", agent_id="shared-agent", task_id="one", ttl=60
        )
        self.assertEqual(renewed["grant_id"], self.grant["grant_id"])
        self.assertEqual(renewed["revision"], 2)
        self.assertEqual(renewed["expires_at"], self.clock + 60)
        self.assertNotEqual(rotated_token, self.token)
        # Old token must be rejected immediately; rotated token keeps the live session and held lock.
        self.expect("ENTRY_UNAUTHORIZED", "session_status", token=self.token, session=sid)
        reused = self.call("session_open", token=rotated_token)
        self.assertTrue(reused["reused"])
        self.assertEqual(reused["session_id"], sid)
        resources = self.call("resource_list", token=rotated_token, session=sid)["resources"]
        self.assertEqual([r["key"] for r in resources], ["steady-lock"])
        # Scope escalation via renew is forbidden; narrowing scopes succeeds.
        with self.assertRaisesRegex(HubError, "ENTRY_SCOPE_ESCALATION_DENIED"):
            self.authority.renew(client_id="client-one", agent_id="shared-agent", task_id="one",
                                 ttl=60, scopes=["locks", "artifacts"])
        with self.assertRaisesRegex(HubError, "ENTRY_GRANT_OWNER_MISMATCH"):
            self.authority.renew(client_id="other-client", agent_id="shared-agent", task_id="one", ttl=60)
        # Expired grant (both before and after Hub.maintain cleanup) can be renewed with same agent_id/task_id.
        self.clock += 61
        self.expect("ENTRY_UNAUTHORIZED", "session_status", token=rotated_token, session=sid)
        renewed_after_exp, token3 = self.authority.renew(
            client_id="client-one", agent_id="shared-agent", task_id="one", ttl=120
        )
        self.assertEqual(renewed_after_exp["grant_id"], self.grant["grant_id"])
        self.assertEqual(renewed_after_exp["revision"], 3)
        self.assertEqual(self.call("session_open", token=token3)["session_id"], sid)
        # Expire again and let maintain() clean up; renew still allows opening fresh active session.
        self.clock += 121
        self.assertEqual(self.hub.maintain()["expired_sessions"], 1)
        self.assertEqual(self.hub.store.resources(session_id=sid), [])
        _, token4 = self.authority.renew(client_id="client-one", agent_id="shared-agent", task_id="one", ttl=90)
        sid_after_maintain = self.call("session_open", token=token4)["session_id"]
        self.assertNotEqual(sid_after_maintain, sid)
        # Revoked grant CANNOT be renewed, but CAN be re-issued with the same agent_id/task_id and a new grant_id.
        self.assertTrue(self.authority.revoke(self.grant["grant_id"]))
        with self.assertRaisesRegex(HubError, "ENTRY_GRANT_REVOKED"):
            self.authority.renew(client_id="client-one", agent_id="shared-agent", task_id="one", ttl=60)
        reissued, token5 = self.enroll("one")
        self.assertTrue(reissued["reissued"])
        self.assertEqual(reissued["previous_grant_id"], self.grant["grant_id"])
        self.assertNotEqual(reissued["grant_id"], self.grant["grant_id"])
        self.expect("ENTRY_UNAUTHORIZED", "session_status", token=token4, session=sid_after_maintain)
        sid_reissued = self.call("session_open", token=token5)["session_id"]
        self.assertNotEqual(sid_reissued, sid_after_maintain)
        self.assertEqual(self.call("session_status", token=token5, session=sid_reissued)["task_id"], "one")
        actions = [row["action"] for row in self.authority.receipts(agent_id="shared-agent", task_id="one")]
        self.assertEqual(actions, ["issue", "renew", "renew", "renew", "revoke", "reissue"])

    def test_qa003_concurrent_renew_and_authorize_is_atomic(self):
        from concurrent.futures import as_completed
        tokens = [self.token]
        lock = __import__("threading").Lock()

        def rotate(_idx):
            _, tok = self.authority.renew(client_id="client-one", agent_id="shared-agent", task_id="one", ttl=60)
            with lock:
                tokens.append(tok)
            return tok

        with ThreadPoolExecutor(max_workers=6) as pool:
            futs = [pool.submit(rotate, i) for i in range(12)]
            for f in as_completed(futs):
                f.result()
        valid_count = 0
        for tok in tokens:
            try:
                self.authority.authorize(f"Bearer {tok}")
                valid_count += 1
            except HubError as exc:
                self.assertEqual(exc.code, "ENTRY_UNAUTHORIZED")
        self.assertEqual(valid_count, 1)

    def test_qa003_legacy_unique_table_migrates_cleanly(self):
        legacy_dir = Path(self.temp.name) / "legacy-db"
        legacy_dir.mkdir()
        db_path = legacy_dir / "entry-grants.sqlite3"
        with closing(sqlite3.connect(db_path)) as db, db:
            db.execute("""CREATE TABLE grants (
                grant_id TEXT PRIMARY KEY, digest TEXT NOT NULL, client_id TEXT NOT NULL,
                agent_id TEXT NOT NULL, task_id TEXT NOT NULL, scopes TEXT NOT NULL, apps TEXT NOT NULL,
                expires_at REAL NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, UNIQUE(agent_id, task_id))""")
            db.execute("INSERT INTO grants VALUES ('eg-00000000000000000000000000000001', 'deadbeef', 'c', 'a', 't', 'locks', '', 500.0, 0)")
        from ff_agent_entry import EntryAuthority
        auth = EntryAuthority(legacy_dir, clock=lambda: 1000.0)
        reissued, token = auth.issue(client_id="c", agent_id="a", task_id="t", scopes=["locks"], apps=[], ttl=60)
        self.assertTrue(reissued["reissued"])
        self.assertEqual(auth.authorize(f"Bearer {token}")["task_id"], "t")

    def test_qa003_cli_renew_and_reissue_overwrite(self):
        import json, subprocess
        cli = Path(__file__).resolve().parents[1] / "tools" / "agent_entry.py"
        state = Path(self.temp.name) / "cli-state"
        cred = Path(self.temp.name) / "cli.credential"
        base = [sys.executable, str(cli)]
        out1 = json.loads(subprocess.check_output(
            [*base, "issue", "--state-dir", str(state), "--credential-file", str(cred),
             "--client", "cli-c", "--agent", "cli-a", "--task", "cli-t", "--ttl", "60", "--scope", "locks"],
            text=True))
        self.assertTrue(out1["ok"])
        tok1 = cred.read_text(encoding="ascii").strip()
        out2 = json.loads(subprocess.check_output(
            [*base, "renew", "--state-dir", str(state), "--credential-file", str(cred),
             "--client", "cli-c", "--agent", "cli-a", "--task", "cli-t", "--ttl", "120"],
            text=True))
        self.assertTrue(out2["ok"])
        self.assertEqual(out2["result"]["grant_id"], out1["result"]["grant_id"])
        self.assertEqual(out2["result"]["revision"], 2)
        tok2 = cred.read_text(encoding="ascii").strip()
        self.assertNotEqual(tok2, tok1)
        revoked = json.loads(subprocess.check_output(
            [*base, "revoke", "--state-dir", str(state), "--grant-id", out1["result"]["grant_id"]],
            text=True))
        self.assertTrue(revoked["result"]["revoked"])
        out3 = json.loads(subprocess.check_output(
            [*base, "issue", "--state-dir", str(state), "--credential-file", str(cred),
             "--client", "cli-c", "--agent", "cli-a", "--task", "cli-t", "--ttl", "60", "--scope", "locks", "--overwrite"],
            text=True))
        self.assertTrue(out3["ok"] and out3["result"]["reissued"])
        self.assertNotEqual(out3["result"]["grant_id"], out1["result"]["grant_id"])
