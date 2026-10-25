"""Durable request lifecycle: no replay after lost ACK, crash or retention."""
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from ff_win_request_journal import (
    RequestJournal,RequestJournalError,choose_request_journal_root,
)


class TestDurableJournalRecovery(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory(prefix="ff-durable-p0-")
        self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name)
        self.journal=RequestJournal(self.root,retention_seconds=86400)

    def test_legacy_production_location_unchanged(self):
        actual=choose_request_journal_root(
            bridge_root=self.root/"bridge",
            override=None,local_appdata=str(self.root/"appdata"),
            home=self.root/"home",
        )
        self.assertEqual(actual,self.root/"appdata/FFWindowsBridge/state/request-outcomes")

    def test_explicit_isolated_root_keeps_durable_records_with_test(self):
        selected=choose_request_journal_root(
            bridge_root=self.root/"test-root",
            override=str(self.root/"test-root"),
            local_appdata=str(self.root/"real-account-appdata"),
            home=self.root,
        )
        self.assertEqual(selected,self.root/"test-root/state/request-outcomes")
        self.assertNotIn("real-account-appdata",str(selected))
        with self.assertRaisesRegex(RequestJournalError,"ROOT_MISMATCH"):
            choose_request_journal_root(
                bridge_root=self.root/"home-live",
                override=str(self.root/"test-root"),
                local_appdata=None,home=self.root,
            )
        with self.assertRaisesRegex(RequestJournalError,"ROOT_NOT_ABSOLUTE"):
            choose_request_journal_root(
                bridge_root=self.root/"test-root",
                override="relative-root",
                local_appdata=None,home=self.root,
            )

    def test_completed_effect_is_not_repeated_after_new_journal_instance(self):
        calls=[]
        payload={"op":"start_process","args":{"command":"owned-readonly-probe"}}
        def initial():
            calls.append("spawned")
            return {"ok":True,"result":{"session_id":"owned-session-01","exit_code":0}}
        first=self.journal.execute("task-01",payload,initial)
        self.assertEqual(first["state"],"completed")
        self.assertFalse(first["cached"])
        restarted=RequestJournal(self.root)
        repeated=restarted.execute("task-01",payload,lambda: calls.append("DUPLICATE"))
        self.assertEqual(repeated["state"],"completed")
        self.assertTrue(repeated["cached"])
        self.assertEqual(repeated["response"],first["response"])
        self.assertEqual(calls,["spawned"])
        self.assertEqual(restarted.status("task-01")["state"],"completed")

    def test_process_died_after_external_effect_unknown_never_replayed(self):
        calls=[]
        request={"op":"write_file","args":{"path":"owned-synthetic.txt"}}
        def interrupted():
            calls.append("external-effect-occurred")
            raise RuntimeError("simulated lost ACK after mutation")
        with self.assertRaises(RuntimeError):
            self.journal.execute("request-crash-01",request,interrupted)
        restarted=RequestJournal(self.root)
        self.assertEqual(restarted.status("request-crash-01")["state"],"outcome_unknown")
        result=restarted.execute("request-crash-01",request,lambda: calls.append("RETRY_FORBIDDEN"))
        self.assertEqual(result["state"],"outcome_unknown")
        self.assertFalse(result["retry_safe"])
        self.assertEqual(calls,["external-effect-occurred"])

    def test_same_key_changed_payload_rejected(self):
        self.journal.execute("task-2",{"a":1},lambda:{"ok":True})
        with self.assertRaisesRegex(RequestJournalError,"REQUEST_KEY_CONFLICT"):
            self.journal.execute("task-2",{"a":2},lambda:{"ok":True})
        self.assertEqual(self.journal.status("task-2")["state"],"completed")

    def test_expired_response_tombstone_prevents_unsafe_reuse(self):
        journal=RequestJournal(self.root,retention_seconds=-1)
        request={"op":"copy_path","args":{"kind":"simulated"}}
        events=[]
        journal.execute("task-3",request,lambda:events.append("once") or {"ok":True})
        journal.maintain()
        status=journal.status("task-3")
        self.assertEqual(status["state"],"outcome_expired")
        result=journal.execute("task-3",request,lambda:events.append("BAD_REPLAY"))
        self.assertEqual(result["state"],"outcome_expired")
        self.assertFalse(result["retry_safe"])
        self.assertEqual(events,["once"])

    def test_invalid_request_key_fails_before_dispatch(self):
        with self.assertRaisesRegex(RequestJournalError,"REQUEST_KEY_INVALID"):
            self.journal.execute("../../escape",{},lambda:{"ok":True})
        self.assertFalse(self.journal.path.is_file())


if __name__=="__main__":
    unittest.main()
