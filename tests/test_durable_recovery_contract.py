"""Recovery decisions backed by real disposable SQLite RequestJournal files."""
import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))

from cua_durable_recovery import advise_recovery, RecoveryCoordinator
from ff_win_request_journal import RequestJournal, RequestJournalError


class TestDurableRecoveryContract(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(prefix="ff-durable-recovery-")
        self.addCleanup(self.t.cleanup)
        self.root = pathlib.Path(self.t.name)
        self.journal = RequestJournal(self.root,retention_seconds=604800)
        self.advisor = RecoveryCoordinator(self.journal)
        self.effects = []

    def effect(self):
        self.effects.append("single-effect")
        return {"ok":True,"private_sample":"not-for-recovery-output"}

    def test_completed_is_not_proof_of_effect_or_postcondition(self):
        completed = self.journal.execute("request-complete",{"op":"test","arg":1},self.effect)
        self.assertEqual(completed["state"],"completed")
        self.assertEqual(len(self.effects),1)
        decision = self.advisor.plan("request-complete")
        self.assertEqual(decision["journal_state"],"completed")
        self.assertTrue(decision["journal_has_recorded_response"])
        self.assertEqual(decision["next_step"],"verify_external_postcondition_and_cleanup_task_owned_resources")
        self.assertFalse(decision["previous_effect_independently_verified"])
        self.assertFalse(decision["automatic_retry_allowed"])
        self.assertNotIn("not-for-recovery-output",str(decision))
        self.assertFalse(decision["response_contents_returned"])
        # A lost ACK followed by the same request must return the recorded
        # outcome, NEVER invoke the operation twice.
        second=self.journal.execute("request-complete",{"op":"test","arg":1},self.effect)
        self.assertTrue(second["cached"])
        self.assertEqual(len(self.effects),1)

    def test_unknown_outcome_after_crash_never_retries(self):
        def ambiguous_dispatch():
            self.effects.append("external-operation-maybe-committed")
            raise RuntimeError("transport terminated after side effect")
        with self.assertRaises(RuntimeError):
            self.journal.execute("request-unknown",{"op":"mutate"},ambiguous_dispatch)
        # Simulate agent/controller restart: another journal instance at same root.
        reboot = RequestJournal(self.root)
        advice=RecoveryCoordinator(reboot).plan("request-unknown")
        self.assertEqual(advice["journal_state"],"outcome_unknown")
        self.assertEqual(advice["next_step"],"inspect_external_effect_and_reconcile_before_new_work")
        self.assertFalse(advice["automatic_retry_allowed"])
        response=reboot.execute("request-unknown",{"op":"mutate"},self.effect)
        self.assertEqual(response["state"],"outcome_unknown")
        self.assertEqual(len(self.effects),1)

    def test_not_found_is_not_permission_to_mutate(self):
        decision=self.advisor.plan("not-present")
        self.assertEqual(decision["journal_state"],"not_found")
        self.assertFalse(decision["automatic_retry_allowed"])
        self.assertFalse(decision["new_mutation_started"])
        self.assertEqual(decision["next_step"],"confirm_correct_device_journal_key_and_external_history")

    def test_expired_response_key_retains_tombstone_no_replay(self):
        old = RequestJournal(self.root,retention_seconds=0)
        old.execute("request-expired",{"op":"test"},self.effect)
        decision=RecoveryCoordinator(old).plan("request-expired")
        self.assertEqual(decision["journal_state"],"outcome_expired")
        self.assertFalse(decision["automatic_retry_allowed"])
        retry=old.execute("request-expired",{"op":"test"},self.effect)
        self.assertEqual(retry["state"],"outcome_expired")
        self.assertEqual(len(self.effects),1)

    def test_same_key_changed_payload_fails_closed(self):
        self.journal.execute("conflicted",{"x":"old"},self.effect)
        with self.assertRaisesRegex(RequestJournalError,"REQUEST_KEY_CONFLICT"):
            self.journal.execute("conflicted",{"x":"new"},self.effect)
        self.assertEqual(len(self.effects),1)

    def test_bad_state_never_suggests_replay(self):
        for incoming in ({"state":"dispatching"},{"state":"FAILED"},None,{"state":"malicious","response":{"token":"private"}}):
            decision=advise_recovery(incoming)
            self.assertEqual(decision["journal_state"],"unrecognized")
            self.assertFalse(decision["automatic_retry_allowed"])
            self.assertFalse(decision["owner_permission_verified"])
            self.assertNotIn("private",str(decision))

    def test_invalid_request_key_is_not_normalized_silently(self):
        with self.assertRaisesRegex(RequestJournalError,"REQUEST_KEY_INVALID"):
            self.advisor.plan("../private-file")


if __name__ == "__main__":
    unittest.main()
