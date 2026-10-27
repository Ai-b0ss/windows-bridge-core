"""No cross-agent cleanup from an expired root process with live Job members."""
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
import ff_win_v3_agent as agent


class FakeOwnedProcess:
    stdout = None
    stderr = None

    def __init__(self, pid, *, failure=False):
        self.pid = pid
        self.failure = failure
        self.terminate_calls = 0
        self.close_calls = 0

    def poll(self):
        return 0

    def terminate_tree(self):
        self.terminate_calls += 1
        if self.failure:
            raise OSError("isolated job termination failure")
        return {"descendant_cleanup_verified": True}

    def close(self):
        self.close_calls += 1


class TestScopedSessionReaping(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.temp = Path(tmp.name)
        self.state = SimpleNamespace(lock=threading.RLock(), sessions={})
        replacement = patch.object(agent, "STATE", self.state)
        replacement.start()
        self.addCleanup(replacement.stop)
        marker = patch.object(agent, "DETACHED_STATE_PATH", self.temp / "detached.json")
        marker.start()
        self.addCleanup(marker.stop)

    def session(self, name, ownership, *, failed=False):
        process = FakeOwnedProcess(len(self.state.sessions) + 100, failure=failed)
        current = agent.Session(process, "fixture", str(self.temp), "python.exe",
                                session_id=name, owner_scope=ownership)
        current.closed_at = 1  # Independently known completed, long-expired root.
        self.state.sessions[name] = current
        return process

    def test_own_cleanup_preserves_other_agent_descendants(self):
        own = self.session("owned", ("agent-a", "task-1"))
        other = self.session("foreign", ("agent-b", "task-2"))
        legacy = self.session("legacy", None)
        receipt = agent.op_cleanup_sessions({
            "agent_id": "agent-a", "task_id": "task-1", "older_than_seconds": 0
        })
        self.assertEqual(receipt["removed"], ["owned"])
        self.assertEqual(receipt["owned_job_descendants_verified"], ["owned"])
        self.assertTrue(receipt["scope_enforced"])
        self.assertEqual(receipt["other_task_sessions_skipped"], 2)
        self.assertEqual(own.terminate_calls, 1)
        self.assertEqual(own.close_calls, 1)
        self.assertEqual(other.terminate_calls, 0)
        self.assertEqual(legacy.terminate_calls, 0)
        self.assertEqual(set(self.state.sessions), {"foreign", "legacy"})

    def test_unscoped_housekeeping_reaps_only_legacy_unowned(self):
        legacy = self.session("legacy", None)
        foreign = self.session("foreign", ("agent-b", "task-2"))
        receipt = agent.op_cleanup_sessions({"older_than_seconds": 0})
        self.assertEqual(receipt["removed"], ["legacy"])
        self.assertFalse(receipt["scope_enforced"])
        self.assertEqual(receipt["other_task_sessions_skipped"], 1)
        self.assertEqual(legacy.terminate_calls, 1)
        self.assertEqual(foreign.terminate_calls, 0)
        self.assertIn("foreign", self.state.sessions)

    def test_partial_scope_and_invalid_age_are_fail_closed(self):
        process = self.session("owned", ("agent-a", "task-1"))
        for payload, error in (
            ({"agent_id": "agent-a"}, "CLEANUP_SCOPE_INCOMPLETE"),
            ({"task_id": "task-1"}, "CLEANUP_SCOPE_INCOMPLETE"),
            ({"agent_id": "bad id!", "task_id": "task-1"}, "CLEANUP_SCOPE_INVALID"),
            ({"older_than_seconds": True}, "CLEANUP_AGE_INVALID"),
            ({"older_than_seconds": -1}, "CLEANUP_AGE_INVALID"),
            ({"older_than_seconds": 2592001}, "CLEANUP_AGE_INVALID"),
        ):
            with self.subTest(payload=payload), self.assertRaises(agent.RPCError) as caught:
                agent.op_cleanup_sessions(payload)
            self.assertEqual(caught.exception.code, error)
        self.assertEqual(process.terminate_calls, 0)
        self.assertIn("owned", self.state.sessions)

    def test_failed_owned_job_cleanup_is_not_reported_as_removed(self):
        process = self.session("owned", ("agent-a", "task-1"), failed=True)
        receipt = agent.op_cleanup_sessions({
            "agent_id": "agent-a", "task_id": "task-1", "older_than_seconds": 0
        })
        self.assertEqual(receipt["removed"], [])
        self.assertEqual(receipt["owned_job_descendants_verified"], [])
        self.assertEqual(receipt["cleanup_failed"], ["owned"])
        self.assertEqual(process.close_calls, 0)
        self.assertIn("owned", self.state.sessions)


if __name__ == "__main__":
    unittest.main()
