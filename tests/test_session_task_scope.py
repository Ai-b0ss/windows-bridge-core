"""Task isolation is restored from owned session metadata, never first caller."""
from pathlib import Path
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime/bridge-v3"))
from cua_restricted_rpc import install


class Error(RuntimeError):
    def __init__(self, code, **kwargs):
        super().__init__(code)


class TestSessionTaskScope(unittest.TestCase):
    def setUp(self):
        self.scope = {"agent_id": "agent-a", "task_id": "task-a"}
        self.foreign = {"agent_id": "agent-a", "task_id": "task-b"}
        self.sessions = {
            "ours": SimpleNamespace(owner_scope=("agent-a", "task-a")),
            "foreign": SimpleNamespace(owner_scope=("agent-b", "task-b")),
            "legacy": SimpleNamespace(owner_scope=None),
        }
        self.originals = {name: Mock(return_value={"ok": True}) for name in (
            "read_process_output", "interact_with_process", "force_terminate")}
        self.core = SimpleNamespace(
            OPS={**self.originals, "list_sessions": lambda args: {"sessions": [
                {"session_id": sid, "command": "private-" + sid} for sid in self.sessions]}},
            RPCError=Error, get_session=lambda sid: self.sessions[sid],
            command_blocked=lambda command: None,
            STATE=SimpleNamespace(sessions=self.sessions, lock=threading.RLock()))
        install(self.core, shell_policy="user")

    def test_owner_can_read_interact_and_terminate_recovered_session(self):
        for op, original in self.originals.items():
            self.core.OPS[op]({"session_id": "ours", **self.scope})
            original.assert_called_once()

    def test_different_task_cannot_read_write_or_terminate(self):
        for op, original in self.originals.items():
            with self.assertRaisesRegex(Error, "OUTSIDE_TASK_SCOPE"):
                self.core.OPS[op]({"session_id": "ours", **self.foreign})
            original.assert_not_called()

    def test_unbound_legacy_session_cannot_be_claimed_by_first_caller(self):
        for op, original in self.originals.items():
            with self.assertRaisesRegex(Error, "OUTSIDE_TASK_SCOPE"):
                self.core.OPS[op]({"session_id": "legacy", **self.scope})
            original.assert_not_called()

    def test_list_exposes_only_exact_task_and_requires_identity(self):
        result = self.core.OPS["list_sessions"](self.scope)
        self.assertEqual(result["sessions"], [{"session_id": "ours", "command": "private-ours"}])
        self.assertEqual(self.core.OPS["list_sessions"](self.foreign)["sessions"], [])
        with self.assertRaisesRegex(Error, "IDENTITY_INVALID"):
            self.core.OPS["list_sessions"]({})


if __name__ == "__main__":
    unittest.main()
