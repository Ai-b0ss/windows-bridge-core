"""Restore must never follow a substituted log outside task ownership."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

RUNTIME = Path(__file__).resolve().parents[1] / "runtime/bridge-v3"
sys.path.insert(0, str(RUNTIME))


class TestDetachedLogOwnership(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="ff-detached-unit-")
        spec = importlib.util.spec_from_file_location("detached_test_agent", RUNTIME / "ff_win_v3_agent.py")
        cls.agent = importlib.util.module_from_spec(spec)
        with patch.dict(os.environ, {"FF_BRIDGE_ROOT": cls.temp.name}):
            spec.loader.exec_module(cls.agent)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.temp_case = tempfile.TemporaryDirectory(dir=self.temp.name)
        self.addCleanup(self.temp_case.cleanup)
        self.root = Path(self.temp_case.name) / "bridge-v3"
        self.log_dir = self.root / "state/detached_logs"
        self.log_dir.mkdir(parents=True)
        self.sid = "0123456789abcdef"
        self.log = self.log_dir / (self.sid + ".log")
        self.log.write_text("OWNED", encoding="utf-8")
        p = patch.object(self.agent, "V3_ROOT", self.root)
        p.start()
        self.addCleanup(p.stop)

    def test_regular_owned_file_and_invalid_identifiers(self):
        self.assertEqual(self.agent.detached_log_path(self.sid, self.log), self.log)
        self.assertIsNone(self.agent.detached_log_path("../escape", self.log))
        self.assertIsNone(self.agent.detached_log_path(self.sid, self.root / "other.log"))
        self.log.unlink()
        self.assertIsNone(self.agent.detached_log_path(self.sid, self.log))

    def test_task_scope_roundtrips_and_invalid_scope_never_gets_invented(self):
        from types import SimpleNamespace
        state = self.root / "state/detached_sessions.json"
        owned = SimpleNamespace(id=self.sid, pid=123, log_path=self.log,
                                command="owned", cwd="test", shell="test", created_at=1,
                                owner_scope=("agent-a", "task-a"))
        with patch.object(self.agent, "DETACHED_STATE_PATH", state), \
             patch.object(self.agent, "process_creation_token", return_value=456):
            self.agent.save_detached_session(owned)
        raw = json.loads(state.read_text(encoding="utf-8"))
        self.assertEqual(raw[self.sid]["owner_scope"], ["agent-a", "task-a"])
        for scope, expected in ((["agent-a", "task-a"], ("agent-a", "task-a")),
                                (None, None), (["agent-a", "../foreign"], None)):
            raw[self.sid]["owner_scope"] = scope
            state.write_text(json.dumps(raw), encoding="utf-8")
            with patch.object(self.agent, "DETACHED_STATE_PATH", state), \
                 patch.object(self.agent, "process_identity_matches", return_value=True), \
                 patch.object(self.agent, "DetachedProcessStub"), \
                 patch.object(self.agent, "Session") as session:
                self.agent.recover_detached_sessions()
                self.assertEqual(session.call_args.kwargs["owner_scope"], expected)

    def make_link(self, link, target, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except OSError:
            self.skipTest("OS account cannot create symlinks; reparse simulation is tested separately")

    def test_symlink_file_is_not_resolved_into_owned_file(self):
        outside = Path(self.temp_case.name) / "foreign.log"
        outside.write_text("FOREIGN", encoding="utf-8")
        self.log.unlink()
        self.make_link(self.log, outside)
        self.assertIsNone(self.agent.detached_log_path(self.sid, self.log))

    def test_symlink_parent_is_rejected(self):
        outside = Path(self.temp_case.name) / "outside"
        self.log_dir.rename(outside)
        self.make_link(self.log_dir, outside, directory=True)
        self.assertIsNone(self.agent.detached_log_path(self.sid, self.log))

    def test_hardlinked_file_is_not_task_exclusive(self):
        os.link(self.log, Path(self.temp_case.name) / "foreign-alias.log")
        self.assertIsNone(self.agent.detached_log_path(self.sid, self.log))

    def test_windows_reparse_attributes_are_rejected(self):
        from types import SimpleNamespace
        original = Path.lstat
        target = self.log_dir
        def lstat(path, *args, **kwargs):
            actual = original(path, *args, **kwargs)
            if path == target:
                return SimpleNamespace(st_mode=actual.st_mode, st_file_attributes=0x400)
            return actual
        with patch.object(Path, "lstat", lstat):
            self.assertIsNone(self.agent.detached_log_path(self.sid, self.log))

    def test_recovery_rejects_link_before_starting_log_tailer(self):
        outside = Path(self.temp_case.name) / "foreign.log"
        outside.write_text("FOREIGN", encoding="utf-8")
        self.log.unlink()
        self.make_link(self.log, outside)
        state = self.root / "state/detached_sessions.json"
        state.write_text(json.dumps({self.sid: {
            "pid": 123, "pid_creation_token": 456, "log_path": str(self.log),
        }}), encoding="utf-8")
        with patch.object(self.agent, "DETACHED_STATE_PATH", state), \
             patch.object(self.agent, "process_identity_matches", return_value=True), \
             patch.object(self.agent, "Session") as session:
            self.assertEqual(self.agent.recover_detached_sessions(), {})
            session.assert_not_called()
        self.assertEqual(outside.read_text(encoding="utf-8"), "FOREIGN")


if __name__ == "__main__":
    unittest.main()
