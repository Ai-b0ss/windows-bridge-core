"""Real bounded Git programmatic tasks on disposable repositories, no UI/model."""
from __future__ import annotations
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime/bridge-v3"))
from cua_bridge_v3 import CuaBridgeControlPlane, CuaBridgeError

GIT = shutil.which("git.exe") or shutil.which("git")


@unittest.skipUnless(GIT, "Git CLI not installed in test environment")
class TestGitTaskExecute(unittest.TestCase):
    def setUp(self):
        self.folder = TemporaryDirectory(prefix="ff-git-owned-")
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name) / "repository"
        self.root.mkdir()
        subprocess.run([GIT, "init", "-q", str(self.root)], check=True, capture_output=True)
        self.fixture = self.root / "README.txt"
        self.fixture.write_text("baseline\n", encoding="utf-8")
        self.git("add", "README.txt")
        self.git("-c", "user.name=Test",
                 "-c", "user.email=test@example.invalid", "commit", "-qm", "baseline")
        self.controller = CuaBridgeControlPlane.__new__(CuaBridgeControlPlane)
        self.args = {
            "command": "task_execute", "app": "Git",
            "task": "git.repository.status", "operation": "status.read",
            "agent_id": "test-agent", "task_id": "test-task",
            "action_args": {"repo_path": str(self.root)},
        }

    def git(self, *args):
        return subprocess.run([GIT, "-C", str(self.root), *args],
                              check=True, capture_output=True)

    def execute(self, **changes):
        return self.controller._task_execute({**self.args, **changes})

    def test_clean_and_dirty_status_are_real_and_read_only(self):
        initial = hashlib.sha256(self.fixture.read_bytes()).hexdigest()
        clean = self.execute(expected_clean=True)
        self.assertEqual(clean["route"], "OFFICIAL_GIT_CLI")
        self.assertTrue(clean["clean"])
        self.assertTrue(clean["verified"])
        self.assertFalse(clean["execution"]["foreground_used"])
        self.assertFalse(clean["execution"]["model_called"])
        self.assertFalse(clean["execution"]["paid_inference_used"])
        self.assertEqual(clean["verification"]["kind"], "two_fresh_real_git_cli_status_reads")
        self.assertFalse(clean["verification"]["independent_saved_artifact_verified"])
        self.assertEqual(hashlib.sha256(self.fixture.read_bytes()).hexdigest(), initial)
        self.fixture.write_text("changed by test\n", encoding="utf-8")
        before_read = hashlib.sha256(self.fixture.read_bytes()).hexdigest()
        dirty = self.execute(expected_clean=False)
        self.assertFalse(dirty["clean"])
        self.assertTrue(any("README.txt" in row for row in dirty["status_lines"]))
        self.assertEqual(hashlib.sha256(self.fixture.read_bytes()).hexdigest(), before_read)

    def test_unknown_expectation_not_mistaken_for_task_failure(self):
        self.fixture.write_text("dirty\n", encoding="utf-8")
        receipt = self.execute()
        self.assertFalse(receipt["clean"])
        self.assertFalse(receipt["verification"]["user_expectation_supplied"])

    def test_wrong_expectation_blocks_claimed_success(self):
        self.fixture.write_text("dirty\n", encoding="utf-8")
        with self.assertRaises(CuaBridgeError) as caught:
            self.execute(expected_clean=True)
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_POSTCONDITION_FAILED")

    def test_nested_repo_scope_not_silently_expanded(self):
        sub = self.root / "child"
        sub.mkdir()
        with self.assertRaises(CuaBridgeError) as caught:
            self.execute(action_args={"repo_path": str(sub)})
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_REPOSITORY_ROOT_REQUIRED")

    def test_invalid_and_forged_foreground_flags_rejected(self):
        attacks = [
            {"approved": True},
            {"physical_input_allowed": True},
            {"foreground_allowed": True},
            {"paid_inference": True},
            {"action_args": {"repo_path": str(self.root), "command": "rm -rf"}},
            {"action_args": {"repo_path": str(self.root) + "\n--config"}},
            {"task_id": ""},
            {"expected_clean": "true"},
            {"task": "cursor.assistant"},
            {"operation": "shell.execute"},
        ]
        for attack in attacks:
            with self.subTest(attack=attack):
                before = self.fixture.read_bytes()
                with self.assertRaises(CuaBridgeError):
                    self.execute(**attack)
                self.assertEqual(self.fixture.read_bytes(), before)

    def test_unowned_or_nonrepo_path_denied(self):
        directory = Path(self.folder.name) / "not-git"
        directory.mkdir()
        with self.assertRaises(CuaBridgeError) as caught:
            self.execute(action_args={"repo_path": str(directory)})
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_REPOSITORY_ROOT_REQUIRED")


if __name__ == "__main__":
    unittest.main()
