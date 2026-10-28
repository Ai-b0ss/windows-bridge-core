"""Real, bounded, read-only Git diff task through the public Core router.

Tests run on disposable repositories. Nothing reaches the owner's live
workspace and no model, GUI, network or paid service is involved.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
from cua_bridge_v3 import CuaBridgeControlPlane, CuaBridgeError
from cua_task_routes import task_routes

GIT = shutil.which("git.exe") or shutil.which("git")


@unittest.skipUnless(GIT, "Git CLI unavailable in this test environment")
class TestGitDiffTask(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(prefix="ff-git-diff-owned-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repository"
        self.root.mkdir()
        subprocess.run([GIT, "init", "-q", str(self.root)],
                       check=True, capture_output=True, timeout=15)
        self.readme = self.root / "README.txt"
        self.readme.write_text("alpha\n", encoding="utf-8")
        self.git("add", "README.txt")
        self.git("-c", "user.name=Test", "-c",
                 "user.email=ci@example.invalid", "commit", "-qm", "baseline")
        self.controller = CuaBridgeControlPlane.__new__(CuaBridgeControlPlane)
        self.args = {
            "command": "task_execute", "app": "Git",
            "task": "git.repository.diff", "operation": "diff.stat.read",
            "agent_id": "ci-git-agent", "task_id": "ci-git-diff",
            "action_args": {"repo_path": str(self.root)},
        }

    def git(self, *args):
        return subprocess.run([GIT, "-C", str(self.root), *args],
                              check=True, capture_output=True, timeout=15)

    def execute(self, **overrides):
        return self.controller._task_execute({**self.args, **overrides})

    def test_real_unstaged_diff_two_readbacks_and_no_index_lock(self):
        clean = self.execute(expected_changed=False)
        self.assertTrue(clean["verified"])
        self.assertFalse(clean["changed"])
        self.assertEqual(clean["changed_file_count"], 0)
        self.assertEqual(clean["files"], [])
        self.assertEqual(clean["verification"]["kind"],
                         "two_fresh_real_git_cli_numstat_reads")
        self.assertFalse(clean["verification"]["independent_saved_artifact_verified"])
        self.readme.write_text("alpha\nbeta\n", encoding="utf-8")
        before = hashlib.sha256(self.readme.read_bytes()).hexdigest()
        diff = self.execute(expected_changed=True)
        self.assertEqual(diff["route"], "OFFICIAL_GIT_CLI")
        self.assertEqual(diff["task"], "git.repository.diff")
        self.assertEqual(diff["operation"], "diff.stat.read")
        self.assertEqual(diff["scope"], "unstaged")
        self.assertTrue(diff["changed"])
        self.assertEqual(diff["changed_file_count"], 1)
        self.assertEqual(diff["files"], [
            {"path": "README.txt", "added": 1, "deleted": 0, "binary": False}
        ])
        self.assertEqual((diff["total_added"], diff["total_deleted"]), (1, 0))
        self.assertFalse(diff["verification"]["untracked_files_included"])
        self.assertFalse(diff["execution"]["foreground_used"])
        self.assertFalse(diff["execution"]["model_called"])
        self.assertFalse(diff["execution"]["paid_inference_used"])
        self.assertFalse(diff["execution"]["repo_mutated_by_task"])
        self.assertEqual(hashlib.sha256(self.readme.read_bytes()).hexdigest(), before)
        self.assertFalse((self.root / ".git" / "index.lock").exists())

    def test_staged_unstaged_head_scope_and_exact_expectation(self):
        self.readme.write_text("alpha\nbeta\n", encoding="utf-8")
        self.git("add", "README.txt")
        self.assertFalse(self.execute()["changed"])
        staged = self.execute(action_args={"repo_path": str(self.root),
                                            "scope": "staged"},
                              expected_changed=True)
        head = self.execute(action_args={"repo_path": str(self.root),
                                          "scope": "head"})
        self.assertEqual(staged["files"], head["files"])
        self.assertEqual(staged["total_added"], 1)
        self.assertEqual(staged["scope"], "staged")
        self.assertEqual(head["scope"], "head")
        with self.assertRaises(CuaBridgeError) as caught:
            self.execute(action_args={"repo_path": str(self.root),
                                      "scope": "unstaged"}, expected_changed=True)
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_POSTCONDITION_FAILED")

    def test_binary_and_tabbed_filename_unambiguous_with_nul_terminated_paths(self):
        tabbed = self.root / "a\tb.txt"
        tabbed.write_text("first\n", encoding="utf-8")
        binary = self.root / "image.bin"
        binary.write_bytes(b"\x00\x01\x02")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c",
                 "user.email=ci@example.invalid", "commit", "-qm", "fixtures")
        tabbed.write_text("first\nsecond\n", encoding="utf-8")
        binary.write_bytes(b"\x00\x01\x02\x03\x04")
        receipt = self.execute()
        by_path = {entry["path"]: entry for entry in receipt["files"]}
        self.assertEqual(by_path["a\tb.txt"]["added"], 1)
        self.assertTrue(by_path["image.bin"]["binary"])
        self.assertIsNone(by_path["image.bin"]["added"])
        self.assertIsNone(by_path["image.bin"]["deleted"])
        self.assertEqual(receipt["binary_file_count"], 1)

    def test_untracked_files_are_not_misrepresented_as_diff(self):
        (self.root / "untracked.txt").write_text("secret scratch", encoding="utf-8")
        result = self.execute(expected_changed=False)
        self.assertFalse(result["changed"])
        self.assertFalse(result["verification"]["untracked_files_included"])

    def test_forged_gui_paid_or_git_flags_rejected_before_execution(self):
        attacks = [
            {"approved": True},
            {"physical_input_allowed": True},
            {"paid_inference": True},
            {"expected_changed": "true"},
            {"expected_clean": True},
            {"operation": "shell.execute"},
            {"task": "git.repository.status"},
            {"action_args": {"repo_path": str(self.root), "scope": "--cached"}},
            {"action_args": {"repo_path": str(self.root), "scope": "HEAD~1"}},
            {"action_args": {"repo_path": str(self.root), "scope": 5}},
            {"action_args": {"repo_path": str(self.root), "command": "git reset --hard"}},
            {"action_args": {"repo_path": str(self.root) + "\n--config"}},
            {"agent_id": ""},
        ]
        before = self.readme.read_bytes()
        for attack in attacks:
            with self.subTest(attack=attack):
                with self.assertRaises(CuaBridgeError):
                    self.execute(**attack)
                self.assertEqual(self.readme.read_bytes(), before)

    def test_nested_repository_scope_does_not_expand(self):
        child = self.root / "child"
        child.mkdir()
        with self.assertRaises(CuaBridgeError) as caught:
            self.execute(action_args={"repo_path": str(child)})
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_REPOSITORY_ROOT_REQUIRED")

    def test_task_planning_cannot_claim_execution(self):
        proposal = task_routes(
            "Git", "git.repository.diff",
            [{"command": "git", "path": "/untrusted/git", "verified": False}],
        )
        self.assertEqual(proposal["task_compatibility"], "unknown")
        self.assertFalse(proposal["verified_task_support"])
        self.assertEqual(proposal["remaining_gate"],
                         "VERIFY_SCOPED_GIT_DIFF_WITH_TWO_REAL_READS")
        self.assertIsNone(proposal["preferred_task_route"])
        self.assertEqual(proposal["potential_task_route"]["command"], "git")

    def test_more_than_200_tracked_changes_fails_closed(self):
        for index in range(201):
            (self.root / f"file{index:03d}.txt").write_text("old\n", encoding="utf-8")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c",
                 "user.email=ci@example.invalid", "commit", "-qm", "many files")
        for index in range(201):
            (self.root / f"file{index:03d}.txt").write_text("new\n", encoding="utf-8")
        with self.assertRaises(CuaBridgeError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_GIT_RESPONSE_TOO_LARGE")


if __name__ == "__main__":
    unittest.main()
