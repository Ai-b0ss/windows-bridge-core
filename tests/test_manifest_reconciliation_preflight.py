"""Security regressions for the read-only, Git-proven runtime migration preflight."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime/bridge-v3"))
import cua_runtime_deploy as deploy


def git(repo, *parts):
    cp = subprocess.run(["git", "-C", str(repo), *parts], capture_output=True,
                        text=True, timeout=25, check=True)
    return cp.stdout.strip()


class ManifestReconciliationPreflight(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ff-reconcile-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.runtime = self.repo / "runtime/bridge-v3"
        self.runtime.mkdir(parents=True)
        self.install = self.root / "installed"
        self.install.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Fixture")
        git(self.repo, "config", "user.email", "fixture@example.invalid")
        agent = self.runtime / "ff_win_v3_agent.py"
        agent.write_text("VERSION='base'\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "base")
        base = git(self.repo, "rev-parse", "HEAD")

        # Legacy installation on a side branch not ancestral to candidate.
        git(self.repo, "switch", "-qc", "legacy", base)
        agent.write_text("VERSION='legacy'\n", encoding="utf-8")
        git(self.repo, "commit", "-qam", "legacy")
        self.legacy = git(self.repo, "rev-parse", "HEAD")
        old_plan = deploy.build_plan(self.repo, ref=self.legacy)

        git(self.repo, "switch", "-qc", "current", base)
        agent.write_text("VERSION='current'\n", encoding="utf-8")
        (self.runtime / "cua_helper.py").write_text("HELPER = True\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "known current")
        self.current = git(self.repo, "rev-parse", "HEAD")
        current_plan = deploy.build_plan(self.repo, ref=self.current)
        for item in current_plan["files"]:
            content = subprocess.check_output(
                ["git", "-C", str(self.repo), "show", self.current + ":" + item["source"]])
            dst = self.install / item["target"]
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(content)
        (self.install / "user-note.txt").write_text("preserve me\n", encoding="utf-8")
        (self.install / deploy.MANIFEST_NAME).write_text(
            json.dumps(old_plan, indent=2) + "\n", encoding="utf-8")

        agent.write_text("VERSION='candidate'\n", encoding="utf-8")
        (self.runtime / "cua_owner_stop.py").write_text("STOP = True\n", encoding="utf-8")
        (self.runtime / "new-nested").mkdir()
        (self.runtime / "new-nested/cua_new.py").write_text("NEW = True\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "candidate")
        self.candidate = git(self.repo, "rev-parse", "HEAD")

    def plan(self, **kwargs):
        return deploy.plan_manifest_reconciliation(
            self.repo, self.install, trusted_head=self.current,
            ref=self.candidate, **kwargs)

    def fingerprint(self):
        files = {}
        for path in self.install.rglob("*"):
            if path.is_file():
                files[path.relative_to(self.install).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        return files

    def test_stale_manifest_proof_is_readonly_and_exact(self):
        before = self.fingerprint()
        proof = self.plan()
        self.assertTrue(proof["eligible"])
        self.assertFalse(proof["production_modified"])
        self.assertEqual(proof["old_head"], self.legacy)
        self.assertEqual(proof["trusted_head"], self.current)
        self.assertEqual(proof["candidate_head"], self.candidate)
        self.assertEqual(proof["verified_files"], 2)
        self.assertEqual(before, self.fingerprint())

        with self.assertRaisesRegex(RuntimeError, "PREVIOUS_MANIFEST_UNPROVEN"):
            deploy.apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertEqual(before, self.fingerprint())

        # The caller can separately test the proof in an authorized disposable
        # installation. The preflight does NOT perform this write itself.
        (self.install / deploy.MANIFEST_NAME).write_text(
            json.dumps(proof["trusted_manifest"], indent=2) + "\n", encoding="utf-8")
        upgraded = deploy.apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertTrue(upgraded["ok"])
        self.assertTrue(deploy.verify_runtime(self.install)["ok"])
        self.assertEqual((self.install / "user-note.txt").read_text(encoding="utf-8"), "preserve me\n")

    def test_changed_trusted_file_refused(self):
        (self.install / "cua_helper.py").write_text("owner modified\n", encoding="utf-8")
        before = self.fingerprint()
        with self.assertRaisesRegex(RuntimeError, "TRUSTED_FILE_MISMATCH"):
            self.plan()
        self.assertEqual(before, self.fingerprint())

    def test_tampered_previous_manifest_refused(self):
        path = self.install / deploy.MANIFEST_NAME
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest["release_id"] = "0" * 64
        path.write_text(json.dumps(manifest), encoding="utf-8")
        before = self.fingerprint()
        with self.assertRaisesRegex(RuntimeError, "PREVIOUS_MANIFEST_UNPROVEN"):
            self.plan()
        self.assertEqual(before, self.fingerprint())

    def test_unrelated_trusted_head_refused(self):
        with self.assertRaisesRegex(RuntimeError, "TRUSTED_HEAD_NOT_ANCESTOR"):
            deploy.plan_manifest_reconciliation(
                self.repo, self.install, trusted_head=self.legacy, ref=self.candidate)

    def test_trusted_head_must_be_full_commit_id(self):
        with self.assertRaisesRegex(RuntimeError, "TRUSTED_HEAD_NOT_PINNED"):
            deploy.plan_manifest_reconciliation(
                self.repo, self.install, trusted_head="current", ref=self.candidate)

    def test_owner_file_in_new_candidate_target_refused(self):
        (self.install / "cua_owner_stop.py").write_text("OWNER FILE - do not overwrite\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "CANDIDATE_TARGET_OCCUPIED"):
            self.plan()

    def test_active_deployment_lock_refused(self):
        (self.install / deploy.LOCK_NAME).write_text("busy", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "RECONCILIATION_TRANSACTION_PRESENT"):
            self.plan()

    def test_missing_trusted_file_refused(self):
        (self.install / "cua_helper.py").unlink()
        with self.assertRaisesRegex(RuntimeError, "TRUSTED_FILE_MISSING"):
            self.plan()


if __name__ == "__main__":
    unittest.main()
