"""CI rehearsal of real public-Core upgrades and crash recovery.

Runs against disposable Git repositories and temporary installations only.
Does not inspect or modify the owner's installed Windows Bridge.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

RUNTIME_SOURCE = Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"
sys.path.insert(0, str(RUNTIME_SOURCE))
from cua_runtime_deploy import (  # noqa: E402
    LOCK_NAME,
    MANIFEST_NAME,
    apply_runtime,
    recover_stale,
    verify_runtime,
)


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    )
    return result.stdout.strip()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class PublicCoreUpgradeRehearsal(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(prefix="wb-core-upgrade-ci-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "public-core"
        self.repo.mkdir()
        self.runtime = self.repo / "runtime" / "bridge-v3"
        self.runtime.mkdir(parents=True)
        self.install = self.base / "installed"

        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.name", "CI Fixture")
        _git(self.repo, "config", "user.email", "ci@example.invalid")

        (self.runtime / "ff_win_v3_agent.py").write_text(
            "VERSION = 'previous'\n", encoding="utf-8"
        )
        (self.runtime / "cua_previous.py").write_text(
            "OLD_FEATURE = True\n", encoding="utf-8"
        )
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-q", "-m", "previous public runtime")
        self.previous = _git(self.repo, "rev-parse", "HEAD")

        (self.runtime / "ff_win_v3_agent.py").write_text(
            "VERSION = 'candidate'\n", encoding="utf-8"
        )
        (self.runtime / "cua_previous.py").unlink()
        (self.runtime / "cua_current.py").write_text(
            "CURRENT_FEATURE = True\n", encoding="utf-8"
        )
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "candidate public runtime")
        self.candidate = _git(self.repo, "rev-parse", "HEAD")

    def _install_previous(self):
        applied = apply_runtime(self.repo, self.install, ref=self.previous)
        self.assertTrue(applied["ok"])
        self.assertEqual(applied["source_head"], self.previous)
        verified = verify_runtime(self.install)
        self.assertTrue(verified["ok"])
        self.assertEqual(verified["file_count"], 2)
        self.assertFalse((self.install / LOCK_NAME).exists())
        return {
            name: _sha(self.install / name)
            for name in ("ff_win_v3_agent.py", "cua_previous.py", MANIFEST_NAME)
        }

    def _assert_previous_intact(self, snapshot):
        self.assertEqual(
            {name: _sha(self.install / name) for name in snapshot},
            snapshot,
        )
        self.assertFalse((self.install / "cua_current.py").exists())
        self.assertFalse((self.install / LOCK_NAME).exists())
        verified = verify_runtime(self.install)
        self.assertTrue(verified["ok"])
        self.assertEqual(verified["source_head"], self.previous)

    def test_injected_partial_upgrade_restores_every_prior_file(self):
        snapshot = self._install_previous()
        with self.assertRaisesRegex(RuntimeError, "INJECTED_FAILURE_AFTER:1"):
            apply_runtime(self.repo, self.install,
                          ref=self.candidate, fail_after=1)

        self._assert_previous_intact(snapshot)

        result = apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertTrue(result["ok"])
        self.assertEqual(result["source_head"], self.candidate)
        self.assertFalse((self.install / LOCK_NAME).exists())
        self.assertFalse((self.install / "cua_previous.py").exists())
        self.assertTrue((self.install / "cua_current.py").exists())
        self.assertTrue(verify_runtime(self.install)["ok"])

    def test_actual_child_process_crash_is_recovered_without_replay(self):
        snapshot = self._install_previous()

        # The child exits after a verified candidate has been written, but
        # before transaction commit removes the journal and lock. No fake
        # journal is constructed: this is the real deployment code path.
        child_code = (
            "import os, sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "from cua_runtime_deploy import apply_runtime\n"
            "apply_runtime(Path(sys.argv[2]), Path(sys.argv[3]), "
            "ref=sys.argv[4], after_install=lambda: os._exit(93))\n"
        )
        child = subprocess.run(
            [
                sys.executable, "-c", child_code,
                str(RUNTIME_SOURCE), str(self.repo),
                str(self.install), self.candidate,
            ],
            capture_output=True,
            timeout=90,
            check=False,
        )
        self.assertEqual(
            child.returncode, 93,
            msg=(child.stderr or b"")[-800:].decode("utf-8", "replace"),
        )
        self.assertTrue((self.install / LOCK_NAME).exists())
        self.assertTrue(verify_runtime(self.install)["error"] == "DEPLOY_LOCK_PRESENT")

        recovered = recover_stale(self.install)
        self.assertTrue(recovered["recovered"])
        self.assertEqual(recovered["phase"], "rollback_from_journal")
        self._assert_previous_intact(snapshot)

        # A second recovery must be a strict no-op.
        self.assertFalse(recover_stale(self.install)["recovered"])
        self._assert_previous_intact(snapshot)

        # A later legitimate upgrade is still possible.
        result = apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertTrue(result["ok"])
        self.assertEqual(result["source_head"], self.candidate)
        self.assertFalse((self.install / LOCK_NAME).exists())
        self.assertTrue(verify_runtime(self.install)["ok"])

    def test_invalid_new_source_is_rejected_before_current_files_change(self):
        snapshot = self._install_previous()
        (self.runtime / "cua_current.py").write_text(
            "def invalid(:\n", encoding="utf-8"
        )
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "invalid candidate source")
        bad = _git(self.repo, "rev-parse", "HEAD")

        with self.assertRaises(SyntaxError):
            apply_runtime(self.repo, self.install, ref=bad)
        self._assert_previous_intact(snapshot)


if __name__ == "__main__":
    unittest.main()
