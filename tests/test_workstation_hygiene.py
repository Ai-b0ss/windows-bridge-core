"""Unit tests for parameterized workstation hygiene gates and storage-guard-v2.ps1."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "tools"))

import workstation_hygiene_engine as whe

STORAGE_GUARD_PS1 = REPO_ROOT / "tools" / "host-wrappers" / "storage-guard-v2.ps1"


class TestWorkstationHygieneEngine(unittest.TestCase):
    def test_backup_duplicate_proof_requires_exact_sha256_subset(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ff-whe-dup-") as td:
            root = Path(td)
            canon = root / "canonical"
            dup = root / "duplicate"
            canon.mkdir()
            dup.mkdir()
            (canon / "a.txt").write_bytes(b"alpha-123")
            (canon / "b.txt").write_bytes(b"beta-456")
            (dup / "copy_of_a.txt").write_bytes(b"alpha-123")

            ok_res = whe.verify_backup_dir_proven_duplicate(dup, canon)
            self.assertTrue(ok_res["ok"])
            self.assertEqual(ok_res["verified_files"], 1)

            (dup / "unique.txt").write_bytes(b"never-backed-up")
            bad_res = whe.verify_backup_dir_proven_duplicate(dup, canon)
            self.assertFalse(bad_res["ok"])
            self.assertEqual(bad_res["reason"], "UNIQUE_CONTENT_PRESENT")
            self.assertIn("unique.txt", bad_res["unmatched_relative_paths"])

    def test_git_worktree_pushed_gate_rejects_unpushed_dirty_and_stash(self) -> None:
        if not shutil.which("git"):
            self.skipTest("git not available")
        with tempfile.TemporaryDirectory(prefix="ff-whe-git-") as td:
            root = Path(td)
            bare = root / "remote.git"
            wt = root / "work"
            subprocess.run(["git", "init", "--bare", str(bare)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "clone", str(bare), str(wt)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["git", "-C", str(wt), "config", "user.name", "Test"], check=True)
            subprocess.run(["git", "-C", str(wt), "config", "user.email", "test@example.invalid"], check=True)

            (wt / "f.txt").write_text("v1\n", encoding="utf-8")
            self.assertEqual(whe.verify_git_worktree_fully_pushed(wt)["reason"], "DIRTY_OR_UNTRACKED_FILES")

            subprocess.run(["git", "-C", str(wt), "add", "f.txt"], check=True)
            subprocess.run(["git", "-C", str(wt), "commit", "-q", "-m", "init"], check=True)
            self.assertEqual(whe.verify_git_worktree_fully_pushed(wt)["reason"], "UNPUSHED_COMMITS_PRESENT")

            branch = subprocess.check_output(["git", "-C", str(wt), "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()
            subprocess.run(["git", "-C", str(wt), "push", "-q", "origin", branch], check=True)
            self.assertTrue(whe.verify_git_worktree_fully_pushed(wt)["ok"])

    def test_storage_guard_ps1_protects_secrets_and_sweeps_orphan_detached_logs(self) -> None:
        ps = shutil.which("powershell.exe") or shutil.which("pwsh")
        if not ps:
            self.skipTest("PowerShell not available")
        with tempfile.TemporaryDirectory(prefix="ff-sg-v2-") as td:
            root = Path(td)
            det = root / "bridge-v3" / "state" / "detached_logs"
            det.mkdir(parents=True)
            (root / "bridge-v3" / "state" / "detached_sessions.json").write_text(
                json.dumps({"1111111111111111": {"pid": 999}}), encoding="utf-8"
            )
            active_log = det / "1111111111111111.log"
            orphan_log = det / "2222222222222222.log"
            active_log.write_text("keep\n", encoding="utf-8")
            orphan_log.write_text("reclaim\n", encoding="utf-8")
            old = time.time() - 7200
            os.utime(active_log, (old, old))
            os.utime(orphan_log, (old, old))

            cmd = (
                f". {str(STORAGE_GUARD_PS1)!r} -LoadFunctionsOnly -LogPath {str(root / 'sg.jsonl')!r}; "
                "function Test-ProcessReference([string]$Path) { return $false }; "
                "$p1 = Test-HardProtected 'C:\\Work\\ff-windows-bridge\\recovery\\snap'; "
                "$p2 = Test-HardProtected 'C:\\Work\\cert.pfx'; "
                "$p3 = Test-HardProtected 'C:\\Work\\cache\\item.tmp'; "
                f"Invoke-BridgeRuntimeCleaners {str(root)!r}; "
                "@{ p1 = $p1; p2 = $p2; p3 = $p3 } | ConvertTo-Json -Compress"
            )
            out = json.loads(subprocess.check_output([ps, "-NoLogo", "-NoProfile", "-Command", cmd], text=True))
            self.assertTrue(out["p1"])
            self.assertTrue(out["p2"])
            self.assertFalse(out["p3"])
            self.assertTrue(active_log.exists())
            self.assertFalse(orphan_log.exists())


if __name__ == "__main__":
    unittest.main()
