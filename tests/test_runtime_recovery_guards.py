"""Recovery transaction preflight: no partial changes on invalid state."""
import hashlib
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
from cua_runtime_deploy import LOCK_SCHEMA, MANIFEST_NAME, TX_DIR_NAME, _restore_journal, _recovery_target

class TestRecoveryGuards(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(prefix="wb-recovery-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "installed"
        self.root.mkdir()
        self.txid = "a" * 32
        self.backup = self.root / TX_DIR_NAME / self.txid / "backup" / "module.py"
        self.backup.parent.mkdir(parents=True)
        self.backup.write_bytes(b"previous\n")
        self.module = self.root / "module.py"
        self.module.write_bytes(b"current\n")
        self.manifest = self.root / MANIFEST_NAME
        self.manifest.write_bytes(b"current manifest")
        self.journal = {
            "schema": LOCK_SCHEMA + "/journal", "txid": self.txid,
            "files": [{"target": "module.py", "existed": True,
                       "backup": str(self.backup),
                       "old_sha256": hashlib.sha256(self.backup.read_bytes()).hexdigest()}],
            "previous_manifest": {"existed": False, "backup": None, "old_sha256": None},
        }

    def test_valid_owned_backup_restores_file(self):
        _restore_journal(self.root, self.journal)
        self.assertEqual(self.module.read_bytes(), b"previous\n")
        self.assertFalse(self.manifest.exists())

    def test_invalid_backup_fails_before_mutating_first_file(self):
        self.journal["files"][0]["old_sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "ROLLBACK_BACKUP_INVALID"):
            _restore_journal(self.root, self.journal)
        self.assertEqual(self.module.read_bytes(), b"current\n")
        self.assertEqual(self.manifest.read_bytes(), b"current manifest")

    def test_target_names_are_install_relative(self):
        for value in ("../other", "C:/drive", "nested/../other", TX_DIR_NAME + "/backup"):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    _recovery_target(self.root, value)

    def test_duplicate_entries_rejected_before_first_mutation(self):
        self.journal["files"].append(dict(self.journal["files"][0]))
        with self.assertRaisesRegex(RuntimeError, "ROLLBACK_TARGET_DUPLICATE"):
            _restore_journal(self.root, self.journal)
        self.assertEqual(self.module.read_bytes(), b"current\n")

    def test_missing_later_backup_prevents_partial_rollback(self):
        self.journal["files"].append({
            "target": "second.py", "existed": True,
            "backup": str(self.backup.parent / "second.py"),
            "old_sha256": "0" * 64,
        })
        with self.assertRaisesRegex(RuntimeError, "ROLLBACK_BACKUP_INVALID"):
            _restore_journal(self.root, self.journal)
        self.assertEqual(self.module.read_bytes(), b"current\n")
        self.assertEqual(self.manifest.read_bytes(), b"current manifest")

    def test_stale_lock_restores_owned_version(self):
        from datetime import datetime, timezone
        from cua_runtime_deploy import recover_stale, LOCK_NAME
        journal_file = self.root / TX_DIR_NAME / self.txid / "journal.json"
        journal_file.write_text(json.dumps(self.journal))
        (self.root / LOCK_NAME).write_text(json.dumps({
            "schema": LOCK_SCHEMA, "txid": self.txid, "pid": 0,
            "journal": str(journal_file),
            "started_at": datetime.now(timezone.utc).isoformat(),
        }))
        result = recover_stale(self.root)
        self.assertEqual(result["phase"], "rollback_from_journal")
        self.assertEqual(self.module.read_bytes(), b"previous\n")
        self.assertFalse((self.root / LOCK_NAME).exists())

    def test_incorrect_recovery_record_keeps_lock(self):
        from cua_runtime_deploy import recover_stale, LOCK_NAME
        (self.root / LOCK_NAME).write_text(json.dumps({
            "schema": LOCK_SCHEMA, "txid": self.txid,
            "pid": 0, "journal": str(self.backup),
        }))
        with self.assertRaisesRegex(RuntimeError, "DEPLOY_JOURNAL_PATH_INVALID"):
            recover_stale(self.root)
        self.assertTrue((self.root / LOCK_NAME).exists())
        self.assertEqual(self.module.read_bytes(), b"current\n")

    def test_public_runtime_map_uses_git_bytes_not_legacy_private_paths(self):
        import subprocess
        from cua_runtime_deploy import build_plan, stage_plan, validate_stage
        repo = self.root.parent / "public-repo"
        repo.mkdir()
        runtime = repo / "runtime" / "bridge-v3"
        runtime.mkdir(parents=True)
        (runtime / "ff_win_v3_agent.py").write_text("AGENT = 1\n")
        (runtime / "cua_demo.py").write_text("DEMO = 2\n")
        for args in (
            ("init", "-q"),
            ("config", "user.email", "tests@example.invalid"),
            ("config", "user.name", "Core Tester"),
            ("add", "."),
            ("commit", "-q", "-m", "fixture"),
        ):
            subprocess.run(["git", "-C", str(repo), *args], check=True,
                           capture_output=True, timeout=10)
        plan = build_plan(repo)
        self.assertEqual(len(plan["files"]), 2)
        self.assertEqual({item["target"] for item in plan["files"]},
                         {"ff_win_v3_agent.py", "cua_demo.py"})
        stage = self.root.parent / "staged"
        stage_plan(repo, plan, stage)
        verified = validate_stage(stage, plan, strict_external=False)
        self.assertEqual(verified["python"], 2)


if __name__ == "__main__":
    unittest.main()
