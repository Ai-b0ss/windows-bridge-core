"""Safety and recovery tests for verified, immutable Bridge snapshots."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "runtime/bridge-v3"))
import cua_cold_rollback_bundle as bundle
import cua_runtime_deploy as deploy


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL, text=True).strip()


class SnapshotSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ff-snapshot-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        self.root = self.base / "live-runtime"
        self.repo.joinpath("runtime", "bridge-v3").mkdir(parents=True)
        self.root.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "test")
        git(self.repo, "config", "user.email", "test@example.invalid")
        source = self.repo / "runtime/bridge-v3"
        (source / "ff_win_v3_agent.py").write_text("old='base'\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "base")
        base_head = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "switch", "-qc", "legacy", base_head)
        (source / "ff_win_v3_agent.py").write_text("old='manifest'\n", encoding="utf-8")
        git(self.repo, "commit", "-qam", "manifest v1")
        old_head = git(self.repo, "rev-parse", "HEAD")
        old_plan = deploy.build_plan(self.repo, old_head)
        git(self.repo, "switch", "-qc", "trusted", base_head)
        (source / "ff_win_v3_agent.py").write_text("old='current'\n", encoding="utf-8")
        (source / "cua_extra.py").write_text("helper=True\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "trusted")
        self.trusted = git(self.repo, "rev-parse", "HEAD")
        self.trusted_plan = deploy.build_plan(self.repo, self.trusted)
        for row in self.trusted_plan["files"]:
            b = subprocess.check_output(["git", "-C", str(self.repo), "show",
                                          self.trusted + ":" + row["source"]])
            p = self.root / row["target"]
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b)
        self.previous_manifest = json.dumps(old_plan, indent=2) + "\n"
        (self.root / deploy.MANIFEST_NAME).write_text(self.previous_manifest, encoding="utf-8")
        (self.root / "owner-sentinel.txt").write_text("leave untouched", encoding="utf-8")
        (source / "ff_win_v3_agent.py").write_text("old='candidate'\n", encoding="utf-8")
        (source / "cua_new.py").write_text("new=True\n", encoding="utf-8")
        git(self.repo, "add", ".")
        git(self.repo, "commit", "-qm", "candidate")
        self.snapshot = self.base / "recovery" / "snapshot"
        self.snapshot.parent.mkdir()
        self.candidate = git(self.repo, "rev-parse", "HEAD")

    def captured(self):
        return bundle.capture(self.repo, self.root, self.snapshot,
                              trusted_head=self.trusted, candidate_ref=self.candidate)

    def test_capture_and_restore_from_candidate(self):
        receipt = self.captured()
        self.assertTrue(receipt["ok"])
        self.assertEqual(receipt["source_files"], 2)
        self.assertTrue(bundle.verify_bundle(self.snapshot))
        with self.assertRaisesRegex(RuntimeError, "RESTORE_OFFLINE_CONFIRMATION_REQUIRED"):
            bundle.restore(self.snapshot, self.root)
        for row in deploy.build_plan(self.repo, self.candidate)["files"]:
            b = subprocess.check_output(["git", "-C", str(self.repo), "show",
                                          self.candidate + ":" + row["source"]])
            (self.root / row["target"]).write_bytes(b)
        candidate_manifest = deploy.build_plan(self.repo, self.candidate)
        (self.root / deploy.MANIFEST_NAME).write_text(
            json.dumps(candidate_manifest), encoding="utf-8")
        result = bundle.restore(self.snapshot, self.root, offline_confirmed=True)
        self.assertTrue(result["ok"])
        self.assertEqual(result["removed_candidate_only_files"], 1)
        self.assertEqual((self.root / deploy.MANIFEST_NAME).read_text(encoding="utf-8"),
                         self.previous_manifest)
        self.assertEqual((self.root / "ff_win_v3_agent.py").read_text(encoding="utf-8"),
                         "old='current'\n")
        self.assertFalse((self.root / "cua_new.py").exists())
        self.assertEqual((self.root / "owner-sentinel.txt").read_text(encoding="utf-8"),
                         "leave untouched")

    def test_restore_blocked_when_bridge_agent_is_running(self):
        self.captured()
        with mock.patch.object(bundle, "assert_runtime_quiescent",
                               side_effect=RuntimeError("RESTORE_RUNTIME_STILL_RUNNING")):
            with self.assertRaisesRegex(RuntimeError, "RESTORE_RUNTIME_STILL_RUNNING"):
                bundle.restore(self.snapshot, self.root, offline_confirmed=True)
        self.assertEqual((self.root / deploy.MANIFEST_NAME).read_text(encoding="utf-8"),
                         self.previous_manifest)

    def test_tampered_backup_refused(self):
        self.captured()
        p = self.snapshot / "files/ff_win_v3_agent.py"
        p.write_text("bad", encoding="utf-8")
        before = (self.root / "ff_win_v3_agent.py").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "SNAPSHOT_FILE_CORRUPT"):
            bundle.restore(self.snapshot, self.root, offline_confirmed=True)
        self.assertEqual(before, (self.root / "ff_win_v3_agent.py").read_bytes())

    def test_changed_live_file_refused_before_restore(self):
        self.captured()
        (self.root / "cua_extra.py").write_text("untrusted owner changes", encoding="utf-8")
        before = (self.root / "cua_extra.py").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "RESTORE_UNEXPECTED_TARGET"):
            bundle.restore(self.snapshot, self.root, offline_confirmed=True)
        self.assertEqual(before, (self.root / "cua_extra.py").read_bytes())

    def test_old_manifest_tampering_fails_preflight(self):
        manifest_path = self.root / deploy.MANIFEST_NAME
        old = json.loads(manifest_path.read_text(encoding="utf-8"))
        old["release_id"] = "0" * 64
        manifest_path.write_text(json.dumps(old), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "PREVIOUS_MANIFEST_UNPROVEN"):
            self.captured()
        self.assertFalse(self.snapshot.exists())

    def test_legacy_journals_are_verified_and_preserved(self):
        txid = "f" * 32
        tx = self.root / deploy.TX_DIR_NAME / txid
        path = tx / "backup" / "ff_win_v3_agent.py"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"legacy source")
        mf = tx / "backup" / deploy.MANIFEST_NAME
        mf.write_bytes(b"old manifest")
        payload = {
            "schema": "cua-runtime-deploy-lock/v1/journal", "txid": txid,
            "files": [{
                "target": "ff_win_v3_agent.py", "existed": True,
                "backup": str(path.resolve()),
                "old_sha256": hashlib.sha256(path.read_bytes()).hexdigest()
            }],
            "previous_manifest": {
                "existed": True,
                "backup": str(mf.resolve()),
                "old_sha256": hashlib.sha256(mf.read_bytes()).hexdigest()
            },
        }
        journal = tx / "journal.json"
        journal.write_text(json.dumps(payload), encoding="utf-8")
        result = self.captured()
        self.assertEqual(result["historical_journals_verified"], 1)
        self.assertEqual(result["historical_files_verified"], 1)
        self.assertTrue(journal.exists())
        self.assertEqual(journal.read_text(encoding="utf-8"), json.dumps(payload))
        path.write_bytes(b"tampered legacy")
        with self.assertRaisesRegex(RuntimeError, "LEGACY_JOURNAL_BACKUP_HASH_INVALID"):
            bundle.preflight(self.repo, self.root, trusted_head=self.trusted)

    def test_snapshot_destination_inside_runtime_refused(self):
        with self.assertRaisesRegex(RuntimeError, "SNAPSHOT_DESTINATION_UNSAFE"):
            bundle.capture(self.repo, self.root, self.root / "backup", trusted_head=self.trusted)

    def test_independent_recovery_kit_dependency_closure(self):
        kit = self.base / "independent-kit"
        receipt = bundle.create_recovery_kit(ROOT, kit)
        self.assertTrue(receipt["independent_import"])
        self.assertEqual(receipt["file_count"], 7)
        self.assertEqual(bundle.verify_recovery_kit(kit)["files_verified"], 7)
        target = kit / "runtime/bridge-v3/cua_release_manifest.py"
        target.write_text("tampered", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "RECOVERY_KIT_HASH_MISMATCH"):
            bundle.verify_recovery_kit(kit)

    def test_win32_process_39076_peer_allowed_but_39073_or_keeper_blocked(self):
        # Direct regression for the owner's live C:-junction prelogin process:
        # WIN-2LK6007IEBP PID 18096 serves --port 39076 while 39073 is offline.
        from unittest import mock
        alias = str(self.root / "ff_win_v3_main.py")
        peer = {"ProcessId": 18096, "Name": "python.exe",
                "CommandLine": f'"C:/Python/python.exe" "{alias}" serve --host 127.0.0.1 --port 39076'}
        target = {"ProcessId": 1896, "Name": "python.exe",
                  "CommandLine": f'"C:/Python/python.exe" "{alias}" serve --host 127.0.0.1 --port 39073'}
        keeper = {"ProcessId": 17088, "Name": "powershell.exe",
                  "CommandLine": str(self.root / "ff_win_v3_keeper.ps1")}
        def check(rows):
            proc = subprocess.CompletedProcess([], 0, json.dumps(rows), "")
            with mock.patch.object(bundle.subprocess, "run", return_value=proc):
                return bundle.assert_runtime_quiescent(self.root, target_port=39073, peer_port=39076)
        self.assertEqual(check([peer])["peer_pids"], [18096])
        for rows in ([peer, target], [peer, keeper],
                     [dict(peer, CommandLine=peer["CommandLine"] + " --also-listen 39073")],
                     [dict(peer, CommandLine=peer["CommandLine"].replace("--port 39076", "--port 39075"))],
                     [dict(peer, CommandLine=peer["CommandLine"].replace("--port 39076", ""))]):
            with self.subTest(rows=rows):
                with self.assertRaisesRegex(RuntimeError, "RESTORE_"):
                    check(rows)
        with self.assertRaisesRegex(RuntimeError, "RESTORE_RUNTIME_STILL_RUNNING"):
            bundle._runtime_process_rows(self.root, [peer], target_port=None, peer_port=None)

    def test_requested_and_canonical_windows_aliases_both_count(self):
        from unittest import mock
        alias_path = self.root / "ff_win_v3_main.py"
        row = {"ProcessId": 18096, "Name": "python.exe",
               "CommandLine": (f'"python.exe" "{alias_path}" serve '
                               "--host 127.0.0.1 --port 39076")}
        proc = subprocess.CompletedProcess([], 0, json.dumps([row]), "")
        with mock.patch.object(bundle.subprocess, "run", return_value=proc):
            # A Windows CI runner may resolve its temp path via a different
            # canonical spelling. The process still names the requested path.
            original_resolve = Path.resolve
            def alternate(self, *a, **kw):
                if self == self_root:
                    return Path("Z:/canonical-physical-fixture")
                return original_resolve(self, *a, **kw)
            self_root = self.root
            with mock.patch.object(Path, "resolve", alternate):
                result = bundle.assert_runtime_quiescent(
                    self.root, target_port=39073, peer_port=39076)
        self.assertEqual(result["peer_pids"], [18096])

    def test_live_peer_blocks_nonpython_restore_changes(self):
        self.captured()
        record_path = self.snapshot / "bundle.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        record["candidate_files"].append(
            {"target": "ff_win_v3_keeper.ps1", "sha256": "a" * 64})
        record_path.write_text(json.dumps(record), encoding="utf-8")
        manifest_before = (self.root / deploy.MANIFEST_NAME).read_bytes()
        from unittest import mock
        with mock.patch.object(bundle, "assert_runtime_quiescent",
                               return_value={"peer_pids": [18096], "target_port": 39073}):
            with self.assertRaisesRegex(RuntimeError, "RESTORE_PEER_NONPYTHON_CHANGE_FORBIDDEN"):
                bundle.restore(self.snapshot, self.root, offline_confirmed=True,
                               target_port=39073, peer_port=39076)
        self.assertEqual((self.root / deploy.MANIFEST_NAME).read_bytes(), manifest_before)

    def test_peer_pid_file_allowed_only_if_positively_identified(self):
        from unittest import mock
        alias = str(self.root / "ff_win_v3_main.py")
        peer = {"ProcessId": 18096, "Name": "python.exe",
                "CommandLine": f'"C:/Python/python.exe" "{alias}" serve --host 127.0.0.1 --port 39076'}
        proc = subprocess.CompletedProcess([], 0, json.dumps([peer]), "")
        (self.root / "agent.pid").write_text("18096", encoding="ascii")
        with (mock.patch.object(bundle.subprocess, "run", return_value=proc),
              mock.patch.object(bundle.deploy, "_process_alive", return_value=True)):
            receipt = bundle.assert_runtime_quiescent(self.root, target_port=39073, peer_port=39076)
            self.assertEqual(receipt["peer_pids"], [18096])
            (self.root / "keeper.pid").write_text("18096", encoding="ascii")
            with self.assertRaisesRegex(RuntimeError, "RESTORE_PID_STILL_ACTIVE:keeper.pid"):
                bundle.assert_runtime_quiescent(self.root, target_port=39073, peer_port=39076)

    def test_restore_with_39076_process_keeps_non_python_files_unmodified(self):
        from unittest import mock
        self.captured()
        candidate = deploy.build_plan(self.repo, self.candidate)
        for row in candidate["files"]:
            b = subprocess.check_output(["git", "-C", str(self.repo), "show",
                                          self.candidate + ":" + row["source"]])
            dest = self.root / row["target"]
            dest.write_bytes(b)
        (self.root / deploy.MANIFEST_NAME).write_text(json.dumps(candidate), encoding="utf-8")
        peer = {"ProcessId": 18096, "Name": "python.exe",
                "CommandLine": (f'"python.exe" "{self.root / "ff_win_v3_main.py"}" '
                                "serve --host 127.0.0.1 --port 39076")}
        with mock.patch.object(bundle.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 0, json.dumps([peer]), "")):
            result = bundle.restore(self.snapshot, self.root, offline_confirmed=True,
                                    target_port=39073, peer_port=39076)
        self.assertTrue(result["ok"])
        self.assertEqual((self.root / "owner-sentinel.txt").read_text(), "leave untouched")
        self.assertEqual((self.root / "ff_win_v3_agent.py").read_text(), "old='current'\n")

    @unittest.skipUnless(os.name == "nt", "Win32_Process is only available on Windows")
    def test_live_win32_process_peer_command_line_on_real_windows(self):
        # Start a harmless child whose command line matches the backup 39076
        # shape; do not open the port or touch the owner's actual prelogin agent.
        import time
        script = self.root / "ff_win_v3_main.py"
        script.write_text("import time; time.sleep(12)\n", encoding="utf-8")
        proc = subprocess.Popen(
            [sys.executable, str(script), "serve", "--host", "127.0.0.1",
             "--port", "39076"],
            cwd=self.root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        try:
            ps = (
                "$ErrorActionPreference='Stop'; "
                "$p=Get-CimInstance Win32_Process -Filter 'ProcessId="
                + str(proc.pid) + "'; "
                "$p | Select-Object ProcessId,Name,CommandLine | ConvertTo-Json -Compress"
            )
            out = subprocess.run(["powershell.exe", "-NoProfile", "-Command", ps],
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(out.returncode, 0, out.stderr)
            row = json.loads(out.stdout)
            self.assertEqual(row["ProcessId"], proc.pid)
            self.assertIsNone(proc.poll(), "fixture must be alive during classification")
            classified = bundle._runtime_process_rows(
                self.root, [row], target_port=39073, peer_port=39076)
            self.assertEqual(classified, {proc.pid})
            with self.assertRaisesRegex(RuntimeError, "RESTORE_RUNTIME_STILL_RUNNING"):
                bundle._runtime_process_rows(self.root, [row], target_port=None, peer_port=None)
        finally:
            proc.terminate()
            proc.wait(timeout=6)

    def test_duplicate_snapshot_refused(self):
        self.captured()
        with self.assertRaisesRegex(RuntimeError, "SNAPSHOT_DESTINATION_UNSAFE"):
            self.captured()


if __name__ == "__main__":
    unittest.main()
