"""CI rehearsal of real public-Core upgrades and crash recovery.

Runs against disposable Git repositories and temporary installations only.
Does not inspect or modify the owner's installed Windows Bridge.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest import mock

RUNTIME_SOURCE = Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"
sys.path.insert(0, str(RUNTIME_SOURCE))
from cua_runtime_deploy import (  # noqa: E402
    JOURNAL_SCHEMA,
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
        (self.runtime / "nested").mkdir()
        (self.runtime / "nested/cua_retired.py").write_text("RETIRED = True\n", encoding="utf-8")
        # Inert binary fixture: never executed, but must not be left stale.
        (self.runtime / "retired-helper.exe").write_bytes(b"MZ-inert-retired-fixture\n")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-q", "-m", "previous public runtime")
        self.previous = _git(self.repo, "rev-parse", "HEAD")

        (self.runtime / "ff_win_v3_agent.py").write_text(
            "VERSION = 'candidate'\n", encoding="utf-8"
        )
        (self.runtime / "cua_previous.py").unlink()
        (self.runtime / "nested/cua_retired.py").unlink()
        (self.runtime / "nested").rmdir()
        (self.runtime / "retired-helper.exe").unlink()
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
        self.assertEqual(verified["file_count"], 4)
        self.assertFalse((self.install / LOCK_NAME).exists())
        return {
            name: _sha(self.install / name)
            for name in ("ff_win_v3_agent.py", "cua_previous.py", "nested/cua_retired.py",
                         "retired-helper.exe", MANIFEST_NAME)
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
        self.assertFalse((self.install / "nested/cua_retired.py").exists())
        self.assertFalse((self.install / "retired-helper.exe").exists())
        self.assertEqual(result["files_retired"], 3)
        self.assertTrue((self.install / "cua_current.py").exists())
        self.assertTrue(verify_runtime(self.install)["ok"])

    def test_forged_old_manifest_cannot_claim_an_owner_file(self):
        self._install_previous()
        owner = self.install / "owner-local-not-in-source.txt"
        owner.write_bytes(b"owner data, never installed by Bridge\n")
        manifest = self.install / MANIFEST_NAME
        data = json.loads(manifest.read_text(encoding="utf-8"))
        data["files"].append({
            "source": "runtime/bridge-v3/" + owner.name,
            "target": owner.name, "bytes": owner.stat().st_size,
            "sha256": _sha(owner),
        })
        manifest.write_text(json.dumps(data), encoding="utf-8")
        snapshot = {p.name: _sha(p) for p in self.install.iterdir() if p.is_file()}

        with self.assertRaisesRegex(RuntimeError, "PREVIOUS_MANIFEST_UNPROVEN"):
            apply_runtime(self.repo, self.install, ref=self.candidate)

        self.assertEqual({name: _sha(self.install / name) for name in snapshot}, snapshot)
        self.assertFalse((self.install / "cua_current.py").exists())
        self.assertFalse((self.install / LOCK_NAME).exists())

    def test_recomputed_manifest_identity_still_cannot_claim_owner_file(self):
        self._install_previous()
        owner = self.install / "owner-local-not-in-source.txt"
        owner.write_bytes(b"private owner file\n")
        path = self.install / MANIFEST_NAME
        data = json.loads(path.read_text(encoding="utf-8"))
        data["files"].append({"source": "runtime/bridge-v3/" + owner.name,
                              "target": owner.name, "bytes": owner.stat().st_size,
                              "sha256": _sha(owner)})
        identity = {"head": data["source_head"], "files": data["files"]}
        data["release_id"] = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        path.write_text(json.dumps(data), encoding="utf-8")
        before = _sha(owner)
        with self.assertRaisesRegex(RuntimeError, "PREVIOUS_MANIFEST_UNPROVEN"):
            apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertEqual(_sha(owner), before)
        self.assertFalse((self.install / LOCK_NAME).exists())

    def test_malformed_and_unsafe_old_claims_fail_before_install(self):
        snapshot = self._install_previous()
        path = self.install / MANIFEST_NAME
        original = path.read_bytes()
        data = json.loads(original)
        cases = [b"{bad json", b"[]", b"null"]
        for field, value in (("schema", "future/v2"), ("source_head", "HEAD"),
                             ("source_head", "0" * 40), ("release_id", "0" * 64),
                             ("files", {}), ("files", [None])):
            cases.append(json.dumps({**data, field: value}).encode())
        unsafe = ["../owner.txt", "/absolute", "C:/owner.txt", "nested/../owner.txt",
                  "nested\\owner.txt", "nested//owner.txt", "NUL.txt", "COM¹.py",
                  "cua_previous.py.", "cua_previous.py ", "cua_previous.py:stream",
                  ".CUA-DEPLOY/file", MANIFEST_NAME.upper(), "nested/*"]
        for target in unsafe:
            claim = {**data, "files": [*data["files"], {**data["files"][0], "target": target}]}
            cases.append(json.dumps(claim).encode())
        for raw in cases:
            with self.subTest(claim=raw[:80]):
                path.write_bytes(raw)
                with self.assertRaisesRegex(RuntimeError, "PREVIOUS_MANIFEST_UNPROVEN"):
                    apply_runtime(self.repo, self.install, ref=self.candidate)
                self.assertFalse((self.install / LOCK_NAME).exists())
                self.assertFalse((self.install / "cua_current.py").exists())
                self.assertEqual(_sha(self.install / "cua_previous.py"), snapshot["cua_previous.py"])
        path.write_bytes(original)

    def test_modified_retired_file_is_preserved_without_success(self):
        snapshot = self._install_previous()
        retired = self.install / "retired-helper.exe"
        retired.write_bytes(b"owner replaced this file\n")
        with self.assertRaisesRegex(RuntimeError, "RETIRED_FILE_UNPROVEN"):
            apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertEqual(retired.read_bytes(), b"owner replaced this file\n")
        self.assertEqual(_sha(self.install / MANIFEST_NAME), snapshot[MANIFEST_NAME])
        self.assertEqual(_sha(self.install / "ff_win_v3_agent.py"), snapshot["ff_win_v3_agent.py"])
        self.assertFalse((self.install / LOCK_NAME).exists())

    def test_v1_bom_and_extra_install_metadata_remain_compatible(self):
        self._install_previous()
        path = self.install / MANIFEST_NAME
        data = json.loads(path.read_text(encoding="utf-8"))
        data["legacy_operator_note"] = "ignored non-authority metadata"
        path.write_text(json.dumps(data), encoding="utf-8-sig")
        owner = self.install / "owner.txt"
        owner.write_bytes(b"keep\n")
        result = apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertTrue(result["ok"])
        self.assertEqual(result["files_retired"], 3)
        self.assertEqual(owner.read_bytes(), b"keep\n")
        repeated = apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertTrue(repeated["ok"])
        self.assertEqual(repeated["files_replaced"], 0)
        self.assertEqual(repeated["files_retired"], 0)

    def test_missing_manifest_on_nonempty_install_is_not_silent_success(self):
        self._install_previous()
        (self.install / MANIFEST_NAME).unlink()
        with self.assertRaisesRegex(RuntimeError, "PREVIOUS_MANIFEST_MISSING_NONEMPTY"):
            apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertTrue((self.install / "retired-helper.exe").exists())
        self.assertFalse((self.install / "cua_current.py").exists())

    def test_missing_retired_name_does_not_authorize_deleting_later_owner_file(self):
        self._install_previous()
        path = self.install / "retired-helper.exe"
        path.unlink()
        result = apply_runtime(self.repo, self.install, ref=self.candidate,
                               before_replace=lambda: path.write_bytes(b"new owner data\n"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["files_retired"], 2)
        self.assertEqual(path.read_bytes(), b"new owner data\n")

    def test_failure_after_retirement_restores_retired_files_and_retries(self):
        snapshot = self._install_previous()
        def fail():
            self.assertFalse((self.install / "retired-helper.exe").exists())
            raise RuntimeError("readiness failed")
        with self.assertRaisesRegex(RuntimeError, "readiness failed"):
            apply_runtime(self.repo, self.install, ref=self.candidate, after_install=fail)
        self._assert_previous_intact(snapshot)
        self.assertFalse(recover_stale(self.install)["recovered"])
        self.assertTrue(apply_runtime(self.repo, self.install, ref=self.candidate)["ok"])

    def test_owner_change_before_delete_is_preserved_and_blocks_rollback(self):
        self._install_previous()
        path = self.install / "retired-helper.exe"
        with self.assertRaisesRegex(RuntimeError, "ROLLBACK_FAILED:ROLLBACK_RETIRED_CONFLICT"):
            apply_runtime(self.repo, self.install, ref=self.candidate,
                          before_replace=lambda: path.write_bytes(b"changed owner data\n"))
        self.assertEqual(path.read_bytes(), b"changed owner data\n")
        self.assertTrue((self.install / LOCK_NAME).exists())
        with self.assertRaisesRegex(RuntimeError, "ROLLBACK_RETIRED_CONFLICT"):
            recover_stale(self.install)
        self.assertEqual(path.read_bytes(), b"changed owner data\n")
        # Resolve only this disposable fixture conflict, then resume recovery.
        path.unlink()
        self.assertTrue(recover_stale(self.install)["recovered"])
        self.assertFalse(recover_stale(self.install)["recovered"])
        self.assertTrue(verify_runtime(self.install)["ok"])

    def test_owner_recreation_after_retirement_is_not_overwritten_by_recovery(self):
        self._install_previous()
        path = self.install / "retired-helper.exe"
        def fail():
            path.write_bytes(b"owner recreated this name\n")
            raise RuntimeError("readiness failed")
        with self.assertRaisesRegex(RuntimeError, "ROLLBACK_FAILED:ROLLBACK_RETIRED_CONFLICT"):
            apply_runtime(self.repo, self.install, ref=self.candidate, after_install=fail)
        for _ in range(2):
            with self.assertRaisesRegex(RuntimeError, "ROLLBACK_RETIRED_CONFLICT"):
                recover_stale(self.install)
            self.assertEqual(path.read_bytes(), b"owner recreated this name\n")
            self.assertTrue((self.install / LOCK_NAME).exists())

    def test_changed_manifest_before_journal_releases_lock_without_mutation(self):
        snapshot = self._install_previous()
        import cua_runtime_deploy as deploy
        acquire = deploy._acquire_lock
        def acquire_then_change(path, payload):
            acquire(path, payload)
            (self.install / MANIFEST_NAME).write_bytes(b"changed concurrently")
        with mock.patch.object(deploy, "_acquire_lock", side_effect=acquire_then_change):
            with self.assertRaisesRegex(RuntimeError, "PREVIOUS_MANIFEST_CHANGED"):
                apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertFalse((self.install / LOCK_NAME).exists())
        self.assertEqual(_sha(self.install / "ff_win_v3_agent.py"), snapshot["ff_win_v3_agent.py"])
        self.assertEqual((self.install / MANIFEST_NAME).read_bytes(), b"changed concurrently")

    @unittest.skipUnless(os.name == "nt", "Windows junction semantics")
    def test_retired_parent_junction_and_runtime_root_junction_are_rejected(self):
        self._install_previous()
        outside = self.base / "owner-directory"
        outside.mkdir()
        owner = outside / "cua_retired.py"
        owner.write_bytes(b"owner data\n")
        nested = self.install / "nested"
        (nested / "cua_retired.py").unlink()
        nested.rmdir()
        subprocess.run(["cmd", "/c", "mklink", "/J", str(nested), str(outside)],
                       capture_output=True, check=True, timeout=10)
        with self.assertRaisesRegex(RuntimeError, "LINK_FORBIDDEN"):
            apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertEqual(owner.read_bytes(), b"owner data\n")
        alias = self.base / "install-alias"
        subprocess.run(["cmd", "/c", "mklink", "/J", str(alias), str(self.install)],
                       capture_output=True, check=True, timeout=10)
        with self.assertRaisesRegex(RuntimeError, "REPARSE_OR_TYPE_FORBIDDEN"):
            apply_runtime(self.repo, alias, ref=self.candidate)

    @unittest.skipUnless(os.name == "nt", "Windows directory handle sharing")
    def test_directory_swap_is_blocked_by_real_windows_handles(self):
        self._install_previous()
        code = ("import os,sys\ntry: os.rename(sys.argv[1],sys.argv[2])\n"
                "except PermissionError: sys.exit(0)\nelse: sys.exit(7)\n")
        def attempt_swap():
            result = subprocess.run([sys.executable, "-c", code,
                                     str(self.install / "nested"), str(self.install / "swapped")],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
        result = apply_runtime(self.repo, self.install, ref=self.candidate, before_replace=attempt_swap)
        self.assertTrue(result["ok"])
        self.assertEqual(result["files_retired"], 3)

    def test_legacy_tools_mapping_is_proven_from_its_own_commit(self):
        _git(self.repo, "rm", "-r", "runtime")
        legacy = self.repo / "tools"
        legacy.mkdir()
        (legacy / "cua_release_manifest.py").write_text(
            "COMPONENTS = ('tools/ff_win_v3_agent.py', 'tools/legacy-helper.exe')\n", encoding="utf-8")
        (legacy / "ff_win_v3_agent.py").write_text("LEGACY = True\n", encoding="utf-8")
        (legacy / "legacy-helper.exe").write_bytes(b"MZ-inert-legacy-fixture\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-q", "-m", "legacy tools layout")
        previous = _git(self.repo, "rev-parse", "HEAD")
        _git(self.repo, "checkout", self.candidate, "--", "runtime")
        _git(self.repo, "commit", "-q", "-m", "migrate to public runtime tree")
        candidate = _git(self.repo, "rev-parse", "HEAD")
        self.assertTrue(apply_runtime(self.repo, self.install, ref=previous)["ok"])
        result = apply_runtime(self.repo, self.install, ref=candidate)
        self.assertTrue(result["ok"])
        self.assertEqual(result["files_retired"], 1)
        self.assertFalse((self.install / "legacy-helper.exe").exists())

    def test_valid_git_commit_outside_candidate_history_is_not_ownership(self):
        snapshot = self._install_previous()
        from cua_runtime_deploy import build_plan
        tree = _git(self.repo, "rev-parse", self.previous + "^{tree}")
        orphan = _git(self.repo, "commit-tree", tree, "-m", "unrelated identical tree")
        (self.install / MANIFEST_NAME).write_text(json.dumps(build_plan(self.repo, orphan)), encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "PREVIOUS_MANIFEST_UNPROVEN"):
            apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertEqual(_sha(self.install / "retired-helper.exe"), snapshot["retired-helper.exe"])
        self.assertFalse((self.install / "cua_current.py").exists())

    def test_missing_old_git_object_fails_before_runtime_changes(self):
        snapshot = self._install_previous()
        commit_object = self.repo / ".git/objects" / self.previous[:2] / self.previous[2:]
        # Only this test's disposable loose Git object is removed.
        commit_object.chmod(0o600)
        commit_object.unlink()
        with self.assertRaisesRegex(RuntimeError, "PREVIOUS_MANIFEST_UNPROVEN"):
            apply_runtime(self.repo, self.install, ref=self.candidate)
        self._assert_previous_intact(snapshot)

    def test_symlinked_retired_file_and_manifest_are_rejected(self):
        self._install_previous()
        owner = self.base / "owner-file"
        owner.write_bytes(b"private data\n")
        for name in ("retired-helper.exe", MANIFEST_NAME):
            path = self.install / name
            old = path.read_bytes()
            path.unlink()
            try:
                path.symlink_to(owner)
            except OSError as exc:
                path.write_bytes(old)
                self.skipTest(f"symlink creation unavailable: {exc}")
            try:
                with self.assertRaisesRegex(RuntimeError, "LINK_FORBIDDEN"):
                    apply_runtime(self.repo, self.install, ref=self.candidate)
                self.assertEqual(owner.read_bytes(), b"private data\n")
                self.assertTrue(path.is_symlink())
                self.assertFalse((self.install / "cua_current.py").exists())
            finally:
                path.unlink()
                path.write_bytes(old)

    @unittest.skipUnless(os.name == "nt", "Windows junction semantics")
    def test_transaction_directory_junction_cannot_redirect_writes(self):
        self._install_previous()
        outside = self.base / "owner-directory"
        outside.mkdir()
        sentinel = outside / "keep.txt"
        sentinel.write_bytes(b"keep\n")
        tx = self.install / ".cua-deploy"
        tx.rmdir()
        subprocess.run(["cmd", "/c", "mklink", "/J", str(tx), str(outside)],
                       capture_output=True, check=True, timeout=10)
        with self.assertRaisesRegex(RuntimeError, "REPARSE_OR_TYPE_FORBIDDEN"):
            apply_runtime(self.repo, self.install, ref=self.candidate)
        self.assertEqual(list(outside.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_bytes(), b"keep\n")

    @unittest.skipUnless(os.name == "nt", "Windows file handle sharing")
    def test_retirement_hash_handle_blocks_real_writer_and_rename(self):
        import cua_runtime_deploy as deploy
        path = self.base / "retired.exe"
        path.write_bytes(b"MZ-inert-fixture\n")
        digest = _sha(path)
        real_digest = hashlib.file_digest
        code = ("import os,sys\n"
                "try: open(sys.argv[1], 'wb').write(b'owner replacement')\n"
                "except PermissionError: pass\nelse: sys.exit(7)\n"
                "try: os.rename(sys.argv[1], sys.argv[1]+'.moved')\n"
                "except PermissionError: pass\nelse: sys.exit(8)\n")
        def check_locked(stream, algorithm):
            result = subprocess.run([sys.executable, "-c", code, str(path)], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            return real_digest(stream, algorithm)
        with mock.patch.object(deploy.hashlib, "file_digest", side_effect=check_locked) as checked:
            deploy._retire_file(path, digest)
        checked.assert_called_once()
        self.assertFalse(path.exists())

    def test_unsafe_windows_target_spellings_are_rejected_directly(self):
        from cua_runtime_deploy import _recovery_target
        for name in ("../x", "a//b", "a/./b", "a\\b", "a:stream", "NUL.py", "COM¹.exe",
                     "x.", "x ", "x/?", "x/\x00", "x/CONOUT$", ".CUA-DEPLOY/x",
                     MANIFEST_NAME.upper(), LOCK_NAME.upper()):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "TARGET_UNSAFE"):
                _recovery_target(self.install, name)

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
        self.assertEqual(verify_runtime(self.install)["error"], "DEPLOY_LOCK_PRESENT")
        # The newer writer must not serialize imaginary backup files for
        # newly created modules. Legacy placeholders are tested separately.
        lock = json.loads((self.install / LOCK_NAME).read_text(encoding="utf-8-sig"))
        journal = json.loads(Path(lock["journal"]).read_text(encoding="utf-8-sig"))
        self.assertEqual(journal["schema"], JOURNAL_SCHEMA)
        retired_rows = [item for item in journal["files"] if "retired_sha256" in item]
        self.assertEqual(len(retired_rows), 3)
        self.assertTrue(all(item["retired_sha256"] == item["old_sha256"] for item in retired_rows))
        new_files = [item for item in journal["files"] if not item["existed"]]
        self.assertTrue(new_files)
        self.assertTrue(all(item["backup"] is None for item in new_files))

        # Crash once with a fully written rollback scratch file, then again
        # just after restoring the first retired module. Real recovery must
        # tolerate both an abandoned scratch slot and a partial prior replay.
        recovery_code = (
            "import os,sys\nfrom pathlib import Path\n"
            "sys.path.insert(0,sys.argv[1])\nimport cua_runtime_deploy as d\n"
            "if sys.argv[3] == 'scratch':\n"
            "    d.os.rename = lambda *a, **k: os._exit(94)\n"
            "else:\n"
            "    real = d._copy_replace\n"
            "    def partial(*a, **k):\n"
            "        real(*a, **k)\n"
            "        if k.get('overwrite') is False: os._exit(95)\n"
            "    d._copy_replace = partial\n"
            "d.recover_stale(Path(sys.argv[2]))\n"
        )
        for mode, expected_exit in (("scratch", 94), ("partial", 95)):
            recovery = subprocess.run([sys.executable, "-c", recovery_code, str(RUNTIME_SOURCE),
                                       str(self.install), mode], capture_output=True, timeout=90)
            self.assertEqual(recovery.returncode, expected_exit,
                             (recovery.stderr or b"")[-800:].decode("utf-8", "replace"))
            self.assertTrue((self.install / LOCK_NAME).exists())
        self.assertFalse(list(self.install.glob("*.new")))

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
