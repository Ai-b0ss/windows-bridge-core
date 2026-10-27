"""Regression tests: complete source candidate parity without reading user-private files."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from shadow_runtime_parity import compare_full_runtime


class TestFullShadowRuntimeParity(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "src"
        self.shadow = self.root / "candidate" / "installed"
        self.live = self.root / "owner-live"
        for root in (self.source / "runtime" / "bridge-v3",
                     self.shadow / "bridge-v3", self.live / "bridge-v3"):
            root.mkdir(parents=True)
        self.archive = self.root / "candidate.zip"
        self.sha = "a" * 40
        self.modules = {
            "ff_win_v3_agent.py": b"x = 1\n",
            "cua_task_routes.py": b"def route():\n    return True\n",
            "cua_vscode_extension.cjs": b"module.exports = {};\n",
            "cua_owner_approval_controller/sample.csproj": b"<Project />\n",
        }
        self.extra = {}
        self._write_zip()
        self.live_root = self.live / "bridge-v3"
        self.shadow_root = self.shadow / "bridge-v3"
        self.source_root = self.source / "runtime" / "bridge-v3"
        for name, data in self.modules.items():
            (self.source_root / name).write_bytes(data)
            (self.shadow_root / name).write_bytes(data)
            (self.live_root / name).write_bytes(data)

    def _write_zip(self):
        files = {
            "runtime/bridge-v3/" + k: hashlib.sha256(v).hexdigest()
            for k, v in self.modules.items()
        }
        files.update(self.extra)
        manifest = {
            "schema": "ff-gh-release-v1",
            "source_commit": self.sha,
            "public_source_commit": self.sha,
            "source_bytes_verified_against_commit": True,
            "files": files,
        }
        with zipfile.ZipFile(self.archive, "w") as z:
            z.writestr("release-manifest.json", json.dumps(manifest))
            for name, data in self.modules.items():
                z.writestr("runtime/bridge-v3/" + name, data)

    def compare(self, **kwargs):
        with patch("shadow_runtime_parity.subprocess.run",
                   return_value=SimpleNamespace(stdout=self.sha + "\n")):
            return compare_full_runtime(self.source, self.archive, self.shadow, self.live, **kwargs)

    def test_source_shadow_and_live_entire_manifest_match(self):
        (self.live_root / "private-credentials.json").write_text("KEEP USER TOKEN PRIVATE")
        result = self.compare(observed_live_agent_sha=hashlib.sha256(self.modules["ff_win_v3_agent.py"]).hexdigest())
        self.assertTrue(result["shadow_disk_matches_candidate"])
        self.assertTrue(result["live_disk_matches_candidate"])
        self.assertEqual(result["runtime_modules"], 4)
        self.assertTrue(result["live_reported_agent_sha_equals_candidate"])
        self.assertFalse(result["live_process_identity_independently_verified"])
        self.assertFalse(result["safe_to_replace_running_runtime"])
        self.assertFalse(result["unknown_private_files_enumerated"])
        self.assertNotIn("KEEP USER TOKEN PRIVATE", str(result))
        self.assertNotIn(str(self.root), str(result))

    def test_drift_is_truthful_and_python_comments_are_semantically_equal(self):
        (self.live_root / "ff_win_v3_agent.py").write_bytes(b"x = 2\n")
        (self.live_root / "cua_task_routes.py").write_bytes(
            self.modules["cua_task_routes.py"] + b"# unchanged behavior\n"
        )
        result = self.compare(observed_live_agent_sha="f"*64)
        self.assertTrue(result["shadow_disk_matches_candidate"])
        self.assertFalse(result["live_disk_matches_candidate"])
        self.assertIs(result["live_reported_agent_sha_equals_candidate"], False)
        by_name = {x["module"]: x for x in result["modules"]}
        self.assertFalse(by_name["ff_win_v3_agent.py"]["live_python_ast_equal_candidate"])
        self.assertTrue(by_name["cua_task_routes.py"]["live_python_ast_equal_candidate"])
        self.assertFalse(result["safe_to_replace_running_runtime"])

    def test_missing_live_file_is_not_a_compatible_install(self):
        (self.live_root / "ff_win_v3_agent.py").unlink()
        result = self.compare()
        self.assertFalse(result["live_disk_matches_candidate"])
        self.assertFalse(next(x for x in result["modules"] if x["module"] == "ff_win_v3_agent.py")["live_present"])
        self.assertIsNone(result["live_reported_agent_sha_equals_candidate"])

    def test_corrupt_candidate_bytes_are_rejected_before_live_is_read(self):
        (self.source_root / "cua_task_routes.py").write_bytes(b"bad source\n")
        with self.assertRaisesRegex(ValueError, "CANDIDATE_AND_SOURCE_BYTES_MISMATCH"):
            self.compare()

    def test_manifest_path_traversal_is_rejected(self):
        self.extra = {"runtime/bridge-v3/../secret.json": "a"*64}
        self._write_zip()
        with self.assertRaisesRegex(ValueError, "UNSAFE_OR_DUPLICATE_RUNTIME_PATH"):
            self.compare()

    def test_duplicate_candidate_entry_fails_closed(self):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.archive, "a") as z:
                z.writestr("runtime/bridge-v3/ff_win_v3_agent.py", b"evil")
        with self.assertRaisesRegex(ValueError, "CANDIDATE_RUNTIME_ENTRY_MISSING_OR_DUPLICATED"):
            self.compare()

    def test_source_commit_drift_refuses_parity(self):
        with patch("shadow_runtime_parity.subprocess.run",
                   return_value=SimpleNamespace(stdout="b"*40)):
            with self.assertRaisesRegex(ValueError, "SOURCE_COMMIT_IDENTITY_MISMATCH"):
                compare_full_runtime(self.source, self.archive, self.shadow, self.live)

    def test_malformed_agent_claim_does_not_enable_live_process_proof(self):
        with self.assertRaisesRegex(ValueError, "LIVE_AGENT_SHA_INVALID"):
            self.compare(observed_live_agent_sha="not-an-attestation")


if __name__ == "__main__":
    unittest.main()
