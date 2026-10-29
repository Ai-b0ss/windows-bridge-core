from pathlib import Path
import sys
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import build_portable_release as builder


class TestReleaseBuildContract(unittest.TestCase):
    def git(self, root, *args):
        return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.STDOUT)

    def source_repo(self, root):
        self.git(root, "init", "--quiet")
        self.git(root, "config", "user.name", "Release test")
        self.git(root, "config", "user.email", "release-test@example.invalid")
        file = root / "source.py"
        file.write_bytes(b"print('pinned')\n")
        self.git(root, "add", "source.py")
        self.git(root, "commit", "--quiet", "-m", "pinned source")
        return file

    def test_exact_committed_source_returns_pinned_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = self.source_repo(root)
            expected = self.git(root, "rev-parse", "HEAD").decode().strip()
            self.assertEqual(builder.verify_source_commit(root, {"source.py": file.read_bytes()}), expected)

    def test_repacked_installer_identity_matches_new_source_and_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = self.source_repo(root)
            expected = self.git(root, "rev-parse", "HEAD").decode().strip()
            previous = root / "previous.zip"
            asset = b"pinned-test-asset"
            with zipfile.ZipFile(previous, "w") as archive:
                archive.writestr("release-manifest.json", json.dumps({
                    "schema": "ff-gh-release-v1", "source_commit": "old-source"}))
                archive.writestr("assets/test.zip", asset)
                archive.writestr("README-FIRST.md", "Previous release")
            original = previous.read_bytes()
            with patch.object(builder, "PREVIOUS_RELEASE_SHA", builder.sha(original)), \
                 patch.object(builder, "ASSET_HASHES", {"assets/test.zip": builder.sha(asset)}), \
                 patch.object(builder, "source_tree", side_effect=lambda repo: {"source.py": file.read_bytes()}):
                first = builder.assemble(root, previous, root / "first.zip")
                second = builder.assemble(root, previous, root / "second.zip")
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertEqual(previous.read_bytes(), original)
            with zipfile.ZipFile(root / "first.zip") as archive:
                manifest = json.loads(archive.read("release-manifest.json"))
                self.assertEqual(manifest["source_commit"], expected)
                self.assertEqual(manifest["public_source_commit"], expected)
                self.assertTrue(manifest["source_bytes_verified_against_commit"])
                self.assertEqual(archive.read("assets/test.zip"), asset)

    def test_modified_file_refused_even_if_git_index_assumes_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = self.source_repo(root)
            self.git(root, "update-index", "--assume-unchanged", "source.py")
            file.write_bytes(b"print('uncommitted')\n")
            with self.assertRaisesRegex(ValueError, "DIFFERS_FROM_COMMIT"):
                builder.verify_source_commit(root, {"source.py": file.read_bytes()})

    def test_untracked_bundled_source_cannot_borrow_head_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.source_repo(root)
            with self.assertRaisesRegex(ValueError, "NOT_IN_COMMIT"):
                builder.verify_source_commit(root, {"new.py": b"untracked"})

    def test_non_git_folder_has_no_source_commit_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(subprocess.CalledProcessError):
                builder.verify_source_commit(Path(tmp), {"source.py": b"unversioned"})

    def test_deleted_runtime_file_cannot_silently_disappear_from_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.source_repo(root)
            (root / "runtime").mkdir()
            file = root / "runtime" / "required.py"
            file.write_bytes(b"required\n")
            self.git(root, "add", "runtime/required.py")
            self.git(root, "commit", "--quiet", "-m", "required runtime")
            file.unlink()
            with self.assertRaisesRegex(ValueError, "MISSING_FROM_BUNDLE"):
                builder.verify_source_commit(root, {})

    def test_no_old_private_repo_history_or_transport_logs(self):
        contents=builder.source_tree(ROOT)
        self.assertIn("tools/optional_addons.py",contents)
        self.assertIn("ADDONS.cmd",contents)
        self.assertIn("runtime/bridge-v3/ff_win_v3_main.py",contents)
        self.assertTrue(all(not name.startswith((".git/","astra_transport/","K:/")) for name in contents))
        self.assertTrue(all(not name.endswith((".jsonl",".sqlite3",".db",".pfx")) for name in contents))
        self.assertEqual(len(contents),len(set(contents)))

    def test_vendor_assets_have_explicit_sha256(self):
        self.assertEqual(len(builder.ASSET_HASHES),3)
        self.assertTrue(all(x.startswith("assets/") and x.endswith(".zip") for x in builder.ASSET_HASHES))
        self.assertTrue(all(len(x)==64 for x in builder.ASSET_HASHES.values()))
        self.assertEqual(len(builder.PREVIOUS_RELEASE_SHA),64)

    def test_transport_bundle_uses_only_bridge_shared_modules(self):
        contents = builder.source_tree(ROOT)
        bridge = {Path(name).name for name in contents if name.startswith("runtime/bridge-v3/") and name.endswith(".py")}
        transport = {Path(name).name for name in contents if name.startswith("runtime/github-transport/") and name.endswith(".py")}
        self.assertFalse(bridge & transport)
        self.assertIn("ff_win_transport_paths.py", transport)
        manifest = json.loads((ROOT / "release-manifest.json").read_text(encoding="utf-8"))
        self.assertTrue(set(contents) <= set(manifest["files"]))
        manifest_transport = {Path(name).name for name in manifest["files"]
                              if name.startswith("runtime/github-transport/") and name.endswith(".py")}
        self.assertEqual(manifest_transport, transport)

    def test_source_manifest_refresh_replaces_stale_records_without_release_claim(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "release-manifest.json"
            path.write_text(json.dumps({"schema": "ff-gh-release-v1", "source_commit": "previous-release",
                                        "files": {"assets/test.zip": "asset-hash", "README-FIRST.md": "readme-hash",
                                                  "runtime/github-transport/ff_win_v3_agent.py": "stale"}}), encoding="utf-8")
            contents = builder.source_tree(ROOT)
            with patch.object(builder, "source_tree", return_value=contents):
                builder.refresh_source_manifest(root)
                first = path.read_bytes()
                builder.refresh_source_manifest(root)
            self.assertEqual(first, path.read_bytes())
            manifest = json.loads(first)
            self.assertNotIn("runtime/github-transport/ff_win_v3_agent.py", manifest["files"])
            self.assertEqual(manifest["files"]["assets/test.zip"], "asset-hash")
            self.assertEqual(manifest["files"]["README-FIRST.md"], "readme-hash")
            self.assertEqual(manifest["source_commit"], "previous-release")
            self.assertNotIn("source_bytes_verified_against_commit", manifest)
            for name, data in contents.items():
                self.assertEqual(manifest["files"][name], builder.sha(data))


if __name__=="__main__":
    unittest.main()
