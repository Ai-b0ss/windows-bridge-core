from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent / "integration"))
from installed_package_smoke import verify_installed


class TestInstalledPackageContract(unittest.TestCase):
    def fixture(self, root):
        package, installed = root / "package", root / "installed"
        package.mkdir()
        (installed / "bridge-v3").mkdir(parents=True)
        files = {}
        for n in range(21):
            name = f"module{n}.py"
            data = f"VALUE={n}\n".encode()
            (installed / "bridge-v3" / name).write_bytes(data)
            files["runtime/bridge-v3/" + name] = hashlib.sha256(data).hexdigest()
        (package / "release-manifest.json").write_text(json.dumps({
            "schema": "ff-gh-release-v1", "source_commit": "new-commit",
            "public_source_commit": "new-commit", "source_bytes_verified_against_commit": True,
            "files": files}), encoding="utf-8")
        marker = installed / "bridge-v3/ff-local-owned-runtime.json"
        marker.write_text(json.dumps({"schema": "ff-local-owned-runtime-v1",
                                      "source_commit": "new-commit"}), encoding="utf-8")
        return package, installed, marker

    def test_full_installed_source_passes_and_a_single_executor_change_fails(self):
        with tempfile.TemporaryDirectory() as td:
            package, installed, marker = self.fixture(Path(td))
            self.assertEqual(verify_installed(package, installed, "new-commit")[1], 21)
            (installed / "bridge-v3/module20.py").write_bytes(b"stale executor")
            with self.assertRaisesRegex(RuntimeError, "SOURCE_SHA_MISMATCH"):
                verify_installed(package, installed, "new-commit")

    def test_old_install_marker_cannot_claim_the_new_package_identity(self):
        with tempfile.TemporaryDirectory() as td:
            package, installed, marker = self.fixture(Path(td))
            marker.write_text(json.dumps({"schema": "ff-local-owned-runtime-v1",
                                          "source_commit": "old-commit"}), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "MARKER_SOURCE_MISMATCH"):
                verify_installed(package, installed, "new-commit")

    def test_different_expected_commit_is_refused_before_runtime_launch(self):
        with tempfile.TemporaryDirectory() as td:
            package, installed, marker = self.fixture(Path(td))
            with self.assertRaisesRegex(RuntimeError, "SOURCE_IDENTITY_MISMATCH"):
                verify_installed(package, installed, "different-commit")

    def test_installed_transport_hashes_are_verified_when_present(self):
        with tempfile.TemporaryDirectory() as td:
            package, installed, marker = self.fixture(Path(td))
            transport = installed / "github-transport"
            transport.mkdir()
            file = transport / "ff_win_transport_paths.py"
            file.write_bytes(b"# transport bootstrap\n")
            manifest_path = package / "release-manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"]["runtime/github-transport/ff_win_transport_paths.py"] = hashlib.sha256(file.read_bytes()).hexdigest()
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(verify_installed(package, installed, "new-commit")[1], 22)
            file.write_bytes(b"stale transport")
            with self.assertRaisesRegex(RuntimeError, "SOURCE_SHA_MISMATCH"):
                verify_installed(package, installed, "new-commit")

    def test_old_transport_duplicate_cannot_shadow_the_shared_runtime(self):
        with tempfile.TemporaryDirectory() as td:
            package, installed, marker = self.fixture(Path(td))
            transport = installed / "github-transport"
            transport.mkdir()
            (transport / "module0.py").write_bytes(b"stale shared module")
            with self.assertRaisesRegex(RuntimeError, "LEGACY_TRANSPORT_MODULE_SHADOWING"):
                verify_installed(package, installed, "new-commit")


if __name__ == "__main__":
    unittest.main()
