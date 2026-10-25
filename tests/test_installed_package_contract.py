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


if __name__ == "__main__":
    unittest.main()
