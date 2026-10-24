import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import optional_addons as addon


class TestAddonInstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ff-addon-ci-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "owned-core"
        bridge = self.root / "bridge-v3"
        bridge.mkdir(parents=True)
        (bridge / "ff_win_v3_main.py").write_text("# core", encoding="utf-8")
        self.archive = Path(self.tmp.name) / "browser.zip"
        self.make_zip({
            "node_modules/playwright/package.json": b'{"version":"test"}',
            "browsers/chromium/readme.txt": b"browser-test",
        })
        self.spec = self.lock()
        self.patch = patch.dict(addon.SPEC, {"browser": self.spec})
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def make_zip(self, entries):
        with zipfile.ZipFile(self.archive, "w", zipfile.ZIP_DEFLATED) as z:
            for name, body in entries.items():
                z.writestr(name, body)

    def lock(self):
        with zipfile.ZipFile(self.archive) as z:
            count = len(z.infolist())
        return {
            "sha256": addon.hash_file(self.archive), "bytes": self.archive.stat().st_size,
            "members": count, "roots": ("node_modules", "browsers"),
            "max_unpacked": 10000,
        }

    def test_install_status_then_uninstall_exact_files(self):
        self.assertEqual(addon.status(self.root)["addons"]["browser"], "missing_optional_dependency")
        result = addon.install(self.root, "browser", self.archive)
        self.assertEqual(result["files"], 2)
        self.assertEqual(addon.status(self.root)["addons"]["browser"], "installed_marker_present_not_deep_verified")
        removed = addon.remove(self.root, "browser")
        self.assertTrue(removed["removed"])
        self.assertFalse((self.root / "bridge-v3/node_modules").exists())
        self.assertTrue((self.root / "bridge-v3/ff_win_v3_main.py").exists())

    def test_hash_rejected_without_modification(self):
        self.spec["sha256"] = "0" * 64
        with self.assertRaisesRegex(addon.AddonError, "SHA256_MISMATCH"):
            addon.install(self.root, "browser", self.archive)
        self.assertFalse((self.root / "bridge-v3/node_modules").exists())

    def test_size_rejected(self):
        self.spec["bytes"] -= 1
        with self.assertRaisesRegex(addon.AddonError, "SIZE_MISMATCH"):
            addon.install(self.root, "browser", self.archive)

    def test_foreign_existing_dir_never_overwritten(self):
        p = self.root / "bridge-v3/node_modules"
        p.mkdir()
        secret = p / "keep.txt"
        secret.write_text("user data", encoding="utf-8")
        with self.assertRaisesRegex(addon.AddonError, "NOT_OWNED"):
            addon.install(self.root, "browser", self.archive)
        self.assertEqual(secret.read_text(), "user data")

    def test_foreign_file_blocks_uninstall(self):
        addon.install(self.root, "browser", self.archive)
        foreign = self.root / "bridge-v3/node_modules/private.txt"
        foreign.write_text("not mine", encoding="utf-8")
        with self.assertRaisesRegex(addon.AddonError, "MODIFIED_OR_FOREIGN"):
            addon.remove(self.root, "browser")
        self.assertTrue(foreign.exists())

    def test_modified_file_blocks_uninstall(self):
        addon.install(self.root, "browser", self.archive)
        item = self.root / "bridge-v3/browsers/chromium/readme.txt"
        item.write_bytes(b"modified")
        with self.assertRaisesRegex(addon.AddonError, "MODIFIED_OR_FOREIGN"):
            addon.remove(self.root, "browser")

    def test_zip_path_escape_rejected_before_extraction(self):
        self.make_zip({
            "node_modules/../evil.txt": b"evil",
            "browsers/chromium/readme.txt": b"good",
        })
        self.spec.update(self.lock())
        with self.assertRaisesRegex(addon.AddonError, "TRAVERSAL"):
            addon.install(self.root, "browser", self.archive)
        self.assertFalse((self.root / "evil.txt").exists())

    def test_zip_foreign_root_rejected(self):
        self.make_zip({"windows/system.ini": b"evil"})
        self.spec.update(self.lock())
        with self.assertRaisesRegex(addon.AddonError, "FOREIGN"):
            addon.install(self.root, "browser", self.archive)

    def test_missing_core_rejected(self):
        (self.root / "bridge-v3/ff_win_v3_main.py").unlink()
        with self.assertRaisesRegex(addon.AddonError, "CORE_NOT_INSTALLED"):
            addon.install(self.root, "browser", self.archive)

    def test_duplicate_casefold_rejected(self):
        self.make_zip({
            "node_modules/READme.txt": b"a",
            "node_modules/readME.txt": b"b",
        })
        self.spec.update(self.lock())
        with self.assertRaisesRegex(addon.AddonError, "DUPLICATE"):
            addon.install(self.root, "browser", self.archive)


if __name__ == "__main__":
    unittest.main()
