import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import optional_addons as addon


class TestVisualCacheCleanup(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ff-visual-cache-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "core"
        (self.root / "bridge-v3").mkdir(parents=True)
        (self.root / "bridge-v3/ff_win_v3_main.py").write_text("# owner core", encoding="utf-8")
        self.archive = Path(self.tmp.name) / "visual.zip"
        with zipfile.ZipFile(self.archive, "w") as z:
            z.writestr("native/detector/python/site-packages/example/__init__.py", b"x=1")
        self.spec = {
            "sha256": addon.hash_file(self.archive), "bytes": self.archive.stat().st_size,
            "members": 1, "roots": ("native",), "max_unpacked": 1024,
        }
        replacement = patch.dict(addon.SPEC, {"visual": self.spec})
        replacement.start()
        self.addCleanup(replacement.stop)

    def test_python_generated_caches_permitted_on_uninstall(self):
        addon.install(self.root, "visual", self.archive)
        base = self.root / "bridge-v3/native/detector/python/site-packages"
        for rel in ("example/__pycache__/__init__.cpython-313.pyc",
                    "__pycache__/typing_extensions.cpython-313.pyc"):
            file = base / rel
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"generated python cache")
        self.assertTrue(addon.remove(self.root, "visual")["removed"])
        self.assertFalse((self.root / "bridge-v3/native").exists())
        self.assertTrue((self.root / "bridge-v3/ff_win_v3_main.py").exists())

    def test_unknown_python_module_still_blocks_uninstall(self):
        addon.install(self.root, "visual", self.archive)
        folder = self.root / "bridge-v3/native/detector/python/site-packages"
        extra = folder / "own_script.py"
        extra.write_text("keep me", encoding="utf-8")
        with self.assertRaisesRegex(addon.AddonError, "MODIFIED_OR_FOREIGN"):
            addon.remove(self.root, "visual")
        self.assertTrue(extra.exists())


if __name__ == "__main__":
    unittest.main()
