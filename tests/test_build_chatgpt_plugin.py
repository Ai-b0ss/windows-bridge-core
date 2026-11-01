import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build_chatgpt_plugin as b


class BuildChatGPTPluginTests(unittest.TestCase):
    def test_bump(self):
        self.assertEqual(b.bump("1.1.1"), "1.1.2")
        with self.assertRaises(SystemExit):
            b.bump("v1")

    def test_keeps_app_binding_and_replaces_skills(self):
        with tempfile.TemporaryDirectory() as tmp:
            src, out = Path(tmp) / "in.zip", Path(tmp) / "out.zip"
            with zipfile.ZipFile(src, "w") as z:
                z.writestr(".app.json", '{"apps": {"x": {"id": "asdk_app_1"}}}')
                z.writestr(".codex-plugin/plugin.json", json.dumps({"name": "dev-1", "version": "1.1.1"}))
                z.writestr("skills/windows-bridge/SKILL.md", "old")
            info = b.build(src, out, "HEAD")
            self.assertEqual(info["new_version"], "1.1.2")
            with zipfile.ZipFile(out) as z:
                self.assertIn("asdk_app_1", z.read(".app.json").decode())
                self.assertEqual(json.loads(z.read(".codex-plugin/plugin.json"))["version"], "1.1.2")
                self.assertNotEqual(z.read("skills/windows-bridge/SKILL.md"), b"old")
                self.assertNotIn(b"\r\n", z.read("skills/windows-bridge/SKILL.md"))

    def test_rejects_non_plugin_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "in.zip"
            with zipfile.ZipFile(src, "w") as z:
                z.writestr("SKILL.md", "x")
            with self.assertRaises(SystemExit):
                b.build(src, Path(tmp) / "out.zip", "HEAD")


if __name__ == "__main__":
    unittest.main()
