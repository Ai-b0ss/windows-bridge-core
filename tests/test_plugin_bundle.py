import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from build_skill_plugin import build

class TestSkillPluginArchive(unittest.TestCase):
    def test_skill_and_plugin_deterministic_and_manifest_valid(self):
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td)
            a=directory/"skill-a.zip"
            b=directory/"skill-b.zip"
            sa=build(ROOT,a,"skill")
            sb=build(ROOT,b,"skill")
            self.assertEqual(sa["sha256"],sb["sha256"])
            self.assertFalse(sa["installed_in_chatgpt"])
            with zipfile.ZipFile(a) as z:
                self.assertIn("SKILL.md",z.namelist())
                self.assertIn("references/PERMISSIONS.md",z.namelist())
            p=directory/"plugin.zip"
            info=build(ROOT,p,"plugin")
            self.assertFalse(info["remote_permission_granted"])
            with zipfile.ZipFile(p) as z:
                manifest=json.loads(z.read("plugin.json"))
                self.assertEqual(manifest["name"],"windows-bridge-agent")
                self.assertEqual(manifest["extensions"]["com.openai"]["onboardingSkill"],"./skills/setup/SKILL.md")
                self.assertIn("skills/windows-bridge/SKILL.md",z.namelist())

if __name__=="__main__":
    unittest.main()
