from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
SKILL=ROOT/"skills/windows-bridge/SKILL.md"


class TestWindowsBridgeSkillSource(unittest.TestCase):
    def test_skill_has_standard_frontmatter_and_new_chat_triggers(self):
        text=SKILL.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("---\nname: windows-bridge\n"))
        for phrase in ("Cursor", "Antigravity", "computer agent", "device_status", "programmatic_plan", "plan_action"):
            self.assertIn(phrase,text)
        for phrase in ("not proof that this skill has been installed",
                       "trusted permission receipt", "independently verify", "clean"):
            self.assertIn(phrase.lower(),text.lower())

    def test_reference_bundle_and_no_embedded_machine_identifier(self):
        root=SKILL.parent
        for name in ("API.md","PERMISSIONS.md","APP_ROUTES.md","TROUBLESHOOTING.md"):
            self.assertTrue((root/"references"/name).is_file())
        content="\n".join(f.read_text(encoding="utf-8") for f in root.rglob("*.md"))
        self.assertNotIn("WIN-2LK",content)
        self.assertNotIn("C:\\Users\\user",content)
        self.assertNotIn("ghp_",content)
        self.assertNotIn("approved=true as authority",content.lower())


if __name__=="__main__":
    unittest.main()
