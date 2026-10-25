import pathlib
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from cua_task_routes import task_routes


class TestTaskSuitability(unittest.TestCase):
    def test_natural_language_does_not_equal_incompatible(self):
        fixtures = (
            ("cursor", "inspect project repository status without modifying it"),
            ("antigravity", "run a read-only agent status check"),
            ("excel", "read workbook metadata through COM"),
        )
        for app, task in fixtures:
            with self.subTest(app=app):
                result=task_routes(app,task,[],probe=True)
                self.assertEqual(result["task_compatibility"],"unknown")
                self.assertEqual(result["remaining_gate"],"TASK_INTENT_NEEDS_CLASSIFICATION")
                self.assertFalse(result["verified_task_support"])

    def test_unrecognized_family_is_research_not_incompatible(self):
        result=task_routes("future-unknown-app","do the authorized work",[])
        self.assertEqual(result["remaining_gate"],"APP_FAMILY_RESEARCH_REQUIRED")
        self.assertEqual(result["task_compatibility"],"unknown")

    def test_explicit_structured_task_remains_deterministic(self):
        candidate={"command":"cursor","path":"cursor.cmd","health":"healthy"}
        result=task_routes("cursor","cursor.open_workspace",[candidate])
        self.assertEqual(result["task_compatibility"],"compatible")
        self.assertEqual(result["preferred_task_route"]["command"],"cursor")
        self.assertFalse(result["verified_task_support"])

    def test_excel_com_is_not_copilot(self):
        result=task_routes("excel","excel.assistant",[],api_capabilities=("cell.read","cell.write"))
        self.assertEqual(result["task_compatibility"],"requires_ui")
        self.assertFalse(result["excel_com_covers_assistant"])

    def test_cli_help_only_proves_headless_flag_not_real_agent_task(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        candidate={"command":"agent","path":"owned-cli.cmd","health":"healthy"}
        with patch("cua_task_routes.subprocess.run",return_value=SimpleNamespace(
                returncode=0,stdout=b"Usage: Cursor agent --print --mode=ask",
                stderr=b"")):
            result=task_routes("Cursor","cursor.assistant",[candidate],probe=True)
        self.assertEqual(result["task_compatibility"],"unknown")
        self.assertIsNone(result["preferred_task_route"])
        self.assertTrue(result["routes"][0]["cli_contract_headless_supported"])
        self.assertFalse(result["verified_task_support"])

    def test_unknown_structured_capability_not_invented(self):
        result=task_routes("antigravity","antigravity.assistant",[])
        self.assertEqual(result["task_compatibility"],"unknown")
        self.assertEqual(result["remaining_gate"],"OBSERVE_APP_ASSISTANT_AND_VERIFY")
        self.assertFalse(result["verified_task_support"])


if __name__=="__main__":
    unittest.main()
