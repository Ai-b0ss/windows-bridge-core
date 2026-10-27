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
        self.assertEqual(result["task_compatibility"],"unknown")
        self.assertEqual(result["remaining_gate"],"RESEARCH_ASSISTANT_API_OR_HIDDEN_AND_VERIFY")
        self.assertFalse(result["requires_visible_desktop"])
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
        self.assertEqual(result["remaining_gate"],"VERIFY_CLI_AUTH_ENTITLEMENT_AND_TASK_POSTCONDITION")
        self.assertFalse(result["verified_task_support"])

    def test_antigravity_cli_presence_is_not_negative_proof(self):
        candidate={"command":"agy","path":"agy.exe","health":"healthy"}
        result=task_routes("Antigravity","antigravity.assistant",[candidate])
        self.assertEqual(result["task_compatibility"],"unknown")
        self.assertEqual(result["routes"][0]["task_compatibility"],"unknown")
        self.assertEqual(result["routes"][0]["task_evidence"],"discovery_only")
        self.assertFalse(result["requires_visible_desktop"])
        self.assertFalse(result["no_route_proven"])
        self.assertIsNone(result["preferred_task_route"])

    def test_office_assistant_does_not_skip_unprobed_programmatic_candidate(self):
        for app, task in (("Word","word.assistant"),("PowerPoint","powerpoint.assistant"),
                          ("Excel","excel.assistant")):
            with self.subTest(app=app):
                result=task_routes(app,task,[{"command":"possible-api","health":"unprobed"}])
                self.assertEqual(result["routes"][0]["task_compatibility"],"unknown")
                self.assertEqual(result["task_compatibility"],"unknown")
                self.assertEqual(result["remaining_gate"],"RESEARCH_ASSISTANT_API_OR_HIDDEN_AND_VERIFY")
                self.assertFalse(result["requires_visible_desktop"])

    def test_cursor_agent_help_can_be_on_stderr_without_claiming_success(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        candidate={"command":"cursor-agent","path":"fixed-agent.cmd","health":"healthy"}
        with patch("cua_task_routes.subprocess.run",return_value=SimpleNamespace(
                returncode=0,stdout=b"",stderr=b"Usage: agent --print")) as run:
            result=task_routes("cursor","cursor.assistant",[candidate],probe=True)
        self.assertTrue(result["routes"][0]["cli_contract_headless_supported"])
        self.assertEqual(result["routes"][0]["task_evidence"],"cli_help_syntax_only")
        self.assertEqual(result["task_compatibility"],"unknown")
        self.assertFalse(result["verified_task_support"])
        self.assertNotIn("Usage: agent",str(result))
        self.assertEqual(run.call_args.kwargs["stdin"],__import__("subprocess").DEVNULL)

    def test_missing_cli_path_never_executes_arbitrary_probe(self):
        from unittest.mock import patch
        with patch("cua_task_routes.subprocess.run",side_effect=AssertionError("probe executed")):
            result=task_routes("Cursor","cursor.assistant",
                               [{"command":"agent","health":"healthy"}],probe=True)
        self.assertEqual(result["routes"][0]["task_compatibility"],"unknown")
        self.assertNotIn("task_probe_exit_code",result["routes"][0])

    def test_unrecognized_helper_is_not_negative_task_evidence(self):
        result=task_routes("Cursor","cursor.assistant",
                           [{"command":"cursor-helper","health":"healthy"}])
        self.assertEqual(result["routes"][0]["task_compatibility"],"unknown")
        self.assertEqual(result["routes"][0]["task_evidence"],"discovery_only")

    def test_advertised_cell_api_still_requires_real_workbook_postcondition(self):
        result=task_routes("excel","excel.cells",[],api_capabilities=("cell.read","cell.write"))
        self.assertEqual(result["task_compatibility"],"compatible")
        self.assertEqual(result["routes"][0]["task_evidence"],"advertised_cell_api_not_executed")
        self.assertFalse(result["verified_task_support"])
        self.assertEqual(result["remaining_gate"],"LOGIN_LICENCE_AND_TASK_POSTCONDITION")


if __name__=="__main__":
    unittest.main()
