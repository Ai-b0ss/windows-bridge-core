"""Decision-gate acceptance: no model, GUI, payment or fake route promotion."""
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime/bridge-v3"))

from cua_router import task_orchestration_gate, TASK_LIFECYCLE
from cua_bridge_v3 import CuaBridgeControlPlane


class TestTaskOrchestrationGate(unittest.TestCase):
    def test_unknown_app_discovers_before_any_execution(self):
        result = task_orchestration_gate("unseen-app", "do the required work", {})
        self.assertEqual(result["current_state"], "DISCOVERING")
        self.assertEqual(result["next_probe"], "DISCOVER_OFFICIAL_AND_OWNED_HIDDEN_INTERFACES")
        self.assertIsNone(result["app_family"])
        self.assertFalse(result["guards"]["execution_allowed"])
        self.assertFalse(result["visible_last_resort_eligible"])
        self.assertEqual(result["lifecycle"][0], "TASK_CREATED")
        self.assertEqual(result["lifecycle"][-1], "OUTCOME_UNKNOWN")

    def test_spoofed_cli_candidate_cannot_become_task_compatible(self):
        programmatic = {"candidates": [{
            "path": r"C:\Users\owner\secret-key.txt",
            "health": "healthy", "verified": True,
            "task_compatibility": "compatible",
            "authentication_token": "SHOULD_NOT_APPEAR",
        }]}
        decision = task_orchestration_gate("Cursor", "cursor.assistant", programmatic)
        self.assertEqual(decision["next_probe"], "RESEARCH_AND_PIN_CANDIDATE_TASK_INTERFACE")
        self.assertEqual(decision["route_candidates"][0]["state"], "UNKNOWN")
        self.assertFalse(decision["guards"]["task_compatible_route_verified"])
        self.assertFalse(decision["guards"]["paid_inference_allowed"])
        self.assertNotIn("secret-key", str(decision))
        self.assertNotIn("SHOULD_NOT_APPEAR", str(decision))

    def test_official_help_and_login_still_do_not_verify_model_entitlement(self):
        decision = task_orchestration_gate("Cursor", "cursor.assistant",
            {"candidates": [{"command": "agent"}]}, cli_contract={
                "path_verified": True, "help_checked": True, "task_completed": False,
                "model_called": False, "service_auth": "authenticated",
                "quota_and_pricing_verified": True, "account": "private@example.com",
            })
        self.assertEqual(decision["next_probe"], "PROBE_VENDOR_TASK_OPERATION_WITH_PROVEN_ENTITLEMENT")
        self.assertFalse(decision["cost_policy"]["inference_entitlement_verified"])
        self.assertFalse(decision["guards"]["execution_allowed"])
        self.assertNotIn("private@example.com", str(decision))

    def test_false_or_partial_vendor_contract_fails_closed(self):
        for contract in (
            {"path_verified": True, "help_checked": False},
            {"path_verified": True, "help_checked": True, "task_completed": True},
            {"path_verified": True, "help_checked": True, "model_called": True},
            {"path_verified": "true", "help_checked": True},
        ):
            with self.subTest(contract=contract):
                decision = task_orchestration_gate("Antigravity", "antigravity.assistant",
                                                   {}, cli_contract=contract)
                self.assertFalse(any(x["route"] == "PROGRAMMATIC_VENDOR_CLI"
                                     for x in decision["route_candidates"]))
                self.assertFalse(decision["guards"]["execution_allowed"])

    def test_excel_com_is_not_copilot_but_cells_offer_real_probe(self):
        office = {"registration_found": True, "registered_executable_present": True,
                  "excel_process_started": False, "task_completed": False}
        for task, expected in (
            ("excel.cells", "PROBE_OWNED_EXCEL_COM_AND_VERIFY_SAVED_WORKBOOK"),
            ("excel.assistant", "RESEARCH_COPILOT_ENTITLEMENT_API_OR_OWNED_HIDDEN_PANEL"),
        ):
            with self.subTest(task=task):
                result = task_orchestration_gate("Excel", task, {}, office_com=office)
                self.assertEqual(result["next_probe"], expected)
                self.assertEqual(result["route_candidates"][0]["route"], "PROGRAMMATIC_EXCEL_COM")
                self.assertFalse(result["guards"]["execution_allowed"])
                self.assertFalse(result["background_routes_exhausted"])

    def test_known_native_semantic_route_is_not_entire_task_verified(self):
        result = task_orchestration_gate("Word", "word.assistant", {},
            semantic_preflight={"selected_route": "UIA_PATTERN", "verified_result": True})
        self.assertEqual(result["next_probe"], "PROBE_BACKGROUND_OPERATION_AND_POSTCONDITION")
        self.assertFalse(result["guards"]["external_postcondition_verified"])
        self.assertFalse(result["route_exhaustion_proven"])
        self.assertFalse(result["visible_last_resort_eligible"])

    def test_physical_and_fake_unknown_route_cannot_be_promoted(self):
        for name in ("PHYSICAL_INPUT", "APP_FAKE", "", None):
            with self.subTest(name=name):
                decision = task_orchestration_gate("Cursor", "cursor.edit_files", {},
                    semantic_preflight={"selected_route": name})
                self.assertFalse(decision["route_candidates"])
                self.assertFalse(decision["guards"]["foreground_input_allowed"])

    def test_no_trusted_consent_or_paid_override_through_kwargs(self):
        decision = task_orchestration_gate("Antigravity", "antigravity.assistant", {
            "approved": True, "paid_allowed": True, "foreground_allowed": True,
            "candidates": [{"command": "agy", "verified": True}],
        })
        self.assertFalse(decision["owner_chat_grant_attested"])
        self.assertFalse(decision["cost_policy"]["purchase_authorized"])
        self.assertFalse(decision["visible_last_resort_eligible"])
        self.assertEqual(decision["current_state"], "PROBING")

    def test_actual_preflight_entrypoint_includes_same_router_decision(self):
        class FakePlane(CuaBridgeControlPlane):
            def __init__(self):
                self.calls = []
            def dispatch(self, args):
                self.calls.append(dict(args))
                if args["command"] == "programmatic_plan":
                    return {"candidates":[{"command":"agent","verified":True}],
                            "preferred_task_route":None,
                            "task_compatibility":"unknown"}
                raise AssertionError("effect dispatch attempted")
        plane = FakePlane()
        decision = plane._task_preflight({
            "app": "Cursor", "task": "cursor.assistant",
            "probe_versions": True, "approved": True, "physical_input_allowed": True,
        })
        self.assertEqual([x["command"] for x in plane.calls], ["programmatic_plan"])
        self.assertFalse(plane.calls[0]["probe_versions"])
        self.assertEqual(decision["orchestration"]["schema"], "ff-task-orchestration-gate-v1")
        self.assertFalse(decision["orchestration"]["guards"]["execution_allowed"])
        self.assertFalse(decision["action_executed"])


if __name__ == "__main__":
    unittest.main()
