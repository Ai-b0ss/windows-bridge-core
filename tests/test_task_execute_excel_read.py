"""Real task-execution boundary for a pre-attached, read-only Excel COM cell."""
import pathlib
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime/bridge-v3"))
from cua_bridge_v3 import CuaBridgeControlPlane, CuaBridgeError


class FakeExecutorPlane(CuaBridgeControlPlane):
    def __init__(self):
        self.calls = []
        self.values = [42.0, 42.0]
        self.route = "APP_API"
        self.report_verified = True
        self.actual_executor = "excel_com"
        self.preflight_route = "APP_API"
        self.handle = SimpleNamespace(
            executor="excel_com", app="Excel",
            capabilities={
                "cell.read": {"mutation": False, "background_safe": True, "desktop_exclusive": False},
                "range.read": {"mutation": False, "background_safe": True, "desktop_exclusive": False},
            },
        )
    def _surface(self, args):
        return "owned-surface", {
            "kind": "app", "app_api_handle": self.handle,
        }
    def dispatch(self, args):
        self.calls.append(("preflight", dict(args)))
        if args.get("command") != "plan_action":
            raise AssertionError("unexpected dispatch")
        return {"selected_route": self.preflight_route, "action_executed": False}
    def _act(self, args):
        self.calls.append(("act", dict(args)))
        value = self.values.pop(0)
        return {
            "route": self.route, "verified": self.report_verified,
            "physical_input_used": False,
            "action_result": {
                "app_api_executor": self.actual_executor,
                "sheet": "Sheet1", "address": "A3", "value": value,
            },
        }


class TestRealReadOnlyTaskExecution(unittest.TestCase):
    def setUp(self):
        self.plane = FakeExecutorPlane()
        self.args = {
            "command": "task_execute", "app": "Excel",
            "task": "excel.cells", "operation": "cell.read",
            "agent_id": "verified-agent", "task_id": "job-one",
            "surface_id": "owned-surface",
            "action_args": {"sheet": "Sheet1", "address": "A3"},
            "expected_value": 42,
        }

    def execute(self, **update):
        return self.plane.dispatch_request({**self.args, **update}) if hasattr(self.plane, "dispatch_request") else (
            self.plane._task_execute({**self.args, **update})
        )

    def test_true_two_pass_read_completes_with_narrow_evidence(self):
        receipt = self.execute()
        self.assertEqual(receipt["state"], "COMPLETED")
        self.assertEqual(receipt["value"], 42.0)
        self.assertTrue(receipt["verified"])
        self.assertEqual(receipt["orchestration"]["gate_schema"], "ff-task-orchestration-gate-v1")
        self.assertEqual(receipt["orchestration"]["selected_next_probe"],
                         "PROBE_BACKGROUND_OPERATION_AND_POSTCONDITION")
        self.assertFalse(receipt["orchestration"]["visible_last_resort_used"])
        self.assertEqual(receipt["orchestration"]["actual_stages"][-1], "COMPLETED")
        self.assertEqual(receipt["verification"]["distinct_read_calls"], 2)
        self.assertFalse(receipt["verification"]["independent_saved_artifact_verified"])
        self.assertFalse(receipt["execution"]["model_called"])
        self.assertFalse(receipt["execution"]["file_or_workbook_mutated"])
        self.assertEqual([name for name, args in self.plane.calls],
                         ["preflight", "act", "act"])
        for _, args in self.plane.calls:
            self.assertEqual(args["policy"], {
                "background_required": True,
                "foreground_allowed": False,
                "physical_input_allowed": False,
                "require_verified": True,
            })

    def test_read_unknown_user_value_is_useful_and_freshly_verified(self):
        request = dict(self.args)
        request.pop("expected_value")
        receipt = self.plane._task_execute(request)
        self.assertEqual(receipt["value"], 42.0)
        self.assertTrue(receipt["verified"])
        self.assertTrue(receipt["verification"]["two_fresh_reads_consistent"])
        self.assertFalse(receipt["verification"]["user_expectation_supplied"])
        self.assertIsNone(receipt["verification"]["postcondition_matches_expected"])
        self.assertEqual([x[0] for x in self.plane.calls], ["preflight", "act", "act"])

    def test_read_unknown_user_value_fails_if_two_live_observations_change(self):
        request = dict(self.args)
        request.pop("expected_value")
        self.plane.values = [42, 99]
        with self.assertRaises(CuaBridgeError) as caught:
            self.plane._task_execute(request)
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_INCONSISTENT_LIVE_READS")

    def test_advertised_capability_without_real_route_fails_before_action(self):
        self.plane.preflight_route = None
        with self.assertRaises(CuaBridgeError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_VERIFIED_BACKGROUND_ROUTE_REQUIRED")
        self.assertEqual(len(self.plane.calls), 1)

    def test_changed_value_between_live_reads_fails_closed(self):
        self.plane.values = [42, 99]
        with self.assertRaises(CuaBridgeError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_POSTCONDITION_FAILED")
        self.assertEqual(len(self.plane.calls), 3)

    def test_false_receipt_and_wrong_executor_fail_closed(self):
        for attr, value in (("report_verified", False), ("route", "UIA_PATTERN"),
                            ("actual_executor", "winapp_cli")):
            with self.subTest(attr=attr):
                self.setUp()
                setattr(self.plane, attr, value)
                with self.assertRaises(CuaBridgeError) as caught:
                    self.execute()
                self.assertEqual(caught.exception.code, "TASK_EXECUTE_READBACK_UNVERIFIED")

    def test_physical_and_paid_and_mutation_flags_are_rejected(self):
        for key, value in (("approved", True), ("allow_gui", True),
                           ("foreground_allowed", True), ("paid_inference", True),
                           ("policy", {"background_required": False})):
            with self.subTest(key=key):
                self.setUp()
                with self.assertRaises(CuaBridgeError) as caught:
                    self.execute(**{key: value})
                self.assertEqual(caught.exception.code, "TASK_EXECUTE_ARGUMENT_UNSUPPORTED")
                self.assertFalse(self.plane.calls)

    def test_unowned_or_invalid_request_cannot_touch_any_cell(self):
        for key, value in (("agent_id", ""), ("task_id", None),
                           ("app", "Cursor"), ("task", "excel.assistant"),
                           ("operation", "cell.write"),
                           ("action_args", {"sheet": "Sheet1", "address": "A3", "value": 99}),
                           ("expected_value", {"secret": "not scalar"})):
            with self.subTest(key=key):
                self.setUp()
                with self.assertRaises(CuaBridgeError):
                    self.execute(**{key: value})
                self.assertFalse(self.plane.calls)

    def test_range_read_unknown_values_returns_verified_matrix(self):
        request = dict(self.args)
        request.pop("expected_value")
        request["operation"] = "range.read"
        request["action_args"] = {"sheet": "Sheet1", "address": "A1:A3"}
        self.plane.values = [[[20], [22], [42]], [[20], [22], [42]]]
        original = self.plane._act
        def range_read(payload):
            result = original(payload)
            result["action_result"]["address"] = "A1:A3"
            return result
        self.plane._act = range_read
        receipt = self.plane._task_execute(request)
        self.assertEqual(receipt["operation"], "range.read")
        self.assertEqual(receipt["value"], [[20], [22], [42]])
        self.assertEqual(receipt["verification"]["kind"], "two_fresh_excel_com_range_reads")
        self.assertFalse(receipt["verification"]["user_expectation_supplied"])
        self.assertEqual([v[0] for v in self.plane.calls], ["preflight", "act", "act"])

    def test_range_read_rejects_large_reversed_and_malformed_ranges_without_effect(self):
        for address in ("A1:AZ20", "A1:A300", "D4:A1", "A1", "A1:ZZ99999"):
            with self.subTest(address=address):
                self.setUp()
                request = dict(self.args)
                request["operation"] = "range.read"
                request["action_args"] = {"sheet": "Sheet1", "address": address}
                request.pop("expected_value")
                with self.assertRaises(CuaBridgeError):
                    self.plane._task_execute(request)
                self.assertFalse(self.plane.calls)

    def test_range_read_rejects_nested_corruption_and_inconsistent_values(self):
        request = dict(self.args)
        request.pop("expected_value")
        request["operation"] = "range.read"
        request["action_args"] = {"sheet": "Sheet1", "address": "A1:B2"}
        original = self.plane._act
        def range_read(payload):
            result = original(payload)
            result["action_result"]["address"] = "A1:B2"
            return result
        self.plane._act = range_read
        self.plane.values = [
            [[1, 2], [3, 4]],
            [[1, 2], [3, 99]],
        ]
        with self.assertRaises(CuaBridgeError) as caught:
            self.plane._task_execute(request)
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_INCONSISTENT_LIVE_READS")
        self.setUp()
        original = self.plane._act
        def malformed(payload):
            result = original(payload)
            result["action_result"]["address"] = "A1:B2"
            return result
        self.plane._act = malformed
        self.plane.values = [ [[1,2]], [[1,2]] ]
        with self.assertRaises(CuaBridgeError) as caught:
            self.plane._task_execute(request)
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_READBACK_UNVERIFIED")

    def test_semantic_fallback_is_never_silently_promoted(self):
        self.plane.handle.executor = "winapp_cli"
        with self.assertRaises(CuaBridgeError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_EXCEL_COM_SURFACE_REQUIRED")
        self.assertFalse(self.plane.calls)

    def test_known_capability_must_be_explicitly_read_only(self):
        self.plane.handle.capabilities["cell.read"]["mutation"] = True
        with self.assertRaises(CuaBridgeError) as caught:
            self.execute()
        self.assertEqual(caught.exception.code, "TASK_EXECUTE_READONLY_CAPABILITY_UNVERIFIED")
        self.assertFalse(self.plane.calls)


if __name__ == "__main__":
    unittest.main()
