import pathlib
import sys
import unittest
from unittest.mock import patch
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))

from cua_router import ControlRouter, RoutePolicy


class Adapter:
    def __init__(self, result):
        self.result = result
        self.act_calls = 0
        self.probe_calls = 0

    def can_handle(self, request):
        self.probe_calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    def act(self, request):
        self.act_calls += 1
        raise AssertionError("preflight MUST NOT execute an action")


class TestExistingRouterPreflight(unittest.TestCase):
    def test_programmatic_path_beats_semantic_gui_without_executing(self):
        router = ControlRouter()
        cli = Adapter({"supported": True, "background_safe": True, "desktop_exclusive": False})
        gui = Adapter({"supported": True, "background_safe": True, "desktop_exclusive": False})
        router.register("APP_API", cli, background_safe=True)
        router.register("UIA_PATTERN", gui, background_safe=True)
        result = router.inspect({"operation": "set_value"}, policy=RoutePolicy(background_required=True))
        self.assertEqual(result["selected_route"], "APP_API")
        self.assertEqual(result["action_executed"], False)
        self.assertEqual(result["owner_authorization_verified"], False)
        self.assertEqual((cli.act_calls, gui.act_calls), (0, 0))
        self.assertEqual(result["next_step"], "execute_selected_route_and_verify")

    def test_unknown_background_safety_does_not_escalate(self):
        router = ControlRouter()
        gui = Adapter({"supported": True})
        router.register("UIA_PATTERN", gui, background_safe=True)
        result = router.inspect({"operation": "invoke"})
        self.assertIsNone(result["selected_route"])
        self.assertEqual(result["route_attempts"][0]["reason"], "background_safety_not_proven")
        self.assertEqual(gui.act_calls, 0)

    def test_no_agent_owned_approval_via_boolean_or_lease_claim(self):
        router = ControlRouter()
        physical = Adapter({"supported": True, "background_safe": False, "desktop_exclusive": True})
        router.register("PHYSICAL_INPUT", physical, background_safe=False, physical_input=True)
        request = {"operation": "click", "approved": True, "user_said_not_home": True}
        result = router.inspect(request, policy=RoutePolicy(
            background_required=False, foreground_allowed=True, physical_input_allowed=True),
            lease={"lease_id": "agent-self-minted"})
        self.assertIsNone(result["selected_route"])
        self.assertTrue(result["requires_verified_foreground_approval"])
        self.assertEqual(result["route_attempts"][0]["status"], "requires_verified_lease")
        self.assertEqual(physical.probe_calls, 0)
        self.assertEqual(physical.act_calls, 0)

    def test_probe_exception_fails_closed_and_next_route_is_considered(self):
        router = ControlRouter()
        a = Adapter(ValueError("secret details must not leak"))
        b = Adapter({"supported": True, "background_safe": True, "desktop_exclusive": False})
        router.register("APP_API", a, background_safe=True)
        router.register("BROWSER_CDP", b, background_safe=True)
        result = router.inspect({"operation": "read"}, policy=RoutePolicy(background_required=True))
        self.assertEqual(result["selected_route"], "BROWSER_CDP")
        self.assertEqual(result["route_attempts"][0]["status"], "probe_failed")
        self.assertNotIn("secret details", str(result))

    def test_control_plane_dispatch_plan_action_no_side_effect(self):
        from cua_bridge_v3 import CuaBridgeControlPlane
        plane = CuaBridgeControlPlane.__new__(CuaBridgeControlPlane)
        dummy = Adapter({"supported": True, "background_safe": True, "desktop_exclusive": False})
        def factory(*args):
            return dummy
        with patch.object(CuaBridgeControlPlane, "_surface", return_value=("test", {
            "kind": "app", "app_api_handle": object()
        })), patch.object(CuaBridgeControlPlane, "_surface_resource_keys", return_value=("surface",)), patch.object(
            CuaBridgeControlPlane, "_app_api_runtime", return_value=None
        ), patch("cua_bridge_v3.AppApiRouteAdapter", factory):
            result = plane.dispatch({"command": "plan_action", "operation": "set_value",
                                     "policy": {"background_required": True}})
        self.assertEqual(result["selected_route"], "APP_API")
        self.assertFalse(result["action_executed"])
        self.assertEqual(dummy.act_calls, 0)


if __name__ == "__main__":
    unittest.main()
