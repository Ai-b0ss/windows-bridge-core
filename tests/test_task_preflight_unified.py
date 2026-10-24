import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from cua_bridge_v3 import CuaBridgeControlPlane,CuaBridgeError
from cua_cli_first_policy import enforce


class FakePlane(CuaBridgeControlPlane):
    def __init__(self):
        self.calls=[]
    def dispatch(self,args):
        self.calls.append(dict(args))
        if args["command"]=="programmatic_plan":
            return {
                "task":"inspect project status","task_compatibility":"unknown",
                "candidates":[{"command":"agent","verified":False,"health":"healthy"}],
                "preferred_task_route":None,
            }
        if args["command"]=="plan_action":
            return {"selected_route":"UIA_PATTERN","action_executed":False}
        raise AssertionError("Forbidden side-effecting dispatch: "+str(args["command"]))


class TestUnifiedTaskPreflight(unittest.TestCase):
    def test_default_readonly_candidate_plan(self):
        plane=FakePlane()
        result=plane._task_preflight({
            "app":"cursor","task":"inspect project status",
            "probe_versions":True,"approved":True,
            "foreground_allowed":True,"physical_input_allowed":True,
        })
        self.assertEqual([x["command"] for x in plane.calls],["programmatic_plan"])
        self.assertIs(plane.calls[0]["probe_versions"],False)
        self.assertTrue(result["has_programmatic_candidates"])
        self.assertEqual(result["task_compatibility"],"unknown")
        for key in ("action_executed","task_completed","foreground_used","model_called","billing_or_purchase_executed","owner_authorization_verified","tools_installed"):
            self.assertFalse(result[key])
        self.assertEqual(result["next_step"],"check_task_specific_cli_support_auth_and_pricing")

    def test_existing_surface_uses_existing_background_route_probe(self):
        plane=FakePlane()
        result=plane._task_preflight({
            "app":"cursor","task":"inspect project status",
            "surface_id":"owned-surface-1","operation":"set_value",
            "policy":{"background_required":False,"foreground_allowed":True,"physical_input_allowed":True},
        })
        self.assertEqual([x["command"] for x in plane.calls],["programmatic_plan","plan_action"])
        policy=plane.calls[1]["policy"]
        self.assertEqual(policy,{"background_required":True,"foreground_allowed":False,
                                 "physical_input_allowed":False,"require_verified":True})
        self.assertEqual(result["semantic_preflight"]["selected_route"],"UIA_PATTERN")
        self.assertEqual(result["next_step"],"verify_background_route_matches_task_then_act_with_postcondition")

    def test_missing_task_rejected_without_probe(self):
        plane=FakePlane()
        with self.assertRaises(CuaBridgeError) as caught:
            plane._task_preflight({"app":"cursor","task":"  "})
        self.assertEqual(caught.exception.code,"TASK_REQUIRED")
        self.assertFalse(plane.calls)

    def test_bad_surface_requires_operation(self):
        plane=FakePlane()
        with self.assertRaises(CuaBridgeError) as caught:
            plane._task_preflight({"app":"cursor","task":"read-only","surface_id":"owned"})
        self.assertEqual(caught.exception.code,"OPERATION_REQUIRED")
        self.assertFalse(any(x["command"]=="plan_action" for x in plane.calls))

    def test_control_plane_dispatch_recognizes_command(self):
        plane=CuaBridgeControlPlane.__new__(CuaBridgeControlPlane)
        with patch.object(CuaBridgeControlPlane,"_task_preflight",return_value={"schema":"ff-cua-task-preflight-v1"}) as f:
            result=plane.dispatch({"command":"task_preflight","app":"cursor","task":"read"})
        self.assertEqual(result["schema"],"ff-cua-task-preflight-v1")
        f.assert_called_once()

    def test_cli_first_allows_readonly_preflight(self):
        class Core:
            class RPCError(RuntimeError):
                pass
        enforce(Core(),"computer_use",{"command":"task_preflight","app":"Cursor","approved":True})


if __name__=="__main__":
    unittest.main()
