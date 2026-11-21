"""Check the new-chat bootstrap manifest is truthful and action-free."""
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from cua_agent_workflows import agent_workflows


class TestAgentWorkflowManifest(unittest.TestCase):
    def test_machine_readable_bootstrap_flow(self):
        data=agent_workflows()
        self.assertEqual(data["schema"],"ff-windows-agent-workflows-v1")
        keys=[x["step"] for x in data["flow"]]
        self.assertEqual(keys,[
            "identify_device","inspect_runtime","discover_task_routes",
            "probe_vendor_contract_if_needed","research_missing_programmatic_interfaces",
            "request_explicit_chat_foreground_permission_if_needed",
            "execute_authorized_task","reconcile_ambiguous_reply",
            "independent_verification_and_cleanup",
        ])
        self.assertEqual(data["flow"][2]["args"]["command"],"task_preflight")
        self.assertEqual(data["flow"][7]["bridge_op"],"request_status")
        self.assertEqual(data["flow"][6]["bridge_op"],"durable_call")
        self.assertEqual(data["flow"][4]["required_before_visible_input"], True)
        self.assertEqual(data["flow"][5]["owner_confirmation_channel"],"same_chat_text")
        self.assertIs(data["flow"][5]["visible_input_allowed_without_host_receipt"],False)

    def test_manifest_is_neither_permission_nor_task_proof(self):
        x=agent_workflows()
        for k in ("manifest_is_authorization","task_completed",
                  "skill_auto_activation_verified",
                  "owner_chat_permission_attested","foreground_input_allowed"):
            self.assertIs(x[k],False)
        self.assertTrue(x["agent_safe_no_effect_discovery"])
        self.assertIn("visible_desktop_only_with_trusted_owner_grant",x["route_preference"])
        self.assertTrue("do_not_auto_replay" in x["refusals"]["outcome_unknown"])

    def test_shared_hub_isolated_hidden_browser_default_and_mandatory_cleanup(self):
        data = agent_workflows()
        browser = data["browser_workflow"]
        self.assertEqual(browser["preferred_route"], "shared_hub.isolated_hidden_browser")
        self.assertEqual(browser["default_ops"], ["managed_browser", "private_browser"])
        self.assertEqual(browser["default_isolation"], "isolated_hidden_profile")
        self.assertTrue(browser["owner_chrome_route"]["explicit_selection_required"])
        self.assertIs(browser["owner_chrome_route"]["silent_fallback_from_hidden"], False)
        self.assertTrue(browser["background_tabs"])
        self.assertIs(browser["focus_or_foreground_input"], False)
        self.assertEqual(browser["cleanup"]["operation"], "session_close")
        self.assertEqual(
            set(browser["cleanup"]["required_on"]),
            {"success", "failure", "cancel", "timeout", "owner_stop"},
        )
        self.assertEqual(
            browser["cleanup"]["verify_fields"],
            ["cleanup_verified", "resources_retained", "browser_tabs_closed"],
        )
        self.assertTrue(browser["legacy_fallback"]["never_silently_fallback"])
        self.assertIn("shared_hub_isolated_hidden_browser", data["route_preference"])
        self.assertIn("shared_hub_browser_background", data["route_preference"])
        self.assertLess(
            data["route_preference"].index("shared_hub_isolated_hidden_browser"),
            data["route_preference"].index("shared_hub_browser_background"),
        )

    def test_advertised_preflight_is_not_assumed_to_be_live_supported(self):
        data=agent_workflows()
        self.assertIs(data["preflight_actual_rpc_support_verified"], False)
        fallback=data["unsupported_preflight_fallback"]
        self.assertIn("CUA_COMMAND_UNSUPPORTED",fallback["error_codes"])
        self.assertEqual(fallback["command"],"programmatic_plan")
        self.assertIs(fallback["probe_versions"],False)
        self.assertIs(fallback["visible_input_allowed"],False)
        gate=data["task_orchestration_gate"]
        self.assertEqual(gate["schema"],"ff-task-orchestration-gate-v1")
        self.assertIs(gate["route_candidate_is_task_proof"],False)
        self.assertIs(gate["owner_grant_attested"],False)
        self.assertIs(gate["next_probe_is_execution"],False)

    def test_installed_skill_handles_command_unsupported_without_gui(self):
        raw=(ROOT/"skills/windows-bridge/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("CUA_COMMAND_UNSUPPORTED",raw)
        self.assertIn('command="programmatic_plan"',raw)
        self.assertIn("guards.execution_allowed=false",raw)
        self.assertIn("installed-runtime drift",raw)

    def test_no_account_or_device_specific_content(self):
        raw=json.dumps(agent_workflows(),sort_keys=True,ensure_ascii=False)
        for sensitive in ("C:\\Users\\user","WIN-2LK","39073",
                          "ghp_","github_pat_","Authorization: Bearer",
                          "secret.txt","api_key"):
            self.assertNotIn(sensitive,raw)

    def test_dispatch_source_uses_exact_pure_manifest(self):
        raw=(ROOT/"runtime/bridge-v3/ff_win_v3_main.py").read_text(encoding="utf-8")
        self.assertIn('core.OPS["agent_workflows"] = lambda args: _agent_workflows()',raw)
        self.assertIn('result["agent_workflows"] = _agent_workflows()',raw)


if __name__=="__main__":
    unittest.main()
