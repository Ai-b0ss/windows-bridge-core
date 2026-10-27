"""Small, read-only workflow discovery for new agents without host Skills.

Returned data is static protocol guidance, not an access token, permission,
action executor, or evidence that any target application is usable.
"""
from __future__ import annotations


def agent_workflows() -> dict:
    return {
        "schema": "ff-windows-agent-workflows-v1",
        "purpose": "Complete authorized Windows tasks with programmatic routes first",
        "manifest_is_authorization": False,
        "task_completed": False,
        "skill_auto_activation_verified": False,
        "owner_chat_permission_attested": False,
        "foreground_input_allowed": False,
        "agent_safe_no_effect_discovery": True,
        # The manifest is static. The connected runtime's dispatcher may be
        # an older version even when this workflow was copied forward.
        "preflight_actual_rpc_support_verified": False,
        "unsupported_preflight_fallback": {
            "error_codes": ["CUA_COMMAND_UNSUPPORTED", "UNKNOWN_COMMAND"],
            "command": "programmatic_plan",
            "probe_versions": False,
            "visible_input_allowed": False,
            "instruction": "Use the fallback on the same device without restarting production",
        },
        "task_orchestration_gate": {
            "schema": "ff-task-orchestration-gate-v1",
            "field": "orchestration",
            "route_candidate_is_task_proof": False,
            "read_only": True,
            "owner_grant_attested": False,
            "next_probe_is_execution": False,
        },
        "flow": [
            {
                "step": "identify_device",
                "action": "Use the connected Windows Bridge device_status/device_ping and read device_info",
                "requirement": "Select the exact intended owner-authorized machine, not a guessed device",
            },
            {
                "step": "inspect_runtime",
                "bridge_op": "capabilities",
                "requirement": "Check the running runtime version; public source and release ZIP may differ",
            },
            {
                "step": "discover_task_routes",
                "bridge_op": "computer_use",
                "args": {
                    "command": "task_preflight",
                    "app": "Cursor",
                    "task": "Inspect the requested workspace without modifications",
                },
                "requirement": "Read-only task/route planning, no model or user desktop",
            },
            {
                "step": "probe_vendor_contract_if_needed",
                "bridge_op": "computer_use",
                "args": {
                    "command": "task_preflight",
                    "app": "Cursor",
                    "task": "Check the supported official headless interface",
                    "verify_cli_contract": True,
                    "include_auth_status": True,
                },
                "requirement": "Only exact vendor --help/--version and redacted login status, not inference entitlement",
            },
            {
                "step": "execute_authorized_task",
                "bridge_op": "durable_call",
                "requirement": "Use a stable request_key, exact device, task_id and agent_id; check costs and signed grants separately",
            },
            {
                "step": "reconcile_ambiguous_reply",
                "bridge_op": "request_status",
                "requirement": "Do not retry a mutation with a new key when the outcome is unknown",
            },
            {
                "step": "independent_verification_and_cleanup",
                "requirement": "Verify the external postcondition and clean only task-owned files/processes; report unknown results",
            },
        ],
        "route_preference": [
            "verified_official_api_cli_sdk_mcp_com",
            "owned_hidden_background_interface",
            "semantic_uia_win32",
            "screen_capture_or_vision_after_verified_need",
            "visible_desktop_only_with_trusted_owner_grant",
        ],
        "app_examples": {
            "cursor": "Official agent CLI can be probed without an inference call; task entitlement and cost require separate proof",
            "antigravity": "Agy CLI version/help is not confirmation of model quota or successful agent execution",
            "excel": "Read-only native COM registry discovery is distinct from a real hidden workbook or Excel Copilot",
        },
        "refusals": {
            "outcome_unknown": "do_not_auto_replay; use request_status and independent postcondition",
            "owner_approval_unverified": "do_not_invent_approval_or_force_visible_desktop",
            "background_route_unproven": "research_another_programmatic_or_owned_hidden_route",
            "model_entitlement_unknown": "do_not_assume_zero_cost_or_execute_unapproved_paid_inference",
        },
        "next_release_gate": "Real app task completion, host-attested chat consent and new-chat activation remain unverified",
    }
