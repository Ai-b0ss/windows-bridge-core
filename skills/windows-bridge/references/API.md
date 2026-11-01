# API & deployment contract

Inspect capabilities from the live connected Bridge; no static README proves current support.

- Device identity: `device_status`, `device_ping`, `bridge_capabilities`, `bridge_call(op="device_info", args={})`.
- Unified no-effect task investigation (newer source/runtime only): `bridge_call(op="computer_use",args={"command":"task_preflight","app":"cursor","task":"<actual task>"})`. Returns programmatic candidates, task compatibility (not guaranteed success), optional existing-surface route preflight, and explicit next steps. Never launches a model or buys an API call.
- Opt-in vendor CLI contract probe on newer runtimes: `computer_use({"command":"task_preflight","app":"Cursor","task":"<actual task>","verify_cli_contract":true,"include_auth_status":true})`. Only pinned official install-location CLI help/version/status, never model prompt. Returns sanitized booleans and `quota_and_pricing_verified=false`; see [vendor contract audit](../../../docs/design/P0_VENDOR_CLI_CONTRACTS.md).
- Older runtime fallback: `bridge_call(op="computer_use",args={"command":"programmatic_plan","app":"cursor","task":"<actual task>","probe_versions":false})`. Candidate discovery alone is not real task verification.
- Exact action plan on a registered surface (newer runtime only): `computer_use({"command":"plan_action","surface_id":"<id>","operation":"<op>","policy":{"background_required":true}})`. This NEVER executes an action.
- Existing route executor: `computer_use({"command":"act","surface_id":"<id>","operation":"<op>","action_args":{},"postcondition":{},"policy":{"background_required":true}})` only after task suitability evidence; use the live contract for required arguments.
- Owner chat permission (target model, check `capabilities.features.owner_chat_permission.enabled`): `set_desktop_mode` with `mode:"dedicated"`, `agent_id`, `task_id`, `targets:[{"hwnd":N}]` (N from `gui_list_windows`; the Bridge resolves and verifies the window) and `owner_chat_permission:{quote,apps,duration_seconds}`; then `computer_use({"command":"windows_mcp","tool":"Click|Type|Scroll|Move|Shortcut|Clipboard|MultiSelect|MultiEdit|Wait","arguments":{},"agent_id","task_id","mode_generation"})`. Read-only reports: `chat_permission_status`, `scope_report`.
- Evidence/recovery: `durable_call`, `request_status`, and relevant owner-scoped session APIs if advertised by the connected Bridge.

The `computer_use` payload uses `command`, not an arbitrary `action` key. The public GitHub source, portable ZIP, installed file and active process are distinct objects; use `tools/runtime_inventory.py`. Never hard-code a user's hostname, port, secret path or GitHub issue into a publicly distributed skill.

Read-only discovery even without standalone Skill installation: `bridge_call(op="agent_workflows",args={})` exposes the recommended task lifecycle; capabilities also contains `agent_workflows`. This is static advice, never authentication or authorization. See [agent discovery](../../../docs/design/P0_AGENT_WORKFLOW_DISCOVERY.md).
