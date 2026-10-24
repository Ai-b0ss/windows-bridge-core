# API & deployment contract

Inspect capabilities from the live connected Bridge; no static README proves current support.

- Device identity: `device_status`, `device_ping`, `bridge_capabilities`, `bridge_call(op="device_info", args={})`.
- Main programmatic investigation: `bridge_call(op="computer_use",args={"command":"programmatic_plan","app":"cursor","task":"<actual task>","probe_versions":true})`.
- Exact action plan on a registered surface (newer runtime only): `computer_use({"command":"plan_action","surface_id":"<id>","operation":"<op>","policy":{"background_required":true}})`. This NEVER executes an action.
- Existing route executor: `computer_use({"command":"act","surface_id":"<id>","operation":"<op>","action_args":{},"postcondition":{},"policy":{"background_required":true}})` only after task suitability evidence; use the live contract for required arguments.
- Evidence/recovery: `durable_call`, `request_status`, and relevant owner-scoped session APIs if advertised by the connected Bridge.

The `computer_use` payload uses `command`, not an arbitrary `action` key. The public GitHub source, portable ZIP, installed file and active process are distinct objects; use `tools/runtime_inventory.py`. Never hard-code a user's hostname, port, secret path or GitHub issue into a publicly distributed skill.
