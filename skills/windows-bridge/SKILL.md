---
name: windows-bridge
description: "Use for authorized Windows-computer tasks: connect to PC, open Cursor or Antigravity, inspect installed applications, execute a computer workflow with FF Windows Bridge. Programmatic first, hidden second, ordinary desktop last after trusted approval."
---

# Windows Bridge: task-oriented computer agent skill

**Status:** Source package for a future ChatGPT plugin/skill distribution. A repository copy is **not proof that this skill has been installed, automatically invoked or authorized by the ChatGPT host.** Do not claim activation from this file alone.

## Trigger

Use when the owner requests work on an authorized Windows device (Cursor, Antigravity, Excel, browsers, system repair, or "подключись к компьютеру"). For general questions without actual computer work, do not connect.

## Mandatory agent algorithm

1. Resolve the **exact device** and owner-authorized purpose. If more than one device exists, never silently pick a wrong one. Read `device_status`, `device_ping`, `bridge_capabilities` and actual `device_info`; verify that the device is connected.
2. Verify **real deployment provenance**: public GitHub main, release archive, source checkout and the installed Windows process may be different. Use `tools/runtime_inventory.py` with the release and installed roots when available. Preserve the working installation; no overwrite before isolated smoke/rollback.
3. Run read-only capability investigation: `computer_use(command="programmatic_plan", app=<target>, task=<requested task>, probe_versions=true)` to discover CLI, API, SDK, MCP, COM, CDP and task suitability. A tool being installed or responding to `--version` is NOT proof it can complete the requested task.
4. For a registered surface, run `computer_use(command="plan_action", surface_id=<id>, operation=<operation>, policy={background_required:true})` before selecting a GUI route. This only inspects existing adapters; `action_executed=false`. Treat `ready` as suitability evidence, never the final action result.
5. Before any new dependency, verify source, license, actual task support and zero new charges or already approved entitlement. Prefer official CLI or proven OSS. Download and install only with an appropriate authorized scope and rollback; do not blindly install from search snippets.
6. Choose: **programmatic route** → owned hidden process/profile/Desktop or semantic UIA/Win32/CDP/WGC/OCR → optional verified vision → foreground desktop **only after a real trusted permission receipt**. Probe multiple applicable routes before escalating. Prefer non-focus-stealing actions.
7. A user's "I'm not home" or "you may use the visible screen" expresses consent *for the stated task*; it is NOT by itself an authenticated tool-side approval. The trusted host/controller must supply a verified device-, task-, operation-, target- and time-scoped grant. Never set `approved=true` or forge a signature; do not require the owner to manually copy cryptographic keys.
8. Execute through existing Bridge/ControlRouter paths with stable task identity, record the action and independently verify the postcondition. On timeout, first query `request_status` / reconcile effects; do not blindly retry non-idempotent actions.
9. Clean up only the task's own tabs, temporary files, profiles, sessions and processes. Restore focus/desktop when actually changed; preserve project edits and user data.
10. Report exact actual device/runtime, selected/rejected routes, costs/permissions, verified outcomes, unknowns, rollback and cleanup.

## References

- [API & device discovery](references/API.md)
- [Foreground authority and fail-closed conditions](references/PERMISSIONS.md)
- [Application-specific verification and routing](references/APP_ROUTES.md)
- [Troubleshooting and recovery](references/TROUBLESHOOTING.md)

For code development, use [public Core](../../README.md), [free CI policy](../../CI_POLICY.md) and [agent commands](../../CHATGPT-REMOTE-CONTROL.md). Keep private support logs and credentials out of public issues and CI.

## Real acceptance criterion

In a **new** chat using an actually installed/available skill, the agent receives an authorized task, discovers the correct computer, verifies a task-capable free/covered route, executes without disturbing the owner's desktop if possible, independently verifies effects and cleans up its own resources. A green static test or the existence of this Markdown file is NOT acceptance evidence.
