# Windows Bridge agent platform — P0 state (25 October 2026)

The objective is a *verified task-level agent*, not just RPC tool coverage:
requested task → device identity → programmatic discovery & suitability → hidden/semantic routes → trusted foreground consent → action → independent postcondition → recovery & task-owned cleanup.

## Evidence: source, archive and live must not be confused

Read-only tool: `tools/runtime_inventory.py` accepts an explicit source directory, exact release ZIP and installed runtime directory. It compares pinned Python modules' SHA-256 and sizes, emits **no absolute host paths or sensitive content**, and does not modify Windows.

Audited against Core Beta 3 and an owner-authorized current Windows installation, before any deployment of this P0 branch:

| Module | Public source vs live | Beta 3 ZIP vs live |
| --- | --- | --- |
| `ff_win_v3_main.py` | differs | differs |
| `ff_win_v3_security.py` | differs | differs |
| `cua_router.py` | matched **before new P0 patch** | matched |
| `cua_task_authority.py` | matched | matched |
| `cua_programmatic_discovery.py` | matched | matched |
| `cua_tool_preparation.py` | matched | matched |
| `cua_cli_first_policy.py` | missing from public | missing from ZIP; installed on live |
| `cua_hidden_desktop.py` | matched | matched |
| `cua_lifecycle.py` | matched | matched |

**Conclusion:** A public release is not the same executable as the current live system. Do not overwrite the live program or claim full parity without an explicit diff/security audit, isolated regression and rollback. The public P0 router change creates an intentional additional source-vs-archive mismatch until a *later validated release*.

## First P0 implementation: integrated no-effect preflight

- The existing `cua_router.ControlRouter.inspect()` probes existing adapters' `can_handle()`, ordered by the existing router's route priority. It **never** calls `act()`.
- Foreground/physical input is not executed or self-authorized from a caller's `approved=true`, a claimed lease, or a chat-message substring.
- Action background safety requires affirmative request-specific evidence; unknown safety is rejected, even when a route is statically background-capable.
- Exceptions produce redacted `probe_failed` receipts, not credential-bearing exception text, and do not trigger an unverified action.
- Existing `CuaBridgeControlPlane.dispatch(command="plan_action")` returns these route observations for a registered surface, using the same router/adapter objects as the real `act` path.
- The response has `action_executed=false`, `owner_authorization_verified=false`, route reasons and a next step. **This is a preliminary planning probe, not complete orchestration or proof of an operation.**
- No modification was made to the installed home Bridge for this P0 stage.

## ChatGPT skill distribution — honest state

`skills/windows-bridge/SKILL.md` plus `references/` provides a standard skill source package (triggers, device discovery, route priority, owner authority, cleanup and app examples).

**It is NOT yet shown to be installed or auto-triggered in arbitrary new ChatGPT chats.** Registration as a usable ChatGPT plugin/skill, a hosted invocation test and the new-chat acceptance trial are separate P0 gates. A GitHub file is not host registration.

## Permission Broker — already-existing code, unfinished integration

`cua_task_authority.py` already verifies signed exact-operation approvals, tracks expiring scoped grants, and serializes desktop mode transitions. **Do not weaken its signature verification.** The missing piece is a host-attested confirmation path: authenticated user intent in ChatGPT → device/task/operation/expiry receipt from a trusted integration → local trusted controller imports grant → Windows Bridge validates it. A raw tool argument or a scraped message is not that receipt.

Until the trusted host integration is proven, visible control requiring such consent must fail closed; unrelated programmatic discovery may continue with ordinary task authorization.

## Next P0 gates (not yet passed)

1. Host/plugin installation and automatic activation of this skill in a new chat.
2. Task-level suitability checks for Cursor/Antigravity/Office, beyond installed executables or `--version`.
3. Host-attested permission broker with replay, task, device, target and expiry proofs, without manual key exchange.
4. Independent end-to-end routing: programmatic first, owned hidden fallback, foreground only with trusted owner grant, actual postcondition and task-owned cleanup.
5. Exact compatibility regression against old live modules; isolate and preserve rollback. **Only after this** update the live Windows Bridge.
6. Finally repackage and update distribution/Drive with the tested exact source, not before.

References: [skill](skills/windows-bridge/SKILL.md), [remote device guide](CHATGPT-REMOTE-CONTROL.md), [CI policy](CI_POLICY.md).
