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

## P0 parity follow-up: restoring the known-app CLI-first policy

The live runtime contained a ~20 KB `cua_cli_first_policy.py` implementation that was absent from public source and all lightweight release ZIPs. It guards known application GUI entry paths and verifies exact owner-signed exceptions instead of agent-supplied booleans.

A public source integration now:
- restores that standalone policy module, after static credential-pattern inspection;
- binds policy to the existing `_computer_use` RPC dispatch, including nested workflows, and identifies known app targets through the live CUA surface registry;
- exposes explicit capability status; `plan_action` is read-only and exempt from mutation blocking;
- repairs recognition of human-facing `Cursor`, `Antigravity`, and `VS Code` display names (previously the guard primarily recognized executable names);
- retains the **stricter public** security redaction. Do not copy the less-redacted live `ff_win_v3_security.py` over public code or publish live logs.

This code still requires a clean Windows runtime smoke and release compatibility proof before deployment to an existing machine. The user-mode CLI-first policy cannot sandbox arbitrary scripts launched outside Bridge and is not a substitute for the trusted Permission Broker.
## AuthorityStore device-binding follow-up

The authority foundation now explicitly requires signed local-device binding and uses a separate `approvals_v2` table instead of trusting unbound legacy rows. Added local revocation and signed-receipt replay/wrong-device regression tests. **Host-issued chat attestation remains unimplemented**, and this source-only change has not been deployed to the currently running owner's Bridge. Details: [P0_PERMISSION_BROKER.md](P0_PERMISSION_BROKER.md).

## Unified read-only task preflight (after PR #18)

The existing `CuaBridgeControlPlane` now supports `computer_use.command="task_preflight"`. It reuses the real `programmatic_plan` discovery and optionally the already-integrated `plan_action` for an existing registered surface. It does not call a model, spend API credit, install a tool, mint a grant, or perform an adapter action.

It returns separately: **candidate availability**, **task compatibility**, **semantic route suitability**, **host authorization status** (always unverified in this read-only stage) and the next check before execution. A present CLI or `--help` is not proof of a completed task; an unknown natural-language task must not become `APP_TASK_MISMATCH`.

An isolated real Bridge v3 process on a nonstandard loopback port was exercised via authenticated RPC: ping, CLI-first capability, natural-language programmatic plan, invalid-surface rejection, unified task preflight and rejection of agent-supplied physical-input permission (**6/6 PASS**). The trial used a separate temporary root, never paid for AI inference or took over the desktop, then stopped its owned PID and removed its own temporary files. Owner's live 39073 and 39076 listeners remained healthy. This is genuine **read-only integration evidence**, not proof that an unstructured Cursor/Antigravity/Excel task was executed end-to-end.

Note that a read-only `task_preflight` request carrying `physical_input_allowed=true` is intentionally blocked by the outer Bridge policy before planning. Do **not** bypass or relax that protection to make a malicious test pass.


## Permanent independent Windows runner acceptance (real process)

`tests/integration/isolated_rpc_smoke.py` starts the **current source** `ff_win_v3_main.py` with `FF_BRIDGE_ROOT` set to a disposable Windows temp directory and a random 127.0.0.1 port. It creates an independent local RPC secret (never printed), then checks:

1. authenticated `ping` from the newly launched process;
2. CLI-first enforcement advertised in live capabilities;
3. unified no-effect `task_preflight` without GUI/model/billing;
4. rejection of an agent-supplied foreground flag;
5. rejection of unscoped `start_process`;
6. **actual** task-scoped read-only `git status` through normal Bridge process RPC, successful `read_process_output`, independent second Git verification, tracked source SHA unchanged.

`finally` terminates the owned agent PID and removes the temporary root; it has no access to operator GitHub tokens or remote transport keys. The public GitHub-hosted `windows-latest` runner now executes this acceptance alongside the unit tests on every PR and `main` push. It is a P0 proof of *one bounded free programmatic task*, not of Cursor/Antigravity/Office assistant completion, host chat consent or full fallback orchestration.
