# P0 — Durable task outcomes and crash-safe retry discipline

## Scope and current evidence

The **existing** `RequestJournal` stores an SQLite record and command fingerprint
*before* dispatching through the usual restricted Bridge RPC. A successful
dispatch stores its redacted response. A repeated matching `request_key` returns
the already saved result with `cached=true` and does **not** perform the
operation again. A repeated key with different command content fails with
`REQUEST_KEY_CONFLICT`. Incomplete records result in
`outcome_unknown`, `retry_safe=false`; expired responses retain tombstones
and cannot be reused as newly invented operations.

This is intentionally **at-most-once admission**, not proof that an operation
completed when the connection died. The agent must independently inspect the
postcondition before choosing a next task step.

## Important compatibility fix

Previously, even an isolated `FF_BRIDGE_ROOT` test wrote durable request
records into the user's standard `LOCALAPPDATA/FFWindowsBridge/state/request-outcomes`.
This risks mixing test keys, retained outcomes and live records.

`choose_request_journal_root()` now sends explicit `FF_BRIDGE_ROOT` runtimes
to their own `<bridge_root>/state/request-outcomes` directory. **Existing live
deployments that do not set `FF_BRIDGE_ROOT` keep precisely the same legacy
directory and all existing no-replay tombstones.** Moving live records without
a migration would be dangerous: it could permit previously issued effects to
be repeated after a software upgrade. Unexpected or relative root overrides
fail closed. No live source or state has been migrated.

## Actual behavior tested

- Unit tests: same-key successful retry across independently constructed
  `RequestJournal` objects, persisted response, changed-payload conflict,
  crashed dispatch after external effect (unknown outcome **must not replay**),
  expired-response tombstones, invalid key refusal and live-vs-isolated root.
- **Real Windows Bridge RPC on isolated loopback process:** a scoped read-only
  `git status` runs via `durable_call(op=start_process)`. Repeated calls
  with the same request key return `cached=true` and the **same session ID**
  without starting a second process. `request_status` returns completed and
  changing command for the same key is rejected. No model inference or GUI.
- The existing integration runner cleans up its temporary Bridge root after
  this smoke. It was not deployed over the owner's active Bridge.
- A full **Bridge-process restart** with live RPC recovery is **not yet
  established**. There are unit-level persisted-database/reinstantiation
  checks, but these should not be reported as a successful real server restart.

## Agent recovery algorithm

1. Select the exact owner-approved device, task and operation. Generate one
   stable `request_key` for that effect, not a fresh key on each retry.
2. Submit `durable_call` via the same restricted RPC with task/agent identity;
   record `request_key`, target, command fingerprint and expected postcondition.
3. If the connection is lost or the response is unclear, use **read-only**
   `request_status(request_key)` on the same device before any resubmission.
4. If `completed`, inspect the saved result and independently verify the
   task effect. If `outcome_unknown`, **do not replay**. Reconcile externally
   (file hash, target Git status, exact owned session/process, etc.). If the
   outcome is unresolvable, report it, rather than claim success or submit the
   same non-idempotent action with a different key.
5. Only clean up confirmed task-owned sessions, tabs and temporary files;
   never kill all processes by application name.

## Remaining gates

- Reconcile durable `start_process` sessions across an actual Bridge restart,
  without losing output or launching a second process; preserve fail-closed
  behavior on lost owner authority.
- Expose a task-level receipt tying the returned process session to its
  postcondition and time-scoped cleanup, separate from `cached` (which only
  proves no second dispatch).
- Test crashes during response storage and non-idempotent operations in an
  isolated environment. Do not simulate by modifying the live owner's state.
- Host-attested ChatGPT consent and new-chat Skill activation remain outside
  this journal's contract.

See [P0 agent platform](P0_AGENT_PLATFORM.md) and
[Windows Bridge Skill](skills/windows-bridge/SKILL.md).
