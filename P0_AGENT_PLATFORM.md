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


## Bounded Cursor and Antigravity CLI contract probes

`task_preflight(verify_cli_contract=true)` can now inspect exact known vendor CLI entrypoints with bounded `--version`/`--help` and optional sanitized Cursor `status`. It does **not** execute a model or approve new costs. On the tested Windows owner PC, Cursor Agent is signed in with headless print/plan flags; Antigravity `agy` 1.4.7 exposes headless/sandbox flags, while its account eligibility remains unverified. Unit checks explicitly reject a misleading `Not logged in` positive match and a false `task_compatibility=compatible` promotion from help syntax alone.

Details and official documentation: [P0_VENDOR_CLI_CONTRACTS.md](P0_VENDOR_CLI_CONTRACTS.md).

## Actual hidden Excel COM execution

The owner-authorized Windows PC has a registered Microsoft Excel.Application COM server. A new isolated acceptance harness creates an *owned invisible* Excel process when no other Excel instance is running; writes two values (20, 22) to a new temporary workbook; asks real Excel to calculate a SUM formula; saves only a temporary XLSX; independently reads its actual OOXML ZIP and formula cached value (=42); and cleans up its own workbook, EXCEL.EXE PID and temp data. The first ad hoc run succeeded but exposed a DateTime cleanup conversion bug; the reusable script fixes this and **passed end-to-end on the actual Windows PC**, exit code 0.

Public tests/integration/excel_com_smoke.ps1 and tests/integration/excel_com_verify_ooxml.py are now run from public CI. On clean GitHub-hosted Windows without Excel COM they explicitly SKIP; they must never pretend a skipped live Excel trial is a PASS. When installed, any live Excel session belonging to the owner also causes an explicit SKIP instead of attaching or mutating it. Independent OOXML regression tests are always run.

This verifies **programmatic Excel cell/formula/save** operations in a hidden process, NOT Copilot chat in Excel, login/licensing for Office AI, UIA fallback, or an arbitrary user workbook modification. Official COM SaveAs documentation: https://learn.microsoft.com/en-us/office/vba/api/excel.workbook.saveas .

## Read-only Excel COM registration in task_preflight

The existing CuaBridgeControlPlane supports opt-in verify_office_com=true for Excel tasks. This is a bounded Windows registry read of Excel.Application/CLSID/LocalServer32; it never calls CoCreateInstance, launches EXCEL.EXE, reads user documents, or falsely reports task success. When registration and executable are present, the next step is to prove an authorized owned hidden COM workbook and its postcondition. Other applications cannot turn on the Excel COM probe through an unrelated app request.

## Durable request recovery and isolated journals

RequestJournal keeps a committed command fingerprint before dispatch, deduplicates repeated keys, rejects changed payloads and preserves tombstones. Explicit FF_BRIDGE_ROOT instances now keep their request journal in the isolated root while installed non-override deployments retain the legacy journal path. 89 local unit tests and actual durable_call RPC deduplication support this behavior; a full live process-restart acceptance test remains outstanding. [Precise recovery contract](P0_DURABLE_TASK_RECOVERY.md).


## Detached process PID reuse prevention

Detached sessions now bind both Windows PID and kernel creation FILETIME before saving and after reattaching. A recycled PID cannot be treated as the task-owned process after restart; old PID-only records fail closed, as do missing or redirected log paths. Tests run real Windows read-only process identity against the test Python PID only. See [P0_DETACHED_SESSION_IDENTITY.md](P0_DETACHED_SESSION_IDENTITY.md).
## New-chat agent discovery via existing MCP
Read-only `agent_workflows` RPC and `capabilities.agent_workflows` expose the core task lifecycle without requiring a standalone ChatGPT Skill; this is not a host installation or proof of automatic tool selection. [Proof and eligibility](P0_AGENT_WORKFLOW_DISCOVERY.md).

## Master-plan Stage 0 / recovery continuation — 25 October 2026

PR [#25](https://github.com/Ai-b0ss/windows-bridge-core/pull/25) was merged as
`a4274ef280fd7d92f84a1593763d035374af60d6`. Its exact candidate passed
[public Windows CI](https://github.com/Ai-b0ss/windows-bridge-core/actions/runs/40193793205):
111 unit tests (one optional cryptography dependency skip), 11 isolated RPC
checks, real Windows creation FILETIME validation, detached Bridge crash/restart
with output reconciliation and independently verified single-effect durable
replay, plus the existing hard-crash lost-ACK test. Excel was explicitly skipped
because the hosted runner has no Excel. The previous detached PowerShell launch
returned exit 0 without running the fixture; hidden-console startup corrects it.
No installed user Bridge or published ZIP was upgraded by this merge.

Stage 0 inventory now includes the actual executor `ff_win_v3_agent.py`, process
identity, journal, RPC scope guard, durable recovery and MCP workflow modules.
Previously these could differ while the inventory reported equality for its
smaller module list. The tool identifies the exact input ZIP with SHA-256 and
size, rejects duplicate members, excessive uncompressed module sizes, empty or
duplicate selections, and names outside the explicit module allowlist.

Inventory compares **installed files on disk**. It does not inspect an active
Windows PID or attest that the process loaded those bytes. Every report now
explicitly returns `running_process_verified=false`; the historical `live_*`
keys remain compatibility aliases, with clearer `all_installed_*` summaries.
Source commit, package hash, installed disk files and actual running process
remain separate evidence. Complete WB-00/public #16 acceptance still requires
an authorized exact-device process/loaded-source check and release/deploy parity.

## First complete bounded task: read-only Excel cell

The public candidate runtime now supports **one explicit application-level real task**
through the same canonical `CuaBridgeControlPlane`, `ControlRouter`, and Excel
COM adapter as ordinary `computer_use.act`. It is not a generic self-driving
agent or Copilot/AI assistant call.

1. Attach an already-open, authorized Excel workbook via
   `computer_use(command="attach",surface_kind="app",app="Excel")`; retain
   its server-issued `surface_id`. No model call, visible launch, new workbook
   or new paid entitlement is authorized by this step.
2. Invoke:
   ```json
   {
     "command": "task_execute", "app": "Excel", "task": "excel.cells",
     "operation": "cell.read", "surface_id": "<registered surface>",
     "agent_id": "your-agent-id", "task_id": "your-task-id",
     "action_args": {"sheet": "Sheet1", "address": "A3"}
   }
   ```
   The server accepts only this **read-only, background-safe, COM-backed**
   operation. It runs a real action through the existing route, checks the
   cell and reads it **again** through COM, requiring two consistent results
   before marking this limited task `COMPLETED`. An optional `expected_value`
   can also assert the value externally. It never calls
   a model, changes an Excel cell, takes foreground input or grants
   authorization via `approved=true`.
3. Close the **owned Bridge surface** with
   `computer_use(command="close",surface_id=<same id>)`. This releases only
   the surface; it does not close the pre-existing user workbook or Excel.
   The caller owns surface cleanup, not the target process.

Two consistent fresh COM reads, even when a supplied expectation matches, are **not**
independent saved-file verification or proof of Excel Copilot operation.
`expected_value` is optional because a user may not know a cell's value.
No unverified UI/CLI fallback,
arbitrary app operation, write, or purchased model inference is allowed through
this first task executor. Mutations will require separate durable requests,
trusted authority where needed, and independent persisted postconditions.

Evidence: `tests/integration/excel_task_com_rpc_smoke.py` runs on actual
Windows/Excel in a separate `FF_BRIDGE_ROOT`, creates its **own hidden temporary
Excel workbook**, performs this RPC task and checks the independently saved
XLSX with openpyxl. It tests forged-consent denial, expected-value mismatch,
scope cleanup, and preservation of the owned Excel instance. A clean CI machine
without Office reports `SKIP`; it does not magically prove Excel compatibility.

### Read a bounded Excel range (real task, no known values needed)

The same `task_execute` path supports `operation="range.read"` with
`action_args={"sheet":"Sheet1","address":"A1:C10"}`, returning a rectangular
two-dimensional list. A range must have two valid cell endpoints in increasing
row/column order, **at most 256 cells, 32 columns and 256 rows**. Both live COM
reads must agree on shape, scalar types and every cell. Total returned scalar
text is bounded. Any unexpected, oversized, malformed, changing or
non-background-safe result fails closed; no UI fallback, writes or AI/model calls
are performed.

Owner Windows acceptance additionally reads a genuine three-row formula table
A1:A3 (`[[20],[22],[42]]`) through authenticated isolated Bridge RPC and
independently checks the separately saved .xlsx. The CI runner without Office
reports an explicit SKIP rather than claiming native Excel proof.

## First real headless AI task: Antigravity subscription baseline (27 Oct 2026)

Unlike `task_preflight`, this operation **calls a real model**, consuming
the user's existing Antigravity baseline quota. It is a genuine new capability
not provided by the previous CLI inventory. The route is *strictly limited*
to one pre-existing official `agy` executable, a pinned
`gemini-3.8-flash-medium` model and a new ephemeral Bridge-owned workspace.
It is not a universal Cursor/Antigravity automation framework.

Use the authenticated existing `computer_use` RPC, with:
```json
{
  "command": "task_execute",
  "app": "Antigravity",
  "task": "antigravity.assistant",
  "operation": "headless.answer",
  "agent_id": "agent-example",
  "task_id": "task-example",
  "context": "Project facts for this request only",
  "prompt": "Answer a question using context.txt in the current workspace"
}
```
An optional exact `expected_response` allows a narrow result postcondition
to be checked. Without it, the model's answer is returned with
`state=OUTCOME_UNKNOWN`, **not falsely certified as complete**. A successful
vendor exit code alone does not verify semantic correctness.

Payment/permission boundaries: the Bridge examines the existing local
Antigravity settings and fails closed when `useG1Credits` is enabled or
`modelProvider` selects an external API-key provider. It does **not** write
the account settings, install the CLI, switch paid features on, purchase
credits, invoke `--dangerously-skip-permissions`, or inherit raw API-key
environment variables. It pins the model, passes an owned context only,
closes stdin, runs with `--sandbox`, binds the subprocess and descendants to
a real Windows Job Object, then checks the ephemeral files have not changed
before deleting the workspace. Neither text from private CLI diagnostics nor
account metadata is returned.

These checks prevent known additional-credit fallbacks but **cannot guarantee
the vendor's actual billing**; baseline rate-limited quota is consumed.
The Bridge does not yet independently verify arbitrary semantic outcomes,
account limits, external broker descendants or a hostile native-process
escape from the vendor's sandbox. Never present the task as a paid API, an
owner-approved GUI action, file-editing automation or universal AI agent.

**Real Windows evidence:** `tests/integration/antigravity_baseline_task_smoke.py`
is an explicitly opted-in integration test (`FF_ENABLE_AGY_FREE_BASELINE_SMOKE=1`)
that performs the actual model call through a fresh authenticated loopback
Bridge. It asks Antigravity to read a random, ephemeral file marker that was
unpredictable to the model. The independently checked answer matched; the
workspace was empty after cleanup. GitHub-hosted CI runs the deterministic
security/unit suite, not a paid or quota-consuming model test.

## Durable recovery for existing multi-stage assistant_task (27 October 2026)

**Problem fixed:** the installed Bridge already had a genuine
`AssistantWorkflow.run` able to operate an application's assistant through
native/APP_CDP routes and verify a final artifact, but the **per-stage** record
was transient. The outer RPC request journal can correctly refuse a replayed
request after an ACK failure, yet cannot tell the owner which stage last passed
and which effect may still be in flight.

The existing execution path now records each `assistant_task` stage durably
into `FF_BRIDGE_ROOT/state/assistant-checkpoints/assistant-step-checkpoints.sqlite3`:

- Reserve exact stable `agent_id/task_id` *after* plan preflight but before
  any stage begins. Atomic uniqueness survives a new RPC request key or process
  restart. Different agent/task scopes remain separate.
- Commit `DISPATCHING(stage/index)` **before** each existing assistant action.
  Commit `VERIFIED(stage/index)` only after that step's existing verified
  postcondition. After the final independently verified artifact stage, mark
  `COMPLETED`.
- On an error, leave `OUTCOME_UNKNOWN`. If the Bridge process is killed,
  `DISPATCHING` survives SQLite restart; no automatic Send/Accept/Save replay.
  A separate `computer_use(command="assistant_task_status",agent_id=...,
  task_id=...)` RPC reports only the stage, count, state and uncertainty. It
  does **not** issue a model request or touch the desktop.
- Never persist prompt, reply, UI selector, window name, owner path or file
  content to this ledger. The request fingerprint itself is stored only as a
  SHA-256 digest. Never reveal it in status. No record is silently pruned:
  capacity exhaustion fails closed rather than losing replay tombstones.

This is a **recovery visibility/safety improvement to an existing working
executor**, NOT newly implemented Cursor, Excel Copilot or native assistant
functionality. It does not automatically resume an interrupted mutation:
external postcondition reconciliation and trusted owner approval are still
required before any new effects. The user may continue through an explicitly
verified new task, but the same task scope cannot silently resend a prompt.

Acceptance:
- `tests/test_assistant_step_checkpoint.py`: injected fake I/O exercises
  **the real `AssistantWorkflow.run` sequence**, durable SQLite, complete,
  failure after a simulated Send, second request-key denial, concurrent agent
  reservation, and absence of sensitive prompt bytes in SQLite.
- `tests/integration/assistant_step_checkpoint_restart_smoke.py`: starts a
  **real separate Windows Bridge**, seeds a simulated effect and a stage
  `DISPATCHING(send)`, queries status over authenticated RPC, terminates only
  its own Bridge, starts another process using the same isolated state root,
  confirms identical stage and that Send cannot be replayed.
- `tests/integration/isolated_rpc_smoke.py`: read-only status and malformed
  request are checked through real authenticated loopback RPC.

The restart smoke uses a simulated non-idempotent file append; it does **not**
claim that a real Cursor/Antigravity chat was interrupted, nor that task-level
reconciliation of actual external assistant state is complete. Working
production Bridge stays untouched until an explicit safe release cutover.

## Read-only final artifact recovery after lost assistant ACK

Once the original `assistant_task` has durably verified **every mutation**
including `save`, the process may crash before the *final read-only* artifact
verification completes. The owner/agent can now use:

```json
{
  "command": "assistant_task_reconcile",
  "agent_id": "original-agent-id",
  "task_id": "original-task-id",
  "app": "Cursor",
  "steps": ["the exact original full structured step objects"],
  "path": "original task-owned artifact path",
  "artifact_root": "original approved artifact root",
  "expected_sha256": "original expected artifact digest"
}
```

All original fields/steps must be supplied **identically** except the command
name. This is a contract sketch; the real `steps` payload is the original
structured stage list, not a string. The Bridge checks the original request
SHA-256 against its durable checkpoint and accepts reconciliation **only**
when the saved workflow had already verified every preceding step, last
verified stage `save`, and the pending stage is exactly `verify_artifact`.
It invokes the **existing** `AssistantWorkflow.step(verify_artifact)`, which
performs independent file SHA/Office artifact verification with path scope and
symlink/junction checks. It never opens an assistant, sends a message,
types, applies edits or saves a file. Wrong digest, altered plan or still
uncertain Send is denied. Successful validation commits `COMPLETED`
atomically and returns `reconciled_without_replay=true`.

The stage-specific status remains read-only under
`computer_use(command="assistant_task_status",agent_id=...,task_id=...)`.
This is **not general automatic recovery**: an ambiguous Send/Accept/Save
remains blocked pending application-specific independent effect
reconciliation. The installed Windows acceptance verifies an actual separate
Bridge restart, then a real authenticated reconciliation RPC against a
*simulated already-saved workflow* and a genuinely persisted owned file.
Do not claim this test sent a real Cursor model prompt.

