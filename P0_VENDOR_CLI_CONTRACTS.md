# P0 — Cursor and Antigravity vendor CLI contracts

The agent platform now distinguishes five independent claims that must **not** be conflated:

| Evidence | How collected | What it does **not** prove |
| --- | --- | --- |
| Official install-location candidate | Bounded, exact `LOCALAPPDATA/cursor-agent/agent.cmd` or `LOCALAPPDATA/agy/bin/agy.exe` | Binary publisher integrity or model entitlement |
| CLI version | Only explicit `--version`, hidden subprocess, bounded timeout | Task support |
| CLI syntax | Only `--help` with output sanitized into supported-flag booleans | The flags actually work on current plan/OS |
| Cursor login-status | Optional `agent status` only, redacted to `authenticated` / `not_authenticated` / `unknown` | Credits, model eligibility, real task execution |
| Real app task success | **NOT YET RUN** | Needs independent postcondition and known cost/entitlement |

Implementation: `runtime/bridge-v3/cua_cli_contracts.py` is called only through
`computer_use.command="task_preflight"` with `verify_cli_contract=true`.
The optional `include_auth_status=true` reads only Cursor status and never returns its raw email or organization. Ordinary `task_preflight` **runs no subprocess at all**. No prompt is passed to Cursor or Antigravity; there is no model inference, subscription usage or user-visible desktop operation in the CLI probe.

Example safe RPC body:

```json
{
  "command": "task_preflight",
  "app": "Cursor",
  "task": "Inspect project repository status without changes",
  "verify_cli_contract": true,
  "include_auth_status": true
}
```

Expected fields include `cli_contract.help_checked`, `version`, `service_auth`,
`observed_flags`, `authenticated_task_execution_verified=false`,
`quota_and_pricing_verified=false`, `model_called=false` and
`task_completed=false`. The `path_verified` field denotes a path under the expected vendor installation directory, **not** Authenticode or independent publisher signature verification.

## Observations on owner's authorized Windows host, 25 October 2026

- Cursor Agent CLI reports build version beginning `2026.10.19`, offers `--print`, `--mode`, `--output-format`, `--sandbox`, and `agent status` reports **logged in**. Identity has been intentionally omitted.
- Antigravity CLI reports version `1.4.7`, advertises `--print`, `--mode`, `--output-format` and `--sandbox`. Actual logged-in model entitlement and quota have **not** been verified.
- Neither CLI was given a prompt or used to invoke a model. Help/Version presence is only a capability contract, not a successful AI task.
- Verified official command docs: https://cursor.com/docs/cli/installation and https://antigravity.google/docs/getting-started?tab=cli . Google explicitly notes that `auto` on Windows requires sufficiently recent Windows 11 builds/sandbox; its presence in `--help` is not proof it can operate on a Windows 10 laptop.

## New regression protections

- A negative login response such as `Not logged in` cannot match the positive `Logged in` branch.
- Raw account names, paths, help text and tokens never appear in the contract response.
- User-controlled prompts, arbitrary executables, unknown applications, path redirects, path shell metacharacters and unrecognized commands are never executed.
- CLI `--help` advertising `--print` leaves `task_compatibility=unknown` until real task execution and independent verification; it cannot promote agent applicability to `compatible`.
- 71+ offline/unit regression tests and the isolated live Windows Bridge RPC smoke cover code paths; on clean CI runners without CLI installs the probe must return an honest missing candidate.

## Remaining hard gates

1. Determine Cursor/Antigravity plan entitlement, model eligibility and marginal cost from a trusted user-authorized account source, **without consuming inference tokens by assumption**.
2. Run a minimal real non-mutating model task in a disposable workspace only after the cost/approval boundary is understood; independently verify response contents and no files changed.
3. For editing operations, use an owned isolated workspace and commit/rollback, task-scoped process IDs, durable request key, before/after hashes, and independent final readback.
4. For Windows UI fallback, only after all programmatic research fails and a trusted host-attested grant exists; `--force`, `--dangerously-skip-permissions` or similar flags must not bypass that requirement.
