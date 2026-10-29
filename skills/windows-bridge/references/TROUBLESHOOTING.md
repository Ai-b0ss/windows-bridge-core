# Troubleshooting / recovery

- `DEVICE_NOT_CONNECTED`: investigate which transport is down before treating the machine as offline; do not select a different user's device.
- `CUA_COMMAND_UNSUPPORTED`: check live `computer_use.command` and the deployed version; new `plan_action` requires a new runtime and will not work on old installed Bridge.
- `NO_BACKGROUND_ROUTE`: inspect prior route attempts; research official software/API and owned hidden alternatives before requesting foreground authority.
- `OWNER_APPROVAL_VERIFIER_NOT_CONFIGURED`: incomplete trusted host/controller wiring, not authorization to mint keys or disable checks.
- `ACTION_UNVERIFIED`, `OUTCOME_UNKNOWN`, lost ACK: inspect status and actual postcondition; a non-idempotent action might have executed. Never send again without reconciliation.
- Vision dependency absent: optional PyTorch model is not required for core CLI/Win32/UIA; verify pinned addon before installation.
- Temporary session cleanup: only close specific owned process/tab/profile IDs, never all `Chrome`, `Cursor` or `PowerShell`.
- Escalation: preserve exact error code and redacted route evidence, then stop with the narrowest blocker rather than inventing success.

Request lifecycle: preserve the same durable `request_key` after an ambiguous response; query `request_status` on the exact same authorized device. `outcome_unknown` and `outcome_expired` are never automatic retry permission. See [Durable Recovery](../../../docs/design/P0_DURABLE_TASK_RECOVERY.md).


Detached process recovery: PID alone is NOT a valid task ownership proof. After restart, the new runtime requires persisted Windows process creation FILETIME and exact task-owned log path; legacy PID-only records do not reattach. If the process identity is unknown, inspect the external postcondition; never terminate an arbitrary current process with a recycled PID. See [Detached session identity contract](../../../docs/design/P0_DETACHED_SESSION_IDENTITY.md).
