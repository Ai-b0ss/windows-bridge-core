# P0 — Detached process identity and safe session recovery

## Why PID alone is unsafe

Windows recycles process IDs. The previous `recover_detached_sessions()` admitted
any live PID found in `detached_sessions.json`. After a Bridge crash/restart, the
original process could have exited and the same number been assigned to a
completely unrelated process. The recovered `DetachedProcessStub` could then
be represented as task-owned, potentially leading to incorrect process status
or a termination attempt directed at the wrong PID.

## Implemented source changes

- `ff_win_process_identity.process_creation_token(pid)` reads Windows process
  creation FILETIME using read-only `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`
  and `GetProcessTimes`. Win32 HANDLE widths and function prototypes are
  defined explicitly. Returns `None` if unavailable.
- A detached record is written only when the exact process creation token can
  be obtained and its log path is inside the expected task-owned log directory.
  No record is created if PID ownership cannot be proven.
- Recovery requires **both** positive PID and exact matching creation FILETIME;
  it also requires the expected per-session log filename and an existing
  non-symlink file. Legacy records containing only PID fail closed rather than
  being silently promoted to the new authority model.
- A recovered `DetachedProcessStub.poll()` checks PID **and** creation token
  every time. Thus even a process that dies *after* recovery cannot remain
  attached to an unrelated process receiving the recycled PID.
- Suspicious, corrupted, legacy and stale records are excluded from the
  recovered session registry and do not cause any process to be terminated.
  Other owner processes, files and Windows Desktop are not accessed by the
  test.

## Evidence and test boundary

On the authorized Windows development PC, real read-only `GetProcessTimes`
returned a stable creation token for the probe Python process. The wrong
token, legacy PID-only record and unexpected log path were each denied.
The positive case saved the token via the real
`save_detached_session()` function and recovered a live session tied only
to that same test process and its own disposable empty log. The isolated
temporary directory is deleted on test exit.

Automated:
- `tests/test_process_identity.py` checks invalid PID/token rejection,
  unavailable identity failure and actual Windows self FILETIME stability.
- `tests/integration/detached_identity_probe.py` runs a new, isolated
  Python process on the public Windows GitHub-hosted runner. It never starts
  Excel, an AI model or a GUI, and never terminates a process.

**Compatibility consideration:** existing saved detached sessions created by
older Bridge versions will not automatically reattach after source upgrade
because they lack a process creation token. This is a deliberate fail-closed
security change. It does not kill the underlying process or delete user
content. Avoid hot-replacing a live Bridge without assessing active detached
sessions and planning rollback.

## Still unfinished

This is a *process identity* test, not proof of full conversation/task
continuation across a real Bridge restart. The legacy
`cua_session_continuation.py` launches successor agents using browser surfaces
and is a different, UI-facing mechanism; it is not suitable evidence for
headless session persistence or owner chat permission by itself.

Required next gates: actual safe Bridge restart acceptance in a disposable
environment, persistent output reconciliation, independent task postconditions,
host-attested ChatGPT grants, and new-chat skill activation.

## Master-plan continuation — 25 October 2026

The candidate now incorporates current Core main, preserving the separate
lost-ACK crash and agent-workflow discovery gates. Restore rejects symlinks
**before** path resolution, Windows reparse points (including junctions),
hardlinked logs, missing logs, invalid session IDs and mismatched filenames.
Querying an exited process with a retained Windows handle no longer reports
that process as live; overflowing DWORD PIDs are rejected.

`tests/integration/detached_restart_smoke.py` is the new real Windows gate:
start an isolated current Bridge via loopback; durably launch one bounded
PowerShell task in a temporary directory; kill only that Bridge; start another
Bridge on the same temporary root; recover the same PID/session; repeat the
same durable request; independently verify one file append; reconcile output
before and after restart; release the task and remove owned resources.
This gate must actually pass on Windows before its behavior is called verified.

Local Linux regression: 111 tests, 109 passed and 2 Windows-only skips.
Windows CI evidence is recorded in the PR after execution, never inferred from
these portable tests.

Remaining boundaries: this is a synthetic task, not AI conversation recovery,
ChatGPT-host permission integration, or full reboot acceptance. Process-scope
ownership for interactive input is in-memory and is not newly granted by this
restore. Restored output replays from the beginning of its log, not a persisted
client cursor. Checking paths does not constitute an OS sandbox against a
concurrent same-account attacker. The legacy PID-based termination path still
requires a separate handle-bound race review; PID birth checks alone are not
a proof of race-free tree termination. No active user installation is changed.

## Retained process reference and accurate exit status

The next master-plan candidate retains a read-only Windows process HANDLE after
birth-token verification. Polling waits on this exact kernel object and reads
its actual exit code, including nonzero failure and exit 259. A reused numeric
PID is never substituted for the retained object. A failed observation returns
`exit_code=null, exit_code_known=false`, rather than a fabricated successful 0.

Session termination now uses Popen's retained HANDLE for fresh processes and
an identity-verified PROCESS_TERMINATE handle for restored processes. Verification
and TerminateProcess use the same handle. No taskkill /PID lookup is performed
after that check. Existing RPC authorization remains enforced. These operations
explicitly report `termination_scope=owned_root_process` and
`descendant_cleanup_verified=false`; this is not yet a verified tree-cleanup
implementation. No user-owned process is touched by its test suite.

Tests cover changed-token termination denial, retained-handle exit 37, actual
exit 259, Windows termination of only the test's own child, query failures,
handle release, and real isolated Bridge restart whose detached fixture exits
37. Windows evidence must be recorded in the PR before acceptance.

Primary Windows contracts:
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess
- https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess
- https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process
