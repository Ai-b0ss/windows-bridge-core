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
