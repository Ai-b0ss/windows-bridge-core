# Durable Windows Bridge task recovery — verified behavior

The agent must not turn a transport timeout, missing ACK or crash into an
automatic replay of a non-idempotent Windows operation. RequestJournal is already
persisted in SQLite before dispatch. The P0 recovery module adds a **pure
read-only interpretation** of its outcomes: `cua_durable_recovery.py`.

| Request journal state | What is known | Safe next step |
| --- | --- | --- |
| `completed` | A response was saved. This does **not** prove an external effect succeeded. | Independently check the actual postcondition, then cleanup only owned resources |
| `outcome_unknown` | The dispatch began, but the result was never persisted. It might have committed. | Reconcile external effects; NEVER re-send automatically |
| `outcome_expired` | The response was pruned, but the key remains reserved. | External/manual reconciliation, never replay that key |
| `not_found` | No entry found under this key in this journal. | Verify device, journal instance, exact key and external history before taking new action |
| Anything else | The journal response is unrecognized. | Stop and inspect, fail closed |

All decisions return `automatic_retry_allowed=false`,
`previous_effect_independently_verified=false`,
`new_mutation_started=false`, `owner_permission_verified=false`.
Task-specific postconditions and host-attested permission still require separate
tools; this contract **does not** claim automatic reconciliation.

## Two evidence layers

The unit suite uses real disposable SQLite `RequestJournal` databases to
verify no replay on recorded response, outcome uncertainty, expired tombstone,
missing key, changed payload, invalid key and sensitive response redaction.

`tests/integration/durable_crash_smoke.py` exercises a **real hard child-process
crash**: it writes a single owned temporary effect marker, flushes it to disk,
then calls `os._exit(17)` before journaling completion. A fresh process
detects `outcome_unknown`, returns conservative recovery advice and refuses a
same-key second dispatch; the effect marker still contains exactly **one**
effect. The test uses a disposable temp root only, no owner files/GUI/paid APIs,
and runs on free public Windows CI.

## Caveats and integration

`RecoveryCoordinator(journal).plan(key)` is wired as `task_recovery_plan` in the existing Bridge RPC registry.
The server reads trusted local RequestJournal status directly: no agent-supplied
status objects, no automatic retry, and no private recorded response content.
An isolated **real authenticated RPC** test checks the new command on a
persisted completed journal entry. This is source/CI acceptance only;
the owner's existing installed Bridge is not automatically upgraded. It intentionally has no `execute` method.

The separate concurrent P0 change to choose the journal path under an
explicit isolated `FF_BRIDGE_ROOT` must be merged without losing the existing
default production journal/tombstones. In particular, never automatically move
an existing journal or reissue stale request keys on live update.

Acceptance beyond this module: evidence-backed external postcondition
verification, task-owned cleanup, crash consistency of actual app operations,
and host-attested owner permission.
