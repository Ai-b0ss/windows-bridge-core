# Independent per-window grants and short input leases

Problem: `set_desktop_mode` held ONE machine-wide `dedicated` state. An agent working in Chrome
(hwnd 67024) made a second agent in Claude Desktop (hwnd 197976) fail with `DESKTOP_MODE_BUSY`,
although the windows were different.

## Model (any Windows application: browsers, IDEs, editors, messengers, terminals, Office, desktop clients)

- **Grant** = one agent/task + exact windows (`hwnd`, `pid`, `process_start_ns` resolved and checked by the
  Bridge) + expiry + its own generation. Up to 16 grants at once. Re-granting replaces only your own.
  The owner's consent (`owner_chat_permission` or a signed approval) is checked per grant, unchanged.
- **Scope check** on every physical action: the live fingerprint of the target window must equal one of the
  agent's own stored targets. A recycled hwnd or pid, or a window of another agent, is refused
  (`DESKTOP_TARGET_OUTSIDE_SCOPE`) before anything is focused or typed.
- **Background routes** (UIA, Chrome extension, COM, hidden desktop) need no lease and run in parallel.
- **Leases** serialize only what is truly shared: `input` (physical mouse, keyboard, focus) and
  `window:<hwnd>`. A lease covers ONE action (a click, a typing burst), never a task, so nobody holds
  the desktop for a long job. Properties (`cua_resource_leases.py`, tested):
  - all-or-nothing acquisition, FIFO per resource, holders never wait while holding, so no deadlock;
  - bounded wait: `LEASE_TIMEOUT` (retry-safe) naming the holder and queue position; `lease_wait_seconds` 0-60;
  - cancellation: a revoked/expired grant or the owner's Stop ends the wait at once;
  - a runaway holder is reported to waiters (`holder_overdue`), never preempted mid-action;
  - re-entrant use by the same thread is refused (`LEASE_REENTRANT`).
- **Focus** : `target_hwnd` on a physical `windows_mcp` call names a granted window. Inside the lease the
  Bridge checks scope first and only then brings that window to the front.
- **State lock** is held only to check a grant, not for the length of an action, so one agent's action never
  blocks another agent's grant.
- **Release** (`set_desktop_mode coexist` with agent/task) ends only your own grant; without identity it is
  refused. **Owner Stop** and `revoke_all` end every grant and cancel in-flight input. Expiry is per grant.
- Old single-grant state files are read as one grant; answers keep the old shape (`mode`, `generation`, ...).

## Evidence

- `tests/test_per_window_grants.py` (19 tests): two agents with different windows, foreign window and
  generation refused, stale hwnd/pid/start refused, own-only release, owner Stop, independent expiry,
  same window granted to two agents, 16-grant limit, legacy file, action does not hold the state lock;
  leases: FIFO exclusivity, parallel on distinct windows, timeout details, cancellation, re-entrancy,
  release on error, 12 threads with overlapping resources never deadlock.
- `tests/integration/two_agents_desktop.py` (real Windows, throw-away Bridge, two Notepad windows it creates):
  both grants at once; each agent types only in its own window; a foreign window is refused without moving
  focus; two simultaneous requests are queued without interleaving; a short wait ends in `LEASE_TIMEOUT`
  naming the holder; releasing one grant leaves the other; Stop revokes all.

## Limits

- Leases live in one Bridge process. During a blue-green overlap (SEAMLESS_UPDATE.md) the old and new
  process each have their own lease table; do not run physical input from both at once.
- The physical mouse is still one mouse: actions of different agents alternate, they do not run together.
