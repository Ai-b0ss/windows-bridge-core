# Updating the Bridge without interrupting running work

Status: the mechanism exists and is proven in isolation (`tests/integration/seamless_handover.py`).
It can be used **starting from the first instance that contains it**. A Bridge process started
from older code cannot be updated this way and must be left running until it ends on its own.

## What blocks a live swap (facts, checked on the owner's PC, 2026-11-01)

1. **Fixed port.** Every transport (GitHub, Cloudflare path, MCP tool, keeper health check)
   calls `127.0.0.1:39073`. A second process cannot take the port from a running one:
   a plain second bind fails (WSAEADDRINUSE 10048); `SO_REUSEADDR` on both sockets succeeds,
   but Windows then gives **every** connection to the first listener until it closes.
   Measured: 40/40 to the old listener, 0 to the new; after the old one closed, 10/10 to the new,
   none refused.
2. **Sessions die with the process.** Every `start_process` child is assigned to one
   `KILL_ON_JOB_CLOSE` job (`_AGENT_JOB_HANDLE`). Stopping the Bridge kills running commands
   of every chat (builds, deploys, migrations). Detached sessions survive, normal ones do not.
3. **No drain in old code.** The only controls are `/shutdown` and killing the process; both end it.
4. Rewriting files on disk changes nothing in a running Python process. Parity on disk is not a deploy.

So for the process that is running now there is no honest zero-loss swap. Do not kill it while
other projects work through it; let it end naturally (reboot, crash, end of work), then start the
new code. Files on disk already hold the new code, so the next start loads it.

## The mechanism (new code)

- `serve --also-listen PORT` : extra check port next to the public one.
- Standby `B` starts with the same public port and its own check port. It shares the public
  port (`SO_REUSEADDR`) but the first listener keeps all traffic, so B can be tested on its
  check port with real RPCs while nothing changes for users.
- `drain {"standby_port": N}` on the old instance `A`: refused unless B answers `ping` with a
  different pid. A opens a private loopback port, records it in `state/peers.json`, finishes the
  connections already queued, then closes the public listener. From that instant B gets every
  new connection.
- B forwards `read_process_output`, `interact_with_process`, `force_terminate` for session ids it
  does not own to A's private port, so running commands keep working for the same chats.
- A leaves after it has no running session and no request in flight for the linger time
  (default 1800 s, `FF_DRAIN_LINGER_SECONDS`).
- Rollback before `drain`: kill B, nothing else changed. After `drain`: start the previous
  version as a new standby and drain B the same way.

## Proof (isolated, throw-away instances)

`python tests/integration/seamless_handover.py` (also run as a unit test): A runs a 9 s command;
B shares the port and is verified on its check port; 24 clients call the public port in a loop
while `drain` runs. Result of three consecutive runs: 2492, 2529 and 2558 requests, none lost;
traffic moved from A to B; the command's output stayed readable through B; `drain` without a
live standby is refused; A exited cleanly once idle and B kept serving.

## Not proven / open

- Requests in the kernel accept queue at the instant of close are reset. The loop closes only
  when the queue is empty (checked with `select`), but a connection arriving in that microsecond
  gap would be reset. None occurred in ~7500 requests.
- A and B overlap on the same state directory (authority/desktop-mode files use file locks,
  the request journal is SQLite). Only the isolated case (separate roots per test, one shared
  during the test) was exercised; run the first live handover when work is quiet.
- B must run in the owner's interactive session with the same rights as the keeper (start it from a
  scheduled task, not from a service session). `list_sessions` on B does not merge A's sessions.
- Windows-MCP worker, the owner notice and the owner-activity guard are per process; a grant
  stays in files, so it carries over.
