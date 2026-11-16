# Instructions for AI agents working on this repository

Read this before changing anything. The owner is a Russian-speaking individual who runs the Bridge on their own Windows PC and is **often away from it**; remote use is the main scenario.

## Owner decisions (binding)

1. **Trust model (2026-10-31).** A strict Skill plus the owner's own "yes" in the chat is the permission to use the visible desktop. The agent passes the owner's words to `set_desktop_mode` as `owner_chat_permission`. Do **not** add per-action signatures, Windows Hello prompts, popups that need the owner at the PC, or new approval gates as the default flow. The signed path (`ff-owner-approval-v1`) stays only as an optional strict mode. Earlier agents added such gates and made remote use impossible; do not repeat that.
2. **Guards that must stay:** off until the owner creates `state/chat-permission.json` locally (never enableable over RPC), time-boxed grants, exact window targets (`hwnd + pid + create_time`), the `OWNER_ACTIVE` pause while the owner uses the PC, the on-screen notice with a durable **Stop** button (`cua_owner_stop.py` / `stop.flag` — agents must never delete `stop.flag`), and the journal/`scope_report`. Do not weaken these.
3. **Scope of the grant:** deleting files, clearing caches and changing settings are allowed after the owner's yes. Sending a message, email or post to other people in the owner's name needs its own yes for the exact text and recipient. UAC prompts and CAPTCHAs are not bypassed; the agent stops and tells the owner.
4. **Route order:** official API/CLI/SDK/MCP/COM, then the owner's signed-in Chrome through the Playwright extension (no mouse), then UIA/Win32 without focus, then the hidden desktop, and only then the visible desktop with the owner's yes. Missing routes are researched on the web and installed (free, pinned, reversible).
5. **Language & public privacy:** Write owner-facing documentation in Russian (`docs/*_RU.md`); keep this public repository strictly free of machine hostnames, local user/drive paths, tokens, and operational logs.

## Working on the code

- One topic per branch and PR, squash-merged after all GitHub checks pass (`ci.yml`, `candidate-install.yml`, `prelogin-recovery.yml`, `windows-bridge-local-safety.yml`). Run `python -m unittest discover -s tests -p "test_*.py"` and `python tests/integration/isolated_rpc_smoke.py` first; the second starts a separate Bridge on a random port and never touches the owner's.
- When touching `tools/cf-flight-controller/` or `tools/prelogin-recovery/`, also run `node --test tools/cf-flight-controller/test-flight-controller.mjs` and `node --test tools/prelogin-recovery/test-supervisor.mjs`.
- `release-manifest.json` lists a SHA-256 for every bundled source file (`ROOT_FILES | TOOL_FILES | runtime/** | tests/**`) and must match the exact **LF** bytes Git stores. Always configure `-c core.autocrlf=false` in working checkouts and run `python tools/build_portable_release.py --repo . --refresh-source-manifest` whenever a bundled file changes; `tests/test_manifest_matches_git.py` enforces byte identity.
- Prefer small verified changes. A claim of "works" needs a real run: a unit test is not proof for anything that touches Windows input, Chrome, or the live runtime.
- After a squash merge, delete the merged feature branch only after verifying its exact `head.sha` matches the merged PR SHA and no new open PR uses it; never rely on `git branch --merged`. See `docs/REPOSITORY_MAINTENANCE_RU.md`.
- The `main` source, portable release ZIP, and installed home runtime are three distinct artifacts; do not present successful CI or a merged PR as proof of live deployment. Do not copy private transport state into this public repository.

## Deploying to the owner's PC

See `docs/OPERATOR_GUIDE_RU.md` and `docs/OPERATOR_COLD_UPGRADE_RU.md`:

- **Hot listener handover (when running runtime supports `socket_handover_v1`):** `cua_socket_transfer.py` transfers the bound WinSock listener via `WSADuplicateSocket` / `adopt_listener` (`docs/design/WINDOWS_SOCKET_HANDOVER_RU.md`) so active RPC clients do not hit `WinError 10054`, while `cua_runtime_deploy.py` manages transactional `/journal/v2` updates.
- **Cold rollout & independent watchdog (for structural/bootstrap upgrades):** capture an offline SHA-verified snapshot and standalone recovery kit via `tools/cua_cold_rollback_bundle.py`, coordinate keeper pause via `.cua-cold-maintenance.lock`, and arm `tools/cua_cold_recovery_watchdog.py` from an external directory via Task Scheduler before stopping active processes.
- **Post-deploy verification:** confirm `ping`, `capabilities`, `chat_permission_status`, `scope_report`, and run `python tools/runtime_parity.py --installed <BRIDGE_ROOT>/bridge-v3 --ref origin/main --disk` to prove byte-exact parity with `origin/main`. Never kill unrelated user apps, VPN clients, or shared keeper processes blindly.

## Where things are

- `runtime/bridge-v3/`: core RPC server (`ff_win_v3_main.py`, `ff_win_v3_agent.py`), consent & Stop latch (`cua_chat_permission.py`, `cua_owner_stop.py`, `cua_task_authority.py`), activity/notice (`cua_owner_activity.py`, `cua_owner_notice.py/.ps1`), pooled worker (`cua_windows_mcp.py`), owner Chrome (`cua_browser_*`, `owner_chrome_session.py`), detached named-Job & log-quota guard (`ff_win_detached_job.py`, `detached_log_guard.py`), hot socket transfer (`cua_socket_transfer.py`), transactional deployer (`cua_runtime_deploy.py`), and workflow discovery (`cua_agent_workflows.py`).
- `runtime/github-transport/`: private GitHub Issues/Actions transport with lease & outbox recovery.
- `tools/cf-flight-controller/`: `FlightController` + `ContextShield v0.5.1` (`12.5s` async handover, `__flight_poll`, `>20 KB` output spillover compaction, `39073 -> 39076` failover).
- `tools/cua_cold_rollback_bundle.py` & `tools/cua_cold_recovery_watchdog.py`: offline provenance-checked snapshot/kit builder and independent cold-upgrade watchdog.
- `tools/build_portable_release.py` & `tools/build_skill_plugin.py`: deterministic builders for the Full Core portable ZIP and ChatGPT Skill/Plugin ZIPs.
- `skills/windows-bridge/`: Skill instructions and references read by chat agents.
- `docs/design/` & `docs/security/`: active architecture and security specifications; `docs/archive/`: superseded historical drafts and branch cleanup manifests.
