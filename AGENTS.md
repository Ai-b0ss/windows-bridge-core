# Instructions for AI agents working on this repository

Read this before changing anything. The owner is a Russian-speaking individual who runs the Bridge on their own Windows PC and is **often away from it**; remote use is the main scenario.

## Owner decisions (binding)

1. **Trust model (2026-10-31).** A strict Skill plus the owner's own "yes" in the chat is the permission to use the visible desktop. The agent passes the owner's words to `set_desktop_mode` as `owner_chat_permission`. Do **not** add per-action signatures, Windows Hello prompts, popups that need the owner at the PC, or new approval gates as the default flow. The signed path (`ff-owner-approval-v1`) stays only as an optional strict mode. Earlier agents added such gates and made remote use impossible; do not repeat that.
2. **Guards that must stay:** off until the owner creates `state/chat-permission.json` locally (never enableable over RPC), time-boxed grants, exact window targets, the `OWNER_ACTIVE` pause while the owner uses the PC, the on-screen notice with a Stop button, and the journal/`scope_report`. Do not weaken these.
3. **Scope of the grant:** deleting files, clearing caches and changing settings are allowed after the owner's yes. Sending a message, email or post to other people in the owner's name needs its own yes for the exact text and recipient. UAC prompts and CAPTCHAs are not bypassed; the agent stops and tells the owner.
4. **Route order:** official API/CLI/SDK/MCP/COM, then the owner's signed-in Chrome through the Playwright extension (no mouse), then UIA/Win32 without focus, then the hidden desktop, and only then the visible desktop with the owner's yes. Missing routes are researched on the web and installed (free, pinned, reversible).
5. Write owner-facing documentation in Russian; keep this repository free of machine names, user paths, tokens and logs.

## Working on the code

- One topic per branch and PR, squash-merged after the GitHub checks pass. Run `python -m unittest discover -s tests -p "test_*.py"` and `python tests/integration/isolated_rpc_smoke.py` first; the second starts a separate Bridge on a random port and never touches the owner's.
- `release-manifest.json` lists a SHA-256 for every bundled source file and must contain the bytes **Git stores** (LF). On a Windows checkout the working tree is CRLF, so hashing disk bytes breaks the release builder. `tests/test_manifest_matches_git.py` enforces this: `git add` your files, then hash `git show :path`.
- Prefer small verified changes. A claim of "works" needs a real run: a unit test is not proof for anything that touches Windows input, Chrome or the live runtime.

## Deploying to the owner's PC

See `docs/OPERATOR_GUIDE_RU.md`, section "Обновление и откат". In short: the installed runtime is not a git checkout; wait until the agent has been idle for about two minutes (`audit.jsonl`), back up the files to `bridge-v3/backups/<name>/` with a `ROLLBACK.txt`, copy the exact bytes of `git show <ref>:<path>`, compile with the bundled Python, kill only the interactive Bridge process (the keeper restarts it), then verify `ping`, `capabilities`, `chat_permission_status` and `scope_report`. Never stop the keeper or unrelated processes.

## Where things are

- `skills/windows-bridge/`: the Skill and its references (what the chat agent reads).
- `runtime/bridge-v3/ff_win_v3_main.py`: RPC wiring; `cua_chat_permission.py`, `cua_task_authority.py` (desktop modes), `cua_owner_activity.py`, `cua_owner_notice.py/.ps1`, `cua_windows_mcp.py` (pooled worker), `cua_browser_*` (owner Chrome), `cua_agent_workflows.py` (rules served to agents).
- `docs/design/SKILL_FIRST_PERMISSION.md`: current design and status. Other `docs/design/P0_*` and WB02 pages describe the optional strict mode and earlier work.
