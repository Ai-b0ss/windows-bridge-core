# Skill-first permission and the browser gap (design, 2026-10-31)

Status: skill text, design, and a first runtime slice (staged in this branch, **not deployed** to the live Bridge).

Implemented in this branch (tests in `tests/test_chat_permission.py`, `tests/test_windows_mcp_physical.py`):
- `cua_chat_permission.py`: owner chat permission policy. Off until the owner creates `state/chat-permission.json` locally. `set_desktop_mode` accepts `owner_chat_permission` (verbatim quote, apps, duration capped by the owner's max) instead of a signature. Grants and refused attempts are logged; `scope_report` and `chat_permission_status` are read-only RPCs.
- Windows-MCP `Click/Type/Scroll/Move/Shortcut/Clipboard/MultiSelect/MultiEdit/Wait` work only in `dedicated` mode for the exact agent/task/generation, and only when the foreground window is in the granted targets. `Shell`, `Registry`, `Process`, `App` stay unavailable.
- CLI-first policy treats an active dedicated grant as the exception for known apps.

- `cua_owner_activity.py`: Windows-MCP input pauses with `OWNER_ACTIVE` (retry after 2 s) while the owner uses the mouse or keyboard.
- `cua_owner_notice.py/.ps1`: always-on-top notice without focus stealing, one per task, heartbeat-driven "finished" message, Stop button that writes `state/chat-permission/stop.flag`; the next agent action then revokes the grant (`OWNER_STOPPED`). Verified visually on the owner's PC. It needs an interactive session; the session-0 Bridge instance simply shows nothing.

- The same pause, notice and Stop now wrap every path that sends visible input: Windows-MCP tools, `computer_use` physical commands and legacy `gui_mouse`/`gui_keyboard` (they route through `computer_use`), and visible launches (`_visible_input_guard`, `_owner_stop_check`).
- Journal kinds written by the Bridge: `VISIBLE_INPUT_WITHOUT_PERMISSION` (refused attempt), `OUT_OF_SCOPE_APP` (input aimed at a window outside the granted targets, refused before any input), `PERMISSION_EXPIRED` (grant ran out), `ROUTE_SEARCH_SKIPPED` (a chat grant for a task that never ran `task_preflight`/`programmatic_plan`/`plan_action`/... first; logged, not blocked). `UNAPPROVED_SEND` and `OWNER_INTERFERENCE` are not logged: the Bridge cannot see what an app sends (the Skill covers it) and interference is prevented by the `OWNER_ACTIVE` pause.
- Verified on a separate Bridge with real input: grant, click and type into Notepad (text arrived), input aimed at another Notepad window refused with nothing typed, violation logged. Known limit: each Windows-MCP call starts its own server and the first call took about 11 s.

Not yet implemented: `autoConnect` for Chrome DevTools MCP (the Playwright extension route already covers the owner's Chrome), a persistent Windows-MCP server to cut per-call latency, and detection of sending in the owner's name.

## 1. Owner's intended architecture

Two layers:

1. **Transport (MCP).** ChatGPT reaches the Bridge through Cloudflare Worker MCP (best), with GitHub and Desktop Commander as fallbacks. This layer only carries calls.
2. **Skill layer.** A personal skill tells the agent how to behave: search for programmatic routes locally and on the internet, install what is missing, and touch the visible desktop only after the owner says "да" in the chat.

The owner chose: no cryptographic per-action approval, because a safe remote signing path needs always-on hosting or a bot, and the owner does not want to lose access to the PC. Try the skill-only approach first. Add technical limits only if monitoring shows the agent leaving its scope.

Why the previous agents' signed-approval design (Windows Hello, `ff-owner-approval-v1`, `DesktopModes`, `chat_consent_*`) does not fit: the owner is often away from the PC, so a Hello prompt can never be answered. The code stays in place as an optional strict mode.

## 2. What changed in this branch

- `skills/windows-bridge/SKILL.md`: hard rule (no visible input until route search is done and the owner said yes), mandatory internet research and installation of missing routes, "unavailable alone is not enough", owner permission by chat reply or advance grant, always-forbidden list, guidance for using the desktop precisely, honest runtime-status section.
- `skills/windows-bridge/references/PERMISSIONS.md`: matching contract.
- `tests/test_skill_contract.py`: asserts the new rule text instead of the old "trusted permission receipt" wording.

## 3. The trap: detect leaving scope without blocking

Needed so the owner can decide after about a day of use whether a technical limit is required.

**Record.** Every visible-input call (`gui_mouse`, `gui_keyboard`, `gui_focus_window`, `gui_action_sequence`, `computer_use` physical commands, launches) writes an audit record that already exists in `audit.jsonl`; add fields `owner_permission_quote`, `permission_scope` (apps, expiry) and `route_search_ref` (the task's preflight id).

**Flag as a violation** (write to `state/scope-violations.jsonl`, and raise a notice in the next `capabilities` response and in the report):

| Check | Violation |
| --- | --- |
| Visible input with no recorded permission | `NO_PERMISSION_RECORDED` |
| Permission quote older than its expiry | `PERMISSION_EXPIRED` |
| Target process or window outside the permitted apps | `OUT_OF_SCOPE_APP` |
| No preflight or plan for this task before the first visible input | `ROUTE_SEARCH_SKIPPED` |

**Report.** A command `scope_report` (read-only) summarises the last 24 hours: counts per violation type and the first examples. After a day, zero violations means the skill is enough. Any violation is the signal to turn on blocking for that type, one type at a time.

**Blocking switch.** A local, non-RPC config (`state/scope-enforcement.json`) per violation type: `off` (log only, default), `block`. Turning it on later needs no new design.

Honest limit: this proves what the agent did, not that it could not do otherwise. An agent that ignores the skill can still act; the log will show it.

## 3a. Visible notice on the PC (owner request)

A small always-on-top notice, so the owner sees when the agent takes the desktop and when it stops. Must never fire falsely.

- **Fires only from the real input path.** The notice is raised by the code that actually calls `SendInput`, moves the cursor, activates a window or launches a visible window. It is never raised by preflight, snapshots, hidden desktop, UIA invoke without focus, or any read-only call. No other trigger exists, so there is nothing to misfire.
- **Once per task, not per click.** First visible action of a `task_id` shows: "Агент <agent_id> начал работу: <приложение>. Нажмите Стоп, чтобы отменить." The same notice is updated (not re-opened) while the task runs.
- **End.** After 60 s with no visible input, or when the task ends, it shows "Агент закончил" for a few seconds and closes.
- **Stop button / hotkey.** Revokes the task's permission immediately and aborts the current input lease; the next visible action is refused with a clear error. This doubles as the owner's panic switch.
- **Away mode.** If the owner has been idle for several minutes, the notice still appears (harmless) and is also written to the audit log with a timestamp, so it can be reviewed later.
- Implementation: a tiny helper process running as the owner's interactive user (the Bridge agent already has an interactive keeper) that receives events from the Bridge over a local named pipe; the Bridge never draws UI itself.

## 4. Why Claude in Chrome clicks so reliably, and what the Bridge lacks

Reading the tool interface of Claude in Chrome (no decompilation is needed or suggested), it works like this:

- It lives **inside the owner's real, signed-in Chrome** as an extension, with page access through the browser's own debugging API.
- It reads the page as an **accessibility tree where every element has a short reference id** (`ref_N`), not as pixels.
- It acts **by reference**: click a ref, set a form field by ref, scroll a ref into view. Coordinates are only a fallback after a screenshot.
- It can **find** elements by text or role, wait, and read console and network output.

The Bridge already has the right engine, but not in the right place:

- `cua_browser_playwright.mjs` already builds ARIA snapshots (`ariaSnapshot`), but runs in an **isolated profile**, so no logins, no real Google session.
- The `browser_companion` extension in `runtime/bridge-v3/browser_companion` is a stub: permissions are only `downloads` and `nativeMessaging`, and it reports `physical_input: false`. It cannot read or click anything on a page.
- So with Chrome the agent falls back to screenshots and coordinates, which is the unreliable part.

### Plan to close the gap

1. Extend the companion extension with `tabs`, `scripting`, `debugger` (or `activeTab`) permissions, limited to an allow-list of tabs the agent opened or the owner marked.
2. Add native-messaging methods mirroring the tool surface: `page.snapshot` (accessibility tree with refs), `page.find`, `page.click(ref)`, `page.type(ref,text)`, `page.set_value(ref,value)`, `page.scroll_to(ref)`, `page.screenshot`, `tab.list/open/close/navigate`.
3. Route browser tasks to it before any physical input. This keeps the owner's mouse untouched and gives the same precision.
4. Keep the Playwright isolated profile for untrusted browsing; use the companion only for the owner's signed-in sessions, with the same scope log.
5. For desktop apps without a DOM, do the same with UIA: snapshot with element ids, then `invoke`/`set_value` patterns instead of coordinates. A UIA3 sidecar already exists (`cua_native_uia3_sidecar.cs`).

## 5. Open issues

- Issue #15 (host-attested chat consent) becomes obsolete under this design and should be closed or rewritten.
- Issue #14 (skill actually loads in a new chat) is now the main risk. Mitigation: duplicate the core rule in the `agent_workflows` response so an agent that never loaded the skill still receives it.
- The runtime must still be changed to accept the chat permission; today it returns `INTERACTIVE_FOREGROUND_DISABLED`. Not done in this branch.
