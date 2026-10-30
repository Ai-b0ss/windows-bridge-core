# Temporary trusted Skill pilot for Claude Desktop (2026-10-30)

## Why this exists
The user explicitly opted into evaluating a short-lived trust model that does
not depend on a signed receipt for every ordinary mouse action. The existing
ChatGPT Plugin setting authorizes its tool calls, but it does not attest any
particular utterance. This is a separate risk acceptance by the owner.

## Design and limits
- **Off by default**. Local config: `state/trusted-skill-input.json`.
- Owner opt-in is bounded by `owner_opt_in_until` (Unix UTC seconds); no
  permanent bypass, and the server rejects timestamps farther than 24h away.
- **Only existing Claude Desktop** with exact validated WindowsApps executable
  identity (not the Claude Code CLI).
- Requires exact target HWND, owning PID, process birth timestamp and window
  rectangle; verifies foreground and unobscured click coordinates each time.
- **Only focus, mouse move, single left click and bounded scroll**; no keyboard,
  text entry, hotkeys, global click, process execution or automatic message
  sending via this pilot. Max 12 actions per session and 600-second session TTL.
- The same task id may reuse its valid session without repeated questions.
  Different task IDs cannot take over a live session.
- Standard `gui_mouse`, `gui_keyboard`, `computer_use`,
  `set_desktop_mode`, deletion, payments and elevated actions remain protected
  under their original policies. No Windows UAC bypass.
- Every RPC call is still included in the Bridge audit trail.
- An old UI screenshot cannot prove safety of a later click. The agent must
  independently verify control/target and postcondition, and not click a
  message-send, destructive, login, billing or privacy setting.
- The config reflects owner's choice to trust the connected agent. It is
  **not independent cryptographic evidence of a chat consent utterance**.
  Treat this as a risk-bearing experiment, not completion of issue #15.

## Enable (owner opt-in)
The local controller writes:
```json
{
  "schema":"ff-trusted-skill-input-v1",
  "enabled":true,
  "agent_id":"chatgpt",
  "purpose":"inspect_claude_usage_readonly",
  "owner_opt_in_until": 0
}
```
Replace 0 with an expiry between now and now+86400. This file is NOT a
password or a new signing key. If removed, disabled or expired, the pilot
fails closed without restarting the Bridge.

## Revoke
Set `enabled` to `false` or delete the opt-in file; the next action
fails closed. All legacy signed-approval enforcement remains in place.

## Independent verification
- `python -m unittest discover -s tests -p test_trusted_skill_input.py -v`
- `python tests/integration/isolated_rpc_smoke.py`
- `python -m unittest discover -s tests -p test_*.py`
- Installed manifest hashes, local health, no effect under disabled config.
- Real harmless navigation only after identifying the exact Claude window and
  confirming the owner-approved context, with screenshot and postcondition.
