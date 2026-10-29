# P0 — Agent workflow discovery directly from the connected MCP Bridge

## Goal

Standalone ChatGPT Skills and the connected Windows Bridge plugin are
different mechanisms. The available installed Windows Bridge MCP tools can
work even when the host does not supply a standalone Skills UI. The Bridge
now returns a **pure, read-only protocol workflow manifest** from:

```json
{"op":"agent_workflows","args":{}}
```

The same object is also returned under `capabilities.agent_workflows`;
`capabilities.features.agent_workflows_discovery=true`.

Schema: `ff-windows-agent-workflows-v1`.

## What a new agent can discover

- How to identify the exact owner-authorized computer and read current runtime
  capabilities rather than trusting a GitHub ZIP's version.
- How to call `computer_use.command=task_preflight` without actions, model
  inference, purchases, or foreground interaction.
- When an explicit, redacted Cursor/Antigravity CLI contract probe or
  Excel.Application COM registration check is suitable, and why those checks
  are not task-completion proof.
- How to preserve `agent_id`, `task_id` and a stable request key for
  `durable_call`, use `request_status` and externally reconcile unknown
  outcomes without unsafe replays.
- Why visible desktop input requires a real trusted owner grant rather than
  an agent-supplied `approved=true` or a chat quote.
- How to independently verify postconditions and clean only resources owned
  by the task.

The manifest does not return machine-specific paths, credentials, account
identities, hostnames or tokens. It is not an authority to execute effects.

## What is actually verified

In the isolated real Windows Bridge RPC smoke, the `agent_workflows` response
matches the value returned from `capabilities`. Test assertions confirm it
does not falsely mark host consent, installed skill activation, task completion
or foreground input as verified. Unit tests also check the exact route
sequence and absence of sensitive literal machine identifiers.

It is **not** yet demonstrated that ChatGPT will *select* this tool
automatically in every new chat, because model tool selection and app/skill
installation depend on the ChatGPT host configuration.

## Current ChatGPT Skills product eligibility

Per OpenAI's official [Skills in ChatGPT Help Center]
(https://help.openai.com/en/articles/20001066-skills-in-chatgpt),
standalone ChatGPT Skills are offered to eligible Business, Enterprise,
Healthcare and Edu accounts subject to workspace settings. Plus is **not**
listed among the eligible plans on this documentation page. Therefore, a
source ZIP release does not automatically make this functionality available
in a Plus user's Skills tab.

Official [Plugin Skills documentation]
(https://developers.openai.com/plugins/concepts/skills) distinguishes an
MCP server (live data and actions) from a skill (workflow instructions).
The immediate fallback for an account with the connected Windows Bridge
plugin is the server-resolved `agent_workflows` capability described above.
It improves discoverability **after** the model selects the connector,
but does not guarantee unsolicited activation.

The installed MCP connector already exposes `device_status`,
`device_ping` and `bridge_call` in this ChatGPT session. **No new
plugin installation or user permission changes** were made.

## Remaining acceptance work

1. Test a brand-new ChatGPT conversation asking for a benign Windows task
   without mentioning the internal command; observe actual connector
   selection, `agent_workflows` query and route choice.
2. If the supported ChatGPT Plugins development surface allows a connected
   custom app update, expose a first-class `task_preflight` tool with a
   task-oriented description. This requires verified app registration
   rights and may require an explicit owner-controlled plugin update.
3. Integrate host-attested owner permissions and test a real app task with
   independent postcondition, including eventual cleanup. Do not invent
   a cryptographic receipt from a model-generated chat message.
4. Assess any policy/plan change against the current official docs before
   claiming that standalone Skills can be installed.

This change is core-source only until a new release is validated and rolled
out to the active Windows Bridge. It has no effect on the old installed
binary's `capabilities` response before deployment.
