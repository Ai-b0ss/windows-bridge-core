# Windows Bridge Full Core

**Portable Windows Bridge v3 core** for owner-authorized local Windows system administration and GUI automation.

- Download the prebuilt ZIP from [Releases](../../releases/latest), extract and run `INSTALL-FRIEND.cmd`. Do **not** run `install.ps1` directly from a source checkout: the checked-in source intentionally omits vendor binary ZIP assets. The release ZIP includes all required core assets and hash manifest.
- Runs as current Windows user, starts a **127.0.0.1-only** local agent; privileged operations require normal Windows authorization/UAC. Local bridge installation alone **does not grant remote access**.
- Core includes PowerShell/CMD, Python, process and file operations, native Windows UIA/Win32 GUI routes. Runtime code still contains optional browser/vision paths, but Playwright Chromium and the large PyTorch/OmniParser bundle are excluded from the default package.
- Browser-specific Playwright/OmniParser capabilities require separately installed dependencies. See `OPTIONAL-ADDONS.md`.
- No machine/user credentials, preconfigured VPN profiles, private transport logs, Astra project state or old repository history are included.
- The original private repository is separate. This repository starts from a **clean initial commit**.

## Usage

Install: `INSTALL-FRIEND.cmd` from a **release ZIP**. Check: `CHECK-BRIDGE.cmd`. If installation is successful, run `%LOCALAPPDATA%\FF-Windows-Bridge\START-FF.cmd` to restart.

Remote support: the device owner must explicitly pair an approved secure remote-access client/transport separately; never embed existing Cloudflare or GitHub tokens into a portable release.

## CI safety

GitHub Actions must use GitHub-hosted standard runners only. Never run untrusted fork pull requests on private self-hosted Windows machines.

This core was derived from the archived, checked source snapshot `c034e527a77b737b266c3c7df8b8521032be6f8a` and repackaged for optional heavy dependencies. The original full archive is not part of the public history.

## Optional consented remote pairing

For a **separate private GitHub transport**, see [REMOTE-PAIRING.md](REMOTE-PAIRING.md). The friend must accept the repository collaboration invitation and explicitly run `PAIR-REMOTE-SUPPORT.cmd` from a release ZIP. **Do not use the public source repository as the remote execution inbox.**

## Managing paired devices from ChatGPT

[CHATGPT-REMOTE-CONTROL.md](CHATGPT-REMOTE-CONTROL.md) documents exact device discovery, private GitHub transport command/results, owner authentication, required friend consent and safe shutdown. Optional no-token CLI: `python tools/bridge_remote_gh.py --list`.

## Public free CI and private-source separation

See [CI_POLICY.md](CI_POLICY.md) for free GitHub-hosted Windows/Linux checks, clean-release smoke runs, private repository safety and the rule against using personal Windows runners for untrusted public pull requests.

## Current lightweight release — Remote Beta 3

[Download Windows Bridge Full Core Remote Beta 3](https://github.com/Ai-b0ss/windows-bridge-core/releases/tag/v2026.10.25-remote-beta3) (61.79 MB). It includes `ADDONS.cmd` for optional offline, pinned browser/vision installs; it does not bundle the heavy binaries. Follow [OPTIONAL-ADDONS.md](OPTIONAL-ADDONS.md). The pairing flow still requires explicit consent and a private GitHub transport.

## P0: Verified agent orchestration and ChatGPT skill

Read [P0_AGENT_PLATFORM.md](P0_AGENT_PLATFORM.md) for verified three-way runtime audit, new no-effect route preflight (computer_use.command=plan_action), the [Windows Bridge Skill source](skills/windows-bridge/SKILL.md), missing host-side permission attestation and explicit acceptance gates. Skill source committed in GitHub is not proof it auto-activates in ChatGPT. The installed home Bridge is intentionally unchanged.

### P0 — Device-bound owner consent

[Permission Broker design and test status](P0_PERMISSION_BROKER.md): signed approvals bind the exact device/agent/task/action/TTL, reject legacy unbound grants and provide local revocation. This is a local authorization foundation, **not** a claim that ChatGPT host-attested consent is integrated.

### P0 — Inspect real Cursor/Antigravity CLI contracts

[Bounded and redacted CLI capability audit](P0_VENDOR_CLI_CONTRACTS.md) is implemented in `task_preflight` as an explicit opt-in. Status/Help/version checks are **not** proof of model entitlement or agent task success.

### P0 — Durable task recovery

[At-most-once request admission and unknown-outcome handling](P0_DURABLE_TASK_RECOVERY.md): actual RPC duplicate suppression; isolated test-root journals; no automatic replay after lost responses. Full live-process restart still pending.


### P0 — Detached session identity

[Windows PID reuse and detached log ownership verification](P0_DETACHED_SESSION_IDENTITY.md) prevents accidentally resuming or acting on a different process after restart.
### P0 — Agent discovery without separate Skills
[Read-only agent_workflows protocol](P0_AGENT_WORKFLOW_DISCOVERY.md) through the existing MCP Bridge and capabilities; does not imply automatic activation or permissions.
