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
