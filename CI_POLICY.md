# Continuous integration policy (public Bridge Core)

**Current development destination:** This PUBLIC repository, not the legacy private history.

## Cost policy

- Standard GitHub-hosted `windows-latest` / `ubuntu-latest` runners are **free** for public repositories under GitHub's current Actions terms.
- Do not use billed larger runners or private GitHub-hosted minutes for routine open-source Core CI.
- Do not attach an owner's personal Windows self-hosted runner to untrusted public pull requests.
- The legacy private repository keeps its full original history, configuration, and sensitive transport logs. It is **not** safe to flip the old repository public. Source files can only move here via targeted content audits and an explicit allowlist, never by importing historical refs or mirroring the original `.git`.

## What runs

1. `.github/workflows/ci.yml` on PR and pushes to `main`: compile the Core Python sources, parse PowerShell, test private-pairing behavior, verify the public source contains no vendored ML/browser asset directories.
2. `.github/workflows/portable-release-smoke.yml` by manual dispatch: download an **existing published ZIP**, verify a pinned SHA-256, install on a fresh GitHub-hosted Windows runner in a separate folder without permanent startup, verify loopback-only listening and clean up test processes.
3. Extra test suites must not require secrets from the owner or the private support transport. Any tests needing real Windows hardware/UAC or an authorized remote second laptop must be recorded separately; an ordinary CI pass **does not** prove those paths.

## Operator/agent decision

- Code change in the deployable Windows Bridge Core or its installer -> issue/branch/PR **here**, wait for free public CI PASS and provide actual run URL.
- Sensitive host-specific credentials, internal logs/history or private GitHub support collaboration -> **stay PRIVATE** and use scoped manual test evidence; no public CI artifacts.
- Documentation-only change in the old private archive -> no hosted CI needed. Do not label disabled or skipped private checks as passing.
- Never send raw remote RPC command/results, VPN subscription data, GitHub tokens, or screenshots containing personal data to the PUBLIC repository or to CI logs.

## Provenance and reproducibility

- Clean initial public repo commit: `200a50ec1592b3731d307838dd370a57cd1383c9`, not a fork that exposes private history.
- [Remote Beta 2 release](https://github.com/Ai-b0ss/windows-bridge-core/releases/tag/v2026.10.24-remote-beta2) was installed on a [clean Windows runner](https://github.com/Ai-b0ss/windows-bridge-core/actions/runs/40133081227) with success.
- [Source and pairing CI](https://github.com/Ai-b0ss/windows-bridge-core/actions/runs/40133853951): success.
- GitHub's current source for public standard runner free use: https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job
