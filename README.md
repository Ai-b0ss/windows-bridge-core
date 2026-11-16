# Windows Bridge Full Core (`v3`)

**Portable, owner-authorized Windows Bridge v3** for local system administration, developer workflows, background browser automation, and bounded GUI control by AI agents.

[![Latest Verified Release](https://img.shields.io/badge/release-v2026.11.16--full--core-blue)](https://github.com/Ai-b0ss/windows-bridge-core/releases/tag/v2026.11.16-full-core)
[![Public Core CI](https://github.com/Ai-b0ss/windows-bridge-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Ai-b0ss/windows-bridge-core/actions/workflows/ci.yml)
[![Candidate Package & RPC Smoke](https://github.com/Ai-b0ss/windows-bridge-core/actions/workflows/candidate-install.yml/badge.svg)](https://github.com/Ai-b0ss/windows-bridge-core/actions/workflows/candidate-install.yml)
[![Transport & Recovery CI](https://github.com/Ai-b0ss/windows-bridge-core/actions/workflows/prelogin-recovery.yml/badge.svg)](https://github.com/Ai-b0ss/windows-bridge-core/actions/workflows/prelogin-recovery.yml)

---

## Quick Start (Portable Release ZIP)

1. Download **`Windows-Bridge-Full-Core-Remote-20261116-verified.zip`** (and verify against `SHA256SUMS.txt`) from the [**Latest Release (`v2026.11.16-full-core`)**](https://github.com/Ai-b0ss/windows-bridge-core/releases/tag/v2026.11.16-full-core).
   - *Do not run `install.ps1` directly from a raw `git clone`: the repository intentionally excludes binary vendor archives (`Python 3.13.9`, `Node.js 22.14.0`, `GitHub CLI 2.101.0`), which are assembled deterministically by `tools/build_portable_release.py`.*
2. Extract the archive and run **`INSTALL-FRIEND.cmd`** (or `powershell -ExecutionPolicy Bypass -File install.ps1`).
3. Run **`CHECK-BRIDGE.cmd`** to verify local health (`127.0.0.1:39073`). To start/restart manually: `%LOCALAPPDATA%\FF-Windows-Bridge\START-FF.cmd`.
4. Optional ChatGPT / Agent Skills: download `Windows-Bridge-ChatGPT-Skill.zip` or `Windows-Bridge-ChatGPT-Plugin.zip` from the same release and follow [`CHATGPT-SKILL-INSTALL.md`](CHATGPT-SKILL-INSTALL.md).

Local installation binds **strictly to `127.0.0.1`** under the current Windows user and **never opens remote access by itself**. Remote transports (Cloudflare Worker tunnel or private GitHub inbox) must be paired explicitly by the device owner.

---

## Key Capabilities & Architecture (`v2026.11.16-full-core`)

| Subsystem | What It Provides | Reference |
| :--- | :--- | :--- |
| **Core Loopback Runtime** (`runtime/bridge-v3/`) | PowerShell/CMD/Python execution, process & file ops, named-Job detached sessions with EOF-pipe stdin & `256 MiB` log-quota guard (`ff_win_detached_job.py`, `detached_log_guard.py`), detached ownership verification (`pid + create_time`), UIA/Win32 & hidden desktop automation, pooled `Windows-MCP` worker (`~1.4s` warm calls). | [`docs/OPERATOR_GUIDE_RU.md`](docs/OPERATOR_GUIDE_RU.md) |
| **Owner's Chrome Without Mouse** (`cua_browser_*`, `owner_chrome_session.py`) | Attaches to the owner's signed-in Chrome via the Playwright extension in an isolated agent tab (`attach -> new_tab -> find -> act -> close`) without stealing focus, mouse, or keyboard. | [`skills/windows-bridge/SKILL.md`](skills/windows-bridge/SKILL.md) |
| **Skill-First Consent & Per-Window Grants** (`cua_chat_permission.py`, `cua_task_authority.py`) | Local opt-in (`state/chat-permission.json`), verbatim chat quote binding (`owner_chat_permission`), concurrent per-window grants (`hwnd + pid + create_time`), `OWNER_ACTIVE` physical-input pause, and rotating `scope_report` audit logs. | [`docs/design/SKILL_FIRST_PERMISSION.md`](docs/design/SKILL_FIRST_PERMISSION.md), [`docs/design/PER_WINDOW_GRANTS.md`](docs/design/PER_WINDOW_GRANTS.md) |
| **Durable Owner Stop Latch** (`cua_owner_stop.py`) | Clicking **Stop** on the non-focus on-screen banner writes a persistent `stop.flag` latch across restarts that blocks desktop input and guarded effects until locally cleared by the owner. | [`docs/design/DURABLE_OWNER_STOP_RU.md`](docs/design/DURABLE_OWNER_STOP_RU.md) |
| **Zero-Drop Hot Handover & Cold Rollback** (`cua_socket_transfer.py`, `cua_runtime_deploy.py`, `tools/cua_cold_*`) | WinSock listener socket transfer (`WSADuplicateSocket` / `adopt_listener`) eliminates `WinError 10054` during live updates; transactional `/journal/v2` deployer + offline SHA-verified cold rollback bundle & external Task Scheduler watchdog with `.cua-cold-maintenance.lock` keeper coordination. | [`docs/design/WINDOWS_SOCKET_HANDOVER_RU.md`](docs/design/WINDOWS_SOCKET_HANDOVER_RU.md), [`docs/OPERATOR_COLD_UPGRADE_RU.md`](docs/OPERATOR_COLD_UPGRADE_RU.md) |
| **Cloudflare FlightController & ContextShield `v0.5.1`** (`tools/cf-flight-controller/`) | Protects calls exceeding the 20s edge timeout via `12.5s` soft async handover (`__flight_poll`), idempotent `__dedupe_key` replay suppression, automatic `39073 -> 39076` port failover, and `>20 KB` output spillover compaction. | [`docs/design/CF_FLIGHT_CONTROLLER_RU.md`](docs/design/CF_FLIGHT_CONTROLLER_RU.md) |
| **Private GitHub Transport & Prelogin Supervisor** (`runtime/github-transport/`, `tools/prelogin-recovery/`) | Private-repo GitHub Issues/Actions transport with lease & outbox crash recovery, explicit multi-device targeting, and prelogin network recovery supervisor. | [`REMOTE-PAIRING.md`](REMOTE-PAIRING.md), [`docs/GITHUB_RETRY_RECOVERY_RU.md`](docs/GITHUB_RETRY_RECOVERY_RU.md), [`tools/prelogin-recovery/README.md`](tools/prelogin-recovery/README.md) |
| **Optional Offline Addons** (`tools/optional_addons.py`) | Keeps the Full Core ZIP compact (~61.8 MB) while supporting SHA-256-pinned offline installation of Playwright Chromium and visual/OmniParser runtimes via `ADDONS.cmd`. | [`OPTIONAL-ADDONS.md`](OPTIONAL-ADDONS.md) |

---

## Three-Way Provenance Rule

`main` in this public repository, a published portable Release ZIP, and an installed runtime on a Windows PC are **three distinct artifacts** until verified:
- Merging a PR into `main` does **not** mutate published release archives or auto-deploy to any PC.
- `tools/build_portable_release.py` verifies every bundled file byte-for-byte against `git archive <HEAD>` (`core.autocrlf=false`), scans text files against credential regexes, and embeds `public_source_commit` into `release-manifest.json`.
- `python tools/runtime_parity.py --installed <BRIDGE_ROOT>/bridge-v3 --ref origin/main --disk` verifies byte-exact SHA-256 parity between `origin/main` and an installed `bridge-v3` directory without exposing file contents or local paths.

---

## Documentation Map

### Operator & Maintenance Guides
- [**Operator Guide / Руководство владельца (RU)**](docs/OPERATOR_GUIDE_RU.md) — architecture, chat consent, durable `Stop`, Chrome without mouse, hot updates, and response codes.
- [**Cold Upgrade & Watchdog / Холодное обновление (RU)**](docs/OPERATOR_COLD_UPGRADE_RU.md) — `cua_cold_rollback_bundle.py`, standalone recovery kit, `cua_cold_recovery_watchdog.py`, and `39073` / `39076` dual-port safety.
- [**Repository Maintenance / Сопровождение репозитория (RU)**](docs/REPOSITORY_MAINTENANCE_RU.md) — directory layout, branch & squash-merge rules, and artifact parity.
- [**Migration Provenance / Проверка происхождения установки (RU)**](docs/MIGRATION_PROVENANCE_RU.md) — strict `manifest.json` verification against Git objects.
- [**Instructions for AI Agents (`AGENTS.md`)**](AGENTS.md) — binding trust model, routing order, testing, and privacy rules.
- [**Continuous Integration Policy (`CI_POLICY.md`)**](CI_POLICY.md) — free GitHub-hosted runner rules, active workflows, and open acceptance queue.

### Pairing, Skills & Addons
- [**ChatGPT Skill & Plugin Packaging**](CHATGPT-SKILL-INSTALL.md)
- [**Managing Paired Devices from ChatGPT**](CHATGPT-REMOTE-CONTROL.md)
- [**Consented Private GitHub Remote Pairing**](REMOTE-PAIRING.md)
- [**Optional Browser & Vision Addons**](OPTIONAL-ADDONS.md)

### Architecture & Security Specifications (`docs/design/` & `docs/security/`)
- [`WINDOWS_SOCKET_HANDOVER_RU.md`](docs/design/WINDOWS_SOCKET_HANDOVER_RU.md) — zero-drop WinSock listener socket transfer.
- [`CF_FLIGHT_CONTROLLER_RU.md`](docs/design/CF_FLIGHT_CONTROLLER_RU.md) — async `FlightController` and `ContextShield` log spillover.
- [`DURABLE_OWNER_STOP_RU.md`](docs/design/DURABLE_OWNER_STOP_RU.md) — persistent `Stop` latch across restarts.
- [`GITHUB_OUTBOX_RECOVERY_RU.md`](docs/design/GITHUB_OUTBOX_RECOVERY_RU.md) & [`GITHUB_EXPLICIT_DEVICE_RU.md`](docs/security/GITHUB_EXPLICIT_DEVICE_RU.md) — reliable delivery and explicit device targeting in GitHub transport.
- [`SKILL_FIRST_PERMISSION.md`](docs/design/SKILL_FIRST_PERMISSION.md) & [`PER_WINDOW_GRANTS.md`](docs/design/PER_WINDOW_GRANTS.md) — trust model and per-window desktop grants.
- [`P0_AGENT_PLATFORM.md`](docs/design/P0_AGENT_PLATFORM.md), [`P0_DURABLE_TASK_RECOVERY.md`](docs/design/P0_DURABLE_TASK_RECOVERY.md), [`P0_DETACHED_SESSION_IDENTITY.md`](docs/design/P0_DETACHED_SESSION_IDENTITY.md), [`P0_JOB_SESSION_CLEANUP.md`](docs/design/P0_JOB_SESSION_CLEANUP.md), [`P0_PERMISSION_BROKER.md`](docs/design/P0_PERMISSION_BROKER.md), [`P0_VENDOR_CLI_CONTRACTS.md`](docs/design/P0_VENDOR_CLI_CONTRACTS.md), [`P0_AGENT_WORKFLOW_DISCOVERY.md`](docs/design/P0_AGENT_WORKFLOW_DISCOVERY.md), [`P0_HIDDEN_NATIVE_ACCEPTANCE.md`](docs/design/P0_HIDDEN_NATIVE_ACCEPTANCE.md).
- [**Historical Archive (`docs/archive/`)**](docs/archive/README.md) — superseded design drafts and branch cleanup manifests.

---

## Verification Boundary & Open Hardware/Host Gates

Automated CI on GitHub-hosted Windows/Linux runners verifies source compilation, unit/contract suites (`546+` Python tests + Node transport/supervisor suites), clean portable ZIP assembly, isolated `install.ps1` bootstrap, and loopback RPC smoke tests. Real hardware/account acceptance gates that require physical multi-device or host-UI trials remain tracked openly:
- [#4](https://github.com/Ai-b0ss/windows-bridge-core/issues/4) — Real second-device pairing, consent, and remote round-trip (`P0`).
- [#6](https://github.com/Ai-b0ss/windows-bridge-core/issues/6) — Optional browser/vision offline addon validation across target workloads (`P1`).
- [#7](https://github.com/Ai-b0ss/windows-bridge-core/issues/7) — CLI/API-first Windows automation routing with native hidden UI fallback (`P1`).
- [#14](https://github.com/Ai-b0ss/windows-bridge-core/issues/14) — Automatic Windows Bridge Skill selection across independent prompts in a fresh ChatGPT chat (`P0`).
- [#16](https://github.com/Ai-b0ss/windows-bridge-core/issues/16) — Three-way parity & end-to-end task-capable Cursor / Antigravity / Office acceptance (`P0`).

## Privacy & Clean Provenance

This repository starts from a clean audited initial commit (`200a50ec1592b3731d307838dd370a57cd1383c9`) and contains **no** machine hostnames, local user paths, VPN profiles, Cloudflare/GitHub tokens, or private operational logs. Never attach personal self-hosted Windows runners to public pull requests; see [`CI_POLICY.md`](CI_POLICY.md).
