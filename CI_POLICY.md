# Continuous integration policy (public Bridge Core)

**Canonical development repository:** `Ai-b0ss/windows-bridge-core` (`main`).

## Cost & runner safety policy

- Standard GitHub-hosted `windows-latest` and `ubuntu-latest` runners are **free** for public repositories under [GitHub's Actions runner policy](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/choose-the-runner-for-a-job).
- Do not use billed larger runners or paid private minutes for routine open-source Core CI.
- **Never** attach a personal self-hosted Windows machine as a runner on this public repository (untrusted fork PRs could execute arbitrary code).
- All third-party GitHub Actions in `.github/workflows/*.yml` must be pinned to full 40-character commit SHAs with minimal `permissions` (`contents: read` by default).
- The legacy private repository retains historical configuration and private transport state; never mirror its `.git` history, hostnames, paths, tokens, or operational logs here.

## Active GitHub Actions workflows

1. **`.github/workflows/ci.yml` (`Safe public core CI`)** — runs on `push` to `main` and `pull_request`:
   - Compiles all Python modules, parses PowerShell scripts, verifies `release-manifest.json` against Git LF blobs (`test_manifest_matches_git.py`), runs the unit/contract test suite (`ubuntu-latest` + `windows-latest`), and checks that no vendored browser/ML binary directories or secret patterns exist in the tree.
2. **`.github/workflows/candidate-install.yml` (`Verified candidate package and installed RPC`)** — runs on `push` to `main` and `pull_request`:
   - Downloads the SHA-pinned base vendor archive (`v2026.10.24-remote-beta2`), builds a candidate Full Core ZIP via `tools/build_portable_release.py` from the exact commit under test, installs it cleanly on `windows-latest` (`install.ps1 -NoStartup -Transport Local`), and runs `tests/integration/installed_package_smoke.py` over loopback RPC.
3. **`.github/workflows/prelogin-recovery.yml` (`Transport and Prelogin Recovery CI`)** — runs on `push` to `main` and `pull_request`:
   - Executes Node.js unit and fault-injection suites for `tools/prelogin-recovery` (`test-supervisor.mjs`) and `tools/cf-flight-controller` (`test-flight-controller.mjs`) on both `ubuntu-latest` and `windows-latest`.
4. **`.github/workflows/windows-bridge-local-safety.yml` (`Windows Bridge Local Safety`)** — runs on `push` to `main` and `pull_request`:
   - Verifies local safety boundaries, durable `Stop` latch behavior, and permission/authority contracts on `windows-latest` and `ubuntu-latest`.
5. **`.github/workflows/portable-release-smoke.yml` (`Published release clean Windows smoke`)** — manual `workflow_dispatch` (`tag` + `sha256`):
   - Downloads an **already published GitHub Release ZIP**, enforces its exact SHA-256, runs a clean isolated install on `windows-latest`, verifies loopback-only listening (`127.0.0.1`) and `installed_package_smoke.py`, and cleans up all test processes.

## Provenance, pinned vendor base & current preferred release

- **Clean initial public commit:** `200a50ec1592b3731d307838dd370a57cd1383c9`.
- **Immutable vendor binary asset source (keep permanently):** [`v2026.10.24-remote-beta2`](https://github.com/Ai-b0ss/windows-bridge-core/releases/tag/v2026.10.24-remote-beta2) (`Windows-Bridge-Full-Core-Remote-20261024-v2.zip`, SHA-256 `46e43217fe6cace1f7a55c8aa00afba694fd03926c276565671a7566cee0d540`) supplies the three SHA-locked vendor archives (`python-3.13.9-embed-amd64.zip`, `node-v22.14.0-win-x64.zip`, `gh_2.101.0_windows_amd64.zip`) used by `tools/build_portable_release.py` and `candidate-install.yml`.
- **Current preferred Full Core release (`Latest`):** [`v2026.11.16-full-core`](https://github.com/Ai-b0ss/windows-bridge-core/releases/tag/v2026.11.16-full-core) — bundles the complete audited `main` runtime (WinSock zero-drop socket handover, durable `Stop`, cold rollback & independent watchdog, GitHub outbox recovery, per-window grants, and optional offline addon installer `ADDONS.cmd`), accompanied by `Windows-Bridge-ChatGPT-Skill.zip`, `Windows-Bridge-ChatGPT-Plugin.zip`, and `SHA256SUMS.txt`.

## Verification boundaries & open acceptance queue

Passing GitHub-hosted CI proves source integrity, unit/contract behavior, deterministic packaging, and isolated runner installation; it **does not** substitute for physical multi-device hardware pairing, interactive UAC elevation, GPU inference, or live ChatGPT host UI trials. Those gates remain tracked openly:

- [#4 — Real second-device pairing, consent and remote round-trip](https://github.com/Ai-b0ss/windows-bridge-core/issues/4) (`P0`, `hardware-gate`)
- [#6 — Optional browser/vision addons without bloating 62 MB Full Core](https://github.com/Ai-b0ss/windows-bridge-core/issues/6) (`P1`, `addon-gate`)
- [#7 — CLI/API-first Windows automation routing with native hidden UI fallback](https://github.com/Ai-b0ss/windows-bridge-core/issues/7) (`P1`, `routing`)
- [#14 — Prove Windows Bridge Skill installation and automatic selection in a NEW ChatGPT chat](https://github.com/Ai-b0ss/windows-bridge-core/issues/14) (`P0`, `host-ui-gate`)
- [#16 — Reconcile live/source/ZIP parity and prove task-capable Cursor/Antigravity/Office routes](https://github.com/Ai-b0ss/windows-bridge-core/issues/16) (`P0`, `parity-gate`)

Resolved items closed with CI and runtime evidence include [#5](https://github.com/Ai-b0ss/windows-bridge-core/issues/5) (scoped signed approvals / permission broker foundation) and [#105](https://github.com/Ai-b0ss/windows-bridge-core/issues/105) (`WinError 10054` socket handover under concurrent load, resolved via PR [#106](https://github.com/Ai-b0ss/windows-bridge-core/pull/106)).
