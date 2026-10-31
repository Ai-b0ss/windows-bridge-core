# P0 — Owner approval / permission broker: secure local contract

> **Status (2026-10-31):** the default permission flow is now the owner's chat "yes" described in [SKILL_FIRST_PERMISSION.md](SKILL_FIRST_PERMISSION.md). What follows describes the optional strict signed mode and earlier work; do not rebuild it as the default.

**Status:** offline authority checks implemented and tested; **NOT** connected to a host-attested chat approval event. The user should not manually exchange cryptographic keys. Do not claim a ChatGPT confirmation is cryptographic proof until a supported trusted transport is demonstrated.

## Trust boundary

| Layer | Current responsibility | Evidence |
| --- | --- | --- |
| ChatGPT user | States permitted purpose and exact intended target | Message is intent, not a local signature |
| ChatGPT host/plugin approval | Presents confirmation and supplies a verifiable device/task/operation decision through a supported host-owned channel | **NOT INTEGRATED / no native cryptographic receipt demonstrated** |
| Trusted owner controller | Holds signing private key outside Bridge/agent/ZIP; authenticates host-issued decision before signing or provisioning | Design contract only; production issuer not yet deployed |
| Windows Bridge | Pins public RSA verifier, checks signed v1 payload, device and exact request, TTL, agent/task, nonce, atomic use limits, revocation | Implemented in `cua_task_authority.AuthorityStore`, covered by unit and wrapper tests |
| Windows OS | Enforces actual process rights, UAC and desktop isolation | Not bypassed by a chat grant |

## Changes to authority store

New stores require exact device binding on all approval records: `payload.device` (a valid local hostname/device label), covered by the owner's RSA signature or a previously trusted **LOCAL-ONLY** delegation. `AuthorityStore(device_id=...)` defaults to `platform.node()`. Current device label is **not hardware cryptographic attestation**. A later host integration should bind to an independently enrolled and authenticated instance ID instead.

A valid signed approval retains the existing `ff-owner-approval-v1` schema and signed fields, and now **must** include `device`. It also requires `agent`, `task`, `nonce`, `approval_reference`, the exact `request`, numeric `expires` (no more than one hour from provisioning), valid optional `not_before`, and a limited `uses` count.

The local controller holds the private signing material; the Bridge stores **only a public verification key** (RSA modulus `n` hexadecimal and exponent `e` decimal, normally 65537). Agent-provided `approved=true`, self-generated unsigned JSON, changed device/target, missing verifier, expired receipt and replay fail closed. The backend matches a canonical signed request digest to the requested action and consumes uses under an SQLite `BEGIN IMMEDIATE` transaction.

**Migrating old approvals:** Rather than treating legacy `approvals` rows as device-bound, the new code uses `approvals_v2`, preserving old rows but refusing to authorize from them. A user with a valid, still-active old grant would need a newly authenticated device-bound one after a future upgrade. This is an intentional compatibility/safety change. Do **not** hot-swap the live Bridge before scoped rollout and rollback testing.

**Revocation:** The trusted local controller can call `AuthorityStore.revoke(grant_id)` or the local CLI `--revoke <sha256-grant-id>`. Revocation is persisted, uses are zeroed, and a re-submitted identical receipt cannot restore them. No unrestricted remote RPC for granting or revocation was added. Local current-user code is not sandboxed from the store, as the module explicitly notes.

## What tests prove

- End-to-end in-process *RSA PKCS#1 v1.5 SHA-256* verification with an ephemeral signing key generated inside a disposable test; signature tampering rejected.
- Correct signed payload sent to a different device rejected even when verifier and SQLite backing path match.
- Request/target/agent/task mismatch, missing device, unsigned flag, expiry, replay and revocation rejected before the effect executes.
- Actual `guard_effect()` wrapper tested with an in-memory simulated operation; only exact bound grant permits a single call; permission context is reset afterward.
- Legacy unbound database rows not migrated into trusted device-bound state.
- Existing routing and packaging regression suite passes.

Tests on a mocked controller do **not** prove ChatGPT host consent, OS UAC, user awareness, or a permissioned visible screen action in real life.

## Real host integration still required

1. Identify a documented host confirmation signal delivered directly to the connected plugin server, not an arbitrary model-supplied argument or text scraped from the UI.
2. Establish who signs the exact confirmation, how the plugin authenticates the host and maps the enrolled device instance, and who holds the signing private key. No manual key copying into chat.
3. Issue a bounded decision `{device,agent,task,request,nonce,not_before,expires,uses}` from that trusted controller and return the public authorization ID to the selected task.
4. Prove on two independent devices that a receipt cannot be replayed across devices, tasks, target windows, grant expiry or revoked state; verify full owner-controlled cancellation.
5. Preserve the owner-approved scope while the task runs; avoid redundant approvals when a still-valid grant applies, but fail closed on all unknown or unverified outcomes.
6. Deploy only after isolated clean Windows CI and rollback tests.

Until the host integration exists, do not invent a chat-signed receipt or bypass signature verification. Existing nonprivileged read-only CLI/API actions remain available as appropriate under normal user authority.

Reference: [Skills/installation](../../CHATGPT-SKILL-INSTALL.md) · [P0 platform](P0_AGENT_PLATFORM.md) · [Core repo](../../README.md).
