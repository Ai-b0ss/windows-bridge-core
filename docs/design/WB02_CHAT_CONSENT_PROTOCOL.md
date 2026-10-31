# WB-02: challenge-bound ChatGPT consent protocol (2026-10-30)

> **Status (2026-10-31):** the default permission flow is now the owner's chat "yes" described in [SKILL_FIRST_PERMISSION.md](SKILL_FIRST_PERMISSION.md). What follows describes the optional strict signed mode and earlier work; do not rebuild it as the default.

## Implemented locally

The Bridge now exposes three read/permission-broker operations:
`chat_consent_prepare`, `chat_consent_status`, and `chat_consent_commit`.
A 300-second unpredictable challenge binds the exact Windows device, agent,
task, operation and canonical request SHA-256 in a durable SQLite transaction.
`commit` validates a separately signed `ff-owner-approval-v1` receipt with
`nonce=<challenge_id>`, `approval_reference=host-chat:<challenge_id>`,
one use, device match, expiry bound and exact request digest. It imports the
result into the existing `AuthorityStore`; the normal operation must then
consume the returned grant under all existing desktop mode and UI guards.

Plain chat text, an LLM-provided `approved=true`, app OAuth or an unsigned
`signed_approval` **cannot** authorize anything. Replay, expired challenges,
wrong targets, wrong user/device/task, tampering and missing verifier are denied.
Requests do not move the mouse, change desktop mode or call paid models.

## Missing for real unattended ChatGPT mouse/keyboard use

The ChatGPT-host-owned plugin transport still needs a trustworthy way to deliver
an **independently attested** owner consent receipt scoped to this exact
challenge and signed by an enrolled issuer key. Existing generic
`Windows_Bridge.bridge_call` tool arguments do not establish that event.
The host must not expose a sign-or-approve operation usable by the agent; that
would allow model-generated consent. The receipt's private signing key must be
outside the owner PC's RPC-accessible filesystem and code. Tool annotation /
`readOnlyHint` and tool-execution approval policy by themselves are not a
cryptographic host-issued receipt.

Until that upstream integration is deployed and tested, the feature flag
`chat_consent_challenge_protocol.attested_host_issuer_connected` is **false**
and visible control remains fail-closed. This release therefore does **not**
close issue #15, and it must never be presented as completed remote GUI consent.

## Verification

- Unit tests: `tests/test_chat_consent.py`
- Real isolated Windows RPC: `tests/integration/isolated_rpc_smoke.py`
- Existing owner authority tests and foreground-denial regressions
- Staged runtime-manifest, independent health check and rollback before live install

No permanent allow-all flag, local secret signing, Windows Hello bypass, copied
credentials or manual keys are involved.
