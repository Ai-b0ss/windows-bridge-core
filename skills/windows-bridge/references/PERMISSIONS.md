# Trusted permission-broker contract

The authenticated owner may express consent in ChatGPT, including "I'm not home" and "you may use the desktop". This establishes **intent** within the task. It is not a verifiable Bridge grant unless the host provides an authenticated receipt through a trusted integration.

Real foreground or high-impact operations must be bound to: exact device, agent identity, task identity, target fingerprint/window generation, exact allowed operation or small bounded scope, expiry, revocation and replay/idempotency record.

Existing `cua_task_authority.py` supports signed exact approvals and a trusted local-controller API. A raw agent-supplied `approved=true`, a scraped message, or a fabricated `signed_approval` is NOT authority. Never turn off its verifier to improve UX. The host-to-broker confirmation integration is a separate P0 gate.

Automatic programmatic read-only discovery is allowed in an authorized context. Do not silently perform privileged/deletion actions, purchases or screen-visible control outside the granted scope. Windows UAC remains in charge of elevation.

The P0 source `AuthorityStore` now binds approvals to an exact device identifier and rejects legacy unbound entries. Errors `OWNER_APPROVAL_DEVICE_REQUIRED`, `OWNER_APPROVAL_DEVICE_MISMATCH`, `OWNER_APPROVAL_EXPIRED_OR_CONSUMED` and `OWNER_APPROVAL_REVOKED` are terminal permission failures; do not retry via another device. The host-attested consent link is still pending; see [Permission Broker state](../../../P0_PERMISSION_BROKER.md).
