# Trusted permission-broker contract

The authenticated owner expresses consent **in the ChatGPT conversation**. "I'm not home" or an initial general work request is **not** consent to *visible mouse, keyboard or focus takeover*. The agent must first research and exhaust appropriate programmatic + hidden interfaces, explain concrete evidence and ask the owner in the same chat before *first* visible desktop action, even if the owner is away. A clear in-chat "да, можно" establishes task-bound owner **intent**, not a Bridge-verifiable grant. Existing valid same-task consent need not be repeatedly requested.

Real foreground or high-impact operations must be bound to: exact device, agent identity, task identity, target fingerprint/window generation, exact allowed operation or small bounded scope, expiry, revocation and replay/idempotency record.

Existing `cua_task_authority.py` supports signed exact approvals and a trusted local-controller API. Host/controller must transparently translate a verified chat confirmation to the exact signed grant. A raw agent-supplied `approved=true`, a scraped message, or a fabricated `signed_approval` is NOT authority. If host attestation is unavailable, leave visible actions blocked, report why and continue safe routes only. Never turn off its verifier to improve UX. Do **not** require manual crypto keys, PowerShell, email or out-of-chat popups from the owner. The host-to-broker confirmation integration remains a separate P0 gate.

Automatic programmatic read-only discovery is allowed in an authorized context. Do not silently perform privileged/deletion actions, purchases or screen-visible control outside the granted scope. Windows UAC remains in charge of elevation.

The P0 source `AuthorityStore` now binds approvals to an exact device identifier and rejects legacy unbound entries. Errors `OWNER_APPROVAL_DEVICE_REQUIRED`, `OWNER_APPROVAL_DEVICE_MISMATCH`, `OWNER_APPROVAL_EXPIRED_OR_CONSUMED` and `OWNER_APPROVAL_REVOKED` are terminal permission failures; do not retry via another device. The host-attested consent link is still pending; see [Permission Broker state](../../../P0_PERMISSION_BROKER.md).
