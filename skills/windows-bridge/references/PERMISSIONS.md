# Trusted permission-broker contract

The authenticated owner may express consent in ChatGPT, including "I'm not home" and "you may use the desktop". This establishes **intent** within the task. It is not a verifiable Bridge grant unless the host provides an authenticated receipt through a trusted integration.

Real foreground or high-impact operations must be bound to: exact device, agent identity, task identity, target fingerprint/window generation, exact allowed operation or small bounded scope, expiry, revocation and replay/idempotency record.

Existing `cua_task_authority.py` supports signed exact approvals and a trusted local-controller API. A raw agent-supplied `approved=true`, a scraped message, or a fabricated `signed_approval` is NOT authority. Never turn off its verifier to improve UX. The host-to-broker confirmation integration is a separate P0 gate.

Automatic programmatic read-only discovery is allowed in an authorized context. Do not silently perform privileged/deletion actions, purchases or screen-visible control outside the granted scope. Windows UAC remains in charge of elevation.
