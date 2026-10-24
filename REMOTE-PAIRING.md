# Friend laptop remote support — explicit consent and private GitHub transport

## Scope and permissions
The local installer `INSTALL-FRIEND.cmd` does **not** provide remote control. If you want the owner/operator `Ai-b0ss` to run Windows Bridge operations, run `PAIR-REMOTE-SUPPORT.cmd` from the signed-hash-checked release ZIP. It explains full control and requires your explicit Y choice. Windows may show standard UAC prompts for administrator-only actions; do not approve something you did not request.

This edition uses GitHub as a **private** command inbox, not a public repository, and does not require a private Cloudflare token on your PC. GitHub CLI and Python are bundled; it opens an ordinary GitHub web login for the friend. No password/token should be sent to the operator.

## Owner preparation
1. The owner has to invite the **friend's own GitHub username** as a collaborator to `Ai-b0ss/windows-bridge-support-20261024`. Invite only the exact account, and use only this dedicated private repository; never share the Windows Bridge source repo.
2. Friend accepts the invitation in GitHub, then runs `PAIR-REMOTE-SUPPORT.cmd` and accepts the GitHub CLI browser/device login themselves.
3. Installer verifies that the GitHub repository is private and that the friend has access. The transport configuration permits commands **only from repository owner `Ai-b0ss`**, not automatically from the account used for local authentication.
4. On success, the installer creates a per-device GitHub inbox Issue and an interactive Windows logon task. Send the owner **only** the device name and issue number from output; never the user's authentication or device tokens.
5. Owner and friend together perform an end-to-end ping/capabilities command on the exact laptop. Consent, device targeting and UAC remain applicable. The operation will be traceable in the private repository.

## Disconnection
Friend runs `STOP-REMOTE-SUPPORT.cmd` to stop and disable **only scheduled tasks and processes matching the exact Bridge installation root and dedicated private support repo**. Owner separately revokes the friend's collaborator access on the private GitHub transport repository; that removes the GitHub network credential's repo authority. The local Bridge is not uninstalled automatically: this makes disconnection reversible and does not delete any unrelated files.

## Security caveats
- This repository's Issues and result branch can contain confidential system findings or file contents from executed commands. Keep it PRIVATE and limit repo collaborators.
- Friend's GitHub token is stored by the official GitHub CLI in the friend's own credential store. We do not bundle or transmit it.
- The operator's permission is defined by the friend agreeing to remote control and the code's existing authorization gates. It does not bypass Windows UAC or user-account permissions.
- No inbound port-forwarding or public unauthenticated HTTP endpoint is created.
- There is no verified pairing until the real friend laptop is connected and a round-trip is confirmed.
