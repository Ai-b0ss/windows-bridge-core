# Real hidden native acceptance — 25 October 2026

This is scoped evidence for two classic Windows applications, not universal
GUI support, Office assistants, inactive-desktop video or visual inference.

## Reproducible gate

```
python tests/integration/hidden_native_smoke.py --app notepad
python tests/integration/hidden_native_smoke.py --app wordpad
```

The test creates a new private Windows Desktop and owned app instance. It first
observes UIA, then resolves the actual direct document HWND through an independent
Win32 read. Only the exactly matching owned control can be edited. A foreign
visible HWND must be denied before dispatch. Native set_value must pass its
postcondition; a separate HWND read verifies the actual document text. Finally
the owned worker/app are closed and their original process creation identities
must no longer be alive. Foreground, cursor coordinates and clipboard sequence
are checked before/after; clipboard content is never read.

UIA can advertise editable StatusBar panes while the document lacks ValuePattern.
Those panes are not document candidates. This is a concrete reason to use the
proven HWND_MESSAGE route, rather than modifying the first UIA Edit entity or
declaring that all hidden routes are unavailable.

## Actual result

Runtime source `c644f460f6bc6d07f433c339233cc001147c5424`, independently downloaded
and hash-checked in an isolated Windows test directory. Acceptance script SHA256
`0ee7addb0bd4cb8c432165c369a297267ba8e0017a1f3940f9a756cd3af093bb`.

| App | Observed version | Edit/readback | Foreign HWND denial | Foreground/cursor/clipboard sequence | Owned cleanup |
| --- | --- | --- | --- | --- | --- |
| Notepad | 10.0.19041.4522 | PASS | PASS | unchanged | PASS |
| WordPad | 10.0.19041.4522 | PASS | PASS | unchanged | PASS |

Independent marker UTF-8 SHA256:
`2f638bf0455169c8b39a52d481226bd404e00fe06fd5fa704953d81869b263be`.
Notepad executable SHA256:
`da5807bb0997cc6b5132950ec87eda2b33b1ac4533cf1f7a22a6f3b576ed7c5b`.
WordPad executable SHA256:
`4b2e23a9130ea4ed8540071d7ebc9f02e5bcfe8eaca96cccab561fd8b7296c2e`.

Full unit and isolated RPC/restart/crash suites on the same Windows host/source
also passed: 127 unit tests with no skips, 11 real RPC checks, FILETIME probe,
detached restart retaining exit 37, and hard-crash no-replay. An actual cloud
response timed out after 15 seconds; request_status retrieved the completed
result without rerunning the test. No production service was restarted.

## Limits

Manual authorized interactive-Windows gate. It is not silently replaced by a
hosted CI skip. User input during the short before/after interval can make the
no-interference result inconclusive. The test rejects such a mismatch rather
than declaring PASS. This proves in-memory text changes, not file Save As,
arbitrary applications, or full mastery of hidden Windows desktops. Private
device and chat evidence stays out of public source.
