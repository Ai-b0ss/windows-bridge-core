# Real Hidden Private Desktop & Native CUA Acceptance

This document records scoped, real-Windows acceptance evidence and explicit
technical boundaries for the Win32 Private Desktop and Native Semantic CUA
subsystem (`cua_hidden_desktop.py`, `cua_hidden_worker.py`, `cua_native_core.py`,
`cua_native_hwnd.py`, `cua_native_uia3.py`, `cua_hidden_capture.py`,
`cua_desktop_identity.py`).

It is scoped evidence for explicitly verified classic Win32 applications and an
isolated Win32 test window — **not** universal GUI compatibility, arbitrary
third-party app mastery, or cross-desktop hardware input.

## Win32 Private Desktop Technical Boundaries

Windows `CreateDesktopW` / `SetThreadDesktop` isolates windows, message queues,
and UIA trees per desktop inside `WinSta0`. The Bridge enforces these exact OS
boundaries fail-closed:

| Mechanism | Private Desktop Status | Behavior & Error Contract |
| --- | --- | --- |
| Win32 HWND messages (`WM_SETTEXT`, `EM_SETSEL` + `EM_REPLACESEL`, `WM_CHAR` via `SendMessageTimeoutW` / `PostMessageW`, `BM_CLICK`, `CB/LB_SETCURSEL` + `WM_COMMAND`, `WM_GETTEXT`) | **SUPPORTED** (same desktop, owned HWND only) | Operates without `SendInput`, focus hijack, or clipboard access. Enforces `hwnd + pid + create_time` and same-desktop identity. |
| In-desktop UIA3 (`System.Windows.Automation` sidecar spawned inside `winsta0\FFBridge-Agent-*`) | **SUPPORTED** (same desktop, owned HWND only) | Runs in dedicated MTA sidecar inside the private desktop Job; supports `surface_entity_value_equals` and post-rerender receipt recovery without mutation replay. |
| Own-window `PrintWindow` capture (`cua_hidden_capture.py`) | **SUPPORTED** (same desktop, owned HWND only) | Revalidates ownership and private-desktop identity before and after capture. Not WGC; does not by itself prove task completion. |
| Hardware `SendInput`, cursor warp (`SetCursorPos`), `SwitchDesktop`, visible-desktop fallback | **UNSUPPORTED — FAIL CLOSED** | Windows `SendInput` targets only the active input desktop and cannot inject across desktops without `SwitchDesktop` (forbidden). Rejected fail-closed with `PRIVATE_DESKTOP_PHYSICAL_INPUT_UNSUPPORTED` / `PHYSICAL_INPUT_FORBIDDEN`; never falls back to the visible desktop. |
| Cross-desktop UIA3 / HWND targeting | **UNSUPPORTED — FAIL CLOSED** | Rejected fail-closed with `HIDDEN_WINDOW_NOT_OWNED` (worker ownership gate) and `CROSS_DESKTOP_UIA_UNSUPPORTED` / `CROSS_DESKTOP_TARGET_FORBIDDEN` (backend/desktop-identity layer). |
| Foreign HWND or mismatched `pid` / `create_time` | **DENIED — FAIL CLOSED** | Rejected before dispatch with `HIDDEN_WINDOW_NOT_OWNED` or `HIDDEN_WINDOW_IDENTITY_MISMATCH` / `TARGET_IDENTITY_MISMATCH`. |
| Deterministic teardown (normal exit, error, timeout, forced `cancel()`, parent process crash) | **SUPPORTED & VERIFIED** | Named kill-on-close Job Object (`Local\FFBridge-HiddenDesktop-<session_id>`) + `TerminateJobObject` + `ActiveProcesses == 0` wait + `CloseDesktop` verification (`job_cleanup_verified`, `desktop_cleanup_verified`). |

## Reproducible Gates

Primary unit + real isolated Windows acceptance suite:

```
python -m unittest discover -s tests -p "test_p0_hidden_desktop_cua.py" -v
```

Strict quiet-window non-interference mode (fails closed if any human input
occurs during the before/after interval):

```
$env:FF_P0_STRICT_OWNER_QUIET = "1"
python -m unittest discover -s tests -p "test_p0_hidden_desktop_cua.py" -v
```

Classic smoke gate (when run directly on the active input desktop):

```
python tests/integration/hidden_native_smoke.py --app notepad
python tests/integration/hidden_native_smoke.py --app wordpad
```

## Verified vs `NOT_VERIFIED` Application Matrix (21 November 2026)

Host OS: Windows 10 (`10.0.19045.0`). All live runs executed in isolated
temporary `FF_BRIDGE_ROOT` directories without touching production services,
owner apps, user documents, or clipboard content (only `GetClipboardSequenceNumber`
and `GetClipboardOwner` HWND are observed; clipboard text is never read).

| Application / Target | Status | Observed Version / Binary SHA-256 | What Was Proven Live |
| --- | --- | --- | --- |
| Classic Notepad (`notepad.exe`, `Edit`) | **VERIFIED** | `10.0.19041.1` / `da5807bb0997cc6b5132950ec87eda2b33b1ac4533cf1f7a22a6f3b576ed7c5b` | Private desktop creation, named Job containment, UIA3 observe (26 entities), `PrintWindow` PNG capture, `WM_SETTEXT`, `EM_REPLACESEL`, `WM_CHAR` (`SendMessageTimeoutW` & `PostMessageW`), ControlPlane `HWND_MESSAGE` `attach`/`act`, independent `read_text` readback, foreign HWND & `pid`/`create_time` denial, fail-closed `PRIVATE_DESKTOP_PHYSICAL_INPUT_UNSUPPORTED`, owner invariance (`foreground_hwnd`, `cursor`, `clipboard_seq`, `clipboard_owner` unchanged), and deterministic teardown (process + desktop destroyed). |
| WordPad (`wordpad.exe`, `RICHEDIT50W`) | **VERIFIED** | `10.0.19041.1` / `4b2e23a9130ea4ed8540071d7ebc9f02e5bcfe8eaca96cccab561fd8b7296c2e` | Private desktop launch, `WM_SETTEXT` edit on direct `RICHEDIT50W` document control, verified postcondition + independent `read_text` readback, strict owner invariance, and deterministic teardown. |
| Isolated Python/Win32 rerender test window (`FFBridgeP0RerenderWindow`) | **VERIFIED** | Synthetic Win32 test window (`tests/test_p0_hidden_desktop_cua.py`) | Real Win32 Edit HWND destruction & recreation on `set_value` proving `3d53aba3` post-rerender receipt recovery (`surface_entity_value_equals`) on **both** `HWND_MESSAGE` and compiled C# `UIA_PATTERN` without mutation replay; cross-control `surface_entity_value_equals` on `BM_CLICK`; cross-session foreign HWND rejection between two concurrent private desktops; deterministic teardown. |
| Arbitrary third-party Electron / Chromium / CEF desktop apps | **`NOT_VERIFIED`** | N/A | Not proven via generic private-desktop CUA. Generic launch fails closed with `HIDDEN_APP_ISOLATION_ROUTE_REQUIRED` when Electron/Chromium markers are present so default-profile singleton IPC cannot hijack an owner session. |
| Custom DirectX / OpenGL / Vulkan / canvas-rendered apps | **`NOT_VERIFIED`** | N/A | Typically lack standard Win32 HWND edit/button controls and UIA value/invoke patterns, and hardware `SendInput` is unsupported across inactive private desktops. |
| Packaged UWP / WinUI 3 / MSIX Store apps (e.g., Windows 11 Store Notepad, modern Settings) | **`NOT_VERIFIED`** | N/A | Generic launch rejects `WindowsApps` paths fail-closed (`HIDDEN_APP_ISOLATION_ROUTE_REQUIRED`); not verified under this gate. |
| Arbitrary third-party Win32 apps with singleton IPC, modal OS dialogs, UAC, or CAPTCHAs | **`NOT_VERIFIED`** | N/A | Out of scope for silent background execution; UAC and CAPTCHAs are never bypassed. |

## Verified GUI Receipt Recovery (`3d53aba34db4459532da26f86eb63b83e77f4ec3`)

`NativeSemanticCore` (`runtime/bridge-v3/cua_native_core.py`) and
`Uia3PersistentBackend` (`runtime/bridge-v3/cua_native_uia3.py`) include
verified post-rerender receipt recovery:

1. Explicit `surface_entity_value_equals` postconditions validate a named
   semantic selector (`automation_id`, `name`, or `control_id`) **before**
   dispatching any mutation.
2. When `set_value` with `value_equals` encounters `STALE_TARGET` during
   postcondition verification (including when the C# UIA3 sidecar reports
   `target disappeared after action` after a control rerender), the core
   performs a fresh read-only snapshot in the same action-scoped window and
   recovers the receipt only if **exactly one** control matches the stable
   semantic identity query — never replaying the mutation and never accepting
   an ambiguous or anonymous match.
3. Ambiguity, disappearance, or unverified rerender fails closed with
   `ACTION_OUTCOME_UNKNOWN` (`attempted=True`, `retry_safe=False`,
   `phase="native_postcondition"`).

## Teardown Matrix Verified on Real Windows

All five lifecycle exit paths were verified live on Windows 10 with kernel
`process_identity_matches` checks and `OpenDesktopW` kernel desktop-object
destruction checks:

- **Normal exit (`with HiddenDesktopSession(...)`)**: `job_cleanup_verified=True`, `desktop_cleanup_verified=True`, worker + child app + UIA sidecar dead, desktop object gone.
- **Exception during session**: `job_cleanup_verified=True`, `desktop_cleanup_verified=True`, all owned processes dead, desktop object gone.
- **Request timeout (`queue.Empty`)**: raises `HIDDEN_ACTION_OUTCOME_UNKNOWN`, closes session automatically, terminates Job + worker + descendants, closes desktop.
- **Forced `cancel()` with in-flight blocking request**: unblocks waiter immediately (`< 100 ms`), returns `HIDDEN_ACTION_OUTCOME_UNKNOWN`, `cancelled=True`, `job_cleanup_verified=True`, `desktop_cleanup_verified=True`, all owned processes dead, desktop object gone.
- **Abrupt parent process hard-kill (`TerminateProcess` without `close()`)**: Windows kernel `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` terminates worker + Notepad and destroys the desktop object automatically with zero orphans.

## Limits

- Interactive Windows acceptance requires an interactive window station
  (`WinSta0`). If human hardware input (`GetLastInputInfo`) occurs during a
  before/after window, strict quiet-window invariance (`FF_P0_STRICT_OWNER_QUIET=1`)
  fails closed rather than falsely claiming zero cursor movement, while
  OS-level isolation invariants (zero owned windows on `Default`, input desktop
  never switched, foreground/clipboard owner never an owned PID) are always
  enforced.
- This proves in-memory control edits, readback, capture, isolation, and
  teardown for the explicitly listed verified targets — not file Save As,
  arbitrary third-party applications, or universal GUI automation.
