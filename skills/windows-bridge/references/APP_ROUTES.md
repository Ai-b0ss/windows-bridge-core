# Tested-route philosophy

| Application | Programmatic check first | Hidden fallback | Evidence required |
| --- | --- | --- | --- |
| Cursor | agent/cursor-agent CLI, auth and a real task capability | owned instance, native editor helpers, UIA/CDP when compatible | actual agent result and file changes/readback |
| Antigravity | installed agy/official CLI compatibility + authenticated task | compatible isolated Electron UI route | requested response or resulting edit |
| Excel | COM/object model and entitlement-specific features | owner-scoped hidden Excel/UIA | saved XLSX and independent document readback |
| Browser | site API, CDP, Playwright, isolated profile | native UIA/semantic fallback | URL and postcondition, only owned tabs closed |
| Claude Desktop GUI | Verify native app PID/HWND and read-only UIA Snapshot; do not substitute Claude Code CLI | Verified owned native/UIA route only with task-scoped consent | Actual existing GUI state, semantic target, postcondition; no arbitrary click under read-only |
| Unknown Windows app | discover official API, CLI, SDK, MCP and tested OSS tool | hidden Desktop, Win32/UIA, WGC/OCR/vision | real task-specific postcondition |

The word `candidate` and the presence of a CLI are not proof of task suitability. Probe costs/licensing and safety. If route absence is not proven, do not jump directly to a visible desktop.

## Excel COM proof and limitations

Use the read-only task_preflight with app="Excel" and verify_office_com=true. It inspects Windows Excel.Application COM registration only and never launches Excel or touches a workbook. The response includes office_com_registration.registered_executable_present and candidate_route "EXCEL_COM" where verified.

A real hidden Excel.Application COM test on an authorized owner Windows machine created an owned temporary book, calculated =SUM(A1:A2) as 42 and saved an XLSX, then independently verified the OOXML ZIP cache/formula and deleted only owned files/PID. Script: tests/integration/excel_com_smoke.ps1. This is evidence for formulas/cells/save, **not** Excel Copilot assistant, subscription rights, or arbitrary owner document access. When a user Excel instance is already running, do NOT attach; the smoke explicitly skips.
