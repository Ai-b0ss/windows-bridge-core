# Tested-route philosophy

| Application | Programmatic check first | Hidden fallback | Evidence required |
| --- | --- | --- | --- |
| Cursor | agent/cursor-agent CLI, auth and a real task capability | owned instance, native editor helpers, UIA/CDP when compatible | actual agent result and file changes/readback |
| Antigravity | installed agy/official CLI compatibility + authenticated task | compatible isolated Electron UI route | requested response or resulting edit |
| Excel | COM/object model and entitlement-specific features | owner-scoped hidden Excel/UIA | saved XLSX and independent document readback |
| Browser | site API, CDP, Playwright, isolated profile | native UIA/semantic fallback | URL and postcondition, only owned tabs closed |
| Unknown Windows app | discover official API, CLI, SDK, MCP and tested OSS tool | hidden Desktop, Win32/UIA, WGC/OCR/vision | real task-specific postcondition |

The word `candidate` and the presence of a CLI are not proof of task suitability. Probe costs/licensing and safety. If route absence is not proven, do not jump directly to a visible desktop.
