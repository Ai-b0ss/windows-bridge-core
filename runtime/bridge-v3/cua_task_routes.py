"""Task suitability: missing classification is NOT evidence of incompatibility.

A CLI responding to --version or --help is NOT evidence that it can perform
the requested task. Human task descriptions are intentionally left unknown
until their required capabilities and entitlement are evaluated.
"""
from pathlib import Path
import subprocess

TASKS = {
    "excel.assistant", "excel.cells",
    "cursor.assistant", "cursor.edit_files", "cursor.open_workspace",
    "antigravity.assistant", "antigravity.edit_files",
    "word.assistant", "powerpoint.assistant",
}


def family_for(app):
    key = str(app or "").strip().casefold()
    if "excel" in key:
        return "excel"
    if "cursor" in key:
        return "cursor"
    if "antigravity" in key or key == "agy":
        return "antigravity"
    if key in {"word", "microsoft word", "winword.exe"}:
        return "word"
    if key in {"powerpoint", "microsoft powerpoint", "powerpnt.exe"}:
        return "powerpoint"
    return None


def task_routes(app, task, candidates, *, probe=False, api_capabilities=()):
    family = family_for(app)
    raw_task = str(task or "").strip()
    if family is None:
        return {
            "task": task, "task_compatibility": "unknown",
            "routes": [], "remaining_gate": "APP_FAMILY_RESEARCH_REQUIRED",
            "verified_task_support": False,
        }
    known = sorted(t for t in TASKS if t.startswith(family + "."))
    if not raw_task.startswith(family + "."):
        return {
            "task": task, "task_compatibility": "unknown",
            "routes": [], "remaining_gate": "TASK_INTENT_NEEDS_CLASSIFICATION",
            "known_task_ids": known, "verified_task_support": False,
            "note": "natural_language_task_not_an_explicit_incompatibility",
        }
    if raw_task not in TASKS:
        return {
            "task": task, "task_compatibility": "unknown",
            "routes": [], "remaining_gate": "TASK_SUPPORT_RESEARCH_REQUIRED",
            "known_task_ids": known, "verified_task_support": False,
        }
    rows = []
    for candidate in candidates:
        row = dict(candidate)
        command = row.get("command", "").casefold()
        support = "incompatible"
        if raw_task == "cursor.open_workspace" and command == "cursor" and row.get("health") == "healthy":
            support = "compatible"
        if raw_task in {"cursor.assistant", "cursor.edit_files"} and command in {"agent", "cursor-agent"}:
            support = "unknown"
            if probe and row.get("health") == "healthy":
                try:
                    p = subprocess.run(
                        [row["path"], "--help"], capture_output=True, timeout=3,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                    help_text = p.stdout.decode("utf-8", errors="replace").lower()
                    # Help text proves syntax, not auth, quota, true ability
                    # to execute the requested task, cost or postcondition.
                    # Do not accidentally promote "--print" to "compatible".
                    row["cli_contract_headless_supported"] = (
                        p.returncode == 0 and "--print" in help_text
                    )
                    support = "unknown"
                    row["task_probe_exit_code"] = p.returncode
                except (OSError, subprocess.TimeoutExpired):
                    support = "unknown"
        row["task_compatibility"] = support
        rows.append(row)
    if raw_task == "excel.cells" and {"cell.read", "cell.write"} <= set(api_capabilities):
        rows.insert(0, {
            "kind": "app_api", "executor": "Excel COM", "task_compatibility": "compatible",
        })
    compatible = [r for r in rows if r["task_compatibility"] == "compatible"]
    return {
        "task": task,
        "task_compatibility": (
            "compatible" if compatible
            else "requires_ui" if raw_task in {
                "excel.assistant", "word.assistant", "powerpoint.assistant"
            } else "unknown"
        ),
        "routes": rows,
        "preferred_task_route": compatible[0] if compatible else None,
        "remaining_gate": (
            "LOGIN_LICENCE_AND_TASK_POSTCONDITION" if compatible
            else "OBSERVE_APP_ASSISTANT_AND_VERIFY"
        ),
        "excel_com_covers_assistant": False,
        "verified_task_support": False,
    }
