"""Task-specific compatibility: launching Excel is not using its assistant."""
from pathlib import Path
import subprocess

TASKS = {"excel.assistant", "excel.cells", "cursor.assistant", "cursor.edit_files", "cursor.open_workspace", "word.assistant", "powerpoint.assistant"}

def task_routes(app, task, candidates, *, probe=False, api_capabilities=()):
    family = "excel" if "excel" in app.casefold() else "cursor" if "cursor" in app.casefold() else None
    if app.strip().casefold() in {"word", "microsoft word", "winword.exe"}: family = "word"
    elif app.strip().casefold() in {"powerpoint", "microsoft powerpoint", "powerpnt.exe"}: family = "powerpoint"
    if family is None or not str(task).startswith(family + "."):
        return {"task": task, "task_compatibility": "incompatible", "routes": [], "remaining_gate": "APP_TASK_MISMATCH"}
    if task not in TASKS:
        return {"task": task, "task_compatibility": "unknown", "routes": [], "remaining_gate": "TASK_SUPPORT_RESEARCH_REQUIRED"}
    rows = []
    for candidate in candidates:
        row = dict(candidate)
        command = row.get("command", "").casefold()
        support = "incompatible"
        if task == "cursor.open_workspace" and command == "cursor" and row.get("health") == "healthy":
            support = "compatible"
        if task in {"cursor.assistant", "cursor.edit_files"} and command in {"agent", "cursor-agent"}:
            support = "unknown"
            if probe and row.get("health") == "healthy":
                try:
                    p = subprocess.run([row["path"], "--help"], capture_output=True, timeout=3,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    help_text = p.stdout.decode("utf-8", errors="replace").lower()
                    support = "compatible" if p.returncode == 0 and "cursor" in help_text and "--print" in help_text else "incompatible"
                    row["task_probe_exit_code"] = p.returncode
                except (OSError, subprocess.TimeoutExpired):
                    support = "unknown"
        row["task_compatibility"] = support
        rows.append(row)
    if task == "excel.cells" and {"cell.read", "cell.write"} <= set(api_capabilities):
        rows.insert(0, {"kind": "app_api", "executor": "Excel COM", "task_compatibility": "compatible"})
    compatible = [r for r in rows if r["task_compatibility"] == "compatible"]
    return {"task": task, "task_compatibility": "compatible" if compatible else "requires_ui" if task in {"excel.assistant", "word.assistant", "powerpoint.assistant"} else "unknown",
            "routes": rows, "preferred_task_route": compatible[0] if compatible else None,
            "remaining_gate": "LOGIN_LICENCE_AND_TASK_POSTCONDITION" if compatible else "OBSERVE_APP_ASSISTANT_AND_VERIFY",
            "excel_com_covers_assistant": False}
