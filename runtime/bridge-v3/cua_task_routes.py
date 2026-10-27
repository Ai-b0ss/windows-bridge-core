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
        command = str(row.get("command") or "").casefold()
        # Discovery without a task-specific negative probe is UNKNOWN, not incompatible.
        support = "unknown"
        row["task_evidence"] = "discovery_only"
        if raw_task == "cursor.open_workspace" and command == "cursor" and row.get("health") == "healthy":
            support = "compatible"
            row["task_evidence"] = "healthy_cli_candidate_not_executed"
        if raw_task in {"cursor.assistant", "cursor.edit_files"} and command in {"agent", "cursor-agent"}:
            support = "unknown"
            if probe and row.get("health") == "healthy" and isinstance(row.get("path"), str) and row["path"]:
                try:
                    p = subprocess.run(
                        [row["path"], "--help"], capture_output=True, timeout=3,
                        stdin=subprocess.DEVNULL, check=False,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                    )
                    # Go/Windows CLIs can print help on stderr. This is syntax
                    # evidence only and must never be returned as raw text.
                    out = p.stdout if isinstance(p.stdout, bytes) else b""
                    err = p.stderr if isinstance(p.stderr, bytes) else b""
                    help_text = (out + b"\n" + err)[:32000].decode("utf-8", errors="replace").lower()
                    # Help text proves syntax, not auth, quota, true ability
                    # to execute the requested task, cost or postcondition.
                    # Do not accidentally promote "--print" to "compatible".
                    row["cli_contract_headless_supported"] = (
                        p.returncode == 0 and "--print" in help_text
                    )
                    support = "unknown"
                    row["task_evidence"] = "cli_help_syntax_only"
                    row["task_probe_exit_code"] = p.returncode
                except (OSError, subprocess.TimeoutExpired):
                    support = "unknown"
        row["task_compatibility"] = support
        rows.append(row)
    if raw_task == "excel.cells" and {"cell.read", "cell.write"} <= set(api_capabilities):
        rows.insert(0, {
            "kind": "app_api", "executor": "Excel COM", "task_compatibility": "compatible",
            "task_evidence": "advertised_cell_api_not_executed",
        })
    compatible = [r for r in rows if r["task_compatibility"] == "compatible"]
    return {
        "task": task,
        # A missing assistant CLI/API is not proof that only the GUI can work.
        "task_compatibility": "compatible" if compatible else "unknown",
        "routes": rows,
        "preferred_task_route": compatible[0] if compatible else None,
        "remaining_gate": (
            "LOGIN_LICENCE_AND_TASK_POSTCONDITION" if compatible
            else "RESEARCH_ASSISTANT_API_OR_HIDDEN_AND_VERIFY" if raw_task in {
                "excel.assistant", "word.assistant", "powerpoint.assistant"
            }
            else "VERIFY_CLI_AUTH_ENTITLEMENT_AND_TASK_POSTCONDITION" if raw_task in {
                "cursor.assistant", "cursor.edit_files", "antigravity.assistant",
                "antigravity.edit_files"
            }
            else "VERIFY_CANDIDATE_OPERATION_AND_POSTCONDITION"
        ),
        "requires_visible_desktop": False,
        "no_route_proven": False,
        "excel_com_covers_assistant": False,
        "verified_task_support": False,
    }
