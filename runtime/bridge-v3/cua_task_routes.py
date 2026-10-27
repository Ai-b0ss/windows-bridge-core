"""Task suitability: missing classification is NOT evidence of incompatibility.

A CLI responding to --version or --help is NOT evidence that it can perform
the requested task. Human task descriptions are intentionally left unknown
until their required capabilities and entitlement are evaluated.
"""
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
    # Task routing is a PURE classification step. Version and help probes are
    # explicitly separate opt-in tools with vendor path validation. Never run
    # executable paths supplied by discovery or caller-controlled candidates.
    for candidate in candidates:
        row = dict(candidate)
        row["task_compatibility"] = "unknown"
        row["task_evidence"] = "discovery_only"
        rows.append(row)
    if raw_task == "excel.cells" and {"cell.read", "cell.write"} <= set(api_capabilities):
        rows.insert(0, {
            "kind": "app_api",
            "executor": "Excel COM",
            "task_compatibility": "unknown",
            "task_evidence": "advertised_cell_api_not_executed",
        })
    potential = [
        row for row in rows
        if (raw_task == "cursor.open_workspace"
            and str(row.get("command") or "").casefold() == "cursor")
        or (raw_task == "excel.cells" and row.get("executor") == "Excel COM")
    ]
    return {
        "task": task,
        # A missing assistant CLI/API is not proof that only the GUI can work.
        "task_compatibility": "unknown",
        "routes": rows,
        "preferred_task_route": None,
        "potential_task_route": potential[0] if potential else None,
        "remaining_gate": (
            "RESEARCH_ASSISTANT_API_OR_HIDDEN_AND_VERIFY" if raw_task in {
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
