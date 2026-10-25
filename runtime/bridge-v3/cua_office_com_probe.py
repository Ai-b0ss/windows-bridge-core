"""Read-only native Excel COM registration discovery without creating Office.

Registration suggests a route, not COM activation or real task success.
"""
from __future__ import annotations
import os
import re
from typing import Callable


_CLSID = re.compile(
    r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$"
)


def excel_registration(*, query: Callable[[str],str] | None=None,
                       file_exists: Callable[[str],bool]=os.path.isfile) -> dict:
    result={
        "schema":"ff-excel-com-discovery-v1",
        "registration_found":False,
        "registered_executable_present":False,
        "candidate_route":None,
        "excel_process_started":False,
        "user_workbook_accessed":False,
        "model_called":False,
        "task_completed":False,
        "task_support_proven":False,
        "next_step":"excel_com_not_discovered_research_other_office_routes",
    }
    if query is None:
        try:
            import winreg
        except ImportError:
            return result
        def query(key: str) -> str:
            return str(winreg.QueryValue(winreg.HKEY_CLASSES_ROOT,key))
    try:
        clsid=query(r"Excel.Application\CLSID").strip()
        if not _CLSID.fullmatch(clsid):
            return result
        cmd=query("CLSID\\"+clsid+r"\LocalServer32")
    except (OSError,ValueError,TypeError):
        return result
    result["registration_found"]=True
    match=re.search(
        r'(?i)"([^"]*EXCEL\.EXE)"|([A-Za-z]:\\[^\r\n]*?EXCEL\.EXE)',
        str(cmd),
    )
    if match:
        exe=match.group(1) or match.group(2)
        try:
            result["registered_executable_present"]=bool(file_exists(
                os.path.expandvars(exe)
            ))
        except (OSError,ValueError):
            pass
    if result["registered_executable_present"]:
        result["candidate_route"]="EXCEL_COM"
        result["next_step"]="verify_owned_hidden_excel_com_and_task_postcondition"
    else:
        result["next_step"]="excel_com_registry_present_but_executable_unverified"
    return result
