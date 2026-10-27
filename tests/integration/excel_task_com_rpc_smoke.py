"""Real Excel COM task-read E2E through an isolated Bridge RPC instance.

Runs ONLY against a newly created, hidden throwaway Excel workbook on a Windows
machine with Excel + pywin32. Skips (not PASS) when Excel is unavailable or an
owner Excel instance already exists. Nothing is installed, paid, or shown.
"""
from __future__ import annotations
import gc
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time

from isolated_rpc_smoke import REPO, SERVER, free_port, rpc, verify


def wait_until(fn, code, seconds=14):
    limit = time.monotonic() + seconds
    while time.monotonic() < limit:
        outcome = fn()
        if outcome:
            return outcome
        time.sleep(.1)
    raise RuntimeError(code)


def main():
    verify(os.name == "nt", "WINDOWS_REQUIRED")
    import pythoncom
    import win32com.client
    import win32process
    from ff_win_process_identity import ProcessReference, process_creation_token

    existing = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         "@(Get-Process -Name EXCEL -ErrorAction SilentlyContinue).Count"],
        capture_output=True, text=True, timeout=12, check=True,
    )
    if existing.stdout.strip() != "0":
        print(json.dumps({"schema": "ff-excel-task-com-rpc-v1", "status": "SKIP",
                          "reason": "owner_or_other_excel_process_already_running"}))
        return 0

    with TemporaryDirectory(prefix="ff-excel-task-rpc-") as td:
        root = Path(td)
        bridge_root = root / "isolated-bridge"
        bridge_root.mkdir()
        workbook_path = root / "owned.xlsx"
        pythoncom.CoInitialize()
        excel = None
        workbook = None
        server = None
        child = None
        try:
            excel = win32com.client.DispatchEx("Excel.Application")
            excel.Visible = False
            excel.DisplayAlerts = False
            excel.EnableEvents = False
            excel.AutomationSecurity = 3
            _thread, pid = win32process.GetWindowThreadProcessId(int(excel.Hwnd))
            verify(pid > 4, "EXCEL_OWNED_PID_MISSING")
            child = ProcessReference(pid, process_creation_token(pid))
            workbook = excel.Workbooks.Add()
            worksheet = workbook.Worksheets.Item(1)
            sheet_name = str(worksheet.Name)
            worksheet.Range("A1").Value2 = 20
            worksheet.Range("A2").Value2 = 22
            worksheet.Range("A3").Formula = "=SUM(A1:A2)"
            excel.CalculateFull()
            verify(float(worksheet.Range("A3").Value2) == 42, "TEST_EXCEL_FORMULA_WRONG")
            workbook.SaveAs(str(workbook_path), 51)
            # Keep workbook OPEN in its own owned hidden Excel instance while
            # isolated Bridge uses the genuine COM adapter to read it.
            port = free_port()
            env = {**os.environ, "FF_BRIDGE_ROOT": str(bridge_root)}
            server = subprocess.Popen(
                [sys.executable, str(SERVER), "serve", "--host", "127.0.0.1",
                 "--port", str(port)],
                cwd=str(REPO), env=env, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            secret_path = bridge_root / "bridge-v3" / "secret"
            def ready():
                verify(server.poll() is None, "ISOLATED_SERVER_EXITED")
                if not secret_path.is_file():
                    return False
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.2):
                        return True
                except OSError:
                    return False
            wait_until(ready, "ISOLATED_SERVER_NOT_READY")
            secret = secret_path.read_text("ascii").strip()

            attached = rpc(port, secret, "computer_use", {
                "command": "attach", "surface_kind": "app", "app": "Excel",
            }, "ci-excel-task-attach")
            verify(attached.get("ok") is True,
                   "EXCEL_APP_ATTACH_FAILED_" + str(attached.get("error_code")))
            surface_id = (attached.get("result") or {}).get("surface_id")
            verify(isinstance(surface_id, str), "EXCEL_APP_SURFACE_NOT_REGISTERED")

            task = rpc(port, secret, "computer_use", {
                "command": "task_execute", "app": "Excel", "task": "excel.cells",
                "operation": "cell.read", "agent_id": "ci-excel-agent",
                "task_id": "ci-cell-read", "surface_id": surface_id,
                "action_args": {"sheet": sheet_name, "address": "A3"},
                "expected_value": 42,
            }, "ci-excel-task-do-real-read")
            verify(task.get("ok") is True,
                   "EXCEL_REAL_TASK_FAILED_" + str(task.get("error_code")))
            receipt = task.get("result") or {}
            verify(receipt.get("state") == "COMPLETED" and receipt.get("verified") is True
                   and receipt.get("value") == 42, "EXCEL_TASK_RESULT_UNVERIFIED")
            evidence = receipt.get("verification") or {}
            verify(evidence.get("distinct_read_calls") == 2 and
                   evidence.get("postcondition_matches_expected") is True,
                   "EXCEL_TASK_DOUBLE_OBSERVATION_MISSING")
            verify((receipt.get("execution") or {}).get("model_called") is False and
                   (receipt.get("execution") or {}).get("foreground_used") is False and
                   (receipt.get("execution") or {}).get("file_or_workbook_mutated") is False,
                   "EXCEL_TASK_UNEXPECTED_EFFECT")

            # The external artifact is checked independently from the Bridge
            # using the actual saved workbook ZIP, not the assistant's claim.
            from openpyxl import load_workbook
            independent = load_workbook(workbook_path, data_only=True, read_only=True)
            try:
                verify(independent[sheet_name]["A3"].value == 42,
                       "EXCEL_TASK_INDEPENDENT_ARTIFACT_MISMATCH")
            finally:
                independent.close()
            # Re-read the owner-created workbook after Bridge returned to ensure
            # that its existing content remains intact and it was not closed.
            verify(float(worksheet.Range("A3").Value2) == 42,
                   "EXCEL_TASK_OWNER_WORKBOOK_CHANGED")
            verify(child.poll() is None, "EXCEL_TASK_OWNER_INSTANCE_TERMINATED")
            print(json.dumps({
                "schema": "ff-excel-task-com-rpc-v1", "status": "PASS",
                "task_execution_via_real_rpc": True,
                "actual_excel_com_cell_read": True,
                "independent_saved_xlsx_check": True,
                "two_fresh_value_observations": True,
                "task_left_owner_workbook_open": True,
                "hidden_excel_only": True,
                "no_model_or_paid_api": True,
                "production_runtime_modified": False,
            }, sort_keys=True))
        finally:
            if server is not None:
                if server.poll() is None:
                    server.terminate()
                try:
                    server.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait(timeout=8)
            if workbook is not None:
                try:
                    workbook.Close(False)
                except Exception:
                    pass
            if excel is not None:
                try:
                    excel.Quit()
                except Exception:
                    pass
            workbook = None
            excel = None
            gc.collect()
            pythoncom.CoUninitialize()
            if child is not None:
                try:
                    if child.poll() is None:
                        child.terminate()  # exact PID/birth-bound owned instance
                finally:
                    child.close()


if __name__ == "__main__":
    sys.path.insert(0, str(REPO / "runtime/bridge-v3"))
    try:
        main()
    except ImportError:
        print(json.dumps({"schema": "ff-excel-task-com-rpc-v1", "status": "SKIP",
                          "reason": "Excel COM or Python test dependency unavailable"}))
    except Exception as exc:
        print("EXCEL_TASK_COM_RPC_FAILED:" + type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
