from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import ctypes
import json
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any, Mapping, Protocol

from cua_router import RouteExecutionError
from cua_universal_fastpath import FastPathError
from cua_winapp_persistent import WinAppPersistentRunner, WinAppSidecarError


class AppApiError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str | None = None,
        *,
        attempted: bool = False,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.attempted = bool(attempted)
        self.details = dict(details or {})


@dataclass(frozen=True)
class AppApiHandle:
    executor: str
    app: str
    backend_route: str
    discovery: dict[str, Any]
    capabilities: dict[str, dict[str, Any]]
    resource_key: str | None = None
    resource_keys: tuple[str, ...] = ()

    def public(self) -> dict[str, Any]:
        window = self.discovery.get("window")
        return {
            "available": True,
            "executor": self.executor,
            "app": self.app,
            "backend_route": self.backend_route,
            "window": dict(window) if isinstance(window, Mapping) else None,
            "capabilities": {name: dict(value) for name, value in self.capabilities.items()},
        }


class AppApiExecutor(Protocol):
    name: str
    priority: int

    def probe(
        self,
        app: str,
        *,
        refresh: bool = False,
        discovered: Mapping[str, Any] | None = None,
    ) -> AppApiHandle | None: ...

    def action(
        self,
        handle: AppApiHandle,
        intent: str,
        *,
        action_args: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]: ...

    def close(self, handle: AppApiHandle) -> Mapping[str, Any] | None: ...

    def describe(self) -> Mapping[str, Any]: ...



_EXCEL_APP_NAMES = frozenset({"excel", "microsoft excel", "excel.exe"})
_EXCEL_CELL_RE = re.compile(r"^\$?([A-Za-z]{1,3})\$?([1-9][0-9]{0,6})$")
_EXCEL_RANGE_RE = re.compile(
    r"^\$?[A-Za-z]{1,3}\$?[1-9][0-9]{0,6}:\$?[A-Za-z]{1,3}\$?[1-9][0-9]{0,6}$"
)

_EXCEL_CAPABILITIES: dict[str, dict[str, Any]] = {
    "inspect": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": False, "verified_capable": True,
    },
    "cell.read": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": False, "verified_capable": True,
    },
    "range.read": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": False, "verified_capable": True,
    },
    "cell.write": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": True, "verified_capable": True,
    },
    "range.write": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": True, "verified_capable": True,
    },
}


def _excel_indexed(member: Any, key: Any) -> Any:
    errors: list[Exception] = []
    if callable(member):
        try:
            return member(key)
        except Exception as exc:
            errors.append(exc)
    try:
        return member[key]
    except Exception as exc:
        errors.append(exc)
    if errors:
        raise errors[0]
    raise TypeError("EXCEL_INDEXED_MEMBER_REQUIRED")


def _excel_item(collection: Any, key: Any) -> Any:
    item = getattr(collection, "Item", None)
    if item is not None:
        return _excel_indexed(item, key)
    return _excel_indexed(collection, key)


def _excel_range(worksheet: Any, address: str) -> Any:
    member = getattr(worksheet, "Range", None)
    if member is None:
        raise AttributeError("Range")
    return _excel_indexed(member, address)


def _excel_hwnd(value: Any) -> int | None:
    if isinstance(value, str):
        try:
            value = int(value, 0)
        except ValueError:
            return None
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _excel_cell_parts(address: str) -> tuple[int, int] | None:
    match = _EXCEL_CELL_RE.fullmatch(address.strip())
    if match is None:
        return None
    letters, row_text = match.groups()
    column = 0
    for ch in letters.upper():
        column = column * 26 + (ord(ch) - 64)
    row = int(row_text)
    if column > 16384 or row > 1048576:
        return None
    return column, row


def _excel_validate_address(address: Any, *, single_cell: bool) -> str:
    value = str(address or "").strip()
    if single_cell:
        if _excel_cell_parts(value) is None:
            raise AppApiError("EXCEL_CELL_INVALID", attempted=False)
        return value
    if _excel_cell_parts(value) is not None:
        return value
    if _EXCEL_RANGE_RE.fullmatch(value) is None:
        raise AppApiError("EXCEL_RANGE_INVALID", attempted=False)
    start, end = value.split(":", 1)
    if _excel_cell_parts(start) is None or _excel_cell_parts(end) is None:
        raise AppApiError("EXCEL_RANGE_INVALID", attempted=False)
    return value


def _excel_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, tuple):
        return [_excel_json_value(item) for item in value]
    if isinstance(value, list):
        return [_excel_json_value(item) for item in value]
    return str(value)


def _excel_workbook_resource_key(descriptor: Mapping[str, Any]) -> str | None:
    identity = str(descriptor.get("full_name") or descriptor.get("name") or "").strip()
    if not identity:
        return None
    digest = hashlib.sha256(identity.casefold().encode("utf-8")).hexdigest()[:24]
    return f"office:excel:workbook:{digest}"


def _excel_has_formula_like_value(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith("=")
    if isinstance(value, (list, tuple)):
        return any(_excel_has_formula_like_value(item) for item in value)
    return False


def _excel_values_equivalent(expected: Any, actual: Any) -> bool:
    expected = _excel_json_value(expected)
    actual = _excel_json_value(actual)
    if isinstance(expected, list) and isinstance(actual, list):
        return len(expected) == len(actual) and all(
            _excel_values_equivalent(left, right)
            for left, right in zip(expected, actual)
        )
    if isinstance(expected, bool) or isinstance(actual, bool):
        return type(expected) is type(actual) and expected == actual
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        return expected == actual
    return expected == actual


@dataclass
class _ExcelComSession:
    app: Any
    provider: str


def _excel_session_parts(value: Any, backend: Any) -> _ExcelComSession:
    if isinstance(value, _ExcelComSession):
        return value
    provider = str(getattr(backend, "provider", "test") or "test")
    return _ExcelComSession(app=value, provider=provider)


class _ExcelComBackend:
    @contextmanager
    def session(self):
        dependency_error: Exception | None = None
        try:
            import pythoncom
            import win32com.client
        except Exception as exc:
            dependency_error = exc
        else:
            pythoncom.CoInitialize()
            app = None
            session = None
            try:
                try:
                    app = win32com.client.GetActiveObject("Excel.Application")
                except Exception as exc:
                    raise AppApiError(
                        "EXCEL_COM_NOT_RUNNING",
                        attempted=False,
                        details={"provider": "pywin32", "exception": type(exc).__name__},
                    ) from exc
                session = _ExcelComSession(app=app, provider="pywin32")
                yield session
                return
            finally:
                if session is not None:
                    session.app = None
                app = None
                pythoncom.CoUninitialize()

        try:
            import comtypes
            import comtypes.client
        except Exception as exc:
            raise AppApiError(
                "EXCEL_COM_DEPENDENCY_MISSING",
                attempted=False,
                details={
                    "providers": ["pywin32", "comtypes"],
                    "pywin32_exception": type(dependency_error).__name__ if dependency_error else None,
                    "comtypes_exception": type(exc).__name__,
                },
            ) from exc

        comtypes.CoInitialize()
        app = None
        session = None
        try:
            try:
                app = comtypes.client.GetActiveObject("Excel.Application")
            except Exception as exc:
                raise AppApiError(
                    "EXCEL_COM_NOT_RUNNING",
                    attempted=False,
                    details={"provider": "comtypes", "exception": type(exc).__name__},
                ) from exc
            session = _ExcelComSession(app=app, provider="comtypes")
            yield session
        finally:
            if session is not None:
                session.app = None
            app = None
            comtypes.CoUninitialize()



_EXCEL_POWERSHELL_SCRIPT = r"""
$ErrorActionPreference='Stop'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$reqText=[Console]::In.ReadToEnd()
$req=$reqText | ConvertFrom-Json
function Emit($obj,[int]$code=0){
  $obj | ConvertTo-Json -Depth 16 -Compress
  exit $code
}
function Descriptor($wb){
  $wins=@()
  try{
    foreach($w in @($wb.Windows)){
      try{$wins += [int64]$w.Hwnd}catch{}
    }
  }catch{}
  return [ordered]@{
    name=[string]$wb.Name
    full_name=[string]$wb.FullName
    path=[string]$wb.Path
    saved=[bool]$wb.Saved
    window_hwnds=@($wins)
  }
}
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
public sealed class ExcelRotEntry { public string DisplayName; public object Value; }
public static class ExcelRotProbe {
  [DllImport("ole32.dll")] static extern int GetRunningObjectTable(int reserved, out IRunningObjectTable pprot);
  [DllImport("ole32.dll")] static extern int CreateBindCtx(int reserved, out IBindCtx ppbc);
  public static ExcelRotEntry[] GetAll() {
    IRunningObjectTable rot; IBindCtx ctx;
    Marshal.ThrowExceptionForHR(GetRunningObjectTable(0,out rot));
    Marshal.ThrowExceptionForHR(CreateBindCtx(0,out ctx));
    IEnumMoniker en; rot.EnumRunning(out en); en.Reset();
    var rows=new List<ExcelRotEntry>(); var mons=new IMoniker[1];
    while(en.Next(1,mons,IntPtr.Zero)==0){
      string display="";
      try { mons[0].GetDisplayName(ctx,null,out display); } catch {}
      object value=null;
      try { rot.GetObject(mons[0],out value); } catch {}
      rows.Add(new ExcelRotEntry{DisplayName=display,Value=value});
    }
    return rows.ToArray();
  }
}
'@
$apps=@()
$seenApps=@{}
try{
  foreach($entry in [ExcelRotProbe]::GetAll()){
    $obj=$entry.Value
    if($null -eq $obj){continue}
    $candidate=$null
    try{$candidate=$obj.Application}catch{
      try{
        if(([string]$obj.Name) -eq 'Microsoft Excel'){$candidate=$obj}
      }catch{}
    }
    if($null -eq $candidate){continue}
    try{
      if(([string]$candidate.Name) -ne 'Microsoft Excel'){continue}
    }catch{continue}
    $key=$null
    try{$key='hwnd:'+([int64]$candidate.Hwnd)}catch{$key='rot:'+([string]$entry.DisplayName)}
    if(-not $seenApps.ContainsKey($key)){
      $seenApps[$key]=$true
      $apps += $candidate
    }
  }
}catch{}
if($apps.Count -eq 0){
  try{$apps += [Runtime.InteropServices.Marshal]::GetActiveObject('Excel.Application')}catch{
    Emit ([ordered]@{ok=$false;error_code='EXCEL_COM_NOT_RUNNING';attempted=$false;exception=$_.Exception.GetType().Name}) 4
  }
}
$descriptors=@()
$books=@()
foreach($app in $apps){
  try{$count=[int]$app.Workbooks.Count}catch{continue}
  for($i=1;$i -le $count;$i++){
    try{$wb=$app.Workbooks.Item($i)}catch{continue}
    $books += $wb
    $descriptors += (Descriptor $wb)
  }
}
if([string]$req.operation -eq 'probe'){
  Emit ([ordered]@{ok=$true;workbooks=@($descriptors)})
}
$identity=$req.identity
$matches=@()
for($i=0;$i -lt $descriptors.Count;$i++){
  $d=$descriptors[$i]
  $match=$false
  if($identity.full_name -and $d.full_name){
    $match=([string]$identity.full_name).Equals([string]$d.full_name,[StringComparison]::OrdinalIgnoreCase)
  }elseif($identity.name){
    $match=([string]$identity.name).Equals([string]$d.name,[StringComparison]::OrdinalIgnoreCase)
  }
  if($match){$matches += $i}
}
if($matches.Count -eq 0){
  Emit ([ordered]@{ok=$false;error_code='STALE_TARGET';attempted=$false;retry_safe=$true}) 5
}
if($matches.Count -gt 1){
  Emit ([ordered]@{ok=$false;error_code='EXCEL_COM_TARGET_AMBIGUOUS';attempted=$false;matches=$matches.Count}) 6
}
$idx=[int]$matches[0]
$wb=$books[$idx]
$desc=$descriptors[$idx]
$op=[string]$req.operation
if($op -eq 'inspect'){
  $names=@()
  for($i=1;$i -le [int]$wb.Worksheets.Count;$i++){$names += [string]$wb.Worksheets.Item($i).Name}
  Emit ([ordered]@{ok=$true;verified=$true;workbook=$desc;sheet_names=@($names)})
}
$sheetName=[string]$req.sheet
$address=[string]$req.address
try{$ws=$wb.Worksheets.Item($sheetName)}catch{
  Emit ([ordered]@{ok=$false;error_code='EXCEL_SHEET_NOT_FOUND';attempted=$false;sheet=$sheetName}) 7
}
try{$range=$ws.Range($address)}catch{
  Emit ([ordered]@{ok=$false;error_code='EXCEL_RANGE_UNAVAILABLE';attempted=$false;address=$address}) 8
}
function ReadMatrix($r){
  $rows=[int]$r.Rows.Count;$cols=[int]$r.Columns.Count
  if($rows -eq 1 -and $cols -eq 1){return $r.Value2}
  $outer=@()
  for($rr=1;$rr -le $rows;$rr++){
    $inner=@()
    for($cc=1;$cc -le $cols;$cc++){$inner += $r.Cells.Item($rr,$cc).Value2}
    $outer += ,@($inner)
  }
  return ,@($outer)
}
if($op -eq 'cell.read' -or $op -eq 'range.read'){
  $value=ReadMatrix $range
  Emit ([ordered]@{ok=$true;verified=$true;sheet=$sheetName;address=$address;value=$value})
}
if($op -eq 'cell.write'){
  try{$range.Value2=$req.value}catch{
    Emit ([ordered]@{ok=$false;error_code='EXCEL_COM_WRITE_FAILED';attempted=$true;retry_safe=$false;exception=$_.Exception.GetType().Name}) 9
  }
  $observed=$range.Value2
  $matched=($observed -eq $req.value)
  Emit ([ordered]@{ok=$true;verified=[bool]$matched;attempted=$true;retry_safe=$false;sheet=$sheetName;address=$address;value=$observed})
}
if($op -eq 'range.write'){
  $rows=[int]$range.Rows.Count;$cols=[int]$range.Columns.Count
  $matrix=@($req.value)
  if($matrix.Count -ne $rows){
    Emit ([ordered]@{ok=$false;error_code='EXCEL_RANGE_SHAPE_MISMATCH';attempted=$false;expected_rows=$rows;actual_rows=$matrix.Count}) 10
  }
  try{
    for($rr=1;$rr -le $rows;$rr++){
      $row=@($matrix[$rr-1])
      if($row.Count -ne $cols){throw 'SHAPE'}
      for($cc=1;$cc -le $cols;$cc++){$range.Cells.Item($rr,$cc).Value2=$row[$cc-1]}
    }
  }catch{
    $attempted=($_.Exception.Message -ne 'SHAPE')
    Emit ([ordered]@{ok=$false;error_code=($(if($attempted){'EXCEL_COM_WRITE_FAILED'}else{'EXCEL_RANGE_SHAPE_MISMATCH'}));attempted=[bool]$attempted;retry_safe=(-not $attempted)}) 11
  }
  $observed=ReadMatrix $range
  Emit ([ordered]@{ok=$true;verified=$true;attempted=$true;retry_safe=$false;sheet=$sheetName;address=$address;value=$observed})
}
Emit ([ordered]@{ok=$false;error_code='ACTION_UNSUPPORTED';attempted=$false;operation=$op}) 12
"""


class ExcelPowerShellComAppApiExecutor:
    name = "excel_powershell_com"
    priority = 290

    def __init__(self, fastpath: Any, *, executable: str | None = None):
        self.fastpath = fastpath
        self.executable = executable or shutil.which("powershell.exe") or shutil.which("powershell")

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "priority": self.priority,
            "backend_route": "APP_EXCEL_POWERSHELL_COM",
            "local_only": True,
            "capabilities": {name: dict(value) for name, value in _EXCEL_CAPABILITIES.items()},
        }

    def close(self, handle: AppApiHandle) -> dict[str, Any]:
        return {"ok": True, "closed": False, "reason": "stateless"}

    def _call(
        self,
        operation: str,
        payload: Mapping[str, Any] | None = None,
        *,
        mutation: bool = False,
        timeout_s: float = 8.0,
    ) -> dict[str, Any]:
        if os.name != "nt" or not self.executable:
            raise AppApiError("EXCEL_POWERSHELL_COM_UNAVAILABLE", attempted=False)
        request = {"operation": operation, **dict(payload or {})}
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            completed = subprocess.run(
                [
                    self.executable, "-NoLogo", "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass", "-Command", _EXCEL_POWERSHELL_SCRIPT,
                ],
                input=json.dumps(request, ensure_ascii=False).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=max(1.0, float(timeout_s)),
                creationflags=flags,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AppApiError(
                "EXCEL_POWERSHELL_COM_TIMEOUT",
                attempted=mutation,
                details={"retry_safe": not mutation},
            ) from exc
        except OSError as exc:
            raise AppApiError(
                "EXCEL_POWERSHELL_COM_UNAVAILABLE",
                attempted=False,
                details={"exception": type(exc).__name__},
            ) from exc
        stdout = completed.stdout.decode("utf-8-sig", errors="replace").strip()
        try:
            result = json.loads(stdout) if stdout else {}
        except json.JSONDecodeError as exc:
            raise AppApiError(
                "EXCEL_POWERSHELL_COM_INVALID_JSON",
                attempted=mutation,
                details={"retry_safe": not mutation, "exit_code": int(completed.returncode)},
            ) from exc
        if completed.returncode != 0 or result.get("ok") is not True:
            attempted = bool(result.get("attempted", mutation))
            details = {k: v for k, v in result.items() if k not in {"ok", "error_code", "attempted"}}
            details.setdefault("retry_safe", not attempted)
            raise AppApiError(
                str(result.get("error_code") or "EXCEL_POWERSHELL_COM_FAILED"),
                attempted=attempted,
                details=details,
            )
        return dict(result)

    @staticmethod
    def _select_descriptor(
        descriptors: list[dict[str, Any]], hwnd: int | None,
    ) -> dict[str, Any] | None:
        if hwnd is not None:
            matches = [
                item for item in descriptors
                if hwnd in [int(v) for v in item.get("window_hwnds", []) if v is not None]
            ]
        else:
            matches = list(descriptors)
        if not matches:
            return None
        if len(matches) > 1:
            raise AppApiError(
                "EXCEL_COM_TARGET_AMBIGUOUS",
                attempted=False,
                details={"matches": len(matches), "reason": "powershell_com_probe"},
            )
        return dict(matches[0])

    def probe(
        self,
        app: str,
        *,
        refresh: bool = False,
        discovered: Mapping[str, Any] | None = None,
    ) -> AppApiHandle | None:
        if app.strip().casefold() not in _EXCEL_APP_NAMES:
            return None
        found: dict[str, Any] = dict(discovered or {})
        if discovered is None:
            try:
                found = dict(self.fastpath.discover(app, refresh=refresh))
            except FastPathError as exc:
                if exc.code != "APP_WINDOW_NOT_FOUND":
                    raise AppApiError(exc.code, attempted=False, details=exc.details) from exc
                found = {
                    "app": app,
                    "route": "APP_EXCEL_POWERSHELL_COM",
                    "window": None,
                    "cdp": None,
                    "programmatic_only": True,
                }
        window = found.get("window")
        hwnd = _excel_hwnd(window.get("hwnd")) if isinstance(window, Mapping) else None
        result = self._call("probe")
        descriptors = [
            dict(item) for item in result.get("workbooks", [])
            if isinstance(item, Mapping)
        ]
        descriptor = self._select_descriptor(descriptors, hwnd)
        if descriptor is None:
            return None
        discovery = dict(found)
        discovery["excel"] = {
            "name": str(descriptor.get("name") or ""),
            "full_name": str(descriptor.get("full_name") or ""),
            "path": str(descriptor.get("path") or ""),
            "saved": bool(descriptor.get("saved", False)),
            "window_hwnd": hwnd,
            "provider": "powershell_com",
            "programmatic_only": hwnd is None,
        }
        native_key = f"native:hwnd:{hwnd}" if hwnd is not None else None
        workbook_key = _excel_workbook_resource_key(descriptor)
        resource_keys = tuple(key for key in (native_key, workbook_key) if key)
        return AppApiHandle(
            executor=self.name,
            app=app,
            backend_route="APP_EXCEL_POWERSHELL_COM",
            discovery=discovery,
            capabilities={name: dict(value) for name, value in _EXCEL_CAPABILITIES.items()},
            resource_key=native_key or workbook_key,
            resource_keys=resource_keys,
        )

    def action(
        self,
        handle: AppApiHandle,
        intent: str,
        *,
        action_args: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if intent not in handle.capabilities:
            raise AppApiError("ACTION_UNSUPPORTED", attempted=False, details={"intent": intent})
        excel = handle.discovery.get("excel")
        if not isinstance(excel, Mapping):
            raise AppApiError("STALE_TARGET", attempted=False, details={"retry_safe": True})
        payload: dict[str, Any] = {
            "identity": {
                "name": str(excel.get("name") or ""),
                "full_name": str(excel.get("full_name") or ""),
            }
        }
        args = dict(action_args or {})
        if intent != "inspect":
            sheet = str(args.get("sheet") or "").strip()
            if not sheet or len(sheet) > 31:
                raise AppApiError("EXCEL_SHEET_REQUIRED", attempted=False)
            single = intent.startswith("cell.")
            address = _excel_validate_address(args.get("address"), single_cell=single)
            payload.update({"sheet": sheet, "address": address})
        if intent in {"cell.write", "range.write"}:
            if "value" not in args:
                raise AppApiError("EXCEL_VALUE_REQUIRED", attempted=False)
            if _excel_has_formula_like_value(args["value"]):
                raise AppApiError("EXCEL_FORMULA_REQUIRES_EXPLICIT_INTENT", attempted=False)
            payload["value"] = args["value"]
        result = self._call(
            intent, payload,
            mutation=intent in {"cell.write", "range.write"},
            timeout_s=12.0 if intent in {"range.write", "range.read"} else 8.0,
        )
        common = {
            "ok": True,
            "backend_route": handle.backend_route,
            "app_api_executor": self.name,
            "verified": bool(result.get("verified", True)),
            "attempted": bool(result.get("attempted", True)),
            "retry_safe": result.get("retry_safe", intent not in {"cell.write", "range.write"}),
            "physical_input_used": False,
        }
        if intent == "inspect":
            wb = result.get("workbook") if isinstance(result.get("workbook"), Mapping) else {}
            return {
                **common,
                "workbook": {
                    "name": str(wb.get("name") or excel.get("name") or ""),
                    "saved": bool(wb.get("saved", excel.get("saved", False))),
                    "sheet_names": list(result.get("sheet_names") or []),
                    "window_hwnd": excel.get("window_hwnd"),
                },
            }
        return {
            **common,
            "sheet": str(payload["sheet"]),
            "address": str(payload["address"]),
            "value": result.get("value"),
            "verification": {
                "mechanism": "excel_powershell_com_readback",
                "matched": bool(result.get("verified", True)),
            },
        }


class ExcelComAppApiExecutor:
    name = "excel_com"
    priority = 300

    def __init__(self, fastpath: Any, *, backend: Any | None = None):
        self.fastpath = fastpath
        self.backend = backend if backend is not None else _ExcelComBackend()

    def close(self, handle: AppApiHandle) -> dict[str, Any]:
        return {"ok": True, "closed": False, "reason": "stateless"}

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "priority": self.priority,
            "backend_route": "APP_EXCEL_COM",
            "local_only": True,
            "capabilities": {
                name: dict(value)
                for name, value in _EXCEL_CAPABILITIES.items()
                if name != "range.write"
            },
            "capabilities_expand_after_probe": True,
        }

    @staticmethod
    def _workbook_descriptor(workbook: Any) -> dict[str, Any]:
        windows: list[int] = []
        window_collection = workbook.Windows
        count = int(window_collection.Count)
        for index in range(1, count + 1):
            hwnd = _excel_hwnd(getattr(_excel_item(window_collection, index), "Hwnd", None))
            if hwnd is not None:
                windows.append(hwnd)
        return {
            "name": str(getattr(workbook, "Name", "") or ""),
            "full_name": str(getattr(workbook, "FullName", "") or ""),
            "path": str(getattr(workbook, "Path", "") or ""),
            "saved": bool(getattr(workbook, "Saved", False)),
            "window_hwnds": windows,
        }

    @classmethod
    def _find_workbook_by_hwnd(cls, app: Any, hwnd: int) -> tuple[Any, dict[str, Any]] | None:
        matches: list[tuple[Any, dict[str, Any]]] = []
        workbooks = app.Workbooks
        for index in range(1, int(workbooks.Count) + 1):
            workbook = _excel_item(workbooks, index)
            descriptor = cls._workbook_descriptor(workbook)
            if hwnd in descriptor["window_hwnds"]:
                matches.append((workbook, descriptor))
        if len(matches) > 1:
            raise AppApiError(
                "EXCEL_COM_TARGET_AMBIGUOUS",
                attempted=False,
                details={"window_hwnd": hwnd, "matches": len(matches)},
            )
        return matches[0] if matches else None

    @staticmethod
    def _same_workbook(expected: Mapping[str, Any], actual: Mapping[str, Any]) -> bool:
        expected_full = str(expected.get("full_name") or "")
        actual_full = str(actual.get("full_name") or "")
        if expected_full and actual_full:
            return expected_full.casefold() == actual_full.casefold()
        return str(expected.get("name") or "").casefold() == str(actual.get("name") or "").casefold()

    @classmethod
    def _unique_workbook(cls, app: Any) -> tuple[Any, dict[str, Any]] | None:
        workbooks = app.Workbooks
        count = int(workbooks.Count)
        if count == 0:
            return None
        if count > 1:
            raise AppApiError(
                "EXCEL_COM_TARGET_AMBIGUOUS",
                attempted=False,
                details={"matches": count, "reason": "no_visible_window_identity"},
            )
        workbook = _excel_item(workbooks, 1)
        return workbook, cls._workbook_descriptor(workbook)

    @classmethod
    def _find_workbook_by_descriptor(
        cls, app: Any, expected: Mapping[str, Any],
    ) -> tuple[Any, dict[str, Any]] | None:
        matches: list[tuple[Any, dict[str, Any]]] = []
        workbooks = app.Workbooks
        for index in range(1, int(workbooks.Count) + 1):
            workbook = _excel_item(workbooks, index)
            descriptor = cls._workbook_descriptor(workbook)
            if cls._same_workbook(expected, descriptor):
                matches.append((workbook, descriptor))
        if len(matches) > 1:
            raise AppApiError(
                "EXCEL_COM_TARGET_AMBIGUOUS",
                attempted=False,
                details={"matches": len(matches), "reason": "workbook_identity"},
            )
        return matches[0] if matches else None

    def _resolve_live(self, app: Any, handle: AppApiHandle) -> tuple[Any, dict[str, Any]]:
        excel = handle.discovery.get("excel")
        if not isinstance(excel, Mapping):
            raise AppApiError("STALE_TARGET", attempted=False, details={"retry_safe": True})
        hwnd = _excel_hwnd(excel.get("window_hwnd"))
        if hwnd is None:
            match = self._find_workbook_by_descriptor(app, excel)
            if match is None:
                raise AppApiError(
                    "STALE_TARGET", attempted=False,
                    details={"retry_safe": True, "identity": "workbook"},
                )
        else:
            match = self._find_workbook_by_hwnd(app, hwnd)
            if match is None:
                raise AppApiError(
                    "STALE_TARGET", attempted=False,
                    details={"retry_safe": True, "window_hwnd": hwnd},
                )
        workbook, descriptor = match
        if not self._same_workbook(excel, descriptor):
            raise AppApiError(
                "STALE_TARGET", attempted=False,
                details={"retry_safe": True, "window_hwnd": hwnd},
            )
        return workbook, descriptor

    def probe(
        self,
        app: str,
        *,
        refresh: bool = False,
        discovered: Mapping[str, Any] | None = None,
    ) -> AppApiHandle | None:
        if app.strip().casefold() not in _EXCEL_APP_NAMES:
            return None
        found: dict[str, Any] = dict(discovered) if discovered is not None else {}
        if discovered is None:
            try:
                found = dict(self.fastpath.discover(app, refresh=refresh))
            except FastPathError as exc:
                if exc.code != "APP_WINDOW_NOT_FOUND":
                    raise AppApiError(exc.code, attempted=False, details=exc.details) from exc
                found = {
                    "app": app,
                    "route": "APP_EXCEL_COM",
                    "window": None,
                    "cdp": None,
                    "programmatic_only": True,
                }

        window = found.get("window")
        hwnd = _excel_hwnd(window.get("hwnd")) if isinstance(window, Mapping) else None

        try:
            with self.backend.session() as raw_session:
                session = _excel_session_parts(raw_session, self.backend)
                if hwnd is None:
                    match = self._unique_workbook(session.app)
                    if match is None:
                        return None
                else:
                    match = self._find_workbook_by_hwnd(session.app, hwnd)
                    if match is None:
                        raise AppApiError(
                            "EXCEL_COM_TARGET_MISMATCH",
                            attempted=False,
                            details={"window_hwnd": hwnd},
                        )
                _workbook, descriptor = match
        except AppApiError:
            raise
        except Exception as exc:
            raise AppApiError(
                "EXCEL_COM_PROBE_FAILED",
                attempted=False,
                details={"retry_safe": True, "exception": type(exc).__name__},
            ) from exc

        discovery = dict(found)
        discovery["excel"] = {
            "name": descriptor["name"],
            "full_name": descriptor["full_name"],
            "path": descriptor["path"],
            "saved": descriptor["saved"],
            "window_hwnd": hwnd,
            "provider": session.provider,
            "programmatic_only": hwnd is None,
        }
        native_key = f"native:hwnd:{hwnd}" if hwnd is not None else None
        workbook_key = _excel_workbook_resource_key(descriptor)
        resource_keys = tuple(
            key for key in (native_key, workbook_key) if isinstance(key, str) and key
        )
        return AppApiHandle(
            executor=self.name,
            app=app,
            backend_route="APP_EXCEL_COM",
            discovery=discovery,
            capabilities={
                name: dict(value)
                for name, value in _EXCEL_CAPABILITIES.items()
                if not (session.provider == "comtypes" and name == "range.write")
            },
            resource_key=native_key or workbook_key,
            resource_keys=resource_keys,
        )

    @staticmethod
    def _worksheet(workbook: Any, action_args: Mapping[str, Any]) -> Any:
        sheet = str(action_args.get("sheet") or "").strip()
        if not sheet or len(sheet) > 31:
            raise AppApiError("EXCEL_SHEET_REQUIRED", attempted=False)
        try:
            return _excel_item(workbook.Worksheets, sheet)
        except Exception as exc:
            raise AppApiError(
                "EXCEL_SHEET_NOT_FOUND",
                attempted=False,
                details={"sheet": sheet},
            ) from exc

    @staticmethod
    def _range(worksheet: Any, action_args: Mapping[str, Any], *, single_cell: bool) -> tuple[Any, str]:
        address = _excel_validate_address(action_args.get("address"), single_cell=single_cell)
        try:
            return _excel_range(worksheet, address), address
        except Exception as exc:
            raise AppApiError(
                "EXCEL_RANGE_UNAVAILABLE",
                attempted=False,
                details={"address": address},
            ) from exc

    @staticmethod
    def _matrix_for_range(target: Any, value: Any) -> tuple[tuple[Any, ...], ...]:
        if not isinstance(value, list) or not value or not all(isinstance(row, list) and row for row in value):
            raise AppApiError("EXCEL_RANGE_VALUE_MATRIX_REQUIRED", attempted=False)
        rows = int(target.Rows.Count)
        columns = int(target.Columns.Count)
        if len(value) != rows or any(len(row) != columns for row in value):
            raise AppApiError(
                "EXCEL_RANGE_SHAPE_MISMATCH",
                attempted=False,
                details={
                    "expected_rows": rows,
                    "expected_columns": columns,
                    "actual_rows": len(value),
                    "actual_columns": [len(row) for row in value],
                },
            )
        return tuple(tuple(item for item in row) for row in value)

    def action(
        self,
        handle: AppApiHandle,
        intent: str,
        *,
        action_args: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if intent not in handle.capabilities:
            raise AppApiError(
                "ACTION_UNSUPPORTED",
                attempted=False,
                details={"intent": intent, "executor": self.name},
            )
        args = dict(action_args or {})
        try:
            with self.backend.session() as raw_session:
                session = _excel_session_parts(raw_session, self.backend)
                if intent == "range.write" and session.provider == "comtypes":
                    raise AppApiError(
                        "EXCEL_RANGE_WRITE_PROVIDER_UNSUPPORTED",
                        attempted=False,
                        details={"provider": "comtypes"},
                    )
                workbook, descriptor = self._resolve_live(session.app, handle)

                if intent == "inspect":
                    sheets = workbook.Worksheets
                    names = [
                        str(getattr(_excel_item(sheets, index), "Name", "") or "")
                        for index in range(1, int(sheets.Count) + 1)
                    ]
                    return {
                        "ok": True,
                        "backend_route": handle.backend_route,
                        "app_api_executor": self.name,
                        "verified": True,
                        "attempted": True,
                        "retry_safe": True,
                        "physical_input_used": False,
                        "workbook": {
                            "name": descriptor["name"],
                            "saved": descriptor["saved"],
                            "sheet_names": names,
                            "window_hwnd": handle.discovery["excel"]["window_hwnd"],
                        },
                    }

                single_cell = intent.startswith("cell.")
                worksheet = self._worksheet(workbook, args)
                target, address = self._range(worksheet, args, single_cell=single_cell)

                if intent in {"cell.read", "range.read"}:
                    return {
                        "ok": True,
                        "backend_route": handle.backend_route,
                        "app_api_executor": self.name,
                        "verified": True,
                        "attempted": True,
                        "retry_safe": True,
                        "physical_input_used": False,
                        "sheet": str(args["sheet"]),
                        "address": address,
                        "value": _excel_json_value(target.Value2),
                    }

                if "value" not in args:
                    raise AppApiError("EXCEL_VALUE_REQUIRED", attempted=False)
                requested = args["value"]
                if _excel_has_formula_like_value(requested):
                    raise AppApiError(
                        "EXCEL_FORMULA_REQUIRES_EXPLICIT_INTENT",
                        attempted=False,
                    )
                if single_cell:
                    if isinstance(requested, (list, tuple, Mapping)):
                        raise AppApiError("EXCEL_CELL_VALUE_SCALAR_REQUIRED", attempted=False)
                    assigned = requested
                else:
                    assigned = self._matrix_for_range(target, requested)

                try:
                    target.Value2 = assigned
                    observed = _excel_json_value(target.Value2)
                except Exception as exc:
                    raise AppApiError(
                        "EXCEL_COM_WRITE_FAILED",
                        attempted=True,
                        details={
                            "retry_safe": False,
                            "exception": type(exc).__name__,
                            "sheet": str(args.get("sheet") or ""),
                            "address": address,
                        },
                    ) from exc

                expected = _excel_json_value(assigned)
                verified = _excel_values_equivalent(expected, observed)
                return {
                    "ok": True,
                    "backend_route": handle.backend_route,
                    "app_api_executor": self.name,
                    "verified": verified,
                    "attempted": True,
                    "retry_safe": False,
                    "physical_input_used": False,
                    "sheet": str(args["sheet"]),
                    "address": address,
                    "value": observed,
                    "verification": {
                        "mechanism": "excel_com_readback",
                        "matched": verified,
                    },
                }
        except AppApiError:
            raise
        except Exception as exc:
            raise AppApiError(
                "EXCEL_COM_ACTION_FAILED",
                attempted=False,
                details={"retry_safe": True, "exception": type(exc).__name__},
            ) from exc


_WINAPP_CAPABILITIES: dict[str, dict[str, Any]] = {
    "inspect": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": False, "verified_capable": True,
    },
    "read": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": False, "verified_capable": True,
    },
    "type": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": True, "verified_capable": True,
    },
    "set_value": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": True, "verified_capable": True,
    },
    "invoke": {
        "background_safe": False, "desktop_exclusive": True,
        "mutation": True, "verified_capable": True,
    },
    "wait_for": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": False, "verified_capable": True,
    },
}


def _winapp_positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(str(value), 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None



_WINAPP_PERSISTENT_SIDECAR_SHA256 = "723ceb00c22ca262a2c26c74a648eddce3fbfd6d5528625cd020639041492d9a"
_WINAPP_PERSISTENT_SIDECAR_BYTES = 122291829
_WINAPP_PERSISTENT_SIDECAR_DIR = "winapp061-ff-sidecar"
_WINAPP_PERSISTENT_HASH_CACHE: dict[tuple[str, int, int], str] = {}


def _sha256_file_cached(path: Path, stat_result: os.stat_result) -> str:
    key = (str(path), int(stat_result.st_size), int(stat_result.st_mtime_ns))
    cached = _WINAPP_PERSISTENT_HASH_CACHE.get(key)
    if cached is not None:
        return cached
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    value = digest.hexdigest()
    if len(_WINAPP_PERSISTENT_HASH_CACHE) >= 8:
        _WINAPP_PERSISTENT_HASH_CACHE.clear()
    _WINAPP_PERSISTENT_HASH_CACHE[key] = value
    return value


def _attested_winapp_sidecar_path() -> str | None:
    local_app_data = str(os.environ.get("LOCALAPPDATA") or "").strip()
    if not local_app_data:
        return None
    path = (
        Path(local_app_data)
        / "FF-Windows-Bridge"
        / "toolcache"
        / _WINAPP_PERSISTENT_SIDECAR_DIR
        / "winapp.exe"
    )
    try:
        stat_result = path.stat()
        if not path.is_file() or stat_result.st_size != _WINAPP_PERSISTENT_SIDECAR_BYTES:
            return None
        if (
            _sha256_file_cached(path, stat_result)
            != _WINAPP_PERSISTENT_SIDECAR_SHA256
        ):
            return None
    except OSError:
        return None
    return str(path)


class _WinAppCliBackend:
    _SIDECAR_COMMANDS = frozenset({
        "inspect", "search", "get-property", "get-value", "set-value",
        "invoke", "wait-for", "scroll-into-view",
    })
    _SIDECAR_MUTATIONS = frozenset({"set-value", "invoke", "scroll-into-view"})

    def __init__(
        self,
        executable: str | None = None,
        *,
        sidecar: Any | None = None,
        sidecar_executable: str | None = None,
    ) -> None:
        explicit_sidecar = (
            sidecar_executable
            or str(os.environ.get("FF_WINAPP_PERSISTENT_EXE") or "").strip()
            or None
        )
        configured_sidecar = explicit_sidecar
        if configured_sidecar is not None and not Path(configured_sidecar).is_file():
            configured_sidecar = None
        if sidecar is None and explicit_sidecar is None:
            configured_sidecar = _attested_winapp_sidecar_path()
        self.executable = (
            executable
            or configured_sidecar
            or shutil.which("winapp.exe")
            or shutil.which("winapp")
        )
        self.sidecar = sidecar
        self.sidecar_source = (
            "explicit"
            if configured_sidecar is not None and explicit_sidecar is not None
            else (
                "attested_toolcache"
                if configured_sidecar is not None and explicit_sidecar is None
                else None
            )
        )
        if self.sidecar is None and configured_sidecar is not None:
            self.sidecar = WinAppPersistentRunner(
                [configured_sidecar, "__ff_bridge_sidecar"]
            )

    def available(self) -> bool:
        return os.name == "nt" and bool(self.executable)

    @staticmethod
    def hwnd_pid(hwnd: int) -> int | None:
        if os.name != "nt" or hwnd <= 0:
            return None
        try:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            get_pid = user32.GetWindowThreadProcessId
            get_pid.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
            get_pid.restype = ctypes.c_ulong
            pid = ctypes.c_ulong(0)
            thread_id = get_pid(ctypes.c_void_p(hwnd), ctypes.byref(pid))
            if not thread_id or not pid.value:
                return None
            return int(pid.value)
        except Exception:
            return None

    @staticmethod
    def hwnd_class_name(hwnd: int) -> str | None:
        if os.name != "nt" or hwnd <= 0:
            return None
        try:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            get_class_name = user32.GetClassNameW
            get_class_name.restype = ctypes.c_int
            buffer = ctypes.create_unicode_buffer(512)
            copied = get_class_name(ctypes.c_void_p(hwnd), buffer, len(buffer))
            return buffer.value if copied > 0 else None
        except Exception:
            return None

    @classmethod
    def _sidecar_eligible(cls, argv: list[str]) -> bool:
        return (
            len(argv) >= 2
            and argv[0] == "ui"
            and argv[1] in cls._SIDECAR_COMMANDS
            and "--json" in argv
            and ("-w" in argv or "--window" in argv)
        )

    def _run_one_shot(
        self, argv: list[str], *, timeout_s: float
    ) -> tuple[Any, int]:
        if not self.executable:
            raise AppApiError("WINAPP_CLI_UNAVAILABLE", attempted=False)
        started = time.perf_counter()
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            completed = subprocess.run(
                [self.executable, *argv],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                timeout=max(0.25, float(timeout_s)),
                creationflags=flags,
            )
        except subprocess.TimeoutExpired as exc:
            raise AppApiError("WINAPP_CLI_TIMEOUT", attempted=False) from exc
        except OSError as exc:
            raise AppApiError(
                "WINAPP_CLI_UNAVAILABLE",
                attempted=False,
                details={"exception": type(exc).__name__},
            ) from exc
        return completed, int((time.perf_counter() - started) * 1000)

    def _execute(
        self,
        argv: list[str],
        *,
        timeout_s: float,
        mutation_attempted: bool,
    ) -> tuple[Any, int]:
        sidecar = self.sidecar
        command_mutates = len(argv) >= 2 and argv[1] in self._SIDECAR_MUTATIONS
        if sidecar is not None and self._sidecar_eligible(argv):
            try:
                result = sidecar.execute(
                    argv, timeout_seconds=max(0.25, float(timeout_s))
                )
                return result, int(result.elapsed_ms)
            except WinAppSidecarError as exc:
                # Never replay a mutation whose request reached the sidecar:
                # its outcome is unknown after a transport failure. Read-only
                # commands are safe to replay with the existing one-shot path.
                if exc.attempted and command_mutates:
                    raise AppApiError(
                        exc.code,
                        attempted=True,
                        details={
                            **exc.details,
                            "retry_safe": False,
                            "transport": "persistent_sidecar",
                        },
                    ) from exc
                if not self.executable:
                    raise AppApiError(
                        exc.code,
                        attempted=bool(exc.attempted and mutation_attempted),
                        details={
                            **exc.details,
                            "retry_safe": not mutation_attempted,
                            "transport": "persistent_sidecar",
                        },
                    ) from exc
        return self._run_one_shot(argv, timeout_s=timeout_s)

    def run_json(
        self,
        argv: list[str],
        *,
        timeout_s: float = 5.0,
        allowed_codes: tuple[int, ...] = (0,),
        mutation_attempted: bool = False,
    ) -> tuple[dict[str, Any], int, int]:
        if not self.available() or not self.executable:
            raise AppApiError("WINAPP_CLI_UNAVAILABLE", attempted=False)
        try:
            completed, elapsed_ms = self._execute(
                argv,
                timeout_s=timeout_s,
                mutation_attempted=mutation_attempted,
            )
        except AppApiError as exc:
            if exc.code == "WINAPP_CLI_TIMEOUT":
                attempted = bool(exc.attempted or mutation_attempted)
                raise AppApiError(
                    exc.code,
                    attempted=attempted,
                    details={**exc.details, "retry_safe": not attempted},
                ) from exc
            raise
        if completed.returncode not in allowed_codes:
            raise AppApiError(
                "WINAPP_CLI_FAILED",
                attempted=mutation_attempted,
                details={
                    "retry_safe": not mutation_attempted,
                    "exit_code": int(completed.returncode),
                },
            )
        stdout = completed.stdout.decode("utf-8-sig", errors="replace").strip()
        if not stdout:
            payload: dict[str, Any] = {}
        else:
            try:
                decoded = json.loads(stdout)
            except json.JSONDecodeError as exc:
                raise AppApiError(
                    "WINAPP_OUTPUT_INVALID",
                    attempted=mutation_attempted,
                    details={"retry_safe": not mutation_attempted},
                ) from exc
            if not isinstance(decoded, Mapping):
                raise AppApiError(
                    "WINAPP_OUTPUT_INVALID",
                    attempted=mutation_attempted,
                    details={"retry_safe": not mutation_attempted},
                )
            payload = dict(decoded)
        return payload, elapsed_ms, int(completed.returncode)


class WinAppCliAppApiExecutor:
    """Generic Windows UIA fallback using Microsoft's WinApp CLI.

    Read/value operations stay background-safe. Semantic invoke is exposed as
    verified structured UIA but remains desktop-exclusive: live WPF proof showed
    InvokePattern can activate the target window even when WinForms did not.
    Input injection verbs (click/send-keys/drag/touch/pen/wheel) are absent.
    """

    name = "winapp_cli"
    priority = 50
    experience_learnable = False

    def __init__(self, fastpath: Any, *, backend: Any | None = None) -> None:
        self.fastpath = fastpath
        self.backend = backend if backend is not None else _WinAppCliBackend()

    def close(self, handle: AppApiHandle) -> dict[str, Any]:
        return {"ok": True, "closed": False, "reason": "stateless"}

    def describe(self) -> dict[str, Any]:
        try:
            available = bool(self.backend.available())
        except Exception:
            available = False
        return {
            "name": self.name,
            "priority": self.priority,
            "backend_route": "APP_WINAPP_UIA",
            "local_only": True,
            "available": available,
            "exact_hwnd_binding": True,
            "experience_learnable": False,
            "capabilities": {
                name: dict(value) for name, value in _WINAPP_CAPABILITIES.items()
            },
        }

    @staticmethod
    def _window_parts(discovery: Mapping[str, Any]) -> tuple[int, int] | None:
        window = discovery.get("window")
        if not isinstance(window, Mapping):
            return None
        hwnd = _winapp_positive_int(window.get("hwnd"))
        pid = _winapp_positive_int(window.get("pid"))
        if hwnd is None or pid is None:
            return None
        return hwnd, pid

    def _revalidate(self, handle: AppApiHandle) -> tuple[int, int]:
        winapp = handle.discovery.get("winapp")
        if not isinstance(winapp, Mapping):
            raise AppApiError(
                "STALE_TARGET", attempted=False, details={"retry_safe": True}
            )
        hwnd = _winapp_positive_int(winapp.get("hwnd"))
        pid = _winapp_positive_int(winapp.get("pid"))
        if hwnd is None or pid is None:
            raise AppApiError(
                "STALE_TARGET", attempted=False, details={"retry_safe": True}
            )
        try:
            current_pid = self.backend.hwnd_pid(hwnd)
        except Exception:
            current_pid = None
        if current_pid != pid:
            raise AppApiError(
                "STALE_TARGET",
                attempted=False,
                details={"retry_safe": True, "window_hwnd": hwnd},
            )
        return hwnd, pid

    @staticmethod
    def _selector(args: Mapping[str, Any]) -> str:
        selector = str(args.get("selector") or args.get("target") or "").strip()
        if not selector or len(selector) > 4096:
            raise AppApiError("WINAPP_SELECTOR_REQUIRED", attempted=False)
        return selector

    @staticmethod
    def _read_value(payload: Mapping[str, Any]) -> Any:
        if "text" in payload:
            return payload.get("text")
        return payload.get("value")

    @staticmethod
    def _search_matches(payload: Mapping[str, Any]) -> list[Mapping[str, Any]]:
        for key in ("matches", "elements"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, Mapping)]
        raise AppApiError(
            "WINAPP_OUTPUT_INVALID",
            attempted=False,
            details={"retry_safe": True, "operation": "search"},
        )

    @staticmethod
    def _is_winforms_class(value: Any) -> bool:
        return isinstance(value, str) and value.startswith("WindowsForms10.")

    def _invoke_target_safety(
        self, hwnd: int, target_match: Mapping[str, Any]
    ) -> dict[str, Any]:
        reader = getattr(self.backend, "hwnd_class_name", None)
        try:
            window_class = reader(hwnd) if callable(reader) else None
        except Exception:
            window_class = None
        target_class = target_match.get("className")
        control_type = target_match.get("type")
        background_safe = (
            self._is_winforms_class(window_class)
            and isinstance(target_class, str)
            and target_class.startswith("WindowsForms10.BUTTON.")
            and control_type in {"Button", "CheckBox", "RadioButton"}
        )
        return {
            "background_safe": background_safe,
            "desktop_exclusive": not background_safe,
            "window_class": window_class,
            "target_class": target_class,
            "control_type": control_type,
            "basis": (
                "verified_winforms_button_window_and_target_class"
                if background_safe and control_type == "Button"
                else (
                    "verified_winforms_stateful_button_family_window_and_target_class"
                    if background_safe
                    else "default_desktop_exclusive"
                )
            ),
        }

    def capability_for(
        self,
        handle: AppApiHandle,
        intent: str,
        *,
        action_args: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        capability = dict(handle.capabilities.get(intent) or {})
        if intent != "invoke":
            return capability
        args = dict(action_args or {})
        hwnd, _pid = self._revalidate(handle)
        selector = self._selector(args)
        target_match, _search_ms = self._unique_search(hwnd, selector)
        if target_match.get("isInvokable") is not True:
            raise AppApiError(
                "ACTION_UNSUPPORTED",
                attempted=False,
                details={"selector": selector, "reason": "target_not_invokable"},
            )
        safety = self._invoke_target_safety(hwnd, target_match)
        capability["background_safe"] = bool(safety["background_safe"])
        capability["desktop_exclusive"] = bool(safety["desktop_exclusive"])
        capability["safety_preflight"] = safety
        return capability

    def _unique_search(
        self, hwnd: int, selector: str
    ) -> tuple[Mapping[str, Any], int]:
        payload, latency_ms, _ = self.backend.run_json(
            ["ui", "search", selector, "-w", str(hwnd), "--json"],
            timeout_s=5.0,
        )
        matches = self._search_matches(payload)
        count = payload.get("matchCount")
        if isinstance(count, bool) or not isinstance(count, int):
            count = len(matches)
        if count == 0:
            raise AppApiError(
                "NO_MATCH",
                attempted=False,
                details={"retry_safe": True, "selector": selector},
            )
        if count != 1 or len(matches) != 1:
            raise AppApiError(
                "TARGET_AMBIGUOUS",
                attempted=False,
                details={
                    "retry_safe": False,
                    "selector": selector,
                    "match_count": int(count),
                },
            )
        return matches[0], latency_ms

    @staticmethod
    def _invoke_verification(
        args: Mapping[str, Any],
    ) -> tuple[str, str, str, int]:
        verify = args.get("verify")
        if not isinstance(verify, Mapping):
            raise AppApiError("WINAPP_VERIFICATION_REQUIRED", attempted=False)
        selector = str(
            verify.get("selector") or verify.get("target") or ""
        ).strip()
        if not selector or len(selector) > 4096:
            raise AppApiError("WINAPP_VERIFICATION_SELECTOR_REQUIRED", attempted=False)
        prop = verify.get("property")
        if prop not in {"Name", "ToggleState", "IsSelected"}:
            raise AppApiError(
                "WINAPP_VERIFICATION_PROPERTY_UNSUPPORTED",
                attempted=False,
                details={"property": prop},
            )
        expected = verify.get("value")
        if not isinstance(expected, str):
            raise AppApiError("WINAPP_VERIFICATION_VALUE_REQUIRED", attempted=False)
        timeout_ms = verify.get("timeout_ms", 3000)
        if (
            isinstance(timeout_ms, bool)
            or not isinstance(timeout_ms, (int, float))
            or not 1 <= float(timeout_ms) <= 30000
        ):
            raise AppApiError("TIMEOUT_INVALID", attempted=False)
        return selector, str(prop), expected, int(timeout_ms)

    def probe(
        self,
        app: str,
        *,
        refresh: bool = False,
        discovered: Mapping[str, Any] | None = None,
    ) -> AppApiHandle | None:
        try:
            if not self.backend.available():
                return None
        except Exception:
            return None
        try:
            found = dict(discovered) if discovered is not None else dict(
                self.fastpath.discover(app, refresh=refresh)
            )
        except FastPathError as exc:
            if exc.code == "APP_WINDOW_NOT_FOUND":
                return None
            raise AppApiError(exc.code, attempted=False, details=exc.details) from exc
        parts = self._window_parts(found)
        if parts is None:
            return None
        hwnd, pid = parts
        try:
            if self.backend.hwnd_pid(hwnd) != pid:
                return None
            self.backend.run_json(
                ["ui", "inspect", "-w", str(hwnd), "--depth", "1", "--json"],
                timeout_s=4.0,
            )
        except AppApiError:
            return None
        except Exception:
            return None
        discovery = dict(found)
        discovery["winapp"] = {"hwnd": hwnd, "pid": pid}
        native_key = f"native:hwnd:{hwnd}"
        return AppApiHandle(
            executor=self.name,
            app=app,
            backend_route="APP_WINAPP_UIA",
            discovery=discovery,
            capabilities={
                name: dict(value) for name, value in _WINAPP_CAPABILITIES.items()
            },
            resource_key=native_key,
            resource_keys=(native_key,),
        )

    def action(
        self,
        handle: AppApiHandle,
        intent: str,
        *,
        action_args: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if intent not in handle.capabilities:
            raise AppApiError(
                "ACTION_UNSUPPORTED",
                attempted=False,
                details={"intent": intent, "executor": self.name},
            )
        args = dict(action_args or {})
        hwnd, _pid = self._revalidate(handle)

        if intent == "inspect":
            depth = args.get("depth", 5)
            if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= 8:
                raise AppApiError("WINAPP_DEPTH_INVALID", attempted=False)
            payload, latency_ms, _ = self.backend.run_json(
                ["ui", "inspect", "-w", str(hwnd), "--depth", str(depth), "--json"],
                timeout_s=6.0,
            )
            return {
                "ok": True,
                "backend_route": handle.backend_route,
                "app_api_executor": self.name,
                "verified": True,
                "attempted": True,
                "retry_safe": True,
                "physical_input_used": False,
                "latency_ms": latency_ms,
                "tree": payload,
            }

        selector = self._selector(args)
        if intent == "invoke":
            (
                verify_selector,
                verify_property,
                verify_value,
                verify_timeout_ms,
            ) = self._invoke_verification(args)
            target_match, target_search_ms = self._unique_search(hwnd, selector)
            if target_match.get("isInvokable") is not True:
                raise AppApiError(
                    "ACTION_UNSUPPORTED",
                    attempted=False,
                    details={"selector": selector, "reason": "target_not_invokable"},
                )
            safety = self._invoke_target_safety(hwnd, target_match)
            if args.get("_background_required") is True and not safety["background_safe"]:
                raise AppApiError(
                    "WINAPP_BACKGROUND_SAFETY_PRECONDITION_FAILED",
                    attempted=False,
                    details={
                        "retry_safe": True,
                        "selector": selector,
                        "safety_preflight": safety,
                    },
                )
            if verify_selector == selector:
                verify_search_ms = 0
            else:
                _verify_match, verify_search_ms = self._unique_search(
                    hwnd, verify_selector
                )
            invoke_payload, invoke_ms, _ = self.backend.run_json(
                ["ui", "invoke", selector, "-w", str(hwnd), "--json"],
                timeout_s=5.0,
                mutation_attempted=True,
            )
            verify_payload, verify_ms, verify_exit = self.backend.run_json(
                [
                    "ui", "wait-for", verify_selector,
                    "-w", str(hwnd),
                    "--property", verify_property,
                    "--value", verify_value,
                    "--timeout", str(verify_timeout_ms),
                    "--json",
                ],
                timeout_s=max(2.0, verify_timeout_ms / 1000.0 + 2.0),
                allowed_codes=(0, 1),
                mutation_attempted=True,
            )
            verified = (
                verify_exit == 0
                and verify_payload.get("found") is True
                and verify_payload.get("timedOut") is not True
            )
            return {
                "ok": True,
                "backend_route": handle.backend_route,
                "app_api_executor": self.name,
                "verified": verified,
                "attempted": True,
                "retry_safe": False,
                "physical_input_used": False,
                "background_safe": bool(safety["background_safe"]),
                "desktop_exclusive": bool(safety["desktop_exclusive"]),
                "safety_preflight": safety,
                "latency_ms": (
                    target_search_ms + verify_search_ms + invoke_ms + verify_ms
                ),
                "selector": selector,
                "invoke_result": invoke_payload,
                "verification": {
                    "mechanism": "winapp_wait_for_property",
                    "matched": verified,
                    "selector": verify_selector,
                    "property": verify_property,
                    "expected": verify_value,
                },
            }

        if intent == "read":
            payload, latency_ms, _ = self.backend.run_json(
                ["ui", "get-value", selector, "-w", str(hwnd), "--json"],
                timeout_s=5.0,
            )
            return {
                "ok": True,
                "backend_route": handle.backend_route,
                "app_api_executor": self.name,
                "verified": True,
                "attempted": True,
                "retry_safe": True,
                "physical_input_used": False,
                "latency_ms": latency_ms,
                "selector": selector,
                "value": self._read_value(payload),
            }

        if intent in {"type", "set_value"}:
            field = "text" if intent == "type" else "value"
            if field not in args or not isinstance(args[field], str):
                raise AppApiError(
                    "WINAPP_VALUE_REQUIRED" if intent == "set_value" else "WINAPP_TEXT_REQUIRED",
                    attempted=False,
                )
            requested = args[field]
            _set_payload, set_ms, _ = self.backend.run_json(
                ["ui", "set-value", selector, requested, "-w", str(hwnd), "--json"],
                timeout_s=5.0,
                mutation_attempted=True,
            )
            observed_payload, read_ms, _ = self.backend.run_json(
                ["ui", "get-value", selector, "-w", str(hwnd), "--json"],
                timeout_s=5.0,
                mutation_attempted=True,
            )
            observed = self._read_value(observed_payload)
            verified = observed == requested
            return {
                "ok": True,
                "backend_route": handle.backend_route,
                "app_api_executor": self.name,
                "verified": verified,
                "attempted": True,
                "retry_safe": False,
                "physical_input_used": False,
                "latency_ms": set_ms + read_ms,
                "selector": selector,
                "value": observed,
                "verification": {
                    "mechanism": "winapp_get_value_readback",
                    "matched": verified,
                },
            }

        timeout_ms = args.get("timeout_ms", 5000)
        if (
            isinstance(timeout_ms, bool)
            or not isinstance(timeout_ms, (int, float))
            or not 1 <= float(timeout_ms) <= 30000
        ):
            raise AppApiError("TIMEOUT_INVALID", attempted=False)
        command = [
            "ui", "wait-for", selector, "-w", str(hwnd),
            "--timeout", str(int(timeout_ms)), "--json",
        ]
        if "value" in args:
            if not isinstance(args["value"], str):
                raise AppApiError("WINAPP_WAIT_VALUE_INVALID", attempted=False)
            command.extend(["--value", args["value"]])
        payload, latency_ms, exit_code = self.backend.run_json(
            command,
            timeout_s=max(2.0, float(timeout_ms) / 1000.0 + 2.0),
            allowed_codes=(0, 1),
        )
        found = payload.get("found") is True
        if exit_code != 0 or not found:
            raise AppApiError(
                "WINAPP_WAIT_TIMEOUT",
                attempted=False,
                details={"retry_safe": True, "selector": selector},
            )
        return {
            "ok": True,
            "backend_route": handle.backend_route,
            "app_api_executor": self.name,
            "verified": True,
            "attempted": True,
            "retry_safe": True,
            "physical_input_used": False,
            "latency_ms": latency_ms,
            "selector": selector,
            "found": True,
        }


_CDP_CAPABILITIES: dict[str, dict[str, Any]] = {
    "panel.inspect": {"background_safe": True, "desktop_exclusive": False, "mutation": False, "verified_capable": True},
    "panel.verify": {"background_safe": True, "desktop_exclusive": False, "mutation": False, "verified_capable": True},
    "panel.type": {"background_safe": True, "desktop_exclusive": False, "mutation": True, "verified_capable": True},
    "panel.invoke": {"background_safe": True, "desktop_exclusive": False, "mutation": True, "verified_capable": True},
    "inspect": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": False, "verified_capable": True,
    },
    "read": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": False, "verified_capable": True,
    },
    "type": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": True, "verified_capable": True,
    },
    "chat.send": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": True, "verified_capable": True,
    },
    "click": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": True, "verified_capable": False,
    },
    "chat.new": {
        "background_safe": True, "desktop_exclusive": False,
        "mutation": True, "verified_capable": False,
    },
}


class CdpAppApiExecutor:
    name = "cdp"
    priority = 100

    def __init__(self, fastpath: Any):
        self.fastpath = fastpath

    def close(self, handle: AppApiHandle) -> dict[str, Any]:
        return {"ok": True, "closed": False, "reason": "stateless"}

    def describe(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "priority": self.priority,
            "backend_route": "APP_CDP",
            "local_only": True,
            "capabilities": {
                name: dict(value) for name, value in _CDP_CAPABILITIES.items()
            },
        }


    def probe(
        self,
        app: str,
        *,
        refresh: bool = False,
        discovered: Mapping[str, Any] | None = None,
    ) -> AppApiHandle | None:
        try:
            found = dict(discovered) if discovered is not None else dict(
                self.fastpath.discover(app, refresh=refresh)
            )
        except FastPathError as exc:
            raise AppApiError(
                exc.code, attempted=False, details=exc.details
            ) from exc
        if found.get("route") != "APP_CDP":
            return None
        if not isinstance(found.get("cdp"), Mapping):
            return None
        return AppApiHandle(
            executor=self.name,
            app=app,
            backend_route="APP_CDP",
            discovery=found,
            capabilities={
                name: dict(value) for name, value in _CDP_CAPABILITIES.items()
            },
        )


    def action(
        self,
        handle: AppApiHandle,
        intent: str,
        *,
        action_args: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        if intent not in handle.capabilities:
            raise AppApiError(
                "ACTION_UNSUPPORTED",
                attempted=False,
                details={"intent": intent, "executor": self.name},
            )
        args = dict(action_args or {})
        text = str(args.get("text") or "")
        target = str(args.get("target") or "")
        try:
            result = dict(self.fastpath.panel_action(handle.discovery, intent, action_args=args)) if intent.startswith("panel.") else dict(
                self.fastpath.action(
                    handle.discovery, intent, text=text, target=target
                )
            )
        except FastPathError as exc:
            attempted = bool(exc.details.get("attempted", False))
            if "attempted" not in exc.details and exc.code != "STALE_TARGET":
                attempted = True
            details = dict(exc.details)
            details.setdefault("retry_safe", not attempted)
            raise AppApiError(
                exc.code, attempted=attempted, details=details
            ) from exc

        result["backend_route"] = handle.backend_route
        result["app_api_executor"] = self.name
        return result


class AppApiRegistry:
    def __init__(
        self,
        executors: list[AppApiExecutor] | None = None,
        *,
        experience: Any | None = None,
    ):
        self._executors: dict[str, AppApiExecutor] = {}
        self._experience = experience
        for executor in executors or []:
            self.register(executor)

    def register(self, executor: AppApiExecutor) -> None:
        name = str(getattr(executor, "name", "") or "").strip()
        if not name:
            raise ValueError("APP_API_EXECUTOR_NAME_REQUIRED")
        if name in self._executors:
            raise ValueError(f"APP_API_EXECUTOR_DUPLICATE:{name}")
        self._executors[name] = executor

    def _ordered(self, app: str = "") -> list[AppApiExecutor]:
        ordered = sorted(
            self._executors.values(),
            key=lambda item: (-int(getattr(item, "priority", 0)), item.name),
        )
        preferred = None
        if self._experience is not None and app:
            try:
                preferred = self._experience.preferred_executor(app)
            except Exception:
                preferred = None
        if preferred and preferred in self._executors:
            chosen = self._executors[preferred]
            if bool(getattr(chosen, "experience_learnable", True)):
                ordered = [chosen, *(item for item in ordered if item.name != preferred)]
        return ordered

    def health(self) -> dict[str, Any]:
        experience = {"enabled": False}
        if self._experience is not None:
            try:
                experience = dict(self._experience.health())
            except Exception:
                experience = {"enabled": False, "error_code": "EXPERIENCE_UNAVAILABLE"}
        return {
            "enabled": True,
            "executors": [dict(executor.describe()) for executor in self._ordered()],
            "experience": experience,
        }


    def probe(
        self,
        app: str,
        *,
        refresh: bool = False,
        discovered: Mapping[str, Any] | None = None,
    ) -> AppApiHandle | None:
        ordered = self._ordered(app)
        failures: list[dict[str, Any]] = []
        for executor in ordered:
            try:
                handle = executor.probe(
                    app, refresh=refresh, discovered=discovered
                )
            except AppApiError as exc:
                failures.append({
                    "executor": executor.name,
                    "error_code": exc.code,
                    "details": dict(exc.details),
                })
                continue
            if handle is not None:
                if (
                    self._experience is not None
                    and bool(getattr(executor, "experience_learnable", True))
                ):
                    try:
                        self._experience.note_probe_success(handle)
                    except Exception:
                        pass
                return handle
        if failures:
            raise AppApiError(
                "APP_API_PROBE_FAILED",
                attempted=False,
                details={"app": app, "failures": failures},
            )
        return None


    def resolve_capability(
        self,
        handle: AppApiHandle,
        intent: str,
        *,
        action_args: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        executor = self._executors.get(handle.executor)
        if executor is None:
            raise AppApiError(
                "APP_API_EXECUTOR_UNAVAILABLE",
                attempted=False,
                details={"executor": handle.executor},
            )
        capability = handle.capabilities.get(intent)
        if not isinstance(capability, Mapping):
            raise AppApiError(
                "ACTION_UNSUPPORTED",
                attempted=False,
                details={"intent": intent, "executor": handle.executor},
            )
        resolver = getattr(executor, "capability_for", None)
        if callable(resolver):
            resolved = resolver(handle, intent, action_args=action_args)
            if not isinstance(resolved, Mapping):
                raise AppApiError("APP_API_CAPABILITY_INVALID", attempted=False)
            return dict(resolved)
        return dict(capability)

    def action(
        self,
        handle: AppApiHandle,
        intent: str,
        *,
        action_args: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        executor = self._executors.get(handle.executor)
        if executor is None:
            raise AppApiError(
                "APP_API_EXECUTOR_UNAVAILABLE",
                attempted=False,
                details={"executor": handle.executor},
            )
        result = executor.action(
            handle, intent, action_args=action_args
        )
        if (
            self._experience is not None
            and bool(getattr(executor, "experience_learnable", True))
        ):
            try:
                self._experience.note_action_success(handle, intent, result)
            except Exception:
                pass
        return result

    def close(self, handle: AppApiHandle) -> dict[str, Any]:
        executor = self._executors.get(handle.executor)
        if executor is None:
            raise AppApiError(
                "APP_API_EXECUTOR_UNAVAILABLE",
                attempted=False,
                details={"executor": handle.executor},
            )
        closer = getattr(executor, "close", None)
        if not callable(closer):
            return {"ok": True, "closed": False, "reason": "stateless"}
        result = closer(handle)
        if result is None:
            return {"ok": True, "closed": True}
        if not isinstance(result, Mapping):
            raise AppApiError(
                "APP_API_CLOSE_INVALID",
                attempted=False,
                details={"executor": handle.executor},
            )
        return dict(result)


class AppApiRouteAdapter:
    def __init__(self, registry: AppApiRegistry, handle: AppApiHandle):
        self.registry = registry
        self.handle = handle

    def can_handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        operation = request.get("operation")
        if not isinstance(operation, str) or not operation:
            return {"supported": False, "reason": "operation_missing"}
        capability = self.handle.capabilities.get(operation)
        if not isinstance(capability, Mapping):
            return {"supported": False, "reason": "unsupported_operation"}
        args = request.get("action_args")
        if args is not None and not isinstance(args, Mapping):
            return {"supported": True, "background_safe": False, "desktop_exclusive": True}
        try:
            capability = self.registry.resolve_capability(
                self.handle,
                operation,
                action_args=dict(args or {}),
            )
        except AppApiError as exc:
            raise RouteExecutionError(
                exc.code,
                exc.message,
                attempted=exc.attempted,
                details=exc.details,
            ) from exc
        return {
            "supported": True,
            "background_safe": bool(capability.get("background_safe", False)),
            "desktop_exclusive": bool(capability.get("desktop_exclusive", False)),
        }


    def act(self, request: Mapping[str, Any]) -> dict[str, Any]:
        operation = request.get("operation")
        if not isinstance(operation, str) or operation not in self.handle.capabilities:
            raise RouteExecutionError(
                "ACTION_UNSUPPORTED", attempted=False
            )
        args = request.get("action_args")
        if args is None:
            args = {}
        if not isinstance(args, Mapping):
            raise RouteExecutionError(
                "INVALID_ARGUMENT", attempted=False
            )
        action_args = dict(args)
        if (
            self.handle.executor == "winapp_cli"
            and request.get("_router_background_required") is True
        ):
            action_args["_background_required"] = True
        try:
            result = self.registry.action(
                self.handle,
                operation,
                action_args=action_args,
            )
        except AppApiError as exc:
            raise RouteExecutionError(
                exc.code,
                exc.message,
                attempted=exc.attempted,
                details=exc.details,
            ) from exc
        capability = self.handle.capabilities[operation]
        verified = bool(result.get("verified", False))

        window = self.handle.discovery.get("window")
        target_before = dict(window) if isinstance(window, Mapping) else {}
        return {
            "operation": operation,
            "target_before": target_before,
            "target": target_before,
            "verified": verified,
            "verification": {
                "matched": verified,
                "mechanism": "app_api",
                "executor": self.handle.executor,
                "backend_route": self.handle.backend_route,
            } if verified else None,
            "background_safe": bool(
                result.get("background_safe", capability.get("background_safe", False))
            ),
            "desktop_exclusive": bool(
                result.get("desktop_exclusive", capability.get("desktop_exclusive", False))
            ),
            "physical_input_used": False,
            "attempted": bool(result.get("attempted", True)),
            "retry_safe": result.get("retry_safe"),
            "latency_ms": result.get("latency_ms"),
            "action_result": result,
        }
