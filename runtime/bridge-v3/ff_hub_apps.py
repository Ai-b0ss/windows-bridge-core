"""Application control plane: find an application, list the ways to drive it, pick the best one.

An agent names the application; this module reports what is installed, what kind of program
it is and which control routes exist, ordered from programmatic to graphical. Each route says
whether it works in the background and how well that is established:

  proven      - exercised end to end on a real machine by the integration tests
  expected    - the mechanism applies to this kind of program, not yet proven for this one
  partial     - works for part of the interface only; the limit is stated
  unsupported - cannot work, with the reason

It never claims a route it has not earned, and it launches nothing by itself.
"""
from __future__ import annotations

import ctypes
import os
import shutil
from ctypes import wintypes
from pathlib import Path
from typing import Any

try:
    import winreg
except ImportError:  # non-Windows test hosts
    winreg = None  # type: ignore[assignment]

KNOWN: dict[str, dict[str, Any]] = {
    "chrome":     {"exe": "chrome.exe", "kind": "chromium_browser"},
    "msedge":     {"exe": "msedge.exe", "kind": "chromium_browser"},
    "excel":      {"exe": "EXCEL.EXE", "kind": "office", "progid": "Excel.Application"},
    "word":       {"exe": "WINWORD.EXE", "kind": "office", "progid": "Word.Application"},
    "powerpoint": {"exe": "POWERPNT.EXE", "kind": "office", "progid": "PowerPoint.Application"},
    "cursor":     {"exe": "Cursor.exe", "kind": "electron_editor", "cli": ["cursor", "cursor-agent"]},
    "vscode":     {"exe": "Code.exe", "kind": "electron_editor", "cli": ["code"]},
    "notepad":    {"exe": "notepad.exe", "kind": "win32"},
    "wordpad":    {"exe": "wordpad.exe", "kind": "win32"},
    "paint":      {"exe": "mspaint.exe", "kind": "win32"},
    "git":        {"exe": "git.exe", "kind": "cli_tool", "cli": ["git"]},
    "github":     {"exe": "gh.exe", "kind": "cli_tool", "cli": ["gh"]},
    "claude-desktop": {"exe": "claude-desktop.exe", "kind": "msix_fulltrust_electron"},
}
ALIASES = {"google chrome": "chrome", "edge": "msedge", "code": "vscode", "visual studio code": "vscode",
           "ms excel": "excel", "ms word": "word", "gh": "github", "mspaint": "paint",
           "claude": "claude-desktop", "claude desktop": "claude-desktop"}
# Hidden-desktop UIA is proven only for what the integration tests really drove.
PROVEN_HIDDEN = {"notepad.exe", "wordpad.exe", "mspaint.exe", "excel.exe", "winword.exe", "powerpnt.exe", "charmap.exe"}


def _app_paths(executable: str) -> str | None:
    if winreg is None:
        return None
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            with winreg.OpenKey(hive, rf"Software\Microsoft\Windows\CurrentVersion\App Paths\{executable}") as key:
                value = winreg.QueryValueEx(key, None)[0]
                if value and os.path.isfile(os.path.expandvars(value.strip('"'))):
                    return os.path.expandvars(value.strip('"'))
        except OSError:
            continue
    return None


def _progid_registered(progid: str) -> bool:
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, rf"{progid}\CLSID"):
            return True
    except OSError:
        return False


def _candidates(executable: str) -> list[Path]:
    local, files, files86 = (os.environ.get(name, "") for name in ("LOCALAPPDATA", "ProgramFiles", "ProgramFiles(x86)"))
    stem = Path(executable).stem
    roots = [Path(local) / "Programs" / stem, Path(local) / "Programs" / stem.lower(), Path(files) / stem,
             Path(files86) / stem, Path(local) / "Programs" / "Microsoft VS Code",
             Path(files) / "Microsoft VS Code", Path(files) / "Windows NT" / "Accessories",
             Path(files) / "Google" / "Chrome" / "Application", Path(files) / "Microsoft Office" / "root" / "Office16",
             Path(files86) / "Microsoft Office" / "root" / "Office16", Path(os.environ.get("WINDIR", "")) / "System32"]
    return [root / executable for root in roots if str(root)]


def resolve(query: str) -> dict:
    """Where the application is and what kind of program it is. No process is started."""
    if not isinstance(query, str) or not query.strip() or len(query) > 400:
        return {"found": False, "query": query, "reason": "APP_QUERY_INVALID"}
    text = query.strip().strip('"')
    key = ALIASES.get(text.lower(), text.lower())
    known = KNOWN.get(key) or KNOWN.get(Path(text).stem.lower())
    path: str | None = None
    if os.path.isabs(text):
        path = text if os.path.isfile(text) else None
    else:
        executable = known["exe"] if known else (text if text.lower().endswith(".exe") else text + ".exe")
        path = _app_paths(executable) or shutil.which(executable)
        if not path:
            path = next((str(item) for item in _candidates(executable) if item.is_file()), None)
    if not path:
        return {"found": False, "query": query, "reason": "APP_NOT_INSTALLED_OR_NOT_FOUND",
                "hint": "give the absolute path of the executable"}
    path = os.path.abspath(path)
    name = os.path.basename(path)
    known = known or next((spec for spec in KNOWN.values() if spec["exe"].lower() == name.lower()), None)
    directory = Path(path).parent
    if known and known.get("kind")=="msix_fulltrust_electron":
        kind="msix_fulltrust_electron"
    elif "\\windowsapps\\" in path.lower():
        kind = "packaged_uwp"
    elif known:
        kind = known["kind"]
    elif (directory / "resources" / "app.asar").is_file() or (directory / "resources" / "app").is_dir():
        kind = "electron"
    elif any(directory.glob("chrome_*.pak")) or (directory / "chrome_elf.dll").is_file():
        kind = "chromium_embedded"
    else:
        kind = "win32"
    return {"found": True, "query": query, "name": name, "executable": path, "kind": kind,
            "known": key if key in KNOWN else None, "running_instances": count_processes(name)}


class _ProcessEntry(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260)]


def count_processes(image_name: str) -> int | None:
    if os.name != "nt":
        return None
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snapshot = kernel32.CreateToolhelp32Snapshot(0x2, 0)
    if snapshot in (None, wintypes.HANDLE(-1).value):
        return None
    try:
        entry = _ProcessEntry()
        entry.dwSize = ctypes.sizeof(entry)
        count, more = 0, kernel32.Process32FirstW(wintypes.HANDLE(snapshot), ctypes.byref(entry))
        while more:
            count += entry.szExeFile.lower() == image_name.lower()
            more = kernel32.Process32NextW(wintypes.HANDLE(snapshot), ctypes.byref(entry))
        return count
    finally:
        kernel32.CloseHandle(wintypes.HANDLE(snapshot))


def routes(app: dict) -> list[dict]:
    """Control routes for a resolved application, best first."""
    if not app.get("found"):
        return []
    kind, name = app["kind"], app["name"].lower()
    known = KNOWN.get(app.get("known") or "", {})
    found: list[dict] = []

    for command in known.get("cli", []):
        location = shutil.which(command)
        if location:
            found.append({"route": "cli", "background": True, "status": "expected", "evidence": location,
                          "use": "Bridge start_process / run_code with this command",
                          "note": "an installed command proves the interface exists, not that a task or a paid model call will succeed"})
    progid = known.get("progid")
    if progid and _progid_registered(progid):
        found.append({"route": "com_automation", "background": True, "status": "proven", "evidence": progid,
                      "use": "Bridge computer_use hidden_start -> hidden_request launch_app/document.* (own hidden instance)",
                      "note": "own instance on a private desktop; the owner's open documents are not touched"})
    if kind == "chromium_browser" and name == "chrome.exe":
        found.append({"route": "owner_chrome_extension", "background": True, "status": "expected",
                      "capability_gate": "backgroundChromePreflight: running Chrome >=158.0.8127.2, extension >=0.5.0; token required at connect",
                      "use": "hub op `browser` (open/snapshot/act/read ...)",
                      "note": "not a live availability claim; connection must pass the read-only background preflight first; "
                              "the owner's signed-in profile through the official Playwright extension; agent tabs stay hidden; "
                              "actions are DOM-level, so pages that demand real pointer or keyboard events need `foreground` (a separate permission)"})
    if kind == "electron_editor":
        found.append({"route": "own_editor_native_api", "background": True, "status": "proven",
                      "use": "Bridge computer_use hidden_request editor.launch/editor.observe/editor.replace_save",
                      "note": "an own private-profile instance; edits one text file through the editor's API. "
                              "It does not drive the editor's AI assistant and does not carry the owner's sign-in"})
    if kind == "cli_tool":
        return found or [{"route": "cli", "background": True, "status": "expected", "evidence": app["executable"],
                          "use": "Bridge start_process"}]
    if kind=="msix_fulltrust_electron":
        found.append({"route":"hidden_desktop_msix_alias","background":True,"status":"partial",
                      "use":"Bridge computer_use hidden_start -> hidden_request launch_app app=claude",
                      "note":"Verified Claude MSIX alias can create its own Electron window on a private desktop "
                             "with no foreground change. Only if there is no existing Claude.exe. "
                             "Code mode, model selection and arbitrary Electron UIA interactions "
                             "require separate postcondition checks; not universally supported."})
    elif kind == "packaged_uwp":
        found.append({"route": "hidden_desktop_uia", "background": True, "status": "unsupported",
                      "note": "packaged (UWP/MSIX) applications are activated by the shell on the interactive desktop only; "
                              "Windows cannot start them on a private desktop"})
    else:
        hidden = {"route": "hidden_desktop_uia", "background": True, "use": "hub ops app_open/app_observe/app_act/app_close",
                  "evidence": "own process on the agent's private Windows desktop; UI Automation patterns, no input events"}
        if kind in {"electron", "electron_editor", "chromium_embedded", "chromium_browser"}:
            hidden.update(status="partial", launch_allowed=False,
                          note="generic launch is disabled: a single-instance handoff can affect the owner's running app; "
                               "use a supported API or a separately verified isolated-profile route")
        elif name in PROVEN_HIDDEN:
            hidden.update(status="expected", note="historical fixed-app tests cover this executable family; "
                          "the Hub launch and installed application still need a separate real acceptance run")
        else:
            hidden.update(status="expected",
                          note="classic Win32/WinForms/WPF controls answer UI Automation patterns without focus; "
                               "custom-drawn controls and apps that need real mouse movement will not")
        found.append(hidden)
    found.append({"route": "visible_desktop", "background": False, "status": "expected",
                  "use": "Bridge set_desktop_mode dedicated + windows_mcp, with the owner's own yes",
                  "note": "takes the shared mouse, keyboard and focus; last resort, never chosen automatically"})
    return found


def plan(query: str) -> dict:
    app = resolve(query)
    options = routes(app)
    usable = [item for item in options if item["status"] in {"proven", "expected", "partial"} and item["background"]
              and item.get("launch_allowed", True)]
    # The route order is an owner decision. A historical GUI success cannot outrank an
    # available CLI/COM route merely because the latter has not been exercised here yet.
    best = usable[0] if usable else None
    return {"app": app, "routes": options, "recommended": best,
            "background_possible": best is not None,
            "why_not": None if best else (app.get("reason") or "no background route exists for this kind of program")}
