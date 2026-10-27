"""CLI-first routing guard for FF Windows Bridge v3.

This is a bridge RPC policy, not an OS sandbox around arbitrary current-user
code. It protects known application routes and cannot control programs launched
outside the bridge. Approval must come from the existing signed owner controller;
request-supplied allow_gui / --force-gui are not authority.
"""
from __future__ import annotations

import ast
import base64
import ctypes
import ctypes.wintypes
import ntpath
import re
import sys
from pathlib import Path

KNOWN = {
    "OmniRush": {
        "identity": ("omnirush.ai.exe", "@omnirushdesktop", "omnirush desktop", "omnirush"),
        "cli": "omnirush",
        "guidance": "omnirush --help (CLI tasks); Desktop GUI needs an owner-signed approval",
    },
    "Antigravity": {
        "identity": ("antigravity.exe", "antigravity.lnk", "antigravity"),
        "cli": "agy",
        "guidance": "agy --help",
    },
    "Cursor": {
        "identity": ("cursor.exe", "cursor.lnk", "cursor"),
        "cli": "agent",
        "guidance": "agent --help",
    },
    "VS Code": {
        "identity": ("code.exe", "code.lnk", "vs code", "visual studio code"),
        "cli": "code",
        "guidance": "code --help",
    },
}
READ_ONLY = {"gui_list_windows", "gui_screenshot", "gui_cursor", "desktop_mode_status",
             "capabilities", "list_processes"}
GUI_MUTATIONS = {"gui_focus_window", "focus_window", "gui_mouse", "gui_keyboard",
                 "gui_action_sequence", "computer_use"}
EXECUTIONS = {"start_process", "interact_with_process", "run_code"}

def _identity(text: object) -> str | None:
    value = str(text or "").casefold()
    for name, entry in KNOWN.items():
        if any(token in value for token in entry["identity"]):
            return name
    return None

def _segments(command: str):
    """Statement splitting outside quotes; quoted documentation stays data."""
    out, buf = [], []
    quote = None
    idx = 0
    while idx < len(command):
        ch = command[idx]
        if quote:
            buf.append(ch)
            if ch == quote:
                if idx + 1 < len(command) and command[idx + 1] == quote:
                    buf.append(command[idx + 1])
                    idx += 1
                else:
                    quote = None
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch in ";\r\n|" or (ch == "&" and idx + 1 < len(command) and command[idx + 1] == "&"):
            out.append("".join(buf).strip())
            buf = []
            if ch == "&":
                idx += 1
        else:
            buf.append(ch)
        idx += 1
    out.append("".join(buf).strip())
    return [s for s in out if s]

def _head(segment: str) -> str:
    s = segment.strip()
    if s.startswith("& "):
        s = s[2:].lstrip()
    if s and s[0] in "'\"":
        e = s.find(s[0], 1)
        return ntpath.basename(s[1:e] if e > 0 else s[1:]).casefold()
    return ntpath.basename(s.split(maxsplit=1)[0]).casefold() if s else ""

def _cli_head(head: str) -> bool:
    return head in {"omnirush", "omnirush.cmd", "omnirush.exe", "agy", "agy.exe",
                    "agent", "agent.exe", "code", "code.cmd"} or head.endswith("\\omnirush.cmd")

def should_close_stdin_for_one_shot(command: str) -> bool:
    """One-shot OmniRush waits for EOF on non-TTY stdin.

    The bridge normally opens a writable pipe for interactive sessions. For
    'omnirush -p'/'--print', an idle pipe prevents a prompt from ever starting.
    Only native CLI command-position matches qualify; other commands retain
    interactive stdin unless explicitly configured.
    """
    for statement in _segments(command):
        head = _head(statement)
        if head not in {"omnirush", "omnirush.cmd", "omnirush.ps1", "omnirush.exe"}:
            continue
        # Ignore flag-like strings inside a quoted prompt argument.
        flags = re.sub(r"""(["']).*?\1""", "", statement)
        if re.search(r"(?i)(?:^|\s)(?:-p|--print)(?=\s|$)", flags):
            return True
    return False


def _benign_head(head: str) -> bool:
    return head in {"echo", "echo.exe", "write-output", "write-host", "printf",
                    "rem", "#", "type", "cat", "get-content", "select-string",
                    "findstr", "rg", "find", "write-information"}

def _decoded_command(command: str) -> str | None:
    match = re.search(r"(?i)(?:^|\s)-(?:encodedcommand|enc|e)\s+([A-Za-z0-9+/=]{8,})", command)
    if not match:
        return None
    try:
        return base64.b64decode(match.group(1), validate=True).decode("utf-16-le")
    except (ValueError, UnicodeError):
        return None

def _shell_target(command: str, depth: int = 0) -> tuple[str, str] | None:
    if depth > 5:
        return None
    decoded = _decoded_command(command)
    if decoded is not None:
        found = _shell_target(decoded, depth + 1)
        if found:
            return found
    variables: dict[str, str] = {}
    pending_process: str | None = None
    for segment in _segments(command):
        head = _head(segment)
        if _benign_head(head) or _cli_head(head) or segment.lstrip().startswith("#"):
            continue
        assignment = re.match(r"""^\s*(\$[A-Za-z_]\w*)\s*=\s*['"]([^'"]+)['"]\s*$""", segment)
        if assignment:
            variables[assignment.group(1).casefold()] = assignment.group(2)
            continue
        if head in {"stop-process", "kill-process"} and pending_process:
            return pending_process, "pipeline_stop_process"
        effective = segment
        if re.search(r"(?i)\b(start-process|saps|invoke-item|ii|start|stop-process|closemainwindow)\b", segment):
            for variable, value in variables.items():
                effective = re.sub(re.escape(variable) + r"\b", lambda _: value, effective, flags=re.IGNORECASE)
        # A nested shell is inspected as a command, not blanket-matched for
        # words inside echoed text or a CLI prompt.
        if head in {"cmd", "cmd.exe"}:
            nested = re.search(r"(?i)(?:^|\s)/(?:c|k)\s+(.+)", segment)
            if nested:
                found = _shell_target(nested.group(1), depth + 1)
                if found:
                    return found
            continue
        if head in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
            nested = re.search(r"(?i)(?:^|\s)-(?:command|c)\s+(.+)", segment)
            if nested:
                found = _shell_target(nested.group(1), depth + 1)
                if found:
                    return found
            continue
        app = _identity(effective)
        if app is None:
            continue
        if head in {"get-process", "gps"}:
            pending_process = app
            continue
        lower = effective.casefold()
        # Executable in command position, including PowerShell call operator.
        direct = _identity(head) is not None
        launch = bool(re.search(r"(?i)\b(start-process|saps|invoke-item|ii|start|startfile|shell\.application|shellexecute)\b", effective))
        close = bool(re.search(r"(?i)\b(closemainwindow|stop-process|taskkill|kill-process|terminateprocess)\b", effective))
        if direct or launch or close:
            return app, "gui_process_operation"
        # Conservative on inline launcher function invocations, but do not
        # treat documentation, arguments, or text output as execution.
        if re.search(r"(?i)\b(subprocess\.(?:popen|run|call)|os\.system|os\.startfile)\s*\(", lower):
            return app, "nested_process_operation"
    return None

def _python_target(code: str) -> tuple[str, str] | None:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return _shell_target(code)
    literals: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            target = node.targets[0] if isinstance(node, ast.Assign) and node.targets else getattr(node, "target", None)
            value = node.value
            if isinstance(target, ast.Name) and isinstance(value, ast.Constant) and isinstance(value.value, str):
                literals[target.id] = value.value
    calls = {"os.system", "os.popen", "os.startfile", "subprocess.Popen", "subprocess.run",
             "subprocess.call", "subprocess.check_output", "subprocess.check_call",
             "subprocess.check_output", "subprocess.getoutput"}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        parts, f = [], node.func
        while isinstance(f, ast.Attribute):
            parts.append(f.attr)
            f = f.value
        if isinstance(f, ast.Name):
            parts.append(f.id)
        call = ".".join(reversed(parts))
        if call not in calls:
            continue
        arg = node.args[0] if node.args else None
        if arg is None:
            arg = next((k.value for k in node.keywords if k.arg in {"args", "command", "file"}), None)
        if isinstance(arg, ast.Name):
            arg = ast.Constant(value=literals.get(arg.id, ""))
        if isinstance(arg, (ast.Tuple, ast.List)) and arg.elts:
            if all(isinstance(item, ast.Constant) and isinstance(item.value, str) for item in arg.elts):
                joined = " ".join(item.value for item in arg.elts)
                nested = _shell_target(joined)
                if nested:
                    return nested
            arg = arg.elts[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            val = arg.value
            found = _shell_target(val)
            if found:
                return found
            app = _identity(val)
            if app and call == "os.startfile":
                return app, "python_startfile"
    return None

def _javascript_target(code: str) -> tuple[str, str] | None:
    # Static Node child_process launchers, not arbitrary documentation strings.
    for match in re.finditer(r"""(?i)\b(?:child_process\.)?(?:spawn|execFile|exec|spawnSync|execFileSync)\s*\(\s*['"]([^'"]+)['"]""", code):
        target = match.group(1)
        nested = _shell_target(target)
        if nested:
            return nested
        app = _identity(target)
        if app:
            return app, "node_child_process"
    return None


def _process_path(pid: int) -> str:
    if not pid or pid < 1:
        return ""
    try:
        kernel = ctypes.windll.kernel32
        kernel.OpenProcess.argtypes = [ctypes.wintypes.DWORD, ctypes.wintypes.BOOL, ctypes.wintypes.DWORD]
        kernel.OpenProcess.restype = ctypes.wintypes.HANDLE
        kernel.QueryFullProcessImageNameW.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD,
                                                       ctypes.wintypes.LPWSTR, ctypes.POINTER(ctypes.wintypes.DWORD)]
        kernel.QueryFullProcessImageNameW.restype = ctypes.wintypes.BOOL
        kernel.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        proc = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not proc:
            return ""
        try:
            buff = ctypes.create_unicode_buffer(32768)
            size = ctypes.wintypes.DWORD(len(buff))
            if kernel.QueryFullProcessImageNameW(proc, 0, buff, ctypes.byref(size)):
                return buff.value
        finally:
            kernel.CloseHandle(proc)
    except (AttributeError, OSError, ValueError):
        pass
    return ""

def _hwnd_identity(hwnd: int) -> str | None:
    try:
        user32 = ctypes.windll.user32
        if not hwnd or not user32.IsWindow(hwnd):
            return None
        pid = ctypes.wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        path = _process_path(pid.value)
        if path:
            return _identity(path)
        length = user32.GetWindowTextLengthW(hwnd)
        title = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, title, len(title))
        return _identity(title.value)
    except (AttributeError, ValueError, OSError):
        return None

def _gui_target(core, args: dict, op: str) -> tuple[str, str] | None:
    app = None
    if op == "computer_use":
        command = str(args.get("command") or "").casefold()
        # The authenticated CUA dispatcher runs this exact operation as a
        # pinned headless vendor CLI inside an owned sandbox. It is not a GUI
        # exception or permission to launch an arbitrary app: the executor
        # independently validates every argument, billing gate and target.
        if (command == "task_execute"
                and args.get("task") == "antigravity.assistant"
                and args.get("operation") == "headless.answer"
                and str(args.get("app") or "").casefold() in {"antigravity", "agy"}):
            return None
        # Discovery and observation can proceed without UI manipulation.
        if command in {"discover", "observe", "status", "health", "list", "get_capabilities", "capabilities", "screenshot", "attach", "inspect", "close", "routes", "route_discover", "discover_cli", "programmatic_plan", "prepare_tool", "app_api_probe", "resolve_app", "find", "wait", "capture", "vision_capture", "vision_detect", "vision_ocr", "vision_observe", "vision_ground", "vision_find", "vision_resolve", "vision_validate", "release_physical_lease", "plan_action", "task_preflight", "assistant_task_status"}:
            return None
        app = _identity(args.get("app"))
        expected = args.get("expected_app")
        if isinstance(expected, dict):
            app = app or _identity(expected.get("app_id"))
        # Existing CUA surfaces contain authoritative targets, unlike a
        # caller-supplied title or a foreground guess.
        surface_id = args.get("surface_id")
        if isinstance(surface_id, str):
            surfaces = getattr(core, "cli_first_surfaces", None)
            if isinstance(surfaces, dict):
                surface = surfaces.get(surface_id)
                if isinstance(surface, dict):
                    # APP_API routes are the preferred programmatic path, not GUI.
                    if command == "act" and surface.get("kind") == "app":
                        return None
                    app = app or _identity(surface.get("app"))
                    target = surface.get("target")
                    if isinstance(target, dict):
                        app = app or _identity(target.get("app") or target.get("process_path"))
                        target_hwnd = target.get("hwnd")
                        if not app and isinstance(target_hwnd, int):
                            app = _hwnd_identity(target_hwnd)
        if command == "windows_mcp":
            # Treat delegated desktop controls as GUI actions. Read-only inventory
            # through Windows MCP remains available.
            tool = str(args.get("tool") or "").casefold()
            if not any(word in tool for word in ("click", "type", "key", "mouse", "focus", "launch", "close", "press", "invoke", "set", "send")):
                return None
            payload = args.get("arguments")
            if isinstance(payload, dict):
                for key in ("app", "title", "title_contains", "window_title", "process_path"):
                    app = app or _identity(payload.get(key))
            if not app:
                try:
                    app = _hwnd_identity(ctypes.windll.user32.GetForegroundWindow())
                except (AttributeError, OSError):
                    pass
            return (app, "windows_mcp_" + tool[:40]) if app else None
        # Native UI commands may specify an app by window rather than a name.
        if app and command in {"launch_app", "ensure_app", "focus_target", "focus", "click", "type", "send_keys", "act", "perform", "auto", "acquire_physical_lease"}:
            return app, "computer_use_" + command
    if op == "gui_action_sequence":
        steps = args.get("steps") or args.get("actions") or args.get("sequence")
        if isinstance(steps, list):
            for step in steps[:100]:
                if isinstance(step, dict):
                    app = app or _identity(step.get("app") or step.get("title_contains") or step.get("target_title_contains"))
                    if app:
                        return app, "gui_action_sequence"
    for key in ("app", "title_contains", "target_title_contains", "window_title", "process_path"):
        app = app or _identity(args.get(key))
    if app:
        return app, "gui_operation_" + op
    hwnd = args.get("hwnd", args.get("target_hwnd"))
    if isinstance(hwnd, str):
        try:
            hwnd = int(hwnd, 0)
        except ValueError:
            hwnd = None
    if isinstance(hwnd, int) and not isinstance(hwnd, bool):
        app = _hwnd_identity(hwnd)
        if app:
            return app, "gui_operation_" + op
    physical = (op in {"gui_mouse", "gui_keyboard", "gui_action_sequence"} or
                (op == "computer_use" and (args.get("physical_input_allowed") is True or
                  (isinstance(args.get("policy"), dict) and
                   args["policy"].get("foreground_allowed") is True))))
    if physical:
        try:
            app = _hwnd_identity(ctypes.windll.user32.GetForegroundWindow())
            if app:
                return app, "foreground_gui_operation"
        except (AttributeError, OSError):
            pass
    return None

def _approval(core, op: str, args: dict) -> None:
    """No request-side boolean can grant a GUI exception."""
    from cua_task_authority import AuthorityStore, AuthorityError, invocation
    import sqlite3
    store = AuthorityStore(core.BRIDGE_ROOT / "state" / "task-authority")
    try:
        grant = (store.provision(signed_approval=args["signed_approval"])
                 if "signed_approval" in args else args.get("authorization_id"))
        if not grant:
            raise AuthorityError("OWNER_APPROVAL_REQUIRED")
        store.consume(grant, agent=args.get("agent_id"),
                      task=args.get("task_id"), request=invocation(op, args))
    except (AuthorityError, sqlite3.Error, OSError, ValueError, TypeError) as exc:
        error = str(exc) if isinstance(exc, AuthorityError) else "APPROVAL_STORAGE_UNAVAILABLE"
        raise core.RPCError("CLI_FIRST_OWNER_APPROVAL_REQUIRED",
                            message="GUI exception requires an exact owner-signed approval; allow_gui and --force-gui are insufficient.",
                            details={"approval_error": error, "execution_started": False}) from exc

def enforce(core, op: str, args: dict) -> None:
    """Single pre-dispatch policy for core, upgraded and CUA RPC operations."""
    match = None
    if op in EXECUTIONS:
        code = args.get("command") if op == "start_process" else args.get("input") if op == "interact_with_process" else args.get("code")
        if isinstance(code, str):
            language = str(args.get("language") or "").casefold()
            match = (_python_target(code) if op == "run_code" and language in {"python", "py"}
                     else _javascript_target(code) if op == "run_code" and language in {"node", "js", "javascript"}
                     else _shell_target(code))
    elif op in GUI_MUTATIONS:
        match = _gui_target(core, args, op)
    elif op in {"kill_process", "force_terminate"}:
        pid = args.get("pid")
        if op == "force_terminate":
            try:
                pid = core.get_session(str(args.get("session_id") or "")).pid
            except Exception:
                pid = None
        if type(pid) is int:
            app = _identity(_process_path(pid))
            if app:
                match = app, "terminate_gui_process"
    if not match:
        return
    app, reason = match
    # GUI exceptions are single-use, scope-bound signed approvals, not flags.
    if args.get("authorization_id") or args.get("signed_approval"):
        # Existing computer_use launch_action already consumes the same exact
        # signed grant; do not consume it twice. The original handler remains
        # responsible for final owner approval and desktop mode verification.
        if op == "computer_use" and args.get("visible_launch_allowed") is True:
            return
        _approval(core, op, args)
        return
    entry = KNOWN[app]
    raise core.RPCError(
        "CLI_FIRST_POLICY_VIOLATION",
        message=f"{app}: direct GUI manipulation is blocked. Prefer an API/SDK/MCP when supported, "
                f"then the native CLI ({entry['cli']}). A desktop-only action requires an exact "
                "owner-signed approval. allow_gui=true and --force-gui do not authorize it.",
        details={"app": app, "reason": reason, "cli_command": entry["cli"],
                 "recommended_call": entry["guidance"], "execution_started": False,
                 "approval_required": True, "rule": "CLI-First Policy v2"},
    )
