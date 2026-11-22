"""Opt-in live check of Claude Desktop MSIX alias on an owned private Windows desktop.

Run: python tests/integration/claude_desktop_private_smoke.py --run
No user desktop focus, input, clipboard, or Chrome operation; never submits a prompt.
"""
from __future__ import annotations
import argparse
import ctypes
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import sys

RUNTIME=Path(__file__).resolve().parents[2]/"runtime"/"bridge-v3"
sys.path.insert(0,str(RUNTIME))

def show(name, **data):
    print(json.dumps({"event":name,**data},ensure_ascii=True),flush=True)

def main():
    cli=argparse.ArgumentParser()
    cli.add_argument("--run",action="store_true")
    cli.add_argument("--observe",action="store_true")
    args=cli.parse_args()
    if not args.run:
        show("NOT_RUN",reason="Requires --run; no app was launched")
        return 0
    if os.name!="nt":
        show("NOT_RUN",reason="Windows required")
        return 0
    from cua_hidden_desktop import HiddenDesktopSession
    from cua_hidden_apps import app_path
    from ff_hub_apps import count_processes
    if count_processes("Claude.exe") is None:
        show("BLOCKED",reason="CLAUDE_PROCESS_INVENTORY_UNAVAILABLE")
        return 2
    if count_processes("Claude.exe"):
        show("BLOCKED",reason="CLAUDE_ALREADY_RUNNING")
        return 2
    if not app_path("claude").is_file():
        show("BLOCKED",reason="CLAUDE_MSIX_ALIAS_NOT_INSTALLED")
        return 2
    u=ctypes.WinDLL("user32")
    u.GetForegroundWindow.restype=w.HWND
    initial=int(u.GetForegroundWindow() or 0)
    try:
        with HiddenDesktopSession(RUNTIME,worker_integrity="owner") as private:
            show("STARTED_PRIVATE_DESKTOP",worker=private.pid)
            launched=private.request({"command":"launch_app","app":"claude"},timeout_s=40)
            show("CLAUDE_OWN_WINDOW",app=launched.get("app"),pid=launched["pid"],hwnd=launched["hwnd"],
                 desktop_match=launched.get("desktop")==private.desktop_name,
                 class_name=launched.get("class_name"),foreground_same=int(u.GetForegroundWindow() or 0)==initial)
            if args.observe:
                import time
                time.sleep(7)  # let the packaged Electron renderer finish loading
                observed=private.request({"command":"uia_observe","hwnd":launched["hwnd"],"options":{"max_items":100}},timeout_s=40)
                show("UIA_OBSERVED",keys=sorted(observed.keys()),generation=observed.get("generation"),
                     list_lengths={k:len(v) for k,v in observed.items() if isinstance(v,list)},
                     nodes=[{"role":v.get("role"),"name":str(v.get("name",""))[:90],
                             "actions":v.get("actions")} for v in observed.get("entities",[])[:70]])
            show("FOREGROUND_FINAL",same=int(u.GetForegroundWindow() or 0)==initial)
        from ff_win_process_identity import process_creation_token
        import time
        for _ in range(30):
            if process_creation_token(launched["pid"]) != launched.get("create_time"):
                break
            time.sleep(.1)
        owned_gone=process_creation_token(launched["pid"]) != launched.get("create_time")
        show("PRIVATE_DESKTOP_CLOSED",cleanup=private.editor_profile_cleanup,
             owned_process_gone=owned_gone)
        return 0 if owned_gone else 3
    except Exception as e:
        show("FAIL",error_type=type(e).__name__,code=str(e),foreground_same=int(u.GetForegroundWindow() or 0)==initial)
        return 1

if __name__=="__main__":
    raise SystemExit(main())
