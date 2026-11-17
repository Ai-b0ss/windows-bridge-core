"""Opt-in end-to-end Claude Desktop PRIVATE Code-mode selection test.

Run: python tests/integration/claude_desktop_code_smoke.py --run
No prompt is submitted. All actions are in the OWNED private desktop via native UIA.
"""
from __future__ import annotations
import argparse
import ctypes
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[2]/"runtime"/"bridge-v3"
sys.path.insert(0,str(ROOT))

def emit(event,**details):
    print(json.dumps({"event":event,**details},ensure_ascii=True),flush=True)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--run",action="store_true")
    args=parser.parse_args()
    if not args.run:
        emit("NOT_RUN",reason="explicit --run needed")
        return 0
    if os.name!="nt":
        emit("NOT_RUN",reason="Windows only")
        return 0
    from cua_hidden_desktop import HiddenDesktopSession
    from ff_hub_apps import count_processes
    from ff_win_process_identity import process_creation_token
    if count_processes("Claude.exe") != 0:
        emit("BLOCKED",reason="existing Claude process or unknown process inventory")
        return 2
    u=ctypes.WinDLL("user32")
    u.GetForegroundWindow.restype=w.HWND
    starting_hwnd=int(u.GetForegroundWindow() or 0)
    launched=None
    try:
        with HiddenDesktopSession(ROOT,worker_integrity="owner") as session:
            launched=session.request({"command":"launch_app","app":"claude"},timeout_s=40)
            emit("LAUNCH",own_pid=launched["pid"],private=True,
                 no_focus=int(u.GetForegroundWindow() or 0)==starting_hwnd)
            time.sleep(7)
            snap=session.request({"command":"uia_observe","hwnd":launched["hwnd"],
                                  "options":{"max_items":240}},timeout_s=40)
            radios=[v for v in snap["entities"] if v.get("role")=="RadioButton" and v.get("name")=="Code"]
            if len(radios)!=1:
                emit("CODE_RADIO_UNAVAILABLE",count=len(radios),nodes=len(snap["entities"]))
                return 3
            code=radios[0]
            emit("CODE_RADIO",selected=code.get("state",{}).get("selected"),actions=code.get("actions"))
            if code.get("state",{}).get("selected") is not True:
                result=session.request({"command":"uia_act","hwnd":launched["hwnd"],
                    "generation":snap["generation"],"ref":code["ref"],"operation":"select",
                    "postcondition":{"type":"state_equals","key":"selected","value":True}},timeout_s=40)
                emit("SELECT_CODE",verified=result.get("verified"),route=result.get("route"),
                     physical_input=result.get("physical_input_used"))
            time.sleep(2)
            snap=session.request({"command":"uia_observe","hwnd":launched["hwnd"],
                                  "options":{"max_items":350}},timeout_s=40)
            interesting=[]
            for entity in snap["entities"]:
                name=str(entity.get("name") or "")
                if (any(x in name.casefold() for x in ("модель","model","fable","effort",
                         "средн","medium","code","новая сессия","new session","open folder","каталог"))
                       or entity.get("role") in ("ComboBox","RadioButton")):
                    interesting.append({"role":entity.get("role"),"name":name[:110],
                                        "actions":entity.get("actions"),
                                        "selected":(entity.get("state") or {}).get("selected")})
            emit("CODE_INTERFACE",nodes=len(snap["entities"]),items=interesting[:70],
                 foreground_same=int(u.GetForegroundWindow() or 0)==starting_hwnd)
        for _ in range(40):
            if process_creation_token(launched["pid"])!=launched.get("create_time"):break
            time.sleep(.1)
        owner_process_gone=process_creation_token(launched["pid"])!=launched.get("create_time")
        emit("CLEANUP",owned_process_gone=owner_process_gone)
        return 0 if owner_process_gone else 4
    except Exception as e:
        emit("ERROR",type=type(e).__name__,code=str(e),
             foreground_same=int(u.GetForegroundWindow() or 0)==starting_hwnd)
        return 1

if __name__=="__main__":
    raise SystemExit(main())
