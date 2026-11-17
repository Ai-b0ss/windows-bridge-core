"""Opt-in real private-desktop generic GUI acceptance, without Chrome or installed Bridge.

Run: python tests/integration/hub_hidden_gui_smoke.py --run
Only two owned Character Map processes, private workers and UIA sidecars are used.
No physical input, clipboard content, desktop switching or process-name cleanup.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import threading
from concurrent.futures import ThreadPoolExecutor
import time

RUNTIME=Path(__file__).resolve().parents[2]/"runtime"/"bridge-v3"


def check(value,code):
    if not value:raise RuntimeError(code)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",action="store_true",help="explicitly run two disposable hidden GUI instances")
    options=parser.parse_args()
    if not options.run:
        print(json.dumps({"status":"NOT_RUN","reason":"explicit --run required"}))
        return 0
    if os.name!="nt":
        print(json.dumps({"status":"NOT_RUN","reason":"Windows required"}))
        return 0
    charmap=Path(os.environ["WINDIR"])/"System32"/"charmap.exe"
    if not charmap.is_file():
        print(json.dumps({"status":"NOT_RUN","reason":"Character Map absent"}))
        return 0
    sys.path.insert(0,str(RUNTIME))
    from cua_hidden_desktop import HiddenDesktopSession,HiddenDesktopError
    from ff_win_process_identity import process_creation_token,process_identity_matches

    user=ctypes.WinDLL("user32",use_last_error=True)
    user.GetForegroundWindow.restype=wintypes.HWND
    user.GetClipboardSequenceNumber.restype=wintypes.DWORD
    user.GetThreadDesktop.argtypes=[wintypes.DWORD]
    user.GetThreadDesktop.restype=wintypes.HANDLE
    user.SetThreadDesktop.argtypes=[wintypes.HANDLE]
    user.SetThreadDesktop.restype=wintypes.BOOL
    enum_callback=ctypes.WINFUNCTYPE(wintypes.BOOL,wintypes.HWND,wintypes.LPARAM)
    user.EnumDesktopWindows.argtypes=[wintypes.HANDLE,enum_callback,wintypes.LPARAM]
    user.EnumDesktopWindows.restype=wintypes.BOOL
    user.GetWindowThreadProcessId.argtypes=[wintypes.HWND,ctypes.POINTER(wintypes.DWORD)]
    user.GetWindowThreadProcessId.restype=wintypes.DWORD
    user.OpenInputDesktop.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    user.OpenInputDesktop.restype=wintypes.HANDLE
    user.CloseDesktop.argtypes=[wintypes.HANDLE]
    user.GetUserObjectInformationW.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    def desktop_name(handle):
        name=ctypes.create_unicode_buffer(256);needed=wintypes.DWORD()
        check(handle and user.GetUserObjectInformationW(handle,2,name,ctypes.sizeof(name),ctypes.byref(needed)),
              "DESKTOP_IDENTITY_UNAVAILABLE")
        return name.value
    class Point(ctypes.Structure):_fields_=[("x",wintypes.LONG),("y",wintypes.LONG)]
    user.GetCursorPos.argtypes=[ctypes.POINTER(Point)]
    user.GetCursorPos.restype=wintypes.BOOL
    def read_owner_state():
        point=Point()
        check(user.GetCursorPos(ctypes.byref(point)),"CURSOR_OBSERVATION_UNAVAILABLE")
        return (int(user.GetForegroundWindow() or 0),point.x,point.y,int(user.GetClipboardSequenceNumber()))
    def bind_observer():
        # The harness itself may run on a private desktop (an agent session started through
        # the hidden route). Cursor and foreground belong to the input desktop, so one
        # dedicated thread is bound to it with read/enumerate access only. Nothing is
        # switched, activated or sent; no window is created on that desktop.
        handle=user.OpenInputDesktop(0,False,0x0041)
        check(handle and user.SetThreadDesktop(handle),"OWNER_OBSERVER_BIND_FAILED")
    owner_observer=ThreadPoolExecutor(max_workers=1,initializer=bind_observer)
    def owner_state():
        return owner_observer.submit(read_owner_state).result(timeout=5)

    before=owner_state()
    check(before[0]>0,"INPUT_DESKTOP_UNAVAILABLE")
    changed=threading.Event()
    foreground_changed=threading.Event()
    finished=threading.Event()
    samples=[0]
    observation_errors=[]
    def sample():
        try:
            while not finished.wait(.01):
                samples[0]+=1
                current=owner_state()
                if current[0]!=before[0]:foreground_changed.set()
                if current!=before:changed.set()
        except Exception:
            observation_errors.append("OWNER_SAMPLER_FAILED")
    def quiet():
        # Owner activity is an observation, not attribution of input to this test.
        # Only private desktop identity authorizes these pattern-only operations.
        handle=user.OpenInputDesktop(0,False,1)
        try:active=desktop_name(handle)
        finally:
            if handle:user.CloseDesktop(handle)
        for session in sessions:
            check(session.desktop_name!=active,"PRIVATE_DESKTOP_BECAME_INPUT_DESKTOP")
    sampler=threading.Thread(target=sample,daemon=True)
    started=time.monotonic()
    owned=[];sessions=[];evidence={"schema":"ff-hidden-generic-smoke-v1","status":"FAIL"}
    original_root=os.environ.get("FF_BRIDGE_ROOT")
    failure=None
    with TemporaryDirectory(prefix="ff-hidden-generic-smoke-") as temporary:
        os.environ["FF_BRIDGE_ROOT"]=temporary
        sampler.start()
        try:
            windows=[]
            for _ in range(2):
                quiet()
                session=HiddenDesktopSession(RUNTIME,allow_generic_launch=True)
                sessions.append(session)
                token=process_creation_token(session.pid)
                check(token is not None,"WORKER_IDENTITY_UNAVAILABLE")
                owned.append((session.pid,token))
                quiet()
                window=session.request({"command":"launch_exe","executable":str(charmap)},timeout_s=30)
                check(type(window.get("create_time")) is int and window["create_time"]>0,"APP_IDENTITY_UNAVAILABLE")
                check(process_identity_matches(window["pid"],window["create_time"]),"APP_IDENTITY_MISMATCH")
                owned.append((window["pid"],window["create_time"]))
                # HWND lookup is desktop-scoped. Bind a fresh observer thread to the
                # private desktop; this does not make that desktop visible or active.
                native=[]
                def observe_native():
                    try:
                        check(user.SetThreadDesktop(session._desktop),"OBSERVER_DESKTOP_BIND_FAILED")
                        pid=wintypes.DWORD()
                        found=[]
                        @enum_callback
                        def visit(hwnd,_):
                            if hwnd==window["hwnd"]:found.append(hwnd)
                            return True
                        check(user.EnumDesktopWindows(session._desktop,visit,0),"NATIVE_DESKTOP_ENUMERATION_FAILED")
                        user.GetWindowThreadProcessId(window["hwnd"],ctypes.byref(pid))
                        native.append(pid.value==window["pid"] and found==[window["hwnd"]])
                    except Exception as exc:
                        evidence["native_probe_error"]=str(exc)
                        native.append(False)
                observer=threading.Thread(target=observe_native)
                observer.start();observer.join(timeout=5)
                check(native==[True],"NATIVE_WINDOW_DESKTOP_MISMATCH")
                windows.append(window)
            check(windows[0]["desktop"]!=windows[1]["desktop"],"SHARED_PRIVATE_DESKTOP")
            check(windows[0]["pid"]!=windows[1]["pid"],"SHARED_GUI_PROCESS")
            for index,session in enumerate(sessions):
                foreign=windows[1-index]["hwnd"]
                for command in ("ui_observe","capture_window"):
                    try:session.request({"command":command,"hwnd":foreign})
                    except HiddenDesktopError as exc:
                        check(exc.code=="HIDDEN_WINDOW_NOT_OWNED","WRONG_FOREIGN_TARGET_DENIAL")
                    else:raise RuntimeError("FOREIGN_WINDOW_WAS_ACCEPTED")
                window=windows[index]
                described=session.request({"command":"describe_owned_windows"})["windows"]
                check(any(item["hwnd"]==window["hwnd"] and item["pid"]==window["pid"]
                          and item["create_time"]==window["create_time"] for item in described),"WINDOW_IDENTITY_NOT_RETAINED")
                seen=session.request({"command":"ui_observe","hwnd":window["hwnd"]},timeout_s=30)
                box=next(item for item in seen["entities"] if item.get("automation_id")=="119" and "toggle" in item.get("actions",[]))
                quiet()
                toggled=session.request({"command":"ui_act","hwnd":window["hwnd"],"generation":seen["generation"],"ref":box["ref"],
                                         "operation":"toggle","postcondition":{"type":"state_equals","key":"toggle_state","value":"On"}})
                check(toggled.get("verified") is True,"TOGGLE_NOT_VERIFIED")
                seen=session.request({"command":"ui_observe","hwnd":window["hwnd"]})
                edit=next(item for item in seen["entities"] if item.get("automation_id")=="104" and "set_value" in item.get("actions",[]))
                marker=f"FF-{index}"
                quiet()
                typed=session.request({"command":"ui_act","hwnd":window["hwnd"],"generation":seen["generation"],"ref":edit["ref"],
                                       "operation":"set_value","action_args":{"value":marker},
                                       "postcondition":{"type":"value_equals","value":marker+chr(13)}})
                check(typed.get("verified") is True,"TEXT_NOT_VERIFIED")
                readback=session.request({"command":"ui_observe","hwnd":window["hwnd"]})
                check(any(item.get("automation_id")=="104" and item.get("value")==marker+chr(13)
                          for item in readback["entities"]),"INDEPENDENT_READBACK_FAILED")
                picture=session.request({"command":"capture_window","hwnd":window["hwnd"]})
                check(picture.get("frame_w",0)>100 and len(picture.get("image_base64",""))>1000,"HIDDEN_CAPTURE_NOT_PROVEN")
                health=session.request({"command":"health"})
                if health.get("ui_pid"):
                    token=process_creation_token(health["ui_pid"])
                    check(token is not None,"UIA_IDENTITY_UNAVAILABLE")
                    owned.append((health["ui_pid"],token))
                try:session.request({"command":"close_app","pid":window["pid"],"create_time":window["create_time"]+1})
                except HiddenDesktopError as exc:check(exc.code=="HIDDEN_APP_IDENTITY_CHANGED","WRONG_CREATION_TIME_DENIAL")
                else:raise RuntimeError("WRONG_CREATION_TIME_ACCEPTED")
                check(process_identity_matches(window["pid"],window["create_time"]),"WRONG_IDENTITY_KILLED_PROCESS")
            evidence.update({"two_private_desktops":True,"separate_gui_processes":True,"foreign_window_denied":True,
                             "native_window_desktop_verified":True,
                             "creation_time_guard":True,"toggle_verified":True,"text_verified":True,"independent_readback":True,
                             "hidden_capture_verified":True,"physical_input_used":False})
        except Exception as exc:
            failure=getattr(exc,"code",str(exc)) or type(exc).__name__
        finally:
            for session in sessions:
                try:session.close()
                except Exception as exc:
                    failure=failure or "HIDDEN_SESSION_CLEANUP_FAILED"
                    evidence.setdefault("cleanup_errors",[]).append(type(exc).__name__)
            deadline=time.monotonic()+5
            while time.monotonic()<deadline and any(process_identity_matches(pid,token) for pid,token in owned):time.sleep(.05)
            after=owner_state()
            finished.set();sampler.join(timeout=1)
            if observation_errors:failure=failure or observation_errors[0]
            evidence.update({"foreground_samples":samples[0],"foreground_unchanged":not foreground_changed.is_set() and before[0]==after[0],
                             "cursor_unchanged":before[1:3]==after[1:3],"clipboard_sequence_unchanged":before[3]==after[3],
                             "owner_state_unchanged":not changed.is_set() and before==after,
                             "owned_processes_closed":not any(process_identity_matches(pid,token) for pid,token in owned)})
            if original_root is None:os.environ.pop("FF_BRIDGE_ROOT",None)
            else:os.environ["FF_BRIDGE_ROOT"]=original_root
    checks=("owner_state_unchanged","foreground_unchanged","cursor_unchanged","clipboard_sequence_unchanged","owned_processes_closed")
    evidence["functional_status"]="PASS" if failure is None and evidence["owned_processes_closed"] else "FAIL"
    evidence["noninterference_status"]="PASS" if all(evidence[key] for key in checks) else "INCONCLUSIVE"
    if failure is None and all(evidence[key] for key in checks):evidence["status"]="PASS"
    elif (failure=="OWNER_STATE_CHANGED_DURING_SMOKE" or
          (failure is None and not evidence["owner_state_unchanged"])) and evidence["owned_processes_closed"]:
        evidence["status"]="INCONCLUSIVE";evidence["reason"]="OWNER_STATE_CHANGED_DURING_SMOKE"
    elif failure is not None:evidence["error_code"]=failure
    evidence["elapsed_ms"]=round((time.monotonic()-started)*1000)
    print(json.dumps(evidence,sort_keys=True))
    return 0 if evidence["status"]=="PASS" else 1


if __name__=="__main__":raise SystemExit(main())
