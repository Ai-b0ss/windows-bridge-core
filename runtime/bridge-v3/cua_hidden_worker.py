from __future__ import annotations
import ctypes
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from cua_bridge_v3 import CuaBridgeControlPlane
from cua_hidden_apps import available_apps,launch_spec,prepare_uia,main_window_area
from ff_win_process_identity import process_creation_token

U=ctypes.WinDLL("user32")
U.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
U.GetWindowThreadProcessId.restype=w.DWORD
U.IsWindowVisible.argtypes=[w.HWND];U.IsWindowVisible.restype=w.BOOL
U.GetWindowTextW.argtypes=[w.HWND,w.LPWSTR,ctypes.c_int];U.GetWindowTextW.restype=ctypes.c_int
U.GetWindow.argtypes=[w.HWND,w.UINT];U.GetWindow.restype=w.HWND
U.GetThreadDesktop.argtypes=[w.DWORD];U.GetThreadDesktop.restype=w.HANDLE
U.OpenInputDesktop.argtypes=[w.DWORD,w.BOOL,w.DWORD];U.OpenInputDesktop.restype=w.HANDLE
U.CloseDesktop.argtypes=[w.HANDLE]
U.GetUserObjectInformationW.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD)]
def name(handle):
    buf=ctypes.create_unicode_buffer(256);size=w.DWORD()
    if not U.GetUserObjectInformationW(handle,2,buf,ctypes.sizeof(buf),ctypes.byref(size)):
        raise RuntimeError("HIDDEN_DESKTOP_QUERY_FAILED")
    return buf.value
desktop=name(U.GetThreadDesktop(ctypes.windll.kernel32.GetCurrentThreadId()))
input_handle=U.OpenInputDesktop(0,False,1)
try:input_desktop=name(input_handle)
finally:U.CloseDesktop(input_handle)
if not desktop.startswith("FFBridge-Agent-") or desktop==input_desktop:
    raise RuntimeError("HIDDEN_DESKTOP_IDENTITY_INVALID")
class HiddenLaunchError(RuntimeError):
    def __init__(self,code,details=None):
        super().__init__(code);self.code=code;self.details=details or {}
plane=CuaBridgeControlPlane(Path(__file__).resolve().parent)
apps={}
app_tokens={}
uia_backend=None
uia_core=None
ui_backend=None
ui_core=None
panels={}
editors={}
def windows(pid):
    found=[];callback_type=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
    @callback_type
    def callback(hwnd,_):
        actual=w.DWORD();U.GetWindowThreadProcessId(hwnd,ctypes.byref(actual))
        if actual.value==pid:found.append(int(hwnd))
        return True
    U.EnumWindows(callback,0)
    return found
def register_app(process):
    token=process_creation_token(process.pid)
    if token is None:
        if process.poll() is None:process.kill()
        process.wait(timeout=5)
        raise HiddenLaunchError("HIDDEN_APP_IDENTITY_UNAVAILABLE")
    apps[process.pid]=process
    app_tokens[process.pid]=token

def live_app(pid):
    process=apps.get(pid)
    return (process is not None and process.poll() is None
            and app_tokens.get(pid) is not None
            and process_creation_token(pid)==app_tokens[pid])

def owns(hwnd):
    if type(hwnd) is not int or hwnd<=0:return False
    pid=w.DWORD();U.GetWindowThreadProcessId(int(hwnd),ctypes.byref(pid))
    return live_app(pid.value) and int(hwnd) in windows(pid.value)
def handle(args):
    global uia_backend,uia_core,ui_backend,ui_core
    command=args.get("command")
    if command=='editor.launch':
        from cua_owned_editor_launch import launch_editor
        def register(proc):register_app(proc)
        ctx=launch_editor(args['__owned_editor_root'],args.get('app'),args.get('document_path'),register,
            executable=args.get('executable'),expected_executable_sha256=args.get('expected_executable_sha256'))
        hwnd=ctx['discovery']['window']['hwnd'];editors[hwnd]=ctx;ctx['generation']=0;ctx['ref']=None
        return {'app':args['app'],'hwnd':hwnd,'pid':ctx['proc'].pid,'desktop':desktop,'route':'NATIVE_EDITOR_API','physical_input_used':False}
    if command in {'editor.observe','editor.replace_save'}:
        from cua_vscode_native import host_request
        import uuid
        hwnd=args.get('hwnd')
        if type(hwnd) is not int or not owns(hwnd) or hwnd not in editors:raise RuntimeError('HIDDEN_EDITOR_NOT_OWNED')
        ctx=editors[hwnd]
        if command=='editor.observe':
            result=host_request(ctx['config'],ctx['discovery'],'observe');ctx['generation']+=1;ctx['ref']=uuid.uuid4().hex;ctx['observed']=result['document']
            return {**result,'hwnd':hwnd,'generation':ctx['generation'],'ref':ctx['ref'],'route':'NATIVE_EDITOR_API'}
        observed=ctx.get('observed')
        if observed is None or type(args.get('generation')) is not int or type(args.get('ref')) is not str or not ctx['ref'] or args.get('generation')!=ctx['generation'] or args.get('ref')!=ctx['ref'] or args.get('expected_text')!=observed['text']:
            raise RuntimeError('EDITOR_OBSERVATION_CHANGED')
        ctx['ref']=None # consume before dispatch, including lost/unknown outcomes
        return {**host_request(ctx['config'],ctx['discovery'],'replace_save',expected_version=observed['version'],
            expected_text=observed['text'],expected_file_sha256=observed['file_sha256'],text=args.get('replacement_text')),
            'hwnd':hwnd,'route':'NATIVE_EDITOR_API'}
    if command in {"document.save","document.read","document.replace"}:
        hwnd=args.get('hwnd');book=args.get('document_path')
        if type(hwnd) is not int or not owns(hwnd):raise RuntimeError('HIDDEN_WINDOW_NOT_OWNED')
        if not isinstance(book,str) or not Path(book).is_absolute() or Path(book).suffix.casefold() not in {'.xlsx','.docx','.pptx'}:raise RuntimeError('HIDDEN_DOCUMENT_INVALID')
        if command!='document.save' and Path(book).suffix.casefold() not in {'.docx','.pptx'}:raise RuntimeError('HIDDEN_DOCUMENT_OPERATION_UNSUPPORTED')
        if command=='document.replace' and any(not isinstance(args.get(key),str) or len(args[key])>65536 for key in ('expected_text','replacement_text')):raise RuntimeError('HIDDEN_DOCUMENT_TEXT_INVALID')
        if uia_backend is None:
            from cua_native_uia3 import Uia3PersistentBackend
            uia_backend=Uia3PersistentBackend(prepare_uia(Path(__file__).resolve().parent),timeout_seconds=8,no_focus=True)
        pid=w.DWORD();U.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
        if Path(book).suffix.casefold()=='.pptx':
            if command=='document.replace' and (type(args.get('slide_id')) is not int or type(args.get('shape_id')) is not int or not isinstance(args.get('shape_name'),str) or len(args['shape_name'])>1024):raise RuntimeError('HIDDEN_DOCUMENT_TARGET_INVALID')
            return uia_backend._request('powerpoint_document',{'hwnd':hwnd,'pid':pid.value,'document_path':str(Path(book).resolve()),'action':command.split('.')[1],'slide_id':args.get('slide_id'),'shape_id':args.get('shape_id'),'shape_name':args.get('shape_name'),'expected_text':args.get('expected_text'),'replacement_text':args.get('replacement_text')})
        if Path(book).suffix.casefold()=='.docx':
            return uia_backend._request('word_document',{'hwnd':hwnd,'pid':pid.value,'document_path':str(Path(book).resolve()),'action':command.split('.')[1],'expected_text':args.get('expected_text'),'replacement_text':args.get('replacement_text')})
        return uia_backend._request('excel_save',{'hwnd':hwnd,'pid':pid.value,'book_path':str(Path(book).resolve())})
    if command in {"panel.discover","panel.inspect","panel.type","panel.invoke","panel.verify"}:
        from cua_universal_fastpath import UniversalFastPath
        from cua_native_hwnd import Win32Transport
        hwnd=args.get('hwnd')
        if type(hwnd) is not int or not owns(hwnd):raise RuntimeError('HIDDEN_WINDOW_NOT_OWNED')
        fp=UniversalFastPath()
        if command=="panel.discover":
            window=Win32Transport().window_info(hwnd)
            cdp=fp._pick_pid_listener_cdp(window)
            if cdp is None:raise RuntimeError('OWN_PANEL_UNAVAILABLE_OR_AMBIGUOUS')
            discovery={'route':'APP_CDP','window':window,'cdp':cdp}
            if not fp._panel_owner_valid(discovery) or not fp._cdp_identity_valid(cdp):raise RuntimeError('STALE_TARGET')
            import uuid
            panel_id=uuid.uuid4().hex;panels[panel_id]=discovery
            return {'panel_id':panel_id,'window':window,'route':'APP_CDP','verified':True,'physical_input_used':False}
        discovery=panels.get(args.get('panel_id'))
        if discovery is None or discovery['window']['hwnd']!=hwnd:raise RuntimeError('HIDDEN_PANEL_NOT_OWNED')
        return fp.panel_action(discovery,command,action_args=args.get('action_args'))
    if command=="health":
        from cua_owned_editor_launch import available_editors
        return {"desktop":desktop,"input_desktop":input_desktop,"physical_input_used":False,"supported_apps":available_apps(),'supported_editor_apps':available_editors(),"uia_pid":uia_backend.supervisor.process.pid if uia_backend and uia_backend.supervisor.process else None,
                "ui_pid":ui_backend.supervisor.process.pid if ui_backend and ui_backend.supervisor.process else None,
                "apps":[{"pid":p.pid,"create_time":app_tokens[p.pid],"hwnds":windows(p.pid)} for p in apps.values() if live_app(p.pid)]}
    if command=="describe_owned_windows":
        from cua_native_hwnd import Win32Transport
        transport=Win32Transport()
        return {"windows":[{**transport.window_info(hwnd),"create_time":app_tokens[p.pid],"visible":bool(U.IsWindowVisible(hwnd))}
                for p in apps.values() if live_app(p.pid) for hwnd in windows(p.pid) if owns(hwnd)]}
    if command=="launch_exe":
        # Generic owned application: no per-app list. Only this process's own top-level
        # window is returned; an app that hands off to another instance is reported as such.
        from cua_hidden_apps import generic_launch_spec
        from cua_native_hwnd import Win32Transport
        executable,arguments,directory,timeout=generic_launch_spec(args)
        si=subprocess.STARTUPINFO();si.dwFlags=subprocess.STARTF_USESHOWWINDOW;si.wShowWindow=4
        p=subprocess.Popen([str(executable),*arguments],startupinfo=si,cwd=directory)
        register_app(p);deadline=time.monotonic()+timeout;transport=Win32Transport()
        while time.monotonic()<deadline:
            if p.poll() is not None:
                apps.pop(p.pid,None);app_tokens.pop(p.pid,None)
                raise HiddenLaunchError("HIDDEN_APP_EXITED_BEFORE_WINDOW",{"exit_code":p.returncode,
                    "hint":"the program ended or handed off to another instance; it has no own window here"})
            best=None
            for hwnd in windows(p.pid):
                if not U.IsWindowVisible(hwnd) or U.GetWindow(hwnd,4):continue
                info=transport.window_info(hwnd);geometry=info.get("geometry") or {}
                area=max(0,geometry.get("right",0)-geometry.get("left",0))*max(0,geometry.get("bottom",0)-geometry.get("top",0))
                if area>0 and (best is None or area>best[0]):best=(area,hwnd,info)
            if best:
                _,hwnd,info=best
                if not owns(hwnd):raise HiddenLaunchError("HIDDEN_APP_IDENTITY_CHANGED")
                return {"app":executable.name,"executable":str(executable),"pid":p.pid,"create_time":app_tokens[p.pid],"hwnd":hwnd,"desktop":desktop,
                        "class_name":info["class_name"],"title":info.get("title"),"route":"HIDDEN_DESKTOP_GENERIC","physical_input_used":False}
            time.sleep(.05)
        p.kill();p.wait(timeout=5);apps.pop(p.pid,None);app_tokens.pop(p.pid,None)
        raise HiddenLaunchError("HIDDEN_APP_WINDOW_NOT_FOUND",{"hint":"no visible top-level window appeared on the private desktop"})
    if command=="close_app":
        pid=args.get("pid")
        if type(pid) is not int or pid not in apps:raise RuntimeError("HIDDEN_APP_NOT_OWNED")
        p=apps[pid]
        if "create_time" in args and (type(args["create_time"]) is not int or args["create_time"]!=app_tokens.get(pid)):
            raise RuntimeError("HIDDEN_APP_IDENTITY_CHANGED")
        if p.poll() is None:p.kill()
        p.wait(timeout=5)
        apps.pop(pid,None);app_tokens.pop(pid,None)
        return {"pid":pid,"closed":True}
    if command in {"launch_notepad","launch_app"}:
        app,executable=launch_spec(args)
        si=subprocess.STARTUPINFO();si.dwFlags=subprocess.STARTF_USESHOWWINDOW;si.wShowWindow=4
        argv=[str(executable)]+{"excel":["/x"],"word":["/n"],
            "claude":["--force-renderer-accessibility=complete"]}.get(app,[])
        if args.get('document_path'):argv.append(str(Path(args['document_path']).resolve()))
        if app=="claude" and args.get("code_link"):
            argv.extend(["--",args["code_link"]])
        if app=='claude':
            # Claude Desktop is a packaged full-trust Electron singleton.
            # Starting the MSIX alias when another Claude.exe is running could
            # activate that *other* process on the owner's visible desktop.
            # Fail closed even if the other process is a CLI named claude.exe.
            from ff_hub_apps import count_processes
            running=count_processes("Claude.exe")
            if running is None:
                raise HiddenLaunchError("OWN_CLAUDE_PROCESS_INVENTORY_FAILED")
            if running:
                raise HiddenLaunchError("OWN_CLAUDE_EXISTING_PROCESS_UNSUPPORTED")
            if executable.name.casefold()!="claude-desktop.exe":
                raise HiddenLaunchError("OWN_CLAUDE_ALIAS_REQUIRED")
        if app=='powerpoint':
            # No documented isolated-instance switch: do not forward the file
            # to any existing process, including another hidden session.
            check=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-Command',"if(Get-Process POWERPNT -ErrorAction SilentlyContinue){exit 42}"],capture_output=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
            if check.returncode==42:raise RuntimeError('OWN_POWERPOINT_EXISTING_PROCESS_UNSUPPORTED')
            if check.returncode!=0:raise RuntimeError('OWN_POWERPOINT_PROCESS_INVENTORY_FAILED')
        if app=="claude":
            from cua_owned_msix_alias import OwnedMsixAliasProcess
            p=OwnedMsixAliasProcess(executable,argv[1:],desktop)
        else:
            p=subprocess.Popen(argv,startupinfo=si)
        word_candidate_errors=[]
        register_app(p);deadline=time.monotonic()+(25 if app in {"excel","word","powerpoint","claude"} else 5)
        while time.monotonic()<deadline:
            found=windows(p.pid)
            from cua_native_hwnd import Win32Transport
            transport=Win32Transport()
            candidates=[]
            for hwnd in found:
                if not U.IsWindowVisible(hwnd) or U.GetWindow(hwnd,4):
                    continue
                info=transport.window_info(hwnd)
                if app=="claude":
                    # Native window_info intentionally omits captions. An
                    # exact title AND class guard prevents selecting Electron's
                    # invisible utility frames or IME windows.
                    caption=ctypes.create_unicode_buffer(256)
                    U.GetWindowTextW(hwnd,caption,len(caption))
                    info["title"]=caption.value
                area=main_window_area(app,info,bool(U.IsWindowVisible(hwnd)),bool(U.GetWindow(hwnd,4)))
                if area is None:continue
                if app in {'word','powerpoint'} and args.get('document_path'):
                    # Office recovery can create several frames. Bind the
                    # requested native document before selecting a window.
                    if uia_backend is None:
                        from cua_native_uia3 import Uia3PersistentBackend
                        uia_backend=Uia3PersistentBackend(prepare_uia(Path(__file__).resolve().parent),timeout_seconds=8,no_focus=True)
                    from cua_native_core import NativeError
                    try:
                        uia_backend._request('word_document' if app=='word' else 'powerpoint_document',{'hwnd':hwnd,'pid':p.pid,'document_path':str(Path(args['document_path']).resolve()),'action':'read'})
                    except NativeError as exc:
                        if exc.code not in {'OWN_DOCUMENT_IDENTITY_MISMATCH','OWN_WORD_NATIVE_OBJECT_NOT_UNIQUE','OWN_WORD_DOCUMENT_FAILED','OWN_POWERPOINT_NATIVE_WINDOW_NOT_UNIQUE','OWN_POWERPOINT_READ_FAILED'}:raise
                        if len(word_candidate_errors)<12:word_candidate_errors.append({'hwnd':hwnd,'code':exc.code,'message':exc.message,'details':exc.details})
                        continue
                candidates.append((area,hwnd,info))
            if candidates:
                _,hwnd,info=max(candidates,key=lambda item:item[0])
                if not owns(hwnd):raise HiddenLaunchError("HIDDEN_APP_IDENTITY_CHANGED")
                return {"app":app,"pid":p.pid,"create_time":app_tokens[p.pid],"hwnd":hwnd,"desktop":desktop,"class_name":info["class_name"]}
            time.sleep(.02)
        if p.poll() is None:p.kill()
        p.wait(timeout=5);apps.pop(p.pid,None);app_tokens.pop(p.pid,None)
        if app in {'word','powerpoint'}:
            from cua_native_core import NativeError
            raise NativeError('HIDDEN_APP_WINDOW_NOT_FOUND',details={('owned_word_candidate_errors' if app=='word' else 'owned_powerpoint_candidate_errors'):word_candidate_errors})
        raise RuntimeError("HIDDEN_APP_WINDOW_NOT_FOUND")
    if command=="capture_window":
        from cua_hidden_capture import capture_owned_window
        return capture_owned_window(args.get("hwnd"), owns)
    if command in {"read_notepad","read_text"}:
        from cua_native_hwnd import Win32Transport
        from cua_hidden_apps import read_document_text
        hwnd=args.get("hwnd",0)
        if type(hwnd) is not int or not owns(hwnd):
            raise RuntimeError("HIDDEN_WINDOW_NOT_OWNED")
        transport=Win32Transport()
        return read_document_text(transport, hwnd, owns)
    if command in {"ui_observe","ui_find","ui_act"}:
        # Full UI Automation patterns (toggle, set_value, select, expand, scroll, invoke) for
        # owned windows. Safe here and only here: this worker proved at start that its desktop
        # is a private FFBridge-Agent desktop and not the input desktop, so any focus change a
        # pattern causes stays on this desktop and never reaches the owner's.
        from cua_hidden_apps import GENERIC_LAUNCH_ENV
        from cua_native_core import NativeSemanticCore,NativeError
        from cua_native_uia3 import Uia3PersistentBackend
        if os.environ.get(GENERIC_LAUNCH_ENV)!="1":raise RuntimeError("HIDDEN_GENERIC_UI_DISABLED")
        hwnd=args.get("hwnd",0)
        if type(hwnd) is not int or not owns(hwnd):raise RuntimeError("HIDDEN_WINDOW_NOT_OWNED")
        if ui_backend is None:
            ui_backend=Uia3PersistentBackend(prepare_uia(Path(__file__).resolve().parent),timeout_seconds=10,no_focus=False)
            ui_core=NativeSemanticCore(ui_backend)
        if command=="ui_observe":
            result=ui_core.observe({"hwnd":hwnd},args.get("options"))
        else:
            generation=args.get("generation")
            state=ui_core._snapshots.get(generation) if type(generation) is int else None
            if not state or state.target!={"hwnd":hwnd}:raise NativeError("STALE_TARGET")
            if command=="ui_find":
                result=ui_core.find(generation,args.get("query"))
            else:
                if not isinstance(args.get("postcondition"),dict):raise NativeError("HIDDEN_UIA_POSTCONDITION_REQUIRED")
                result=ui_core.act(args.get("ref"),args.get("operation"),args.get("action_args"),
                    args["postcondition"],{"background_required":False},generation=generation)
                if not result["verified"]:
                    raise NativeError("POSTCONDITION_FAILED",details={"retry_safe":False,"attempted":True,"result":result})
        return {**result,"route":"HIDDEN_DESKTOP_UIA_PATTERNS","private_desktop":desktop,
                "owner_desktop_access_allowed":False,"physical_input_used":False}
    if command in {"uia_observe","uia_find","uia_act"}:
        from cua_native_core import NativeSemanticCore,NativeError
        from cua_native_uia3 import Uia3PersistentBackend
        hwnd=args.get("hwnd",0)
        if type(hwnd) is not int or not owns(hwnd):
            raise RuntimeError("HIDDEN_WINDOW_NOT_OWNED")
        if uia_backend is None:
            uia_backend=Uia3PersistentBackend(prepare_uia(Path(__file__).resolve().parent),timeout_seconds=8,no_focus=True)
        if uia_core is None:
            uia_core=NativeSemanticCore(uia_backend)
        if command=="uia_observe":
            result=uia_core.observe({"hwnd":hwnd},args.get("options"))
        else:
            generation=args.get("generation")
            state=uia_core._snapshots.get(generation) if type(generation) is int else None
            if not state or state.target!={"hwnd":hwnd}:
                raise NativeError("STALE_TARGET")
            if command=="uia_find":
                result=uia_core.find(generation,args.get("query"))
            else:
                if not isinstance(args.get("postcondition"),dict):
                    raise NativeError("HIDDEN_UIA_POSTCONDITION_REQUIRED")
                result=uia_core.act(args.get("ref"),args.get("operation"),args.get("action_args"),
                    args["postcondition"],{"background_required":False},generation=generation)
                if not result["verified"]:
                    raise NativeError("POSTCONDITION_FAILED",details={"retry_safe":False,"result":result})
        return {**result,"route":"HIDDEN_UIA_MSAA","private_desktop":desktop,
                "private_desktop_exclusive":True,"owner_desktop_access_allowed":False,"physical_input_used":False}
    if command not in {"attach","observe","find","act","wait","close"}:
        raise RuntimeError("HIDDEN_COMMAND_UNSUPPORTED")
    payload=dict(args)
    payload["policy"]={"background_required":True,"foreground_allowed":False,"physical_input_allowed":False,"require_verified":True}
    if command=="attach":
        target=payload.get("target") or {}
        if not owns(target.get("hwnd",0)):
            raise RuntimeError("HIDDEN_WINDOW_NOT_OWNED")
        payload["surface_kind"]="native";payload["route"]="HWND_MESSAGE"
    else:
        surface=plane._surfaces.get(payload.get("surface_id"))
        if not surface or not owns(surface.get("target",{}).get("hwnd",0)):
            raise RuntimeError("HIDDEN_WINDOW_NOT_OWNED")
    return plane.dispatch(payload)
try:
    for line in sys.stdin:
        request_id=None
        try:
            request=json.loads(line);request_id=request.get("id")
            result=handle(request.get("args") or {})
            reply={"id":request_id,"ok":True,"result":result}
        except Exception as exc:
            reply={"id":request_id,"ok":False,"error_code":getattr(exc,"code",str(exc)),"details":{**getattr(exc,"details",{}),"message":getattr(exc,"message",str(exc))}}
        print(json.dumps(reply,ensure_ascii=True),flush=True)
finally:
    plane.close()
    if uia_backend is not None:uia_backend.close()
    if ui_backend is not None:ui_backend.close()
    for p in apps.values():
        if p.poll() is None:p.kill()
        p.wait(timeout=5)
