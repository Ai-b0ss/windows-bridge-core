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

U=ctypes.WinDLL("user32")
U.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
U.GetWindowThreadProcessId.restype=w.DWORD
U.IsWindowVisible.argtypes=[w.HWND];U.IsWindowVisible.restype=w.BOOL
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
plane=CuaBridgeControlPlane(Path(__file__).resolve().parent)
apps={}
uia_backend=None
uia_core=None
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
def owns(hwnd):
    pid=w.DWORD();U.GetWindowThreadProcessId(int(hwnd),ctypes.byref(pid))
    return pid.value in apps and apps[pid.value].poll() is None and int(hwnd) in windows(pid.value)
def handle(args):
    global uia_backend,uia_core
    command=args.get("command")
    if command=='editor.launch':
        from cua_owned_editor_launch import launch_editor
        def register(proc):apps[proc.pid]=proc
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
        return {"desktop":desktop,"input_desktop":input_desktop,"physical_input_used":False,"supported_apps":available_apps(),'supported_editor_apps':available_editors(),"uia_pid":uia_backend.supervisor.process.pid if uia_backend and uia_backend.supervisor.process else None,"apps":[{"pid":p.pid,"hwnds":windows(p.pid)} for p in apps.values() if p.poll() is None]}
    if command=="describe_owned_windows":
        from cua_native_hwnd import Win32Transport
        transport=Win32Transport()
        return {"windows":[{**transport.window_info(hwnd),"visible":bool(U.IsWindowVisible(hwnd))}
                for p in apps.values() if p.poll() is None for hwnd in windows(p.pid)]}
    if command in {"launch_notepad","launch_app"}:
        app,executable=launch_spec(args)
        si=subprocess.STARTUPINFO();si.dwFlags=subprocess.STARTF_USESHOWWINDOW;si.wShowWindow=4
        argv=[str(executable)]+{"excel":["/x"],"word":["/n"]}.get(app,[])
        if args.get('document_path'):argv.append(str(Path(args['document_path']).resolve()))
        if app=='powerpoint':
            # No documented isolated-instance switch: do not forward the file
            # to any existing process, including another hidden session.
            check=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-Command',"if(Get-Process POWERPNT -ErrorAction SilentlyContinue){exit 42}"],capture_output=True,timeout=10,creationflags=subprocess.CREATE_NO_WINDOW)
            if check.returncode==42:raise RuntimeError('OWN_POWERPOINT_EXISTING_PROCESS_UNSUPPORTED')
            if check.returncode!=0:raise RuntimeError('OWN_POWERPOINT_PROCESS_INVENTORY_FAILED')
        p=subprocess.Popen(argv,startupinfo=si)
        word_candidate_errors=[]
        apps[p.pid]=p;deadline=time.monotonic()+(25 if app in {"excel","word","powerpoint"} else 5)
        while time.monotonic()<deadline:
            found=windows(p.pid)
            from cua_native_hwnd import Win32Transport
            transport=Win32Transport()
            candidates=[]
            for hwnd in found:
                if not U.IsWindowVisible(hwnd) or U.GetWindow(hwnd,4):
                    continue
                info=transport.window_info(hwnd)
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
                return {"app":app,"pid":p.pid,"hwnd":hwnd,"desktop":desktop,"class_name":info["class_name"]}
            time.sleep(.02)
        if p.poll() is None:p.kill()
        p.wait(timeout=5);apps.pop(p.pid,None)
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
    for p in apps.values():
        if p.poll() is None:p.kill()
        p.wait(timeout=5)
