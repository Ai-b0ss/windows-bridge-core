"""Windows AppContainer execution: zero capabilities, Win32k lockdown, private workspace."""
from __future__ import annotations
import ctypes,json,os,shutil,subprocess,sys,tempfile,time,uuid
from ctypes import wintypes as w
from pathlib import Path
from types import SimpleNamespace
class RestrictedExecutionError(RuntimeError):
    def __init__(self,code,details=None):
        super().__init__(code);self.code=code;self.details=details or {}

def _profile_environment_details(hresult):
    """Diagnostic facts only; never derive a SID or relax the native sandbox."""
    details={"hresult":hresult,"hresult_hex":f"0x{hresult & 0xffffffff:08x}",
             "fallback_used":False,"required_isolation":"windows_appcontainer"}
    try:
        a=ctypes.WinDLL("advapi32",use_last_error=True); k=ctypes.WinDLL("kernel32",use_last_error=True)
        a.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)]
        a.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
        a.IsTokenRestricted.argtypes=[w.HANDLE];k.GetCurrentProcess.restype=w.HANDLE;k.CloseHandle.argtypes=[w.HANDLE]
        token=w.HANDLE()
        if a.OpenProcessToken(k.GetCurrentProcess(),8,ctypes.byref(token)):
            try:
                details["parent_token_restricted"]=bool(a.IsTokenRestricted(token))
                value=w.DWORD();size=w.DWORD()
                if a.GetTokenInformation(token,29,ctypes.byref(value),ctypes.sizeof(value),ctypes.byref(size)):
                    details["parent_is_appcontainer"]=bool(value.value)
            finally:k.CloseHandle(token)
        details["localappdata_exists"]=Path(os.environ.get("LOCALAPPDATA","")).is_dir()
        # A missing-profile HRESULT can conceal a denied native store. Read
        # only the documented AppContainer store, never account/auth data.
        a.RegOpenKeyExW.argtypes=[w.HANDLE,w.LPCWSTR,w.DWORD,w.DWORD,ctypes.POINTER(w.HANDLE)]
        a.RegOpenKeyExW.restype=ctypes.c_long;a.RegCloseKey.argtypes=[w.HANDLE]
        mappings=w.HANDLE()
        status=a.RegOpenKeyExW(w.HANDLE(-2147483647),r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings",0,0x20019,ctypes.byref(mappings))
        details["profile_store_read_open_winerror"]=int(status)
        if status==0:a.RegCloseKey(mappings)
    except (OSError,AttributeError):details["environment_diagnostics_available"]=False
    if (hresult & 0xffffffff)==0x80070002:
        details["recovery_gate"]="Native profile API returned FILE_NOT_FOUND; check profile-store access and restricted parent token in an authorized ordinary user session. Do not modify profile ACLs, derive a replacement SID, or substitute ordinary shell."
    return details
class SecurityCapabilities(ctypes.Structure):
    _fields_=[("AppContainerSid",w.LPVOID),("Capabilities",w.LPVOID),("CapabilityCount",w.DWORD),("Reserved",w.DWORD)]
class IO_COUNTERS(ctypes.Structure):
    _fields_=[(n,ctypes.c_ulonglong) for n in ("ReadOperationCount","WriteOperationCount","OtherOperationCount","ReadTransferCount","WriteTransferCount","OtherTransferCount")]
class BASIC_LIMIT(ctypes.Structure):
    _fields_=[("PerProcessUserTimeLimit",ctypes.c_longlong),("PerJobUserTimeLimit",ctypes.c_longlong),("LimitFlags",w.DWORD),
              ("MinimumWorkingSetSize",ctypes.c_size_t),("MaximumWorkingSetSize",ctypes.c_size_t),("ActiveProcessLimit",w.DWORD),
              ("Affinity",ctypes.c_size_t),("PriorityClass",w.DWORD),("SchedulingClass",w.DWORD)]
class EXTENDED_LIMIT(ctypes.Structure):
    _fields_=[("BasicLimitInformation",BASIC_LIMIT),("IoInfo",IO_COUNTERS),("ProcessMemoryLimit",ctypes.c_size_t),
              ("JobMemoryLimit",ctypes.c_size_t),("PeakProcessMemoryUsed",ctypes.c_size_t),("PeakJobMemoryUsed",ctypes.c_size_t)]
class RestrictedWorkspace:
    """Keep ownership outside the sandbox-writable task directory."""
    def __init__(self, parent, delete_profile):
        from cua_global_resources import _StateLock, process_creation_identity, process_is_same
        from cua_browser_profiles import linked, remove_owned_tree
        self.parent = Path(parent)
        if linked(self.parent):
            raise RestrictedExecutionError("RESTRICTED_WORKSPACE_ROOT_LINK")
        self.parent.mkdir(parents=True, exist_ok=True)
        self.delete_profile = delete_profile
        self.owner = {"schema": 1, "kind": "ff-restricted-run", "pid": os.getpid(),
                      "creation": process_creation_identity(), "nonce": uuid.uuid4().hex}
        self.path = self.parent / ("run-" + self.owner["nonce"])
        self.profile = "FFBridge.Restricted." + self.owner["nonce"]
        self.reclaimed = 0
        with _StateLock(self.parent / "runs.lock"):
            for candidate in self.parent.iterdir():
                owner = self.read_owner(candidate)
                if owner is None or process_is_same(owner["pid"], owner["creation"]):
                    continue
                if owner.get("profile_state") != "absent":
                    self.delete_profile("FFBridge.Restricted." + owner["nonce"])
                remove_owned_tree(candidate, owner)
                self.reclaimed += 1
            self.path.mkdir()
            (self.path / "owner.json").write_text(json.dumps(self.owner), encoding="utf-8")

    @staticmethod
    def read_owner(candidate):
        import re
        from cua_browser_profiles import linked
        if not re.fullmatch(r"run-[0-9a-f]{32}", candidate.name) or linked(candidate) or not candidate.is_dir():
            return None
        marker = candidate / "owner.json"
        try:
            if linked(marker) or marker.stat().st_size > 4096:
                return None
            owner = json.loads(marker.read_text(encoding="utf-8"))
            if (not isinstance(owner, dict) or owner.get("schema") != 1 or
                owner.get("kind") != "ff-restricted-run" or type(owner.get("pid")) is not int or
                owner["pid"] <= 0 or not isinstance(owner.get("creation"), str) or
                not re.fullmatch(r"(?:win|proc):[0-9]+", owner["creation"]) or
                candidate.name != "run-" + str(owner.get("nonce"))):
                return None
            return owner
        except (OSError, ValueError):
            return None

    def __enter__(self):
        return str(self.path)

    def profile_creation_failed(self):
        """A failed native create with no returned SID has no profile to delete.

        Keep older/pending markers conservative: a crash after creation still
        requires native cleanup of that exact unpredictable owned name.
        """
        from cua_global_resources import _StateLock
        with _StateLock(self.parent / "runs.lock"):
            if self.read_owner(self.path) != self.owner:
                raise RestrictedExecutionError("RESTRICTED_WORKSPACE_OWNERSHIP_CHANGED")
            updated = {**self.owner, "profile_state": "absent"}
            marker = self.path / "owner.json"
            temporary = self.path / "owner.json.tmp"
            with temporary.open("x", encoding="utf-8") as stream:
                json.dump(updated, stream)
                stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, marker)
            self.owner = updated

    def __exit__(self, *_):
        from cua_global_resources import _StateLock
        from cua_browser_profiles import remove_owned_tree
        with _StateLock(self.parent / "runs.lock"):
            if self.read_owner(self.path) != self.owner:
                raise RestrictedExecutionError("RESTRICTED_WORKSPACE_OWNERSHIP_CHANGED")
            if self.owner.get("profile_state") != "absent":
                self.delete_profile(self.profile)
            remove_owned_tree(self.path, self.owner)

def validate_request(code,timeout_seconds):
    if not isinstance(code,str) or not code or len(code.encode("utf-8"))>262144:
        raise RestrictedExecutionError("RESTRICTED_CODE_INVALID")
    if type(timeout_seconds) not in (int,float) or not 0<timeout_seconds<=60:
        raise RestrictedExecutionError("RESTRICTED_TIMEOUT_INVALID")
def _call(argv):
    result=subprocess.run(argv,capture_output=True,timeout=30,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
    if result.returncode:raise RestrictedExecutionError("RESTRICTED_ACL_FAILED",{"exit_code":result.returncode})
def _grant(path,sid,rights):
    _call(["icacls.exe",str(path),"/grant","*"+sid+":(OI)(CI)"+rights,"/T","/C"])
    _call(["icacls.exe",str(path),"/setintegritylevel","(OI)(CI)L","/T","/C"])
def _source_python():
    candidates=[Path(sys.executable).parent,Path(os.environ.get("LOCALAPPDATA",""))/"FF-Windows-Bridge/tools/python-3.13.9-embed"]
    for root in candidates:
        if (root/"python.exe").is_file() and (root/"python313.zip").is_file():return root
    raise RestrictedExecutionError("RESTRICTED_EMBEDDED_PYTHON_UNAVAILABLE")
def run_python(code,*,timeout_seconds=30,base=None):
    validate_request(code,timeout_seconds)
    if os.name!="nt":raise RestrictedExecutionError("RESTRICTED_EXECUTION_WINDOWS_ONLY")
    import msvcrt
    from cua_hidden_desktop import _StartupInfo,_ProcessInfo
    from cua_sidecar_supervisor import _bind_windows_kill_on_close_job,_close_windows_job_handle
    class StartupEx(ctypes.Structure):
        _fields_=[("StartupInfo",_StartupInfo),("lpAttributeList",w.LPVOID)]
    k=ctypes.WinDLL("kernel32",use_last_error=True)
    a=ctypes.WinDLL("advapi32",use_last_error=True)
    u=ctypes.WinDLL("userenv",use_last_error=True)
    def bind(dll,name,args,restype=w.BOOL):
        fn=getattr(dll,name);fn.argtypes=args;fn.restype=restype;return fn
    bind(u,"CreateAppContainerProfile",[w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,w.LPVOID,w.DWORD,ctypes.POINTER(w.LPVOID)],ctypes.c_long)
    bind(u,"DeleteAppContainerProfile",[w.LPCWSTR],ctypes.c_long)
    bind(a,"FreeSid",[w.LPVOID],w.LPVOID)
    bind(a,"ConvertSidToStringSidW",[w.LPVOID,ctypes.POINTER(w.LPWSTR)])
    bind(a,"OpenProcessToken",[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)])
    bind(a,"GetTokenInformation",[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)])
    bind(k,"InitializeProcThreadAttributeList",[w.LPVOID,w.DWORD,w.DWORD,ctypes.POINTER(ctypes.c_size_t)])
    bind(k,"UpdateProcThreadAttribute",[w.LPVOID,w.DWORD,ctypes.c_size_t,w.LPVOID,ctypes.c_size_t,w.LPVOID,w.LPVOID])
    bind(k,"DeleteProcThreadAttributeList",[w.LPVOID],None)
    bind(k,"CreateProcessW",[w.LPCWSTR,w.LPWSTR,w.LPVOID,w.LPVOID,w.BOOL,w.DWORD,w.LPVOID,w.LPCWSTR,ctypes.POINTER(StartupEx),ctypes.POINTER(_ProcessInfo)])
    bind(k,"SetHandleInformation",[w.HANDLE,w.DWORD,w.DWORD])
    bind(k,"CloseHandle",[w.HANDLE])
    bind(k,"LocalFree",[w.LPVOID],w.LPVOID)
    bind(k,"ResumeThread",[w.HANDLE],w.DWORD)
    bind(k,"TerminateProcess",[w.HANDLE,w.UINT])
    bind(k,"WaitForSingleObject",[w.HANDLE,w.DWORD],w.DWORD)
    bind(k,"GetExitCodeProcess",[w.HANDLE,ctypes.POINTER(w.DWORD)])
    bind(k,"GetProcessMitigationPolicy",[w.HANDLE,ctypes.c_int,w.LPVOID,ctypes.c_size_t])
    bind(k,"SetInformationJobObject",[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD])
    bind(k,"TerminateJobObject",[w.HANDLE,w.UINT])
    bind(k,"QueryInformationJobObject",[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,w.LPVOID])
    def check(ok,operation):
        if not ok:raise RestrictedExecutionError("RESTRICTED_NATIVE_FAILED",{"operation":operation,"winerror":ctypes.get_last_error()})
    sid=w.LPVOID();sid_text=None;profile=False;attributes=None;job=None;pi=_ProcessInfo()
    parent=Path(base) if base else Path(os.environ["LOCALAPPDATA"])/"FFWindowsBridge/state/restricted"
    source=_source_python()
    def delete_profile(name):
        hr=u.DeleteAppContainerProfile(name)
        if hr<0:raise RestrictedExecutionError("RESTRICTED_PROFILE_DELETE_FAILED",{"hresult":hr})
    workspace=RestrictedWorkspace(parent,delete_profile)
    identity=workspace.profile
    with workspace as directory:
        root=Path(directory);toolchain=root/"python";task=root/"task";toolchain.mkdir();task.mkdir()
        for file in source.iterdir():
            if file.is_file() and (file.suffix.lower() in {".dll",".pyd",".exe",".zip"} or file.name=="python313._pth"):
                shutil.copyfile(file,toolchain/file.name)
        (toolchain/"python313._pth").write_text(chr(10).join(["python313.zip",".",""]),encoding="utf-8")
        (task/"payload.py").write_text(code,encoding="utf-8")
        argv=[str(toolchain/"python.exe"),"-I","-X","utf8",str(task/"payload.py")]
        try:
            hr=u.CreateAppContainerProfile(identity,identity,"FF Bridge restricted execution",None,0,ctypes.byref(sid))
            if hr<0:
                if not sid.value:workspace.profile_creation_failed()
                raise RestrictedExecutionError("RESTRICTED_PROFILE_CREATE_FAILED",_profile_environment_details(hr))
            profile=True
            text=w.LPWSTR();check(a.ConvertSidToStringSidW(sid,ctypes.byref(text)),"sid_text")
            try:sid_text=text.value
            finally:k.LocalFree(text)
            _grant(root,sid_text,"RX");_grant(task,sid_text,"M")
            with open(os.devnull,"rb") as stdin,open(task/"stdout.bin","w+b") as stdout,open(task/"stderr.bin","w+b") as stderr:
                handles=(w.HANDLE*3)(*[msvcrt.get_osfhandle(stream.fileno()) for stream in (stdin,stdout,stderr)])
                for handle in handles:check(k.SetHandleInformation(handle,1,1),"inherit_stdio")
                count=3;size=ctypes.c_size_t()
                k.InitializeProcThreadAttributeList(None,count,0,ctypes.byref(size))
                attributes=ctypes.create_string_buffer(size.value)
                check(k.InitializeProcThreadAttributeList(attributes,count,0,ctypes.byref(size)),"attributes")
                caps=SecurityCapabilities(sid,None,0,0);mitigation=ctypes.c_ulonglong(1<<28)
                for key,value in [(0x20009,caps),(0x20002,handles),(0x20007,mitigation)]:
                    check(k.UpdateProcThreadAttribute(attributes,0,key,ctypes.byref(value),ctypes.sizeof(value),None,None),"attribute_"+hex(key))
                si=StartupEx();si.StartupInfo.cb=ctypes.sizeof(si);si.StartupInfo.dwFlags=0x100
                si.StartupInfo.hStdInput,si.StartupInfo.hStdOutput,si.StartupInfo.hStdError=handles
                si.lpAttributeList=ctypes.cast(attributes,w.LPVOID)
                env={"SystemRoot":os.environ["SystemRoot"],"WINDIR":os.environ["SystemRoot"],
                     "PATH":str(toolchain)+os.pathsep+str(Path(os.environ["SystemRoot"])/"System32"),
                     "TEMP":str(task),"TMP":str(task),"LOCALAPPDATA":str(task),"USERPROFILE":str(task),
                     "PYTHONIOENCODING":"utf-8","PYTHONUTF8":"1"}
                block=ctypes.create_unicode_buffer("\0".join(f"{key}={value}" for key,value in sorted(env.items(),key=lambda p:p[0].casefold()))+"\0\0")
                command=ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
                check(k.CreateProcessW(argv[0],command,None,None,True,0x08000000|0x80000|0x400|0x4,block,str(task),ctypes.byref(si),ctypes.byref(pi)),"create_process")
                job=_bind_windows_kill_on_close_job(SimpleNamespace(pid=pi.pid))
                limits=EXTENDED_LIMIT();limits.BasicLimitInformation.LimitFlags=0x2000|0x8|0x200
                limits.BasicLimitInformation.ActiveProcessLimit=8;limits.JobMemoryLimit=256*1024*1024
                check(k.SetInformationJobObject(job,9,ctypes.byref(limits),ctypes.sizeof(limits)),"job_limits")
                ui=w.DWORD(0xff);check(k.SetInformationJobObject(job,4,ctypes.byref(ui),ctypes.sizeof(ui)),"job_ui_limits")
                cpu=(w.DWORD*2)(0x1|0x4,2000)
                check(k.SetInformationJobObject(job,15,ctypes.byref(cpu),ctypes.sizeof(cpu)),"job_cpu_limit")
                token=w.HANDLE();check(a.OpenProcessToken(pi.hProcess,8,ctypes.byref(token)),"open_token")
                try:
                    is_container=w.DWORD();needed=w.DWORD()
                    check(a.GetTokenInformation(token,29,ctypes.byref(is_container),ctypes.sizeof(is_container),ctypes.byref(needed)),"is_container")
                    if is_container.value!=1:raise RestrictedExecutionError("RESTRICTED_TOKEN_NOT_APPCONTAINER")
                    a.GetTokenInformation(token,31,None,0,ctypes.byref(needed))
                    sid_info=ctypes.create_string_buffer(needed.value)
                    check(a.GetTokenInformation(token,31,sid_info,needed.value,ctypes.byref(needed)),"token_container_sid")
                    container_sid=ctypes.cast(sid_info,ctypes.POINTER(w.LPVOID))[0]
                    actual=w.LPWSTR();check(a.ConvertSidToStringSidW(container_sid,ctypes.byref(actual)),"token_sid_text")
                    try:
                        if actual.value!=sid_text:raise RestrictedExecutionError("RESTRICTED_TOKEN_IDENTITY_MISMATCH")
                    finally:k.LocalFree(actual)
                    a.GetTokenInformation(token,30,None,0,ctypes.byref(needed))
                    groups=ctypes.create_string_buffer(needed.value)
                    check(a.GetTokenInformation(token,30,groups,needed.value,ctypes.byref(needed)),"token_capabilities")
                    if ctypes.cast(groups,ctypes.POINTER(w.DWORD))[0]!=0:
                        raise RestrictedExecutionError("RESTRICTED_TOKEN_CAPABILITIES_NOT_EMPTY")
                finally:k.CloseHandle(token)
                policy=w.DWORD()
                check(k.GetProcessMitigationPolicy(pi.hProcess,4,ctypes.byref(policy),ctypes.sizeof(policy)),"win32k_policy")
                if not policy.value&1:raise RestrictedExecutionError("RESTRICTED_WIN32K_NOT_DISABLED")
                if k.ResumeThread(pi.hThread)==0xffffffff:check(False,"resume")
                started=time.monotonic();reason=None
                while k.WaitForSingleObject(pi.hProcess,50)==258:
                    if time.monotonic()-started>timeout_seconds:reason="RESTRICTED_TIMEOUT";break
                    if os.fstat(stdout.fileno()).st_size+os.fstat(stderr.fileno()).st_size>2*1024*1024:
                        reason="RESTRICTED_OUTPUT_LIMIT";break
                check(k.TerminateJobObject(job,1),"terminate_job_tree")
                accounting=ctypes.create_string_buffer(48)
                tree_deadline=time.monotonic()+5
                while True:
                    check(k.QueryInformationJobObject(job,1,accounting,48,None),"job_accounting")
                    active=ctypes.c_uint32.from_buffer(accounting,40).value
                    if active==0:break
                    if time.monotonic()>tree_deadline:
                        raise RestrictedExecutionError("RESTRICTED_JOB_TREE_DID_NOT_EXIT")
                    time.sleep(.01)
                _close_windows_job_handle(job);job=None
                if os.fstat(stdout.fileno()).st_size+os.fstat(stderr.fileno()).st_size>2*1024*1024:
                    reason=reason or "RESTRICTED_OUTPUT_LIMIT"
                k.WaitForSingleObject(pi.hProcess,5000)
                exit_code=w.DWORD();check(k.GetExitCodeProcess(pi.hProcess,ctypes.byref(exit_code)),"exit_code")
                if exit_code.value==259:raise RestrictedExecutionError("RESTRICTED_PROCESS_DID_NOT_EXIT")
                stdout.seek(0);stderr.seek(0)
                return {"exit_code":exit_code.value,"stdout":stdout.read(1048576).decode("utf-8","replace"),
                        "stderr":stderr.read(1048576).decode("utf-8","replace"),"error_code":reason,
                        "isolation":"windows_appcontainer","appcontainer_token_verified":True,
                        "win32k_disabled_verified":True,"network_capabilities":0,"cpu_percent_limit":20,
                        "job_memory_limit_bytes":256*1024*1024,"process_count_limit":8,"physical_input_allowed":False,
                        "job_tree_closed":True,"workspace_is_temporary":True,"pid":pi.pid,
                        "stale_workspaces_reclaimed":workspace.reclaimed}
        finally:
            _close_windows_job_handle(job)
            if pi.hProcess:
                k.TerminateProcess(pi.hProcess,1);k.WaitForSingleObject(pi.hProcess,5000);k.CloseHandle(pi.hProcess)
            if pi.hThread:k.CloseHandle(pi.hThread)
            if attributes:k.DeleteProcThreadAttributeList(attributes)
            if sid:a.FreeSid(sid)
