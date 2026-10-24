"""Inactive Windows desktop worker. No SwitchDesktop or physical input API."""
from __future__ import annotations
import ctypes
from ctypes import wintypes as w
import json
import msvcrt
import os
from pathlib import Path
import queue
import socket
import subprocess
import sys
import threading
from types import SimpleNamespace
import uuid
from cua_sidecar_supervisor import _bind_windows_kill_on_close_job, _close_windows_job_handle

class HiddenDesktopError(RuntimeError):
    def __init__(self, code, details=None):
        super().__init__(code)
        self.code = code
        self.details = details or {}

class _StartupInfo(ctypes.Structure):
    _fields_=[("cb",w.DWORD),("lpReserved",w.LPWSTR),("lpDesktop",w.LPWSTR),("lpTitle",w.LPWSTR),("dwX",w.DWORD),("dwY",w.DWORD),("dwXSize",w.DWORD),("dwYSize",w.DWORD),("dwXCountChars",w.DWORD),("dwYCountChars",w.DWORD),("dwFillAttribute",w.DWORD),("dwFlags",w.DWORD),("wShowWindow",w.WORD),("cbReserved2",w.WORD),("lpReserved2",ctypes.POINTER(ctypes.c_ubyte)),("hStdInput",w.HANDLE),("hStdOutput",w.HANDLE),("hStdError",w.HANDLE)]

class _StartupInfoEx(ctypes.Structure):
    _fields_=[("StartupInfo",_StartupInfo),("lpAttributeList",w.LPVOID)]

class _ProcessInfo(ctypes.Structure):
    _fields_=[("hProcess",w.HANDLE),("hThread",w.HANDLE),("pid",w.DWORD),("tid",w.DWORD)]

def _medium_desktop(u, k, desktop_name):
    """Label only the new private desktop; retain this owner's access."""
    a=ctypes.WinDLL('advapi32',use_last_error=True)
    k.GetCurrentProcess.restype=w.HANDLE;k.LocalFree.argtypes=[w.HLOCAL]
    a.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)]
    a.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
    a.ConvertSidToStringSidW.argtypes=[w.LPVOID,ctypes.POINTER(w.LPWSTR)]
    a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[w.LPCWSTR,w.DWORD,ctypes.POINTER(w.LPVOID),w.LPVOID]
    class SA(ctypes.Structure):_fields_=[('length',w.DWORD),('descriptor',w.LPVOID),('inherit',w.BOOL)]
    token=w.HANDLE();sidtext=w.LPWSTR();descriptor=w.LPVOID();size=w.DWORD()
    try:
        if not a.OpenProcessToken(k.GetCurrentProcess(),8,ctypes.byref(token)):raise ctypes.WinError(ctypes.get_last_error())
        a.GetTokenInformation(token,1,None,0,ctypes.byref(size));buf=ctypes.create_string_buffer(size.value)
        if not a.GetTokenInformation(token,1,buf,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        sid=ctypes.cast(buf,ctypes.POINTER(w.LPVOID)).contents.value
        if not a.ConvertSidToStringSidW(sid,ctypes.byref(sidtext)):raise ctypes.WinError(ctypes.get_last_error())
        sddl='D:(A;;GA;;;SY)(A;;GA;;;'+sidtext.value+')S:(ML;;NW;;;ME)'
        if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,ctypes.byref(descriptor),None):raise ctypes.WinError(ctypes.get_last_error())
        sa=SA(ctypes.sizeof(SA),descriptor,False)
        return u.CreateDesktopW(desktop_name,None,None,0,0x01ff,ctypes.byref(sa))
    finally:
        if descriptor:k.LocalFree(descriptor)
        if sidtext:k.LocalFree(ctypes.cast(sidtext,w.HLOCAL))
        if token:k.CloseHandle(token)

def _medium_create(k, cmd, environment, current_dir, extended, pi):
    """Reduce privileges/integrity of the same owner's token, never raise them.

    Owner groups remain present. This is not proof of standard-user operation.
    Windows may refuse process creation; that refusal is preserved.
    """
    a=ctypes.WinDLL('advapi32',use_last_error=True)
    k.GetCurrentProcess.restype=w.HANDLE;k.LocalFree.argtypes=[w.HLOCAL]
    a.OpenProcessToken.argtypes=[w.HANDLE,w.DWORD,ctypes.POINTER(w.HANDLE)]
    a.CreateRestrictedToken.argtypes=[w.HANDLE,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.LPVOID,w.DWORD,w.LPVOID,ctypes.POINTER(w.HANDLE)]
    a.ConvertStringSidToSidW.argtypes=[w.LPCWSTR,ctypes.POINTER(w.LPVOID)]
    a.SetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD]
    a.GetTokenInformation.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
    a.GetSidSubAuthorityCount.argtypes=[w.LPVOID];a.GetSidSubAuthorityCount.restype=ctypes.POINTER(ctypes.c_ubyte)
    a.GetSidSubAuthority.argtypes=[w.LPVOID,w.DWORD];a.GetSidSubAuthority.restype=ctypes.POINTER(w.DWORD)
    a.GetLengthSid.argtypes=[w.LPVOID];a.GetLengthSid.restype=w.DWORD
    a.CreateProcessAsUserW.argtypes=[w.HANDLE,w.LPCWSTR,w.LPWSTR,w.LPVOID,w.LPVOID,w.BOOL,w.DWORD,w.LPVOID,w.LPCWSTR,ctypes.POINTER(_StartupInfoEx),ctypes.POINTER(_ProcessInfo)]
    class SIDATTR(ctypes.Structure):_fields_=[('sid',w.LPVOID),('attributes',w.DWORD)]
    original=w.HANDLE();limited=w.HANDLE();medium=w.LPVOID();size=w.DWORD()
    try:
        if not a.OpenProcessToken(k.GetCurrentProcess(),0xF01FF,ctypes.byref(original)):raise ctypes.WinError(ctypes.get_last_error())
        a.GetTokenInformation(original,25,None,0,ctypes.byref(size));buf=ctypes.create_string_buffer(size.value)
        if not a.GetTokenInformation(original,25,buf,size,ctypes.byref(size)):raise ctypes.WinError(ctypes.get_last_error())
        sid=ctypes.cast(buf,ctypes.POINTER(w.LPVOID)).contents.value
        level=a.GetSidSubAuthority(sid,a.GetSidSubAuthorityCount(sid)[0]-1)[0]
        if level<8192:
            raise HiddenDesktopError('HIDDEN_INTEGRITY_RAISE_FORBIDDEN')
        if level==8192:
            # A normal medium caller needs no token assignment privileges.
            # Preserve its existing token rather than requiring an elevated
            # Windows API just to create another medium process.
            return k.CreateProcessW(None,cmd,None,None,True,0x08000000|0x80000|0x4|0x400,environment,current_dir,ctypes.byref(extended),ctypes.byref(pi))
        if not a.CreateRestrictedToken(original,1,0,None,0,None,0,None,ctypes.byref(limited)):raise ctypes.WinError(ctypes.get_last_error())
        if not a.ConvertStringSidToSidW('S-1-16-8192',ctypes.byref(medium)):raise ctypes.WinError(ctypes.get_last_error())
        label=SIDATTR(medium,0x20)
        if not a.SetTokenInformation(limited,25,ctypes.byref(label),ctypes.sizeof(label)+a.GetLengthSid(medium)):raise ctypes.WinError(ctypes.get_last_error())
        return a.CreateProcessAsUserW(limited,None,cmd,None,None,True,0x08000000|0x80000|0x4|0x400,environment,current_dir,ctypes.byref(extended),ctypes.byref(pi))
    finally:
        if original:k.CloseHandle(original)
        if limited:k.CloseHandle(limited)
        if medium:k.LocalFree(medium)

class HiddenDesktopSession:
    def __init__(self, package_root: str | Path, *, worker_integrity="owner", webview_debug=False):
        if type(worker_integrity) is not str or worker_integrity not in {"owner","medium"} or type(webview_debug) is not bool:
            raise HiddenDesktopError("HIDDEN_START_OPTION_INVALID")
        if os.name != "nt":
            raise HiddenDesktopError("HIDDEN_DESKTOP_WINDOWS_ONLY")
        self.root=Path(package_root).resolve()
        self.session_id=uuid.uuid4().hex
        self.desktop_name="FFBridge-Agent-"+self.session_id
        self._lock=threading.Lock();self._queue=queue.Queue()
        self._desktop=None;self._process=None;self._job=None;self._writer=None;self._reader=None
        self._stderr=None;self.pid=None;self._closed=False
        self._editor_profiles=[];self.editor_profile_cleanup=[]
        self.worker_integrity=worker_integrity;self.webview_port=None
        self._u=ctypes.WinDLL("user32",use_last_error=True);self._k=ctypes.WinDLL("kernel32",use_last_error=True)
        self._u.CreateDesktopW.argtypes=[w.LPCWSTR,w.LPCWSTR,ctypes.c_void_p,w.DWORD,w.DWORD,ctypes.c_void_p];self._u.CreateDesktopW.restype=w.HANDLE
        self._u.CloseDesktop.argtypes=[w.HANDLE]
        self._k.CreateProcessW.argtypes=[w.LPCWSTR,w.LPWSTR,ctypes.c_void_p,ctypes.c_void_p,w.BOOL,w.DWORD,ctypes.c_void_p,w.LPCWSTR,ctypes.POINTER(_StartupInfoEx),ctypes.POINTER(_ProcessInfo)]
        self._k.CloseHandle.argtypes=[w.HANDLE];self._k.ResumeThread.argtypes=[w.HANDLE]
        self._k.SetHandleInformation.argtypes=[w.HANDLE,w.DWORD,w.DWORD]
        self._k.TerminateProcess.argtypes=[w.HANDLE,w.UINT];self._k.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD]
        self._k.InitializeProcThreadAttributeList.argtypes=[w.LPVOID,w.DWORD,w.DWORD,ctypes.POINTER(ctypes.c_size_t)]
        self._k.UpdateProcThreadAttribute.argtypes=[w.LPVOID,w.DWORD,ctypes.c_size_t,w.LPVOID,ctypes.c_size_t,w.LPVOID,w.LPVOID]
        self._k.DeleteProcThreadAttributeList.argtypes=[w.LPVOID]
        attributes=None
        descriptors=[]
        try:
            self._desktop=(_medium_desktop(self._u,self._k,self.desktop_name) if worker_integrity=="medium"
                           else self._u.CreateDesktopW(self.desktop_name,None,None,0,0x01ff,None))
            if not self._desktop:raise ctypes.WinError(ctypes.get_last_error())
            input_read,input_write=os.pipe();output_read,output_write=os.pipe()
            descriptors=[input_read,input_write,output_read,output_write]
            self._stderr=open(os.devnull,"wb")
            extended=_StartupInfoEx();si=extended.StartupInfo;si.cb=ctypes.sizeof(extended);si.lpDesktop="winsta0"+chr(92)+self.desktop_name;si.dwFlags=0x100
            si.hStdInput=msvcrt.get_osfhandle(input_read);si.hStdOutput=msvcrt.get_osfhandle(output_write);si.hStdError=msvcrt.get_osfhandle(self._stderr.fileno())
            for handle in [si.hStdInput,si.hStdOutput,si.hStdError]:
                if not self._k.SetHandleInformation(handle,1,1):raise ctypes.WinError(ctypes.get_last_error())
            handles=(w.HANDLE*3)(si.hStdInput,si.hStdOutput,si.hStdError)
            size=ctypes.c_size_t()
            self._k.InitializeProcThreadAttributeList(None,1,0,ctypes.byref(size))
            attributes=ctypes.create_string_buffer(size.value)
            if not self._k.InitializeProcThreadAttributeList(attributes,1,0,ctypes.byref(size)):
                attributes=None
                raise ctypes.WinError(ctypes.get_last_error())
            if not self._k.UpdateProcThreadAttribute(attributes,0,0x20002,ctypes.byref(handles),ctypes.sizeof(handles),None,None):
                raise ctypes.WinError(ctypes.get_last_error())
            extended.lpAttributeList=ctypes.cast(attributes,w.LPVOID)
            cmd=ctypes.create_unicode_buffer(subprocess.list2cmdline([sys.executable,str(self.root/"cua_hidden_worker.py")]))
            pi=_ProcessInfo()
            child_env=dict(os.environ)
            # Debugging is explicit, confined to owned children, and inspected
            # only after loopback/listener/ancestry checks in the worker.
            child_env.pop('WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS',None)
            if webview_debug:
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1',0));self.webview_port=sock.getsockname()[1]
                child_env['WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS']='--remote-debugging-address=127.0.0.1 --remote-debugging-port='+str(self.webview_port)
            environment=ctypes.create_unicode_buffer('\0'.join(key+'='+value for key,value in sorted(child_env.items()))+'\0\0')
            created=(_medium_create(self._k,cmd,environment,str(self.root),extended,pi) if worker_integrity=="medium" else
                     self._k.CreateProcessW(None,cmd,None,None,True,0x08000000|0x80000|0x4|0x400,environment,str(self.root),ctypes.byref(extended),ctypes.byref(pi)))
            if not created:
                raise ctypes.WinError(ctypes.get_last_error())
            self._process=pi.hProcess;self.pid=pi.pid
            try:
                self._job=_bind_windows_kill_on_close_job(SimpleNamespace(pid=self.pid))
                if self._k.ResumeThread(pi.hThread)==0xffffffff:raise ctypes.WinError(ctypes.get_last_error())
            finally:self._k.CloseHandle(pi.hThread)
            os.close(input_read);descriptors.remove(input_read);os.close(output_write);descriptors.remove(output_write)
            self._writer=os.fdopen(input_write,"w",encoding="utf-8",newline="\n");descriptors.remove(input_write)
            self._reader=os.fdopen(output_read,"r",encoding="utf-8");descriptors.remove(output_read)
            threading.Thread(target=self._pump,daemon=True).start()
            ready=self.request({"command":"health"},timeout_s=10)
            self.supported_apps=ready.get("supported_apps",[])
            if ready.get("desktop")!=self.desktop_name or ready.get("input_desktop")==self.desktop_name:
                raise HiddenDesktopError("HIDDEN_DESKTOP_IDENTITY_INVALID")
        except Exception:
            for fd in descriptors:os.close(fd)
            self.close()
            raise

        finally:
            if attributes is not None:self._k.DeleteProcThreadAttributeList(attributes)

    def _pump(self):
        try:
            for line in self._reader:
                try:self._queue.put(json.loads(line))
                except ValueError:self._queue.put({"fatal":"HIDDEN_WORKER_PROTOCOL_INVALID"})
        finally:
            self._reader.close()
            self._queue.put({"fatal":"HIDDEN_WORKER_CLOSED"})

    def request(self, payload: dict, *, timeout_s: float=15):
        if not isinstance(payload,dict):
            raise HiddenDesktopError("HIDDEN_REQUEST_INVALID")
        if not isinstance(timeout_s,(int,float)) or not 0<timeout_s<=60:
            raise HiddenDesktopError("HIDDEN_TIMEOUT_INVALID")
        with self._lock:
            if self._closed:raise HiddenDesktopError("HIDDEN_WORKER_CLOSED")
            if '__owned_editor_root' in payload:raise HiddenDesktopError('EDITOR_INTERNAL_ROOT_FORBIDDEN')
            if payload.get('command')=='editor.launch':
                from cua_browser_profiles import ManagedBrowserProfiles
                profiles=ManagedBrowserProfiles(Path(os.environ['LOCALAPPDATA'])/'FFWindowsBridge/state/owned-editor')
                self._editor_profiles.append(profiles)
                payload={**payload,'__owned_editor_root':str(profiles.path)}
            request_id=uuid.uuid4().hex
            try:
                self._writer.write(json.dumps({"id":request_id,"args":payload},ensure_ascii=True)+"\n");self._writer.flush()
                reply=self._queue.get(timeout=timeout_s)
            except (OSError,queue.Empty):
                self.close()
                raise HiddenDesktopError("HIDDEN_ACTION_OUTCOME_UNKNOWN")
            if reply.get("fatal") or reply.get("id")!=request_id:
                self.close();raise HiddenDesktopError("HIDDEN_ACTION_OUTCOME_UNKNOWN")
            if not reply.get("ok"):raise HiddenDesktopError(reply.get("error_code","HIDDEN_WORKER_ERROR"),reply.get("details"))
            return reply["result"]

    def close(self):
        if self._closed:return
        self._closed=True
        _close_windows_job_handle(self._job);self._job=None
        if self._process:
            self._k.TerminateProcess(self._process,0);self._k.WaitForSingleObject(self._process,5000)
            self._k.CloseHandle(self._process);self._process=None
        if self._writer:
            # The owned worker/job is already closed. Windows can raise
            # EINVAL/EPIPE while flushing this dead pipe; do not let that
            # replace HIDDEN_ACTION_OUTCOME_UNKNOWN or skip desktop cleanup.
            writer,self._writer=self._writer,None
            try:writer.close()
            except OSError:pass
        if self._stderr:self._stderr.close()
        if self._desktop:self._u.CloseDesktop(self._desktop);self._desktop=None
        for profiles in self._editor_profiles:
            try:
                # Preserve small protocol outcome summaries before erasing the private profile.
                # The main durable journal retains full request/response task authority.
                from cua_browser_profiles import linked
                from ff_win_evidence import TaskEvidence
                import re
                if linked(profiles.path) or profiles._read_owner(profiles.path)!=profiles.owner:raise RuntimeError('EDITOR_PROFILE_OWNER_CHANGED')
                channel=profiles.path/'editor-channel'
                if channel.exists():
                    if linked(channel):raise RuntimeError('EDITOR_CHANNEL_LINK_FORBIDDEN')
                    evidence=TaskEvidence(profiles.root/'history')
                    for packet in channel.glob('*.request.json'):
                        if linked(packet) or not re.fullmatch(r'[a-f0-9]{32}\.request\.json',packet.name) or packet.stat().st_size>262144:raise RuntimeError('EDITOR_CHANNEL_PACKET_INVALID')
                        value=json.loads(packet.read_bytes());ident=packet.name[:32];result=packet.with_name(ident+'.result.json')
                        outcome={}
                        if result.exists():
                            if linked(result) or result.stat().st_size>262144:raise RuntimeError('EDITOR_CHANNEL_RESULT_INVALID')
                            outcome=json.loads(result.read_bytes())
                        evidence.append('hidden-editor-native',self.session_id,{'event':'owned_editor_outcome','request_id':ident,
                            'document_path':value.get('document'),'command':value.get('command'),
                            'expected_version':value.get('expected_version'),'expected_file_sha256':value.get('expected_file_sha256'),
                            'state':'completed' if outcome else 'outcome_unknown',
                            'outcome':{k:outcome.get(k) for k in ('ok','error_code','attempted','retry_safe','native_editor_edit','native_document_save','saved_sha256','fingerprint')}})
                removed=profiles.close()
                self.editor_profile_cleanup.append({'root':str(profiles.path),'removed':removed,'history_agent':'hidden-editor-native','history_task':self.session_id})
            except Exception as exc:
                self.editor_profile_cleanup.append({'root':str(profiles.path),'removed':False,'error_type':type(exc).__name__,'error':str(exc)})
        self._editor_profiles=[]

    def __enter__(self):return self
    def __exit__(self,*exc):self.close()
