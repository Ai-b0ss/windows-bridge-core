"""One native editor API family: private Antigravity/Cursor/VS Code instances, same protocol."""
import ctypes,hashlib,os,subprocess,time
from ctypes import wintypes as w
from pathlib import Path
from cua_universal_fastpath import UniversalFastPath,FastPathError
from cua_native_hwnd import Win32Transport
from cua_vscode_native import prepare_extension,host_request

_EDITOR_LEAVES = {
    'cursor': 'cursor/Cursor.exe',
    'vscode': 'Microsoft VS Code/Code.exe',
    'antigravity': 'antigravity/Antigravity.exe',
}
_EDITOR_NAMES = {
    'cursor': 'cursor.exe',
    'vscode': 'code.exe',
    'antigravity': 'antigravity.exe',
}


def editor_path(app):
    if app not in _EDITOR_LEAVES:raise FastPathError('EDITOR_APP_UNSUPPORTED',{'attempted':False})
    leaf=_EDITOR_LEAVES[app]
    candidates=[Path(os.environ.get('LOCALAPPDATA',''))/'Programs'/leaf]
    if app=='vscode':candidates += [Path(p)/leaf for p in (os.environ.get('ProgramFiles'),os.environ.get('ProgramFiles(x86)')) if p]
    elif app=='antigravity':candidates += [Path(p)/leaf for p in (os.environ.get('ProgramFiles'),) if p]
    return next((p for p in candidates if str(p) and p.is_file()),None)

def available_editors():return [app for app in ('cursor','vscode') if editor_path(app)]


def _isolated_env(profile):
    env=dict(os.environ)
    for key in list(env):
        if any(x in key.upper() for x in ('TOKEN','COOKIE','SECRET','API_KEY','ANTIGRAVITY','AGY_','VSCODE','ELECTRON')):
            env.pop(key)
    for key,leaf in (('HOME','user'),('USERPROFILE','user'),('APPDATA','roaming'),('LOCALAPPDATA','local'),('TEMP','temp'),('TMP','temp')):
        p=profile/leaf;p.mkdir(parents=True,exist_ok=True);env[key]=str(p)
    return env


def launch_electron_isolated(root,app,register,*,executable=None,expected_executable_sha256=None,arguments=None,window_timeout_s=25):
    """Launch an Electron app/IDE on the caller's private desktop with isolated profile dirs."""
    root=Path(root)
    if executable is not None:
        candidate=Path(executable)
        if not candidate.is_absolute() or not candidate.is_file():
            raise FastPathError('EDITOR_EXECUTABLE_INVALID',{'attempted':False})
        if expected_executable_sha256 is not None and hashlib.sha256(candidate.read_bytes()).hexdigest()!=expected_executable_sha256:
            raise FastPathError('EDITOR_EXECUTABLE_IDENTITY_CHANGED',{'attempted':False})
        exe=candidate.resolve()
    else:
        exe=editor_path(app)
    if not exe:raise FastPathError('EDITOR_APP_NOT_INSTALLED',{'attempted':False})
    extra=list(arguments or [])
    if len(extra)>16 or any(not isinstance(item,str) or len(item)>1024 or '\0' in item or item.startswith('--user-data-dir') or item.startswith('--extensions-dir') for item in extra):
        raise FastPathError('EDITOR_ARGUMENTS_INVALID',{'attempted':False})
    profile=root/'profile';profile.mkdir(parents=True,exist_ok=True)
    env=_isolated_env(profile)
    argv=[str(exe),f"--user-data-dir={profile/'data'}",f"--extensions-dir={profile/'extensions'}",
          '--force-renderer-accessibility=complete']
    if app in {'cursor','vscode'}:
        argv.append('--new-window')
    argv.extend(extra)
    si=subprocess.STARTUPINFO();si.dwFlags=0x80|subprocess.STARTF_USESHOWWINDOW;si.wShowWindow=4
    proc=subprocess.Popen(argv,cwd=root,env=env,startupinfo=si,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    register(proc)
    u=ctypes.WinDLL('user32');u.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
    u.IsWindowVisible.argtypes=[w.HWND];u.IsWindowVisible.restype=w.BOOL
    u.GetWindow.argtypes=[w.HWND,w.UINT];u.GetWindow.restype=w.HWND
    callback_type=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM);transport=Win32Transport()
    deadline=time.monotonic()+min(max(float(window_timeout_s),2.0),60.0)
    while time.monotonic()<deadline and proc.poll() is None:
        found=[]
        @callback_type
        def collect(hwnd,_):
            pid=w.DWORD();u.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
            if pid.value==proc.pid and u.IsWindowVisible(hwnd) and not u.GetWindow(hwnd,4):
                info=transport.window_info(int(hwnd))
                if info.get('class_name')=='Chrome_WidgetWin_1':found.append(info)
            return True
        u.EnumWindows(collect,0)
        if found:
            best=max(found,key=lambda info:max(0,(info.get('geometry') or {}).get('right',0)-(info.get('geometry') or {}).get('left',0))*max(0,(info.get('geometry') or {}).get('bottom',0)-(info.get('geometry') or {}).get('top',0)))
            return {'proc':proc,'window':best,'executable':str(exe),'profile_path':str(profile)}
        time.sleep(.1)
    if proc.poll() is None:proc.kill()
    proc.wait(timeout=5)
    raise FastPathError('OWN_EDITOR_WINDOW_OR_HOST_UNAVAILABLE',{'attempted':True,'retry_safe':False})


def launch_editor(root,app,document,register,*,executable=None,expected_executable_sha256=None):
    root=Path(root);document=Path(document).resolve(strict=True);exe=editor_path(app)
    if executable is not None:
        candidate=Path(executable)
        if not candidate.is_absolute() or not candidate.is_file() or candidate.name.lower()!=_EDITOR_NAMES[app]:
            raise FastPathError('EDITOR_EXECUTABLE_INVALID',{'attempted':False})
        if not isinstance(expected_executable_sha256,str) or hashlib.sha256(candidate.read_bytes()).hexdigest()!=expected_executable_sha256:
            raise FastPathError('EDITOR_EXECUTABLE_IDENTITY_CHANGED',{'attempted':False})
        exe=candidate.resolve()
    if not exe:raise FastPathError('EDITOR_APP_NOT_INSTALLED',{'attempted':False})
    if not document.is_file() or document.stat().st_size>262144:
        raise FastPathError('EDITOR_DOCUMENT_SCOPE_UNSUPPORTED',{'attempted':False})
    if len(document.read_text(encoding='utf-8'))>65536:raise FastPathError('EDITOR_TEXT_LIMIT',{'attempted':False})
    config=prepare_extension(root,document)
    profile=root/'profile';profile.mkdir();env=_isolated_env(profile)
    env['FFBRIDGE_EDITOR_CHANNEL']=config['channel']
    si=subprocess.STARTUPINFO();si.dwFlags=0x80|subprocess.STARTF_USESHOWWINDOW;si.wShowWindow=4
    proc=subprocess.Popen([str(exe),'--user-data-dir',str(profile/'data'),'--extensions-dir',str(profile/'extensions'),
        '--remote-debugging-port=0','--extensionDevelopmentPath='+config['extension'],'--new-window',str(document)],
        cwd=root,env=env,startupinfo=si,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
    register(proc)
    u=ctypes.WinDLL('user32');u.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)]
    u.IsWindowVisible.argtypes=[w.HWND];u.IsWindowVisible.restype=w.BOOL
    callback_type=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM);transport=Win32Transport();fp=UniversalFastPath()
    deadline=time.monotonic()+25
    while time.monotonic()<deadline and proc.poll() is None:
        found=[]
        @callback_type
        def collect(hwnd,_):
            pid=w.DWORD();u.GetWindowThreadProcessId(hwnd,ctypes.byref(pid))
            if pid.value==proc.pid and u.IsWindowVisible(hwnd):
                info=transport.window_info(int(hwnd))
                if info['class_name']=='Chrome_WidgetWin_1':found.append(info)
            return True
        u.EnumWindows(collect,0)
        if len(found)==1:
            window=found[0];cdp=fp._pick_pid_listener_cdp(window)
            if cdp:
                discovery={'window':window,'cdp':cdp,'route':'APP_CDP'}
                observed=host_request(config,discovery,'observe')
                return {'proc':proc,'config':config,'discovery':discovery,'observed':observed}
        time.sleep(.1)
    raise FastPathError('OWN_EDITOR_WINDOW_OR_HOST_UNAVAILABLE',{'attempted':True,'retry_safe':False})
