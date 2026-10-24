"""One native editor API family: private Cursor/VS Code instances, same protocol."""
import ctypes,hashlib,os,subprocess,time
from ctypes import wintypes as w
from pathlib import Path
from cua_universal_fastpath import UniversalFastPath,FastPathError
from cua_native_hwnd import Win32Transport
from cua_vscode_native import prepare_extension,host_request

def editor_path(app):
    if app not in ('cursor','vscode'):raise FastPathError('EDITOR_APP_UNSUPPORTED',{'attempted':False})
    leaf='cursor/Cursor.exe' if app=='cursor' else 'Microsoft VS Code/Code.exe'
    candidates=[Path(os.environ['LOCALAPPDATA'])/'Programs'/leaf]
    if app=='vscode':candidates += [Path(p)/leaf for p in (os.environ.get('ProgramFiles'),os.environ.get('ProgramFiles(x86)')) if p]
    return next((p for p in candidates if p.is_file()),None)

def available_editors():return [app for app in ('cursor','vscode') if editor_path(app)]

def launch_editor(root,app,document,register,*,executable=None,expected_executable_sha256=None):
    root=Path(root);document=Path(document).resolve(strict=True);exe=editor_path(app)
    if executable is not None:
        candidate=Path(executable)
        if not candidate.is_absolute() or not candidate.is_file() or candidate.name.lower()!=('cursor.exe' if app=='cursor' else 'code.exe'):
            raise FastPathError('EDITOR_EXECUTABLE_INVALID',{'attempted':False})
        if not isinstance(expected_executable_sha256,str) or hashlib.sha256(candidate.read_bytes()).hexdigest()!=expected_executable_sha256:
            raise FastPathError('EDITOR_EXECUTABLE_IDENTITY_CHANGED',{'attempted':False})
        exe=candidate.resolve()
    if not exe:raise FastPathError('EDITOR_APP_NOT_INSTALLED',{'attempted':False})
    if not document.is_file() or document.stat().st_size>262144:
        raise FastPathError('EDITOR_DOCUMENT_SCOPE_UNSUPPORTED',{'attempted':False})
    if len(document.read_text(encoding='utf-8'))>65536:raise FastPathError('EDITOR_TEXT_LIMIT',{'attempted':False})
    config=prepare_extension(root,document)
    profile=root/'profile';profile.mkdir();env=dict(os.environ)
    for key in list(env):
        if any(x in key.upper() for x in ('TOKEN','COOKIE','SECRET','API_KEY')):env.pop(key)
    for key,leaf in (('HOME','user'),('USERPROFILE','user'),('APPDATA','roaming'),('LOCALAPPDATA','local'),('TEMP','temp'),('TMP','temp')):
        p=profile/leaf;p.mkdir(exist_ok=True);env[key]=str(p)
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
