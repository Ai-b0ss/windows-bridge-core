"""Fixed hidden-app launch paths and source-verified UIA sidecar preparation."""
from pathlib import Path
import hashlib,json,os,re,subprocess,uuid
from cua_global_resources import _StateLock
from cua_browser_profiles import linked

SUPPORTED_APPS=("notepad","wordpad","paint","excel","word","powerpoint","claude")

def app_path(app):
    if app=="claude":
        # A real MSIX AppExecutionAlias retains the package identity. Direct
        # CreateProcess of the WindowsApps binary fails with ACCESS_DENIED.
        # Never copy package binaries or change their ACL.
        local=os.environ.get("LOCALAPPDATA")
        if not local:return Path("__missing_claude_alias__")
        return Path(local)/"Microsoft"/"WindowsApps"/"claude-desktop.exe"
    if app in {"excel","word","powerpoint"}:
        executable={"excel":"EXCEL.EXE","word":"WINWORD.EXE","powerpoint":"POWERPNT.EXE"}[app]
        roots=[os.environ.get("ProgramFiles"),os.environ.get("ProgramFiles(x86)")]
        paths=[Path(root)/"Microsoft Office/root/Office16"/executable for root in roots if root]
        return next((p for p in paths if p.is_file()),paths[0] if paths else Path("__missing_"+app+"__"))
    if app=="notepad":
        return Path(os.environ["WINDIR"])/"System32/notepad.exe"
    if app=="paint":
        return Path(os.environ["WINDIR"])/"System32/mspaint.exe"
    if app=="wordpad":
        return Path(os.environ["ProgramFiles"])/"Windows NT/Accessories/wordpad.exe"
    raise ValueError("HIDDEN_APP_UNSUPPORTED")

def available_apps():
    if os.name != "nt":
        return []
    return [app for app in SUPPORTED_APPS if app_path(app).is_file()]

def claude_code_link(url):
    """Validate the exact Claude Desktop Code URL without performing activation."""
    from urllib.parse import urlsplit, parse_qs
    if not isinstance(url,str) or len(url)>20000 or "\x00" in url:
        raise ValueError("HIDDEN_CLAUDE_LINK_INVALID")
    parsed=urlsplit(url)
    if (parsed.scheme!="claude" or parsed.netloc!="code" or parsed.path!="/new"
            or parsed.fragment or not parsed.query):
        raise ValueError("HIDDEN_CLAUDE_LINK_INVALID")
    values=parse_qs(parsed.query,keep_blank_values=True)
    if set(values)!={"q","folder"} or any(len(items)!=1 for items in values.values()):
        raise ValueError("HIDDEN_CLAUDE_LINK_INVALID")
    prompt,folder=values["q"][0],values["folder"][0]
    if not prompt.strip() or len(prompt)>12000:
        raise ValueError("HIDDEN_CLAUDE_LINK_INVALID")
    target=Path(folder)
    if not target.is_absolute() or not target.is_dir():
        raise ValueError("HIDDEN_CLAUDE_FOLDER_INVALID")
    return url

def launch_spec(args):
    if set(args)-{"command","app","document_path","code_link"}:
        raise ValueError("HIDDEN_LAUNCH_OPTION_FORBIDDEN")
    app="notepad" if args.get("command")=="launch_notepad" else args.get("app")
    if app not in SUPPORTED_APPS:
        raise ValueError("HIDDEN_APP_UNSUPPORTED")
    if "code_link" in args:
        if app!="claude":
            raise ValueError("HIDDEN_LAUNCH_OPTION_FORBIDDEN")
        claude_code_link(args["code_link"])
    if "document_path" in args:
        value=args["document_path"]
        suffix={"excel":".xlsx","word":".docx","powerpoint":".pptx"}.get(app)
        if suffix is None or not isinstance(value,str) or not Path(value).is_absolute() or Path(value).suffix.casefold()!=suffix or not Path(value).is_file():
            raise ValueError("HIDDEN_DOCUMENT_INVALID")
    path=app_path(app)
    if not path.is_file():
        raise ValueError("HIDDEN_APP_NOT_INSTALLED")
    return app,path

GENERIC_LAUNCH_ENV="FF_HIDDEN_GENERIC_LAUNCH"

def hidden_worker_environment(environment, *, allow_generic_launch=False):
    """The Hub opts in only its own worker; ambient flags never enable another session."""
    if type(allow_generic_launch) is not bool:
        raise ValueError("HIDDEN_START_OPTION_INVALID")
    child=dict(environment)
    child.pop(GENERIC_LAUNCH_ENV,None)
    if allow_generic_launch:
        child[GENERIC_LAUNCH_ENV]="1"
    return child

def generic_launch_spec(args):
    """Any installed executable on the private desktop. Off unless the session owner (the
    agent Hub, after its permission check) set FF_HIDDEN_GENERIC_LAUNCH=1 for this worker."""
    if os.environ.get(GENERIC_LAUNCH_ENV)!="1":
        raise ValueError("HIDDEN_GENERIC_LAUNCH_DISABLED")
    if set(args)-{"command","executable","arguments","working_directory","window_timeout_s"}:
        raise ValueError("HIDDEN_LAUNCH_OPTION_FORBIDDEN")
    executable=args.get("executable")
    if (not isinstance(executable,str) or not Path(executable).is_absolute()
            or Path(executable).suffix.casefold()!=".exe" or not Path(executable).is_file()):
        raise ValueError("HIDDEN_EXECUTABLE_INVALID")
    executable=Path(executable).resolve()
    # A private desktop does not isolate an application's process-singleton IPC.
    # Launching these with the default profile can activate or send arguments to
    # an owner's existing process before this worker observes that its child quit.
    # They require their existing explicit own-instance route, never generic Popen.
    directory=executable.parent
    if (executable.name.casefold() in {"chrome.exe","msedge.exe","chromium.exe","brave.exe",
            "opera.exe","vivaldi.exe","cursor.exe","code.exe","electron.exe",
            "excel.exe","winword.exe","powerpnt.exe"}
            or "windowsapps" in {part.casefold() for part in executable.parts}
            or (directory/"resources"/"app.asar").is_file()
            or (directory/"resources"/"app").is_dir()
            or (directory/"chrome_elf.dll").is_file()
            or any(directory.glob("chrome_*.pak"))):
        raise ValueError("HIDDEN_APP_ISOLATION_ROUTE_REQUIRED")
    arguments=args.get("arguments",[])
    if (not isinstance(arguments,list) or len(arguments)>32
            or any(not isinstance(item,str) or len(item)>2048 or "\0" in item for item in arguments)):
        raise ValueError("HIDDEN_ARGUMENTS_INVALID")
    directory=args.get("working_directory")
    if directory is not None and (not isinstance(directory,str) or not Path(directory).is_absolute() or not Path(directory).is_dir()):
        raise ValueError("HIDDEN_WORKING_DIRECTORY_INVALID")
    timeout=args.get("window_timeout_s",15)
    if type(timeout) not in (int,float) or not 1<=timeout<=60:
        raise ValueError("HIDDEN_WINDOW_TIMEOUT_INVALID")
    return executable,list(arguments),directory,float(timeout)

def main_window_area(app,info,visible,owned):
    expected={"notepad":"Notepad","wordpad":"WordPadClass","paint":"MSPaintApp",
              "excel":"XLMAIN","word":"OpusApp","powerpoint":"PPTFrameClass",
              "claude":"Chrome_WidgetWin_1"}[app]
    if app=="claude" and info.get("title")!="Claude":
        return None
    if not visible or owned or info["class_name"].casefold()!=expected.casefold():
        return None
    geometry=info.get("geometry") or {}
    return max(0,geometry.get("right",0)-geometry.get("left",0))*max(0,geometry.get("bottom",0)-geometry.get("top",0))

def read_document_text(transport, hwnd, owns):
    """Read the unique direct document control, never a ribbon/font edit."""
    if not owns(hwnd):
        raise RuntimeError("HIDDEN_WINDOW_NOT_OWNED")
    root = transport.window_info(hwnd)
    expected = {
        "notepad": {"edit"},
        "wordpadclass": {"richedit", "richedit20w", "richedit50w", "richeditd2dpt"},
    }.get(root["class_name"].casefold())
    if expected is None:
        raise RuntimeError("HIDDEN_DOCUMENT_TEXT_UNSUPPORTED")
    candidates = []
    for child in transport.child_windows(hwnd):
        info = transport.window_info(child)
        if (info["class_name"].casefold() in expected and
                info["parent_hwnd"] == hwnd and info["pid"] == root["pid"]):
            candidates.append(info)
    if len(candidates) != 1:
        raise RuntimeError("HIDDEN_DOCUMENT_TEXT_TARGET_AMBIGUOUS")
    selected = candidates[0]
    def identity(info):
        return tuple(info[key] for key in ("hwnd", "pid", "parent_hwnd", "class_name"))
    def valid():
        return (owns(hwnd) and identity(transport.window_info(hwnd)) == identity(root) and
                identity(transport.window_info(selected["hwnd"])) == identity(selected))
    if not valid():
        raise RuntimeError("HIDDEN_DOCUMENT_TEXT_TARGET_CHANGED")
    value = transport.get_text(selected["hwnd"])
    if not valid():
        raise RuntimeError("HIDDEN_DOCUMENT_TEXT_TARGET_CHANGED")
    return {"value": value, "document_hwnd": selected["hwnd"],
            "document_class": selected["class_name"], "route": "HWND_MESSAGE"}

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def prepare_uia(root, *, cache_root=None):
    """Compile the verified sidecar into owner state, never into package bytes."""
    root=Path(root)
    if cache_root is None:
        # FF_BRIDGE_ROOT is unique per installed/isolated Bridge. A repository
        # checkout and a read-only release must never acquire compiled artifacts.
        state_root=os.environ.get("FF_BRIDGE_ROOT")
        if not state_root:
            local=os.environ.get("LOCALAPPDATA")
            if not local:
                raise ValueError("HIDDEN_UIA_STATE_ROOT_UNAVAILABLE")
            state_root=str(Path(local)/"FF-Windows-Bridge")
        cache_root=Path(state_root)/"state"/"uia3-sidecar-cache"
    cache_root=Path(cache_root)
    if not cache_root.is_absolute():
        raise ValueError("HIDDEN_UIA_CACHE_ROOT_NOT_ABSOLUTE")
    if cache_root.resolve().is_relative_to(root.resolve()):
        raise ValueError("HIDDEN_UIA_SOURCE_CACHE_FORBIDDEN")
    framework=Path(os.environ["WINDIR"])/"Microsoft.NET/Framework64/v4.0.30319"
    compiler=framework/"csc.exe"
    references=[framework/"WPF/UIAutomationClient.dll",framework/"WPF/UIAutomationTypes.dll",framework/"System.Web.Extensions.dll"]
    source=root/"cua_native_uia3_sidecar.cs"
    inputs=[source,compiler,*references]
    if not all(path.is_file() for path in inputs):
        raise ValueError("HIDDEN_UIA_DEPENDENCY_MISSING")
    hashes={str(path):sha(path) for path in inputs}
    identity=hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()
    from cua_windows_paths import extended_path
    cache=extended_path(cache_root)
    if linked(cache) or linked(cache.parent):
        raise ValueError("HIDDEN_UIA_CACHE_LINK_FORBIDDEN")
    cache.mkdir(parents=True,exist_ok=True)
    if linked(cache) or linked(cache.parent):
        raise ValueError("HIDDEN_UIA_CACHE_LINK_FORBIDDEN")
    marker=extended_path(cache/(identity+".json"))
    with _StateLock(cache/"build.lock"):
        try:
            if linked(marker) or marker.stat().st_size>16384:
                raise ValueError("invalid cache marker")
            data=json.loads(marker.read_text(encoding="utf-8"))
            name=data["output"]
            if data.get("schema")!=1 or data.get("inputs")!=hashes or not re.fullmatch(r"uia-[0-9a-f]{32}\.exe",name):
                raise ValueError("invalid cache record")
            output=cache/name
            if not linked(output) and output.is_file() and sha(output)==data["sha256"]:
                return output
        except (OSError,ValueError,KeyError,TypeError):
            pass
        output=extended_path(cache/("uia-"+uuid.uuid4().hex+".exe"))
        argv=[str(compiler),"/nologo","/optimize+","/target:exe","/out:"+str(output),*["/r:"+str(path) for path in references],str(source)]
        result=subprocess.run(argv,capture_output=True,timeout=30,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        if result.returncode or not output.is_file():
            raise ValueError("HIDDEN_UIA_BUILD_FAILED")
        if hashes!={str(path):sha(path) for path in inputs}:
            raise ValueError("HIDDEN_UIA_BUILD_INPUT_CHANGED")
        record={"schema":1,"inputs":hashes,"output":output.name,"sha256":sha(output)}
        temporary=extended_path(cache/(identity+"-"+uuid.uuid4().hex+".tmp"))
        temporary.write_text(json.dumps(record),encoding="utf-8")
        os.replace(temporary,marker)
        return output
