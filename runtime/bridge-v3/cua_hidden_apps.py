"""Fixed hidden-app launch paths and source-verified UIA sidecar preparation."""
from pathlib import Path
import hashlib,json,os,re,subprocess,uuid
from cua_global_resources import _StateLock
from cua_browser_profiles import linked

SUPPORTED_APPS=("notepad","wordpad","paint","excel","word","powerpoint")

def app_path(app):
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

def launch_spec(args):
    if set(args)-{"command","app","document_path"}:
        raise ValueError("HIDDEN_LAUNCH_OPTION_FORBIDDEN")
    app="notepad" if args.get("command")=="launch_notepad" else args.get("app")
    if app not in SUPPORTED_APPS:
        raise ValueError("HIDDEN_APP_UNSUPPORTED")
    if "document_path" in args:
        value=args["document_path"]
        suffix={"excel":".xlsx","word":".docx","powerpoint":".pptx"}.get(app)
        if suffix is None or not isinstance(value,str) or not Path(value).is_absolute() or Path(value).suffix.casefold()!=suffix or not Path(value).is_file():
            raise ValueError("HIDDEN_DOCUMENT_INVALID")
    path=app_path(app)
    if not path.is_file():
        raise ValueError("HIDDEN_APP_NOT_INSTALLED")
    return app,path

def main_window_area(app,info,visible,owned):
    expected={"notepad":"Notepad","wordpad":"WordPadClass","paint":"MSPaintApp","excel":"XLMAIN","word":"OpusApp","powerpoint":"PPTFrameClass"}[app]
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

def prepare_uia(root):
    root=Path(root)
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
    cache=extended_path(root/".uia3-sidecar-cache")
    if linked(cache):
        raise ValueError("HIDDEN_UIA_CACHE_LINK_FORBIDDEN")
    cache.mkdir(exist_ok=True)
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
