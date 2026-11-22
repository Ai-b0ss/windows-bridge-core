"""Unattended, bounded owner-Chrome CDP recovery using the *existing* Default profile.

Starts Chrome only if no owner-Chrome process exists. In Chrome 158, a native
remote-debugging consent dialog needs a temporary top-level Chrome window,
which is created only when the existing watcher is installed and a Hub-owned
CDP connection needs approval. Only the exact newly created helper window is
closed after the connection comes up. Existing windows and profiles are not
touched. No auto-grants, cookie copies, session secrets, or direct CDP bypasses.
"""
from __future__ import annotations
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import psutil

FLAGS = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
WM_CLOSE = 0x0010
WINDOW_CLASS = "Chrome_WidgetWin_1"
USER32 = ctypes.windll.user32 if os.name == "nt" else None


def process_is_owner_chrome(p: psutil.Process, chrome: Path, user_data: Path) -> bool:
    try:
        if Path(p.exe()).resolve() != chrome.resolve(): return False
        cmd = p.cmdline()
        if any(arg.startswith("--type=") for arg in cmd[1:]): return False
        for i,arg in enumerate(cmd[1:], 1):
            if arg.startswith("--user-data-dir="):
                directory=arg.split("=",1)[1].strip('"')
                return Path(directory).resolve() == user_data.resolve()
            if arg=="--user-data-dir":
                return i+1<len(cmd) and Path(cmd[i+1].strip('"')).resolve()==user_data.resolve()
        return True
    except (psutil.Error,OSError,ValueError,PermissionError):
        return False


def owner_processes(chrome: Path, user_data: Path) -> list[psutil.Process]:
    result=[]
    for p in psutil.process_iter(["pid","name"]):
        try:
            if p.info["name"] and p.info["name"].lower()=="chrome.exe" and process_is_owner_chrome(p,chrome,user_data):
                result.append(p)
        except (psutil.Error,OSError):pass
    return result


def windows_for_owner(pid: int) -> set[int]:
    if USER32 is None:return set()
    result=set()
    callback_type=ctypes.WINFUNCTYPE(ctypes.c_bool,ctypes.c_void_p,ctypes.c_void_p)
    @callback_type
    def callback(hwnd,lp):
        target=ctypes.c_ulong(0)
        USER32.GetWindowThreadProcessId(hwnd,ctypes.byref(target))
        if target.value==pid:
            name=ctypes.create_unicode_buffer(128)
            USER32.GetClassNameW(hwnd,name,len(name))
            if name.value==WINDOW_CLASS and USER32.IsWindow(hwnd):
                result.add(int(hwnd))
        return True
    USER32.EnumWindows(callback,None)
    # A normal browser window has no GW_OWNER. Chrome consent dialogs,
    # "Restore pages" prompts, and other transient popups are owned by
    # that browser window and must not be counted as separate helpers.
    USER32.GetWindow.argtypes=[ctypes.c_void_p,ctypes.c_uint]
    USER32.GetWindow.restype=ctypes.c_void_p
    return {hwnd for hwnd in result if not USER32.GetWindow(hwnd,4)}


def listener_pid(port:int) -> int|None:
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.status=="LISTEN" and c.laddr and c.laddr.port==port and c.pid and c.laddr.ip in ("127.0.0.1","::1"):
                return c.pid
    except (psutil.Error,OSError):
        return None
    return None


def configured_port(user_data:Path) -> int:
    p=user_data/"DevToolsActivePort"
    try:
        port=int(p.read_text(encoding="ascii").splitlines()[0])
        if 1<=port<=65535:return port
    except (OSError,ValueError,UnicodeError,IndexError):pass
    return 9222


def remote_debugging_enabled(user_data:Path) -> bool:
    try:
        settings=json.loads((user_data/"Local State").read_text(encoding="utf-8-sig"))
        return settings.get("devtools",{}).get("remote_debugging",{}).get("user-enabled") is True
    except (OSError,ValueError,UnicodeError):return False


def hub_status(hub_state:Path, timeout=4)->dict|None:
    try:
        endpoint=json.loads((hub_state/"endpoint.json").read_text(encoding="utf-8-sig"))
        pkg=Path(endpoint["package"])
        script=pkg/"ff_hub.py"
        if not script.is_file():return None
        result=subprocess.run([sys.executable,str(script),"--state-dir",str(hub_state),"status"],capture_output=True,text=True,
                              encoding="utf-8",errors="replace",timeout=timeout,creationflags=FLAGS)
        if result.returncode:return None
        data=json.loads(result.stdout)
        if data.get("pid")!=endpoint.get("pid"):return None
        return data
    except (OSError,ValueError,subprocess.TimeoutExpired,KeyError):return None


def watcher_running(script:Path)->bool:
    if not script.is_file():return False
    try:
        for p in psutil.process_iter(["name"]):
            if p.info["name"] and p.info["name"].lower() in ("powershell.exe","pwsh.exe"):
                cmd=" ".join(p.cmdline()).lower()
                if script.name.lower() in cmd:return True
    except (psutil.Error,OSError):pass
    return False


def native_support_window(chrome:Path,pid:int,owner:Path,*,wait_s:float=7)->int|None:
    before=windows_for_owner(pid)
    if before:return None  # do not touch real user windows
    foreground=USER32.GetForegroundWindow() if USER32 else 0
    startup=subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow=7 # SW_SHOWMINNOACTIVE; Chrome may ignore this hint
    subprocess.Popen([str(chrome),"--new-window","chrome://inspect/#remote-debugging","--profile-directory=Default"],
                     cwd=str(chrome.parent),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL,startupinfo=startup,creationflags=FLAGS)
    until=time.monotonic()+wait_s
    while time.monotonic()<until:
        new=windows_for_owner(pid)-before
        if len(new)==1:
            hwnd=new.pop()
            # Chrome may steal focus even when process startup is minimized.
            # Restore only the previously active unrelated owner window.
            if USER32 and foreground and foreground!=hwnd and USER32.GetForegroundWindow()==hwnd and USER32.IsWindow(foreground):
                USER32.SetForegroundWindow(foreground)
            return hwnd
        if len(new)>1:return None
        time.sleep(.25)
    return None


class Recovery:
    def __init__(self,hub_state:Path,workdir:Path):
        self.hub_state=hub_state
        self.workdir=workdir
        self.workdir.mkdir(parents=True,exist_ok=True)
        self.user_data=Path(os.environ["LOCALAPPDATA"])/"Google/Chrome/User Data"
        self.chrome=Path(os.environ.get("PROGRAMFILES",r"C:\Program Files"))/"Google/Chrome/Application/chrome.exe"
        self.watch_script=workdir/"owner-chrome-consent-watcher.ps1"
        self.last_attempt=0.0
        self.attempts=0
        self.attempt_window=time.monotonic()
        self.status_file=workdir/"chrome-owner-recovery-status.json"
        self.log_file=workdir/"chrome-owner-recovery.log"

    def report(self,code:str,**extra):
        now=time.time()
        status={"code":code,"timestamp":now,**extra}
        tmp=self.status_file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(status,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
        os.replace(tmp,self.status_file)
        with self.log_file.open("a",encoding="utf-8") as log:
            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {code} {json.dumps(extra,ensure_ascii=False)}\n")
        return status

    def step(self,*,allow_support:bool=True)->dict:
        if (self.workdir/"stop.flag").exists():return self.report("STOP_FLAG")
        if not self.chrome.is_file() or not (self.user_data/"Default").is_dir():
            return self.report("OWNER_CHROME_NOT_INSTALLED")
        if not remote_debugging_enabled(self.user_data):
            return self.report("OWNER_CHROME_REMOTE_DEBUG_DISABLED")
        status=hub_status(self.hub_state)
        if status is None:return self.report("HUB_UNAVAILABLE")
        owners=owner_processes(self.chrome,self.user_data)
        if len(owners)>1:return self.report("MULTIPLE_OWNER_CHROME_PROCESSES")
        remote=status.get("owner_chrome_secondary",{})
        if remote.get("connected") and len(owners)==1:
            current=owners[0]
            if listener_pid(configured_port(self.user_data))==current.pid:
                connected_at=remote.get("connected_at")
                try:
                    if connected_at is not None and float(connected_at)>=current.create_time()-1:
                        return self.report("CDP_CONNECTED",hub_pid=status["pid"],chrome_pid=current.pid)
                except (ValueError,TypeError,psutil.Error):pass
                return self.report("STALE_CDP_WAIT_FOR_HUB_KEEPALIVE",chrome_pid=current.pid)
        elif remote.get("connected") and not owners:
            self.report("CHROME_MISSING_DESPITE_STALE_HUB_STATUS")
        if not owners:
            # User has already enabled Chrome's remote debug toggle. No extra
            # command-line CDP port is needed for the *actual* Default profile.
            proc=subprocess.Popen([str(self.chrome),"--no-startup-window","--keep-alive-for-test",
                  "--no-first-run","--no-default-browser-check","--profile-directory=Default"],
                  stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                  cwd=str(self.chrome.parent),creationflags=FLAGS)
            time.sleep(3)
            owners=owner_processes(self.chrome,self.user_data)
            if len(owners)!=1:return self.report("BACKGROUND_CHROME_START_FAILED",launched_pid=proc.pid)
            self.report("BACKGROUND_CHROME_STARTED",pid=owners[0].pid)
        owner=owners[0]
        pid=owner.pid
        port=configured_port(self.user_data)
        if listener_pid(port)!=pid:
            return self.report("CDP_PORT_NOT_OWNED_BY_CHROME",chrome_pid=pid,port=port)
        if remote.get("connected"):
            return self.report("STALE_CDP_WAIT_FOR_HUB_KEEPALIVE",chrome_pid=pid)
        if windows_for_owner(pid):
            return self.report("CHROME_ALREADY_HAS_WINDOW_WAIT_FOR_WATCHER",pid=pid,port=port)
        if not allow_support:return self.report("CDP_AVAILABLE_AWAITING_NATIVE_CONSENT",pid=pid,port=port)
        if not watcher_running(self.watch_script):
            return self.report("CONSENT_WATCHER_NOT_RUNNING",pid=pid)
        # Limit intervention: max three support windows in any 15-minute period.
        now=time.monotonic()
        if now-self.attempt_window>900:
            self.attempt_window=now
            self.attempts=0
        if self.attempts>=3 or now-self.last_attempt<65:
            return self.report("CONSENT_COOLDOWN",attempts=self.attempts)
        self.attempts+=1
        self.last_attempt=now
        hwnd=native_support_window(self.chrome,pid,self.workdir)
        if hwnd is None:return self.report("SUPPORT_WINDOW_NOT_CREATED",chrome_pid=pid)
        self.report("TEMPORARY_CHROME_WINDOW_OPENED",chrome_pid=pid,window=hwnd)
        try:
            deadline=time.monotonic()+55
            while time.monotonic()<deadline:
                if (self.workdir/"stop.flag").exists():break
                state=hub_status(self.hub_state)
                if state and state.get("owner_chrome_secondary",{}).get("connected"):
                    return self.report("CDP_RECOVERED",chrome_pid=pid,hub_pid=state["pid"])
                time.sleep(2)
            return self.report("CONSENT_NOT_CONFIRMED",chrome_pid=pid)
        finally:
            # Do not close a pre-existing user window, or one reused for a
            # different process. The helper was absent in the baseline.
            if USER32 and USER32.IsWindow(hwnd):
                current=ctypes.c_ulong()
                USER32.GetWindowThreadProcessId(hwnd,ctypes.byref(current))
                if current.value==pid and hwnd in windows_for_owner(pid):
                    USER32.PostMessageW(hwnd,WM_CLOSE,0,0)

    def run(self,interval:int):
        while not (self.workdir/"stop.flag").exists():
            try:self.step()
            except Exception as e:self.report("RECOVERY_EXCEPTION",type=type(e).__name__)
            time.sleep(max(5,interval))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--hub-state",type=Path,required=True)
    parser.add_argument("--workdir",type=Path,required=True)
    parser.add_argument("--once",action="store_true")
    parser.add_argument("--dry-run",action="store_true")
    parser.add_argument("--interval",type=int,default=15)
    args=parser.parse_args()
    recovery=Recovery(args.hub_state,args.workdir)
    if args.dry_run:
        print(json.dumps({"chrome":str(recovery.chrome),"remote_debugging_enabled":remote_debugging_enabled(recovery.user_data),
            "owner_processes":[p.pid for p in owner_processes(recovery.chrome,recovery.user_data)],
            "port":configured_port(recovery.user_data),"hub_connected":bool((hub_status(args.hub_state) or {}).get("owner_chrome_secondary",{}).get("connected"))}))
        return 0
    if args.once:
        result=recovery.step()
        print(json.dumps(result,ensure_ascii=False))
        return 0 if result["code"] in ("CDP_CONNECTED","CDP_RECOVERED") else 2
    recovery.run(args.interval)
    return 0


if __name__=="__main__":
    raise SystemExit(main())
