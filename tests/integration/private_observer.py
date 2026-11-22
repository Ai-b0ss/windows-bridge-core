"""Read-only input Desktop observer. Never switches or sends input."""
import ctypes,ctypes.wintypes as w,json,threading,time
class Observer:
    def __init__(self):
        self.u=ctypes.WinDLL('user32',use_last_error=True);u=self.u
        u.GetForegroundWindow.restype=w.HWND;u.GetThreadDesktop.argtypes=[w.DWORD];u.GetThreadDesktop.restype=w.HANDLE
        u.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)];u.GetWindowThreadProcessId.restype=w.DWORD
        u.GetUserObjectInformationW.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
        u.OpenInputDesktop.argtypes=[w.DWORD,w.BOOL,w.DWORD];u.OpenInputDesktop.restype=w.HANDLE
        u.OpenDesktopW.argtypes=[w.LPCWSTR,w.DWORD,w.BOOL,w.DWORD];u.OpenDesktopW.restype=w.HANDLE
        u.SetThreadDesktop.argtypes=[w.HANDLE];u.CloseDesktop.argtypes=[w.HANDLE]
        self.samples=[];self.error=None;self.stop=threading.Event();self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def name(self,h):
        buf=ctypes.create_unicode_buffer(512);n=w.DWORD()
        if not h or not self.u.GetUserObjectInformationW(h,2,buf,ctypes.sizeof(buf),ctypes.byref(n)):raise RuntimeError('DESKTOP_NAME')
        return buf.value
    def run(self):
        u=self.u;original=u.GetThreadDesktop(ctypes.windll.kernel32.GetCurrentThreadId());h=u.OpenInputDesktop(0,False,0x41)
        try:
            if not h or not u.SetThreadDesktop(h):raise RuntimeError('OBSERVER_BIND_FAILED')
            while not self.stop.is_set():
                hwnd=u.GetForegroundWindow();pid=w.DWORD();u.GetWindowThreadProcessId(hwnd,ctypes.byref(pid));p=w.POINT()
                if not u.GetCursorPos(ctypes.byref(p)):raise RuntimeError('CURSOR_UNAVAILABLE')
                active=u.OpenInputDesktop(0,False,1)
                try:name=self.name(active)
                finally:u.CloseDesktop(active)
                self.samples.append({'at':time.time(),'hwnd':hwnd,'pid':pid.value,'cursor':[p.x,p.y],'input':name,'clipboard_sequence':u.GetClipboardSequenceNumber()});self.stop.wait(.02)
        except Exception as exc:self.error=str(exc)
        finally:u.SetThreadDesktop(original);u.CloseDesktop(h)
    def window(self,name,hwnd,pid):
        u=self.u;h=u.OpenDesktopW(name,0,False,0x41);found=[];callback=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
        u.EnumDesktopWindows.argtypes=[w.HANDLE,callback,w.LPARAM]
        @callback
        def visit(value,_):
            actual=w.DWORD();u.GetWindowThreadProcessId(value,ctypes.byref(actual))
            if int(value)==hwnd and actual.value==pid:found.append(value)
            return True
        try:
            if not h or self.name(h)!=name or not u.EnumDesktopWindows(h,visit,0):raise RuntimeError('DESKTOP_ENUM_FAILED')
            return len(found)==1
        finally:
            if h:u.CloseDesktop(h)
    def finish(self,out,owned):
        self.stop.set();self.thread.join(3);pids={x[0] for x in owned}
        (out/'owner-samples.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in self.samples))
        return {'samples':len(self.samples),'sample_interval_ms':20,'foreground_owned':any(s['pid'] in pids for s in self.samples),'private_input':any(s['input'].startswith('FFBridge-Agent-') for s in self.samples),'error':self.error,'foreground_values':len({s['hwnd'] for s in self.samples}),'cursor_values':len({tuple(s['cursor']) for s in self.samples})}
