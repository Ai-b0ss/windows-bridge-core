"""Real Windows gate: private native GUI + headful Chrome, owned test data only.

python tests/integration/hidden_chrome_smoke.py --output <absolute evidence directory>
Uses a separate loopback Bridge. Never switches Desktop or uses physical input.
CDP performs browser actions; Win32 independently proves OS Desktop placement.
"""
from __future__ import annotations
import argparse,base64,ctypes,ctypes.wintypes as w,hashlib,json,os,platform,socket,subprocess,sys,threading,time,urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

REPO=Path(__file__).resolve().parents[2]
RUNTIME=REPO/'runtime/bridge-v3'
sys.path.insert(0,str(RUNTIME))
from ff_win_process_identity import process_creation_token,process_identity_matches
from cua_universal_fastpath import _LocalWebSocket

def check(value,code):
    if not value:raise RuntimeError(code)

def free_port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

class Gate:
    def __init__(self,out):
        self.out=out;out.mkdir(parents=True,exist_ok=True)
        self.root=out/'isolated-state';self.port=free_port();self.process=None
        self.log=(out/'rpc.jsonl').open('a',encoding='utf-8');self.serial=0;self.owned=[];self.sessions=[]
        self.http=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.receipts=[];self.samples=[];self.stop=threading.Event();self.artifacts=[]
    def record(self,kind,value):
        self.log.write(json.dumps({'time':time.time(),'kind':kind,'value':value},ensure_ascii=False)+'\n');self.log.flush()
    def start(self):
        self.serverlog=(self.out/'bridge.log').open('ab')
        env={**os.environ,'FF_BRIDGE_ROOT':str(self.root),'PYTHONUTF8':'1'}
        self.process=subprocess.Popen([sys.executable,str(RUNTIME/'ff_win_v3_main.py'),'serve','--host','127.0.0.1','--port',str(self.port)],env=env,cwd=REPO,stdin=subprocess.DEVNULL,stdout=self.serverlog,stderr=self.serverlog,creationflags=subprocess.CREATE_NO_WINDOW)
        deadline=time.monotonic()+25
        while time.monotonic()<deadline:
            check(self.process.poll() is None,'ISOLATED_BRIDGE_EXITED')
            secret=self.root/'bridge-v3/secret'
            if secret.is_file():
                self.secret=secret.read_text(encoding='ascii').strip()
                try:
                    if self.rpc('ping',{}).get('ok'):break
                except OSError:pass
            time.sleep(.1)
        else:raise RuntimeError('ISOLATED_BRIDGE_NOT_READY')
        self.record('bridge_started',{'pid':self.process.pid,'port':self.port})
    def rpc(self,op,args):
        body=json.dumps({'target_device':platform.node(),'op':op,'args':args}).encode()
        req=urllib.request.Request(f'http://127.0.0.1:{self.port}/rpc',body,{'X-FF3-Key':self.secret,'Content-Type':'application/json'})
        try:
            with self.http.open(req,timeout=75) as response:return json.load(response)
        except urllib.error.HTTPError as error:return json.load(error)
    def call(self,args,key=None,expect=None):
        self.serial+=1
        if key:
            response=self.rpc('durable_call',{'op':'computer_use','args':args,'request_key':key,'agent_id':'hidden-chrome-gate','task_id':'hidden-chrome-gate','target_device':platform.node()})
            check(response.get('ok'),'DURABLE_WRAPPER_FAILED')
            wrapper=response['result'];response=wrapper.get('response',{})
            self.record('durable',{'key':key,'state':wrapper.get('state'),'cached':wrapper.get('cached')})
        else:response=self.rpc('computer_use',args)
        clean=json.loads(json.dumps(response))
        if 'image_base64' in clean.get('result',{}):clean['result']['image_base64']='[artifact]'
        self.record('rpc',{'args':args,'response':clean})
        if expect:
            check(not response.get('ok') and response.get('error_code')==expect,'EXPECTED_'+expect)
            return response
        check(response.get('ok'),str(response.get('error_code') or 'RPC_FAILED'))
        return response['result']
    def request(self,s,payload,key=None,expect=None):
        return self.call({'command':'hidden_request','session_id':s['session_id'],'timeout_s':60,'request':payload},key,expect)
    def new(self,key):
        s=self.call({'command':'hidden_start','worker_integrity':'medium'},key)
        self.sessions.append(s);self.own(s['worker_pid']);return s
    def own(self,pid):
        token=process_creation_token(pid);check(token is not None,'MISSING_PROCESS_TOKEN');self.owned.append((pid,token))
    def own_tree(self,pid):
        import psutil
        self.own(pid)
        for child in psutil.Process(pid).children(recursive=True):
            token=process_creation_token(child.pid)
            if token is not None and (child.pid,token) not in self.owned:self.owned.append((child.pid,token))
    def launch(self,s,key):
        result=self.request(s,{'command':'browser.launch'},key);self.own_tree(result['pid']);return result
    def cdp(self,b,method,params=None,target=None):
        # Revalidate browser OS/process/listener identity immediately before dispatch.
        current=self.request(b['session'],{'command':'browser.info'})
        check(current['browser_ws_endpoint']==b['browser_ws_endpoint'],'BROWSER_IDENTITY_DRIFT')
        endpoint=target or b['browser_ws_endpoint']
        sock=_LocalWebSocket(endpoint,15)
        self.record('cdp_dispatch',{'pid':b['pid'],'method':method,'target':target is not None})
        try:
            sock.send(json.dumps({'id':1,'method':method,'params':params or {}}))
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                msg=json.loads(sock.recv())
                if msg.get('id')!=1:continue
                check('error' not in msg,'CDP_'+str(msg.get('error')))
                return msg.get('result',{})
            raise RuntimeError('CDP_OUTCOME_UNKNOWN_NO_REPLAY')
        finally:sock.close()
    def pages(self,b):
        self.request(b['session'],{'command':'browser.info'})
        with self.http.open(b['cdp_endpoint']+'/json/list',timeout=5) as r:return json.load(r)
    def page(self,b,tid=None):
        pages=[p for p in self.pages(b) if p['type']=='page' and (tid is None or p['id']==tid)]
        check(len(pages)==1,'PAGE_AMBIGUOUS');return pages[0]
    def evaluate(self,b,p,expression):
        result=self.cdp(b,'Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':True},p['webSocketDebuggerUrl'])
        check('exceptionDetails' not in result,'JS_EXCEPTION');return result.get('result',{}).get('value')
    def wait_value(self,b,p,expression,predicate,code,timeout=25):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            value=self.evaluate(b,p,expression)
            if predicate(value):return value
            time.sleep(.15)
        raise RuntimeError(code)
    def close(self,s,key):
        result=self.call({'command':'hidden_close','session_id':s['session_id']},key)
        for item in result.get('browser_profile_cleanup',[]):
            check(item['removed'] and not Path(item['root']).exists(),'PROFILE_CLEANUP_FAILED')
        self.sessions=[x for x in self.sessions if x['session_id']!=s['session_id']]
        return result
    def capture(self,s,hwnd,name):
        r=self.request(s,{'command':'capture_window','hwnd':hwnd})
        image=base64.b64decode(r['image_base64']);check(hashlib.sha256(image).hexdigest()==r['image_sha256'],'CAPTURE_HASH')
        (self.out/name).write_bytes(image);self.artifacts.append(name)
        return {k:v for k,v in r.items() if k!='image_base64'}
    def stop_bridge(self):
        if self.process and self.process.poll() is None:self.process.terminate();self.process.wait(timeout=10)
        if hasattr(self,'serverlog'):self.serverlog.close()
    def cleanup(self):
        for s in list(self.sessions):
            try:self.close(s,'cleanup-'+s['session_id'])
            except Exception as exc:self.record('cleanup_error',str(exc))
        self.stop_bridge();self.stop.set()
        deadline=time.monotonic()+8
        while time.monotonic()<deadline and any(process_identity_matches(*p) for p in self.owned):time.sleep(.1)
        check(not any(process_identity_matches(*p) for p in self.owned),'OWNED_PROCESS_LEAK')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);opt=parser.parse_args()
    check(os.name=='nt','WINDOWS_REQUIRED');out=opt.output.resolve();g=Gate(out)
    u=ctypes.WinDLL('user32',use_last_error=True)
    u.GetForegroundWindow.restype=w.HWND;u.GetThreadDesktop.argtypes=[w.DWORD];u.GetThreadDesktop.restype=w.HANDLE
    u.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)];u.GetWindowThreadProcessId.restype=w.DWORD
    u.GetUserObjectInformationW.argtypes=[w.HANDLE,ctypes.c_int,w.LPVOID,w.DWORD,ctypes.POINTER(w.DWORD)]
    u.OpenInputDesktop.argtypes=[w.DWORD,w.BOOL,w.DWORD];u.OpenInputDesktop.restype=w.HANDLE;u.CloseDesktop.argtypes=[w.HANDLE]
    u.OpenDesktopW.argtypes=[w.LPCWSTR,w.DWORD,w.BOOL,w.DWORD];u.OpenDesktopW.restype=w.HANDLE
    u.SetThreadDesktop.argtypes=[w.HANDLE];u.SetThreadDesktop.restype=w.BOOL
    callback_type=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
    u.EnumDesktopWindows.argtypes=[w.HANDLE,callback_type,w.LPARAM];u.EnumDesktopWindows.restype=w.BOOL
    def desktop_name(h):
        buf=ctypes.create_unicode_buffer(512);n=w.DWORD();check(u.GetUserObjectInformationW(h,2,buf,ctypes.sizeof(buf),ctypes.byref(n)),'DESKTOP_NAME_FAILED');return buf.value
    def owner_sample():
        hwnd=int(u.GetForegroundWindow() or 0);pid=w.DWORD();u.GetWindowThreadProcessId(hwnd,ctypes.byref(pid));point=w.POINT()
        check(u.GetCursorPos(ctypes.byref(point)),'CURSOR_UNAVAILABLE')
        h=u.OpenInputDesktop(0,False,1)
        try:name=desktop_name(h)
        finally:u.CloseDesktop(h)
        return {'time':time.time(),'hwnd':hwnd,'pid':pid.value,'cursor':[point.x,point.y],'input':name,'clipboard_sequence':u.GetClipboardSequenceNumber()}
    def sampler():
        original=u.GetThreadDesktop(ctypes.windll.kernel32.GetCurrentThreadId())
        handle=u.OpenInputDesktop(0,False,0x0041)
        try:
            check(handle and u.SetThreadDesktop(handle),'OBSERVER_BIND_FAILED')
            while not g.stop.is_set():
                g.samples.append(owner_sample());g.stop.wait(.01)
        except Exception as exc:g.record('observer_error',str(exc));g.observer_error=str(exc)
        finally:
            if handle:
                u.SetThreadDesktop(original)
                u.CloseDesktop(handle)
    def window_on_desktop(name,hwnd,pid):
        handle=u.OpenDesktopW(name,0,False,0x0041);check(handle,'OPEN_PRIVATE_DESKTOP_FAILED');found=[]
        @callback_type
        def visit(candidate,_):
            actual=w.DWORD();u.GetWindowThreadProcessId(candidate,ctypes.byref(actual))
            if int(candidate)==hwnd and actual.value==pid:found.append(hwnd)
            return True
        try:
            check(desktop_name(handle)==name,'DESKTOP_NAME_MISMATCH')
            check(u.EnumDesktopWindows(handle,visit,0),'ENUM_PRIVATE_WINDOWS_FAILED')
            return found==[hwnd]
        finally:u.CloseDesktop(handle)
    t=threading.Thread(target=sampler,daemon=True);t.start()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            data=b'''<!doctype html><html><meta charset="utf-8"><title>Hidden Chrome proof</title><style>body{font:24px sans-serif;background:#eaf1ff;padding:40px}input,button{font-size:24px}output{display:block;margin:30px}</style><h1>Private Desktop test</h1><form><label>Name <input id="name" name="name"></label><button>Confirm</button></form><output id="result">Waiting</output><a href="/second" target="_blank">Second tab</a><script>document.querySelector('form').onsubmit=async e=>{e.preventDefault();let v=document.querySelector('input').value;let r=await fetch('/submit',{method:'POST',body:v});document.querySelector('output').textContent=await r.text()}</script></html>'''
            self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.end_headers();self.wfile.write(data)
        def do_POST(self):
            size=int(self.headers.get('Content-Length','0'));check(size<4096,'FORM_BODY_LIMIT')
            value=self.rfile.read(size).decode();g.receipts.append(value);data=('Confirmed: '+value).encode()
            self.send_response(200);self.end_headers();self.wfile.write(data)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);threading.Thread(target=server.serve_forever,daemon=True).start()
    url=f'http://127.0.0.1:{server.server_port}/';summary={'status':'FAIL','gates':[]};failure=None
    try:
        g.start();s=g.new('start-native');native=g.request(s,{'command':'launch_notepad'},'notepad-launch');g.own(native['pid'])
        original=g.request(s,{'command':'read_text','hwnd':native['hwnd']})
        attached=g.request(s,{'command':'attach','target':{'hwnd':native['hwnd']}});obs=attached['observation']
        entities=[e for e in obs['entities'] if e['identity'].get('hwnd')==original['document_hwnd'] and 'set_value' in e['actions']]
        check(len(entities)==1,'NATIVE_DOCUMENT_AMBIGUOUS');entity=entities[0];marker='Private GUI verified 47'
        payload={'command':'act','surface_id':attached['surface_id'],'generation':obs['generation'],'ref':entity['ref'],'operation':'set_value','action_args':{'value':marker},'postcondition':{'type':'value_equals','value':marker}}
        check(g.request(s,payload,'native-edit')['verified'],'NATIVE_EDIT_UNVERIFIED')
        check(g.request(s,{'command':'read_text','hwnd':native['hwnd']})['value']==marker,'NATIVE_READBACK')
        g.request(s,payload,'native-edit') # cached result, no replay
        g.capture(s,native['hwnd'],'native.png');summary['gates'].append('native_ui_write_independent_read_capture_effect_once')
        b=g.launch(s,'chrome-launch');b['session']=s
        check(window_on_desktop(s['desktop'],b['hwnd'],b['pid']),'OS_WINDOW_DESKTOP_MISMATCH')
        check(not window_on_desktop(g.samples[-1]['input'],b['hwnd'],b['pid']),'CHROME_VISIBLE_ON_OWNER_DESKTOP')
        check(g.request(s,{'command':'browser.launch'},'chrome-launch')['pid']==b['pid'],'DUPLICATE_CHROME')
        p=g.page(b);g.cdp(b,'Page.navigate',{'url':url},p['webSocketDebuggerUrl'])
        g.wait_value(b,p,'document.title',lambda v:v=='Hidden Chrome proof','LOCAL_PAGE_NOT_LOADED')
        # Use DOM observation, focus/input, and an actual button click on our own page.
        check(g.evaluate(b,p,"({label:document.querySelector('label').innerText,button:document.querySelector('button').textContent})")['button']=='Confirm','FORM_OBSERVATION')
        g.cdp(b,'Runtime.evaluate',{'expression':"document.querySelector('#name').focus()"},p['webSocketDebuggerUrl'])
        g.cdp(b,'Input.insertText',{'text':'agent-one'},p['webSocketDebuggerUrl'])
        g.evaluate(b,p,"document.querySelector('button').click()")
        g.wait_value(b,p,"document.querySelector('output').textContent",lambda v:v=='Confirmed: agent-one','FORM_READBACK')
        check(g.receipts==['agent-one'],'INDEPENDENT_FORM_SERVER_RECEIPT')
        g.evaluate(b,p,"document.cookie='proof_agent=one; SameSite=Strict';document.cookie")
        shot=g.cdp(b,'Page.captureScreenshot',{'format':'png'},p['webSocketDebuggerUrl']);(out/'chrome-dom.png').write_bytes(base64.b64decode(shot['data']))
        g.capture(s,b['hwnd'],'chrome-native.png')
        created=g.cdp(b,'Target.createTarget',{'url':'about:blank','background':True})['targetId'];p2=g.page(b,created)
        g.cdp(b,'Target.activateTarget',{'targetId':created})
        g.cdp(b,'Page.navigate',{'url':'https://example.com/'},p2['webSocketDebuggerUrl'])
        external=g.wait_value(b,p2,'({title:document.title,url:location.href,text:document.body?.innerText})',lambda v:isinstance(v,dict) and v.get('title')=='Example Domain','EXTERNAL_SITE_FAILED')
        g.cdp(b,'Target.activateTarget',{'targetId':p['id']})
        check(g.evaluate(b,p,"document.querySelector('output').textContent")=='Confirmed: agent-one','TAB_STATE_LOST')
        summary['external']=external;summary['gates'].append('chrome_native_desktop_local_form_input_tabs_external_dom_screenshots')
        # A second independent worker/browser: real profile/cookie/window isolation.
        s2=g.new('start-second');b2=g.launch(s2,'chrome-launch-second');b2['session']=s2
        check(b['pid']!=b2['pid'] and b['profile_path']!=b2['profile_path'] and s['desktop']!=s2['desktop'],'BROWSER_ISOLATION_FAILED')
        p3=g.page(b2);g.cdp(b2,'Page.navigate',{'url':url},p3['webSocketDebuggerUrl']);g.wait_value(b2,p3,'document.title',lambda v:v=='Hidden Chrome proof','SECOND_PAGE')
        check(g.evaluate(b2,p3,'document.cookie')=='','COOKIE_LEAK')
        g.evaluate(b2,p3,"document.cookie='proof_agent=two; SameSite=Strict'")
        check('proof_agent=one' in g.evaluate(b,p,'document.cookie'),'COOKIE_CROSS_WRITE')
        def form_job(browser,page,text):
            g.evaluate(browser,page,"document.querySelector('#name').value='';document.querySelector('#name').focus()")
            g.cdp(browser,'Input.insertText',{'text':text},page['webSocketDebuggerUrl'])
            g.evaluate(browser,page,"document.querySelector('button').click()")
            return g.wait_value(browser,page,"document.querySelector('output').textContent",lambda value:value=='Confirmed: '+text,'CONCURRENT_FORM_READBACK')
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs=[pool.submit(form_job,b,p,'concurrent-one'),pool.submit(form_job,b2,p3,'concurrent-two')]
            check([job.result(timeout=40) for job in jobs]==['Confirmed: concurrent-one','Confirmed: concurrent-two'],'CONCURRENT_FORM_RESULTS')
        check(sorted(g.receipts)==['agent-one','concurrent-one','concurrent-two'],'CONCURRENT_SERVER_RECEIPTS')
        g.request(s2,{'command':'capture_window','hwnd':b['hwnd']},expect='HIDDEN_WINDOW_NOT_OWNED')
        g.request(s,{'command':'read_text','hwnd':g.samples[-1]['hwnd']},expect='HIDDEN_WINDOW_NOT_OWNED')
        g.request(s,{'command':'browser.launch','arguments':['--no-sandbox']},expect='HIDDEN_CHROME_OPTION_FORBIDDEN')
        g.request(s,{'command':'browser.launch','__owned_browser_root':str(out)},expect='BROWSER_INTERNAL_ROOT_FORBIDDEN')
        summary['gates'].append('two_concurrent_forms_workers_profiles_cookies_foreign_hwnd_and_options_denied')
        summary['sessions']=[{k:v for k,v in b.items() if k!='session'},{k:v for k,v in b2.items() if k!='session'}]
        g.close(s2,'close-second');check(g.request(s,{'command':'browser.info'})['pid']==b['pid'],'OTHER_SESSION_CLOSED')
        # Kill only a saved owned worker, then reconcile error and prove automatic cleanup.
        g.own_tree(b['pid'])
        import _winapi
        handle=_winapi.OpenProcess(1,False,s['worker_pid'])
        try:_winapi.TerminateProcess(handle,19)
        finally:_winapi.CloseHandle(handle)
        g.request(s,{'command':'health'},key='killed-worker-read',expect='HIDDEN_ACTION_OUTCOME_UNKNOWN')
        g.request(s,{'command':'health'},key='killed-worker-read',expect='HIDDEN_ACTION_OUTCOME_UNKNOWN')
        g.call({'command':'hidden_request','session_id':s['session_id'],'request':{'command':'health'}},expect='HIDDEN_SESSION_NOT_FOUND')
        g.sessions=[];check(not Path(b['profile_path']).exists(),'KILL_PROFILE_NOT_CLEANED')
        summary['gates'].append('worker_kill_unknown_no_replay_slot_and_profile_cleanup')
        s3=g.new('start-after-kill');b3=g.launch(s3,'launch-after-kill');g.own(b3['pid']);g.close(s3,'cancel-after-kill')
        # Crash the isolated Bridge itself while it owns Chrome. Job handle must kill descendants.
        s4=g.new('start-parent-crash');b4=g.launch(s4,'launch-parent-crash');g.own_tree(b4['pid']);g.stop_bridge();g.sessions=[]
        deadline=time.monotonic()+8
        while time.monotonic()<deadline and any(process_identity_matches(*p) for p in g.owned):time.sleep(.1)
        check(not any(process_identity_matches(*p) for p in g.owned),'PARENT_CRASH_PROCESS_LEAK')
        g.start();s5=g.new('start-after-restart');b5=g.launch(s5,'launch-after-restart')
        check(not Path(b4['profile_path']).exists(),'STALE_PROFILE_NOT_RECLAIMED')
        cached=g.rpc('request_status',{'request_key':'launch-parent-crash'});check(cached['result']['state']=='completed','JOURNAL_NOT_DURABLE')
        # Read cached receipt only; never automatically dispatch the old launch again.
        g.close(s5,'close-after-restart');summary['gates'].append('cancel_parent_crash_restart_stale_profile_reclaim_durable_receipt')
        summary['status']='PASS'
    except Exception as exc:
        failure=exc;summary['error']=str(exc);g.record('failure',str(exc))
    finally:
        try:g.cleanup()
        except Exception as exc:summary['cleanup_error']=str(exc);summary['status']='FAIL';failure=failure or exc
        server.shutdown();g.stop.set();t.join(timeout=3)
        (out/'owner-samples.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in g.samples))
        owned_pids={p for p,_ in g.owned};owned_desktops={s.get('desktop') for s in g.sessions}
        foreground_owned=any(x['pid'] in owned_pids for x in g.samples)
        private_input=any(x['input'].startswith('FFBridge-Agent-') for x in g.samples)
        summary['observer']={'samples':len(g.samples),'foreground_owned':foreground_owned,'private_input':private_input,'foreground_values':len({x['hwnd'] for x in g.samples}),'cursor_values':len({tuple(x['cursor']) for x in g.samples}),'clipboard_sequence_values':len({x['clipboard_sequence'] for x in g.samples}),'sampling_interval_ms':10,'human_activity_may_change_foreground':True}
        if foreground_owned or private_input or not g.samples or getattr(g,'observer_error',None):summary['status']='FAIL';failure=failure or RuntimeError('OWNER_DESKTOP_OBSERVATION_FAILED')
        summary['owned_processes_closed']=not any(process_identity_matches(*p) for p in g.owned)
        summary['chrome_native_printwindow_visual_verified']=False
        summary['chrome_page_screenshot_route']='CDP Page.captureScreenshot; native Desktop placement independently enumerated'
        summary['owned_process_tokens']=g.owned;summary['local_form_receipts']=g.receipts
        (out/'result.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8');g.log.close()
    print(json.dumps(summary,ensure_ascii=False))
    return 1 if failure else 0

if __name__=='__main__':raise SystemExit(main())
