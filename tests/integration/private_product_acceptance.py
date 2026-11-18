"""P0-P3 real Windows product gate through the public authenticated Hub HTTP API.

Only disposable own applications/profiles/files; no physical input or owner data.
Usage: python tests/integration/private_product_acceptance.py --output <new directory>
"""
from __future__ import annotations
import argparse,base64,hashlib,json,os,subprocess,sys,threading,time,zipfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'runtime/bridge-v3'))
from ff_hub import HubClient,HubError
from ff_hub_permissions import Policy
from cua_hidden_chrome import chrome_path
from ff_win_process_identity import ProcessReference,process_creation_token,process_identity_matches
from hidden_chrome_smoke import Gate,check,RUNTIME
from private_observer import Observer

class ProductGate(Gate):
    def __init__(self,out):
        super().__init__(out);self.clients=[];self.hub_state=self.root/'state/hub';self.results={};self.events=[];self.extra_processes=[]
    def start(self):
        self.serverlog=(self.out/'hub.log').open('ab')
        self.process=subprocess.Popen([sys.executable,str(RUNTIME/'ff_hub.py'),'serve','--state-dir',str(self.hub_state),'--port','0'],env={**os.environ,'FF_BRIDGE_ROOT':str(self.root),'PYTHONUTF8':'1'},stdin=subprocess.DEVNULL,stdout=self.serverlog,stderr=self.serverlog,creationflags=subprocess.CREATE_NO_WINDOW)
        self.own(self.process.pid);deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            check(self.process.poll() is None,'HUB_EXITED')
            try:
                c=HubClient(self.hub_state,timeout=2);c.call('hub_status');break
            except (HubError,OSError):time.sleep(.1)
        else:raise RuntimeError('HUB_NOT_READY')
        Policy(self.hub_state/'policy.json').add_grant(['app_launch'],agents=['p0','one','two','three','crash','reboot'],apps=['charmap.exe','winword.exe','chrome.exe'],ttl_seconds=3600,note='Owner-authorized disposable acceptance only')
        Policy(self.hub_state/'policy.json').add_grant(['browser_script'],agents=['one','two','three'],ttl_seconds=3600,note='Owner-authorized controlled recovery scripts; disposable profiles only')
        (self.root/'state/universal-agent-runtime.json').write_text(json.dumps({'version':1,'enabled':True}))
        self.record('hub_started',{'pid':self.process.pid})
    def client(self,name):
        c=HubClient(self.hub_state,timeout=75);c.call('session_open',{'agent_id':name,'task_id':'product-acceptance'});self.clients.append(c);return c
    def call(self,c,op,args=None,key=None,expect=None):
        started=time.time()
        try:
            result=c.call(op,args or {},request_key=key)
            self.record('api',{'op':op,'args':args,'request_key':key,'elapsed':time.time()-started,'result':result if op not in {'app_capture'} and (args or {}).get('command')!='screenshot' else '[image artifact]'})
            if expect:raise RuntimeError('EXPECTED_'+expect)
            return result
        except HubError as exc:
            self.record('api_error',{'op':op,'args':args,'key':key,'code':exc.code,'details':exc.details})
            if expect:check(exc.code==expect,'EXPECTED_'+expect+'_GOT_'+exc.code);return {'error_code':exc.code}
            raise
    def browser(self,c,b,command,key=None,**args):return self.call(c,'private_browser',{'browser_id':b,'command':command,**args},key)
    def wait_read(self,c,b,tab,needle,timeout=30):
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            value=self.browser(c,b,'read',tab_id=tab)
            if needle in value.get('text',''):return value
            time.sleep(.15)
        raise RuntimeError('PAGE_READ_TIMEOUT_'+needle)
    def control(self,c,b,tab,field,value):
        obs=self.browser(c,b,'observe',tab_id=tab);matches=[e for e in obs['controls'] if e.get(field)==value]
        check(len(matches)==1,'AMBIGUOUS_CONTROL_'+value);return {'tab_id':tab,'snapshot':obs['snapshot'],'ref':matches[0]['ref']}
    def act(self,c,b,tab,field,match_value,operation,condition,key,**extra):
        return self.browser(c,b,'act',key,**self.control(c,b,tab,field,match_value),operation=operation,postcondition=condition,**extra)
    def cancel(self,c):
        result=self.call(c,'task_cancel',key='task-cancel-'+c.session['session_id'])
        check(result['cleanup_verified'],'CANCEL_CLEANUP_FAILED');return result
    def crash_browser_then_worker(self,item):
        import psutil
        client,browser,_,info=item
        child=psutil.Process(info['pid'])
        worker=child.parent()
        check(process_identity_matches(child.pid,info['create_time']),'CHROME_CHANGED_BEFORE_TEST')
        check(Path(child.exe()).resolve()==chrome_path(),'CHROME_IMAGE_CHANGED_BEFORE_TEST')
        check('--user-data-dir='+info['profile_path'] in child.cmdline(),'CHROME_PROFILE_NOT_OWNED')
        check(worker is not None and worker.ppid()==self.process.pid,'WORKER_NOT_OWNED')
        worker_token=process_creation_token(worker.pid)
        check(Path(worker.exe()).resolve()==Path(sys.executable).resolve(),'WORKER_IMAGE_CHANGED_BEFORE_TEST')
        check(Path(worker.cmdline()[1]).resolve()==RUNTIME/'cua_hidden_worker.py','WORKER_COMMAND_CHANGED_BEFORE_TEST')
        check(process_identity_matches(worker.pid,worker_token),'WORKER_CHANGED_BEFORE_TEST')
        with_process=(ProcessReference(child.pid,info['create_time']), ProcessReference(worker.pid,worker_token))
        try:
            with_process[0].terminate()
            self.call(client,'private_browser',{'browser_id':browser,'command':'info'},expect='HIDDEN_CHROME_PROCESS_CHANGED')
            with_process[1].terminate()
            self.call(client,'private_browser',{'browser_id':browser,'command':'info'},expect='HIDDEN_ACTION_OUTCOME_UNKNOWN')
        finally:
            for process in with_process:process.close()
        self.cancel(client)
    def bridge_proxy(self):
        proc=subprocess.Popen([sys.executable,str(RUNTIME/'ff_win_v3_main.py'),'serve','--host','127.0.0.1','--port',str(self.port)],env={**os.environ,'FF_BRIDGE_ROOT':str(self.root)},stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW)
        self.own(proc.pid);self.extra_processes.append(proc);deadline=time.monotonic()+20
        while time.monotonic()<deadline:
            secret=self.root/'bridge-v3/secret'
            if secret.exists():
                self.secret=secret.read_text().strip()
                try:
                    if self.rpc('ping',{}).get('ok'):return proc
                except OSError:pass
            time.sleep(.1)
        raise RuntimeError('BRIDGE_PROXY_NOT_READY')
    def cleanup(self):
        for proc in self.extra_processes:
            if proc.poll() is None:proc.terminate();proc.wait(timeout=8)
        self.own_tree(self.process.pid) if self.process and self.process.poll() is None else None
        for c in self.clients:
            try:self.cancel(c)
            except Exception as exc:self.record('cleanup_note',str(exc))
        self.stop_bridge();deadline=time.monotonic()+8
        while time.monotonic()<deadline and any(process_identity_matches(*p) for p in self.owned):time.sleep(.1)
        check(not any(process_identity_matches(*p) for p in self.owned),'PRODUCT_PROCESS_LEAK')

SPA=b'''<!doctype html><meta charset="utf-8"><title>Private inventory SPA</title><style>body{font:20px sans-serif;background:#edf2ff;padding:35px}input,button{font:inherit;margin:8px}#modal{border:2px solid #246;padding:20px}</style><h1>Inventory workspace</h1><nav><a id="orders" href="#orders">Orders</a><a id="reports" href="#reports">Reports</a></nav><main id="view"></main><output id="receipt"></output><script>
const view=document.querySelector('#view');function render(){if(location.hash==='#reports'){view.innerHTML='<h2>Reports</h2><a id="download" href="/report.csv" download="report.csv">Download report</a><button id="back">Back to orders</button>';document.querySelector('#back').onclick=()=>location.hash='orders';return}view.innerHTML='<h2>Orders</h2><input id="filter" aria-label="Filter"><button id="search">Search inventory</button><ul id="items"></ul><button id="new">New order</button>';document.querySelector('#search').onclick=async()=>{const items=await(await fetch('/items?q='+encodeURIComponent(document.querySelector('#filter').value))).json();document.querySelector('#items').innerHTML=items.map(x=>'<li>'+x+'</li>').join('')};document.querySelector('#new').onclick=()=>{const d=document.createElement('section');d.id='modal';d.innerHTML='<h3>Create order</h3><input id="customer" aria-label="Customer"><select id="priority"><option>Normal</option><option>High</option></select><input id="attachment" type="file"><button id="submit">Submit order</button>';view.append(d);document.querySelector('#submit').onclick=async()=>{const data={customer:document.querySelector('#customer').value,priority:document.querySelector('#priority').value,file:document.querySelector('#attachment').files[0]?await document.querySelector('#attachment').files[0].text():''};document.querySelector('#receipt').textContent=await(await fetch('/submit',{method:'POST',body:JSON.stringify(data)})).text();d.remove()}}};onhashchange=render;render();</script>'''

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--only',choices=['p0','browser','recovery','all'],default='all');a=p.parse_args();out=a.output.resolve();check(not out.exists(),'OUTPUT_MUST_BE_NEW');g=ProductGate(out);observer=Observer()
    class Server(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            if self.path.startswith('/items'):data=json.dumps(['Widget A','Widget B','Widget C']).encode();typ='application/json'
            elif self.path.startswith('/report.csv'):data=b'item,count\nWidget A,47\n';typ='text/csv';self.send_response(200);self.send_header('Content-Disposition','attachment; filename="report.csv"');self.send_header('Content-Type',typ);self.end_headers();self.wfile.write(data);return
            else:data=SPA;typ='text/html; charset=utf-8'
            self.send_response(200);self.send_header('Content-Type',typ);self.end_headers();self.wfile.write(data)
        def do_POST(self):
            n=int(self.headers.get('Content-Length','0'));check(n<2000000,'BODY_LIMIT');data=self.rfile.read(n).decode();g.events.append(data)
            self.send_response(200);self.end_headers();self.wfile.write(('Saved order '+json.loads(data).get('customer','')).encode())
    server=ThreadingHTTPServer(('127.0.0.1',0),Server);threading.Thread(target=server.serve_forever,daemon=True).start();url=f'http://127.0.0.1:{server.server_port}/';failure=None
    try:
        g.start()
        if a.only in {'p0','all'}:
            c=g.client('p0')
            app=g.call(c,'app_open',{'app':'charmap.exe'},'charmap-open');g.own(app['pid']);(out/'charmap-open.json').write_text(json.dumps(app))
            check(observer.window(app['desktop'],app['hwnd'],app['pid']),'CHARMAP_OS_DESKTOP')
            seen=g.call(c,'app_observe',{'app_id':app['app_id']});(out/'charmap-observe.json').write_text(json.dumps(seen,ensure_ascii=False))
            toggle=next(e for e in seen['entities'] if e.get('automation_id')=='119' and 'toggle' in e.get('actions',[]))
            g.call(c,'app_act',{'app_id':app['app_id'],'generation':seen['generation'],'ref':toggle['ref'],'operation':'toggle','postcondition':{'type':'state_equals','key':'toggle_state','value':'On'}},'charmap-toggle')
            seen=g.call(c,'app_observe',{'app_id':app['app_id']});edit=next(e for e in seen['entities'] if e.get('automation_id')=='104' and 'set_value' in e.get('actions',[]))
            g.call(c,'app_act',{'app_id':app['app_id'],'generation':seen['generation'],'ref':edit['ref'],'operation':'set_value','action_args':{'value':'P0 owned GUI'},'postcondition':{'type':'value_equals','value':'P0 owned GUI\r'}},'charmap-text')
            check(any(e.get('value')=='P0 owned GUI\r' for e in g.call(c,'app_observe',{'app_id':app['app_id']})['entities']),'CHARMAP_READBACK')
            capture=g.call(c,'app_capture',{'app_id':app['app_id']});(out/'charmap.png').write_bytes(base64.b64decode(capture['image_base64']))
            g.call(c,'app_open',{'app':'chrome'},'unsupported-generic-chrome',expect='APP_BACKGROUND_ROUTE_UNSUPPORTED')
            from docx import Document
            document=out/'owned.docx';doc=Document();doc.add_paragraph('Product GUI original 42');doc.save(document)
            word=g.call(c,'app_open',{'app':'word','document_path':str(document)},'word-open');g.own(word['pid'])
            check(observer.window(word['desktop'],word['hwnd'],word['pid']),'WORD_OS_DESKTOP')
            text=g.call(c,'app_document',{'app_id':word['app_id'],'command':'read'})['text']
            g.call(c,'app_document',{'app_id':word['app_id'],'command':'replace','expected_text':text,'replacement_text':'Product GUI saved 47\r'},'word-replace-save')
            check('Product GUI saved 47' in '\n'.join(p.text for p in Document(document).paragraphs),'WORD_FILE_READBACK')
            g.results['P0']={'status':'PASS','apps':['Character Map Win32/UIA','Word native GUI/COM'],'independent_docx_readback':True,'unsupported_generic_chrome_denied':True}
            g.cancel(c)
            check(not process_identity_matches(app['pid'],app['create_time']),'CHARMAP_ALIVE_AFTER_CANCEL_RECEIPT')
            check(not process_identity_matches(word['pid'],word['create_time']),'WORD_ALIVE_AFTER_CANCEL_RECEIPT')
        if a.only!='p0':
            clients=[g.client(n) for n in ['one','two','three']];browsers=[]
            for index,client in enumerate(clients):
                b=g.call(client,'private_browser',{'command':'open'},'browser-open');g.own_tree(b['pid']);browser=b['browser_id']
                tab=g.browser(client,browser,'tabs')['tabs'][0]['tab_id'];g.browser(client,browser,'navigate','navigate-local',tab_id=tab,url=url);g.wait_read(client,browser,tab,'Inventory workspace');browsers.append((client,browser,tab,b))
            c,b,tab,info=browsers[0]
            if a.only!='recovery':
                g.act(c,b,tab,'id','filter','fill',{'type':'value_equals','selector':'#filter','value':'Widget'},'spa-filter',value='Widget')
                g.act(c,b,tab,'id','search','click',{'type':'text_includes','value':'Widget C'},'spa-search')
                g.act(c,b,tab,'id','new','click',{'type':'text_includes','value':'Create order'},'spa-modal')
                g.act(c,b,tab,'id','customer','fill',{'type':'value_equals','selector':'#customer','value':'First'},'spa-customer',value='First')
                upload=g.browser(c,b,'upload','upload-owned',**g.control(c,b,tab,'id','attachment'),name='owned.txt',content_base64=base64.b64encode(b'owned-upload-47').decode())
                g.act(c,b,tab,'id','submit','click',{'type':'text_includes','value':'Saved order First'},'submit-once')
                check(json.loads(g.events[-1])['file']=='owned-upload-47','INDEPENDENT_UPLOAD_SERVER_READBACK')
                receipt=g.call(c,'request_status',{'request_key':'submit-once'});check(receipt['state']=='completed','SUBMIT_RECEIPT')
                saved=receipt['response'];check(saved['verified'],'SUBMIT_NOT_VERIFIED')
                # Same key+payload is read from the durable journal, never redispatched.
                rows=[json.loads(line) for line in (out/'rpc.jsonl').read_text(encoding='utf-8').splitlines()]
                submit=next(row['value']['args'] for row in rows if row['kind']=='api' and row['value'].get('request_key')=='submit-once')
                g.call(c,'private_browser',submit,'submit-once');check(len(g.events)==1,'SUBMIT_REPLAY')
                g.browser(c,b,'download_prepare','download-prepare',tab_id=tab)
                g.act(c,b,tab,'id','reports','click',{'type':'text_includes','value':'Download report'},'spa-reports')
                g.act(c,b,tab,'id','download','click',{'type':'text_includes','value':'Reports'},'download-click')
                deadline=time.monotonic()+15
                while True:
                    try:download=g.browser(c,b,'download_read',tab_id=tab,name='report.csv');break
                    except HubError as exc:
                        if exc.code!='PRIVATE_DOWNLOAD_NOT_READY' or time.monotonic()>deadline:raise
                        time.sleep(.2)
                check(base64.b64decode(download['content_base64'])==b'item,count\nWidget A,47\n','DOWNLOAD_BYTES')
                shot=g.browser(c,b,'screenshot',tab_id=tab);(out/'spa.png').write_bytes(base64.b64decode(shot['data']))
                ext=g.browser(c,b,'tab_open','external-open',url='https://react.dev/learn')['tab_id'];g.wait_read(c,b,ext,'Quick Start',timeout=45)
                external=g.browser(c,b,'read',tab_id=ext);check('react.dev' in external['url'],'EXTERNAL_REACT_SPA')
                g.results['P1']={'status':'PASS','spa':'async inventory search, modal, controlled form, hash-route rerender','external_spa':external['url'],'upload_sha256':upload['sha256'],'download_sha256':download['sha256'],'submit_receipt':'completed_once'}
                def parallel_job(item,index):
                    client,browser,page,_=item
                    g.act(client,browser,page,'id','new','click',{'type':'text_includes','value':'Create order'},f'parallel-modal-{index}')
                    g.act(client,browser,page,'id','customer','fill',{'type':'value_equals','selector':'#customer','value':f'Agent{index}'},f'parallel-fill-{index}',value=f'Agent{index}')
                    return g.act(client,browser,page,'id','submit','click',{'type':'text_includes','value':f'Saved order Agent{index}'},f'parallel-submit-{index}')
                # First client returns from Reports to Orders; all three then act independently.
                g.browser(c,b,'navigate','return-orders',tab_id=tab,url=url);g.wait_read(c,b,tab,'Orders')
                with ThreadPoolExecutor(max_workers=3) as pool:check(all(x['verified'] for x in pool.map(lambda pair:parallel_job(*pair),zip(browsers,range(3)))),'PARALLEL_FORMS')
                lock=g.call(clients[0],'resource_claim',{'kind':'custom','key':'shared-report'},'resource-one')
                g.call(clients[1],'resource_claim',{'kind':'custom','key':'shared-report'},'resource-conflict',expect='RESOURCE_BUSY')
                with ThreadPoolExecutor(max_workers=1) as pool:
                    wait=pool.submit(g.call,clients[1],'resource_claim',{'kind':'custom','key':'shared-report','wait_seconds':4},'resource-queued')
                    time.sleep(.25);g.call(clients[0],'resource_release',{'resource_id':lock['resource_id']});check(wait.result(timeout=8)['session_id']==clients[1].session['session_id'],'QUEUED_RESOURCE')
                g.call(clients[1],'private_browser',{'browser_id':b,'command':'tabs'},expect='RESOURCE_NOT_OWNED')
                check(len({x[3]['profile_path'] for x in browsers})==3,'PROFILE_COLLISION')
                for index,(client,browser,page,_) in enumerate(browsers):
                    g.browser(client,browser,'evaluate',f'cookie-set-{index}',tab_id=page,expression=f"document.cookie='private_agent={index}; SameSite=Strict'")
                for index,(client,browser,page,_) in enumerate(browsers):
                    cookie=g.browser(client,browser,'evaluate',f'cookie-read-{index}',tab_id=page,expression='document.cookie')['value']
                    check(cookie==f'private_agent={index}','COOKIE_CROSS_CLIENT_LEAK')
                cancelled=g.cancel(clients[2]);again=g.cancel(clients[2]);check(again['deduplicated'],'CANCEL_RECEIPT_NOT_REPLAYABLE')
                g.browser(c,b,'read',tab_id=tab)
                g.results['P2']={'status':'PASS','clients':3,'queued_resource':True,'foreign_browser_denied':True,'cancel_receipt_deduplicated':True}
            # Socket disconnect after dispatch: journal completes despite vanished client.
            short=HubClient(g.hub_state,timeout=.05);short.session=c.session
            expr="new Promise(resolve=>setTimeout(()=>resolve('completed after socket close'),700))"
            try:g.call(short,'private_browser',{'browser_id':b,'command':'evaluate','tab_id':tab,'expression':expr},'disconnect-after-dispatch')
            except HubError as exc:check(exc.code=='HUB_UNREACHABLE','DISCONNECT_WRONG_ERROR')
            deadline=time.monotonic()+15
            while g.call(c,'request_status',{'request_key':'disconnect-after-dispatch'})['state']!='completed':
                check(time.monotonic()<deadline,'DISCONNECT_RECEIPT_LOST');time.sleep(.2)
            bridge=g.bridge_proxy();hub_pid=g.process.pid
            forwarded={'op':'private_browser','args':{'browser_id':b,'command':'read','tab_id':tab},'session_id':c.session['session_id'],'session_secret':c.session['session_secret']}
            check(g.rpc('hub',forwarded)['ok'],'BRIDGE_HUB_READ_FAILED')
            bridge.terminate();bridge.wait(timeout=8);g.bridge_proxy()
            check(g.rpc('hub',forwarded)['ok'] and g.process.pid==hub_pid,'BRIDGE_CRASH_LOST_HUB')
            g.record('bridge_restart_preserved_hub',{'hub_pid':hub_pid})
            # Backend timeout may still execute JS later. Keep unknown receipt, no replay.
            unknown={'browser_id':b,'command':'evaluate','tab_id':tab,'expression':"new Promise(resolve=>setTimeout(()=>{fetch('/submit',{method:'POST',body:JSON.stringify({customer:'late-once'})}).then(()=>resolve(1))},800))",'timeout_s':.15}
            g.call(c,'private_browser',unknown,'backend-timeout',expect='PRIVATE_CDP_OUTCOME_UNKNOWN');time.sleep(1)
            g.call(c,'private_browser',unknown,'backend-timeout',expect='REQUEST_OUTCOME_UNKNOWN')
            check(sum(json.loads(e).get('customer')=='late-once' for e in g.events)==1,'UNKNOWN_REPLAYED')
            check(g.call(c,'request_status',{'request_key':'backend-timeout'})['state']=='unknown','UNKNOWN_RECEIPT')
            # Browser crash, then worker/Hub crash: only exact saved owned identities.
            g.own_tree(g.process.pid);g.crash_browser_then_worker(browsers[1])
            g.own_tree(g.process.pid);g.stop_bridge();time.sleep(.5);g.start()
            # Resume saved identity; journal survives, old native handles are deliberately lost.
            session=c.session;c.call('session_open',{'agent_id':'one','task_id':'product-acceptance','resume_token':session['resume_token']})
            check(g.call(c,'request_status',{'request_key':'disconnect-after-dispatch'})['state']=='completed','RESTART_JOURNAL_LOST')
            g.call(c,'private_browser',{'browser_id':b,'command':'info'},expect='RESOURCE_NOT_FOUND')
            reopened=g.call(c,'private_browser',{'command':'open'},'explicit-reopen-after-crash');g.own_tree(reopened['pid'])
            check(not Path(info['profile_path']).exists(),'ORPHAN_PROFILE_NOT_RECLAIMED')
            g.cancel(c)
            g.results['P3']={'status':'PARTIAL','socket_disconnect':'PASS','backend_timeout_unknown_no_replay':'PASS','browser_crash':'PASS','hub_crash_restart_resume_journal_orphans':'PASS','worker_crash':'PASS','bridge_crash_restart_shared_hub_preserved':'PASS','windows_reboot':'NOT_RUN: no disruptive reboot authorized'}
    except Exception as exc:failure=exc;g.record('failure',{'type':type(exc).__name__,'code':getattr(exc,'code',str(exc))})
    finally:
        try:g.cleanup()
        except Exception as exc:failure=failure or exc;g.record('cleanup_failure',str(exc))
        server.shutdown();g.log.close()
        observation=observer.finish(out,g.owned)
        if not observation['samples'] or observation['error'] or observation['foreground_owned'] or observation['private_input']:failure=failure or RuntimeError('OWNER_INTERFERENCE_OR_OBSERVATION_FAILURE')
        result={'status':'FAIL' if failure else 'PASS','error':getattr(failure,'code',str(failure)) if failure else None,'milestones':g.results,'owner_observer':observation,'owned_processes_closed':not any(process_identity_matches(*p) for p in g.owned),'owned_identities':g.owned,'server_receipts':g.events}
        (out/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');print(json.dumps({k:v for k,v in result.items() if k not in {'owned_identities','server_receipts'}},ensure_ascii=False))
    return 1 if failure else 0

if __name__=='__main__':raise SystemExit(main())
