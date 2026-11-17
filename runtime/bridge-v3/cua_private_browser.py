"""Semantic broker for one owned headful Chrome on a private OS Desktop.

Called inside the private worker; the Hub journals every effectful command.
No user profile, executable override, physical input or external file paths.
"""
from __future__ import annotations
import base64,hashlib,json,re,time,uuid
from pathlib import Path
from urllib.parse import urlsplit
import urllib.request
from cua_hidden_chrome import verify_chrome
from cua_universal_fastpath import _LocalWebSocket

READ_COMMANDS=frozenset({'tabs','observe','read','screenshot','download_read','info'})
COMMANDS=READ_COMMANDS|{'tab_open','navigate','activate','act','upload','download_prepare','evaluate','tab_close'}

class PrivateBrowserError(RuntimeError):
    def __init__(self,code,**details):
        self.code=code;self.details=details;super().__init__(code)

def safe_name(name):
    if not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}',name) or '..' in name:
        raise PrivateBrowserError('PRIVATE_FILE_NAME_INVALID',attempted=False)
    return name

def valid_url(url):
    if not isinstance(url,str) or len(url)>8192:raise PrivateBrowserError('PRIVATE_URL_INVALID',attempted=False)
    p=urlsplit(url)
    if url!='about:blank' and (p.scheme not in {'http','https'} or not p.hostname or p.username or p.password):
        raise PrivateBrowserError('PRIVATE_URL_INVALID',attempted=False)
    return url

class PrivateBrowser:
    def __init__(self,context,owns,desktop):
        self.context=context;self.owns=owns;self.desktop=desktop;self.snapshots={};self.tabs=set();self._download_socket=None
        self.root=Path(context['root'])/'artifacts';self.root.mkdir(exist_ok=True)
        self.http=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.info()
        self.tabs.update(p['id'] for p in self.pages())
    def info(self):return verify_chrome(self.context,owns=self.owns,desktop=self.desktop)
    def pages(self):
        info=self.info()
        with self.http.open(info['cdp_endpoint']+'/json/list',timeout=3) as r:pages=json.load(r)
        return [p for p in pages if p.get('type')=='page']
    def page(self,tab):
        if tab not in self.tabs:raise PrivateBrowserError('PRIVATE_TAB_NOT_OWNED',attempted=False)
        candidates=[p for p in self.pages() if p['id']==tab]
        if len(candidates)!=1:raise PrivateBrowserError('PRIVATE_TAB_LOST',attempted=False,retry_safe=False)
        return candidates[0]
    def send(self,method,params=None,tab=None,timeout=10,followup=None):
        info=self.info();endpoint=self.page(tab)['webSocketDebuggerUrl'] if tab else info['browser_ws_endpoint']
        parsed=urlsplit(endpoint)
        if parsed.scheme!='ws' or parsed.hostname!='127.0.0.1' or parsed.port!=info['cdp_port']:
            raise PrivateBrowserError('PRIVATE_ENDPOINT_CHANGED',attempted=False)
        sock=None;sent=False
        try:
            sock=_LocalWebSocket(endpoint,timeout);request_id=1;sock.send(json.dumps({'id':request_id,'method':method,'params':params or {}}));sent=True
            deadline=time.monotonic()+timeout
            while time.monotonic()<deadline:
                reply=json.loads(sock.recv())
                if reply.get('id')!=request_id:continue
                if 'error' in reply:raise PrivateBrowserError('PRIVATE_CDP_REJECTED',attempted=True,retry_safe=False,cdp_code=reply['error'].get('code'))
                result=reply.get('result',{})
                if followup is not None:
                    method,next_params=followup(result);followup=None;request_id+=1
                    sock.send(json.dumps({'id':request_id,'method':method,'params':next_params}));continue
                self.info();return result
            raise TimeoutError()
        except PrivateBrowserError:raise
        except Exception as exc:
            raise PrivateBrowserError('PRIVATE_CDP_OUTCOME_UNKNOWN' if sent else 'PRIVATE_CDP_DISCONNECTED',attempted=sent,outcome_unknown=sent,retry_safe=False,cause=type(exc).__name__) from exc
        finally:
            if sock:sock.close()
    def evaluate(self,tab,expression,timeout=10):
        result=self.send('Runtime.evaluate',{'expression':expression,'returnByValue':True,'awaitPromise':True},tab,timeout)
        if 'exceptionDetails' in result:raise PrivateBrowserError('PRIVATE_SCRIPT_FAILED',attempted=True,retry_safe=False)
        return result.get('result',{}).get('value')
    def observe(self,tab):
        token=uuid.uuid4().hex
        data=self.evaluate(tab,"""(()=>{const nodes=[...document.querySelectorAll('input,textarea,button,select,a,[role=button],[contenteditable=true]')].filter(e=>e.getClientRects().length).slice(0,128);window.__ffprivate={token:TOKEN,nodes};return {url:location.href,title:document.title,text:(document.body?.innerText||'').slice(0,16000),controls:nodes.map((e,i)=>({ref:String(i),tag:e.tagName.toLowerCase(),type:e.type||'',id:e.id,name:e.getAttribute('aria-label')||e.labels?.[0]?.innerText||e.innerText||e.name||'',value:e.value??null,disabled:!!e.disabled}))}})()""".replace('TOKEN',json.dumps(token)))
        self.snapshots[tab]=token;return {**data,'snapshot':token,'tab_id':tab}
    def target_js(self,args):
        tab=args.get('tab_id');token=args.get('snapshot');ref=args.get('ref')
        if not isinstance(token,str) or self.snapshots.get(tab)!=token or not isinstance(ref,str) or not ref.isdigit():
            raise PrivateBrowserError('PRIVATE_STALE_TARGET',attempted=False)
        return "const s=window.__ffprivate;if(!s||s.token!=="+json.dumps(token)+")return {error:'PRIVATE_STALE_TARGET'};const e=s.nodes["+ref+"];if(!e||!e.isConnected||e.disabled)return {error:'PRIVATE_STALE_TARGET'};"
    def postcondition(self,tab,condition):
        if not isinstance(condition,dict):raise PrivateBrowserError('PRIVATE_POSTCONDITION_REQUIRED',attempted=False)
        kind=condition.get('type');value=condition.get('value')
        if kind not in {'text_includes','url_equals','value_equals'} or not isinstance(value,str) or len(value)>16000:
            raise PrivateBrowserError('PRIVATE_POSTCONDITION_INVALID',attempted=False)
        if kind=='value_equals' and (not isinstance(condition.get('selector'),str) or len(condition['selector'])>512):
            raise PrivateBrowserError('PRIVATE_POSTCONDITION_INVALID',attempted=False)
        return kind,value
    def verify(self,tab,condition):
        kind,value=self.postcondition(tab,condition)
        expression={'text_includes':"(document.body?.innerText||'').includes("+json.dumps(value)+')','url_equals':'location.href==='+json.dumps(value),'value_equals':"(()=>{const n=document.querySelectorAll("+json.dumps(condition.get('selector',''))+");return n.length===1&&n[0].value==="+json.dumps(value)+"})()"}[kind]
        deadline=time.monotonic()+8
        while time.monotonic()<deadline:
            if self.evaluate(tab,expression) is True:return {'verified':True,'postcondition':condition}
            time.sleep(.1)
        raise PrivateBrowserError('PRIVATE_POSTCONDITION_FAILED',attempted=True,retry_safe=False)
    def dispatch(self,args):
        command=args.get('command');tab=args.get('tab_id')
        if command not in COMMANDS:raise PrivateBrowserError('PRIVATE_BROWSER_COMMAND_UNSUPPORTED',attempted=False)
        if command=='info':return self.info()
        if command=='tabs':return {'tabs':[{'tab_id':p['id'],'url':p['url'],'title':p['title']} for p in self.pages() if p['id'] in self.tabs]}
        if command=='tab_open':
            result=self.send('Target.createTarget',{'url':valid_url(args.get('url','about:blank')),'background':True});tab=result['targetId'];self.tabs.add(tab);return {'tab_id':tab}
        self.page(tab)
        if command=='observe':return self.observe(tab)
        if command=='read':return self.evaluate(tab,"({url:location.href,title:document.title,text:(document.body?.innerText||'').slice(0,32000)})")
        if command=='navigate':
            result=self.send('Page.navigate',{'url':valid_url(args.get('url'))},tab)
            self.snapshots.pop(tab,None)
            if result.get('errorText'):raise PrivateBrowserError('PRIVATE_NAVIGATION_FAILED',attempted=True,retry_safe=False)
            return {'tab_id':tab,'navigated':True,'requested_url':args['url']}
        if command=='activate':return self.send('Target.activateTarget',{'targetId':tab})
        if command=='tab_close':
            result=self.send('Target.closeTarget',{'targetId':tab});self.tabs.discard(tab);self.snapshots.pop(tab,None);return result
        if command=='screenshot':return {'mime':'image/png',**self.send('Page.captureScreenshot',{'format':'png'},tab)}
        if command=='act':
            condition=args.get('postcondition');self.postcondition(tab,condition)
            prefix=self.target_js(args);operation=args.get('operation');value=args.get('value','')
            if operation not in {'fill','click','select'} or not isinstance(value,str) or len(value)>16000:
                raise PrivateBrowserError('PRIVATE_ACTION_INVALID',attempted=False)
            code={
                'fill':"if(e.type==='file'||!['INPUT','TEXTAREA'].includes(e.tagName))return {error:'PRIVATE_ACTION_INVALID'};const setter=Object.getOwnPropertyDescriptor(Object.getPrototypeOf(e),'value')?.set;if(setter)setter.call(e,VALUE);else e.value=VALUE;e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));",
                'click':"e.click();",
                'select':"if(e.tagName!=='SELECT')return {error:'PRIVATE_ACTION_INVALID'};e.value=VALUE;e.dispatchEvent(new Event('change',{bubbles:true}));"
            }[operation].replace('VALUE',json.dumps(value))
            self.snapshots.pop(tab,None)
            result=self.evaluate(tab,'(()=>{'+prefix+code+'return {acted:true}})()')
            if not isinstance(result,dict) or result.get('error'):
                raise PrivateBrowserError((result or {}).get('error','PRIVATE_ACTION_FAILED'),attempted=False,retry_safe=False)
            return {'acted':True,**self.verify(tab,condition)}
        if command=='evaluate':
            expression=args.get('expression')
            if not isinstance(expression,str) or len(expression)>32000:raise PrivateBrowserError('PRIVATE_SCRIPT_INVALID',attempted=False)
            timeout=args.get('timeout_s',10)
            if type(timeout) not in (float,int) or not 0<timeout<=15:raise PrivateBrowserError('PRIVATE_TIMEOUT_INVALID',attempted=False)
            return {'value':self.evaluate(tab,expression,timeout)}
        if command=='upload':
            prefix=self.target_js(args);name=safe_name(args.get('name'))
            try:data=base64.b64decode(args.get('content_base64',''),validate=True)
            except Exception:raise PrivateBrowserError('PRIVATE_FILE_CONTENT_INVALID',attempted=False)
            if len(data)>1048576:raise PrivateBrowserError('PRIVATE_FILE_TOO_LARGE',attempted=False)
            check=self.evaluate(tab,'(()=>{'+prefix+"return {valid:e.tagName==='INPUT'&&e.type==='file'}})()")
            if not check.get('valid'):raise PrivateBrowserError('PRIVATE_UPLOAD_TARGET_INVALID',attempted=False)
            directory=self.root/'uploads'/uuid.uuid4().hex;directory.mkdir(parents=True);path=directory/name;path.write_bytes(data)
            self.send('Runtime.evaluate',{'expression':'window.__ffprivate.nodes['+args['ref']+']'},tab,
                followup=lambda result:('DOM.setFileInputFiles',{'objectId':result['result']['objectId'],'files':[str(path)]}))
            return {'uploaded':True,'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        if command=='download_prepare':
            directory=self.root/'downloads';directory.mkdir(exist_ok=True)
            # Chrome resets this override when its CDP connection detaches.
            # Keep this dedicated connection alive for the worker lifetime.
            if self._download_socket is None:
                info=self.info();sock=_LocalWebSocket(info['browser_ws_endpoint'],5)
                try:
                    sock.send(json.dumps({'id':1,'method':'Browser.setDownloadBehavior','params':{'behavior':'allow','downloadPath':str(directory),'eventsEnabled':True}}))
                    while True:
                        reply=json.loads(sock.recv())
                        if reply.get('id')==1:break
                    if reply.get('error'):raise PrivateBrowserError('PRIVATE_DOWNLOAD_SETUP_FAILED',attempted=True,retry_safe=False)
                    self._download_socket=sock
                except Exception:
                    sock.close();raise
            return {'prepared':True}
        if command=='download_read':
            name=safe_name(args.get('name'));path=self.root/'downloads'/name
            if path.is_symlink() or not path.is_file():raise PrivateBrowserError('PRIVATE_DOWNLOAD_NOT_READY',attempted=False)
            if path.stat().st_size>4194304:raise PrivateBrowserError('PRIVATE_FILE_TOO_LARGE',attempted=False)
            data=path.read_bytes();return {'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'content_base64':base64.b64encode(data).decode()}
