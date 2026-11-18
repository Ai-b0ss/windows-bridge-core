"""Semantic broker for one owned headful Chrome on a private OS Desktop.

Called inside the private worker; the Hub journals every effectful command.
No user profile, executable override, physical input or external file paths.
"""
from __future__ import annotations
import base64,hashlib,json,re,time,uuid
from pathlib import Path
from urllib.parse import urlsplit
from cua_hidden_chrome import verify_chrome
from cua_universal_fastpath import _LocalWebSocket

READ_COMMANDS=frozenset({'tabs','observe','read','screenshot','download_read','info'})
COMMANDS=READ_COMMANDS|{'tab_open','navigate','activate','act','upload','download_prepare','evaluate','tab_close'}
MAX_TABS = 8
_ENDPOINT_KEYS = {'browser_ws_endpoint', 'browser_ws_path', 'cdp_endpoint', 'cdp_port'}
_WINDOWS_DEVICE = re.compile(r'(?i)^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)')

class PrivateBrowserError(RuntimeError):
    def __init__(self,code,**details):
        self.code=code;self.details=details;super().__init__(code)

def safe_name(name):
    if (not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,100}',name)
            or '..' in name or name.endswith('.') or _WINDOWS_DEVICE.match(name)):
        raise PrivateBrowserError('PRIVATE_FILE_NAME_INVALID',attempted=False)
    return name

def valid_url(url):
    if not isinstance(url,str) or len(url)>8192:raise PrivateBrowserError('PRIVATE_URL_INVALID',attempted=False)
    try:p=urlsplit(url)
    except ValueError:raise PrivateBrowserError('PRIVATE_URL_INVALID',attempted=False) from None
    if url!='about:blank' and (p.scheme not in {'http','https'} or not p.hostname or p.username or p.password):
        raise PrivateBrowserError('PRIVATE_URL_INVALID',attempted=False)
    return url


class _BrowserConnection:
    """One verified Chrome connection and exact target attachments for a private worker."""

    def __init__(self):
        self.socket = None
        self.endpoint = None
        self.sessions = {}
        self.request_id = 0
        self.generation = 0

    def reset(self):
        if self.socket is not None:
            self.socket.close()
        self.socket = self.endpoint = None
        self.sessions.clear()

    def connect(self, info, deadline):
        endpoint = info['browser_ws_endpoint']
        parsed = urlsplit(endpoint)
        if (parsed.scheme != 'ws' or parsed.hostname != '127.0.0.1' or parsed.port != info['cdp_port']
                or self.endpoint not in {None, endpoint}):
            self.reset()
            raise PrivateBrowserError('PRIVATE_ENDPOINT_CHANGED', attempted=False)
        if self.socket is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('PRIVATE_CDP_DEADLINE')
            self.socket = _LocalWebSocket(endpoint, remaining)
            self.endpoint = endpoint
            self.generation += 1
        self.socket.set_deadline(deadline)

    def request(self, method, params, session=None, *, attempted=False):
        self.request_id += 1
        request_id = self.request_id
        request = {'id': request_id, 'method': method, 'params': params or {}}
        if session is not None:
            request['sessionId'] = session
        self.socket.send(json.dumps(request))
        while True:
            reply = json.loads(self.socket.recv())
            if reply.get('method') == 'Target.detachedFromTarget':
                detached = reply.get('params', {}).get('sessionId')
                self.sessions = {tab: sid for tab, sid in self.sessions.items() if sid != detached}
            if reply.get('id') != request_id:
                continue
            if reply.get('error'):
                raise PrivateBrowserError('PRIVATE_CDP_REJECTED', attempted=attempted,
                                          retry_safe=False, cdp_code=reply['error'].get('code'))
            if reply.get('sessionId') != session:
                raise RuntimeError('PRIVATE_CDP_SESSION_CHANGED')
            return reply.get('result', {})

    def attach(self, tab):
        session = self.sessions.get(tab)
        if session is None:
            result = self.request('Target.attachToTarget', {'targetId': tab, 'flatten': True})
            session = result.get('sessionId')
            if not isinstance(session, str) or not session:
                raise RuntimeError('PRIVATE_CDP_SESSION_INVALID')
            self.sessions[tab] = session
        return session


class PrivateBrowser:
    def __init__(self,context,owns,desktop):
        self.context=context;self.owns=owns;self.desktop=desktop;self.snapshots={};self.tabs=set()
        self.cdp = _BrowserConnection()
        self.download_generation = None
        self.unknown_tab_open = False
        self.root=Path(context['root'])/'artifacts';self.root.mkdir(exist_ok=True)
        self.tabs.update(p['targetId'] for p in self.pages())

    def verified_chrome(self, *, retained_socket=False):
        return verify_chrome(self.context, owns=self.owns, desktop=self.desktop, retained_socket=retained_socket)

    def info(self):
        return {**{key: value for key, value in self.verified_chrome().items() if key not in _ENDPOINT_KEYS},
                'transport': {'kind': 'private_cdp', 'socket_retained': self.cdp.socket is not None,
                              'generation': self.cdp.generation, 'attached_tabs': len(self.cdp.sessions),
                              'tab_limit': MAX_TABS, 'unknown_tab_open': self.unknown_tab_open}}

    def pages(self):
        pages = [page for page in self.send('Target.getTargets', timeout=3, effectful=False)['targetInfos']
                 if page.get('type') == 'page']
        present = {page['targetId'] for page in pages}
        for tab in self.tabs - present:
            self.cdp.sessions.pop(tab, None)
            self.snapshots.pop(tab, None)
        self.tabs.intersection_update(present)
        return pages

    def page(self,tab):
        if tab not in self.tabs:raise PrivateBrowserError('PRIVATE_TAB_NOT_OWNED',attempted=False)
        candidates=[p for p in self.pages() if p['targetId']==tab]
        if len(candidates)!=1:raise PrivateBrowserError('PRIVATE_TAB_LOST',attempted=False,retry_safe=False)
        return candidates[0]

    def send(self, method, params=None, tab=None, timeout=10, followup=None, effectful=True):
        if tab is not None and tab not in self.tabs:
            raise PrivateBrowserError('PRIVATE_TAB_NOT_OWNED', attempted=False)
        info = self.verified_chrome(retained_socket=self.cdp.socket is not None)
        attempted = False
        deadline = time.monotonic() + timeout
        try:
            self.cdp.connect(info, deadline)
            session = self.cdp.attach(tab) if tab is not None else None
            # A failed send may already have transmitted bytes. A followup's first call
            # only resolves an object handle and does not change the page.
            attempted = effectful and followup is None
            result = self.cdp.request(method, params, session, attempted=attempted)
            if followup is not None:
                method, params = followup(result)
                attempted = True
                result = self.cdp.request(method, params, session, attempted=True)
            self.verified_chrome(retained_socket=True)
            return result
        except PrivateBrowserError:
            raise
        except Exception as exc:
            self.cdp.reset()
            raise PrivateBrowserError('PRIVATE_CDP_OUTCOME_UNKNOWN' if attempted else 'PRIVATE_CDP_DISCONNECTED',
                                      attempted=attempted, outcome_unknown=attempted, retry_safe=False,
                                      cause=type(exc).__name__) from exc
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
        if not isinstance(token,str) or self.snapshots.get(tab)!=token or not isinstance(ref,str) or not re.fullmatch(r'[0-9]{1,3}',ref):
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
        if command=='tabs':
            pages = self.pages()
            return {'tabs':[{'tab_id':page['targetId'],'url':page['url'],'title':page['title']}
                            for page in pages if page['targetId'] in self.tabs],
                    'unclaimed_pages':sum(page['targetId'] not in self.tabs for page in pages)}
        if command=='tab_open':
            url = valid_url(args.get('url','about:blank'))
            if self.unknown_tab_open:
                raise PrivateBrowserError('PRIVATE_TAB_OPEN_RECONCILIATION_REQUIRED', attempted=False,
                                          retry_safe=False, recovery='close_browser_or_task')
            pages = self.pages()
            if len(pages) >= MAX_TABS:
                raise PrivateBrowserError('PRIVATE_TAB_LIMIT', attempted=False, limit=MAX_TABS)
            try:
                result = self.send('Target.createTarget', {'url':url, 'background':True})
            except PrivateBrowserError as exc:
                if exc.details.get('outcome_unknown'):
                    self.unknown_tab_open = True
                raise
            tab = result.get('targetId')
            if not isinstance(tab, str) or not tab or tab in self.tabs:
                self.unknown_tab_open = True
                raise PrivateBrowserError('PRIVATE_TAB_OPEN_IDENTITY_UNKNOWN', attempted=True,
                                          outcome_unknown=True, retry_safe=False)
            self.tabs.add(tab)
            return {'tab_id':tab}
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
            result = self.send('Target.closeTarget',{'targetId':tab})
            if result.get('success') is not True:
                raise PrivateBrowserError('PRIVATE_TAB_CLOSE_UNCONFIRMED', attempted=True,
                                          outcome_unknown=True, retry_safe=False)
            self.tabs.remove(tab)
            self.cdp.sessions.pop(tab, None)
            self.snapshots.pop(tab, None)
            return result
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
            directory=self.root/'uploads'/uuid.uuid4().hex;directory.mkdir(parents=True);path=directory/name;path.write_bytes(data)
            group = 'ff-upload-' + uuid.uuid4().hex
            self.snapshots.pop(tab, None)
            expression = '(()=>{'+prefix+"return e.tagName==='INPUT'&&e.type==='file'?e:null})()"

            def upload_to_element(result):
                element = result.get('result', {})
                if element.get('subtype') != 'node' or not isinstance(element.get('objectId'), str):
                    raise PrivateBrowserError('PRIVATE_UPLOAD_TARGET_INVALID', attempted=False)
                return 'DOM.setFileInputFiles', {'objectId':element['objectId'], 'files':[str(path)]}

            # Keep the object handle on its originating target session. Release it even
            # when CDP rejects the file operation, without replacing that operation's outcome.
            try:
                self.send('Runtime.evaluate', {'expression':expression, 'objectGroup':group}, tab,
                          followup=upload_to_element)
            finally:
                if self.cdp.socket is not None and tab in self.cdp.sessions:
                    try:
                        self.send('Runtime.releaseObjectGroup', {'objectGroup':group}, tab, timeout=2, effectful=False)
                    except Exception:
                        self.cdp.reset()
            return {'uploaded':True,'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
        if command=='download_prepare':
            directory=self.root/'downloads';directory.mkdir(exist_ok=True)
            # The override belongs to the verified connection and Chrome drops it on detach.
            if self.download_generation != self.cdp.generation:
                self.send('Browser.setDownloadBehavior', {'behavior':'allow','downloadPath':str(directory)}, timeout=5)
                self.download_generation = self.cdp.generation
            return {'prepared':True}
        if command=='download_read':
            name=safe_name(args.get('name'));path=self.root/'downloads'/name
            if path.is_symlink() or not path.is_file():raise PrivateBrowserError('PRIVATE_DOWNLOAD_NOT_READY',attempted=False)
            if path.stat().st_size>4194304:raise PrivateBrowserError('PRIVATE_FILE_TOO_LARGE',attempted=False)
            data=path.read_bytes();return {'name':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'content_base64':base64.b64encode(data).decode()}
