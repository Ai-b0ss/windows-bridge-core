import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { BrowserSidecarError } from './cua_browser_sidecar.mjs';

const hash=value=>crypto.createHash('sha256').update(String(value)).digest('hex').slice(0,24);
const EXPLICIT_PAGE_KEYS=['pageIndex','pageUrlContains','pageTitleContains'];

export class PlaywrightEngine {
  constructor(playwright, coreTools=null) { this.pw = playwright; this.coreTools = coreTools; this.frameIds = new WeakMap(); this.pageIds = new WeakMap(); }
  _timeout(value,fallback,cap=30000){ const n=Number(value??fallback); if(!Number.isFinite(n)||n<=0)throw new BrowserSidecarError('TIMEOUT_INVALID','timeout must be a positive finite number'); return Math.min(Math.max(1,Math.trunc(n)),cap); }
  _boundedInteger(value,{fallback,min,max,code,field}){ const n=Number(value??fallback); if(!Number.isFinite(n))throw new BrowserSidecarError(code,`${field} must be a finite number`,{field}); return Math.min(Math.max(Math.trunc(n),min),max); }
  async _bounded(code,timeout,fn){ try{return await fn();}catch(error){ if(error?.name==='TimeoutError'||String(error?.name||'').includes('Timeout'))throw new BrowserSidecarError(code,String(error?.message||error),{timeout_ms:timeout}); throw error; } }
  static async create() { try { const [playwright,coreBundle]=await Promise.all([import('playwright'),import('playwright-core/lib/coreBundle')]); return new PlaywrightEngine(playwright,coreBundle.tools); } catch(e) { throw new BrowserSidecarError('PLAYWRIGHT_NOT_INSTALLED',String(e?.message||e)); } }
  _frameId(frame){ let value=this.frameIds.get(frame); if(!value){ value=`frame-${crypto.randomBytes(6).toString('hex')}`; this.frameIds.set(frame,value); } return value; }
  _pageId(page){ let value=this.pageIds.get(page); if(!value){ value=`page-${crypto.randomBytes(6).toString('hex')}`; this.pageIds.set(page,value); } return value; }
  async _targetId(context,page){ let session=null; try{ session=await context.newCDPSession(page); const info=await session.send('Target.getTargetInfo'); return info?.targetInfo?.targetId?String(info.targetInfo.targetId):null; } catch { return null; } finally { if(session)await session.detach?.().catch(()=>{}); } }
  _hasExplicitPageSelector(options={}){ return EXPLICIT_PAGE_KEYS.some(key=>options[key]!==undefined); }
  _wireLifecycle(h){ if(typeof h.browser?.on==='function') h.browser.on('disconnected',()=>{h.disconnected=true;}); if(typeof h.context?.on==='function') h.context.on('close',()=>{h.contextClosed=true;}); }
  _markOwned(h,page,{created=false}={}){ h.ownedPages.add(page); if(created)h.createdPages.add(page); this._pageId(page); if(typeof page.on==='function'){ page.on('popup',popup=>this._markOwned(h,popup,{created:true})); page.on('crash',()=>h.crashedPages.add(page)); } }
  _assertLive(h,page){ if(h.disconnected||h.browser?.isConnected?.()===false) throw new BrowserSidecarError('BROWSER_CONNECTION_LOST','browser connection is no longer live'); if(h.contextClosed) throw new BrowserSidecarError('BROWSER_CONTEXT_CLOSED'); if(h.crashedPages?.has(page)) throw new BrowserSidecarError('BROWSER_RENDERER_CRASHED'); if(page?.isClosed?.()) throw new BrowserSidecarError('BROWSER_PAGE_CLOSED'); }
  _isInternalExtensionPage(h,page){ return h?.ownerTransport==='extension'&&String(page?.url?.()??'').startsWith('chrome-extension://mmlmfjhmonkocbjadbfplnigmagldckm/connect.html'); }
  _extensionClientNameFromPage(h,page){ if(!this._isInternalExtensionPage(h,page))return null; try{ const raw=new URL(String(page.url())).searchParams.get('client'); if(!raw)return null; const client=JSON.parse(raw); return typeof client?.name==='string'?client.name:null; }catch{return null;} }
  _publicPageUrl(h,page){ return this._isInternalExtensionPage(h,page)?'[playwright-extension-connect]':page.url(); }
  _assertOwned(h,page){ this._assertLive(h,page); if(!h.ownedPages.has(page)) throw new BrowserSidecarError('BROWSER_PAGE_NOT_OWNED','page is not owned by this surface',{page_id:this._pageId(page),url:this._publicPageUrl(h,page)}); }
  _findPageById(h,pageId){ const page=h.context.pages().find(candidate=>this._pageId(candidate)===pageId); if(!page) throw new BrowserSidecarError('BROWSER_PAGE_NOT_FOUND','page id not found',{page_id:pageId}); return page; }
  async _selectContext(browser,options){
    const contexts=browser.contexts();
    if(options.contextIndex!==undefined){ const context=contexts[Number(options.contextIndex)]; if(!context) throw new BrowserSidecarError('BROWSER_CONTEXT_NOT_FOUND'); return context; }
    if(contexts.length===1) return contexts[0];
    if(contexts.length===0) throw new BrowserSidecarError('BROWSER_CONTEXT_NOT_FOUND');
    throw new BrowserSidecarError('TARGET_AMBIGUOUS','multiple browser contexts; explicit contextIndex required',{contexts:contexts.length});
  }
  async _selectPage(context,options){
    const pages=context.pages();
    if(options.pageIndex!==undefined){ const page=pages[Number(options.pageIndex)]; if(!page) throw new BrowserSidecarError('BROWSER_PAGE_NOT_FOUND'); return page; }
    if(options.pageUrlContains!==undefined){ const needle=String(options.pageUrlContains); const matches=pages.filter(page=>page.url().includes(needle)); if(matches.length===1)return matches[0]; if(matches.length===0)throw new BrowserSidecarError('BROWSER_PAGE_NOT_FOUND','no page matched pageUrlContains',{needle}); throw new BrowserSidecarError('TARGET_AMBIGUOUS','multiple pages matched pageUrlContains',{needle,matches:matches.length}); }
    if(options.pageTitleContains!==undefined){ const needle=String(options.pageTitleContains); const titled=await Promise.all(pages.map(async page=>({page,title:await page.title()}))); const matches=titled.filter(item=>item.title.includes(needle)).map(item=>item.page); if(matches.length===1)return matches[0]; if(matches.length===0)throw new BrowserSidecarError('BROWSER_PAGE_NOT_FOUND','no page matched pageTitleContains',{needle}); throw new BrowserSidecarError('TARGET_AMBIGUOUS','multiple pages matched pageTitleContains',{needle,matches:matches.length}); }
    if(options.createPage===true)return context.newPage();
    if(pages.length===1)return pages[0];
    if(pages.length===0)throw new BrowserSidecarError('BROWSER_PAGE_NOT_FOUND','attached context has no page; set createPage=true explicitly');
    throw new BrowserSidecarError('TARGET_AMBIGUOUS','multiple browser pages; explicit page selector required',{pages:pages.length});
  }
  async _discoverOwnerChromeEndpoint(options={}){
    const dataDir=String(options.chromeUserDataDir??path.join(process.env.LOCALAPPDATA||'', 'Google', 'Chrome', 'User Data'));
    const activePortPath=String(options.devToolsActivePortPath??path.join(dataDir,'DevToolsActivePort'));
    let text;
    try{text=await fs.readFile(activePortPath,'utf8');}
    catch(error){throw new BrowserSidecarError('OWNER_BROWSER_REMOTE_DEBUGGING_NOT_ENABLED','Chrome DevToolsActivePort is unavailable',{cause:error?.code??'READ_FAILED'});}
    const [portLine,targetPath]=String(text).trim().split(/\r?\n/); const port=Number(portLine);
    if(!Number.isInteger(port)||port<=0||port>65535||!String(targetPath||'').startsWith('/devtools/browser/')) throw new BrowserSidecarError('OWNER_BROWSER_REMOTE_DEBUGGING_INVALID','Chrome DevToolsActivePort is malformed');
    return `ws://127.0.0.1:${port}${targetPath}`;
  }
  async _createBackgroundPage(browser,context){
    if(typeof browser?.newBrowserCDPSession!=='function') throw new BrowserSidecarError('OWNER_BACKGROUND_TAB_ROUTE_UNAVAILABLE','CDP browser session is unavailable');
    const session=await browser.newBrowserCDPSession();
    try{
      const created=await session.send('Target.createTarget',{url:'about:blank',background:true}); const targetId=String(created?.targetId||'');
      if(!targetId) throw new BrowserSidecarError('OWNER_BACKGROUND_TAB_ROUTE_UNAVAILABLE','Chrome did not return a target id');
      const deadline=Date.now()+2000;
      while(Date.now()<deadline){
        for(const page of context.pages()){ if(await this._targetId(context,page)===targetId)return page; }
        await new Promise(r=>setTimeout(r,20));
      }
      throw new BrowserSidecarError('OWNER_BACKGROUND_TAB_ROUTE_UNAVAILABLE','background tab did not materialize');
    } finally { await session.detach?.().catch(()=>{}); }
  }
  async _resolveApprovedServerEndpoint(options={}){
    if(options.playwrightServerEndpointFile!==undefined){
      const endpointFile=String(options.playwrightServerEndpointFile||'');
      if(!endpointFile) throw new BrowserSidecarError('OWNER_BROWSER_APPROVED_TRANSPORT_ENDPOINT_FILE_INVALID','approved transport endpoint file path is empty');
      let text;
      try{text=await fs.readFile(endpointFile,'utf8');}
      catch(error){throw new BrowserSidecarError('OWNER_BROWSER_APPROVED_TRANSPORT_UNAVAILABLE','approved transport endpoint file is unavailable',{cause:error?.code??'READ_FAILED'});}
      const endpoint=String(text).trim();
      if(!endpoint) throw new BrowserSidecarError('OWNER_BROWSER_APPROVED_TRANSPORT_UNAVAILABLE','approved transport endpoint file is empty');
      return endpoint;
    }
    const endpoint=String(options.playwrightServerEndpoint??'').trim();
    if(!endpoint) throw new BrowserSidecarError('OWNER_BROWSER_APPROVED_TRANSPORT_UNAVAILABLE','approved Playwright server endpoint is required');
    return endpoint;
  }
  async _connectOwnerApprovedServer(options={}){
    const endpoint=await this._resolveApprovedServerEndpoint(options);
    const timeout=Math.min(Math.max(Number(options.attachTimeoutMs??2500),250),30000);
    try{return await this.pw.chromium.connect(endpoint,{timeout});}
    catch(error){throw new BrowserSidecarError('OWNER_BROWSER_APPROVED_TRANSPORT_LOST','approved Playwright transport is unavailable',{cause:error?.name??'Error',timeout_ms:timeout});}
  }
  async _connectOwnerExtension(options={}){
    const token=String(process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN??'');
    if(!token) throw new BrowserSidecarError('OWNER_BROWSER_EXTENSION_TOKEN_UNAVAILABLE','protected Playwright Extension token was not injected into this process');
    const factory=this.coreTools?.createBrowserWithInfo;
    if(typeof factory!=='function') throw new BrowserSidecarError('OWNER_BROWSER_EXTENSION_RUNTIME_UNAVAILABLE','pinned Playwright Extension factory is unavailable');
    const userDataDir=options.chromeUserDataDir===undefined?undefined:String(options.chromeUserDataDir);
    const config={extension:true,browser:{browserName:'chromium',launchOptions:{channel:'chrome'},userDataDir}};
    try {
      const clientName=String(options.extensionClientName??'FF Windows Bridge').trim()||'FF Windows Bridge';
      const result=await factory(config,{cwd:process.cwd(),clientName},{extension:true,browser:'chrome'});
      if(!result?.browser) throw new Error('factory returned no browser');
      return {browser:result.browser,clientName};
    } catch(error) {
      throw new BrowserSidecarError('OWNER_BROWSER_EXTENSION_ATTACH_FAILED','authorized Playwright Extension transport could not be established',{cause:error?.name??'Error',message:String(error?.message||error||'')});
    }
  }
  async attach(options={}) {
    if(this.isolatedOnly){
      if(!options||typeof options!=='object'||Array.isArray(options))throw new BrowserSidecarError('ISOLATED_BROWSER_OPTIONS_INVALID');
      if(Object.keys(options).some(key=>key!=='headless'))throw new BrowserSidecarError('ISOLATED_BROWSER_OPTIONS_FORBIDDEN');
      if(options.headless!==undefined&&options.headless!==true)throw new BrowserSidecarError('ISOLATED_BROWSER_HEADLESS_REQUIRED');
      // Internally owned temporary profile; caller cannot substitute a daily profile.
      let executablePath;
      const candidates=[this.pw.chromium.executablePath(),
        path.join(process.env.PROGRAMFILES||'C:/Program Files','Google/Chrome/Application/chrome.exe'),
        path.join(process.env['PROGRAMFILES(X86)']||'C:/Program Files (x86)','Microsoft/Edge/Application/msedge.exe')];
      for(const candidate of candidates){try{await fs.access(candidate);executablePath=candidate;break;}catch{}}
      if(!executablePath)throw new BrowserSidecarError('ISOLATED_BROWSER_EXECUTABLE_NOT_FOUND');
      options={headless:true,executablePath};
    }
    const ownerBrowser=options.ownerBrowser===true||options.ownerMode==='daily-driver';
    if(options.ownerTransport==='extension'){
      if(!ownerBrowser) throw new BrowserSidecarError('OWNER_BROWSER_EXTENSION_MODE_INVALID','extension transport requires ownerBrowser=true or ownerMode=daily-driver');
      const extensionConnection=await this._connectOwnerExtension(options);
      const browser=extensionConnection.browser;
      const context=await this._selectContext(browser,options);
      const explicit=this._hasExplicitPageSelector(options);
      const created=!explicit&&options.createPage!==false;
      let page;
      let reusedConnectPage=false;
      if(created){
        const provisional={ownerTransport:'extension',extensionClientName:extensionConnection.clientName};
        const connectPage=context.pages().find(candidate=>this._isInternalExtensionPage(provisional,candidate)&&this._extensionClientNameFromPage(provisional,candidate)===extensionConnection.clientName);
        if(connectPage){
          try{
            await connectPage.goto('about:blank',{waitUntil:'domcontentloaded',timeout:2000});
            page=connectPage;
            reusedConnectPage=true;
          }catch{}
        }
        if(!page)page=await context.newPage();
      }else page=await this._selectPage(context,options);
      const handle={browser,context,page,ownedBrowser:false,ownerBrowser:true,ownerTransport:'extension',connectionMode:'extension',extensionClientName:extensionConnection.clientName,ownedPages:new WeakSet(),createdPages:new WeakSet(),crashedPages:new WeakSet(),disconnected:false,contextClosed:false}; this._wireLifecycle(handle);
      if(created)this._markOwned(handle,page,{created:true});
      else if(options.claimPage===true&&explicit)this._markOwned(handle,page);
      else throw new BrowserSidecarError('BROWSER_PAGE_OWNERSHIP_REQUIRED','extension transport requires one newly-created owned page or explicit claim');
      if(created&&!reusedConnectPage){
        const connectPages=context.pages().filter(candidate=>candidate!==page&&this._isInternalExtensionPage(handle,candidate)&&this._extensionClientNameFromPage(handle,candidate)===handle.extensionClientName);
        for(const connectPage of connectPages){ if(!connectPage.isClosed?.()) await connectPage.close().catch(()=>{}); }
      }
      return handle;
    }
    if(ownerBrowser&&options.ownerTransport==='playwright-server'){
      const browser=await this._connectOwnerApprovedServer(options);
      const context=await this._selectContext(browser,options);
      const explicit=this._hasExplicitPageSelector(options);
      const page=!explicit&&options.createPage!==false?await this._createBackgroundPage(browser,context):await this._selectPage(context,options);
      const handle={browser,context,page,ownedBrowser:false,ownerBrowser:true,ownerTransport:'playwright-server',connectionMode:'playwright-server',ownedPages:new WeakSet(),createdPages:new WeakSet(),crashedPages:new WeakSet(),disconnected:false,contextClosed:false}; this._wireLifecycle(handle);
      if(!explicit&&options.createPage!==false)this._markOwned(handle,page,{created:true});
      else if(options.claimPage===true&&explicit)this._markOwned(handle,page);
      else throw new BrowserSidecarError('BROWSER_PAGE_OWNERSHIP_REQUIRED','approved owner transport requires one newly-created owned page or explicit claim');
      return handle;
    }
    const endpoint=options.cdpEndpoint??(ownerBrowser?await this._discoverOwnerChromeEndpoint(options):null);
    if(endpoint){
      const requestedTimeout=Number(options.attachTimeoutMs??(ownerBrowser?2500:30000));
      if(!Number.isFinite(requestedTimeout)||requestedTimeout<=0) throw new BrowserSidecarError('BROWSER_ATTACH_TIMEOUT_INVALID','attachTimeoutMs must be a positive finite number');
      const attachTimeoutMs=Math.min(Math.max(requestedTimeout,250),30000);
      let browser;
      try { browser=await this.pw.chromium.connectOverCDP(endpoint,{timeout:attachTimeoutMs}); }
      catch(error) {
        if(ownerBrowser){
          const message=String(error?.message||error||'owner browser attach failed');
          const approvalLike=error?.name==='TimeoutError'||/allow.*incoming|remote[- ]debug|timed out|timeout/i.test(message);
          if(approvalLike) throw new BrowserSidecarError('OWNER_BROWSER_APPROVAL_REQUIRED','owner Chrome remote-debugging route requires browser approval or an authorized supported transport',{transport:options.ownerTransport??'chrome-remote-debugging',timeout_ms:attachTimeoutMs});
          throw new BrowserSidecarError('NO_UNATTENDED_OWNER_BROWSER_ROUTE','owner Chrome attach failed before a supported unattended route was established',{transport:options.ownerTransport??'chrome-remote-debugging',cause:error?.name??'Error'});
        }
        throw error;
      }
      const context=await this._selectContext(browser,options);
      const explicit=this._hasExplicitPageSelector(options);
      const page=ownerBrowser&&!explicit&&options.createPage!==false?await this._createBackgroundPage(browser,context):await this._selectPage(context,options);
      const handle={browser,context,page,ownedBrowser:false,ownerBrowser,ownerTransport:ownerBrowser?(options.ownerTransport??'chrome-remote-debugging'):null,connectionMode:'cdp',ownedPages:new WeakSet(),createdPages:new WeakSet(),crashedPages:new WeakSet(),disconnected:false,contextClosed:false}; this._wireLifecycle(handle);
      if(ownerBrowser&&!explicit&&options.createPage!==false) this._markOwned(handle,page,{created:true});
      else if(options.createPage===true && !explicit) this._markOwned(handle,page,{created:true});
      else if(options.claimPage===true && explicit) this._markOwned(handle,page);
      else throw new BrowserSidecarError('BROWSER_PAGE_OWNERSHIP_REQUIRED','external browser pages require explicit selector plus claimPage=true; owner daily-driver mode otherwise creates one background-owned tab');
      return handle;
    }
    const launchOptions={headless:options.headless??true,...(options.proxy?{proxy:options.proxy}:{}),...(options.executablePath?{executablePath:String(options.executablePath)}:{}),...(Array.isArray(options.args)?{args:options.args.map(String)}:{})};
    let managedProfile=null;
    if(this.isolatedOnly){
      const root=process.env.FF_ISOLATED_BROWSER_PROFILE_ROOT;
      if(!root)throw new BrowserSidecarError('ISOLATED_PROFILE_STORAGE_UNAVAILABLE');
      const info=await fs.lstat(root);
      if(!info.isDirectory()||info.isSymbolicLink())throw new BrowserSidecarError('ISOLATED_PROFILE_STORAGE_INVALID');
      managedProfile=await fs.mkdtemp(path.join(root,'profile-'));
    }
    let context,page;
    try{
      context=await this.pw.chromium.launchPersistentContext(managedProfile||options.userDataDir||'',launchOptions);
      page=context.pages()[0]??await context.newPage();
    }catch(error){
      if(context)await context.close().catch(()=>{});
      if(managedProfile)await fs.rm(managedProfile,{recursive:true,force:true,maxRetries:10,retryDelay:100});
      throw error;
    }
    const handle={browser:context.browser?.()??null,context,page,ownedBrowser:true,headless:launchOptions.headless,managedTemporaryProfile:!options.userDataDir,managedProfile,connectionMode:'persistent',ownedPages:new WeakSet(),createdPages:new WeakSet(),crashedPages:new WeakSet(),disconnected:false,contextClosed:false}; this._wireLifecycle(handle); this._markOwned(handle,page,{created:true}); return handle;
  }
  async capabilities(h){return {physical_input:false,semantic_dom:true,isolated_profile:!h?.ownerBrowser,cdp_attach:true,iframe_semantics:true,tab_ownership:true,external_browser_close_safe:!h?.ownedBrowser,owner_browser:Boolean(h?.ownerBrowser),owner_transport:h?.ownerTransport??null,owner_attach_approval_pending:false,headless:h?.headless===true,managed_temporary_profile:h?.managedTemporaryProfile===true};}
  async _mutationSignature(page){
    const signature=[];
    for(const frame of page.frames()){
      const frameId=this._frameId(frame);
      try {
        const epoch=await frame.evaluate(()=>{
          const key='__cuaMutationEpochState_v1';
          let state=globalThis[key];
          if(!state){
            state={epoch:0,documentId:(globalThis.crypto?.randomUUID?.()??('doc-'+Date.now()+'-'+Math.random()))}; globalThis[key]=state;
            const bump=()=>{state.epoch++;};
            const watched=new Set(['id','role','name','placeholder','type','disabled','checked','hidden','style','contenteditable']);
            const root=document.documentElement;
            if(root&&typeof MutationObserver==='function'){
              state.observer=new MutationObserver(records=>{
                for(const record of records){
                  if(record.type!=='attributes'||watched.has(record.attributeName)||String(record.attributeName||'').startsWith('aria-')){bump();break;}
                }
              });
              state.observer.observe(root,{subtree:true,childList:true,characterData:true,attributes:true});
            }
            addEventListener('input',bump,true); addEventListener('change',bump,true);
          }
          return {epoch:state.epoch,documentId:state.documentId};
        });
        signature.push({frameId,url:frame.url(),epoch});
      } catch { signature.push({frameId,url:frame.url(),detached:true}); }
    }
    return hash(JSON.stringify(signature));
  }
  async fingerprint(h){ this._assertOwned(h,h.page); return `${this._pageId(h.page)}|${h.page.url()}|${await this._mutationSignature(h.page)}`; }
  async _snapshotOnce(h){
    this._assertOwned(h,h.page); const fingerprint=await this.fingerprint(h); const entities=[]; let truncated=false; let sensitiveRedactions=0;
    for(const frame of h.page.frames()){
      const frameId=this._frameId(frame); let rows=[];
      try { rows=await frame.locator('a,button,input,textarea,select,[role],[contenteditable="true"]').evaluateAll(els=>els.slice(0,501).map(el=>({semantic_key:el.id?`id:${el.id}`:(()=>{let n=el,parts=[];while(n&&n.nodeType===1&&n!==document.documentElement){let j=1,p=n;while((p=p.previousElementSibling))if(p.tagName===n.tagName)j++;parts.unshift(`${n.tagName.toLowerCase()}:nth-of-type(${j})`);n=n.parentElement;}return `css:${parts.join('>')}`;})(),role:el.getAttribute('role')||el.tagName.toLowerCase(),name:el.getAttribute('aria-label')||el.getAttribute('name')||el.textContent?.trim().slice(0,160)||el.getAttribute('placeholder')||'',actions:[...(el.matches('input[type="file"]')?['upload']:[]),...(el.matches('a[download]')?['download']:[]),...(el.matches('a,button,input[type="button"],input[type="submit"],[role="button"]')?['click']:[]),...(el.matches('input:not([type="button"]):not([type="submit"]):not([type="file"]):not([type="checkbox"]):not([type="radio"]),textarea,[contenteditable="true"]')?['fill','clear','type']:[]),...(el.matches('input[type="checkbox"],[role="checkbox"]')?['check','uncheck']:[]),...(el.matches('input[type="radio"],[role="radio"]')?['check']:[]),...(el.matches('select')?['select']:[]),'hover','press','focus','scroll_into_view','drag_to'],state:{disabled:Boolean(el.disabled)||el.getAttribute('aria-disabled')==='true',readonly:Boolean(el.readOnly)||el.getAttribute('aria-readonly')==='true',checked:el.matches('input[type="checkbox"],input[type="radio"]')?Boolean(el.checked):null,value:el.matches('input:not([type="file"]),textarea,select')?String(el.value??''):null,selected:el.matches('select')?Array.from(el.selectedOptions||[]).map(o=>String(o.value)):null},evidence:{id:el.id||null,tag:el.tagName.toLowerCase(),type:el.getAttribute('type')||null}}))); } catch { continue; }
      if(rows.length>500){truncated=true;rows=rows.slice(0,500);} for(const row of rows){ const safeRow=row?.evidence?.type==='password'&&row?.state?{...row,state:{...row.state,value:'[REDACTED]'}}:row; if(safeRow!==row)sensitiveRedactions++; entities.push({...safeRow,frame_id:frameId}); }
    }
    return {fingerprint,entities,truncated,sensitive_redactions:sensitiveRedactions};
  }
  async _passwordAriaSignatures(frame,timeout){
    let fields; let count;
    try { fields=frame.locator('input[type="password"]'); count=await fields.count(); }
    catch(error){ throw new BrowserSidecarError('SNAPSHOT_SENSITIVE_REDACTION_FAILED','password-field discovery failed',{cause:error?.name??'Error'}); }
    if(!Number.isInteger(count)||count<0) throw new BrowserSidecarError('SNAPSHOT_SENSITIVE_REDACTION_FAILED','password-field count was invalid');
    if(count>32) throw new BrowserSidecarError('SNAPSHOT_SENSITIVE_FIELDS_EXCEEDED','too many password fields to redact safely',{count,limit:32});
    const signatures=new Map();
    const valueRow=/^(\s*-\s+[^\s:\[]+(?:\s+"(?:[^"\\]|\\.)*")?(?:\s+\[[^\]]*\])*)\s*:\s?(.*)$/;
    for(let index=0;index<count;index++){
      let tree;
      try { tree=await fields.nth(index).ariaSnapshot({timeout:Math.min(timeout,1000),mode:'default',depth:1}); }
      catch(error){ throw new BrowserSidecarError('SNAPSHOT_SENSITIVE_REDACTION_FAILED','password-field semantic identity failed',{index,cause:error?.name??'Error'}); }
      const line=String(tree??'').split(/\r?\n/).find(candidate=>candidate.trimStart().startsWith('-'));
      if(!line)continue;
      const match=line.match(valueRow);
      if(!match)continue;
      const parsed=this._parseAriaRoot(line.trimStart(),'textbox');
      const key=this._ariaKey(parsed.role||'textbox',parsed.name);
      if(!signatures.has(key))signatures.set(key,new Set());
      signatures.get(key).add(match[2]);
    }
    return signatures;
  }
  _redactSensitiveAriaRows(tree,signatures){
    const lines=String(tree??'').split(/\r?\n/); let redactions=0;
    if(!signatures?.size)return {tree:lines.join('\n'),redactions};
    const valueRow=/^(\s*-\s+[^\s:\[]+(?:\s+"(?:[^"\\]|\\.)*")?(?:\s+\[[^\]]*\])*)\s*:\s?(.*)$/;
    for(let index=0;index<lines.length;index++){
      const match=lines[index].match(valueRow);
      if(!match)continue;
      const parsed=this._parseAriaRoot(lines[index].trimStart());
      const values=signatures.get(this._ariaKey(parsed.role,parsed.name));
      if(!values?.has(match[2]))continue;
      lines[index]=match[1]+': [REDACTED]'; redactions++;
    }
    return {tree:lines.join('\n'),redactions};
  }
  async _ariaSnapshotOnce(h,options={}){
    this._assertOwned(h,h.page);
    const fingerprint=await this.fingerprint(h);
    const maxChars=this._boundedInteger(options.maxChars,{fallback:24000,min:1000,max:200000,code:'SNAPSHOT_MAX_CHARS_INVALID',field:'maxChars'});
    const depth=this._boundedInteger(options.depth,{fallback:24,min:1,max:64,code:'SNAPSHOT_DEPTH_INVALID',field:'depth'});
    const timeout=this._boundedInteger(options.timeoutMs,{fallback:3000,min:100,max:10000,code:'SNAPSHOT_TIMEOUT_INVALID',field:'timeoutMs'});
    const frames=[]; let used=0; let truncated=false; let sensitiveRedactions=0;
    for(const frame of h.page.frames()){
      if(used>=maxChars){truncated=true;break;}
      const frameId=this._frameId(frame); let tree='';
      try {
        tree=await frame.locator('body').ariaSnapshot({timeout,mode:'default',depth});
      } catch(error) { tree=`<aria-snapshot-unavailable:${error?.name??'Error'}>`; }
      if(!tree.startsWith('<aria-snapshot-unavailable:')){
        const sensitiveSignatures=await this._passwordAriaSignatures(frame,timeout);
        const redacted=this._redactSensitiveAriaRows(tree,sensitiveSignatures);
        tree=redacted.tree; sensitiveRedactions+=redacted.redactions;
      }
      const remaining=maxChars-used;
      if(tree.length>remaining){tree=tree.slice(0,remaining);truncated=true;}
      used+=tree.length;
      frames.push({frame_id:frameId,url:frame.url(),tree});
    }
    return {fingerprint,entities:[],semantic_tree:{frames},truncated,representation:'aria',semantic_chars:used,semantic_depth:depth,semantic_max_chars:maxChars,sensitive_redactions:sensitiveRedactions};
  }
  async _hybridSnapshotOnce(h,options={}){
    const [aria,dom]=await Promise.all([this._ariaSnapshotOnce(h,options),this._snapshotOnce(h)]);
    if(aria.fingerprint!==dom.fingerprint) throw new BrowserSidecarError('SNAPSHOT_UNSTABLE','browser surface changed while hybrid snapshot was being captured',{mode:'hybrid'});
    return {
      fingerprint:aria.fingerprint,
      entities:dom.entities,
      semantic_tree:aria.semantic_tree,
      truncated:Boolean(aria.truncated||dom.truncated),
      semantic_truncated:Boolean(aria.truncated),
      entity_truncated:Boolean(dom.truncated),
      representation:'hybrid',
      semantic_chars:aria.semantic_chars,
      semantic_depth:aria.semantic_depth,
      semantic_max_chars:aria.semantic_max_chars,
      sensitive_redactions:Number(aria.sensitive_redactions??0)+Number(dom.sensitive_redactions??0),
    };
  }
  async snapshot(h,options={}){
    const maxAttempts=this._boundedInteger(options.snapshotAttempts,{fallback:2,min:1,max:4,code:'SNAPSHOT_ATTEMPTS_INVALID',field:'snapshotAttempts'});
    const mode=String(options.mode??'aria').toLowerCase();
    if(!['aria','dom','hybrid'].includes(mode))throw new BrowserSidecarError('SNAPSHOT_MODE_UNSUPPORTED',mode);
    for(let attempt=1;attempt<=maxAttempts;attempt++){
      const candidate=mode==='aria'?await this._ariaSnapshotOnce(h,options):mode==='dom'?await this._snapshotOnce(h):await this._hybridSnapshotOnce(h,options);
      const after=await this.fingerprint(h);
      if(candidate.fingerprint===after)return {...candidate,snapshot_attempts:attempt};
    }
    throw new BrowserSidecarError('SNAPSHOT_UNSTABLE','browser surface changed while snapshot was being captured',{attempts:maxAttempts,mode});
  }
  _parseAriaRoot(snapshot, fallbackRole=''){
    const line=String(snapshot??'').split(/\r?\n/,1)[0].trim();
    const match=line.match(/^-\s+([^\s:\[]+)(?:\s+"((?:[^"\\]|\\.)*)")?/);
    if(!match)return {role:String(fallbackRole||'').toLowerCase(),name:''};
    let name='';
    if(match[2]!==undefined){ try{name=JSON.parse(`"${match[2]}"`);}catch{name=match[2];} }
    return {role:String(match[1]||fallbackRole||'').toLowerCase(),name};
  }
  _ariaKey(role,name){return `aria:${JSON.stringify({role:String(role).toLowerCase(),name:String(name)})}`;}
  _decodeAriaKey(key){try{return JSON.parse(String(key).slice(5));}catch{return null;}}
  async _entityFromLocator(locator,roleHint=''){
    const aria=await locator.ariaSnapshot({timeout:1500});
    const identity=this._parseAriaRoot(aria,roleHint);
    const meta=await locator.evaluate(el=>({evidence:{id:el.id||null,tag:el.tagName.toLowerCase(),type:el.getAttribute('type')||null},state:{disabled:Boolean(el.disabled)||el.getAttribute('aria-disabled')==='true',readonly:Boolean(el.readOnly)||el.getAttribute('aria-readonly')==='true',checked:el.matches('input[type="checkbox"],input[type="radio"]')?Boolean(el.checked):null,value:el.matches('input:not([type="file"]),textarea,select')?String(el.value??''):null,selected:el.matches('select')?Array.from(el.selectedOptions||[]).map(o=>String(o.value)):null}}));
    const actions=await locator.evaluate(el=>[...(el.matches('input[type="file"]')?['upload']:[]),...(el.matches('a[download]')?['download']:[]),...(el.matches('a,button,input[type="button"],input[type="submit"],[role="button"]')?['click']:[]),...(el.matches('input:not([type="button"]):not([type="submit"]):not([type="file"]):not([type="checkbox"]):not([type="radio"]),textarea,[contenteditable="true"]')?['fill','clear','type']:[]),...(el.matches('input[type="checkbox"],[role="checkbox"]')?['check','uncheck']:[]),...(el.matches('input[type="radio"],[role="radio"]')?['check']:[]),...(el.matches('select')?['select']:[]),'hover','press','focus','scroll_into_view','drag_to']);
    return {semantic_key:this._ariaKey(identity.role,identity.name),role:identity.role,name:identity.name,actions,state:meta.state,evidence:meta.evidence};
  }
  async find(h,query={}){
    this._assertOwned(h,h.page);
    const limit=Math.min(Math.max(Number(query.limit??20),1),100); const needle=String(query.text??''); const role=query.role==null?null:String(query.role).toLowerCase(); const action=query.action==null?null:String(query.action);
    const fingerprint=await this.fingerprint(h); const entities=[]; let totalMatches=0;
    if(role&&['button','link','textbox','combobox','checkbox','radio','option','menuitem','tab','switch','slider','spinbutton'].includes(role)){
      for(const frame of h.page.frames()){
        const frameId=this._frameId(frame); let locator;
        try{ locator=frame.getByRole(role,needle?{name:needle,exact:false}:{}); }catch{ continue; }
        let count=0; try{count=await locator.count();}catch{continue;}
        for(let i=0;i<count;i++){
          try{
            const entity=await this._entityFromLocator(locator.nth(i),role);
            if(action&&!entity.actions.includes(action))continue;
            totalMatches++;
            if(entities.length<limit)entities.push({...entity,frame_id:frameId});
          }catch{}
        }
      }
    } else {
      const lowerNeedle=needle.toLowerCase();
      for(const frame of h.page.frames()){
        const frameId=this._frameId(frame); let part;
        try { part=await frame.locator('a,button,input,textarea,select,[role],[contenteditable="true"]').evaluateAll((els,q)=>{ const rows=[]; let total=0; for(const el of els){ const actions=[...(el.matches('input[type="file"]')?['upload']:[]),...(el.matches('a[download]')?['download']:[]),...(el.matches('a,button,input[type="button"],input[type="submit"],[role="button"]')?['click']:[]),...(el.matches('input:not([type="button"]):not([type="submit"]):not([type="file"]):not([type="checkbox"]):not([type="radio"]),textarea,[contenteditable="true"]')?['fill','clear','type']:[]),...(el.matches('input[type="checkbox"],[role="checkbox"]')?['check','uncheck']:[]),...(el.matches('input[type="radio"],[role="radio"]')?['check']:[]),...(el.matches('select')?['select']:[]),'hover','press','focus','scroll_into_view','drag_to']; const role=el.getAttribute('role')||el.tagName.toLowerCase(); const name=el.getAttribute('aria-label')||el.getAttribute('name')||el.textContent?.trim().slice(0,160)||el.getAttribute('placeholder')||''; let semantic_key;if(el.id)semantic_key=`id:${el.id}`;else{let n=el,parts=[];while(n&&n.nodeType===1&&n!==document.documentElement){let j=1,p=n;while((p=p.previousElementSibling))if(p.tagName===n.tagName)j++;parts.unshift(`${n.tagName.toLowerCase()}:nth-of-type(${j})`);n=n.parentElement;}semantic_key=`css:${parts.join('>')}`;} if((!q.needle||name.toLowerCase().includes(q.needle)||semantic_key.toLowerCase().includes(q.needle))&&(!q.action||actions.includes(q.action))){ total++; if(rows.length<q.limit)rows.push({semantic_key,role,name,actions,state:{disabled:Boolean(el.disabled)||el.getAttribute('aria-disabled')==='true',readonly:Boolean(el.readOnly)||el.getAttribute('aria-readonly')==='true',checked:el.matches('input[type="checkbox"],input[type="radio"]')?Boolean(el.checked):null,value:el.matches('input:not([type="file"]),textarea,select')?String(el.value??''):null,selected:el.matches('select')?Array.from(el.selectedOptions||[]).map(o=>String(o.value)):null},evidence:{id:el.id||null,tag:el.tagName.toLowerCase(),type:el.getAttribute('type')||null}}); }} return {rows,total}; },{needle:lowerNeedle,action,limit:Math.max(0,limit-entities.length)}); } catch { continue; }
        totalMatches+=Number(part.total||0); for(const row of part.rows||[])if(entities.length<limit)entities.push({...row,frame_id:frameId});
      }
    }
    const after=await this.fingerprint(h); if(after!==fingerprint)throw new BrowserSidecarError('SNAPSHOT_UNSTABLE','interactive DOM changed while find was running');
    return {fingerprint,entities,truncated:totalMatches>entities.length,total_matches:totalMatches};
  }
  _findFrame(h,frameId){ return h.page.frames().find(frame=>this._frameId(frame)===frameId)??null; }
  async resolve(h,entity){
    this._assertOwned(h,h.page);
    const frame=this._findFrame(h,entity.frame_id); if(!frame)return null;
    const key=entity.semantic_key||''; let locator;
    if(key.startsWith('aria:')){
      const identity=this._decodeAriaKey(key); if(!identity?.role)return null;
      locator=frame.getByRole(identity.role,{name:String(identity.name??''),exact:true});
    } else if(key.startsWith('id:')) locator=frame.locator(`[id=${JSON.stringify(key.slice(3))}]`);
    else if(key.startsWith('css:')) locator=frame.locator(key.slice(4));
    else return null;
    const count=await locator.count(); if(count===0)return null; if(count>1)return {locator:locator.first(),ambiguous:true,frame};
    if(key.startsWith('aria:')){
      const currentEntity=await this._entityFromLocator(locator.first(),entity.role);
      const changed=currentEntity.role!==entity.role||currentEntity.name!==entity.name||currentEntity.evidence?.tag!==(entity.evidence?.tag??null)||currentEntity.evidence?.type!==(entity.evidence?.type??null);
      return {locator:locator.first(),ambiguous:false,changed,frame,details:changed?{observed:{role:entity.role,name:entity.name,evidence:entity.evidence},current:{role:currentEntity.role,name:currentEntity.name,evidence:currentEntity.evidence}}:null};
    }
    const current=await locator.first().evaluate(el=>({role:el.getAttribute('role')||el.tagName.toLowerCase(),name:el.getAttribute('aria-label')||el.getAttribute('name')||el.textContent?.trim().slice(0,160)||el.getAttribute('placeholder')||'',id:el.id||null,tag:el.tagName.toLowerCase(),type:el.getAttribute('type')||null}));
    const changed=current.role!==entity.role||current.name!==entity.name||current.id!==(entity.evidence?.id??null)||current.tag!==(entity.evidence?.tag??null)||current.type!==(entity.evidence?.type??null);
    return {locator:locator.first(),ambiguous:false,changed,frame,details:changed?{observed:{role:entity.role,name:entity.name,evidence:entity.evidence},current}:null};
  }
  async act(h,resolved,action,args={},ctx={}){
    this._assertOwned(h,h.page); const timeout=this._timeout(args.timeout_ms,5000); const locator=resolved.locator;
    return this._bounded('ACTION_TIMEOUT',timeout,async()=>{
      if(action==='click'){
        if(args.dialog){ const dialogPromise=h.page.waitForEvent('dialog',{timeout}).then(async dialog=>{ const evidence={type:dialog.type(),message:dialog.message()}; if(args.dialog.action==='dismiss')await dialog.dismiss(); else await dialog.accept(args.dialog.promptText); return evidence; }); const [,dialogEvidence]=await Promise.all([locator.click({timeout}),dialogPromise]); return {trace_refs:[{kind:'dialog',...dialogEvidence}]}; }
        await locator.click({timeout}); return {};
      }
      if(action==='fill'){await locator.fill(String(args.text??''),{timeout});return {};}
      if(action==='clear'){await locator.fill('',{timeout});return {};}
      if(action==='type'){await locator.pressSequentially(String(args.text??''),{delay:Number(args.delay_ms??0),timeout});return {};}
      if(action==='select'){await locator.selectOption(args.value??args.values,{timeout});return {};}
      if(action==='check'){await locator.check({timeout});return {};}
      if(action==='uncheck'){await locator.uncheck({timeout});return {};}
      if(action==='hover'){await locator.hover({timeout});return {};}
      if(action==='focus'){await locator.focus({timeout});return {};}
      if(action==='scroll_into_view'){await locator.scrollIntoViewIfNeeded({timeout});return {};}
      if(action==='press'){await locator.press(String(args.key??''),{timeout});return {};}
      if(action==='drag_to'){ if(!ctx.targetResolved?.locator)throw new BrowserSidecarError('DRAG_TARGET_REQUIRED'); await locator.dragTo(ctx.targetResolved.locator,{timeout}); return {}; }
      if(action==='upload'){ const files=Array.isArray(args.files)?args.files:[args.file].filter(Boolean); if(!files.length)throw new BrowserSidecarError('UPLOAD_FILES_REQUIRED'); if(h.ownerTransport==='extension'){ const payloads=[]; for(const file of files){ const filename=path.resolve(String(file)); const stat=await fs.stat(filename); payloads.push({name:path.basename(filename),mimeType:'application/octet-stream',buffer:await fs.readFile(filename),lastModifiedMs:stat.mtimeMs}); } await locator.setInputFiles(payloads,{timeout}); } else await locator.setInputFiles(files,{timeout}); return {}; }
      if(action==='download'){
        if(h.ownerTransport==='extension'){
          const operationId=String(args._ff_companion_operation_id??'');
          if(!/^[A-Za-z0-9._-]{8,96}$/.test(operationId)) throw new BrowserSidecarError('BROWSER_EXTENSION_DOWNLOAD_UNSUPPORTED','FF Browser Companion must be prepared before an owner-extension download',{transport:'extension'});
          await locator.click({timeout});
          return {postcondition:{kind:'companion_download_click',operation_id:operationId}};
        }
        const [download]=await Promise.all([h.page.waitForEvent('download',{timeout}),locator.click({timeout})]); const failure=await download.failure(); let savedPath=null; if(args.save_as){savedPath=String(args.save_as);await download.saveAs(savedPath);} else savedPath=await download.path(); let sha256=null; if(savedPath&&!failure){sha256=crypto.createHash('sha256').update(await fs.readFile(savedPath)).digest('hex');} return {postcondition:{kind:'download',path:savedPath,filename:download.suggestedFilename(),failure,sha256}};
      }
      throw new BrowserSidecarError('ACTION_UNSUPPORTED',action);
    });
  }
  async verify(h,spec,ctx={}){
    this._assertOwned(h,h.page); const {resolved,action,args={}}=ctx;
    if(spec?.selector!==undefined) throw new BrowserSidecarError('VERIFY_TARGET_MISMATCH_RISK','selector-based verification is forbidden for target-bound actions');
    if(!spec){
      if((action==='clear'||action==='type')&&resolved?.locator){ const expected=action==='clear'?'':String(args.expected??args.text??''); const actual=await resolved.locator.inputValue().catch(async()=>String(await resolved.locator.textContent()??'')); return {verified:actual===expected,kind:'target_value',expected_value:expected,actual_value:actual}; }
      if((action==='check'||action==='uncheck')&&resolved?.locator){ const expected=action==='check'; const actual=await resolved.locator.isChecked(); return {verified:actual===expected,kind:'target_checked',expected_checked:expected,actual_checked:actual}; }
      if(action==='upload'&&resolved?.locator){ const files=Array.isArray(args.files)?args.files:[args.file].filter(Boolean); const expected=files.map(file=>path.basename(String(file))); const actual=await resolved.locator.evaluate(el=>Array.from(el.files||[]).map(file=>file.name)); return {verified:expected.length===actual.length&&expected.every((value,index)=>value===actual[index]),kind:'target_files',expected_names:expected,actual_names:actual}; }
      if(action==='fill'&&resolved?.locator){ const expected=String(args.text??''); const actual=await resolved.locator.inputValue().catch(async()=>String(await resolved.locator.textContent()??'')); return {verified:actual===expected,kind:'target_value',expected_value:expected,actual_value:actual}; }
      if(action==='select'&&resolved?.locator){ const expected=Array.isArray(args.values)?args.values.map(String):[String(args.value??'')]; const actual=await resolved.locator.locator('option:checked').evaluateAll(options=>options.map(option=>String(option.value))); return {verified:expected.length===actual.length&&expected.every((value,index)=>value===actual[index]),kind:'target_selection',expected_values:expected,actual_values:actual}; }
      return {verified:false,reason:'postcondition_required'};
    }
    if(spec?.kind==='download')return {verified:!spec.failure&&Boolean(spec.path)&&Boolean(spec.sha256),kind:'download',path:spec.path,filename:spec.filename,failure:spec.failure??null,sha256:spec.sha256??null};
    if(spec?.kind==='companion_download_click')return {verified:true,kind:'companion_download_click',operation_id:String(spec.operation_id||'')};
    if(spec.url!==undefined)return {verified:h.page.url()===String(spec.url),actual_url:h.page.url()};
    if(spec.text!==undefined){ const scope=resolved?.frame??h.page; return {verified:await scope.getByText(String(spec.text),{exact:false}).count()>0,kind:'target_frame_text',text:String(spec.text)}; }
    if(spec.focused!==undefined){ if(!resolved?.locator)throw new BrowserSidecarError('VERIFY_TARGET_REQUIRED'); const actual=await resolved.locator.evaluate(el=>el===document.activeElement); const expected=Boolean(spec.focused); return {verified:actual===expected,kind:'target_focus',expected_focused:expected,actual_focused:Boolean(actual)}; }
    if(spec.value!==undefined){ if(!resolved?.locator)throw new BrowserSidecarError('VERIFY_TARGET_REQUIRED'); const actual=await resolved.locator.inputValue().catch(async()=>String(await resolved.locator.textContent()??'')); return {verified:actual===String(spec.value),kind:'target_value',expected_value:String(spec.value),actual_value:actual}; }
    return {verified:false,reason:'unsupported_verify_spec'};
  }
  async waitFor(h,spec={},timeoutMs=5000){ this._assertOwned(h,h.page); const timeout=this._timeout(timeoutMs,5000); return this._bounded('WAIT_TIMEOUT',timeout,async()=>{ if(spec.url!==undefined){await h.page.waitForURL(String(spec.url),{timeout});return {matched:true,kind:'url',url:h.page.url()};} if(spec.text!==undefined){await h.page.getByText(String(spec.text),{exact:false}).first().waitFor({state:'visible',timeout});return {matched:true,kind:'text',text:String(spec.text)};} if(spec.selector!==undefined){await h.page.locator(String(spec.selector)).first().waitFor({state:spec.state??'visible',timeout});return {matched:true,kind:'selector',selector:String(spec.selector),state:spec.state??'visible'};} throw new BrowserSidecarError('WAIT_CONDITION_UNSUPPORTED'); }); }
  async _navigate(h,operation,fn,timeoutMs=10000){ this._assertOwned(h,h.page); const timeout=this._timeout(timeoutMs,10000); return this._bounded('NAVIGATION_TIMEOUT',timeout,async()=>fn(timeout)); }
  async navigate(h,url,timeoutMs=10000){ return this._navigate(h,'navigate',timeout=>h.page.goto(url,{waitUntil:'domcontentloaded',timeout}),timeoutMs); }
  async reload(h,timeoutMs=10000){ return this._navigate(h,'reload',timeout=>h.page.reload({waitUntil:'domcontentloaded',timeout}),timeoutMs); }
  async back(h,timeoutMs=10000){ return this._navigate(h,'back',timeout=>h.page.goBack({waitUntil:'commit',timeout}),timeoutMs); }
  async forward(h,timeoutMs=10000){ return this._navigate(h,'forward',timeout=>h.page.goForward({waitUntil:'commit',timeout}),timeoutMs); }
  async identity(h){ this._assertOwned(h,h.page); return {page_id:this._pageId(h.page),url:this._publicPageUrl(h,h.page),title:await this._safeTitle(h.page,h.ownerBrowser?300:1000),owned:true}; }
  async _safeTitle(page,timeoutMs=300){
    const timeout=Math.max(1,Number(timeoutMs));
    return Promise.race([page.title().catch(()=>''),new Promise(resolve=>setTimeout(()=>resolve(''),timeout))]);
  }
  async listTabs(h){ const pages=h.context.pages().filter(p=>!this._isInternalExtensionPage(h,p)); return Promise.all(pages.map(async(p,index)=>({index,page_id:this._pageId(p),url:this._publicPageUrl(h,p),title:await this._safeTitle(p,h.ownerBrowser?300:1000),owned:h.ownedPages.has(p),active:p===h.page}))); }
  async claimTab(h,selector={}){ if(h.ownedBrowser)throw new BrowserSidecarError('BROWSER_PAGE_ALREADY_MANAGED','isolated context pages are already under Bridge ownership'); if(!this._hasExplicitPageSelector(selector))throw new BrowserSidecarError('BROWSER_PAGE_OWNERSHIP_REQUIRED','claim requires explicit page selector'); const page=await this._selectPage(h.context,selector); this._markOwned(h,page); h.page=page; return {page_id:this._pageId(page),owned:true}; }
  async newTab(h,url='about:blank',timeoutMs=10000){
    const timeout=this._timeout(timeoutMs,10000);
    const requested=String(url||'about:blank');
    const liveOwned=h.context.pages().filter(page=>h.ownedPages.has(page)&&!page.isClosed?.()&&!this._isInternalExtensionPage(h,page));
    let page=liveOwned.find(candidate=>String(candidate.url?.()??'')===requested)??null;
    let reused=Boolean(page);
    if(!page&&requested!=='about:blank'){
      page=liveOwned.find(candidate=>h.createdPages.has(candidate)&&String(candidate.url?.()??'')==='about:blank')??null;
      if(page){
        reused=true;
        await this._bounded('NAVIGATION_TIMEOUT',timeout,()=>page.goto(requested,{waitUntil:'domcontentloaded',timeout}));
      }
    }
    if(!page){
      if(h.ownerTransport==='extension'){
        page=(h.page&&!h.page.isClosed?.()&&h.createdPages.has(h.page)?h.page:null)??liveOwned.find(candidate=>h.createdPages.has(candidate))??null;
        if(!page)throw new BrowserSidecarError('BROWSER_EXTENSION_WORK_TAB_UNAVAILABLE');
        reused=true;
      }else{
        page=await h.context.newPage();
        this._markOwned(h,page,{created:true});
      }
      if(String(page.url?.()??'')!==requested)await this._bounded('NAVIGATION_TIMEOUT',timeout,()=>page.goto(requested,{waitUntil:'domcontentloaded',timeout}));
    }
    h.page=page;
    for(const candidate of h.context.pages()){
      if(candidate!==page&&h.createdPages.has(candidate)&&!candidate.isClosed?.()&&String(candidate.url?.()??'')==='about:blank')await candidate.close().catch(()=>{});
    }
    return {page_id:this._pageId(page),owned:true,reused};
  }
  async switchTab(h,pageId){ const page=this._findPageById(h,pageId); this._assertOwned(h,page); h.page=page; return {page_id:pageId,owned:true}; }
  async closeTab(h,pageId){ const page=this._findPageById(h,pageId); this._assertOwned(h,page); if(h.context.pages().length===1 && !h.ownedBrowser) throw new BrowserSidecarError('BROWSER_EXTERNAL_LAST_PAGE_CLOSE_FORBIDDEN'); await page.close(); if(h.page===page){ const replacement=h.context.pages().find(candidate=>h.ownedPages.has(candidate)); if(replacement)h.page=replacement; } return {page_id:pageId,closed:true}; }
  async close(h){
    if(h.ownedBrowser){ await h.context.close(); if(h.managedProfile)await fs.rm(h.managedProfile,{recursive:true,force:true,maxRetries:10,retryDelay:100}); return {detached:false,closed:true,owned_pages_closed:0,managed_profile_removed:Boolean(h.managedProfile)}; }
    let ownedPagesClosed=0;
    const extensionConnectPages=h.ownerTransport==='extension'&&h.extensionClientName?h.context.pages().filter(page=>this._isInternalExtensionPage(h,page)&&this._extensionClientNameFromPage(h,page)===h.extensionClientName):[];
    if(extensionConnectPages.length>1) throw new BrowserSidecarError('OWNER_BROWSER_EXTENSION_CONNECT_PAGE_AMBIGUOUS','multiple extension connect pages matched this surface',{matches:extensionConnectPages.length});
    if(h.page&&h.createdPages.has(h.page)&&!h.page.isClosed()){ await h.page.close(); ownedPagesClosed++; }
    for(const page of h.context.pages()){
      if(page!==h.page&&h.createdPages.has(page)&&!page.isClosed()){ await page.close(); ownedPagesClosed++; }
    }
    let extensionConnectPagesClosed=0;
    if(extensionConnectPages.length===1&&!extensionConnectPages[0].isClosed()){ await extensionConnectPages[0].close(); extensionConnectPagesClosed++; }
    let protocolConnectionClosed=false;
    if(h.ownerTransport==='extension'&&h.browser?._connection&&typeof h.browser._connection.close==='function'){
      h.browser._connection.close();
      protocolConnectionClosed=true;
    }
    return {detached:true,closed:false,owned_pages_closed:ownedPagesClosed,extension_connect_pages_closed:extensionConnectPagesClosed,protocol_connection_closed:protocolConnectionClosed};
  }
}
