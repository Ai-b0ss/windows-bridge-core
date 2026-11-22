import fs from 'node:fs';
import path from 'node:path';
import {BrowserHub,extensionConnector,backgroundChromePreflight} from '../../runtime/bridge-v3/ff_browser_hub.mjs';

// Never invoke outside a disposable own-tab test: phases are driven by the
// parent test and the authenticated Playwright-extension DPAPI launcher.
const phase=process.argv[2];
const work=process.env.FF_HUB_CRASH_WORKDIR;
if(!['create','restore','cleanup'].includes(phase)||!work)throw new Error('PHASE_OR_WORKDIR_REQUIRED');
const config=JSON.parse(fs.readFileSync(path.join(work,'config.json'),'utf8'));
const ledgerFile=path.join(work,'ledger.json');
const owners=['hub-recover-alpha','hub-recover-beta'];
const connector=extensionConnector({
 playwrightRoot:process.env.FF_PLAYWRIGHT_ROOT,background:true,
 clientName:'FF Hub crash proof '+phase
});
function emit(step,props={}){console.log(JSON.stringify({step,...props}));}
await backgroundChromePreflight();
if(!process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN)throw new Error('NO_EXTENSION_TOKEN');
if(phase==='cleanup'){
 const existing=fs.existsSync(ledgerFile)?JSON.parse(fs.readFileSync(ledgerFile,'utf8')).tabs:[];
 if(!existing.length){emit('CLEANUP_SUCCESS',{count:0});process.exit(0);}
 let closed=0;
 const conn=await connector.connect();
 try {
  const seed=conn.context.pages().find(p=>{try{const u=new URL(p.url());return u.protocol==='chrome-extension:'&&u.hostname==='mmlmfjhmonkocbjadbfplnigmagldckm'&&u.pathname==='/connect.html';}catch{return false;}});
  if(!seed)throw new Error('CLEANUP_SEED_NOT_FOUND');
  for(const item of existing) {
   if(!owners.includes(item.owner)||typeof item.target_id!=='string')throw new Error('CLEANUP_UNTRUSTED_LEDGER');
   const outcome=await seed.evaluate(async ({wanted,base,title})=>{
    if(chrome.runtime?.id!=='mmlmfjhmonkocbjadbfplnigmagldckm')return 'WRONG_EXTENSION';
    const targets=(await chrome.debugger.getTargets()).filter(t=>t.id===wanted&&t.type==='page'&&Number.isSafeInteger(t.tabId));
    if(!targets.length)return 'ALREADY_ABSENT';
    if(targets.length!==1||targets[0].attached)return 'BUSY_OR_AMBIGUOUS';
    const tab=await chrome.tabs.get(targets[0].tabId);
    if(!tab.url?.startsWith(base)||tab.title!==title)return 'UNEXPECTED_TAB';
    const status=await chrome.runtime.sendMessage({type:'getConnectionStatus'});
    if(status.connections?.some(c=>c.connectedTabIds?.includes(tab.id)))return 'CLAIMED_BY_ANOTHER_SESSION';
    await chrome.tabs.remove(tab.id);
    return 'CLOSED_EXACT_TARGET';
   },{wanted:item.target_id,base:config.base,title:config.marker});
   if(!['CLOSED_EXACT_TARGET','ALREADY_ABSENT'].includes(outcome))throw new Error('CLEANUP_REFUSED_'+outcome);
   closed++;
  }
  fs.writeFileSync(ledgerFile,JSON.stringify({version:1,tabs:[]}));
  emit('CLEANUP_SUCCESS',{count:closed});
 }finally{await conn.browser.close().catch(()=>{});}
 process.exit(0);
}
const hub=new BrowserHub(connector,{ledgerFile});
let success=false;
try{
 if(phase==='create'){
  for(const owner of owners){
   const tab=await hub.tabOpen({owner,url:config.base+owner});
   const entry=hub._live(owner,tab.tab_id);
   if(!/^[a-fA-F0-9]{32}$/.test(entry.target_id||''))throw new Error('DURABLE_TARGET_MISSING');
   await entry.page.evaluate(({owner,marker})=>{
    window.__hubMemory={owner,marker,count:42};
    document.querySelector('#remember').value='typed-'+owner+'-'+marker;
   },{owner,marker:config.marker});
  }
  const records=JSON.parse(fs.readFileSync(ledgerFile,'utf8')).tabs;
  if(records.length!==2||new Set(records.map(x=>x.target_id)).size!==2)throw new Error('LEDGER_INVALID');
  emit('READY',{count:2,distinct_target_ids:true});
  await new Promise(()=>{setInterval(()=>{},1000);});
 }else if(phase==='restore'){
  const records=JSON.parse(fs.readFileSync(ledgerFile,'utf8')).tabs;
  if(records.length!==2||new Set(records.map(x=>x.target_id)).size!==2)throw new Error('LEDGER_RECORDS_INVALID');
  for(const owner of owners){
   const record=records.find(x=>x.owner===owner);
   if(!record)throw new Error('OWNER_MISSING');
   const recovered=await hub.tabRestore({owner,tab_id:record.tab_id});
   if(!recovered.reattached||recovered.evidence!=='cdp_target_id'||
      recovered.tab_id!==record.tab_id||recovered.page_state_preserved!==true)
     throw new Error('WRONG_PHYSICAL_TAB');
   const page=hub._live(owner,record.tab_id).page;
   const truth=await page.evaluate(({owner,marker})=>({
    memory:window.__hubMemory?.owner===owner&&window.__hubMemory?.marker===marker&&window.__hubMemory?.count===42,
    input:document.querySelector('#remember')?.value==='typed-'+owner+'-'+marker,
   }),{owner,marker:config.marker});
   if(!truth.memory||!truth.input)throw new Error('STATE_NOT_PRESERVED');
   emit('RESTORED',{owner,memory:true,input:true,exact_id:true});
  }
  for(const owner of owners){
   const closed=await hub.tabCloseOwner({owner});
   if(closed.closed!==1||closed.unconfirmed.length)throw new Error('OWNED_TAB_CLEANUP_UNCONFIRMED');
  }
  const left=JSON.parse(fs.readFileSync(ledgerFile,'utf8')).tabs;
  if(left.length!==0)throw new Error('LEDGER_NOT_CLEAN');
  emit('RESTORE_SUCCESS',{count:2,ledger_empty:true});
  success=true;
 }
}catch(error){
 emit('ERROR',{phase,code:error.code||error.name,message:String(error.message||'').slice(0,250)});
 process.exitCode=1;
}finally{
 if(phase!=='create'){
  await hub.shutdown({close_tabs:success}).catch(()=>{});
 }
}
