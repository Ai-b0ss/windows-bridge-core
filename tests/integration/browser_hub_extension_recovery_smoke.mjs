import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import {BrowserHub,extensionConnector,backgroundChromePreflight} from '../../runtime/bridge-v3/ff_browser_hub.mjs';

// Destructive only to ONE newly-created, owned test tab. Never touches other tabs.
if (!process.argv.includes('--run')) {
 console.log('NOT_RUN: require --run');
 process.exit(0);
}
await backgroundChromePreflight();
if(!process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN)throw new Error('NO_EXTENSION_TOKEN');
const work=fs.mkdtempSync(path.join(os.tmpdir(),'ff-hub-relay-resume-'));
const marker='ff-owned-'+Math.random().toString(36).slice(2);
const html='<!doctype html><title>'+marker+'</title><input id=held><div id=only-owner>'+marker+'</div>';
const server=http.createServer((req,res)=>{res.setHeader('content-type','text/html');res.end(html);});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const url='http://127.0.0.1:'+server.address().port+'/';
const connector=extensionConnector({playwrightRoot:process.env.FF_PLAYWRIGHT_ROOT,background:true,clientName:'FF-Hub relay recovery TEST'});
const hub=new BrowserHub(connector,{ledgerFile:path.join(work,'owned-tabs.json')});
const owner='ff-hub-owned-smoke';
let tabid=null,original=null,physicalClosed=false;
function log(step,props={}){console.log(JSON.stringify({step,...props}));}
async function emergencyExactCleanup(){
 if(!original)return false;
 try{
  const conn=await hub._ensureConnected();
  const seed=conn.context.pages().find(p=>{try{const x=new URL(p.url());return x.protocol==='chrome-extension:'&&x.hostname==='mmlmfjhmonkocbjadbfplnigmagldckm'&&x.pathname==='/connect.html';}catch{return false;}});
  if(!seed)return false;
  const result=await seed.evaluate(async ({wanted,title})=>{
   if(chrome.runtime?.id!=='mmlmfjhmonkocbjadbfplnigmagldckm')return 'NOT_EXTENSION';
   const matches=(await chrome.debugger.getTargets()).filter(t=>t.id===wanted && t.type==='page' && Number.isSafeInteger(t.tabId));
   if(matches.length!==1)return 'TARGET_NOT_FOUND_OR_AMBIGUOUS';
   const tab=await chrome.tabs.get(matches[0].tabId);
   if(tab.title!==title||!tab.url?.startsWith('http://127.0.0.1:'))return 'UNEXPECTED_TARGET_CONTENT';
   const status=await chrome.runtime.sendMessage({type:'getConnectionStatus'});
   if(status.connections?.some(c=>c.connectedTabIds?.includes(tab.id)))return 'TARGET_BUSY';
   await chrome.tabs.remove(tab.id);
   return 'CLOSED_EXACT_OWNED_TARGET';
  },{wanted:original,title:marker});
  log('EMERGENCY_CLEANUP',{result});
  return result==='CLOSED_EXACT_OWNED_TARGET';
 }catch(error){log('EMERGENCY_CLEANUP_ERROR',{code:error.code||error.name,message:String(error.message||'').slice(0,120)});return false;}
}
let resultCode=1;
try{
 const opened=await hub.tabOpen({owner,url});
 tabid=opened.tab_id;
 const held=hub._live(owner,tabid);
 original=held.target_id;
 if(!original)throw new Error('NO_EXACT_TARGET_ID');
 await held.page.evaluate((text)=>{
  globalThis.__ffMemory={unique:text,count:42};
  document.getElementById('held').value='typed-'+text;
 },marker);
 const ledger=JSON.parse(fs.readFileSync(path.join(work,'owned-tabs.json'),'utf8'));
 if(ledger.tabs?.length!==1||ledger.tabs[0].target_id!==original)throw new Error('IDENTITY_NOT_DURABLE');
 log('OPENED',{durable:true,ledger_entries:1});
 await hub.connection.browser.close();
 await new Promise(resolve=>setTimeout(resolve,450));
 if(hub.tabList({owner}).tabs[0]?.state!=='lost')throw new Error('DID_NOT_RECORD_LOSS');
 log('DISCONNECTED',{ownerChromeRemainsOpen:true});
 const restored=await hub.tabRestore({owner,tab_id:tabid});
 const same=restored.reattached===true && restored.evidence==='cdp_target_id' && restored.page_state_preserved===true && restored.tab_id===tabid;
 const page=hub._live(owner,tabid).page;
 const proof=await page.evaluate(text=>({
  memory:globalThis.__ffMemory?.unique===text && globalThis.__ffMemory?.count===42,
  input:document.getElementById('held')?.value==='typed-'+text
 }),marker);
 log('RECOVERED',{same_physical_page:same,js_state_preserved:proof.memory,input_preserved:proof.input});
 if(!same||!proof.memory||!proof.input)throw new Error('REATTACH_VERIFICATION_FAILED');
 const cleanup=await hub.tabCloseOwner({owner});
 physicalClosed=cleanup.closed===1 && cleanup.unconfirmed?.length===0;
 const finalLedger=JSON.parse(fs.readFileSync(path.join(work,'owned-tabs.json'),'utf8'));
 if(!physicalClosed||finalLedger.tabs.length!==0)throw new Error('CLEANUP_NOT_VERIFIED');
 log('CLEANUP',{physically_closed:true,ledger_empty:true});
 resultCode=0;
}catch(error){log('FAIL',{code:error.code||error.name,message:String(error.message||'').slice(0,260),details:error.details||{}});}
finally{
 if(original&&!physicalClosed){
  try{
   const cleanup=await hub.tabCloseOwner({owner});
   physicalClosed=cleanup.closed===1 && cleanup.unconfirmed.length===0;
   log('NORMAL_CLEANUP_AFTER_FAILURE',{physically_closed:physicalClosed});
  }catch{}
  if(!physicalClosed)physicalClosed=await emergencyExactCleanup();
 }
 await hub.shutdown({close_tabs:true}).catch(()=>{});
 server.close();
 log('RESULT',{passed:resultCode===0 && physicalClosed,physicalClosed});
 fs.rmSync(work,{recursive:true,force:true});
 process.exit(resultCode===0&&physicalClosed?0:1);
}
