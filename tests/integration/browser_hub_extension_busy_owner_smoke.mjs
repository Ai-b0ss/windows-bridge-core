import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {BrowserHub,extensionConnector,backgroundChromePreflight} from '../../runtime/bridge-v3/ff_browser_hub.mjs';

// Negative live test: second manager must not steal the first manager's
// still-attached tab, even with a stale copy of its ledger.
if(!process.argv.includes('--run')){console.log('NOT_RUN: --run required');process.exit(0);}
await backgroundChromePreflight();
assert.ok(process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN,'TOKEN_REQUIRED');
const work=fs.mkdtempSync(path.join(os.tmpdir(),'ff-hub-negative-'));
const marker='ff-claimed-'+crypto.randomBytes(7).toString('hex');
const server=http.createServer((req,res)=>{res.writeHead(200,{'content-type':'text/html'});res.end('<title>'+marker+'</title><input id=keep>');});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const root=process.env.FF_PLAYWRIGHT_ROOT;
const connectorA=extensionConnector({playwrightRoot:root,background:true,clientName:'FF-Hub negative owner A'});
const connectorB=extensionConnector({playwrightRoot:root,background:true,clientName:'FF-Hub negative stale B'});
const originalLedger=path.join(work,'original.json');
const copiedLedger=path.join(work,'stale.json');
const first=new BrowserHub(connectorA,{ledgerFile:originalLedger});
let second=null,created=null,closed=false;
async function tabGroupForTarget(connection,target) {
 const seed=connection.context.pages().find(p=>{try{const u=new URL(p.url());return u.protocol==='chrome-extension:'&&u.hostname==='mmlmfjhmonkocbjadbfplnigmagldckm'&&u.pathname==='/connect.html';}catch{return false;}});
 assert.ok(seed,'NO_EXTENSION_SEED');
 return seed.evaluate(async id=>{
  const found=(await chrome.debugger.getTargets()).filter(t=>t.id===id&&Number.isSafeInteger(t.tabId));
  if(found.length!==1)return {found:found.length};
  const tab=await chrome.tabs.get(found[0].tabId);
  return {found:1,group:tab.groupId,attached:found[0].attached};
 },target);
}
let exit=1;
try{
 created=await first.tabOpen({owner:'agent-a',url:'http://127.0.0.1:'+server.address().port+'/'});
 const tab=first._live('agent-a',created.tab_id);
 const exactId=tab.target_id;
 assert.match(exactId,/^[a-fA-F0-9]{32}$/);
 await tab.page.evaluate(text=>{window.__ownedState=text;document.getElementById('keep').value=text;},marker);
 const originalGroup=await tabGroupForTarget(first.connection,exactId);
 assert.equal(originalGroup.attached,true);
 fs.copyFileSync(originalLedger,copiedLedger);
 second=new BrowserHub(connectorB,{ledgerFile:copiedLedger});
 let refused=null;
 try{await second.tabRestore({owner:'agent-a',tab_id:created.tab_id});}
 catch(error){refused=error.code||error.name;}
 assert.equal(refused,'TAB_RECOVERY_UNAVAILABLE','stale manager must not steal attached tab');
 const after=await tabGroupForTarget(first.connection,exactId);
 assert.equal(after.group,originalGroup.group,'foreign owner group must remain unchanged');
 assert.equal(after.attached,true);
 const state=await tab.page.evaluate(text=>window.__ownedState===text&&document.getElementById('keep').value===text,marker);
 assert.equal(state,true,'original owner retains working page');
 console.log(JSON.stringify({step:'BUSY_OWNER_REFUSED',error_code:refused,original_group_unchanged:true,original_page_usable:true}));
 const close=await first.tabCloseOwner({owner:'agent-a'});
 assert.equal(close.closed,1);
 closed=true;
 assert.equal(JSON.parse(fs.readFileSync(originalLedger,'utf8')).tabs.length,0);
 console.log(JSON.stringify({step:'CLEAN',closed_original:1,ledger_empty:true}));
 exit=0;
}catch(error){
 console.log(JSON.stringify({step:'FAIL',code:error.code||error.name,message:String(error.message).slice(0,220)}));
}finally{
 if(second)await second.shutdown({close_tabs:false}).catch(()=>{});
 if(!closed&&created){
  const cleanup=await first.tabCloseOwner({owner:'agent-a'}).catch(()=>null);
  closed=cleanup?.closed===1;
 }
 await first.shutdown({close_tabs:true}).catch(()=>{});
 server.close();
 if(closed)fs.rmSync(work,{recursive:true,force:true});
 else console.log(JSON.stringify({step:'CLEANUP_UNCONFIRMED',folder:work}));
 console.log(JSON.stringify({step:'FINAL',passed:exit===0&&closed,physical_close_verified:closed}));
 process.exit(exit===0&&closed?0:1);
}
