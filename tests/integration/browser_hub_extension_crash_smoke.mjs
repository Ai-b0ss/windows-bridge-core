import {spawn} from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

// An isolated crash test of two newly-created, owned tabs; no other Chrome tab
// is ever selected, manipulated or closed.
if(!process.argv.includes('--run')){console.log('NOT_RUN: --run required');process.exit(0);}
if(!process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN)throw new Error('TOKEN_REQUIRED');
const work=fs.mkdtempSync(path.join(os.tmpdir(),'ff-hub-hard-crash-'));
const marker='ff-hub-owned-'+crypto.randomBytes(7).toString('hex');
const html='<!doctype html><title>'+marker+'</title><input id=remember><div>'+marker+'</div>';
const server=http.createServer((req,res)=>{res.writeHead(200,{'content-type':'text/html; charset=utf-8'});res.end(html);});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
const config={base:'http://127.0.0.1:'+server.address().port+'/',marker};
fs.writeFileSync(path.join(work,'config.json'),JSON.stringify(config));
const fixture=path.join(path.dirname(fileURLToPath(import.meta.url)),'browser_hub_extension_crash_fixture.mjs');
const env={...process.env,FF_HUB_CRASH_WORKDIR:work};
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const send=(step,data={})=>console.log(JSON.stringify({step,...data}));
function spawnFixture(phase){
 const child=spawn(process.execPath,[fixture,phase],{env,stdio:['ignore','pipe','pipe'],windowsHide:true});
 child._messages=[];
 child._exit=new Promise((resolve,reject)=>{child.once('exit',(code,signal)=>resolve({code,signal}));child.once('error',reject);});
 let buffer='';
 child.stdout.setEncoding('utf8');
 child.stdout.on('data',data=>{
  buffer+=data;
  while(buffer.includes('\n')){
   const index=buffer.indexOf('\n');
   const line=buffer.slice(0,index).trim();buffer=buffer.slice(index+1);
   try{
    const item=JSON.parse(line);child._messages.push(item);
    send('FIXTURE_'+phase.toUpperCase(),item);
   }catch{ if(line) send('UNEXPECTED_CHILD_OUTPUT',{phase,length:line.length}); }
  }
 });
 let stderrBytes=0;
 child.stderr.on('data',chunk=>{stderrBytes+=chunk.length;});
 child._stderrBytes=()=>stderrBytes;
 return child;
}
function exitWithin(child,timeoutMs){
 return Promise.race([
  child._exit,
  new Promise((_,reject)=>setTimeout(()=>{
   child.kill('SIGKILL');reject(new Error('PHASE_TIMEOUT_'+timeoutMs));
  },timeoutMs))
 ]);
}
function readyWithin(child,timeoutMs){
 return new Promise((resolve,reject)=>{
  const deadline=Date.now()+timeoutMs;
  const poll=()=>{
   if(child._messages.some(x=>x.step==='READY'))return resolve(true);
   if(child.exitCode!==null||child.signalCode!==null)return reject(new Error('CREATOR_EXITED_BEFORE_READY'));
   if(Date.now()>deadline)return reject(new Error('CREATOR_READY_TIMEOUT'));
   setTimeout(poll,75);
  };poll();
 });
}
const fgLog=path.join(work,'foreground.log');
const fd=fs.openSync(fgLog,'w');
const fgScript=[
  "Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class FGHub { [DllImport(\"user32.dll\")] public static extern IntPtr GetForegroundWindow(); }'",
  '$last=[IntPtr]::Zero',
  "while($true){$h=[FGHub]::GetForegroundWindow();if($h -ne $last){Write-Output ('hwnd='+$h);$last=$h}; Start-Sleep -Milliseconds 35}"
].join('\n');
const sampler=spawn('powershell.exe',['-NoProfile','-NonInteractive','-Command',fgScript],{stdio:['ignore',fd,'ignore'],windowsHide:true});
fs.closeSync(fd);
let creator=null,restorer=null,cleaner=null,passed=false,cleaned=false;
try{
 const deadline=Date.now()+15000;
 while((!fs.existsSync(fgLog)||!fs.statSync(fgLog).size)&&Date.now()<deadline)await sleep(90);
 if(!fs.statSync(fgLog).size)throw new Error('FOREGROUND_MONITOR_NO_BASELINE');
 creator=spawnFixture('create');
 await readyWithin(creator,35000);
 send('CREATOR_READY',{owned_tabs:2});
 await sleep(250);
 if(!creator.kill('SIGKILL'))throw new Error('FAILED_TO_KILL_OWN_CREATOR');
 const death=await exitWithin(creator,6000);
 send('HARD_KILL',{creator_code:death.code,signal:death.signal||null});
 if(death.code===0)throw new Error('CREATOR_EXITED_NORMALLY');
 await sleep(750);
 restorer=spawnFixture('restore');
 const restored=await exitWithin(restorer,45000);
 if(restored.code!==0 || !restorer._messages.some(x=>x.step==='RESTORE_SUCCESS'))
  throw new Error('RESTORER_FAILED_'+restored.code);
 cleaned=true;passed=true;
 send('RECOVERY',{process_restarted:true,same_pages:2,js_and_input_preserved:true});
}catch(error){
 send('TEST_ERROR',{code:error.name||'ERROR',message:String(error.message||error).slice(0,230)});
}finally{
 for(const child of [creator,restorer]){
  if(child&&child.exitCode===null&&child.signalCode===null)child.kill('SIGKILL');
 }
 if(!cleaned) {
  cleaner=spawnFixture('cleanup');
  try{
   const result=await exitWithin(cleaner,25000);
   cleaned=result.code===0&&cleaner._messages.some(x=>x.step==='CLEANUP_SUCCESS');
   send('FALLBACK_CLEANUP',{successful:cleaned});
  }catch(error){send('FALLBACK_CLEANUP',{successful:false,reason:String(error.message).slice(0,120)});}
 }
 server.close();
 sampler.kill();
 await sleep(350);
 const lines=fs.existsSync(fgLog)?fs.readFileSync(fgLog,'utf8').trim().split(/\r?\n/).filter(Boolean):[];
 const zeroFocusChange=lines.length===1;
 send('FOREGROUND',{observations:lines.length,zero_focus_changes:zeroFocusChange});
 const accepted=passed&&cleaned&&zeroFocusChange;
 send('FINAL',{passed:accepted,manager_hard_killed:true,cleanup_proven:cleaned,restore_proven:passed});
 if(cleaned)fs.rmSync(work,{recursive:true,force:true});
 else send('RECOVERY_EVIDENCE_RETAINED',{working_folder:work});
 process.exit(accepted?0:1);
}
