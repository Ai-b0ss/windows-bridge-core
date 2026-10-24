'use strict';
// Generic native editor API adapter, loaded only in the owned development host.
const vscode=require('vscode'),fs=require('fs'),path=require('path'),crypto=require('crypto');
let timer;
const digest=x=>crypto.createHash('sha256').update(x).digest('hex');
const canonical=x=>fs.realpathSync.native(x).toLowerCase();
function atomic(file,value){const temp=file+'.'+crypto.randomUUID()+'.tmp';const h=fs.openSync(temp,'wx');try{fs.writeFileSync(h,JSON.stringify(value));fs.fsyncSync(h);}finally{fs.closeSync(h);}fs.renameSync(temp,file);}
function activate(context){
 const root=process.env.FFBRIDGE_EDITOR_CHANNEL;
 if(!root||!path.isAbsolute(root))return;
 const owner=JSON.parse(fs.readFileSync(path.join(root,'owner.json'),'utf8'));
 if(owner.protocol!==1||!/^[a-f0-9]{32}$/.test(owner.nonce))throw Error('EDITOR_CHANNEL_OWNER_INVALID');
 const document=canonical(owner.document);
 atomic(path.join(root,'ready.json'),{protocol:1,nonce:owner.nonce,pid:process.pid,vscode_version:vscode.version});
 const done=new Set();let busy=false;
 const fail=code=>{throw Object.assign(Error(code),{code});};
 async function dispatch(q,flight){
  if(q.nonce!==owner.nonce)fail('EDITOR_CHANNEL_NONCE_MISMATCH');
  const editor=vscode.window.activeTextEditor;
  if(!editor||editor.document.isClosed||editor.document.uri.scheme!=='file')fail('EDITOR_ACTIVE_DOCUMENT_UNAVAILABLE');
  const doc=editor.document;
  if(canonical(doc.uri.fsPath)!==document||canonical(q.document)!==document)fail('EDITOR_DOCUMENT_IDENTITY_MISMATCH');
  if(doc.getText().length>65536)fail('EDITOR_TEXT_LIMIT');
  const view=()=>({path:doc.uri.fsPath,uri:doc.uri.toString(),version:doc.version,text:doc.getText(),dirty:doc.isDirty,language:doc.languageId,file_sha256:digest(fs.readFileSync(doc.uri.fsPath))});
  if(q.command==='observe')return {ok:true,attempted:false,document:view()};
  if(q.command!=='replace_save')fail('EDITOR_COMMAND_UNSUPPORTED');
  if(!Number.isInteger(q.expected_version)||doc.version!==q.expected_version||doc.getText()!==q.expected_text)fail('EDITOR_EXPECTED_STATE_CHANGED');
  if(q.expected_file_sha256!==digest(fs.readFileSync(doc.uri.fsPath)))fail('EDITOR_FILE_STATE_CHANGED');
  if(typeof q.text!=='string'||q.text.length>65536)fail('EDITOR_TEXT_LIMIT');
  const before=view();
  // One version-checked native edit; no typing, clipboard, host focus or generic code execution.
  flight.attempted=true;
  const edited=await editor.edit(builder=>builder.replace(new vscode.Range(doc.positionAt(0),doc.positionAt(doc.getText().length)),q.text),{undoStopBefore:true,undoStopAfter:true});
  if(!edited||doc.getText()!==q.text)fail('EDITOR_NATIVE_EDIT_UNVERIFIED');
  if(canonical(doc.uri.fsPath)!==document)fail('EDITOR_DOCUMENT_CHANGED_AFTER_EDIT');
  if(q.expected_file_sha256!==digest(fs.readFileSync(doc.uri.fsPath)))fail('EDITOR_FILE_CHANGED_AFTER_EDIT');
  if(!await doc.save()||doc.isDirty||doc.getText()!==q.text)fail('EDITOR_NATIVE_SAVE_UNVERIFIED');
  return {ok:true,attempted:true,native_editor_edit:true,native_document_save:true,before,document:view(),saved_sha256:digest(fs.readFileSync(doc.uri.fsPath))};
 }
 timer=setInterval(async()=>{
  if(busy)return;busy=true;
  try{
   for(const name of fs.readdirSync(root).filter(x=>/^[a-f0-9]{32}\.request\.json$/.test(x))){
    const id=name.slice(0,32);if(done.has(id))continue;
    const input=path.join(root,name),result=path.join(root,id+'.result.json'),claim=path.join(root,id+'.claim.json');
    const bytes=fs.readFileSync(input);if(bytes.length>262144){done.add(id);continue;}
    const fingerprint=digest(bytes);
    if(fs.existsSync(result)){done.add(id);continue;}
    if(fs.existsSync(claim)){atomic(result,{id,fingerprint,pid:process.pid,ok:false,error_code:'EDITOR_OUTCOME_UNKNOWN',attempted:true,retry_safe:false});done.add(id);continue;}
    atomic(claim,{id,fingerprint,state:'dispatching'});
    let q,reply;const flight={attempted:false};
    try{q=JSON.parse(bytes);reply=await dispatch(q,flight);}
    catch(e){reply={ok:false,error_code:e.code||'EDITOR_NATIVE_REQUEST_FAILED',attempted:flight.attempted,retry_safe:!flight.attempted};}
    atomic(result,{...reply,id,fingerprint,pid:process.pid});done.add(id);
   }
  }finally{busy=false;}
 },100);
 context.subscriptions.push({dispose(){clearInterval(timer);timer=null;}});
}
function deactivate(){if(timer)clearInterval(timer);}
module.exports={activate,deactivate};
