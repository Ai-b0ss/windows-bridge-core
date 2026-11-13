import assert from 'node:assert/strict';
import { PlaywrightEngine } from './cua_browser_playwright.mjs';

const engine=new PlaywrightEngine({});
engine._assertOwned=()=>{};
const mainUrl='http://127.0.0.1:8772/case/05';
const expectedUrl='http://127.0.0.1:8772/result/05';
const main={url:()=>mainUrl};
const page={url:()=>mainUrl,mainFrame:()=>main};
const checks=[];
async function check(name,holder,frame,expected,verified,scope=null){
  const result=await engine.verify(holder,{url:expected},{action:'click',resolved:{frame}});
  assert.equal(result.verified,verified,name);
  if(scope!==null)assert.equal(result.verification_scope,scope,name+' scope');
  checks.push(name);
  console.log(JSON.stringify({name,verified:result.verified,scope:result.verification_scope}));
}
await check('main frame exact URL',{page},main,mainUrl,true,'main_page');
const childAtResult={url:()=>expectedUrl,isDetached:()=>false};
await check('child frame exact URL',{page},childAtResult,expectedUrl,true,'target_frame');
await check('wrong URL rejected',{page},childAtResult,'http://127.0.0.1:8772/wrong',false);
const unrelated={url:()=>expectedUrl,isDetached:()=>false};
const notNavigated={url:()=> 'http://127.0.0.1:8772/frame/05',isDetached:()=>false};
await check('unrelated sibling URL is not evidence',{page:{...page,frames:()=>[main,notNavigated,unrelated]}},
  notNavigated,expectedUrl,false);
const detached={url:()=>expectedUrl,isDetached:()=>true};
await check('detached child URL is not evidence',{page},detached,expectedUrl,false);

let childUrl='http://127.0.0.1:8772/frame/05';
const asyncChild={url:()=>childUrl,isDetached:()=>false,
  async waitForURL(target){childUrl=target;}};
await check('asynchronous iframe commit observed',{page},asyncChild,expectedUrl,true,'target_frame');

let updatedMain=mainUrl;
const asyncPage={url:()=>updatedMain,mainFrame:()=>main,
  async waitForURL(target){updatedMain=target;}};
const childNoChange={url:()=> 'http://127.0.0.1:8772/frame/05',isDetached:()=>false,
  async waitForURL(){throw new Error('iframe did not navigate');}};
await check('child link may navigate the main page',{page:asyncPage},
  childNoChange,expectedUrl,true,'main_page');
const failPage={url:()=>mainUrl,mainFrame:()=>main,
  async waitForURL(){throw new Error('timeout');}};
const failChild={url:()=> 'http://127.0.0.1:8772/frame/05',isDetached:()=>false,
  async waitForURL(){throw new Error('timeout');}};
await check('failed asynchronous waits remain unverified',{page:failPage},failChild,expectedUrl,false);
console.log(JSON.stringify({status:'PASS',total:checks.length}));
