// Real, isolated Chromium fixture; no Google account, profile or credentials.
import assert from 'node:assert/strict';
import test from 'node:test';
import { BrowserSidecar } from '../runtime/bridge-v3/cua_browser_sidecar.mjs';
import { PlaywrightEngine } from '../runtime/bridge-v3/cua_browser_playwright.mjs';

const pw = await import(process.env.FF_TEST_PLAYWRIGHT_MODULE ||
  new URL('../runtime/bridge-v3/node_modules/playwright/index.mjs', import.meta.url).href);
test('ARIA links advertise and execute a guarded browser click in every discovery mode', async () => {
  const sidecar = new BrowserSidecar(new PlaywrightEngine(pw));
  const { surface_id } = await sidecar.attach({ headless: true,
    ...(process.env.FF_TEST_CHROME ? { executablePath: process.env.FF_TEST_CHROME } : {}) });
  try {
    const fixture = `<div role="link" tabindex="0" id="choice">Synthetic identity</div>
      <div role="note" id="note">Plain note</div>
      <a href="#native" id="native">Native link</a>
      <button id="button">Native button</button><p id="result">Waiting</p>
      <div role="link">Duplicate</div><div role="link">Duplicate</div>
      <script>document.querySelector('#choice').addEventListener('click',e=>{
        document.querySelector('#result').textContent=e.isTrusted?'Selected by browser input':'Untrusted';
      });</script>`;
    await sidecar.navigate(surface_id, 'data:text/html,' + encodeURIComponent(fixture));
    for (const query of [{role:'link',text:'Synthetic identity',action:'click'},
                         {text:'Synthetic identity',action:'click'}]) {
      const found = await sidecar.find(surface_id, query);
      assert.equal(found.matches.length,1,'click discovery must include div[role=link]');
      assert.equal(found.matches[0].evidence.tag,'div');
    }
    const dom = await sidecar.observe(surface_id,{mode:'dom'});
    for (const id of ['choice','native','button'])
      assert.ok(dom.entities.find(e=>e.evidence.id===id).actions.includes('click'),id);
    assert.ok(!dom.entities.find(e=>e.evidence.id==='note').actions.includes('click'));
    const note=dom.entities.find(e=>e.evidence.id==='note');
    await assert.rejects(sidecar.act(surface_id,{ref:note.ref,generation:dom.generation,
      action:'click'}),{code:'ACTION_UNSUPPORTED'});
    const found = await sidecar.find(surface_id,{role:'link',text:'Synthetic identity'});
    const chosen=found.matches[0];
    const result=await sidecar.act(surface_id,{ref:chosen.ref,generation:found.generation,
      action:'click',verify:{text:'Selected by browser input'}});
    assert.equal(result.verified,true);
    assert.equal(result.physical_input_used,false);
    // A new observation invalidates an old reference even after a working click.
    await sidecar.observe(surface_id,{mode:'dom'});
    await assert.rejects(sidecar.act(surface_id,{ref:chosen.ref,generation:found.generation,
      action:'click'}),{code:'STALE_TARGET'});
    const duplicates=await sidecar.find(surface_id,{role:'link',text:'Duplicate'});
    assert.equal(duplicates.matches.length,2);
    await assert.rejects(sidecar.act(surface_id,{ref:duplicates.matches[0].ref,
      generation:duplicates.generation,action:'click'}),{code:'TARGET_AMBIGUOUS'});
    const handle=sidecar.surfaces.get(surface_id).handle;
    handle.ownedPages.delete(handle.page);
    await assert.rejects(sidecar.observe(surface_id,{mode:'dom'}),{code:'BROWSER_PAGE_NOT_OWNED'});
    await assert.rejects(sidecar.act(surface_id,{ref:duplicates.matches[0].ref,
      generation:duplicates.generation,action:'click'}),{code:'BROWSER_PAGE_NOT_OWNED'});
    handle.ownedPages.add(handle.page);
  } finally { await sidecar.close(surface_id); }
});
