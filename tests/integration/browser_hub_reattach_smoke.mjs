// Real crash recovery of physical tabs: real BrowserHub process, real hard kill, real Chromium
// page handles. The browser is a disposable headless Chromium with its own temporary profile.
// The owner's Chrome, profile, extension token and the installed runtime are never used.
//
//   node tests/integration/browser_hub_reattach_smoke.mjs [--require]
//
// Without a Playwright runtime or a bundled headless Chromium the result is NOT_RUN (exit 0,
// or exit 3 with --require). The transport is plain CDP: this proves the ledger and target-id
// mechanism, not the owner's extension relay.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '..', '..');
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const finish = (status, extra = {}, exitCode = 0) => { console.log(JSON.stringify({status, ...extra})); process.exitCode = exitCode; };
const notRun = reason => finish('NOT_RUN', {reason}, process.argv.includes('--require') ? 3 : 0);

function findRuntime() {
  for (const root of [process.env.FF_PLAYWRIGHT_ROOT, path.join(repo, 'runtime', 'bridge-v3')].filter(Boolean)) {
    try { return {root, playwright: createRequire(path.join(root, 'package.json'))('playwright-core')}; } catch {}
  }
  return null;
}

function findChromium(playwright) {
  const candidates = [process.env.FF_TEST_CHROMIUM];
  const cache = process.env.PLAYWRIGHT_BROWSERS_PATH || (process.platform === 'win32'
    ? path.join(process.env.LOCALAPPDATA || '', 'ms-playwright') : path.join(os.homedir(), '.cache', 'ms-playwright'));
  try {
    const builds = fs.readdirSync(cache).filter(name => /^chromium(_headless_shell)?-\d+$/.test(name)).sort().reverse();
    for (const entry of [...builds.filter(name => name.includes('headless')), ...builds.filter(name => !name.includes('headless'))])
      for (const inner of fs.readdirSync(path.join(cache, entry)))
        for (const name of ['chrome-headless-shell.exe', 'headless_shell.exe', 'chrome.exe', 'chrome-headless-shell', 'headless_shell', 'chrome'])
          candidates.push(path.join(cache, entry, inner, name));
  } catch {}
  try { candidates.push(playwright.chromium.executablePath()); } catch {}
  // Only a bundled test browser is acceptable; an installed Chrome is never selected here.
  return candidates.find(file => file && fs.existsSync(file) && fs.statSync(file).isFile()) || null;
}

const getJson = (port, route, method = 'GET') => new Promise((resolve, reject) => {
  const request = http.request({host: '127.0.0.1', port, path: route, method}, response => {
    const chunks = [];
    response.on('data', chunk => chunks.push(chunk));
    response.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); try { resolve(JSON.parse(text)); } catch { resolve(text); } });
  });
  request.on('error', reject);
  request.setTimeout(15000, () => request.destroy(new Error(`TIMEOUT ${route.split('?')[0]}`)));
  request.end();
});

function rpc(port, key, op, args = {}) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify({op, args}));
    const request = http.request({host: '127.0.0.1', port, path: '/rpc', method: 'POST',
      headers: {'content-type': 'application/json', 'content-length': body.length, 'x-ff-browser-key': key}}, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))));
    });
    request.on('error', reject);
    request.setTimeout(60000, () => request.destroy(new Error(`TIMEOUT rpc ${op}`)));
    request.end(body);
  });
}

async function waitFile(file, alive) {
  for (let i = 0; i < 400; i++) {
    if (fs.existsSync(file)) { const text = fs.readFileSync(file, 'utf8'); if (text.trim()) return text; }
    if (!alive()) break;
    await sleep(50);
  }
  throw new Error(`TIMEOUT_WAITING_FOR_${path.basename(file)}`);
}

async function main() {
  const runtime = findRuntime();
  if (!runtime) return notRun('PLAYWRIGHT_RUNTIME_UNAVAILABLE');
  const executable = findChromium(runtime.playwright);
  if (!executable) return notRun('BUNDLED_HEADLESS_CHROMIUM_UNAVAILABLE');

  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ff-hub-reattach-'));
  const children = [];
  const site = http.createServer((request, response) => {
    response.writeHead(200, {'content-type': 'text/html'});
    response.end('<!doctype html><title>ff reattach</title><input id="field"><p>page</p>');
  });
  await new Promise(resolve => site.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${site.address().port}/page`;
  try {
    const profile = path.join(work, 'profile');
    const chromium = spawn(executable, ['--headless', '--remote-debugging-port=0', `--user-data-dir=${profile}`,
      '--no-first-run', '--no-default-browser-check', '--disable-gpu', 'about:blank'],
      {stdio: ['ignore', 'ignore', fs.openSync(path.join(work, 'chromium.log'), 'w')], windowsHide: true});
    children.push(chromium);
    let cdpPort;
    try { cdpPort = Number((await waitFile(path.join(profile, 'DevToolsActivePort'), () => chromium.exitCode === null)).split('\n')[0]); }
    catch (error) {
      const tail = fs.readFileSync(path.join(work, 'chromium.log'), 'utf8').trim().split('\n').slice(-3).join(' | ').slice(0, 400);
      throw new Error(`${error.message}; browser=${path.basename(executable)} exit=${chromium.exitCode} log=${tail}`);
    }
    const pages = async () => (await getJson(cdpPort, '/json/list')).filter(target => target.type === 'page');
    const baseline = (await pages()).map(target => target.id);

    const ledger = path.join(work, 'tab-ledger.json');
    const startHub = async name => {
      const key = crypto.randomBytes(32).toString('hex');
      const endpoint = path.join(work, `${name}.json`);
      const child = spawn(process.execPath, [path.join(here, 'browser_hub_reattach_fixture.mjs'), endpoint, ledger, String(cdpPort), runtime.root],
        {stdio: ['ignore', 'ignore', 'inherit'], windowsHide: true, env: {...process.env, FF_BROWSER_HUB_KEY: key}});
      children.push(child);
      const port = JSON.parse(await waitFile(endpoint, () => child.exitCode === null)).port;
      const call = async (op, args) => { const reply = await rpc(port, key, op, args); if (!reply.ok) throw Object.assign(new Error(reply.error_code), reply); return reply.result; };
      const denied = async (code, op, args) => { const reply = await rpc(port, key, op, args); assert.equal(reply.ok, false, `${op} must fail`); assert.equal(reply.error_code, code); return reply; };
      return {child, call, denied};
    };

    // ---- before the crash -------------------------------------------------------------
    const first = await startHub('hub-a');
    const a1 = await first.call('tab_open', {owner: 'agent-a', url});
    const a2 = await first.call('tab_open', {owner: 'agent-a', url});
    const b1 = await first.call('tab_open', {owner: 'agent-b', url});
    assert.equal(a1.durable_identity, true);
    const marker = crypto.randomBytes(8).toString('hex');
    await first.call('evaluate', {owner: 'agent-a', tab_id: a1.tab_id, expression: `window.__ff_marker = '${marker}'; document.querySelector('#field').value = 'typed-${marker}'; true`});
    const recorded = Object.fromEntries(JSON.parse(fs.readFileSync(ledger, 'utf8')).tabs.map(tab => [tab.tab_id, tab]));
    assert.equal(Object.keys(recorded).length, 3);

    // ---- hard crash of the manager; the browser and its tabs stay --------------------
    first.child.kill('SIGKILL');
    await Promise.race([new Promise(resolve => first.child.once('exit', resolve)), sleep(5000)]);
    assert.notEqual(first.child.exitCode ?? first.child.signalCode, null, 'the first manager is gone');
    // A foreign page at the same address: it must never be adopted in place of a lost tab.
    const foreign = await getJson(cdpPort, `/json/new?${url}`, 'PUT');
    // One recorded tab disappears while the manager is down.
    await getJson(cdpPort, `/json/close/${recorded[a2.tab_id].target_id}`);
    for (let i = 0; i < 100 && (await pages()).some(target => target.id === recorded[a2.tab_id].target_id); i++) await sleep(50);

    // ---- a new manager process with the same ledger -----------------------------------
    const second = await startHub('hub-b');
    const listed = (await second.call('tab_list', {owner: 'agent-a'})).tabs;
    assert.deepEqual(listed.map(tab => tab.state), ['lost', 'lost']);
    assert.ok(listed.every(tab => tab.orphaned === true));
    await second.denied('TAB_LOST', 'read', {owner: 'agent-a', tab_id: a1.tab_id});
    await second.denied('TAB_NOT_OWNED', 'tab_restore', {owner: 'agent-b', tab_id: a1.tab_id});
    await second.denied('TAB_NOT_OWNED', 'tab_close', {owner: 'agent-b', tab_id: a1.tab_id});

    const restored = await second.call('tab_restore', {owner: 'agent-a', tab_id: a1.tab_id});
    assert.equal(restored.tab_id, a1.tab_id);
    assert.equal(restored.reattached, true);
    assert.equal(restored.page_state_preserved, true);
    const state = await second.call('evaluate', {owner: 'agent-a', tab_id: a1.tab_id,
      expression: `[window.__ff_marker, document.querySelector('#field').value]`});
    assert.deepEqual(state.value, [marker, `typed-${marker}`], 'JS state and unsaved input of the same physical tab');

    const before = (await pages()).length;
    const refused = await second.denied('TAB_RECOVERY_UNAVAILABLE', 'tab_restore', {owner: 'agent-a', tab_id: a2.tab_id});
    assert.equal(refused.details.automatic_replay, false);
    assert.equal((await pages()).length, before, 'no duplicate was opened for the missing tab');
    const gone = await second.call('tab_close', {owner: 'agent-a', tab_id: a2.tab_id});
    assert.equal(gone.page_closed_in_browser, true);
    assert.equal(gone.evidence, 'target_absent_in_browser');

    const closedA = await second.call('tab_close', {owner: 'agent-a', tab_id: a1.tab_id});
    assert.equal(closedA.page_closed_in_browser, true);
    const closedB = await second.call('tab_close_owner', {owner: 'agent-b', forget_unconfirmed: true});
    assert.equal(closedB.closed, 1);
    assert.deepEqual(closedB.unconfirmed, []);
    assert.equal(closedB.tabs[0].reattached, true);
    assert.equal(closedB.tabs[0].tab_id, b1.tab_id);

    const remaining = (await pages()).map(target => target.id).sort();
    assert.deepEqual(remaining, [...baseline, foreign.id].sort(), 'only pages the hub never owned remain, untouched');
    assert.deepEqual(JSON.parse(fs.readFileSync(ledger, 'utf8')).tabs, []);
    finish('PASS', {real_manager_hard_kill: true, real_chromium_page_handles: true, transport: 'cdp-isolated-test-browser',
      owner_chrome_used: false, reattached_by_target_id: 2, js_state_preserved: true, foreign_same_url_page_untouched: true,
      missing_tab_not_reopened: true, closure_proven_by_target_absence: true, ledger_empty_after_cleanup: true});
  } finally {
    for (const child of children)
      if (child.exitCode === null && child.signalCode === null) {
        child.kill('SIGKILL');
        await Promise.race([new Promise(resolve => child.once('exit', resolve)), sleep(5000)]);
      }
    site.close();
    site.closeAllConnections?.();
    for (let i = 0; i < 20; i++) { try { fs.rmSync(work, {recursive: true, force: true}); break; } catch { await sleep(200); } }
  }
}

const watchdog = setTimeout(() => { finish('FAIL', {error: 'SMOKE_WATCHDOG_TIMEOUT'}, 1); process.exit(1); }, 150000);
main().catch(error => { finish('FAIL', {error: String(error?.message || error).split('\n')[0]}, 1); })
  .finally(() => clearTimeout(watchdog));
