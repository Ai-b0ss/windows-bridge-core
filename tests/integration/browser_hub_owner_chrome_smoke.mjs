// REAL owner-Chrome smoke for the FF Browser Session Manager.
//
// Run through the launcher so the token never leaves DPAPI:
//   powershell -File tests/integration/run_with_extension_token.ps1 -Script tests/integration/browser_hub_owner_chrome_smoke.mjs
//
// It opens only its own background tabs against a loopback page, never touches the owner's
// tabs, and closes everything it opened. It records every foreground-window change.
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const {BrowserHub, backgroundChromePreflight, extensionConnector} = await import('file://' + path.join(repo, 'runtime/bridge-v3/ff_browser_hub.mjs').replace(/\\/g, '/'));
const playwrightRoot = process.env.FF_PLAYWRIGHT_ROOT || path.join(repo, 'runtime/bridge-v3');
let connector;
try {
  // Fail before opening a connection or unsealing anything when upstream cannot guarantee
  // that the connect page itself remains in the background.
  await backgroundChromePreflight();
  if (!process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN) throw {code: 'EXTENSION_TOKEN_UNAVAILABLE'};
  connector = extensionConnector({playwrightRoot, background: true});
} catch (error) {
  console.log(JSON.stringify({status: 'NOT_RUN', reason: error.code || 'BACKGROUND_PREFLIGHT_UNAVAILABLE'}));
  process.exit(0);
}
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'ff-browser-hub-smoke-'));
const checks = [];
const check = (name, ok, extra = '') => { checks.push({name, ok: Boolean(ok)}); console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${extra ? ' :: ' + extra : ''}`); };

const page = `<!doctype html><title>ff-hub-smoke</title><h1>Agent page</h1>
<button id=add onclick="count.textContent=+count.textContent+1">Add one</button> <output id=count>0</output>
<form onsubmit="event.preventDefault();sent.textContent='sent:'+who.value"><input id=who aria-label="Who"><button>Send</button></form>
<output id=sent></output><select aria-label="Pick"><option>red<option>green</select>
<label><input type=checkbox aria-label="Agree">Agree</label>
<a href="/second">Second page</a>`;
const server = http.createServer((request, response) => {
  response.setHeader('content-type', 'text/html; charset=utf-8');
  response.end(request.url === '/second' ? '<title>second</title><h1>Second page reached</h1>' : page);
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${server.address().port}`;

// Foreground sampler: every change of the foreground window, with the owning process.
const foregroundLog = path.join(work, 'foreground.log');
const foregroundFd = fs.openSync(foregroundLog, 'w');
const sampler = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', `
Add-Type @"
using System; using System.Runtime.InteropServices;
public class FG { [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid); }
"@
$last = [IntPtr]::Zero
while ($true) { $h = [FG]::GetForegroundWindow()
  if ($h -ne $last) { $p = 0; [void][FG]::GetWindowThreadProcessId($h, [ref]$p); $n = (Get-Process -Id $p -ErrorAction SilentlyContinue).ProcessName
    "$([DateTime]::Now.ToString('HH:mm:ss.fff')) hwnd=$h pid=$p process=$n"; $last = $h }
  Start-Sleep -Milliseconds 25 }`], {stdio: ['ignore', foregroundFd, 'ignore'], windowsHide: true});
fs.closeSync(foregroundFd);
const samplerDone = new Promise(resolve => { sampler.once('exit', resolve); sampler.once('error', resolve); });

const ledgerFile = path.join(work, 'tab-ledger.json');
const hub = new BrowserHub(connector, {artifactDir: path.join(work, 'shots'), ledgerFile});
const code = async promise => { try { await promise; return 'NO_ERROR'; } catch (error) { return error.code || String(error); } };
let exitCode = 1;
try {
  const baselineDeadline = Date.now() + 15000;
  while (!fs.statSync(foregroundLog).size && sampler.exitCode === null && Date.now() < baselineDeadline)
    await new Promise(resolve => setTimeout(resolve, 100));
  if (!fs.statSync(foregroundLog).size) throw {code: 'FOREGROUND_SAMPLER_UNAVAILABLE', message: 'no baseline was recorded'};
  const started = Date.now();
  const status = await hub.connect();
  check('connects to the owner Chrome without a prompt', status.connected && status.route.isolated_profile === false, `${Date.now() - started} ms, ${JSON.stringify(status.route)}`);

  // Three agents work at the same time, each in its own tab.
  const agents = ['agent-a', 'agent-b', 'agent-c'];
  const parallelStart = Date.now();
  const results = await Promise.all(agents.map(async (owner, index) => {
    const tab = await hub.tabOpen({owner, url: base + '/'});
    for (let i = 0; i <= index; i++) await hub.act({owner, tab_id: tab.tab_id, action: 'click', target: {role: 'button', name: 'Add one'}});
    await hub.act({owner, tab_id: tab.tab_id, action: 'fill', target: {label: 'Who'}, value: owner,
      postcondition: {target: {label: 'Who'}, value: owner}});
    const text = (await hub.read({owner, tab_id: tab.tab_id, target: {selector: '#count'}})).text;
    const snap = await hub.snapshot({owner, tab_id: tab.tab_id});
    return {owner, tab, count: text, visibility: snap.visibility, snapshot: snap.snapshot};
  }));
  check('three agents ran in parallel in separate tabs', results.every((r, i) => r.count === String(i + 1)), `${Date.now() - parallelStart} ms, counts=${results.map(r => r.count)}`);
  check('agent tabs stayed hidden from the owner', results.every(r => r.visibility === 'hidden'), results.map(r => r.visibility).join(','));
  check('aria snapshot carries element refs', /\[ref=/.test(results[0].snapshot));

  const [a, b] = results;
  check('agent B cannot read agent A tab', (await code(hub.read({owner: 'agent-b', tab_id: a.tab.tab_id}))) === 'TAB_NOT_OWNED');
  check('agent B cannot act in agent A tab', (await code(hub.act({owner: 'agent-b', tab_id: a.tab.tab_id, action: 'click', target: {selector: '#add'}}))) === 'TAB_NOT_OWNED');
  check('agent B cannot close agent A tab', (await code(hub.tabClose({owner: 'agent-b', tab_id: a.tab.tab_id}))) === 'TAB_NOT_OWNED');
  check('agent A tab untouched by the attempts', (await hub.read({owner: 'agent-a', tab_id: a.tab.tab_id, target: {selector: '#count'}})).text === '1');
  check('tab list is per owner', hub.tabList({owner: 'agent-b'}).tabs.length === 1 && hub.tabList({owner: 'agent-b'}).tabs[0].tab_id === b.tab.tab_id);

  // Ref-based action, select, checkbox, form submit by Enter, link navigation; all verified.
  const snap = await hub.snapshot({owner: 'agent-a', tab_id: a.tab.tab_id});
  const ref = /button "Add one" \[ref=([A-Za-z0-9]+)\]/.exec(snap.snapshot)?.[1];
  await hub.act({owner: 'agent-a', tab_id: a.tab.tab_id, action: 'click', target: {ref}});
  check('click by snapshot ref', (await hub.read({owner: 'agent-a', tab_id: a.tab.tab_id, target: {selector: '#count'}})).text === '2', `ref=${ref}`);
  await hub.act({owner: 'agent-a', tab_id: a.tab.tab_id, action: 'select', target: {label: 'Pick'}, value: 'green', postcondition: {target: {label: 'Pick'}, value: 'green'}});
  const checked = await hub.act({owner: 'agent-a', tab_id: a.tab.tab_id, action: 'check', target: {label: 'Agree'}, postcondition: {target: {label: 'Agree'}, checked: true}});
  check('select and checkbox verified', checked.verified === true);
  const pressed = await hub.act({owner: 'agent-a', tab_id: a.tab.tab_id, action: 'press', key: 'Enter', target: {label: 'Who'}, postcondition: {text_present: 'sent:agent-a'}});
  check('Enter submits the form in a hidden tab', pressed.verified === true && pressed.trusted_input === false, pressed.detail);
  check('unmet postcondition is reported, not hidden', (await code(hub.act({owner: 'agent-a', tab_id: a.tab.tab_id, action: 'click', target: {selector: '#add'}, postcondition: {text_present: 'never appears'}, timeout_ms: 700}))) === 'ACTION_NOT_VERIFIED');
  const link = await hub.act({owner: 'agent-a', tab_id: a.tab.tab_id, action: 'click', target: {role: 'link', name: 'Second page'}, postcondition: {text_present: 'Second page reached'}});
  check('link click navigates in the background', link.navigated && link.verified === true, link.url_after);
  const shot = await hub.screenshot({owner: 'agent-a', tab_id: a.tab.tab_id});
  check('screenshot of a hidden tab', shot.bytes > 1000, `${shot.bytes} bytes`);
  check('non-http scheme refused', (await code(hub.navigate({owner: 'agent-a', tab_id: a.tab.tab_id, url: 'file:///C:/Windows/win.ini'}))) === 'URL_SCHEME_FORBIDDEN');

  // The extension can now expose an exact target id from its existing debugger
  // attachment. Do NOT deliberately sever a real owner's relay merely because
  // an ID is present: the next extension connection may not be able to select
  // that tab automatically. Crash/relay restoration needs a separate handoff test.
  const durable = results.every(r => r.tab.durable_identity === true);
  check('every owned browser tab has a durable identity', durable);
  const stored = JSON.parse(fs.readFileSync(ledgerFile, 'utf8')).tabs;
  const durableIds = stored.map(tab => tab.target_id);
  check('durable ledger persists exact distinct Chrome target IDs for the three owners',
    stored.length === 3 && agents.every(owner => stored.filter(tab => tab.owner === owner).length === 1) &&
    durableIds.every(id => typeof id === 'string' && /^[0-9A-Fa-f]{32}$/.test(id)) &&
    new Set(durableIds).size === 3);
  console.log('SKIP owner-Chrome relay crash: exact identity is available; selection/handoff across a new extension connection remains unproven');
  const cleanup = await Promise.all(agents.map(owner => hub.tabCloseOwner({owner})));
  check('each agent closed only its own tabs', agents.every(owner => hub.tabList({owner}).tabs.length === 0), cleanup.map(c => c.closed).join(','));
  const remaining = JSON.parse(fs.readFileSync(ledgerFile, 'utf8')).tabs;
  check('durable ledger is empty after physical closure', remaining.length === 0);
  exitCode = checks.every(c => c.ok) ? 0 : 1;
} catch (error) {
  check('smoke completed without an unexpected error', false, `${error.code || ''} ${error.message} ${JSON.stringify(error.details || {})}`);
} finally {
  await hub.shutdown({close_tabs: true}).catch(() => {});
  server.close();
  await new Promise(resolve => setTimeout(resolve, 800));
  sampler.kill();
  await Promise.race([samplerDone, new Promise(resolve => setTimeout(resolve, 5000))]);
  const lines = fs.readFileSync(foregroundLog, 'utf8').trim().split(/\r?\n/).filter(Boolean);
  check('foreground sampler recorded a baseline', lines.length > 0);
  check('foreground HWND stayed unchanged throughout the run', lines.length === 1);
  console.log(`foreground window changes during the run (first line is the starting window): ${lines.length - 1}`);
  for (const line of lines) console.log('  ' + line);
  console.log(JSON.stringify({passed: checks.filter(c => c.ok).length, failed: checks.filter(c => !c.ok).length}));
  fs.rmSync(work, {recursive: true, force: true});
  process.exit(checks.every(c => c.ok) ? exitCode : 1);
}
