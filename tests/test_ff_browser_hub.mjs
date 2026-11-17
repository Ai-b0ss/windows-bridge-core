// Deterministic ownership/lifecycle tests. No browser, extension token or desktop is used.
import assert from 'node:assert/strict';
import {EventEmitter} from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {BrowserHub, HubError, backgroundCapability, backgroundExtensionPreflight, requireBackgroundChrome, serve, releaseAfterParentLoss} from '../runtime/bridge-v3/ff_browser_hub.mjs';

test('capability probe reports a blocker without disclosing profile data or claiming live acceptance', async () => {
  const blocked = await backgroundCapability(async () => { throw new HubError('BACKGROUND_CONNECT_UNSAFE'); });
  assert.equal(blocked.available, false);
  assert.equal(blocked.fallback, null);
  const ready = await backgroundCapability(async () => ({chrome_versions: ['158.0.8127.2'], extension_version: '0.5.0', user_data_dir: 'private'}),
    () => ({backgroundSupported: true, version: '1.65.1'}));
  assert.equal(ready.available, true);
  assert.equal(ready.live_verified, false);
  assert.equal(ready.token_checked, false);
  assert.equal(JSON.stringify(ready).includes('private'), false);
  assert.equal((await backgroundCapability(async () => ({}), () => ({backgroundSupported: false}))).available, false);
});

const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
};
const tick = () => new Promise(resolve => setImmediate(resolve));
const code = expected => error => error instanceof HubError && error.code === expected;

test('background preflight refuses missing, older or unverifiable running Chrome', () => {
  for (const versions of [[], null])
    assert.throws(() => requireBackgroundChrome(versions), code('CHROME_NOT_RUNNING'));
  for (const versions of [['157.0.8103.79'], ['158.0.8127.1'], ['unknown'], ['158.0.8127.2', '157.0.0.0']])
    assert.throws(() => requireBackgroundChrome(versions), code('BACKGROUND_CONNECT_UNSAFE'));
  assert.equal(requireBackgroundChrome(['158.0.8127.2']).already_running, true);
  assert.equal(requireBackgroundChrome(['159.0.0.0']).already_running, true);
});

test('extension preflight selects the same profile and rejects older or unverifiable extension', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ff-hub-extension-test-'));
  const extension = 'mmlmfjhmonkocbjadbfplnigmagldckm';
  const write = (profile, version, state = 1) => {
    fs.mkdirSync(path.join(root, profile), {recursive: true});
    fs.writeFileSync(path.join(root, profile, 'Secure Preferences'), JSON.stringify({extensions: {settings: {
      [extension]: {state, manifest: {version}},
    }}}));
  };
  try {
    write('Default', '0.5.0');
    write('Profile 1', '0.4.0');
    fs.writeFileSync(path.join(root, 'Local State'), JSON.stringify({profile: {last_used: 'Profile 1'}}));
    assert.throws(() => backgroundExtensionPreflight({userDataDir: root}), code('BACKGROUND_EXTENSION_UNSUPPORTED'));
    assert.equal(backgroundExtensionPreflight({userDataDir: root, profileDirName: 'Default'}).extension_version, '0.5.0');
    write('Profile 1', '0.5.0');
    assert.equal(backgroundExtensionPreflight({userDataDir: root}).profile_dir_name, 'Profile 1');
    write('Profile 1', '0.5.0', 0);
    assert.throws(() => backgroundExtensionPreflight({userDataDir: root}), code('BACKGROUND_EXTENSION_UNVERIFIED'));
    fs.rmSync(path.join(root, 'Profile 1', 'Secure Preferences'));
    fs.mkdirSync(path.join(root, 'Profile 1', 'Extensions', extension), {recursive: true});
    assert.throws(() => backgroundExtensionPreflight({userDataDir: root}), code('BACKGROUND_EXTENSION_UNVERIFIED'));
    assert.throws(() => backgroundExtensionPreflight({userDataDir: root, profileDirName: '../outside'}), code('OWNER_CHROME_PROFILE_INVALID'));
  } finally {
    assert.equal(path.dirname(path.resolve(root)), path.resolve(os.tmpdir()));
    fs.rmSync(root, {recursive: true, force: true});
  }
});

class FakePage extends EventEmitter {
  constructor(url = 'about:blank') {
    super();
    this.address = url;
    this.closed = false;
    this.closeCalls = 0;
    this.nativeInputCalls = 0;
    this.evaluations = 0;
    this.matchCount = 1;
  }
  isClosed() { return this.closed; }
  url() { return this.address; }
  mainFrame() { return this; }
  async title() { return 'test'; }
  async goto(url) {
    if (this.gotoError) throw this.gotoError;
    this.address = url;
    this.emit('framenavigated', this);
  }
  async close() {
    this.closeCalls++;
    if (this.closeError) throw this.closeError;
    this.closed = true;
    this.emit('close');
  }
  async bringToFront() { this.nativeInputCalls++; }
  locator() {
    const page = this;
    return {
      count: async () => page.matchCount,
      isVisible: async () => true,
      isEnabled: async () => true,
      isChecked: async () => false,
      inputValue: async () => '',
      evaluate: async () => { page.evaluations++; return page.readGate ? page.readGate.promise : 'text'; },
      click: async () => { page.nativeInputCalls++; },
      ariaSnapshot: async () => '- button "Test" [ref=e1]',
    };
  }
  async evaluate(fn) { return String(fn).includes('visibilityState') ? 'hidden' : 'text'; }
}

class FakeBrowser extends EventEmitter {
  connected = true;
  isConnected() { return this.connected; }
  async close() { this.connected = false; this.emit('disconnected'); }
}

function fixture(options = {}) {
  const connections = [];
  let connects = 0;
  const connector = {
    describe: () => ({transport: 'fake', background: true}),
    async connect() {
      connects++;
      if (connector.gate) await connector.gate.promise;
      if (connector.error) throw connector.error;
      const browser = new FakeBrowser();
      const context = new EventEmitter();
      context.created = [];
      context.newPage = async () => {
        if (context.gate) await context.gate.promise;
        const page = context.nextPage || new FakePage();
        context.nextPage = null;
        context.created.push(page);
        context.emit('page', page);
        return page;
      };
      const connection = {browser, context, internal: new Set([foreign])};
      connections.push(connection);
      return connection;
    },
  };
  const foreign = new FakePage('https://foreign.invalid/');
  const hub = new BrowserHub(connector, options);
  return {hub, connector, connections, foreign, get connects() { return connects; }};
}

test('one connection is shared across simultaneous agents', async () => {
  const f = fixture();
  f.connector.gate = deferred();
  const opened = ['a', 'b', 'c'].map(owner => f.hub.tabOpen({owner}));
  await tick();
  assert.equal(f.connects, 1);
  f.connector.gate.resolve();
  assert.equal((await Promise.all(opened)).length, 3);
  assert.equal(f.hub.status().tabs.live, 3);
  await f.hub.shutdown();
});

test('owner quota reserves pending opens before connection yields', async () => {
  const f = fixture({maxTabsPerOwner: 1});
  f.connector.gate = deferred();
  const first = f.hub.tabOpen({owner: 'a'});
  await assert.rejects(f.hub.tabOpen({owner: 'a'}), code('TAB_LIMIT_OWNER'));
  f.connector.gate.resolve();
  await first;
  assert.equal(f.hub.tabList({owner: 'a'}).tabs.length, 1);
  await f.hub.shutdown();
});

test('total quota reserves pending opens across owners', async () => {
  const f = fixture({maxTabs: 1});
  f.connector.gate = deferred();
  const first = f.hub.tabOpen({owner: 'a'});
  await assert.rejects(f.hub.tabOpen({owner: 'b'}), code('TAB_LIMIT_TOTAL'));
  f.connector.gate.resolve();
  await first;
  await f.hub.shutdown();
});

test('invalid capacities fail closed', () => {
  for (const options of [{maxTabs: NaN}, {maxTabs: 0}, {maxTabsPerOwner: 1.5}])
    assert.throws(() => fixture(options), code('LIMIT_INVALID'));
});

test('unsupported URLs are refused before connecting or opening a page', async () => {
  const f = fixture();
  await assert.rejects(f.hub.tabOpen({owner: 'a', url: 'file:///private'}), code('URL_SCHEME_FORBIDDEN'));
  assert.equal(f.connects, 0);
  assert.equal(f.hub.tabList({owner: 'a'}).tabs.length, 0);
});

test('all tab operations check ownership before touching the page', async () => {
  const f = fixture();
  const tab = await f.hub.tabOpen({owner: 'a'});
  for (const op of ['read', 'snapshot', 'navigate', 'act', 'evaluate', 'screenshot', 'wait_for', 'tab_close', 'tab_restore'])
    await assert.rejects(Promise.resolve().then(() => f.hub.dispatch(op, {owner: 'b', tab_id: tab.tab_id})), code('TAB_NOT_OWNED'));
  assert.equal(f.hub.tabList({owner: 'b'}).tabs.length, 0);
  assert.equal(f.connections[0].context.created[0].closeCalls, 0);
  await f.hub.shutdown();
});

test('operations serialize within one tab, while another tab proceeds independently', async () => {
  const f = fixture();
  const a = await f.hub.tabOpen({owner: 'a'});
  const b = await f.hub.tabOpen({owner: 'b'});
  const [pageA, pageB] = f.connections[0].context.created;
  pageA.readGate = deferred();
  const first = f.hub.read({owner: 'a', tab_id: a.tab_id, target: {selector: 'body'}});
  const close = f.hub.tabClose({owner: 'a', tab_id: a.tab_id});
  await f.hub.read({owner: 'b', tab_id: b.tab_id, target: {selector: 'body'}});
  assert.equal(pageB.evaluations, 1);
  assert.equal(pageA.closeCalls, 0);
  pageA.readGate.resolve('done');
  assert.equal((await first).text, 'done');
  await close;
  assert.equal(pageA.closeCalls, 1);
  await f.hub.shutdown();
});

test('queued work cannot use a tab after an earlier close', async () => {
  const f = fixture();
  const tab = await f.hub.tabOpen({owner: 'a'});
  const close = f.hub.tabClose({owner: 'a', tab_id: tab.tab_id});
  const read = f.hub.read({owner: 'a', tab_id: tab.tab_id});
  await close;
  await assert.rejects(read, code('TAB_NOT_FOUND'));
  await f.hub.shutdown();
});

test('failed close retains ownership and reports that the page remains open', async () => {
  const f = fixture();
  const tab = await f.hub.tabOpen({owner: 'a'});
  const page = f.connections[0].context.created[0];
  page.closeError = new Error('refused');
  await assert.rejects(f.hub.tabClose({owner: 'a', tab_id: tab.tab_id}), code('TAB_CLOSE_FAILED'));
  assert.equal(f.hub.tabList({owner: 'a'}).tabs[0].state, 'live');
  assert.equal(page.isClosed(), false);
  page.closeError = null;
  assert.equal((await f.hub.tabClose({owner: 'a', tab_id: tab.tab_id})).page_closed_in_browser, true);
  await f.hub.shutdown();
});

test('failed navigation with failed cleanup retains the created page identity', async () => {
  const f = fixture();
  await f.hub.connect();
  const page = new FakePage();
  page.gotoError = new Error('network');
  page.closeError = new Error('refused');
  f.connections[0].context.nextPage = page;
  await assert.rejects(f.hub.tabOpen({owner: 'a', url: 'https://example.invalid/'}), error => {
    assert.equal(error.code, 'NAVIGATION_FAILED');
    assert.equal(error.details.cleanup_failed, true);
    assert.equal(error.details.tab_id, f.hub.tabList({owner: 'a'}).tabs[0].tab_id);
    return true;
  });
  assert.equal(page.isClosed(), false);
  page.closeError = null;
  await f.hub.shutdown();
});

test('failed restore preserves the lost record for another deliberate attempt', async () => {
  const f = fixture({maxTabs: 1, maxTabsPerOwner: 1, backoffBaseMs: 0});
  const tab = await f.hub.tabOpen({owner: 'a', url: 'https://example.invalid/'});
  await f.connections[0].browser.close();
  f.connector.error = new Error('offline');
  await assert.rejects(f.hub.tabRestore({owner: 'a', tab_id: tab.tab_id}), code('TAB_RECOVERY_UNAVAILABLE'));
  assert.equal(f.hub.tabList({owner: 'a'}).tabs[0].tab_id, tab.tab_id);
  assert.equal(f.hub.tabList({owner: 'a'}).tabs[0].state, 'lost');
  f.connector.error = null;
  const beforeCount=f.connections[0].context.created.length;
  await assert.rejects(f.hub.tabRestore({owner: 'a', tab_id: tab.tab_id}), error => {
    assert.equal(error.code, 'TAB_RECOVERY_UNAVAILABLE');
    assert.equal(error.details.no_address_fallback, true);
    assert.equal(error.details.page_state_preserved, false);
    return true;
  });
  assert.equal(f.connections.slice(1).flatMap(c => c.context.created).length, 0,
    'never open a duplicate by URL, regardless of reconnect outcome');
  assert.equal(f.connections[0].context.created.length, beforeCount);
  assert.equal(f.hub.tabList({owner: 'a'}).tabs.length, 1);
  assert.equal(f.hub.tabList({owner: 'a'}).tabs[0].state, 'lost');
  await f.hub.shutdown();
});

test('connection loss is explicit and does not replay a mutation', async () => {
  const f = fixture();
  const tab = await f.hub.tabOpen({owner: 'a'});
  await f.connections[0].browser.close();
  await assert.rejects(f.hub.act({owner: 'a', tab_id: tab.tab_id, action: 'click', target: {selector: 'button'}}), code('TAB_LOST'));
  assert.equal(f.connects, 1);
  await f.hub.shutdown();
});

test('lost handles are retained and never counted as physically closed', async () => {
  const f = fixture();
  const tab = await f.hub.tabOpen({owner: 'a'});
  await f.connections[0].browser.close();
  const close = await f.hub.tabClose({owner: 'a', tab_id: tab.tab_id});
  assert.equal(close.closed, false);
  assert.equal(close.page_closed_in_browser, false);
  const cleanup = await f.hub.tabCloseOwner({owner: 'a'});
  assert.equal(cleanup.closed, 0);
  assert.deepEqual(cleanup.unconfirmed, [tab.tab_id]);
  assert.equal(f.hub.tabList({owner: 'a'}).tabs[0].state, 'lost');
  assert.equal((await f.hub.shutdown()).errors[0].code, 'TAB_CLEANUP_UNCONFIRMED');
});

test('popup inherits owner and closes when total capacity is reached', async () => {
  const f = fixture({maxTabs: 1});
  await f.hub.tabOpen({owner: 'a'});
  const popup = new FakePage('https://popup.invalid/');
  f.connections[0].context.created[0].emit('popup', popup);
  await tick();
  assert.equal(popup.isClosed(), true);
  assert.equal(f.hub.tabList({owner: 'a'}).tabs.length, 1);
  assert.equal(f.hub.tabList({owner: 'b'}).tabs.length, 0);
  await f.hub.shutdown();
});

test('a popup that refuses cleanup still retains owner identity', async () => {
  const f = fixture({maxTabsPerOwner: 1});
  await f.hub.tabOpen({owner: 'a'});
  const popup = new FakePage('https://popup.invalid/');
  popup.closeError = new Error('refused');
  f.connections[0].context.created[0].emit('popup', popup);
  await tick();
  assert.equal(f.hub.tabList({owner: 'a'}).tabs.length, 2);
  await assert.rejects(f.hub.tabOpen({owner: 'a'}), code('TAB_LIMIT_OWNER'));
  popup.closeError = null;
  await f.hub.shutdown();
});

test('background click uses DOM and reports untrusted and unverified input', async () => {
  const f = fixture();
  const tab = await f.hub.tabOpen({owner: 'a'});
  const result = await f.hub.act({owner: 'a', tab_id: tab.tab_id, action: 'click', target: {selector: 'button'}});
  const page = f.connections[0].context.created[0];
  assert.equal(page.evaluations, 1);
  assert.equal(page.nativeInputCalls, 0);
  assert.equal(result.trusted_input, false);
  assert.equal(result.verified, null);
  await f.hub.shutdown();
});

test('direct sidecar dispatch rejects foreground before page input', async () => {
  const f = fixture();
  const tab = await f.hub.tabOpen({owner: 'a'});
  await assert.rejects(f.hub.dispatch('act', {owner: 'a', tab_id: tab.tab_id, foreground: true,
    action: 'click', target: {selector: 'button'}}), code('FOREGROUND_ROUTE_REQUIRED'));
  const page = f.connections[0].context.created[0];
  assert.equal(page.nativeInputCalls, 0);
  assert.equal(page.evaluations, 0);
  await f.hub.shutdown();
});

test('background fill uses DOM evaluation and never native Playwright fill', async () => {
  const f = fixture();
  const tab = await f.hub.tabOpen({owner: 'a'});
  const result = await f.hub.act({owner: 'a', tab_id: tab.tab_id, action: 'fill', target: {selector: 'input'}, value: 'test'});
  const page = f.connections[0].context.created[0];
  assert.equal(page.evaluations, 1);
  assert.equal(page.nativeInputCalls, 0);
  assert.equal(result.trusted_input, false);
  await f.hub.shutdown();
});

test('action and script verify the live host after a redirect before executing', async () => {
  const f = fixture();
  const tab = await f.hub.tabOpen({owner: 'a', url: 'https://allowed.invalid/'});
  const page = f.connections[0].context.created[0];
  page.address = 'https://redirect.invalid/';
  for (const [op, args] of [['act', {action: 'click', target: {selector: 'button'}}], ['evaluate', {expression: 'document.title'}]])
    await assert.rejects(f.hub[op]({owner: 'a', tab_id: tab.tab_id, expected_host: 'allowed.invalid', ...args}), error => {
      assert.equal(error.code, 'TAB_HOST_CHANGED');
      assert.equal(error.details.attempted, false);
      return true;
    });
  assert.equal(page.evaluations, 0);
  await f.hub.shutdown();
});

test('shutdown during a pending connection never opens a page after stopping', async () => {
  const f = fixture();
  f.connector.gate = deferred();
  const opened = f.hub.tabOpen({owner: 'a'});
  const stopped = f.hub.shutdown();
  f.connector.gate.resolve();
  await assert.rejects(opened, code('HUB_SHUTDOWN'));
  await stopped;
  assert.equal(f.connections[0].context.created.length, 0);
  assert.equal(f.connections[0].browser.isConnected(), false);
});

test('ambiguous target is not accepted as an absent postcondition', async () => {
  let at = 0;
  const f = fixture({clock: () => at += 1000});
  const tab = await f.hub.tabOpen({owner: 'a'});
  f.connections[0].context.created[0].matchCount = 2;
  await assert.rejects(f.hub.waitFor({owner: 'a', tab_id: tab.tab_id,
    condition: {target: {selector: 'button'}, state: 'absent'}, timeout_ms: 100}), code('WAIT_TIMEOUT'));
  await f.hub.shutdown();
});

test('shutdown preserves foreign initial pages, closes owned tabs and refuses new work', async () => {
  const f = fixture();
  const tab = await f.hub.tabOpen({owner: 'a'});
  const page = f.connections[0].context.created[0];
  const result = await f.hub.shutdown();
  assert.equal(result.closed_tabs, 1);
  assert.equal(page.isClosed(), true);
  assert.equal(f.foreign.closeCalls, 0);
  await assert.rejects(f.hub.tabOpen({owner: 'a'}), code('HUB_SHUTDOWN'));
  await assert.rejects(f.hub.read({owner: 'a', tab_id: tab.tab_id}), code('TAB_NOT_FOUND'));
});

test('shutdown waits for pending creation and cleans the late page', async () => {
  const f = fixture();
  await f.hub.connect();
  const connection = f.connections[0];
  connection.context.gate = deferred();
  const opened = f.hub.tabOpen({owner: 'a'});
  await tick();
  const stopped = f.hub.shutdown();
  connection.context.gate.resolve();
  await assert.rejects(opened, code('HUB_SHUTDOWN'));
  await stopped;
  assert.equal(connection.context.created.length, 1);
  assert.equal(connection.context.created[0].isClosed(), true);
  assert.equal(connection.browser.isConnected(), false);
});

test('shutdown reports failed cleanup instead of counting a closed page', async () => {
  const f = fixture();
  const tab = await f.hub.tabOpen({owner: 'a'});
  f.connections[0].context.created[0].closeError = new Error('refused');
  const result = await f.hub.shutdown();
  assert.equal(result.closed_tabs, 0);
  assert.deepEqual(result.errors, [{tab_id: tab.tab_id, code: 'TAB_CLOSE_FAILED'}]);
});

test('repeated connection failures use backoff and circuit without retry storms', async () => {
  let at = 0;
  const f = fixture({clock: () => at, failureThreshold: 2, backoffBaseMs: 10, circuitOpenMs: 100});
  f.connector.error = new Error('offline');
  await assert.rejects(f.hub.connect(), code('BROWSER_CONNECT_FAILED'));
  await assert.rejects(f.hub.connect(), code('BROWSER_CONNECT_BACKOFF'));
  assert.equal(f.connects, 1);
  at = 10;
  await assert.rejects(f.hub.connect(), code('BROWSER_CONNECT_FAILED'));
  await assert.rejects(f.hub.connect(), code('BROWSER_CONNECT_CIRCUIT_OPEN'));
  assert.equal(f.connects, 2);
  at = 110;
  f.connector.error = null;
  await f.hub.connect();
  assert.equal(f.hub.status().connected, true);
  await f.hub.shutdown();
});

test('connection errors redact the injected extension token', async () => {
  const prior = process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN;
  const secret = 'test-only-extension-token';
  process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN = secret;
  try {
    const f = fixture();
    f.connector.error = new Error(`failed https://extension.invalid/connect?token=${secret}&x=1`);
    await assert.rejects(f.hub.connect(), error => !JSON.stringify(error.details).includes(secret));
    assert.equal(JSON.stringify(f.hub.status()).includes(secret), false);
  } finally {
    if (prior === undefined) delete process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN;
    else process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN = prior;
  }
});

test('browser sidecar is loopback only and requires its private key', async () => {
  const f = fixture();
  assert.throws(() => serve(f.hub, {key: 'x'.repeat(32), host: '0.0.0.0'}), code('LOOPBACK_REQUIRED'));
  assert.throws(() => serve(f.hub, {key: ''}), code('HUB_KEY_REQUIRED'));
  const key = 'x'.repeat(32);
  const server = await serve(f.hub, {key});
  try {
    const endpoint = `http://127.0.0.1:${server.address().port}/rpc`;
    assert.equal((await fetch(endpoint, {method: 'POST', body: '{}'})).status, 401);
    const response = await fetch(endpoint, {method: 'POST', headers: {'x-ff-browser-key': key}, body: '{invalid'});
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error_code, 'REQUEST_JSON_INVALID');
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

// ---- durable ledger and target-id reattachment (fake CDP; the real run is the integration smoke) ----
function cdpFixture(ledgerFile, world = {pages: [], seq: 0}, {listsAllTargets = false} = {}) {
  const connector = {
    describe: () => ({transport: 'fake-cdp'}),
    async connect() {
      const browser = new FakeBrowser();
      const context = new EventEmitter();
      context.newPage = async () => {
        const page = new FakePage();
        page.targetId = `TARGET${String(++world.seq).padStart(8, '0')}`;
        world.pages.push(page);
        return page;
      };
      context.pages = () => world.pages.filter(page => !page.isClosed());
      context.newCDPSession = async page => ({send: async () => ({targetInfo: {targetId: page.targetId}}), detach: async () => {}});
      const connection = {browser, context};
      if (listsAllTargets) connection.listTargetIds = async () => context.pages().map(page => page.targetId);
      return connection;
    },
  };
  return {hub: new BrowserHub(connector, {ledgerFile}), world};
}

const withLedger = async body => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ff-hub-ledger-test-'));
  try { await body(path.join(directory, 'tab-ledger.json')); }
  finally { fs.rmSync(directory, {recursive: true, force: true}); }
};

test('a new manager reattaches its recorded tab only by exact target id', () => withLedger(async ledger => {
  const first = cdpFixture(ledger);
  const tab = await first.hub.tabOpen({owner: 'a', url: 'https://same.invalid/'});
  assert.equal(tab.durable_identity, true);
  // The first manager dies without shutdown. A foreign page shows the same address.
  const foreign = new FakePage('https://same.invalid/');
  foreign.targetId = 'FOREIGN00000001';
  first.world.pages.unshift(foreign);
  const second = cdpFixture(ledger, first.world);
  const [listed] = second.hub.tabList({owner: 'a'}).tabs;
  assert.equal(listed.state, 'lost');
  assert.equal(listed.orphaned, true);
  await assert.rejects(second.hub.read({owner: 'a', tab_id: tab.tab_id}), code('TAB_LOST'));
  await assert.rejects(second.hub.tabRestore({owner: 'b', tab_id: tab.tab_id}), code('TAB_NOT_OWNED'));
  const restored = await second.hub.tabRestore({owner: 'a', tab_id: tab.tab_id});
  assert.equal(restored.tab_id, tab.tab_id);
  assert.equal(restored.reattached, true);
  assert.equal(restored.page_state_preserved, true);
  assert.equal(first.world.pages.length, 2, 'no page was opened');
  const closed = await second.hub.tabClose({owner: 'a', tab_id: tab.tab_id});
  assert.equal(closed.page_closed_in_browser, true);
  assert.equal(foreign.isClosed(), false);
  assert.equal(foreign.closeCalls, 0);
  assert.deepEqual(JSON.parse(fs.readFileSync(ledger, 'utf8')).tabs, []);
}));

test('a recorded tab that is not found is neither adopted by address nor reopened', () => withLedger(async ledger => {
  const first = cdpFixture(ledger);
  const tab = await first.hub.tabOpen({owner: 'a', url: 'https://same.invalid/'});
  first.world.pages[0].targetId = 'CHANGED00000001';  // same address, different identity
  const second = cdpFixture(ledger, first.world);
  await assert.rejects(second.hub.tabRestore({owner: 'a', tab_id: tab.tab_id}), code('TAB_RECOVERY_UNAVAILABLE'));
  assert.equal(first.world.pages.length, 1, 'no duplicate');
  const close = await second.hub.tabClose({owner: 'a', tab_id: tab.tab_id});
  assert.equal(close.page_closed_in_browser, false);
  assert.equal(close.reason, 'TAB_CLEANUP_UNCONFIRMED');
  assert.equal(first.world.pages[0].closeCalls, 0);
  assert.equal(second.hub.tabList({owner: 'a'}).tabs.length, 1, 'record retained');
  // Session end: reported as unconfirmed, then the unreachable record stops holding quota.
  const sweep = await second.hub.tabCloseOwner({owner: 'a', forget_unconfirmed: true});
  assert.deepEqual(sweep.unconfirmed, [tab.tab_id]);
  assert.equal(sweep.closed, 0);
  assert.equal(second.hub.tabList({owner: 'a'}).tabs.length, 0);
  assert.deepEqual(JSON.parse(fs.readFileSync(ledger, 'utf8')).tabs, []);
}));

test('closure is confirmed by absence only when the transport lists every browser target', () => withLedger(async ledger => {
  const first = cdpFixture(ledger);
  const tab = await first.hub.tabOpen({owner: 'a'});
  first.world.pages[0].closed = true;  // closed in the browser while no manager was running
  const partial = cdpFixture(ledger, first.world);
  assert.equal((await partial.hub.tabClose({owner: 'a', tab_id: tab.tab_id})).page_closed_in_browser, false);
  const full = cdpFixture(ledger, first.world, {listsAllTargets: true});
  const close = await full.hub.tabClose({owner: 'a', tab_id: tab.tab_id});
  assert.equal(close.page_closed_in_browser, true);
  assert.equal(close.evidence, 'target_absent_in_browser');
}));

test('a relay reconnect in the same process reattaches the surviving tab instead of duplicating it', () => withLedger(async ledger => {
  const f = cdpFixture(ledger);
  const tab = await f.hub.tabOpen({owner: 'a', url: 'https://kept.invalid/'});
  await f.hub.connection.browser.close();
  assert.equal(f.hub.tabList({owner: 'a'}).tabs[0].state, 'lost');
  const restored = await f.hub.tabRestore({owner: 'a', tab_id: tab.tab_id});
  assert.equal(restored.reattached, true);
  assert.equal(f.world.pages.length, 1);
}));

test('a damaged ledger is reported and never invents tabs', () => withLedger(async ledger => {
  fs.writeFileSync(ledger, '{"version":1,"tabs":[{"tab_id":"../x","owner":"a"},{"tab_id":"tab-0123456789abcdef","owner":""}]}');
  assert.equal(cdpFixture(ledger).hub.tabList({owner: 'a'}).tabs.length, 0);
  fs.writeFileSync(ledger, 'not json');
  const hub = cdpFixture(ledger).hub;
  assert.equal(hub.status().tab_ledger.error, 'TAB_LEDGER_UNREADABLE');
  assert.equal(hub.tabList({owner: 'a'}).tabs.length, 0);
}));

test('an older Chrome names the owner-side remedy and no automatic fallback', async () => {
  const blocked = await backgroundCapability(async () => { throw new HubError('BACKGROUND_CONNECT_UNSAFE'); });
  assert.equal(blocked.remedy, 'OWNER_CHROME_UPDATE_AND_RELAUNCH');
  assert.equal(blocked.automatic, false);
  assert.equal(blocked.fallback, null);
});


test('existing Playwright extension page delegate yields exact durable identity without a new CDP attach', async () => {
  const f = fixture();
  const target = '9C69A6D1B082466BB52264B7E1F590AA';
  const serverContext = {};
  const serverPage = {browserContext: serverContext};
  serverPage.delegate = {_page: serverPage, _targetId: target};
  Object.setPrototypeOf(serverPage.delegate, {constructor: {name: 'CRPage'}});
  const clientContext = {};
  const clientPage = {context: () => clientContext};
  const bridge = {toImpl: object => object === clientPage ? serverPage : object === clientContext ? serverContext : null};
  clientPage._connection = bridge;
  const connection = {context: {newCDPSession: () => { throw new Error('must not attach to browser target'); }}};
  assert.equal(await f.hub._targetId(connection, clientPage), target);
  serverPage.delegate._targetId = '../not-a-valid-id';
  assert.equal(await f.hub._targetId(connection, clientPage), null);
  serverPage.delegate._targetId = target;
  serverPage.browserContext = {};
  assert.equal(await f.hub._targetId(connection, clientPage), null, 'wrong context cannot supply identity');
  await f.hub.shutdown();
});


test('a stale extension ledger cannot reclaim a duplicate target ID or untrusted seed', async () => {
  const f = fixture();
  f.hub.connector.describe = () => ({transport: 'playwright-extension'});
  const targetId = 'AA8912CC0014BB2391ED592D78BD26CD';
  const tab = {id: 'tab-a', owner: 'alice', generation: 0, state: 'lost',
    target_id: targetId, lane: Promise.resolve()};
  const impostor = {id: 'tab-b', owner: 'bob', generation: 0, state: 'lost',
    target_id: targetId, lane: Promise.resolve()};
  f.hub.tabs.set(tab.id, tab);
  f.hub.tabs.set(impostor.id, impostor);
  let unexpectedEval = 0;
  const seed = {url: () => 'chrome-extension://mmlmfjhmonkocbjadbfplnigmagldckm/connect.html',
    isClosed: () => false, evaluate: async () => { unexpectedEval++; return true; }};
  const pages = [seed];
  const conn = {context: {pages: () => pages}, browser: {isConnected: () => true}};
  f.hub.connection = conn;
  assert.equal(await f.hub._bringBackExtensionTab(conn, tab), false);
  assert.equal(unexpectedEval, 0, 'duplicate persisted identity must never mutate Chrome');
  f.hub.tabs.delete(impostor.id);
  seed.url = () => 'chrome-extension://evil.example/connect.html';
  assert.equal(await f.hub._bringBackExtensionTab(conn, tab), false);
  assert.equal(unexpectedEval, 0, 'non-official extension origin is never trusted');
  seed.url = () => 'https://example.invalid/connect.html';
  assert.equal(await f.hub._bringBackExtensionTab(conn, tab), false);
  assert.equal(unexpectedEval, 0, 'ordinary web pages cannot gain privileged recovery');
});

test('a lost tab can be reattached by exact id after an extension group handoff', async () => {
  const f = fixture();
  f.hub.connector.describe = () => ({transport: 'playwright-extension'});
  const targetId = 'D7A90E194BDE0034DBBE119F01D8A50B';
  const tab = {id: 'tab-recover', owner: 'alice', generation: 0, state: 'lost',
    target_id: targetId, lane: Promise.resolve(), url: 'https://owner.invalid/',
    created_at: 1, last_used_at: 1, orphaned: true};
  f.hub.tabs.set(tab.id, tab);
  let groupMutations = 0;
  const survivor = new FakePage('https://owner.invalid/');
  const seed = {url: () => 'chrome-extension://mmlmfjhmonkocbjadbfplnigmagldckm/connect.html',
    isClosed: () => false, evaluate: async (_trustedFunction, requestedId) => {
      assert.equal(requestedId, targetId);
      groupMutations++;
      pages.push(survivor);
      return true;
    }};
  const pages = [seed];
  const conn = {context: {pages: () => pages}, browser: {isConnected: () => true}, generation: 2};
  f.hub.connection = conn;
  f.hub._targetId = async (_connection, page) => page === survivor ? targetId : null;
  assert.equal(await f.hub._reattach(tab), true);
  assert.equal(groupMutations, 1);
  assert.equal(tab.page, survivor);
  assert.equal(tab.generation, 2);
  assert.equal(tab.orphaned, false);
  assert.equal(pages.length, 2, 'no duplicate page opened during reattach');
});

test('parent EOF disconnects without closing owned pages and preserves the exact-target recovery ledger', async () => withLedger(async ledger => {
  const first = cdpFixture(ledger);
  const tab = await first.hub.tabOpen({owner: 'parent-crash-owner', url: 'https://owner.invalid/unfinished'});
  const physical = first.world.pages[0];
  const connection = first.hub.connection;
  const disconnect = connection.browser.close.bind(connection.browser);
  connection.browser.close = async () => {
    // Real Playwright closes local Page handles before reporting disconnect;
    // that does not mean Chrome's physical tab was closed.
    physical.emit('close');
    await disconnect();
  };
  const before = JSON.parse(fs.readFileSync(ledger, 'utf8'));
  const result = await releaseAfterParentLoss(first.hub);
  assert.equal(result.closed_tabs, 0);
  assert.equal(physical.isClosed(), false, 'transport EOF must not discard an unfinished page');
  assert.equal(physical.closeCalls, 0);
  assert.equal(JSON.parse(fs.readFileSync(ledger, 'utf8')).tabs[0].target_id, before.tabs[0].target_id);
  const second = cdpFixture(ledger, first.world);
  const restored = await second.hub.tabRestore({owner: 'parent-crash-owner', tab_id: tab.tab_id});
  assert.equal(restored.reattached, true);
  assert.equal(restored.evidence, 'cdp_target_id');
  assert.equal(first.world.pages.length, 1, 'recovery must not open a replacement URL');
  await second.hub.shutdown();
}));
