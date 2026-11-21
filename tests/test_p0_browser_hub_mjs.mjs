// P0 verification tests for Playwright 1.65.1 ABI, attach rollback, non-blocking close,
// ff_browser_hub.mjs hardening, integrity scanning, and real isolated Playwright lifecycle.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {EventEmitter} from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import {createRequire} from 'node:module';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {promisify} from 'node:util';

import {
  BrowserHub,
  HubError,
  backgroundCapability,
  extensionConnector,
  loadPlaywright,
  resolvePlaywrightRoot,
  verifyPlaywrightCoreBundle,
} from '../runtime/bridge-v3/ff_browser_hub.mjs';
import {PlaywrightEngine, verifyPlaywrightCoreBundleSync} from '../runtime/bridge-v3/cua_browser_playwright.mjs';
import {BrowserSidecar, BrowserSidecarError} from '../runtime/bridge-v3/cua_browser_sidecar.mjs';

const execFileAsync = promisify(execFile);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..');
const HUB_SCRIPT = path.join(REPO_ROOT, 'runtime', 'bridge-v3', 'ff_browser_hub.mjs');
const LOCAL_BRIDGE_PW_ROOT = path.join(REPO_ROOT, 'runtime', 'bridge-v3');
const PW165_ROOT = [
  process.env.FF_TEST_PW165_ROOT,
  process.env.FF_PLAYWRIGHT_ROOT,
  fs.existsSync(path.join(LOCAL_BRIDGE_PW_ROOT, 'node_modules', 'playwright-core', 'lib', 'coreBundle.js'))
    ? LOCAL_BRIDGE_PW_ROOT
    : null,
].find(candidate => typeof candidate === 'string' && candidate.trim() && fs.existsSync(path.join(candidate, 'node_modules', 'playwright-core', 'lib', 'coreBundle.js'))) || null;

function findIsolatedBrowserExecutable() {
  const candidates = [];
  if (PW165_ROOT) {
    try {
      const req = createRequire(path.join(PW165_ROOT, 'package.json'));
      const pw = req('playwright');
      candidates.push(pw.chromium.executablePath());
    } catch {}
  }
  candidates.push(
    path.join(process.env.PROGRAMFILES || 'C:/Program Files', 'Google/Chrome/Application/chrome.exe'),
    path.join(process.env['PROGRAMFILES(X86)'] || 'C:/Program Files (x86)', 'Microsoft/Edge/Application/msedge.exe'),
  );
  for (const candidate of candidates) {
    if (candidate && fs.existsSync(candidate)) return candidate;
  }
  return null;
}

class MockPage extends EventEmitter {
  constructor(url = 'about:blank') {
    super();
    this._url = url;
    this.closed = false;
    this.closeCalls = 0;
    this.gotoCalls = [];
    this.gotoError = null;
    this.closeError = null;
    this.onCloseHook = null;
  }
  url() { return this._url; }
  isClosed() { return this.closed; }
  mainFrame() { return this; }
  async title() { return 'Mock Title'; }
  async goto(url) {
    this.gotoCalls.push(url);
    if (this.gotoError) throw this.gotoError;
    this._url = url;
    this.emit('framenavigated', this);
  }
  async close() {
    this.closeCalls++;
    if (this.onCloseHook) await this.onCloseHook(this);
    if (this.closeError) throw this.closeError;
    this.closed = true;
    this.emit('close');
  }
}

class MockBrowser extends EventEmitter {
  constructor(contexts = []) {
    super();
    this._contexts = contexts;
    this.connected = true;
    this.protocolClosed = false;
    this.browserCloseCalls = 0;
    this._connection = {
      close: () => {
        this.protocolClosed = true;
        this.connected = false;
        this.emit('disconnected');
      },
    };
  }
  contexts() { return this._contexts; }
  isConnected() { return this.connected; }
  async close() {
    this.browserCloseCalls++;
    this.connected = false;
    this.emit('disconnected');
  }
}

function makeMockContext(initialPages = []) {
  const ctx = new EventEmitter();
  const pages = [...initialPages];
  ctx.createdPages = [];
  ctx.pages = () => pages.filter(p => !p.isClosed());
  ctx.newPage = async () => {
    const page = ctx.nextPage || new MockPage('about:blank');
    ctx.nextPage = null;
    pages.push(page);
    ctx.createdPages.push(page);
    ctx.emit('page', page);
    return page;
  };
  return ctx;
}

test('Playwright 1.65.1 coreBundle.js ABI signature and 4-arg createBrowserWithInfo contract', async () => {
  if (PW165_ROOT) {
    const bundlePath = path.join(PW165_ROOT, 'node_modules', 'playwright-core', 'lib', 'coreBundle.js');
    assert.equal(fs.existsSync(bundlePath), true, 'pw165 coreBundle.js must exist');
    const source = fs.readFileSync(bundlePath, 'utf8');
    assert.match(source, /async function createBrowserWithInfo\(config,\s*clientInfo,\s*cliOptions,\s*bindOptions\)/);
    assert.match(source, /browser\.bind\(bindOptions\.title/);

    const runtime = loadPlaywright(PW165_ROOT);
    assert.equal(runtime.version, '1.65.1');
    assert.equal(runtime.backgroundSupported, true);
    assert.equal(typeof runtime.tools.createBrowserWithInfo, 'function');
    assert.equal(runtime.tools.createBrowserWithInfo.length, 4);
  }

  // Strict 1.65.1-faithful 4-arg factory that crashes if bindOptions.title is missing.
  const calls = [];
  const connectUrl = `chrome-extension://mmlmfjhmonkocbjadbfplnigmagldckm/connect.html?client=${encodeURIComponent(JSON.stringify({name: 'BridgeABI'}))}`;
  const connectPage = new MockPage(connectUrl);
  const ctx = makeMockContext([connectPage]);
  const browser = new MockBrowser([ctx]);
  const strict165Factory = async (config, clientInfo, cliOptions, bindOptions) => {
    // Reproduce exact Playwright 1.65.1 crash if bindOptions is omitted.
    const title = bindOptions.title;
    assert.equal(typeof title, 'string');
    assert.ok(title.length > 0);
    assert.equal(typeof bindOptions.workspaceDir, 'string');
    calls.push({config, clientInfo, cliOptions, bindOptions});
    return {browser, endpoint: 'ws://127.0.0.1:0/mock'};
  };

  const prevToken = process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN;
  process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN = 'synthetic-unit-test-token-do-not-use-in-prod-0000';
  try {
    const engine = new PlaywrightEngine({}, {createBrowserWithInfo: strict165Factory});
    const handle = await engine.attach({
      ownerBrowser: true,
      ownerTransport: 'extension',
      extensionClientName: 'BridgeABI',
      url: 'https://example.invalid/start',
    });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].config.extension, true);
    assert.equal(calls[0].config.background, true);
    assert.equal(calls[0].config.tabGroup, true);
    assert.equal(calls[0].cliOptions.extension, true);
    assert.equal(calls[0].bindOptions.title.startsWith('BridgeABI-'), true);
    // Reused connectPage navigated directly to target URL without creating an extra about:blank tab.
    assert.equal(ctx.createdPages.length, 0);
    assert.deepEqual(connectPage.gotoCalls, ['https://example.invalid/start']);
    assert.equal((await engine.capabilities(handle)).background, true);
    const cleanup = await engine.close(handle);
    assert.equal(cleanup.owned_pages_closed, 1);
    assert.equal(cleanup.protocol_connection_closed, true);

    // Backwards compatibility with legacy 3-arg mock factory.
    const ctx3 = makeMockContext([]);
    const browser3 = new MockBrowser([ctx3]);
    let seenArgs = 0;
    const legacy3ArgFactory = async function (config, clientInfo, cliOptions) {
      assert.equal(config.extension, true);
      assert.equal(typeof clientInfo.clientName, 'string');
      assert.equal(cliOptions.browser, 'chrome');
      seenArgs = arguments.length;
      return {browser: browser3};
    };
    const engine3 = new PlaywrightEngine({}, {createBrowserWithInfo: legacy3ArgFactory});
    const h3 = await engine3.attach({ownerBrowser: true, ownerTransport: 'extension'});
    assert.equal(seenArgs, 4);
    await engine3.close(h3);
  } finally {
    if (prevToken === undefined) delete process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN;
    else process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN = prevToken;
  }
});

test('attach rollback closes created pages, owned connect.html, and protocol connection on any error', async () => {
  const prevToken = process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN;
  process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN = 'synthetic-unit-test-token-do-not-use-in-prod-0001';
  try {
    // 1. BROWSER_PAGE_OWNERSHIP_REQUIRED (createPage=false, no claimPage) rolls back connection & connect.html
    const connectUrl = `chrome-extension://mmlmfjhmonkocbjadbfplnigmagldckm/connect.html?client=${encodeURIComponent(JSON.stringify({name: 'RollbackOne'}))}`;
    const existingTab = new MockPage('https://owner.invalid/');
    const connectPage = new MockPage(connectUrl);
    const ctx1 = makeMockContext([existingTab, connectPage]);
    const browser1 = new MockBrowser([ctx1]);
    const engine1 = new PlaywrightEngine({}, {
      createBrowserWithInfo: async () => ({browser: browser1}),
    });
    await assert.rejects(
      engine1.attach({
        ownerBrowser: true,
        ownerTransport: 'extension',
        extensionClientName: 'RollbackOne',
        createPage: false,
        pageIndex: 0,
      }),
      error => error instanceof BrowserSidecarError && error.code === 'BROWSER_PAGE_OWNERSHIP_REQUIRED' &&
        error.details.rollback_attempted === true && error.details.protocol_connection_closed === true,
    );
    assert.equal(existingTab.isClosed(), false, 'must never close foreign owner tab');
    assert.equal(connectPage.isClosed(), true, 'owned connect.html must be closed on rollback');
    assert.equal(browser1.protocolClosed, true, 'protocol connection must be closed on rollback');

    // 2. Navigation error after newPage() closes the newly created page and connection
    const ctx2 = makeMockContext([]);
    const badPage = new MockPage('about:blank');
    badPage.gotoError = new Error('net::ERR_ABORTED');
    ctx2.nextPage = badPage;
    const browser2 = new MockBrowser([ctx2]);
    const engine2 = new PlaywrightEngine({}, {
      createBrowserWithInfo: async () => ({browser: browser2}),
    });
    await assert.rejects(
      engine2.attach({
        ownerBrowser: true,
        ownerTransport: 'extension',
        extensionClientName: 'RollbackNav',
        url: 'https://broken.invalid/',
      }),
      /ERR_ABORTED/,
    );
    assert.equal(badPage.isClosed(), true, 'newly created page must be closed on attach failure');
    assert.equal(browser2.protocolClosed, true, 'connection must be closed on attach failure');

    // 3. BrowserSidecar.attach() rolls back engine handle if capabilities() throws
    let closedHandle = false;
    const failingCapEngine = {
      attach: async () => ({id: 'h-leak-check'}),
      capabilities: async () => { throw new BrowserSidecarError('CAPABILITIES_BROKEN'); },
      close: async () => { closedHandle = true; return {detached: true}; },
    };
    const sidecar = new BrowserSidecar(failingCapEngine);
    await assert.rejects(sidecar.attach({}), {code: 'CAPABILITIES_BROKEN'});
    assert.equal(closedHandle, true, 'sidecar.attach must close handle when capabilities() fails');
    assert.equal(sidecar.surfaces.size, 0, 'no leaked surface entry');
  } finally {
    if (prevToken === undefined) delete process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN;
    else process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN = prevToken;
  }
});

test('close(h) closes owned pages and detaches BEFORE flagging >=2 connect.html; recover() refuses live-close swallow', async () => {
  const prevToken = process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN;
  process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN = 'synthetic-unit-test-token-do-not-use-in-prod-0002';
  try {
    const connectUrl = `chrome-extension://mmlmfjhmonkocbjadbfplnigmagldckm/connect.html?client=${encodeURIComponent(JSON.stringify({name: 'MultiConnect'}))}`;
    const conn1 = new MockPage(connectUrl);
    const conn2 = new MockPage(connectUrl);
    const foreign = new MockPage('https://owner-mail.invalid/');
    // Make conn1 fail goto so attach falls back to newPage() and leaves both connect pages
    conn1.gotoError = new Error('cannot navigate extension page');
    const ownedWorkPage = new MockPage('about:blank');
    const ctx = makeMockContext([foreign, conn1, conn2]);
    ctx.nextPage = ownedWorkPage;
    // Prevent attach's best-effort cleanup from closing conn1/conn2 so we can test close() with >=2 connect.html
    conn1.closeError = new Error('transient');
    conn2.closeError = new Error('transient');
    const browser = new MockBrowser([ctx]);
    const engine = new PlaywrightEngine({}, {createBrowserWithInfo: async () => ({browser})});
    const sidecar = new BrowserSidecar(engine);
    const {surface_id} = await sidecar.attach({
      ownerBrowser: true,
      ownerTransport: 'extension',
      extensionClientName: 'MultiConnect',
    });
    // Also attach a popup owned page
    const popup = new MockPage('https://popup.invalid/');
    ctx.createdPages.push(popup);
    const handle = sidecar.surfaces.get(surface_id).handle;
    engine._markOwned(handle, popup, {created: true});
    const origPages = ctx.pages.bind(ctx);
    ctx.pages = () => [...origPages(), popup].filter((p, i, arr) => !p.isClosed() && arr.indexOf(p) === i);
    conn1.closeError = null;
    conn2.closeError = null;

    await assert.rejects(
      sidecar.close(surface_id),
      error => error instanceof BrowserSidecarError &&
        error.code === 'OWNER_BROWSER_EXTENSION_CONNECT_PAGE_AMBIGUOUS' &&
        error.details.owned_pages_closed === 2 &&
        error.details.protocol_connection_closed === true &&
        error.details.matches === 2,
    );
    assert.equal(ownedWorkPage.isClosed(), true, 'main owned page MUST be closed even with >=2 connect.html');
    assert.equal(popup.isClosed(), true, 'owned popup MUST be closed even with >=2 connect.html');
    assert.equal(foreign.isClosed(), false, 'foreign owner page MUST remain untouched');
    assert.equal(conn1.isClosed(), false, 'ambiguous connect.html #1 must not be blindly closed');
    assert.equal(conn2.isClosed(), false, 'ambiguous connect.html #2 must not be blindly closed');
    assert.equal(browser.protocolClosed, true, 'protocol connection MUST still be detached');
    assert.equal(sidecar.surfaces.has(surface_id), false, 'detached surface must not leak in sidecar map');

    // BrowserSidecar.recover() fails closed when close() errors on a still-live surface
    let attachCalls = 0;
    const liveFailEngine = {
      attach: async () => {
        attachCalls++;
        return {disconnected: false, browser: {isConnected: () => true}};
      },
      capabilities: async () => ({ok: true}),
      close: async () => { throw new BrowserSidecarError('BROWSER_CLOSE_FAILED', 'still open', {detached: false}); },
    };
    const sc2 = new BrowserSidecar(liveFailEngine);
    const attached = await sc2.attach({});
    await assert.rejects(sc2.recover(attached.surface_id), {code: 'SURFACE_RECOVER_CLOSE_FAILED'});
    assert.equal(attachCalls, 1, 'recover() must NOT double-attach when live surface failed to close');
  } finally {
    if (prevToken === undefined) delete process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN;
    else process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN = prevToken;
  }
});

test('ff_browser_hub.mjs: disconnect during page.close() NEVER reports false-positive cleanup_verified', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ff-p0-hub-disc-'));
  const ledgerFile = path.join(tmpDir, 'tab-ledger.json');
  try {
    let seq = 0;
    const pages = [];
    const connector = {
      describe: () => ({transport: 'fake-extension', background: true}),
      async connect() {
        const browser = new MockBrowser();
        const context = makeMockContext([]);
        context.newPage = async () => {
          const page = new MockPage('https://work.invalid/');
          page.targetId = `TGT00000${++seq}`;
          pages.push(page);
          context.emit('page', page);
          return page;
        };
        context.newCDPSession = async page => ({
          send: async () => ({targetInfo: {targetId: page.targetId}}),
          detach: async () => {},
        });
        return {browser, context};
      },
    };
    const hub = new BrowserHub(connector, {ledgerFile});
    const tab = await hub.tabOpen({owner: 'agent-disc'});
    const page = pages[0];
    const conn = hub.connection;

    // Simulate relay disconnect happening inside page.close():
    // local Playwright sets page.closed = true AND drops browser connection!
    page.onCloseHook = async () => {
      conn.browser.connected = false;
      conn.browser.emit('disconnected');
    };

    const closeResult = await hub.tabClose({owner: 'agent-disc', tab_id: tab.tab_id, forget_unconfirmed: false});
    assert.equal(closeResult.closed, false);
    assert.equal(closeResult.page_closed_in_browser, false);
    assert.equal(closeResult.reason, 'TAB_CLEANUP_UNCONFIRMED');
    assert.equal(closeResult.record_dropped, false);

    // Tab MUST remain in memory as 'lost' AND persisted in tab-ledger.json!
    const listed = hub.tabList({owner: 'agent-disc'}).tabs;
    assert.equal(listed.length, 1);
    assert.equal(listed[0].state, 'lost');
    const persisted = JSON.parse(fs.readFileSync(ledgerFile, 'utf8'));
    assert.equal(persisted.tabs.length, 1);
    assert.equal(persisted.tabs[0].tab_id, tab.tab_id);
    assert.equal(persisted.tabs[0].target_id, page.targetId);

    // Also test shutdown({close_tabs: true}) when disconnect happens mid-close
    const hub2 = new BrowserHub(connector, {ledgerFile: path.join(tmpDir, 'ledger2.json')});
    const tab2 = await hub2.tabOpen({owner: 'agent-disc2'});
    const page2 = pages[1];
    const conn2 = hub2.connection;
    page2.onCloseHook = async () => {
      conn2.browser.connected = false;
      conn2.browser.emit('disconnected');
    };
    const shut = await hub2.shutdown({close_tabs: true});
    assert.equal(shut.closed_tabs, 0);
    assert.deepEqual(shut.errors, [{tab_id: tab2.tab_id, code: 'TAB_CLEANUP_UNCONFIRMED'}]);
  } finally {
    fs.rmSync(tmpDir, {recursive: true, force: true});
  }
});

test('ff_browser_hub.mjs: tabCloseOwner per-tab fault isolation, forget_unconfirmed=false, _onDisconnected persist, and _onUnclaimedPage auditing', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ff-p0-hub-own-'));
  const ledgerFile = path.join(tmpDir, 'tab-ledger.json');
  try {
    let seq = 0;
    const allPages = [];
    let currentCtx = null;
    const connector = {
      describe: () => ({transport: 'fake-extension', background: true}),
      async connect() {
        const browser = new MockBrowser();
        const context = makeMockContext([]);
        currentCtx = context;
        context.newPage = async () => {
          const page = new MockPage(`https://site-${++seq}.invalid/`);
          page.targetId = `TABTARGET000${seq}`;
          allPages.push(page);
          context.emit('page', page);
          return page;
        };
        context.newCDPSession = async page => ({
          send: async () => ({targetInfo: {targetId: page.targetId}}),
          detach: async () => {},
        });
        return {browser, context};
      },
    };
    const hub = new BrowserHub(connector, {ledgerFile});
    const t1 = await hub.tabOpen({owner: 'owner-a'});
    const t2 = await hub.tabOpen({owner: 'owner-a'});
    const tOther = await hub.tabOpen({owner: 'owner-b'});

    // Claimed pages opened via tabOpen MUST NOT appear as unclaimed
    assert.equal(hub.status().unclaimed_pages.active, 0);
    assert.equal(hub.status().unclaimed_pages.total_observed, 0);

    // Emit an unclaimed noopener page (e.g. target="_blank" rel="noopener")
    const noopener = new MockPage('https://external.invalid/noopener?token=secret123');
    noopener.targetId = 'NOOPENER00001';
    currentCtx.emit('page', noopener);
    await new Promise(resolve => setImmediate(resolve));
    const statusWithUnclaimed = hub.status();
    assert.equal(statusWithUnclaimed.unclaimed_pages.active, 1);
    assert.equal(statusWithUnclaimed.unclaimed_pages.total_observed, 1);
    assert.equal(statusWithUnclaimed.unclaimed_pages.pages[0].url.includes('secret123'), false, 'token must be redacted');
    assert.equal(statusWithUnclaimed.unclaimed_pages.pages[0].target_id, 'NOOPENER00001');

    // Make t1 fail close; t2 should still close cleanly; t1 stays in ledger when forget_unconfirmed=false
    allPages[0].closeError = new Error('close refused');
    const ownerClose = await hub.tabCloseOwner({owner: 'owner-a', forget_unconfirmed: false});
    assert.equal(ownerClose.closed, 1);
    assert.deepEqual(ownerClose.unconfirmed, [t1.tab_id]);
    assert.deepEqual(ownerClose.errors, [{tab_id: t1.tab_id, code: 'TAB_CLOSE_FAILED'}]);
    assert.deepEqual(ownerClose.results, ownerClose.tabs);
    assert.equal(allPages[1].isClosed(), true, 'second tab must close even when first failed');
    assert.equal(allPages[2].isClosed(), false, 'other owner tab must not be touched');
    assert.equal(noopener.isClosed(), false, 'unclaimed foreign page must not be closed');
    const ledgerAfter = JSON.parse(fs.readFileSync(ledgerFile, 'utf8'));
    assert.deepEqual(ledgerAfter.tabs.map(t => t.tab_id).sort(), [t1.tab_id, tOther.tab_id].sort());

    // Simulate page.close immediately before browser.disconnected -> _onDisconnected must re-persist 'lost'
    allPages[2].emit('close');
    hub.connection.browser.connected = false;
    hub.connection.browser.emit('disconnected');
    const ledgerAfterDisconnect = JSON.parse(fs.readFileSync(ledgerFile, 'utf8'));
    assert.ok(ledgerAfterDisconnect.tabs.some(t => t.tab_id === tOther.tab_id),
      '_onDisconnected must persist restored lost record immediately');

    // Close noopener externally -> unclaimed active drops to 0 while total_observed remains 1
    await noopener.close();
    assert.equal(hub.status().unclaimed_pages.active, 0);
    assert.equal(hub.status().unclaimed_pages.total_observed, 1);

    allPages[0].closeError = null;
    const shut = await hub.shutdown({close_tabs: false});
    assert.equal(shut.unclaimed_pages_observed, 1);
    assert.equal(shut.unclaimed_pages_active, 0);
  } finally {
    fs.rmSync(tmpDir, {recursive: true, force: true});
  }
});

test('ff_browser_hub.mjs: backgroundCapability honors --playwright-root & config.json and integrity guard catches tampered coreBundle.js', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ff-p0-pw-int-'));
  try {
    // 1. config.json playwright_root resolution
    const cfgDir = path.join(tmpDir, 'state', 'hub');
    fs.mkdirSync(cfgDir, {recursive: true});
    const fakeRoot = path.join(tmpDir, 'custom-pw');
    fs.writeFileSync(path.join(cfgDir, 'config.json'), JSON.stringify({playwright_root: fakeRoot}));
    const prevEnv = process.env.FF_PLAYWRIGHT_ROOT;
    delete process.env.FF_PLAYWRIGHT_ROOT;
    try {
      const resolved = resolvePlaywrightRoot({configPaths: [path.join(cfgDir, 'config.json')]});
      assert.equal(resolved, path.resolve(fakeRoot));
    } finally {
      if (prevEnv !== undefined) process.env.FF_PLAYWRIGHT_ROOT = prevEnv;
    }

    // 2. Synthetic tampered coreBundle.js is rejected fail-closed by BOTH ff_browser_hub.mjs & cua_browser_playwright.mjs
    const tamperedRoot = path.join(tmpDir, 'tampered-pw');
    const bundleDir = path.join(tamperedRoot, 'node_modules', 'playwright-core', 'lib');
    fs.mkdirSync(bundleDir, {recursive: true});
    fs.writeFileSync(path.join(tamperedRoot, 'package.json'), JSON.stringify({name: 'tampered'}));
    const tamperedBundle = path.join(bundleDir, 'coreBundle.js');
    fs.writeFileSync(
      tamperedBundle,
      "const connectUrl = 'ws://127.0.0.1:9999/ext'; require('fs').writeFileSync('C:/Users/demo/ChatGPT_Conversation_Audit/pw_connect_url.txt', connectUrl);\n",
    );
    assert.throws(
      () => verifyPlaywrightCoreBundle(tamperedRoot),
      error => error instanceof HubError && error.code === 'PLAYWRIGHT_CORE_BUNDLE_TAMPERED' &&
        error.details.rules.includes('FORBIDDEN_DEBUG_ARTIFACT_NAME'),
    );
    assert.throws(
      () => verifyPlaywrightCoreBundleSync(tamperedBundle),
      error => error instanceof BrowserSidecarError && error.code === 'PLAYWRIGHT_CORE_BUNDLE_TAMPERED',
    );
    const blockedCap = await backgroundCapability(
      async () => ({chrome_versions: ['158.0.8127.2'], extension_version: '0.5.0'}),
      loadPlaywright,
      tamperedRoot,
    );
    assert.equal(blockedCap.available, false);
    assert.equal(blockedCap.reason, 'PLAYWRIGHT_CORE_BUNDLE_TAMPERED');

    // 3. Clean pw165 passes integrity + backgroundCapability + real CLI --preflight!
    if (PW165_ROOT) {
      assert.equal(verifyPlaywrightCoreBundle(PW165_ROOT).ok, true);
      const pw165Bundle = path.join(PW165_ROOT, 'node_modules', 'playwright-core', 'lib', 'coreBundle.js');
      assert.equal(verifyPlaywrightCoreBundleSync(pw165Bundle).ok, true);
      const cap = await backgroundCapability(
        async () => ({chrome_versions: ['158.0.8127.2'], extension_version: '0.5.0'}),
        loadPlaywright,
        PW165_ROOT,
      );
      assert.equal(cap.available, true);
      assert.equal(cap.playwright_version, '1.65.1');
      assert.equal(cap.live_verified, false);
      assert.equal(cap.token_checked, false);

      // Real subprocess CLI check (read-only preflight; never connects or reads tokens)
      const {stdout} = await execFileAsync(
        process.execPath,
        [HUB_SCRIPT, '--preflight', '--playwright-root', PW165_ROOT, '--state-dir', path.join(tmpDir, 'preflight-state')],
        {timeout: 15000, windowsHide: true},
      );
      const parsed = JSON.parse(stdout.trim());
      assert.equal(typeof parsed.available, 'boolean');
      assert.equal(parsed.live_verified, false);
      assert.equal(parsed.token_checked, false);
      assert.notEqual(parsed.reason, 'PLAYWRIGHT_NOT_INSTALLED');
      assert.notEqual(parsed.reason, 'PLAYWRIGHT_CORE_BUNDLE_TAMPERED');
      if (parsed.available) {
        assert.equal(parsed.playwright_version, '1.65.1');
      }
    }
  } finally {
    fs.rmSync(tmpDir, {recursive: true, force: true});
  }
});

test('REAL isolated headless Playwright 1.65.1 browser lifecycle with local 127.0.0.1 HTTP server', async t => {
  if (!PW165_ROOT) {
    t.skip('pw165 root not available');
    return;
  }
  const executablePath = findIsolatedBrowserExecutable();
  if (!executablePath) {
    t.skip('no local Chromium/Chrome/Edge executable available for isolated headless test');
    return;
  }

  const req = createRequire(path.join(PW165_ROOT, 'package.json'));
  const pw = req('playwright');
  const coreBundle = req('playwright-core/lib/coreBundle');
  const tmpProfileRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ff-p0-isolated-pw-'));

  const server = http.createServer((_req, res) => {
    res.writeHead(200, {'content-type': 'text/html; charset=utf-8'});
    res.end(`<!doctype html>
      <html><head><title>Isolated P0 Harness</title></head>
      <body>
        <input id="note" aria-label="Note input" />
        <button id="go">Apply</button>
        <p id="status">READY</p>
        <script>
          document.querySelector('#go').addEventListener('click', () => {
            document.querySelector('#status').textContent = 'DONE:' + document.querySelector('#note').value;
          });
        </script>
      </body></html>`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${server.address().port}/`;
  const prevRoot = process.env.FF_ISOLATED_BROWSER_PROFILE_ROOT;
  process.env.FF_ISOLATED_BROWSER_PROFILE_ROOT = tmpProfileRoot;

  try {
    const engine = new PlaywrightEngine(pw, coreBundle.tools);
    engine.isolatedOnly = true;
    const sidecar = new BrowserSidecar(engine);
    const attached = await sidecar.attach({headless: true});
    assert.equal(attached.capabilities.isolated_profile, true);
    assert.equal(attached.capabilities.headless, true);
    assert.equal(attached.capabilities.owner_browser, false);
    const sid = attached.surface_id;
    try {
      await sidecar.navigate(sid, url, 10000);
      const foundInput = await sidecar.find(sid, {role: 'textbox', text: 'Note input'});
      assert.equal(foundInput.matches.length, 1);
      const fillRes = await sidecar.act(sid, {
        ref: foundInput.matches[0].ref,
        generation: foundInput.generation,
        action: 'fill',
        args: {text: 'p0-verified'},
      });
      assert.equal(fillRes.verified, true);

      const foundBtn = await sidecar.find(sid, {role: 'button', text: 'Apply'});
      assert.equal(foundBtn.matches.length, 1);
      const clickRes = await sidecar.act(sid, {
        ref: foundBtn.matches[0].ref,
        generation: foundBtn.generation,
        action: 'click',
        verify: {text: 'DONE:p0-verified'},
      });
      assert.equal(clickRes.verified, true);
      assert.equal(clickRes.physical_input_used, false);
    } finally {
      const closed = await sidecar.close(sid);
      assert.equal(closed.ok, true);
      assert.equal(closed.cleanup.closed, true);
      assert.equal(closed.cleanup.managed_profile_removed, true);
    }
    assert.equal(fs.readdirSync(tmpProfileRoot).length, 0, 'temporary isolated profile dir must be removed');
  } finally {
    if (prevRoot === undefined) delete process.env.FF_ISOLATED_BROWSER_PROFILE_ROOT;
    else process.env.FF_ISOLATED_BROWSER_PROFILE_ROOT = prevRoot;
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(tmpProfileRoot, {recursive: true, force: true});
  }
});

test('extension transport declares visible_tab_strip=true, hidden_secondary_window_supported=false and fails closed on strict hidden secondary requests', async () => {
  // 1. backgroundCapability explicitly declares hidden_secondary_window_supported=false & visible_tab_strip=true
  const capOk = await backgroundCapability(
    async () => ({chrome_versions: ['158.0.8127.36'], extension_version: '0.5.0'}),
    () => ({backgroundSupported: true, version: '1.65.1'}),
  );
  assert.equal(capOk.available, true);
  assert.equal(capOk.hidden_secondary_window_supported, false);
  assert.equal(capOk.visible_tab_strip, true);

  const capBlocked = await backgroundCapability(
    async () => { throw new HubError('CHROME_NOT_RUNNING'); },
    () => ({backgroundSupported: true, version: '1.65.1'}),
  );
  assert.equal(capBlocked.available, false);
  assert.equal(capBlocked.hidden_secondary_window_supported, false);
  assert.equal(capBlocked.visible_tab_strip, true);

  // 2. extensionConnector.describe() declares flags and constructor refuses strict hidden secondary flags
  const fakeRuntimeLoader = () => ({
    version: '1.65.1',
    backgroundSupported: true,
    tools: {createBrowserWithInfo: async () => { throw new Error('must not connect'); }},
  });
  const extConn = extensionConnector({runtimeLoader: fakeRuntimeLoader});
  assert.equal(extConn.describe().hidden_secondary_window_supported, false);
  assert.equal(extConn.describe().visible_tab_strip, true);
  for (const flag of [{invisible_required: true}, {hidden_secondary: true}, {new_window_hidden: true}]) {
    assert.throws(
      () => extensionConnector({runtimeLoader: fakeRuntimeLoader, ...flag}),
      error => error instanceof HubError &&
        error.code === 'OWNER_CHROME_HIDDEN_SECONDARY_UNSUPPORTED_ON_TRANSPORT' &&
        error.details.hidden_secondary_window_supported === false &&
        error.details.visible_tab_strip === true &&
        error.details.isolated_fallback === false &&
        error.details.attempted === false,
    );
  }

  // 3. BrowserHub.status() declares flags and tabOpen/connect fail closed BEFORE connecting (0 connect calls!)
  let connectCalls = 0;
  const hub = new BrowserHub({
    describe: () => ({transport: 'playwright-extension', background: true, hidden_secondary_window_supported: false, visible_tab_strip: true}),
    async connect() { connectCalls++; throw new Error('must not connect'); },
  });
  const st = hub.status();
  assert.equal(st.hidden_secondary_window_supported, false);
  assert.equal(st.visible_tab_strip, true);
  for (const args of [
    {owner: 'agent-1', invisible_required: true},
    {owner: 'agent-1', hidden_secondary: true},
    {owner: 'agent-1', new_window_hidden: true},
    {owner: 'agent-1', window_mode: 'hidden_secondary'},
    {owner: 'agent-1', route: 'owner_chrome_profile1_hidden_secondary'},
  ]) {
    await assert.rejects(
      hub.tabOpen(args),
      error => error instanceof HubError &&
        error.code === 'OWNER_CHROME_HIDDEN_SECONDARY_UNSUPPORTED_ON_TRANSPORT' &&
        error.details.isolated_fallback === false &&
        error.details.attempted === false,
    );
    await assert.rejects(
      hub.connect(args),
      error => error instanceof HubError &&
        error.code === 'OWNER_CHROME_HIDDEN_SECONDARY_UNSUPPORTED_ON_TRANSPORT',
    );
  }
  assert.equal(connectCalls, 0, 'hub must fail closed BEFORE connecting or opening connect.html/about:blank');

  // 4. PlaywrightEngine.attach() & _connectOwnerExtension() fail closed BEFORE factory() call (0 connect.html / 0 about:blank!)
  let factoryCalls = 0;
  const engine = new PlaywrightEngine({}, {
    createBrowserWithInfo: async () => { factoryCalls++; throw new Error('must not invoke factory'); },
  });
  const prevToken = process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN;
  process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN = 'synthetic-unit-test-token-do-not-use-in-prod-9999';
  try {
    for (const extra of [
      {invisible_required: true},
      {invisibleRequired: true},
      {hidden_secondary: true},
      {hiddenSecondary: true},
      {new_window_hidden: true},
      {newWindowHidden: true},
      {window_mode: 'hidden_secondary'},
      {route_mode: 'owner_chrome_profile1_hidden_secondary'},
    ]) {
      await assert.rejects(
        engine.attach({ownerBrowser: true, ownerTransport: 'extension', ...extra}),
        error => error instanceof BrowserSidecarError &&
          error.code === 'OWNER_CHROME_HIDDEN_SECONDARY_UNSUPPORTED_ON_TRANSPORT' &&
          error.details.hidden_secondary_window_supported === false &&
          error.details.visible_tab_strip === true &&
          error.details.isolated_fallback === false &&
          error.details.attempted === false,
      );
    }
    assert.equal(factoryCalls, 0, 'extension factory must never be called when hidden secondary is requested');
    const caps = await engine.capabilities({ownerBrowser: true, ownerTransport: 'extension', background: true});
    assert.equal(caps.hidden_secondary_window_supported, false);
    assert.equal(caps.visible_tab_strip, true);
  } finally {
    if (prevToken === undefined) delete process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN;
    else process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN = prevToken;
  }
});
