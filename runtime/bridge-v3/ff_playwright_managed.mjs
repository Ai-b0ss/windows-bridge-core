#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import {createRequire} from 'node:module';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

class ManagedError extends Error {
  constructor(code, message, details = {}) {
    super(message || code);
    this.code = code;
    this.details = details;
  }
}

function parseArgs(argv) {
  const out = {};
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--preflight') { out.preflight = true; continue; }
    if (arg.startsWith('--') && i + 1 < argv.length) {
      out[arg.slice(2)] = argv[++i];
    }
  }
  return out;
}

function loadPlaywright(playwrightRoot) {
  const searchPaths = [playwrightRoot, __dirname, process.cwd()].filter(Boolean);
  const resolved = require.resolve('playwright', {paths: searchPaths});
  const pkgPath = path.join(path.dirname(resolved), 'package.json');
  const pkg = fs.existsSync(pkgPath) ? JSON.parse(fs.readFileSync(pkgPath, 'utf8')) : {};
  return {pw: require(resolved), version: pkg.version || 'unknown', resolved};
}

function checkUrl(raw) {
  if (raw === undefined || raw === null || raw === '') return 'about:blank';
  let parsed;
  try { parsed = new URL(String(raw)); }
  catch { throw new ManagedError('URL_INVALID', 'give a complete http(s) URL', {url: raw}); }
  if (!['http:', 'https:'].includes(parsed.protocol) && parsed.href !== 'about:blank') {
    throw new ManagedError('URL_SCHEME_FORBIDDEN', 'only http(s) pages are automated', {scheme: parsed.protocol});
  }
  return parsed.href;
}

function safeDownloadFilename(raw) {
  const base = path.basename(String(raw || 'download.bin')).replace(/[^a-zA-Z0-9._-]/g, '_');
  return (base && !base.startsWith('.')) ? base.slice(0, 80) : 'download.bin';
}

function resolveChromiumExecutable(pw) {
  const defaultExe = typeof pw.chromium?.executablePath === 'function' ? pw.chromium.executablePath() : null;
  if (defaultExe && fs.existsSync(defaultExe)) return {executablePath: defaultExe, source: 'playwright_default'};
  const msRoot = process.env.LOCALAPPDATA ? path.join(process.env.LOCALAPPDATA, 'ms-playwright') : null;
  if (msRoot && fs.existsSync(msRoot)) {
    const dirs = fs.readdirSync(msRoot, {withFileTypes: true})
      .filter(d => d.isDirectory() && /^chromium_headless_shell-\d+$|^chromium-\d+$/.test(d.name))
      .sort((a, b) => (a.name.startsWith('chromium-') ? -1 : 1) - (b.name.startsWith('chromium-') ? -1 : 1) || b.name.localeCompare(a.name));
    for (const d of dirs) {
      const full = path.join(msRoot, d.name, 'chrome-win64', 'chrome.exe');
      const headlessShell = path.join(msRoot, d.name, 'chrome-headless-shell-win64', 'chrome-headless-shell.exe');
      if (fs.existsSync(full)) return {executablePath: full, source: d.name};
      if (fs.existsSync(headlessShell)) return {executablePath: headlessShell, source: d.name};
    }
  }
  for (const cand of [
    process.env.ProgramFiles && path.join(process.env.ProgramFiles, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    process.env['ProgramFiles(x86)'] && path.join(process.env['ProgramFiles(x86)'], 'Google', 'Chrome', 'Application', 'chrome.exe'),
  ].filter(Boolean)) {
    if (fs.existsSync(cand)) return {executablePath: cand, source: 'system_chrome'};
  }
  return {executablePath: defaultExe, source: 'missing'};
}

async function main() {
  const opts = parseArgs(process.argv);
  const playwrightRoot = opts['playwright-root'] || process.env.FF_PLAYWRIGHT_ROOT || __dirname;

  if (opts.preflight) {
    const t0 = Date.now();
    try {
      const {pw, version} = loadPlaywright(playwrightRoot);
      const {executablePath: exe, source} = resolveChromiumExecutable(pw);
      const exists = Boolean(exe && fs.existsSync(exe));
      console.log(JSON.stringify({
        ok: exists,
        route: 'persistent_playwright',
        playwright_version: version,
        chromium_executable: exe,
        chromium_source: source,
        chromium_exists: exists,
        probe_ms: Date.now() - t0,
      }));
      process.exit(exists ? 0 : 1);
    } catch (error) {
      console.log(JSON.stringify({
        ok: false,
        route: 'persistent_playwright',
        error_code: 'PLAYWRIGHT_UNAVAILABLE',
        message: String(error?.message || error),
        probe_ms: Date.now() - t0,
      }));
      process.exit(1);
    }
  }

  const key = process.env.FF_MANAGED_PW_KEY;
  if (!key || key.length < 24) throw new Error('FF_MANAGED_PW_KEY missing');
  const stateDir = path.resolve(opts['state-dir'] || path.join(process.cwd(), 'managed-playwright'));
  const endpointFile = path.resolve(opts['endpoint-file'] || path.join(stateDir, 'endpoint.json'));
  const profilesRoot = path.join(stateDir, 'profiles');
  const ledgerFile = path.join(stateDir, 'ledger.json');
  fs.mkdirSync(profilesRoot, {recursive: true});

  const {pw, version: pwVersion} = loadPlaywright(playwrightRoot);
  const contexts = new Map();
  const stickyByOwner = new Map();
  let stopping = false;

  const persistLedger = () => {
    const data = {
      pid: process.pid,
      updated_at: Date.now(),
      browsers: [...contexts.values()].map(ctx => ({
        browser_id: ctx.id,
        owner: ctx.owner,
        profile_dir: ctx.profileDir,
        tabs: [...ctx.tabs.values()].map(t => ({
          tab_id: t.id,
          target_id: t.targetId || null,
          url: t.url,
          title: t.title,
        })),
      })),
    };
    const tmp = `${ledgerFile}.${crypto.randomUUID()}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tmp, ledgerFile);
  };

  // Clean up stale abandoned profile directories from any prior crashed instance.
  for (const entry of fs.readdirSync(profilesRoot, {withFileTypes: true})) {
    if (entry.isDirectory() && entry.name.startsWith('pw-')) {
      fs.rmSync(path.join(profilesRoot, entry.name), {recursive: true, force: true, maxRetries: 5, retryDelay: 50});
    }
  }

  const removeDirVerified = dir => {
    if (!dir || !fs.existsSync(dir)) return true;
    try {
      fs.rmSync(dir, {recursive: true, force: true, maxRetries: 15, retryDelay: 100});
    } catch {}
    return !fs.existsSync(dir);
  };

  const getTabTargetId = async (context, page) => {
    try {
      const cdp = await context.newCDPSession(page);
      try {
        const info = await cdp.send('Target.getTargetInfo');
        return info?.targetInfo?.targetId || null;
      } finally {
        await cdp.detach().catch(() => {});
      }
    } catch {
      return null;
    }
  };

  const attachTab = async (ctx, page) => {
    const id = 'pwtab-' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
    const tab = {
      id,
      page,
      url: page.url() || 'about:blank',
      title: await page.title().catch(() => ''),
      targetId: await getTabTargetId(ctx.context, page),
      createdAt: Date.now(),
    };
    ctx.tabs.set(id, tab);
    page.on('close', () => {
      ctx.tabs.delete(id);
      persistLedger();
    });
    page.on('framenavigated', frame => {
      if (frame === page.mainFrame()) {
        tab.url = frame.url();
        persistLedger();
      }
    });
    return tab;
  };

  const describeTab = tab => ({
    tab_id: tab.id,
    target_id: tab.targetId || null,
    url: tab.page && !tab.page.isClosed() ? tab.page.url() : tab.url,
    title: tab.title,
    state: tab.page && !tab.page.isClosed() ? 'live' : 'closed',
    durable_identity: Boolean(tab.targetId),
  });

  const requireContext = (owner, browserId) => {
    const ctx = contexts.get(String(browserId || ''));
    if (!ctx) throw new ManagedError('BROWSER_NOT_FOUND', 'no such managed Playwright browser', {browser_id: browserId});
    if (ctx.owner !== owner) throw new ManagedError('BROWSER_NOT_OWNED', 'browser belongs to another agent', {browser_id: browserId});
    return ctx;
  };

  const requireTab = (ctx, tabId) => {
    const id = tabId ? String(tabId) : [...ctx.tabs.keys()][0];
    const tab = ctx.tabs.get(id || '');
    if (!tab || !tab.page || tab.page.isClosed()) {
      throw new ManagedError('TAB_NOT_FOUND', 'no live tab for managed browser', {tab_id: tabId});
    }
    return tab;
  };

  const locateTarget = async (page, target) => {
    if (!target || typeof target !== 'object') throw new ManagedError('TARGET_REQUIRED');
    let locator;
    if (typeof target.ref === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(target.ref)) {
      locator = page.locator(`aria-ref=${target.ref}`);
    } else if (typeof target.selector === 'string' && target.selector) {
      locator = page.locator(target.selector);
    } else if (typeof target.role === 'string') {
      locator = page.getByRole(target.role, target.name ? {name: target.name, exact: target.exact === true} : {});
    } else if (typeof target.label === 'string') {
      locator = page.getByLabel(target.label, {exact: target.exact === true});
    } else if (typeof target.text === 'string') {
      locator = page.getByText(target.text, {exact: target.exact === true});
    } else {
      throw new ManagedError('TARGET_REQUIRED', 'give ref, selector, role(+name), label or text');
    }
    const count = await locator.count();
    if (count === 0) throw new ManagedError('TARGET_NOT_FOUND', 'nothing matches target', {target});
    if (count > 1) throw new ManagedError('TARGET_AMBIGUOUS', 'several elements match target', {target, matches: count});
    return locator;
  };

  const checkPostcondition = async (page, condition, timeoutMs = 5000) => {
    if (!condition) return null;
    const deadline = Date.now() + Math.min(Math.max(Number(timeoutMs || 5000), 100), 30000);
    const evaluateOnce = async () => {
      if (typeof condition.url_contains === 'string') return page.url().includes(condition.url_contains);
      if (typeof condition.text_present === 'string') {
        return page.evaluate(txt => Boolean(document.body?.innerText.includes(txt)), condition.text_present);
      }
      if (typeof condition.text_absent === 'string') {
        return page.evaluate(txt => !document.body?.innerText.includes(txt), condition.text_absent);
      }
      if (condition.target) {
        const count = await (async () => {
          try {
            const loc = await locateTarget(page, condition.target);
            return loc ? 1 : 0;
          } catch (e) {
            if (e instanceof ManagedError && e.code === 'TARGET_NOT_FOUND') return 0;
            throw e;
          }
        })();
        if (count === 0) return condition.state === 'absent';
        if (condition.state === 'absent') return false;
        const loc = await locateTarget(page, condition.target);
        if (typeof condition.value === 'string') return (await loc.inputValue().catch(() => null)) === condition.value;
        if (typeof condition.checked === 'boolean') return (await loc.isChecked().catch(() => null)) === condition.checked;
        return true;
      }
      throw new ManagedError('POSTCONDITION_INVALID', 'unsupported postcondition');
    };
    while (true) {
      let ok = false;
      try { ok = await evaluateOnce(); }
      catch (e) { if (e instanceof ManagedError && e.code === 'POSTCONDITION_INVALID') throw e; }
      if (ok) return true;
      if (Date.now() >= deadline) return false;
      await new Promise(r => setTimeout(r, 100));
    }
  };

  const closeContextRecord = async ctx => {
    contexts.delete(ctx.id);
    if (stickyByOwner.get(ctx.owner) === ctx.id) stickyByOwner.delete(ctx.owner);
    try { await ctx.context.close(); } catch {}
    const cleaned = removeDirVerified(ctx.profileDir);
    persistLedger();
    return {
      closed: true,
      browser_id: ctx.id,
      route: 'persistent_playwright',
      profile_cleanup_verified: cleaned,
      downloads_cleaned: cleaned,
    };
  };

  async function handle(op, args = {}) {
    if (op === 'shutdown') {
      setTimeout(() => void shutdown(), 20);
      return {stopping: true};
    }
    if (stopping) throw new ManagedError('HUB_SHUTDOWN');
    if (op === 'status') {
      return {
        ok: true,
        connected: true,
        playwright_version: pwVersion,
        contexts: contexts.size,
        sticky_owners: stickyByOwner.size,
      };
    }
    const owner = String(args.owner || '');
    if (!owner) throw new ManagedError('OWNER_REQUIRED');

    if (op === 'open') {
      const targetUrl = args.url ? checkUrl(args.url) : null;
      const existingId = stickyByOwner.get(owner);
      if (args.sticky !== false && existingId && contexts.has(existingId)) {
        const existing = contexts.get(existingId);
        const firstTab = [...existing.tabs.values()][0] || await attachTab(existing, await existing.context.newPage());
        if (targetUrl) {
          await firstTab.page.goto(targetUrl, {waitUntil: 'domcontentloaded', timeout: 30000});
          firstTab.url = firstTab.page.url();
          firstTab.title = await firstTab.page.title().catch(() => '');
        }
        persistLedger();
        return {
          browser_id: existing.id,
          route: 'persistent_playwright',
          headless: true,
          isolated_profile: true,
          affinity_reused: true,
          tab_id: firstTab.id,
          target_id: firstTab.targetId,
          url: firstTab.url,
          title: firstTab.title,
          tabs: [...existing.tabs.values()].map(describeTab),
        };
      }
      if ([...contexts.values()].filter(c => c.owner === owner).length >= 2) {
        throw new ManagedError('BROWSER_LIMIT_OWNER', 'owner already holds max persistent Playwright contexts');
      }
      if (contexts.size >= 10) {
        throw new ManagedError('BROWSER_LIMIT_TOTAL', 'managed Playwright pool is at capacity');
      }
      const id = 'pw-' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
      const profileDir = path.join(profilesRoot, id);
      const downloadsDir = path.join(profileDir, 'downloads');
      fs.mkdirSync(downloadsDir, {recursive: true});
      const {executablePath} = resolveChromiumExecutable(pw);
      const context = await pw.chromium.launchPersistentContext(profileDir, {
        ...(executablePath && fs.existsSync(executablePath) ? {executablePath} : {}),
        headless: true,
        acceptDownloads: true,
        downloadsPath: downloadsDir,
        viewport: {width: 1280, height: 800},
        args: [
          '--no-first-run',
          '--no-default-browser-check',
          '--disable-background-timer-throttling',
          '--disable-renderer-backgrounding',
        ],
      });
      const ctx = {
        id,
        owner,
        profileDir,
        downloadsDir,
        context,
        tabs: new Map(),
        downloads: new Map(),
        createdAt: Date.now(),
      };
      contexts.set(id, ctx);
      stickyByOwner.set(owner, id);
      try {
        const page = context.pages()[0] || await context.newPage();
        const tab = await attachTab(ctx, page);
        if (targetUrl) {
          await page.goto(targetUrl, {waitUntil: 'domcontentloaded', timeout: 30000});
          tab.url = page.url();
          tab.title = await page.title().catch(() => '');
        }
        persistLedger();
        return {
          browser_id: id,
          route: 'persistent_playwright',
          headless: true,
          isolated_profile: true,
          affinity_reused: false,
          tab_id: tab.id,
          target_id: tab.targetId,
          url: tab.url,
          title: tab.title,
          tabs: [describeTab(tab)],
        };
      } catch (err) {
        await closeContextRecord(ctx).catch(() => {});
        throw err;
      }
    }

    if (op === 'close_owner') {
      const owned = [...contexts.values()].filter(c => c.owner === owner);
      let closedCount = 0;
      const errors = [];
      for (const ctx of owned) {
        const res = await closeContextRecord(ctx);
        if (res.profile_cleanup_verified) closedCount++;
        else errors.push({browser_id: ctx.id, code: 'PROFILE_CLEANUP_INCOMPLETE'});
      }
      return {closed: closedCount, errors};
    }

    const ctx = requireContext(owner, args.browser_id);
    if (op === 'close') return closeContextRecord(ctx);
    if (op === 'info') {
      return {
        browser_id: ctx.id,
        owner: ctx.owner,
        route: 'persistent_playwright',
        headless: true,
        isolated_profile: true,
        tabs: [...ctx.tabs.values()].map(describeTab),
        downloads: [...ctx.downloads.keys()],
      };
    }
    if (op === 'tabs') {
      return {tabs: [...ctx.tabs.values()].map(describeTab)};
    }
    if (op === 'tab_open') {
      if (ctx.tabs.size >= 8) throw new ManagedError('TAB_LIMIT_OWNER', 'max tabs per persistent context reached');
      const targetUrl = args.url ? checkUrl(args.url) : null;
      const page = await ctx.context.newPage();
      const tab = await attachTab(ctx, page);
      if (targetUrl) {
        await page.goto(targetUrl, {waitUntil: 'domcontentloaded', timeout: 30000});
        tab.url = page.url();
        tab.title = await page.title().catch(() => '');
      }
      persistLedger();
      return describeTab(tab);
    }
    if (op === 'tab_close') {
      const tab = requireTab(ctx, args.tab_id);
      await tab.page.close();
      ctx.tabs.delete(tab.id);
      persistLedger();
      return {tab_id: tab.id, closed: true, page_closed_in_browser: tab.page.isClosed()};
    }

    const tab = requireTab(ctx, args.tab_id);
    const page = tab.page;
    if (op === 'navigate') {
      const targetUrl = checkUrl(args.url);
      await page.goto(targetUrl, {waitUntil: 'domcontentloaded', timeout: Number(args.timeout_ms || 30000)});
      tab.url = page.url();
      tab.title = await page.title().catch(() => '');
      persistLedger();
      return describeTab(tab);
    }
    if (op === 'observe' || op === 'snapshot') {
      const limit = Math.min(Math.max(Number(args.max_chars ?? 60000), 1000), 400000);
      const tree = await page.locator('body').ariaSnapshot({mode: 'ai', timeout: 15000});
      tab.url = page.url();
      tab.title = await page.title().catch(() => '');
      return {
        tab_id: tab.id,
        url: tab.url,
        title: tab.title,
        format: 'aria-yaml-with-refs',
        truncated: tree.length > limit,
        snapshot: tree.slice(0, limit),
        route: 'persistent_playwright',
      };
    }
    if (op === 'read') {
      const limit = Math.min(Math.max(Number(args.max_chars ?? 60000), 100), 400000);
      const text = args.target
        ? await (await locateTarget(page, args.target)).evaluate(el => el.innerText ?? el.textContent ?? '')
        : await page.evaluate(() => document.body?.innerText ?? '');
      return {
        tab_id: tab.id,
        url: page.url(),
        title: await page.title().catch(() => ''),
        truncated: text.length > limit,
        text: text.slice(0, limit),
      };
    }
    if (op === 'act') {
      if (args.foreground === true) {
        throw new ManagedError('FOREGROUND_ROUTE_REQUIRED', 'managed Playwright never falls back to foreground');
      }
      const action = String(args.action || '');
      const needsTarget = action !== 'press' || args.target;
      const locator = needsTarget ? await locateTarget(page, args.target) : null;
      const timeoutMs = Math.min(Math.max(Number(args.timeout_ms || 15000), 500), 60000);
      if (action === 'click') await locator.click({timeout: timeoutMs});
      else if (action === 'fill') await locator.fill(String(args.value ?? ''), {timeout: timeoutMs});
      else if (action === 'select') {
        await locator.selectOption(Array.isArray(args.value) ? args.value.map(String) : String(args.value ?? ''), {timeout: timeoutMs});
      }
      else if (action === 'check') await locator.check({timeout: timeoutMs});
      else if (action === 'uncheck') await locator.uncheck({timeout: timeoutMs});
      else if (action === 'press') {
        const k = String(args.key || 'Enter');
        if (locator) await locator.press(k, {timeout: timeoutMs});
        else await page.keyboard.press(k);
      } else {
        throw new ManagedError('ACTION_UNSUPPORTED', `unsupported managed browser action: ${action}`);
      }
      tab.url = page.url();
      tab.title = await page.title().catch(() => '');
      const verified = args.postcondition ? await checkPostcondition(page, args.postcondition, args.timeout_ms) : true;
      if (args.postcondition && !verified) {
        throw new ManagedError('POSTCONDITION_FAILED', 'browser action postcondition was not met', {
          attempted: true, retry_safe: false, url: tab.url,
        });
      }
      return {
        ok: true,
        action,
        verified,
        tab_id: tab.id,
        url: tab.url,
        title: tab.title,
        physical_input_used: false,
        route: 'persistent_playwright',
      };
    }
    if (op === 'upload') {
      const filePath = path.resolve(String(args.path || ''));
      if (!path.isAbsolute(String(args.path || '')) || !fs.existsSync(filePath) || fs.lstatSync(filePath).isSymbolicLink()) {
        throw new ManagedError('UPLOAD_FILE_INVALID', 'upload requires an existing non-symlink file');
      }
      const locator = await locateTarget(page, args.target);
      await locator.setInputFiles(filePath);
      return {ok: true, tab_id: tab.id, uploaded: path.basename(filePath)};
    }
    if (op === 'download_prepare') {
      const timeoutMs = Math.min(Math.max(Number(args.timeout_ms || 15000), 500), 60000);
      const waitPromise = page.waitForEvent('download', {timeout: timeoutMs});
      if (args.target) {
        const locator = await locateTarget(page, args.target);
        await locator.click({timeout: timeoutMs});
      } else if (args.url) {
        await page.evaluate(u => {
          const a = document.createElement('a');
          a.href = u;
          a.download = '';
          document.body.appendChild(a);
          a.click();
          a.remove();
        }, checkUrl(args.url));
      }
      const download = await waitPromise;
      const downloadId = 'dl-' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
      const suggested = safeDownloadFilename(download.suggestedFilename());
      const dest = path.join(ctx.downloadsDir, `${downloadId}-${suggested}`);
      await download.saveAs(dest);
      const bytes = fs.readFileSync(dest);
      const sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
      const rec = {
        download_id: downloadId,
        filename: suggested,
        path: dest,
        size: bytes.length,
        sha256,
        url: download.url(),
      };
      ctx.downloads.set(downloadId, rec);
      return {
        download_id: downloadId,
        filename: suggested,
        size: bytes.length,
        sha256,
        url: download.url(),
        route: 'persistent_playwright',
      };
    }
    if (op === 'download_read') {
      const rec = ctx.downloads.get(String(args.download_id || ''));
      if (!rec || !fs.existsSync(rec.path)) {
        throw new ManagedError('DOWNLOAD_NOT_FOUND', 'unknown download_id', {download_id: args.download_id});
      }
      const offset = Math.max(0, Number(args.offset || 0));
      const limit = Math.min(Math.max(Number(args.limit || 262144), 1), 262144);
      const buf = fs.readFileSync(rec.path);
      const slice = buf.subarray(offset, offset + limit);
      return {
        download_id: rec.download_id,
        filename: rec.filename,
        size: buf.length,
        sha256: rec.sha256,
        offset,
        content_base64: slice.toString('base64'),
        eof: offset + slice.length >= buf.length,
      };
    }
    if (op === 'screenshot') {
      const buf = await page.screenshot({type: 'png', fullPage: args.full_page === true});
      const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
      return {
        tab_id: tab.id,
        image_mime: 'image/png',
        image_base64: buf.toString('base64'),
        image_sha256: sha256,
        url: page.url(),
        headless: true,
      };
    }
    if (op === 'evaluate') {
      if (typeof args.expression !== 'string' || !args.expression || args.expression.length > 32768) {
        throw new ManagedError('EVALUATE_EXPRESSION_INVALID');
      }
      const value = await page.evaluate(expr => (0, eval)(expr), args.expression);
      return {tab_id: tab.id, value: value === undefined ? null : value};
    }
    throw new ManagedError('OP_UNSUPPORTED', `unknown managed browser op: ${op}`);
  }

  const server = http.createServer(async (req, res) => {
    const authHeader = String(req.headers['x-ff-managed-key'] || '');
    const keyBuf = Buffer.from(key);
    const authBuf = Buffer.from(authHeader);
    if (keyBuf.length !== authBuf.length || !crypto.timingSafeEqual(keyBuf, authBuf)) {
      res.writeHead(403, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ok: false, error_code: 'MANAGED_PW_UNAUTHORIZED'}));
      return;
    }
    if (req.method !== 'POST' || req.url !== '/rpc') {
      res.writeHead(404);
      res.end();
      return;
    }
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
      total += chunk.length;
      if (total > 4 * 1024 * 1024) {
        res.writeHead(413);
        res.end();
        return;
      }
      chunks.push(chunk);
    }
    let reply;
    try {
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      const result = await handle(body.op, body.args || {});
      reply = {ok: true, result};
    } catch (error) {
      reply = {
        ok: false,
        error_code: error?.code || 'MANAGED_PW_ERROR',
        message: String(error?.message || error),
        details: error?.details || {},
      };
    }
    res.writeHead(200, {'Content-Type': 'application/json'});
    res.end(JSON.stringify(reply));
  });

  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  const endpointPayload = {pid: process.pid, port: addr.port, playwright_version: pwVersion};
  const tmpEndpoint = `${endpointFile}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(tmpEndpoint, JSON.stringify(endpointPayload), 'utf8');
  fs.renameSync(tmpEndpoint, endpointFile);

  let shutdownStarted = false;
  const shutdown = async () => {
    if (shutdownStarted) return;
    shutdownStarted = true;
    stopping = true;
    server.close();
    for (const ctx of [...contexts.values()]) {
      await closeContextRecord(ctx).catch(() => {});
    }
    try {
      if (fs.existsSync(endpointFile)) {
        const cur = JSON.parse(fs.readFileSync(endpointFile, 'utf8'));
        if (cur?.pid === process.pid) fs.unlinkSync(endpointFile);
      }
    } catch {}
    process.exit(0);
  };

  process.stdin.resume();
  process.stdin.on('end', () => void shutdown());
  process.stdin.on('close', () => void shutdown());
  process.on('SIGINT', () => void shutdown());
  process.on('SIGTERM', () => void shutdown());
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
