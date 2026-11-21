#!/usr/bin/env node
import {execFileSync} from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import {createRequire} from 'node:module';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const PROFILE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const WINDOWS_DEVICE_RE = /^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)/i;

const OWNER_LOCALAPPDATA_SUBPATHS = [
  ['Google', 'Chrome', 'User Data'],
  ['Google', 'Chrome Beta', 'User Data'],
  ['Google', 'Chrome SxS', 'User Data'],
  ['Google', 'Chrome Dev', 'User Data'],
  ['Chromium', 'User Data'],
  ['Microsoft', 'Edge', 'User Data'],
  ['Microsoft', 'Edge Beta', 'User Data'],
  ['Microsoft', 'Edge Dev', 'User Data'],
  ['Microsoft', 'Edge SxS', 'User Data'],
  ['BraveSoftware', 'Brave-Browser', 'User Data'],
  ['Vivaldi', 'User Data'],
  ['Opera Software'],
  ['Mozilla', 'Firefox'],
  ['Yandex', 'YandexBrowser', 'User Data'],
  ['Arc', 'User Data'],
];

const OWNER_APPDATA_SUBPATHS = [
  ['Mozilla', 'Firefox'],
  ['Opera Software'],
];

const OWNER_POSIX_SUBPATHS = [
  ['.config', 'google-chrome'],
  ['.config', 'google-chrome-beta'],
  ['.config', 'google-chrome-unstable'],
  ['.config', 'chromium'],
  ['.config', 'microsoft-edge'],
  ['.config', 'BraveSoftware', 'Brave-Browser'],
  ['.config', 'vivaldi'],
  ['.mozilla', 'firefox'],
];

const OWNER_PROFILE_PATTERNS = [
  /(?:^|\/)google\/chrome(?:\s+(?:beta|dev|sxs))?\/user data(?:\/|$)/i,
  /(?:^|\/)chromium\/user data(?:\/|$)/i,
  /(?:^|\/)microsoft\/edge(?:\s+(?:beta|dev|sxs))?\/user data(?:\/|$)/i,
  /(?:^|\/)bravesoftware\/brave-browser\/user data(?:\/|$)/i,
  /(?:^|\/)vivaldi\/user data(?:\/|$)/i,
  /(?:^|\/)yandex\/yandexbrowser\/user data(?:\/|$)/i,
  /(?:^|\/)arc\/user data(?:\/|$)/i,
  /(?:^|\/)opera software(?:\/|$)/i,
  /(?:^|\/)mozilla\/firefox(?:\/|$)/i,
  /(?:^|\/)\.config\/(?:google-chrome(?:-(?:beta|unstable))?|chromium|microsoft-edge|bravesoftware\/brave-browser|vivaldi)(?:\/|$)/i,
  /(?:^|\/)\.mozilla\/firefox(?:\/|$)/i,
];

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

function stripExtendedPrefix(raw) {
  const value = String(raw || '');
  if (value.startsWith('\\\\?\\UNC\\')) return '\\\\' + value.slice(8);
  if (value.startsWith('\\\\?\\')) return value.slice(4);
  return value;
}

function normKey(p) {
  const cleaned = path.normalize(stripExtendedPrefix(p)).replace(/[\\/]+$/, '');
  return process.platform === 'win32' ? cleaned.toLowerCase() : cleaned;
}

function slashNorm(p) {
  return stripExtendedPrefix(p).replace(/\\/g, '/');
}

function pathOverlaps(a, b) {
  if (!a || !b) return true;
  if (a === b) return true;
  const sep = path.sep;
  return a.startsWith(b + sep) || b.startsWith(a + sep);
}

function getOwnerBrowserRoots() {
  const roots = new Set();
  const homeBases = new Set();
  for (const key of ['USERPROFILE', 'HOME']) {
    if (process.env[key]) homeBases.add(process.env[key]);
  }
  try { homeBases.add(os.homedir()); } catch {}

  const localBases = new Set();
  const roamingBases = new Set();
  if (process.env.LOCALAPPDATA) localBases.add(process.env.LOCALAPPDATA);
  if (process.env.APPDATA) roamingBases.add(process.env.APPDATA);

  for (const home of homeBases) {
    localBases.add(path.join(home, 'AppData', 'Local'));
    roamingBases.add(path.join(home, 'AppData', 'Roaming'));
    for (const sub of OWNER_POSIX_SUBPATHS) {
      roots.add(normKey(path.join(home, ...sub)));
    }
  }
  for (const base of localBases) {
    for (const sub of OWNER_LOCALAPPDATA_SUBPATHS) {
      roots.add(normKey(path.join(base, ...sub)));
    }
  }
  for (const base of roamingBases) {
    for (const sub of OWNER_APPDATA_SUBPATHS) {
      roots.add(normKey(path.join(base, ...sub)));
    }
  }
  return [...roots];
}

function isOwnerBrowserProfilePath(rawPath) {
  if (typeof rawPath !== 'string' || !rawPath || rawPath.includes('\0')) return true;
  const cleaned = stripExtendedPrefix(rawPath);
  const candidates = [cleaned, path.resolve(cleaned)];
  try { candidates.push(fs.realpathSync(cleaned)); } catch {}
  const ownerRoots = getOwnerBrowserRoots();
  for (const item of candidates) {
    const slash = slashNorm(item);
    if (OWNER_PROFILE_PATTERNS.some(re => re.test(slash))) return true;
    const key = normKey(item);
    for (const root of ownerRoots) {
      if (pathOverlaps(key, root)) return true;
    }
  }
  return false;
}

function assertNoLinksOnPath(targetPath) {
  const resolved = path.resolve(stripExtendedPrefix(targetPath));
  const root = path.parse(resolved).root;
  const rel = resolved.slice(root.length);
  const parts = rel.split(/[\\/]+/).filter(Boolean);
  let cur = root;
  let deepestExisting = null;
  for (const part of parts) {
    cur = path.join(cur, part);
    let stat;
    try { stat = fs.lstatSync(cur); } catch { continue; }
    if (stat.isSymbolicLink()) {
      let real = null;
      try { real = fs.realpathSync(cur); } catch {}
      if (real && isOwnerBrowserProfilePath(real)) {
        throw new ManagedError('OWNER_BROWSER_PROFILE_FORBIDDEN', 'symlink/junction resolves into owner browser profile', {path: targetPath});
      }
      throw new ManagedError('PROFILE_LINK_FORBIDDEN', 'symlinks and junctions are forbidden in isolated browser profiles', {path: cur});
    }
    deepestExisting = cur;
  }
  if (deepestExisting) {
    let real;
    try { real = fs.realpathSync(deepestExisting); } catch { real = deepestExisting; }
    if (normKey(real) !== normKey(deepestExisting)) {
      if (isOwnerBrowserProfilePath(real)) {
        throw new ManagedError('OWNER_BROWSER_PROFILE_FORBIDDEN', 'resolved path overlaps owner browser profile', {path: targetPath});
      }
      throw new ManagedError('PROFILE_LINK_FORBIDDEN', 'reparse point or link detected in isolated profile path', {path: deepestExisting});
    }
  }
  return resolved;
}

function isStrictlyInside(child, parent) {
  const childKey = normKey(child);
  const parentKey = normKey(parent);
  if (!childKey || !parentKey || childKey === parentKey) return false;
  return childKey.startsWith(parentKey + path.sep);
}

function validateProfileId(raw) {
  if (typeof raw !== 'string' || !PROFILE_ID_RE.test(raw) || raw.includes('..') || WINDOWS_DEVICE_RE.test(raw)) {
    throw new ManagedError('PROFILE_ID_INVALID', 'profile_id must be 1..64 ASCII [A-Za-z0-9_-] without traversal or reserved device names', {profile_id: raw});
  }
  return raw;
}

function validateIsolatedRoot(rawRoot) {
  if (typeof rawRoot !== 'string' || !rawRoot || rawRoot.includes('\0')) {
    throw new ManagedError('PROFILE_ROOT_INVALID', 'isolated profile root is invalid');
  }
  const cleaned = stripExtendedPrefix(rawRoot);
  if (cleaned.split(/[\\/]+/).includes('..')) {
    throw new ManagedError('PROFILE_PATH_TRAVERSAL', 'isolated profile root must not contain traversal segments');
  }
  if (isOwnerBrowserProfilePath(cleaned)) {
    throw new ManagedError('OWNER_BROWSER_PROFILE_FORBIDDEN', 'isolated profile root must never overlap an owner browser profile', {path: rawRoot});
  }
  return assertNoLinksOnPath(cleaned);
}

function resolveProfileSpec(args, persistentProfilesRoot, ephemeralProfilesRoot, id) {
  if (args.headless === false || args.foreground === true) {
    throw new ManagedError('FOREGROUND_ROUTE_REQUIRED', 'managed Playwright runs headless only and never falls back to foreground');
  }
  const rawId = args.profile_id !== undefined ? args.profile_id : args.profile_name;
  const rawDir = args.profile_dir;
  const wantPersistent = args.persistent_profile;

  if (wantPersistent !== undefined && typeof wantPersistent !== 'boolean') {
    throw new ManagedError('PROFILE_OPTION_INVALID', 'persistent_profile must be a boolean');
  }
  if (wantPersistent === false && (rawId !== undefined || rawDir !== undefined)) {
    throw new ManagedError('PROFILE_OPTION_CONFLICT', 'cannot combine persistent_profile=false with profile_id or profile_dir');
  }
  if (wantPersistent === true && rawId === undefined && rawDir === undefined) {
    throw new ManagedError('PROFILE_ID_REQUIRED', 'persistent_profile=true requires an explicit profile_id or isolated profile_dir');
  }
  if (rawId === undefined && rawDir === undefined) {
    return {
      persistent: false,
      profileId: null,
      profileDir: path.join(ephemeralProfilesRoot, id),
    };
  }

  const validatedId = rawId !== undefined ? validateProfileId(rawId) : null;
  if (rawDir !== undefined) {
    if (typeof rawDir !== 'string' || !rawDir || rawDir.includes('\0')) {
      throw new ManagedError('PROFILE_PATH_INVALID', 'profile_dir must be a non-empty absolute path');
    }
    const cleaned = stripExtendedPrefix(rawDir);
    if (cleaned.split(/[\\/]+/).includes('..')) {
      throw new ManagedError('PROFILE_PATH_TRAVERSAL', 'profile_dir must not contain path traversal segments', {profile_dir: rawDir});
    }
    if (isOwnerBrowserProfilePath(cleaned)) {
      throw new ManagedError('OWNER_BROWSER_PROFILE_FORBIDDEN', 'owner browser profile directories are strictly forbidden', {profile_dir: rawDir});
    }
    if (!path.isAbsolute(cleaned)) {
      throw new ManagedError('PROFILE_PATH_NOT_ABSOLUTE', 'profile_dir must be an absolute path', {profile_dir: rawDir});
    }
    const resolved = assertNoLinksOnPath(cleaned);
    if (isOwnerBrowserProfilePath(resolved)) {
      throw new ManagedError('OWNER_BROWSER_PROFILE_FORBIDDEN', 'owner browser profile directories are strictly forbidden', {profile_dir: rawDir});
    }
    if (!isStrictlyInside(resolved, persistentProfilesRoot)) {
      throw new ManagedError('PROFILE_OUTSIDE_ISOLATED_ROOT', 'profile_dir must stay strictly inside the isolated persistent profiles root', {
        profile_dir: resolved,
        isolated_root: persistentProfilesRoot,
      });
    }
    const base = path.basename(resolved);
    if (!base || WINDOWS_DEVICE_RE.test(base) || base.endsWith('.') || base.endsWith(' ')) {
      throw new ManagedError('PROFILE_ID_INVALID', 'invalid profile directory name', {profile_dir: rawDir});
    }
    if (validatedId !== null) {
      const expected = path.resolve(persistentProfilesRoot, validatedId);
      if (normKey(resolved) !== normKey(expected)) {
        throw new ManagedError('PROFILE_OPTION_CONFLICT', 'profile_dir does not match profile_id');
      }
      return {persistent: true, profileId: validatedId, profileDir: expected};
    }
    return {persistent: true, profileId: base, profileDir: resolved};
  }

  const candidate = assertNoLinksOnPath(path.resolve(persistentProfilesRoot, validatedId));
  if (isOwnerBrowserProfilePath(candidate)) {
    throw new ManagedError('OWNER_BROWSER_PROFILE_FORBIDDEN', 'owner browser profile directories are strictly forbidden');
  }
  if (!isStrictlyInside(candidate, persistentProfilesRoot)) {
    throw new ManagedError('PROFILE_OUTSIDE_ISOLATED_ROOT', 'resolved profile escaped isolated root');
  }
  return {persistent: true, profileId: validatedId, profileDir: candidate};
}

function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err?.code === 'EPERM';
  }
}

function forceKillProcessTree(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return;
  if (process.platform === 'win32') {
    try {
      execFileSync('taskkill.exe', ['/PID', String(pid), '/T', '/F'], {
        stdio: 'ignore',
        timeout: 5000,
        windowsHide: true,
      });
      return;
    } catch {}
  }
  try { process.kill(pid, 'SIGKILL'); } catch {}
}

async function waitPidExit(pid, timeoutMs = 5000) {
  if (!Number.isInteger(pid) || pid <= 0) return true;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!pidAlive(pid)) return true;
    await new Promise(r => setTimeout(r, 50));
  }
  return !pidAlive(pid);
}

async function inspectBrowserPids(context) {
  try {
    const browser = typeof context.browser === 'function' ? context.browser() : null;
    if (!browser || typeof browser.newBrowserCDPSession !== 'function') {
      return {browserPid: null, allPids: []};
    }
    const cdp = await browser.newBrowserCDPSession();
    try {
      const info = await cdp.send('SystemInfo.getProcessInfo');
      const list = Array.isArray(info?.processInfo) ? info.processInfo : [];
      const browserEntry = list.find(item => item?.type === 'browser' && Number.isInteger(item?.id));
      const allPids = [...new Set(list.map(item => item?.id).filter(id => Number.isInteger(id) && id > 0))];
      return {
        browserPid: browserEntry ? browserEntry.id : (allPids[0] || null),
        allPids,
      };
    } finally {
      await cdp.detach().catch(() => {});
    }
  } catch {
    return {browserPid: null, allPids: []};
  }
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
  const stateDir = validateIsolatedRoot(path.resolve(opts['state-dir'] || path.join(process.cwd(), 'managed-playwright')));
  const endpointFile = path.resolve(opts['endpoint-file'] || path.join(stateDir, 'endpoint.json'));
  const profilesRoot = path.join(stateDir, 'profiles');
  const persistentProfilesRoot = validateIsolatedRoot(
    path.resolve(opts['persistent-profiles-root'] || process.env.FF_MANAGED_PW_PERSISTENT_ROOT || path.join(stateDir, 'persistent-profiles'))
  );
  const downloadsRoot = path.join(stateDir, 'downloads');
  const locksRoot = path.join(stateDir, 'profile-locks');
  const ledgerFile = path.join(stateDir, 'ledger.json');
  fs.mkdirSync(profilesRoot, {recursive: true});
  fs.mkdirSync(persistentProfilesRoot, {recursive: true});
  fs.mkdirSync(downloadsRoot, {recursive: true});
  fs.mkdirSync(locksRoot, {recursive: true});

  const {pw, version: pwVersion} = loadPlaywright(playwrightRoot);
  const contexts = new Map();
  const stickyByOwner = new Map();
  const activeProfileDirs = new Map();
  let stopping = false;

  const profileLockPath = dir => {
    const digest = crypto.createHash('sha256').update(normKey(dir)).digest('hex').slice(0, 32);
    return path.join(locksRoot, `${digest}.lock.json`);
  };

  const acquireProfileLease = (dir, browserId, owner) => {
    const keyNorm = normKey(dir);
    if (activeProfileDirs.has(keyNorm)) {
      throw new ManagedError('PERSISTENT_PROFILE_IN_USE', 'persistent profile is already open in another session', {
        profile_dir: dir,
      });
    }
    const lockFile = profileLockPath(dir);
    if (fs.existsSync(lockFile)) {
      try {
        const existing = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
        if (existing?.pid && existing.pid !== process.pid && pidAlive(existing.pid)) {
          throw new ManagedError('PERSISTENT_PROFILE_IN_USE', 'persistent profile is locked by another live process', {
            profile_dir: dir,
            owner_pid: existing.pid,
          });
        }
      } catch (err) {
        if (err instanceof ManagedError) throw err;
      }
      try { fs.unlinkSync(lockFile); } catch {}
    }
    fs.writeFileSync(lockFile, JSON.stringify({
      pid: process.pid,
      browser_id: browserId,
      owner,
      profile_dir: dir,
      acquired_at: Date.now(),
    }), 'utf8');
    activeProfileDirs.set(keyNorm, browserId);
    return lockFile;
  };

  const releaseProfileLease = (dir, browserId) => {
    const keyNorm = normKey(dir);
    if (activeProfileDirs.get(keyNorm) === browserId) {
      activeProfileDirs.delete(keyNorm);
    }
    const lockFile = profileLockPath(dir);
    try {
      if (fs.existsSync(lockFile)) {
        const cur = JSON.parse(fs.readFileSync(lockFile, 'utf8'));
        if (cur?.pid === process.pid && cur?.browser_id === browserId) {
          fs.unlinkSync(lockFile);
        }
      }
    } catch {}
  };

  const persistLedger = () => {
    const data = {
      pid: process.pid,
      updated_at: Date.now(),
      persistent_profiles_root: persistentProfilesRoot,
      browsers: [...contexts.values()].map(ctx => ({
        browser_id: ctx.id,
        owner: ctx.owner,
        profile_dir: ctx.profileDir,
        persistent_profile: ctx.persistent,
        profile_id: ctx.profileId,
        child_pid: ctx.browserPid,
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

  // Clean up stale abandoned ephemeral profile/download dirs from any prior crashed instance.
  // Never deletes persistent profiles under persistentProfilesRoot.
  for (const entry of fs.readdirSync(profilesRoot, {withFileTypes: true})) {
    if (entry.isDirectory() && entry.name.startsWith('pw-')) {
      fs.rmSync(path.join(profilesRoot, entry.name), {recursive: true, force: true, maxRetries: 5, retryDelay: 50});
    }
  }
  for (const entry of fs.readdirSync(downloadsRoot, {withFileTypes: true})) {
    if (entry.isDirectory() && entry.name.startsWith('pw-')) {
      fs.rmSync(path.join(downloadsRoot, entry.name), {recursive: true, force: true, maxRetries: 5, retryDelay: 50});
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
      if (contexts.has(ctx.id)) persistLedger();
    });
    page.on('framenavigated', frame => {
      if (frame === page.mainFrame()) {
        tab.url = frame.url();
        if (contexts.has(ctx.id)) persistLedger();
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

    const pidInfo = await inspectBrowserPids(ctx.context).catch(() => ({browserPid: ctx.browserPid, allPids: ctx.knownPids || []}));
    const trackedPid = pidInfo.browserPid || ctx.browserPid || null;
    const trackedAll = [...new Set([...(ctx.knownPids || []), ...(pidInfo.allPids || []), ...(trackedPid ? [trackedPid] : [])])];

    // Graceful context close flushes cookies/localStorage to SQLite cleanly for persistent profiles.
    const livePages = (() => {
      try { return ctx.context.pages(); } catch { return []; }
    })();
    await Promise.race([
      ctx.context.close().catch(() => {}),
      new Promise(resolve => setTimeout(resolve, 10000)),
    ]);

    let childExited = true;
    if (trackedPid) {
      childExited = await waitPidExit(trackedPid, 5000);
      if (!childExited) {
        forceKillProcessTree(trackedPid);
        childExited = await waitPidExit(trackedPid, 4000);
      }
    }
    const leakedPids = [];
    for (const p of trackedAll) {
      if (pidAlive(p)) {
        forceKillProcessTree(p);
        const gone = await waitPidExit(p, 2000);
        if (!gone) leakedPids.push(p);
      }
    }
    if (leakedPids.length > 0) childExited = false;
    const pagesClosedVerified = livePages.every(p => p.isClosed()) && ctx.tabs.size === 0;
    ctx.tabs.clear();

    const downloadsCleaned = removeDirVerified(ctx.downloadsDir);
    let profileCleanupVerified;
    let profilePreserved = false;
    if (ctx.persistent) {
      releaseProfileLease(ctx.profileDir, ctx.id);
      profilePreserved = fs.existsSync(ctx.profileDir);
      profileCleanupVerified = childExited && downloadsCleaned && pagesClosedVerified && profilePreserved;
    } else {
      const removed = removeDirVerified(ctx.profileDir);
      profileCleanupVerified = childExited && removed && downloadsCleaned && pagesClosedVerified;
    }

    persistLedger();
    return {
      closed: true,
      browser_id: ctx.id,
      route: 'persistent_playwright',
      persistent_profile: ctx.persistent,
      profile_id: ctx.profileId,
      profile_dir: ctx.profileDir,
      profile_preserved: profilePreserved,
      profile_cleanup_verified: profileCleanupVerified,
      downloads_cleaned: downloadsCleaned,
      pages_closed_verified: pagesClosedVerified,
      child_pid: trackedPid,
      child_exited: childExited,
      leaked_pids: leakedPids,
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
        persistent_profiles_root: persistentProfilesRoot,
        active_browsers: [...contexts.values()].map(ctx => ({
          browser_id: ctx.id,
          owner: ctx.owner,
          persistent_profile: ctx.persistent,
          profile_id: ctx.profileId,
          child_pid: ctx.browserPid,
          tab_count: ctx.tabs.size,
        })),
      };
    }
    const owner = String(args.owner || '');
    if (!owner) throw new ManagedError('OWNER_REQUIRED');

    if (op === 'open') {
      const targetUrl = args.url ? checkUrl(args.url) : null;
      const id = 'pw-' + crypto.randomUUID().replace(/-/g, '').slice(0, 16);
      const spec = resolveProfileSpec(args, persistentProfilesRoot, profilesRoot, id);

      const existingId = stickyByOwner.get(owner);
      if (args.sticky !== false && existingId && contexts.has(existingId)) {
        const existing = contexts.get(existingId);
        const sameProfile = spec.persistent
          ? (existing.persistent && normKey(existing.profileDir) === normKey(spec.profileDir))
          : !existing.persistent;
        if (sameProfile) {
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
            persistent_profile: existing.persistent,
            profile_id: existing.profileId,
            profile_dir: existing.profileDir,
            child_pid: existing.browserPid,
            affinity_reused: true,
            tab_id: firstTab.id,
            target_id: firstTab.targetId,
            url: firstTab.url,
            title: firstTab.title,
            tabs: [...existing.tabs.values()].map(describeTab),
          };
        }
      }
      if ([...contexts.values()].filter(c => c.owner === owner).length >= 2) {
        throw new ManagedError('BROWSER_LIMIT_OWNER', 'owner already holds max persistent Playwright contexts');
      }
      if (contexts.size >= 10) {
        throw new ManagedError('BROWSER_LIMIT_TOTAL', 'managed Playwright pool is at capacity');
      }

      const profileDir = spec.profileDir;
      const downloadsDir = spec.persistent ? path.join(downloadsRoot, id) : path.join(profileDir, 'downloads');
      if (spec.persistent) {
        acquireProfileLease(profileDir, id, owner);
      }
      let context = null;
      try {
        fs.mkdirSync(profileDir, {recursive: true});
        fs.mkdirSync(downloadsDir, {recursive: true});
        const {executablePath} = resolveChromiumExecutable(pw);
        context = await pw.chromium.launchPersistentContext(profileDir, {
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
      } catch (err) {
        if (spec.persistent) releaseProfileLease(profileDir, id);
        else removeDirVerified(profileDir);
        removeDirVerified(downloadsDir);
        throw err;
      }

      const pidInfo = await inspectBrowserPids(context);
      const ctx = {
        id,
        owner,
        persistent: spec.persistent,
        profileId: spec.profileId,
        profileDir,
        downloadsDir,
        context,
        browserPid: pidInfo.browserPid,
        knownPids: pidInfo.allPids,
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
          persistent_profile: ctx.persistent,
          profile_id: ctx.profileId,
          profile_dir: ctx.profileDir,
          child_pid: ctx.browserPid,
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
      const unconfirmed = [];
      const errors = [];
      const preservedProfiles = [];
      for (const ctx of owned) {
        const res = await closeContextRecord(ctx);
        if (res.profile_preserved && res.profile_id) preservedProfiles.push(res.profile_id);
        if (res.profile_cleanup_verified) {
          closedCount++;
        } else {
          unconfirmed.push(ctx.id);
          errors.push({
            browser_id: ctx.id,
            code: res.child_exited ? 'PROFILE_CLEANUP_INCOMPLETE' : 'BROWSER_CHILD_STILL_ALIVE',
            child_exited: res.child_exited,
            leaked_pids: res.leaked_pids,
          });
        }
      }
      return {closed: closedCount, unconfirmed, errors, preserved_profiles: preservedProfiles};
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
        persistent_profile: ctx.persistent,
        profile_id: ctx.profileId,
        profile_dir: ctx.profileDir,
        child_pid: ctx.browserPid,
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
      const limit = Math.min(Math.max(Number(args.max_chars ?? 60000), 1000), 400000);
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
  const endpointPayload = {
    pid: process.pid,
    port: addr.port,
    playwright_version: pwVersion,
    persistent_profiles_root: persistentProfilesRoot,
  };
  const tmpEndpoint = `${endpointFile}.${crypto.randomUUID()}.tmp`;
  fs.writeFileSync(tmpEndpoint, JSON.stringify(endpointPayload), 'utf8');
  fs.renameSync(tmpEndpoint, endpointFile);

  let shutdownStarted = false;
  const shutdown = async (exitCode = 0) => {
    if (shutdownStarted) return;
    shutdownStarted = true;
    stopping = true;
    try { server.close(); } catch {}
    for (const ctx of [...contexts.values()]) {
      await closeContextRecord(ctx).catch(() => {
        if (ctx.browserPid) forceKillProcessTree(ctx.browserPid);
        if (ctx.persistent) releaseProfileLease(ctx.profileDir, ctx.id);
      });
    }
    try {
      if (fs.existsSync(endpointFile)) {
        const cur = JSON.parse(fs.readFileSync(endpointFile, 'utf8'));
        if (cur?.pid === process.pid) fs.unlinkSync(endpointFile);
      }
    } catch {}
    process.exit(exitCode);
  };

  const emergencyTeardown = () => {
    for (const ctx of [...contexts.values()]) {
      if (ctx.browserPid) forceKillProcessTree(ctx.browserPid);
      for (const p of ctx.knownPids || []) {
        if (pidAlive(p)) forceKillProcessTree(p);
      }
      if (ctx.persistent) releaseProfileLease(ctx.profileDir, ctx.id);
    }
  };

  process.stdin.resume();
  process.stdin.on('end', () => void shutdown(0));
  process.stdin.on('close', () => void shutdown(0));
  process.on('SIGINT', () => void shutdown(0));
  process.on('SIGTERM', () => void shutdown(0));
  process.on('uncaughtException', err => {
    console.error(err);
    emergencyTeardown();
    process.exit(1);
  });
  process.on('unhandledRejection', err => {
    console.error(err);
    emergencyTeardown();
    process.exit(1);
  });
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
