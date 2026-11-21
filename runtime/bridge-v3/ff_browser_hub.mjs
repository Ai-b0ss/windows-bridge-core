// FF Browser Session Manager.
//
// One long-lived process holds ONE authorised connection to the owner's signed-in Chrome
// (official Playwright extension + profile token, background mode) and hands out tabs to
// agents. Every tab has exactly one owner; an owner can reach only its own tabs. Nothing here
// activates a tab, focuses a window or sends physical input. Foreground actions must use
// the existing guarded Bridge route; this sidecar does not implement desktop grants.
//
// It never reads cookies or passwords, never launches Chrome with the owner's profile and
// never answers a Chrome prompt.
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import {execFile} from 'node:child_process';
import {createRequire} from 'node:module';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {promisify} from 'node:util';

export const VERSION = 1;
const MIN_BACKGROUND_PLAYWRIGHT = [1, 65, 0];
const MIN_BACKGROUND_CHROME = [158, 0, 8127, 2];
const MIN_BACKGROUND_EXTENSION = [0, 5, 0];
const PLAYWRIGHT_EXTENSION_ID = 'mmlmfjhmonkocbjadbfplnigmagldckm';
const execFileAsync = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const CORE_BUNDLE_INTEGRITY_RULES = [
  ['FORBIDDEN_DEBUG_ARTIFACT_NAME', /pw_connect_url/i],
  ['FORBIDDEN_AUDIT_PATH_LITERAL', /ChatGPT_Conversation_Audit/i],
  ['HARDCODED_WINDOWS_USER_PATH', /(?<![A-Za-z0-9_])[A-Za-z]:[/\\]{1,2}Users[/\\]{1,2}/i],
  ['HARDCODED_POSIX_USER_PATH', /\/Users\/[A-Za-z0-9._-]+\//],
  ['RAW_REQUIRE_FS_WRITE', /require\s*\(\s*['"](?:node:)?fs['"]\s*\)\s*\.\s*(?:writeFileSync|appendFileSync|writeFile|promises\s*\.\s*writeFile)/],
  ['SUSPICIOUS_FS_WRITE_CONNECT_OR_TOKEN', /(?:writeFileSync|appendFileSync|writeFile)\s*\([^;\n]{0,240}(?:connect|token|relay|pw_|audit|extension|ws:\/\/|chrome-extension:\/\/|\.txt\b)/i],
];

export function verifyPlaywrightCoreBundle(root) {
  const base = path.resolve(root || here);
  const bundlePath = path.join(base, 'node_modules', 'playwright-core', 'lib', 'coreBundle.js');
  let text;
  try {
    text = fs.readFileSync(bundlePath, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') {
      throw new HubError('PLAYWRIGHT_NOT_INSTALLED', 'pinned Playwright runtime is unavailable', {root: base, cause: 'ENOENT'});
    }
    throw new HubError('PLAYWRIGHT_CORE_BUNDLE_UNREADABLE', 'cannot read playwright-core coreBundle.js', {cause: brief(error)});
  }
  const rules = [];
  for (const [name, pattern] of CORE_BUNDLE_INTEGRITY_RULES) {
    if (pattern.test(text)) rules.push(name);
  }
  if (rules.length) {
    throw new HubError('PLAYWRIGHT_CORE_BUNDLE_TAMPERED', 'unauthorized local patch detected in playwright-core coreBundle.js', {rules});
  }
  return {ok: true, rules: []};
}

export function resolvePlaywrightRoot({playwrightRoot = null, stateDir = null, configPaths = null} = {}) {
  if (typeof playwrightRoot === 'string' && playwrightRoot.trim()) return path.resolve(playwrightRoot.trim());
  const cliOpt = option('playwright-root', null);
  if (typeof cliOpt === 'string' && cliOpt.trim()) return path.resolve(cliOpt.trim());
  if (typeof process.env.FF_PLAYWRIGHT_ROOT === 'string' && process.env.FF_PLAYWRIGHT_ROOT.trim()) {
    return path.resolve(process.env.FF_PLAYWRIGHT_ROOT.trim());
  }
  const candidates = Array.isArray(configPaths) ? configPaths : [
    ...(stateDir ? [path.join(stateDir, 'config.json'), path.join(path.dirname(stateDir), 'config.json')] : []),
    path.join(here, 'state', 'hub', 'config.json'),
    ...(process.env.FF_BRIDGE_ROOT ? [path.join(process.env.FF_BRIDGE_ROOT, 'state', 'hub', 'config.json')] : []),
    ...(process.env.LOCALAPPDATA ? [path.join(process.env.LOCALAPPDATA, 'FF-Windows-Bridge', 'state', 'hub', 'config.json')] : []),
  ];
  for (const file of candidates) {
    try {
      const data = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (typeof data?.playwright_root === 'string' && data.playwright_root.trim()) {
        return path.resolve(data.playwright_root.trim());
      }
    } catch {}
  }
  return here;
}

export class HubError extends Error {
  constructor(code, message = code, details = {}) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

const now = () => Date.now();
const newId = prefix => `${prefix}-${crypto.randomBytes(8).toString('hex')}`;
const brief = error => {
  let message = String(error?.message || error || '').split('\n')[0];
  const token = process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN;
  if (token) message = message.replaceAll(token, '[redacted]');
  return message.replace(/([?&](?:token|relayToken|extensionToken)=)[^&\s]+/gi, '$1[redacted]').slice(0, 300);
};

function versionAtLeast(version, minimum) {
  const parts = String(version || '').split(/[.-]/).slice(0, minimum.length).map(Number);
  for (let i = 0; i < minimum.length; i++) {
    if ((parts[i] || 0) > minimum[i]) return true;
    if ((parts[i] || 0) < minimum[i]) return false;
  }
  return true;
}

export function requireBackgroundChrome(versions) {
  if (!Array.isArray(versions) || !versions.length)
    throw new HubError('CHROME_NOT_RUNNING', 'background mode requires an already running Chrome; the Hub will not start it');
  if (versions.some(version => !/^\d+(?:\.\d+){3}$/.test(version) || !versionAtLeast(version, MIN_BACKGROUND_CHROME)))
    throw new HubError('BACKGROUND_CONNECT_UNSAFE', 'this Chrome cannot keep the extension connect page in the background',
      {required: MIN_BACKGROUND_CHROME.join('.'), versions});
  return {chrome_versions: versions, already_running: true};
}

// Upstream background-connect preconditions (extension >=0.5.0 is also required):
// https://github.com/microsoft/playwright-mcp/releases/tag/v0.0.85
// This read-only inventory runs before the extension factory, which otherwise can start
// Chrome or open its connect page in the foreground on older Chrome builds.
export function backgroundExtensionPreflight({userDataDir, profileDirName} = {}) {
  const root = userDataDir || (process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Google', 'Chrome', 'User Data'));
  if (!root) throw new HubError('BACKGROUND_EXTENSION_UNVERIFIED');
  if (profileDirName && !/^(Default|Profile [0-9]+)$/.test(profileDirName)) throw new HubError('OWNER_CHROME_PROFILE_INVALID');
  const readJson = file => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; } };
  let profiles;
  try {
    profiles = fs.readdirSync(root, {withFileTypes: true}).filter(entry => entry.isDirectory() && /^(Default|Profile [0-9]+)$/.test(entry.name))
      .map(entry => entry.name).sort((a, b) => (a === 'Default' ? -1 : Number(a.slice(8))) - (b === 'Default' ? -1 : Number(b.slice(8))));
  } catch { throw new HubError('BACKGROUND_EXTENSION_UNVERIFIED'); }
  const lastUsed = readJson(path.join(root, 'Local State'))?.profile?.last_used;
  if (profileDirName) profiles = profiles.includes(profileDirName) ? [profileDirName] : [];
  else if (profiles.includes(lastUsed)) profiles = [lastUsed, ...profiles.filter(profile => profile !== lastUsed)];
  for (const profile of profiles) {
    const records = ['Preferences', 'Secure Preferences'].map(file => readJson(path.join(root, profile, file))?.extensions?.settings?.[PLAYWRIGHT_EXTENSION_ID])
      .filter(record => record && typeof record === 'object' && Object.keys(record).length);
    // Match upstream's profile choice, including a stale extension directory. Do not skip
    // an unverifiable/old chosen profile and silently attach to a different signed-in one.
    if (!records.length && !fs.existsSync(path.join(root, profile, 'Extensions', PLAYWRIGHT_EXTENSION_ID))) continue;
    const versions = records.map(record => record.manifest?.version);
    if (!versions.length || versions.some(version => typeof version !== 'string' || !/^\d+\.\d+\.\d+$/.test(version)) ||
        records.some(record => record.state !== undefined && record.state !== 1))
      throw new HubError('BACKGROUND_EXTENSION_UNVERIFIED', 'cannot verify the enabled extension in the selected profile');
    if (versions.some(version => !versionAtLeast(version, MIN_BACKGROUND_EXTENSION)))
      throw new HubError('BACKGROUND_EXTENSION_UNSUPPORTED', 'the selected extension does not support background mode',
        {required: MIN_BACKGROUND_EXTENSION.join('.'), versions});
    return {profile_dir_name: profile, user_data_dir: root, extension_version: versions[0]};
  }
  throw new HubError('BACKGROUND_EXTENSION_UNVERIFIED', 'no verified Playwright extension in the selected profile');
}

function readProfileBinding(file) {
  if (!file) return null;
  try {
    const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (saved?.version !== 1 || !/^(Default|Profile [0-9]+)$/.test(saved.profile) || !/^[a-f0-9]{64}$/.test(saved.root_hash))
      throw new Error('invalid binding');
    return saved;
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw new HubError('OWNER_CHROME_PROFILE_BINDING_INVALID', 'the stored authorized profile cannot be verified');
  }
}

function verifiedProfileBinding(verified, requested, previous) {
  if (!/^(Default|Profile [0-9]+)$/.test(verified?.profile_dir_name) || typeof verified?.user_data_dir !== 'string')
    throw new HubError('BACKGROUND_EXTENSION_UNVERIFIED');
  const root = path.resolve(verified.user_data_dir);
  const rootHash = crypto.createHash('sha256').update(process.platform === 'win32' ? root.toLowerCase() : root).digest('hex');
  if ((requested && verified.profile_dir_name !== requested) ||
      (previous && (previous.profile !== verified.profile_dir_name || previous.root_hash !== rootHash)))
    throw new HubError('OWNER_CHROME_PROFILE_CHANGED', 'the verified Chrome profile differs from the persistent binding');
  return {version: 1, profile: verified.profile_dir_name, root_hash: rootHash};
}

export async function backgroundChromePreflight({profileDirName, profileBindingFile} = {}) {
  if (process.platform !== 'win32') throw new HubError('BACKGROUND_PREFLIGHT_UNAVAILABLE');
  let browsers;
  try {
    const {stdout} = await execFileAsync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
      "$ErrorActionPreference='Stop'; $browsers = @(Get-Process chrome -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne [IntPtr]::Zero } | ForEach-Object { try { $img = $_.MainModule; if ($img.FileName) { [pscustomobject]@{ version=$img.FileVersionInfo.ProductVersion; executable=$img.FileName } } } catch {} }); ConvertTo-Json -Compress -InputObject $browsers"],
    {windowsHide: true, timeout: 10000, maxBuffer: 65536});
    browsers = JSON.parse(stdout);
    if (!Array.isArray(browsers)) throw new Error('invalid Chrome inventory');
  } catch { throw new HubError('BACKGROUND_PREFLIGHT_UNAVAILABLE', 'cannot verify a background-safe existing Chrome'); }
  const chrome = requireBackgroundChrome([...new Set(browsers.map(item => item.version))]);
  const executables = new Set(browsers.map(item => path.resolve(item.executable).toLowerCase()));
  if (executables.size !== 1) throw new HubError('BACKGROUND_CHROME_EXECUTABLE_AMBIGUOUS');
  const binding = readProfileBinding(profileBindingFile);
  const profile = backgroundExtensionPreflight({profileDirName: binding?.profile || profileDirName});
  verifiedProfileBinding(profile, profileDirName, binding);
  return {...chrome, ...profile, executable_path: browsers[0].executable};
}

// Public capability probe: no connection, token read, profile path or profile content
// in its result. This is eligibility for connection, not live browser acceptance.
export async function backgroundCapability(
  preflight = backgroundChromePreflight,
  runtimeLoader = loadPlaywright,
  playwrightRoot = resolvePlaywrightRoot(),
) {
  const required = {chrome: MIN_BACKGROUND_CHROME.join('.'), extension: MIN_BACKGROUND_EXTENSION.join('.'),
    playwright: MIN_BACKGROUND_PLAYWRIGHT.join('.'), already_running: true};
  try {
    const verified = await preflight();
    const runtime = runtimeLoader(playwrightRoot);
    if (!runtime.backgroundSupported) throw new HubError('BACKGROUND_MODE_UNSUPPORTED');
    return {available: true, live_verified: false, token_checked: false, required,
      chrome_versions: verified.chrome_versions, extension_version: verified.extension_version, playwright_version: runtime.version};
  } catch (error) {
    const reason = error.code || 'BACKGROUND_PREFLIGHT_UNAVAILABLE';
    // The only supported remedy for an older Chrome is the owner's own ordinary update and
    // relaunch. The Hub never updates, restarts or reconfigures the owner's browser.
    return {available: false, live_verified: false, token_checked: false, required, reason, fallback: null,
      ...(reason === 'BACKGROUND_CONNECT_UNSAFE' ? {remedy: 'OWNER_CHROME_UPDATE_AND_RELAUNCH', automatic: false} : {})};
  }
}

export function loadPlaywright(root) {
  const base = path.resolve(root || here);
  verifyPlaywrightCoreBundle(base);
  const require = createRequire(path.join(base, 'package.json'));
  try {
    const version = require('playwright-core/package.json').version;
    const {tools} = require('playwright-core/lib/coreBundle');
    if (typeof tools?.createBrowserWithInfo !== 'function') throw new Error('extension factory missing');
    return {version, tools, backgroundSupported: versionAtLeast(version, MIN_BACKGROUND_PLAYWRIGHT)};
  } catch (error) {
    if (error instanceof HubError) throw error;
    throw new HubError('PLAYWRIGHT_NOT_INSTALLED', 'pinned Playwright runtime is unavailable', {root: base, cause: brief(error)});
  }
}

// The default connector: the official extension transport. Tests inject their own.
export function extensionConnector({playwrightRoot, profileDirName, clientName = 'FF Bridge agents', background = true,
  preflight = backgroundChromePreflight, runtimeLoader = loadPlaywright, profileBindingFile = null}) {
  const runtime = runtimeLoader(playwrightRoot);
  if (background && !runtime.backgroundSupported)
    throw new HubError('BACKGROUND_MODE_UNSUPPORTED', 'this Playwright cannot keep owner Chrome tabs in the background',
      {playwright: runtime.version, required: MIN_BACKGROUND_PLAYWRIGHT.join('.')});
  let binding = null;
  return {
    describe: () => ({transport: 'playwright-extension', playwright: runtime.version, background,
      owner_profile: binding?.profile || profileDirName || 'last-used', profile_pinned: Boolean(binding), isolated_profile: false}),
    async connect() {
      if (!process.env.PLAYWRIGHT_MCP_EXTENSION_TOKEN)
        throw new HubError('EXTENSION_TOKEN_UNAVAILABLE', 'the protected extension token was not injected into this process');
      let verified = null;
      if (background) {
        binding ??= readProfileBinding(profileBindingFile);
        const requested = binding?.profile || profileDirName;
        verified = await preflight({profileDirName: requested});
        const chosen = verifiedProfileBinding(verified, profileDirName || requested, binding);
        if (!binding) {
          if (profileBindingFile) {
            try {
              fs.writeFileSync(`${profileBindingFile}.tmp`, JSON.stringify(chosen));
              fs.renameSync(`${profileBindingFile}.tmp`, profileBindingFile);
            } catch {
              throw new HubError('OWNER_CHROME_PROFILE_BINDING_WRITE_FAILED', 'failed to keep the verified Chrome profile binding');
            }
          }
          binding = chosen;
        }
      }
      const config = {extension: true, background, tabGroup: true,
        browser: {browserName: 'chromium', launchOptions: {channel: 'chrome'}, contextOptions: {}}};
      const cliOptions = {extension: true, browser: 'chrome'};
      if (verified?.executable_path) cliOptions.executablePath = verified.executable_path;
      if (verified?.user_data_dir) config.browser.userDataDir = verified.user_data_dir;
      if (verified?.profile_dir_name || profileDirName) cliOptions.profileDirName = verified?.profile_dir_name || profileDirName;
      const info = await runtime.tools.createBrowserWithInfo(config, {cwd: process.cwd(), clientName},
        cliOptions, {title: `ff-browser-hub-${process.pid}`});
      const context = info.browser.contexts()[0];
      if (!context) throw new Error('extension returned no browser context');
      // Existing context pages are not ours. In particular, never sweep them on shutdown:
      // the extension can expose an initial owner tab as well as its own connect page.
      return {browser: info.browser, context};
    },
  };
}

// Runs in the page. DOM-level activation: works in a hidden tab and never needs the tab to be shown.
function domClick(element) {
  element.scrollIntoView({block: 'center', inline: 'center'});
  const box = element.getBoundingClientRect();
  const init = {bubbles: true, cancelable: true, composed: true, view: window, button: 0,
    clientX: box.left + box.width / 2, clientY: box.top + box.height / 2};
  for (const [type, ctor] of [['pointerover', 'PointerEvent'], ['mouseover', 'MouseEvent'],
    ['pointerdown', 'PointerEvent'], ['mousedown', 'MouseEvent']])
    element.dispatchEvent(new window[ctor](type, {...init, buttons: 1}));
  if (typeof element.focus === 'function') element.focus({preventScroll: true});
  for (const [type, ctor] of [['pointerup', 'PointerEvent'], ['mouseup', 'MouseEvent']])
    element.dispatchEvent(new window[ctor](type, init));
  element.click();
}

function domPress(element, key) {
  const target = element || document.activeElement || document.body;
  const init = {key, code: key.length === 1 ? `Key${key.toUpperCase()}` : key, bubbles: true, cancelable: true, composed: true};
  const proceed = target.dispatchEvent(new KeyboardEvent('keydown', init));
  target.dispatchEvent(new KeyboardEvent('keyup', init));
  if (proceed && key === 'Enter' && target.form && typeof target.form.requestSubmit === 'function') {
    target.form.requestSubmit();
    return 'form_submitted';
  }
  return proceed ? 'dispatched' : 'prevented_by_page';
}

function domFill(element, value) {
  if (element.readOnly) return {error: 'TARGET_NOT_EDITABLE'};
  const view = element.ownerDocument.defaultView;
  const input = element instanceof view.HTMLInputElement;
  const textarea = element instanceof view.HTMLTextAreaElement;
  if (input && ['button', 'submit', 'reset', 'image', 'checkbox', 'radio', 'file', 'hidden'].includes(element.type))
    return {error: 'TARGET_NOT_EDITABLE'};
  if (!input && !textarea && !element.isContentEditable) return {error: 'TARGET_NOT_EDITABLE'};
  element.focus({preventScroll: true});
  if (element.isContentEditable) element.textContent = value;
  else {
    const prototype = textarea ? view.HTMLTextAreaElement.prototype : view.HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(prototype, 'value').set.call(element, value);
  }
  element.dispatchEvent(new view.InputEvent('input', {bubbles: true, composed: true, inputType: 'insertText', data: value}));
  element.dispatchEvent(new view.Event('change', {bubbles: true}));
  return {mode: 'dom-value-setter'};
}

export class BrowserHub {
  constructor(connector, {maxTabsPerOwner = 8, maxTabs = 32, failureThreshold = 4, circuitOpenMs = 120000,
    backoffBaseMs = 1000, backoffMaxMs = 60000, artifactDir = null, ledgerFile = null, clock = now} = {}) {
    this.connector = connector;
    this.limits = {maxTabsPerOwner, maxTabs};
    this.policy = {failureThreshold, circuitOpenMs, backoffBaseMs, backoffMaxMs};
    this.artifactDir = artifactDir;
    this.clock = clock;
    this.tabs = new Map();
    this._unclaimedPages = new Map();
    this.connection = null;
    this.connecting = null;
    this.generation = 0;
    this.failures = 0;
    this.nextAttemptAt = 0;
    this.circuitOpenUntil = 0;
    this.lastError = null;
    this.stats = {connects: 0, disconnects: 0, operations: 0, started_at: clock()};
    this.stopping = false;
    this.shutdownPromise = null;
    this.ledgerFile = ledgerFile;
    this.ledgerError = null;
    this.ledgerLoadError = null;
    for (const [name, value] of Object.entries(this.limits))
      if (!Number.isSafeInteger(value) || value < 1) throw new HubError('LIMIT_INVALID', name);
    this._loadLedger();
  }

  // ---- durable tab ledger --------------------------------------------------------------
  // Survives a hard crash of this process. It records which agent owns which Chrome target.
  // The CDP target id is a random identifier minted by the browser for one tab; an exact match
  // is the only accepted proof that a page seen after a restart is the page this hub opened.
  // URL and title are never used as proof. A record without a match stays `lost`.
  _loadLedger() {
    if (!this.ledgerFile) return;
    let stored;
    try { stored = JSON.parse(fs.readFileSync(this.ledgerFile, 'utf8')); }
    catch (error) {
      if (error?.code !== 'ENOENT') this._ledgerUnreadable();
      return;
    }
    if (stored?.version !== 1 || !Array.isArray(stored.tabs)) { this._ledgerUnreadable(); return; }
    for (const item of stored.tabs) {
      if (!item || typeof item.tab_id !== 'string' || !/^tab-[0-9a-f]{16}$/.test(item.tab_id) ||
          typeof item.owner !== 'string' || !item.owner || this.tabs.has(item.tab_id)) continue;
      this.tabs.set(item.tab_id, {id: item.tab_id, owner: item.owner, generation: 0, state: 'lost', page: null,
        url: typeof item.url === 'string' ? item.url : 'about:blank', title: '', created_at: Number(item.created_at) || 0,
        last_used_at: Number(item.created_at) || 0, opened_by: typeof item.opened_by === 'string' ? item.opened_by : null,
        target_id: typeof item.target_id === 'string' && /^[0-9A-Za-z-]{8,64}$/.test(item.target_id) ? item.target_id : null,
        open_uncertain: item.open_uncertain === true, orphaned: true, lost_at: this.clock(), lane: Promise.resolve()});
    }
  }

  // Keep the damaged file as evidence; later writes start a new ledger beside it.
  _ledgerUnreadable() {
    this.ledgerLoadError = 'TAB_LEDGER_UNREADABLE';
    try { fs.renameSync(this.ledgerFile, `${this.ledgerFile}.unreadable`); } catch {}
  }

  _persist() {
    if (!this.ledgerFile) return;
    const tabs = this._heldTabs().map(tab => ({tab_id: tab.id, owner: tab.owner, target_id: tab.target_id ?? null,
      url: tab.url, created_at: tab.created_at, opened_by: tab.opened_by,
      ...(tab.open_uncertain ? {open_uncertain: true} : {})}));
    const body = JSON.stringify({version: 1, tabs});
    if (body === this._ledgerBody) return;
    try {
      fs.writeFileSync(`${this.ledgerFile}.tmp`, body);
      fs.renameSync(`${this.ledgerFile}.tmp`, this.ledgerFile);
      this._ledgerBody = body;
      this.ledgerError = null;
    } catch { this.ledgerError = 'TAB_LEDGER_WRITE_FAILED'; }
  }

  async _targetId(connection, page) {
    const valid = id => typeof id === 'string' && /^[0-9A-Za-z-]{8,64}$/.test(id);
    // The official Playwright Extension 0.5.0 uses chrome.debugger.sendCommand
    // on its *already attached tab*, and receives Target.getTargetInfo there.
    // The public newCDPSession(page) API instead tries attaching to the browser
    // target, which Chrome rejects with 'Not allowed'. With in-process
    // Playwright 1.65+, we can read that exact existing target identity from
    // the CRPage delegate without issuing a new debugger command or accessing
    // other tabs. This internal API is deliberately fail-closed if it changes.
    try {
      const bridge = page?._connection;
      if (typeof bridge?.toImpl === 'function') {
        const impl = bridge.toImpl(page);
        const context = bridge.toImpl(page.context());
        const delegate = impl?.delegate;
        if (impl?.browserContext === context && delegate?._page === impl &&
            delegate?.constructor?.name === 'CRPage' && valid(delegate._targetId))
          return delegate._targetId;
      }
    } catch { /* Not an in-process / matching Playwright page. */ }
    if (typeof connection?.context?.newCDPSession !== 'function') return null;
    let session = null;
    try {
      session = await connection.context.newCDPSession(page);
      const id = (await session.send('Target.getTargetInfo'))?.targetInfo?.targetId;
      return valid(id) ? id : null;
    } catch { return null; }
    finally { await session?.detach?.().catch(() => {}); }
  }

  async _identify(tab, connection, page) {
    tab.target_id = await this._targetId(connection, page);
    this._persist();
  }

  // A new extension relay initially owns a fresh connect.html tab. The official
  // extension has permissions to enumerate Chrome debugger targets, but Playwright's
  // public API does not offer a tab-picker RPC. Through this *existing authenticated*
  // extension page only, move precisely one ledger-owned, detached target into
  // this relay's Playwright group. The extension's own group-change listener then
  // attaches it and emits a normal Playwright Page. No URLs, titles or tab indices
  // are used to identify the recovery candidate. This code is never exposed as
  // a generic agent operation; a duplicate target-id record is rejected.
  async _bringBackExtensionTab(connection, tab) {
    if (this.connector.describe()?.transport !== 'playwright-extension' ||
        typeof tab.target_id !== 'string' || !/^[0-9A-Za-z-]{8,64}$/.test(tab.target_id))
      return false;
    if ([...this.tabs.values()].some(other => other !== tab &&
        other.state !== 'closed' && other.target_id === tab.target_id))
      return false;
    const seed = connection.context.pages().find(page => {
      try {
        const url = new URL(page.url());
        return url.protocol === 'chrome-extension:' &&
          url.hostname === 'mmlmfjhmonkocbjadbfplnigmagldckm' && url.pathname === '/connect.html';
      } catch { return false; }
    });
    if (!seed || seed.isClosed()) return false;
    let adopted = false;
    try {
      adopted = await seed.evaluate(async wantedId => {
        const extension = 'mmlmfjhmonkocbjadbfplnigmagldckm';
        if (location.protocol !== 'chrome-extension:' || location.hostname !== extension ||
            location.pathname !== '/connect.html' || chrome.runtime?.id !== extension)
          return false;
        if (typeof chrome.debugger?.getTargets !== 'function' ||
            typeof chrome.tabs?.group !== 'function')
          return false;
        const seedTab = await chrome.tabs.getCurrent();
        if (!seedTab || !Number.isSafeInteger(seedTab.id) ||
            !Number.isSafeInteger(seedTab.groupId) || seedTab.groupId < 0)
          return false;
        const group = await chrome.tabGroups.get(seedTab.groupId);
        if (group.windowId !== seedTab.windowId ||
            !String(group.title || '').startsWith('Playwright · '))
          return false;
        const matches = (await chrome.debugger.getTargets()).filter(t =>
          t.id === wantedId && t.type === 'page' && Number.isSafeInteger(t.tabId));
        if (matches.length !== 1 || matches[0].attached) return false;
        const source = await chrome.tabs.get(matches[0].tabId);
        if (source.windowId !== seedTab.windowId || source.id === seedTab.id || source.active !== false ||
            source.groupId === seedTab.groupId ||
            !/^(https?:|about:blank)/.test(source.url || ''))
          return false;
        // The official extension refuses a tab held by another client; also
        // explicitly reject it *before* changing the tab's group.
        const status = await chrome.runtime.sendMessage({type: 'getConnectionStatus'});
        if (!Array.isArray(status?.connections) || status.connections.some(c =>
            c.connectedTabIds?.includes(source.id))) return false;
        // This is the only mutation. The extension reacts to the group move,
        // attaches the exact tab, and publishes a new Page in this connection.
        await chrome.tabs.group({tabIds: [source.id], groupId: seedTab.groupId});
        return true;
      }, tab.target_id);
    } catch { return false; }
    if (!adopted) return false;
    // Page events from the extension are asynchronous; await bounded delivery.
    for (let attempt = 0; attempt < 30; attempt++) {
      if (this.connection !== connection || !connection.browser.isConnected()) return false;
      const visible = connection.context.pages();
      for (const page of visible) {
        if (page.isClosed()) continue;
        if (await this._targetId(connection, page) === tab.target_id) return true;
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    return false;
  }

  // Find the physical page of a lost tab by exact target id. Never adopts a page that another
  // record holds, and never matches by address.
  async _reattach(tab) {
    if (!tab.target_id) return false;
    let connection;
    try { connection = await this._ensureConnected(); } catch { return false; }
    const held = new Set([...this.tabs.values()].map(other => other.page).filter(Boolean));
    if (!(await (async () => {
      for (const page of connection.context.pages())
        if (!page.isClosed() && !held.has(page) &&
            await this._targetId(connection, page) === tab.target_id) return true;
      return false;
    })())) await this._bringBackExtensionTab(connection, tab);
    for (const page of connection.context.pages()) {
      if (held.has(page) || page.isClosed()) continue;
      if (await this._targetId(connection, page) !== tab.target_id) continue;
      if (tab.state !== 'lost' || this.connection !== connection) return false;
      tab.generation = connection.generation;
      this._wire(tab, page);
      tab.url = page.url();
      tab.orphaned = false;
      tab.reattached_at = this.clock();
      this._persist();
      return true;
    }
    return false;
  }

  // Proof of absence needs a transport that lists every target of the browser. The extension
  // relay exposes only attached tabs, so it does not offer this and the answer stays unknown.
  async _targetGone(tab) {
    if (!tab.target_id) return false;
    const connection = this.connection;
    if (!connection?.browser.isConnected() || typeof connection.listTargetIds !== 'function') return false;
    try {
      const ids = await connection.listTargetIds();
      return Array.isArray(ids) && !ids.includes(tab.target_id);
    } catch { return false; }
  }

  // ---- connection ----------------------------------------------------------------------
  async _ensureConnected() {
    if (this.stopping) throw new HubError('HUB_SHUTDOWN');
    if (this.connection?.browser.isConnected()) return this.connection;
    if (this.connecting) return this.connecting;
    const at = this.clock();
    if (at < this.circuitOpenUntil)
      throw new HubError('BROWSER_CONNECT_CIRCUIT_OPEN', 'repeated connection failures; not retrying yet',
        {retry_after_ms: this.circuitOpenUntil - at, last_error: this.lastError, retry_safe: true});
    if (at < this.nextAttemptAt)
      throw new HubError('BROWSER_CONNECT_BACKOFF', 'waiting before the next connection attempt',
        {retry_after_ms: this.nextAttemptAt - at, last_error: this.lastError, retry_safe: true});
    this.connecting = (async () => {
      try {
        const connection = await this.connector.connect();
        this.generation++;
        connection.generation = this.generation;
        connection.browser.on('disconnected', () => this._onDisconnected(connection));
        connection.context.on('page', page => this._onUnclaimedPage(connection, page));
        this.connection = connection;
        this.failures = 0;
        this.lastError = null;
        this.stats.connects++;
        return connection;
      } catch (error) {
        this.failures++;
        this.lastError = {code: error?.code || 'BROWSER_CONNECT_FAILED', message: brief(error), at: this.clock()};
        const delay = Math.min(this.policy.backoffBaseMs * 2 ** (this.failures - 1), this.policy.backoffMaxMs);
        this.nextAttemptAt = this.clock() + delay;
        if (this.failures >= this.policy.failureThreshold) this.circuitOpenUntil = this.clock() + this.policy.circuitOpenMs;
        if (error instanceof HubError) throw error;
        throw new HubError('BROWSER_CONNECT_FAILED', 'owner Chrome connection could not be established',
          {cause: brief(error), failures: this.failures, retry_after_ms: delay, retry_safe: true, isolated_fallback: false});
      } finally {
        this.connecting = null;
      }
    })();
    return this.connecting;
  }

  _onDisconnected(connection) {
    if (this.connection !== connection) return;
    this.connection = null;
    this.stats.disconnects++;
    for (const tab of this.tabs.values()) {
      if (tab.generation !== connection.generation) continue;
      const droppedWithConnection = tab.state === 'closed' && typeof tab.closed_by_browser_at === 'number' && this.clock() - tab.closed_by_browser_at < 5000;
      if (!['live', 'opening'].includes(tab.state) && !droppedWithConnection) continue;
      tab.state = 'lost';
      tab.lost_at = this.clock();
      tab.page = null;
    }
    // page.on('close') can fire right before browser.on('disconnected') and erase
    // the tab from the ledger; re-persist recovered 'lost' records immediately.
    this._persist();
  }

  _safePageUrl(page) {
    try {
      const raw = String(page?.url?.() ?? '');
      if (raw.startsWith(`chrome-extension://${PLAYWRIGHT_EXTENSION_ID}/connect.html`)) {
        return '[playwright-extension-connect]';
      }
      return raw.replace(/([?&](?:token|relayToken|extensionToken)=)[^&\s]+/gi, '$1[redacted]');
    } catch { return ''; }
  }

  _onUnclaimedPage(connection, page) {
    // Popups are claimed through their opener (see _wire). Pages opened via _openPage are
    // removed from _unclaimedPages as soon as _wire attaches them. Anything else (such as
    // target="_blank" rel="noopener" pages) is audited without adopting or closing foreign pages.
    if (!page || [...this.tabs.values()].some(tab => tab.page === page)) return;
    const record = {
      generation: connection?.generation ?? 0,
      url: this._safePageUrl(page),
      target_id: null,
      detected_at: this.clock(),
      closed: Boolean(page.isClosed?.()),
      closed_at: null,
    };
    this._unclaimedPages.set(page, record);
    if (this._unclaimedPages.size > 64) {
      for (const [candidate, entry] of this._unclaimedPages) {
        if (entry.closed) {
          this._unclaimedPages.delete(candidate);
          if (this._unclaimedPages.size <= 64) break;
        }
      }
    }
    if (typeof page.on === 'function') {
      page.on('close', () => {
        const current = this._unclaimedPages.get(page);
        if (current) {
          current.closed = true;
          current.closed_at = this.clock();
        }
      });
      page.on('framenavigated', frame => {
        const current = this._unclaimedPages.get(page);
        if (current && typeof page.mainFrame === 'function' && frame === page.mainFrame()) {
          current.url = this._safePageUrl(page);
        }
      });
    }
    void this._targetId(connection, page).then(targetId => {
      const current = this._unclaimedPages.get(page);
      if (current && targetId) current.target_id = targetId;
    }).catch(() => {});
  }

  _unclaimedSummary() {
    const pages = [...this._unclaimedPages.values()].map(entry => ({
      generation: entry.generation,
      url: entry.url,
      target_id: entry.target_id,
      detected_at: entry.detected_at,
      closed: entry.closed,
      closed_at: entry.closed_at,
    }));
    const active = pages.filter(entry => !entry.closed).length;
    return {active, total_observed: pages.length, pages};
  }

  // ---- tabs ----------------------------------------------------------------------------
  _ownerTabs(owner) { return [...this.tabs.values()].filter(tab => tab.owner === owner && tab.state !== 'closed'); }

  _tab(owner, tabId) {
    const tab = this.tabs.get(String(tabId || ''));
    if (!tab || tab.state === 'closed') throw new HubError('TAB_NOT_FOUND', 'no such tab', {tab_id: tabId});
    if (tab.owner !== owner) throw new HubError('TAB_NOT_OWNED', 'this tab belongs to another agent', {tab_id: tabId});
    return tab;
  }

  _live(owner, tabId) {
    const tab = this._tab(owner, tabId);
    if (tab.state === 'lost' || !tab.page || tab.page.isClosed())
      throw new HubError('TAB_LOST', 'the tab is gone (browser connection or tab was closed); restore it explicitly',
        {tab_id: tab.id, last_url: tab.url, lost_at: tab.lost_at ?? null, next_step: 'tab_restore', retry_safe: false});
    return tab;
  }

  _describe(tab) {
    return {tab_id: tab.id, owner: tab.owner, state: tab.state, url: tab.url, title: tab.title,
      created_at: tab.created_at, last_used_at: tab.last_used_at, opened_by: tab.opened_by,
      restored_from: tab.restored_from ?? null, connection_generation: tab.generation,
      durable_identity: Boolean(tab.target_id), orphaned: tab.orphaned === true, open_uncertain: tab.open_uncertain === true};
  }

  _wire(tab, page) {
    this._unclaimedPages.delete(page);
    tab.page = page;
    tab.state = 'live';
    // A page that closes on its own is remembered for a moment: when the whole connection drops
    // right after, the tab was lost with it (recoverable) rather than closed by somebody.
    page.on('close', () => { if (tab.page === page && tab.state === 'live') { tab.state = 'closed'; tab.page = null; tab.closed_by_browser_at = this.clock(); this._persist(); } });
    page.on('framenavigated', frame => { if (frame === page.mainFrame()) { tab.url = frame.url(); this._persist(); } });
    page.on('popup', popup => {
      const overflow = this.stopping || this._ownerTabs(tab.owner).length >= this.limits.maxTabsPerOwner ||
        this._heldTabs().length >= this.limits.maxTabs;
      const child = this._register(tab.owner, tab.generation, {opened_by: tab.id});
      this._wire(child, popup);
      child.url = popup.url();
      if (this.connection) void this._identify(child, this.connection, popup);
      // Even a popup that refuses to close retains its owner and remains visible in tab_list.
      if (overflow) child.lane = popup.close().catch(() => undefined);
    });
  }

  _register(owner, generation, extra = {}) {
    const at = this.clock();
    for (const [id, previous] of this.tabs) {
      if (previous.state === 'closed' && at - (previous.closed_by_browser_at || 0) >= 5000) this.tabs.delete(id);
    }
    const tab = {id: newId('tab'), owner, generation, state: 'opening', url: 'about:blank', title: '',
      created_at: at, last_used_at: at, opened_by: null, lane: Promise.resolve(), ...extra};
    this.tabs.set(tab.id, tab);
    return tab;
  }

  _heldTabs() { return [...this.tabs.values()].filter(tab => tab.state !== 'closed'); }

  async _openPage(owner, url, extra, replaces = null) {
    if (this.stopping) throw new HubError('HUB_SHUTDOWN');
    if (typeof owner !== 'string' || !owner) throw new HubError('OWNER_REQUIRED');
    if (url) BrowserHub.checkUrl(url);
    if (this._ownerTabs(owner).some(tab => tab.state === 'lost' && tab.open_uncertain))
      throw new HubError('TAB_OPEN_RECONCILIATION_REQUIRED', 'the outcome of an earlier tab open is unknown',
        {attempted: false, retry_safe: false, automatic_replay: false});
    if (this._ownerTabs(owner).filter(tab => tab !== replaces).length >= this.limits.maxTabsPerOwner)
      throw new HubError('TAB_LIMIT_OWNER', 'this agent already holds the maximum number of tabs', {limit: this.limits.maxTabsPerOwner});
    if (this._heldTabs().filter(tab => tab !== replaces).length >= this.limits.maxTabs)
      throw new HubError('TAB_LIMIT_TOTAL', 'the browser hub holds the maximum number of tabs', {limit: this.limits.maxTabs});
    // Reserve capacity synchronously, before connect/newPage can yield to another agent.
    const tab = this._register(owner, 0, extra);
    const opening = (async () => {
      let dispatched = false;
      try {
        const connection = await this._ensureConnected();
        if (this.stopping) throw new HubError('HUB_SHUTDOWN');
        tab.generation = connection.generation;
        tab.open_uncertain = true;
        this._persist();
        if (this.ledgerError) throw new HubError('TAB_LEDGER_WRITE_FAILED', 'tab creation was withheld', {attempted: false});
        dispatched = true;
        const page = await connection.context.newPage();
        this._wire(tab, page);
        await this._identify(tab, connection, page);
        if (this.connection !== connection || !connection.browser.isConnected())
          throw new HubError('TAB_LOST', 'browser connection dropped while opening the tab', {tab_id: tab.id, retry_safe: false});
        tab.open_uncertain = false;
        this._persist();
        if (this.ledgerError) throw new HubError('TAB_LEDGER_WRITE_FAILED', 'tab identity was not committed', {attempted: true});
        if (this.stopping) throw new HubError('HUB_SHUTDOWN');
        if (url) await this._goto(tab, url, 30000);
        return tab;
      } catch (error) {
        if (dispatched && !tab.page && tab.state !== 'closed') {
          tab.state = 'lost';
          tab.lost_at = this.clock();
          tab.open_uncertain = true;
          this._persist();
          throw new HubError('TAB_OPEN_OUTCOME_UNKNOWN', 'a tab may have opened without returning its handle',
            {tab_id: tab.id, attempted: true, outcome_unknown: true, cleanup_failed: true, retry_safe: false});
        }
        if (tab.page && !tab.page.isClosed()) await tab.page.close().catch(() => {});
        if (tab.page && !tab.page.isClosed())
          throw new HubError(error.code || 'TAB_OPEN_FAILED', brief(error),
            {...(error.details || {}), tab_id: tab.id, cleanup_failed: true, retry_safe: false});
        tab.state = 'closed';
        tab.page = null;
        this.tabs.delete(tab.id);
        this._persist();
        throw error;
      }
    })();
    tab.lane = opening.catch(() => undefined);
    return opening;
  }

  static checkUrl(url) {
    let parsed;
    try { parsed = new URL(String(url)); } catch { throw new HubError('URL_INVALID', 'not an absolute URL'); }
    if (!['http:', 'https:'].includes(parsed.protocol) && parsed.href !== 'about:blank')
      throw new HubError('URL_SCHEME_FORBIDDEN', 'only http(s) pages are automated', {scheme: parsed.protocol});
    return parsed.href;
  }

  async _goto(tab, url, timeout) {
    const target = BrowserHub.checkUrl(url);
    try {
      await tab.page.goto(target, {waitUntil: 'domcontentloaded', timeout});
    } catch (error) {
      throw new HubError('NAVIGATION_FAILED', 'navigation did not complete', {cause: brief(error), url: target, attempted: true});
    }
    tab.url = tab.page.url();
    tab.title = await tab.page.title().catch(() => '');
    this._persist();
  }

  // Operations on one tab run one at a time; different tabs never wait for each other.
  _serial(tab, fn, {allowLost = false} = {}) {
    if (this.stopping) return Promise.reject(new HubError('HUB_SHUTDOWN'));
    const run = tab.lane.catch(() => undefined).then(() => {
      if (tab.state === 'closed') throw new HubError('TAB_NOT_FOUND', 'the tab was closed', {tab_id: tab.id});
      if (!allowLost) this._live(tab.owner, tab.id);
      return fn();
    });
    tab.lane = run;
    tab.last_used_at = this.clock();
    this.stats.operations++;
    return run;
  }

  async _locate(tab, target) {
    if (!target || typeof target !== 'object') throw new HubError('TARGET_REQUIRED');
    const page = tab.page;
    let locator;
    if (typeof target.ref === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(target.ref)) locator = page.locator(`aria-ref=${target.ref}`);
    else if (typeof target.selector === 'string' && target.selector) locator = page.locator(target.selector);
    else if (typeof target.role === 'string') locator = page.getByRole(target.role, target.name ? {name: target.name, exact: target.exact === true} : {});
    else if (typeof target.label === 'string') locator = page.getByLabel(target.label, {exact: target.exact === true});
    else if (typeof target.text === 'string') locator = page.getByText(target.text, {exact: target.exact === true});
    else throw new HubError('TARGET_REQUIRED', 'give ref, selector, role(+name), label or text');
    let count;
    try { count = await locator.count(); }
    catch (error) { throw new HubError('TARGET_STALE', 'the reference no longer resolves; take a new snapshot', {cause: brief(error)}); }
    if (count === 0) throw new HubError('TARGET_NOT_FOUND', 'nothing matches the target', {target});
    if (count > 1) throw new HubError('TARGET_AMBIGUOUS', 'several elements match; be more specific', {target, matches: count});
    return locator;
  }

  _checkHost(page, expectedHost) {
    if (expectedHost === undefined) return;
    let actual = '';
    try { actual = new URL(page.url()).hostname.replace(/^\[|\]$/g, ''); }
    catch { throw new HubError('TAB_HOST_CHANGED', 'the live tab address cannot be verified', {attempted: false}); }
    if (actual !== String(expectedHost).toLowerCase())
      throw new HubError('TAB_HOST_CHANGED', 'the live tab changed host; authorize its current address before acting',
        {expected_host: expectedHost, actual_host: actual, attempted: false, retry_safe: false});
  }

  async _check(tab, condition, timeoutMs) {
    if (!condition) return null;
    const deadline = this.clock() + Math.min(Math.max(Number(timeoutMs ?? 5000), 100), 30000);
    const page = tab.page;
    const test = async () => {
      if (typeof condition.url_contains === 'string') return page.url().includes(condition.url_contains);
      if (typeof condition.text_present === 'string')
        return page.evaluate(text => document.body?.innerText.includes(text) ?? false, condition.text_present);
      if (typeof condition.text_absent === 'string')
        return page.evaluate(text => !(document.body?.innerText.includes(text) ?? false), condition.text_absent);
      if (condition.target) {
        const locator = await this._locate(tab, condition.target).catch(error => {
          if (error instanceof HubError && error.code === 'TARGET_NOT_FOUND') return null;
          throw error;
        });
        if (!locator) return condition.state === 'absent';
        if (condition.state === 'absent') return false;
        if (typeof condition.value === 'string') return (await locator.inputValue().catch(() => null)) === condition.value;
        if (typeof condition.checked === 'boolean') return (await locator.isChecked().catch(() => null)) === condition.checked;
        return true;
      }
      throw new HubError('POSTCONDITION_INVALID', 'use url_contains, text_present, text_absent or target');
    };
    for (;;) {
      let ok = false;
      try { ok = await test(); } catch (error) { if (error instanceof HubError && error.code === 'POSTCONDITION_INVALID') throw error; }
      if (ok) return true;
      if (this.clock() >= deadline) return false;
      await new Promise(resolve => setTimeout(resolve, 150));
    }
  }

  // ---- public operations ---------------------------------------------------------------
  status() {
    const at = this.clock();
    return {version: VERSION, pid: process.pid, stopping: this.stopping, connected: Boolean(this.connection?.browser.isConnected()),
      connection_generation: this.generation, route: this.connector.describe(),
      circuit_open: at < this.circuitOpenUntil, retry_after_ms: Math.max(0, Math.max(this.circuitOpenUntil, this.nextAttemptAt) - at),
      consecutive_failures: this.failures, last_error: this.lastError,
      tabs: {live: [...this.tabs.values()].filter(tab => tab.state === 'live').length,
        lost: [...this.tabs.values()].filter(tab => tab.state === 'lost').length,
        orphaned: [...this.tabs.values()].filter(tab => tab.state === 'lost' && tab.orphaned).length},
      unclaimed_pages: this._unclaimedSummary(),
      tab_ledger: {enabled: Boolean(this.ledgerFile), error: this.ledgerError || this.ledgerLoadError,
        recovery_proof: 'exact CDP target id; never URL or title'},
      limits: this.limits, stats: {...this.stats, uptime_ms: at - this.stats.started_at}};
  }

  async connect() { await this._ensureConnected(); return this.status(); }

  async tabOpen({owner, url}) {
    const tab = await this._openPage(owner, url || null, {});
    return this._describe(tab);
  }

  tabList({owner}) {
    if (typeof owner !== 'string' || !owner) throw new HubError('OWNER_REQUIRED');
    return {tabs: this._ownerTabs(owner).map(tab => this._describe(tab))};
  }

  async tabClose({owner, tab_id, forget_unconfirmed}) {
    const tab = this._tab(owner, tab_id);
    return this._serial(tab, async () => {
      let reattached = false;
      if (!tab.page && tab.state === 'lost') reattached = await this._reattach(tab);
      const page = tab.page;
      const connection = this.connection;
      if (!page) {
        if (await this._targetGone(tab)) {
          tab.state = 'closed';
          this.tabs.delete(tab.id);
          this._persist();
          return {tab_id: tab.id, closed: true, page_closed_in_browser: true, was_lost: true, evidence: 'target_absent_in_browser'};
        }
        // The owning session is ending: its record is dropped only when forget_unconfirmed===true
        // and open outcome is certain. Otherwise keep it in the ledger so cleanup stays fail-closed.
        const canForget = forget_unconfirmed === true && !tab.open_uncertain;
        if (canForget) { tab.state = 'closed'; this.tabs.delete(tab.id); this._persist(); }
        return {tab_id: tab.id, closed: false, page_closed_in_browser: false, was_lost: true,
          record_dropped: canForget, reason: 'TAB_CLEANUP_UNCONFIRMED'};
      }
      if (!connection || !connection.browser.isConnected()) {
        tab.state = 'lost';
        tab.lost_at ??= this.clock();
        tab.page = null;
        const canForget = forget_unconfirmed === true && !tab.open_uncertain;
        if (canForget) { tab.state = 'closed'; this.tabs.delete(tab.id); }
        this._persist();
        return {tab_id: tab.id, closed: false, page_closed_in_browser: false, was_lost: true,
          record_dropped: canForget, reason: 'TAB_CLEANUP_UNCONFIRMED'};
      }
      if (!page.isClosed()) {
        try { await page.close(); }
        catch (error) {
          const stillConnected = this.connection === connection && connection.browser.isConnected();
          if (!stillConnected) {
            tab.state = 'lost';
            tab.lost_at ??= this.clock();
            tab.page = null;
            const canForget = forget_unconfirmed === true && !tab.open_uncertain;
            if (canForget) { tab.state = 'closed'; this.tabs.delete(tab.id); }
            this._persist();
            return {tab_id: tab.id, closed: false, page_closed_in_browser: false, was_lost: true,
              record_dropped: canForget, reason: 'TAB_CLEANUP_UNCONFIRMED'};
          }
          if (!page.isClosed()) throw new HubError('TAB_CLOSE_FAILED', 'the tab remains owned; inspect before retrying',
            {tab_id: tab.id, cause: brief(error), attempted: true, retry_safe: false});
        }
      }
      // Verify the relay stayed connected AFTER page.close(). If the browser/relay
      // disconnected during close, local page.isClosed() becomes true without proving
      // Chrome physically closed the tab — never report false-positive cleanup_verified.
      const stillConnected = this.connection === connection && connection.browser.isConnected();
      if (!stillConnected) {
        tab.state = 'lost';
        tab.lost_at ??= this.clock();
        tab.page = null;
        const canForget = forget_unconfirmed === true && !tab.open_uncertain;
        if (canForget) { tab.state = 'closed'; this.tabs.delete(tab.id); }
        this._persist();
        return {tab_id: tab.id, closed: false, page_closed_in_browser: false, was_lost: true,
          record_dropped: canForget, reason: 'TAB_CLEANUP_UNCONFIRMED'};
      }
      if (!page.isClosed()) throw new HubError('TAB_CLOSE_FAILED', 'the browser did not close the tab', {tab_id: tab.id});
      tab.state = 'closed';
      tab.page = null;
      this.tabs.delete(tab.id);
      this._persist();
      return {tab_id: tab.id, closed: true, page_closed_in_browser: true, was_lost: false,
        ...(reattached ? {reattached: true, evidence: 'cdp_target_id'} : {})};
    }, {allowLost: true});
  }

  async tabCloseOwner({owner, forget_unconfirmed = false}) {
    const results = [];
    for (const tab of this._ownerTabs(owner)) {
      try {
        results.push(await this.tabClose({owner, tab_id: tab.id, forget_unconfirmed}));
      } catch (error) {
        if (error instanceof HubError && error.code === 'HUB_SHUTDOWN') throw error;
        results.push({tab_id: tab.id, closed: false, page_closed_in_browser: false, reason: error?.code || 'TAB_CLOSE_FAILED'});
      }
    }
    const unconfirmed = results.filter(tab => !tab.page_closed_in_browser).map(tab => tab.tab_id);
    const errors = results
      .filter(tab => !tab.page_closed_in_browser)
      .map(tab => ({tab_id: tab.tab_id, code: tab.reason || 'TAB_CLEANUP_UNCONFIRMED'}));
    return {
      closed: results.filter(tab => tab.page_closed_in_browser).length,
      tabs: results,
      results,
      unconfirmed,
      errors,
    };
  }

  async tabRestore({owner, tab_id}) {
    const old = this._tab(owner, tab_id);
    return this._serial(old, async () => {
      if (old.state === 'live' && old.page && !old.page.isClosed())
        return {...this._describe(old), restored: false, note: 'tab is live'};
      if (await this._reattach(old))
        return {...this._describe(old), restored: true, reattached: true, evidence: 'cdp_target_id', page_state_preserved: true,
          note: 'the same physical tab was found by its exact browser target id'};
      // A lost tab is NOT known to have closed merely because its connection disappeared.
      // The extension relay can lack CDP target IDs and cannot list every browser target.
      // Reopening its URL would create a duplicate, lose input, and orphan the original tab.
      // This holds for same-process reconnects as well as manager crash recovery.
      throw new HubError('TAB_RECOVERY_UNAVAILABLE',
        'the original physical tab could not be proven and reattached by its exact target id',
        {tab_id: old.id, last_url: old.url, durable_identity: Boolean(old.target_id),
          orphaned: old.orphaned === true, retry_safe: false, automatic_replay: false,
          page_state_preserved: false, no_address_fallback: true});
    }, {allowLost: true});
  }

  async navigate({owner, tab_id, url, timeout_ms}) {
    const tab = this._live(owner, tab_id);
    return this._serial(tab, async () => {
      await this._goto(tab, url, Math.min(Math.max(Number(timeout_ms ?? 30000), 1000), 120000));
      return this._describe(tab);
    });
  }

  async snapshot({owner, tab_id, max_chars}) {
    const tab = this._live(owner, tab_id);
    return this._serial(tab, async () => {
      const limit = Math.min(Math.max(Number(max_chars ?? 60000), 1000), 400000);
      let tree;
      try { tree = await tab.page.locator('body').ariaSnapshot({mode: 'ai', timeout: 15000}); }
      catch (error) { throw new HubError('SNAPSHOT_FAILED', 'the page could not be read', {cause: brief(error)}); }
      tab.url = tab.page.url();
      tab.title = await tab.page.title().catch(() => '');
      return {tab_id: tab.id, url: tab.url, title: tab.title, format: 'aria-yaml-with-refs',
        visibility: await tab.page.evaluate(() => document.visibilityState).catch(() => null),
        truncated: tree.length > limit, snapshot: tree.slice(0, limit)};
    });
  }

  async read({owner, tab_id, target, max_chars}) {
    const tab = this._live(owner, tab_id);
    return this._serial(tab, async () => {
      const limit = Math.min(Math.max(Number(max_chars ?? 60000), 100), 400000);
      const text = target
        ? await (await this._locate(tab, target)).evaluate(element => element.innerText ?? element.textContent ?? '')
        : await tab.page.evaluate(() => document.body?.innerText ?? '');
      return {tab_id: tab.id, url: tab.page.url(), title: await tab.page.title().catch(() => ''),
        truncated: text.length > limit, text: text.slice(0, limit)};
    });
  }

  async act({owner, tab_id, action, target, value, key, postcondition, timeout_ms, foreground, expected_host}) {
    const tab = this._live(owner, tab_id);
    return this._serial(tab, async () => {
      if (foreground === true)
        throw new HubError('FOREGROUND_ROUTE_REQUIRED', 'foreground input requires the guarded Bridge desktop route', {attempted: false});
      const page = tab.page;
      this._checkHost(page, expected_host);
      const before = page.url();
      const needsTarget = action !== 'press' || target;
      const locator = needsTarget ? await this._locate(tab, target) : null;
      if (locator && !(await locator.isVisible().catch(() => false)))
        throw new HubError('TARGET_NOT_VISIBLE', 'the element is hidden on the page', {attempted: false});
      if (locator && ['click', 'fill', 'select', 'check', 'uncheck'].includes(action) && !(await locator.isEnabled().catch(() => true)))
        throw new HubError('TARGET_DISABLED', 'the element is disabled', {attempted: false});
      this._checkHost(page, expected_host);
      let detail = null;
      try {
        if (action === 'click') await locator.evaluate(domClick);
        else if (action === 'fill') {
          detail = await locator.evaluate(domFill, String(value ?? ''));
          if (detail?.error) throw new HubError(detail.error, 'the target cannot be filled through DOM input', {attempted: false});
        }
        else if (action === 'select') detail = await locator.selectOption(Array.isArray(value) ? value.map(String) : String(value), {timeout: 10000});
        else if (action === 'check' || action === 'uncheck') {
          const want = action === 'check';
          if ((await locator.isChecked()) !== want) await locator.evaluate(domClick);
          if ((await locator.isChecked()) !== want) throw new HubError('ACTION_NO_EFFECT', 'the control did not change state', {attempted: true});
        } else if (action === 'press') {
          if (typeof key !== 'string' || !key) throw new HubError('KEY_REQUIRED');
          detail = locator ? await locator.evaluate(domPress, key) : await page.evaluate(k => {
            const el = document.activeElement || document.body;
            const init = {key: k, bubbles: true, cancelable: true, composed: true};
            const proceed = el.dispatchEvent(new KeyboardEvent('keydown', init));
            el.dispatchEvent(new KeyboardEvent('keyup', init));
            if (proceed && k === 'Enter' && el.form?.requestSubmit) { el.form.requestSubmit(); return 'form_submitted'; }
            return proceed ? 'dispatched' : 'prevented_by_page';
          }, key);
        } else throw new HubError('ACTION_UNSUPPORTED', 'use click, fill, select, check, uncheck or press', {action});
      } catch (error) {
        if (error instanceof HubError) throw error;
        throw new HubError('ACTION_FAILED', 'the action may have partly run; verify before repeating',
          {cause: brief(error), attempted: true, retry_safe: false});
      }
      const verified = await this._check(tab, postcondition, timeout_ms);
      tab.url = page.url();
      const result = {tab_id: tab.id, action, performed: true, trusted_input: false, detail,
        url_before: before, url_after: tab.url, navigated: before !== tab.url,
        verified: verified === null ? null : verified,
        visibility: await page.evaluate(() => document.visibilityState).catch(() => null)};
      if (verified === false)
        throw new HubError('ACTION_NOT_VERIFIED', 'the action was sent but the expected result did not appear',
          {...result, attempted: true, retry_safe: false,
            hint: 'inspect before repeating; pages that require real input need the guarded Bridge foreground route'});
      return result;
    });
  }

  async waitFor({owner, tab_id, condition, timeout_ms}) {
    const tab = this._live(owner, tab_id);
    return this._serial(tab, async () => {
      const ok = await this._check(tab, condition || {}, timeout_ms);
      if (!ok) throw new HubError('WAIT_TIMEOUT', 'the condition did not become true', {retry_safe: true});
      return {tab_id: tab.id, satisfied: true, url: tab.page.url()};
    });
  }

  async screenshot({owner, tab_id, full_page}) {
    const tab = this._live(owner, tab_id);
    return this._serial(tab, async () => {
      if (!this.artifactDir) throw new HubError('ARTIFACT_DIR_UNAVAILABLE');
      const directory = path.join(this.artifactDir, crypto.createHash('sha256').update(tab.owner).digest('hex').slice(0, 16));
      fs.mkdirSync(directory, {recursive: true});
      const file = path.join(directory, `${tab.id}-${this.clock()}.png`);
      try { await tab.page.screenshot({path: file, fullPage: full_page === true, timeout: 20000}); }
      catch (error) { throw new HubError('SCREENSHOT_FAILED', 'the tab could not be captured', {cause: brief(error)}); }
      return {tab_id: tab.id, path: file, bytes: fs.statSync(file).size, url: tab.page.url()};
    });
  }

  async evaluate({owner, tab_id, expression, expected_host}) {
    const tab = this._live(owner, tab_id);
    return this._serial(tab, async () => {
      if (typeof expression !== 'string' || !expression.trim() || expression.length > 20000) throw new HubError('EXPRESSION_INVALID');
      this._checkHost(tab.page, expected_host);
      let value;
      try { value = await tab.page.evaluate(expression); }
      catch (error) { throw new HubError('EVALUATE_FAILED', 'the script threw', {cause: brief(error), attempted: true}); }
      const json = JSON.stringify(value ?? null);
      if (json.length > 400000) throw new HubError('EVALUATE_RESULT_TOO_LARGE', 'narrow the script result', {chars: json.length});
      return {tab_id: tab.id, value: value ?? null};
    });
  }

  async shutdown({close_tabs = true} = {}) {
    if (this.shutdownPromise) return this.shutdownPromise;
    this.stopping = true;
    this.shutdownPromise = (async () => {
      await this.connecting?.catch(() => {});
      // Drain already accepted work, including pending tab creation, before the final sweep.
      await Promise.allSettled([...this.tabs.values()].map(tab => tab.lane));
      let closed = 0;
      const errors = [];
      if (close_tabs)
        for (const tab of this.tabs.values())
          if (tab.state === 'lost' && !tab.page) {
            errors.push({tab_id: tab.id, code: 'TAB_CLEANUP_UNCONFIRMED'});
          } else if (tab.page && !tab.page.isClosed()) {
            const connBefore = this.connection;
            const page = tab.page;
            await page.close().catch(() => {});
            const stillConnected = Boolean(connBefore && this.connection === connBefore && connBefore.browser.isConnected());
            if (!stillConnected) {
              tab.state = 'lost';
              tab.lost_at ??= this.clock();
              tab.page = null;
              errors.push({tab_id: tab.id, code: 'TAB_CLEANUP_UNCONFIRMED'});
            } else if (page.isClosed()) {
              tab.state = 'closed';
              tab.page = null;
              closed++;
            } else {
              errors.push({tab_id: tab.id, code: 'TAB_CLOSE_FAILED'});
            }
          }
      const connection = this.connection;
      this.connection = null;
      if (!close_tabs) {
        // Playwright emits Page.close when its transport disconnects even if
        // the physical Chrome page survives. Detach handles BEFORE closing
        // the connection so _wire cannot erase durable identities as closed.
        for (const tab of this.tabs.values()) {
          if (!['live', 'opening'].includes(tab.state)) continue;
          tab.state = 'lost';
          tab.lost_at = this.clock();
          tab.page = null;
        }
      }
      this._persist();
      // Only pages explicitly registered to an agent are closed. Initial/foreign pages stay.
      if (connection) await connection.browser.close().catch(() => {});
      const unclaimed = this._unclaimedSummary();
      return {closed_tabs: closed, errors, unclaimed_pages_active: unclaimed.active, unclaimed_pages_observed: unclaimed.total_observed};
    })();
    return this.shutdownPromise;
  }

  dispatch(op, args = {}) {
    switch (op) {
      case 'status': return this.status();
      case 'connect': return this.connect();
      case 'tab_open': return this.tabOpen(args);
      case 'tab_list': return this.tabList(args);
      case 'tab_close': return this.tabClose(args);
      case 'tab_close_owner': return this.tabCloseOwner(args);
      case 'tab_restore': return this.tabRestore(args);
      case 'navigate': return this.navigate(args);
      case 'snapshot': return this.snapshot(args);
      case 'read': return this.read(args);
      case 'act': return this.act(args);
      case 'wait_for': return this.waitFor(args);
      case 'screenshot': return this.screenshot(args);
      case 'evaluate': return this.evaluate(args);
      default: throw new HubError('OP_UNSUPPORTED', 'unknown browser hub operation', {op});
    }
  }
}

export function serve(hub, {key, port = 0, host = '127.0.0.1', onShutdown = null}) {
  if (host !== '127.0.0.1') throw new HubError('LOOPBACK_REQUIRED');
  if (typeof key !== 'string' || key.length < 32) throw new HubError('HUB_KEY_REQUIRED');
  const expected = Buffer.from(key);
  const server = http.createServer((request, response) => {
    const reply = (status, body) => {
      const payload = Buffer.from(JSON.stringify(body));
      response.writeHead(status, {'content-type': 'application/json', 'content-length': payload.length});
      response.end(payload);
    };
    const given = Buffer.from(String(request.headers['x-ff-browser-key'] || ''));
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return reply(401, {ok: false, error_code: 'UNAUTHORIZED'});
    if (request.method !== 'POST' || request.url !== '/rpc') return reply(404, {ok: false, error_code: 'NOT_FOUND'});
    const chunks = [];
    let size = 0;
    request.on('data', chunk => { size += chunk.length; if (size > 2 * 1024 * 1024) request.destroy(); else chunks.push(chunk); });
    request.on('end', async () => {
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
      catch { return reply(400, {ok: false, error_code: 'REQUEST_JSON_INVALID'}); }
      try {
        if (body?.op === 'shutdown') {
          const result = await hub.shutdown(body.args || {});
          reply(200, {ok: true, result});
          server.close();
          onShutdown?.();
          return;
        }
        reply(200, {ok: true, result: await hub.dispatch(String(body?.op || ''), body?.args || {})});
      } catch (error) {
        reply(200, {ok: false, error_code: error?.code || 'INTERNAL_ERROR', message: brief(error),
          details: error instanceof HubError ? error.details : {}});
      }
    });
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

function option(name, fallback = null) {
  const index = process.argv.indexOf(`--${name}`);
  return index > 0 && index + 1 < process.argv.length ? process.argv[index + 1] : fallback;
}

export function releaseAfterParentLoss(hub) {
  // EOF is a transport crash, not an owner's request to discard work. Keep
  // physical pages and the exact-target ledger for the replacement Hub.
  return hub.shutdown({close_tabs: false});
}

async function main() {
  const stateDir = path.resolve(option('state-dir', path.join(here, 'state', 'browser-hub')));
  const profileDirName = option('profile', null);
  const profileBindingFile = path.join(stateDir, 'owner-profile-binding.json');
  const playwrightRoot = resolvePlaywrightRoot({playwrightRoot: option('playwright-root', null), stateDir});
  if (process.argv.includes('--preflight')) {
    const capability = await backgroundCapability(() => backgroundChromePreflight({profileDirName, profileBindingFile}),
      loadPlaywright, playwrightRoot);
    process.stdout.write(JSON.stringify(capability) + '\n');
    return;
  }
  const key = process.env.FF_BROWSER_HUB_KEY || '';
  delete process.env.FF_BROWSER_HUB_KEY;
  fs.mkdirSync(stateDir, {recursive: true});
  const connector = extensionConnector({playwrightRoot, profileDirName, profileBindingFile,
    background: option('background', 'true') !== 'false'});
  const hub = new BrowserHub(connector, {artifactDir: path.join(stateDir, 'screenshots'), ledgerFile: path.join(stateDir, 'tab-ledger.json'),
    maxTabsPerOwner: Number(option('max-tabs-per-owner', 8)), maxTabs: Number(option('max-tabs', 32))});
  const endpointFile = option('endpoint-file', path.join(stateDir, 'endpoint.json'));
  const cleanup = () => {
    try {
      if (JSON.parse(fs.readFileSync(endpointFile, 'utf8')).pid === process.pid) fs.unlinkSync(endpointFile);
    } catch {}
  };
  const server = await serve(hub, {key, port: Number(option('port', 0)), onShutdown: () => { cleanup(); setTimeout(() => process.exit(0), 200); }});
  const record = {version: VERSION, pid: process.pid, port: server.address().port, started_at: now(), route: connector.describe()};
  fs.writeFileSync(`${endpointFile}.tmp`, JSON.stringify(record));
  fs.renameSync(`${endpointFile}.tmp`, endpointFile);
  // Explicit shutdown RPC still closes owned tabs; unexpected parent loss only
  // disconnects the relay. Never delete unfinished forms because the Hub died.
  process.stdin.on('end', async () => { await releaseAfterParentLoss(hub).catch(() => {}); cleanup(); process.exit(0); });
  process.stdin.resume();
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => { await hub.shutdown({close_tabs: true}).catch(() => {}); cleanup(); process.exit(0); });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    process.stderr.write(`${error?.code || 'BROWSER_HUB_START_FAILED'}: ${brief(error)}\n`);
    process.exit(2);
  });
}
