import {DownloadOperationStore} from './download_state.mjs';

const HOST = 'com.ff.browser_companion';
const PROTOCOL_VERSION = 1;
const store = new DownloadOperationStore();
let nativePort = null;
let reconnectTimer = null;
let connectionState = 'DISCONNECTED';
let disconnectCode = null;
let reconnectAttempts = 0;

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const errorCode = error => String(error?.message || error || 'COMPANION_ERROR').split(':', 1)[0];

function nativeDiagnostics() {
  return {
    state: connectionState,
    last_disconnect_code: disconnectCode,
    reconnect_attempts: reconnectAttempts,
  };
}

// Available in the extension's own service-worker inspector, including when IPC is down.
globalThis.ffCompanionDiagnostics = nativeDiagnostics;

async function capabilities() {
  let downloadsOperational = false;
  try {
    await chrome.downloads.search({limit: 1});
    downloadsOperational = true;
  } catch {}
  return {
    protocol_version: PROTOCOL_VERSION,
    extension_version: chrome.runtime.getManifest().version,
    downloads: downloadsOperational,
    native_messaging: connectionState === 'CONNECTED',
    native_connection: nativeDiagnostics(),
    physical_input: false,
  };
}

async function waitOperation(operationId, timeoutMs) {
  const duration = Number(timeoutMs ?? 10000);
  if (!Number.isFinite(duration)) throw new Error('TIMEOUT_INVALID');
  const deadline = Date.now() + Math.min(Math.max(duration, 250), 30000);
  for (;;) {
    let status = store.status(operationId);
    if (status.matched && !status.terminal) {
      const [item] = await chrome.downloads.search({id: status.matched_id});
      if (item) status = store.onChanged(item);
    }
    if (status.terminal) return status;
    if (Date.now() >= deadline) return store.status(operationId);
    await sleep(100);
  }
}

async function cleanupOperation(operationId) {
  const target = store.cleanupTargets(operationId);
  for (const id of target.ids) {
    let item = (await chrome.downloads.search({id}))[0] || null;
    if (!item) throw new Error('DOWNLOAD_CLEANUP_UNVERIFIED');
    if (!store.ownsFilename(operationId, item.filename)) throw new Error('CLEANUP_OWNERSHIP_UNPROVEN');
    if (item?.state === 'in_progress') {
      await chrome.downloads.cancel(id);
      item = (await chrome.downloads.search({id}))[0] || null;
      if (!item || !store.ownsFilename(operationId, item.filename)) throw new Error('DOWNLOAD_CLEANUP_UNVERIFIED');
    }
    if (item?.state === 'complete' && item.exists !== false) {
      await chrome.downloads.removeFile(id);
      const deadline = Date.now() + 3000;
      do {
        await sleep(40);
        item = (await chrome.downloads.search({id}))[0] || null;
      } while (item?.exists !== false && Date.now() < deadline);
      if (item?.exists !== false) throw new Error('DOWNLOAD_CLEANUP_UNVERIFIED');
    }
    if (!['complete', 'interrupted'].includes(item?.state)) throw new Error('DOWNLOAD_CLEANUP_UNVERIFIED');
    if (!(await chrome.downloads.erase({id})).includes(id)) throw new Error('DOWNLOAD_CLEANUP_UNVERIFIED');
  }
  return store.markCleaned(operationId);
}

async function dispatch(method, params = {}) {
  switch (method) {
    case 'health': return {ok: true, ...(await capabilities())};
    case 'capabilities': return capabilities();
    case 'download.prepare': return store.prepare(params);
    case 'download.status': return store.status(params.operation_id);
    case 'download.wait': return waitOperation(params.operation_id, params.timeout_ms);
    case 'download.cleanup': return cleanupOperation(params.operation_id);
    default: throw new Error('METHOD_UNSUPPORTED');
  }
}

async function handleNativeMessage(port, message) {
  if (port !== nativePort || !message) return;
  if (message.type === 'host_ready' && message.protocol_version === PROTOCOL_VERSION) {
    markConnected();
    return;
  }
  if (message.type === 'host_error' && message.error_code === 'HOST_PIPE_BUSY') {
    disconnectCode = 'HOST_PIPE_BUSY';
    return;
  }
  if (message.type !== 'command' || typeof message.request_id !== 'string') return;
  markConnected(); // Older hosts send commands without a host_ready frame.
  const requestId = message.request_id;
  let response;
  try {
    const result = await dispatch(String(message.method || ''), message.params || {});
    response = {ok: true, result};
  } catch (error) {
    // Chrome API error text can contain a path or a URL. Only emit bounded codes.
    const code = errorCode(error);
    response = {ok: false, error_code: /^[A-Z0-9_]{1,64}$/.test(code) ? code : 'COMPANION_API_FAILED'};
  }
  if (port !== nativePort) return;
  try {
    port.postMessage({type: 'response', request_id: requestId, ...response});
  } catch {
    // The port may close after the identity check, before postMessage runs.
  }
}

function markConnected() {
  connectionState = 'CONNECTED';
  disconnectCode = null;
  reconnectAttempts = 0;
}

function classifyDisconnect(error) {
  const message = String(error?.message || '').toLowerCase();
  if (message.includes('not found')) return 'HOST_NOT_FOUND';
  if (message.includes('forbidden')) return 'HOST_FORBIDDEN';
  if (message.includes('failed to start')) return 'HOST_START_FAILED';
  if (message.includes('communicating')) return 'HOST_PROTOCOL_ERROR';
  if (message.includes('exited')) return 'HOST_EXITED';
  return 'HOST_DISCONNECTED';
}

function reconnect(code) {
  connectionState = 'DISCONNECTED';
  disconnectCode = code;
  if (reconnectTimer) return;
  const delay = Math.min(60000, 1000 * 2 ** Math.min(reconnectAttempts, 6));
  reconnectAttempts++;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connectNative();
  }, delay);
}

function connectNative() {
  if (nativePort || reconnectTimer) return;
  connectionState = 'CONNECTING';
  try {
    const port = chrome.runtime.connectNative(HOST);
    nativePort = port;
    port.onMessage.addListener(message => { void handleNativeMessage(port, message); });
    port.onDisconnect.addListener(() => {
      // Reading lastError in the callback prevents unchecked-runtime red errors.
      const code = classifyDisconnect(chrome.runtime.lastError);
      if (port !== nativePort) return;
      nativePort = null;
      reconnect(disconnectCode === 'HOST_PIPE_BUSY' && connectionState === 'CONNECTING' ? disconnectCode : code);
    });
  } catch (error) {
    nativePort = null;
    reconnect(classifyDisconnect(error));
  }
}

chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  let suggestion;
  try {
    store.onCreated(item);
    const owned = store.filenameSuggestion(item);
    if (owned) suggestion = {filename: owned.filename, conflictAction: 'uniquify'};
  } catch {}
  if (suggestion) suggest(suggestion);
  else suggest();
});

chrome.downloads.onChanged.addListener(delta => {
  const id = Number(delta?.id);
  if (!Number.isInteger(id)) return;
  chrome.downloads.search({id}).then(items => {
    if (items[0]) store.onChanged(items[0]);
  }).catch(() => {});
});

chrome.runtime.onStartup.addListener(connectNative);
chrome.runtime.onInstalled.addListener(connectNative);
connectNative();
