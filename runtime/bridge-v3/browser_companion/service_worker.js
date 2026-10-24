import {DownloadOperationStore} from './download_state.mjs';

const HOST = 'com.ff.browser_companion';
const PROTOCOL_VERSION = 1;
const store = new DownloadOperationStore();
let nativePort = null;
let reconnectTimer = null;

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const errorCode = error => String(error?.message || error || 'COMPANION_ERROR').split(':', 1)[0];

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
    native_messaging: true,
    physical_input: false,
  };
}

async function waitOperation(operationId, timeoutMs) {
  const deadline = Date.now() + Math.min(Math.max(Number(timeoutMs || 10000), 250), 30000);
  for (;;) {
    const status = store.status(operationId);
    if (status.terminal) return status;
    if (Date.now() >= deadline) return store.status(operationId);
    await sleep(40);
  }
}

async function cleanupOperation(operationId) {
  const target = store.cleanupTargets(operationId);
  for (const id of target.ids) {
    let items = await chrome.downloads.search({id});
    let item = items[0] || null;
    if (item?.state === 'in_progress') {
      try { await chrome.downloads.cancel(id); } catch {}
      items = await chrome.downloads.search({id});
      item = items[0] || null;
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
    try { await chrome.downloads.erase({id}); } catch {}
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

function handleNativeMessage(message) {
  if (!message || message.type !== 'command' || typeof message.request_id !== 'string') return;
  const requestId = message.request_id;
  dispatch(String(message.method || ''), message.params || {}).then(result => {
    nativePort?.postMessage({type: 'response', request_id: requestId, ok: true, result});
  }).catch(error => {
    nativePort?.postMessage({
      type: 'response', request_id: requestId, ok: false,
      error_code: errorCode(error), message: String(error?.message || error).slice(0, 500),
    });
  });
}

function connectNative() {
  if (nativePort) return;
  try {
    nativePort = chrome.runtime.connectNative(HOST);
    nativePort.onMessage.addListener(handleNativeMessage);
    nativePort.onDisconnect.addListener(() => {
      nativePort = null;
      if (!reconnectTimer) reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connectNative();
      }, 1000);
    });
  } catch {
    nativePort = null;
  }
}

chrome.downloads.onCreated.addListener(item => {
  try { store.onCreated(item); } catch {}
});

chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  try {
    store.onCreated(item);
    const owned = store.filenameSuggestion(item);
    if (owned) suggest({filename: owned.filename, conflictAction: 'uniquify'});
  } catch {}
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
