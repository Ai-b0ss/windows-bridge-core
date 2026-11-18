import assert from 'node:assert/strict';
import test from 'node:test';
import {DownloadOperationStore} from '../runtime/bridge-v3/browser_companion/download_state.mjs';

const url = 'http://127.0.0.1/download';

test('recent receipts stay bounded independently of the outstanding work quota', () => {
  let now = 1;
  const store = new DownloadOperationStore({clock: () => now, maxOperations: 2, maxRecentOperations: 4});
  const prepare = id => store.prepare({operation_id: id, expected_url: url, timeout_ms: 250});
  prepare('capacity-1');
  prepare('capacity-2');
  assert.throws(() => prepare('capacity-3'), /OPERATION_LIMIT/);
  now += 250;
  assert.equal(store.status('capacity-1').state, 'TIMEOUT');
  for (let i = 0; i < 150; i++) {
    const id = `download-${i}`;
    assert.equal(prepare(id).state, 'PREPARED');
    assert.equal(store.markCleaned(id).cleanup_complete, true);
  }
  assert.ok(store.operations.size <= 5);
  assert.throws(() => prepare('download-149'), /OPERATION_EXISTS/);
  assert.throws(() => store.prepare({operation_id: 'bad-timeout', expected_url: url, timeout_ms: 'bad'}), /TIMEOUT_INVALID/);
});

test('download completion requires the namespace suggested to Chrome for this operation', () => {
  const store = new DownloadOperationStore();
  const spec = {operation_id: 'download-owned', expected_url: url, expected_filename: 'probe.bin'};
  const item = {id: 123, url, filename: 'probe.bin'};
  store.prepare(spec);
  assert.equal(store.onCreated(item).matched, true);
  assert.equal(store.filenameSuggestion(item).filename, 'FF-CUA/download-owned/probe.bin');
  store.prepare({...spec, operation_id: 'download-other'});
  assert.equal(store.onCreated(item), null);
  assert.equal(store.status('download-other').state, 'PREPARED');
  assert.equal(store.ownsFilename(spec.operation_id, 'somewhere\\probe.bin'), false);
  const unowned = store.onChanged({...item, state: 'complete'});
  assert.equal(unowned.state, 'FAILED');
  assert.equal(unowned.terminal_reason, 'DOWNLOAD_FILENAME_OWNERSHIP_UNPROVEN');
  assert.equal(unowned.item, null);
  const owned = store.onChanged({...item, state: 'complete', filename: 'root\\FF-CUA\\download-owned\\probe.bin'});
  assert.equal(owned.state, 'COMPLETE');
});

test('Native Messaging disconnect reads lastError and drops responses from the old port', async () => {
  const ports = [];
  const timers = [];
  const callbacks = {};
  let lastErrorReads = 0;
  let releaseSearch;
  const oldTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (callback, delay) => {
    timers.push({callback, delay});
    return timers.length;
  };
  const event = name => ({addListener: callback => { callbacks[name] = callback; }});
  globalThis.chrome = {
    runtime: {
      connectNative() {
        const port = {
          onMessage: event('message'), onDisconnect: event('disconnect'), sent: [],
          postMessage(message) { this.sent.push(message); },
        };
        ports.push(port);
        return port;
      },
      onInstalled: event('install'), onStartup: event('startup'),
      getManifest: () => ({version: '0.1.1'}),
      get lastError() { lastErrorReads++; return {message: 'Specified native messaging host not found.'}; },
    },
    downloads: {
      search: () => new Promise(resolve => { releaseSearch = resolve; }),
      onChanged: event('change'), onDeterminingFilename: event('suggest'),
    },
  };
  try {
    await import('../runtime/bridge-v3/browser_companion/service_worker.js');
    callbacks.message({type: 'command', request_id: 'in-flight', method: 'capabilities'});
    callbacks.disconnect();
    assert.equal(lastErrorReads, 1);
    assert.equal(globalThis.ffCompanionDiagnostics().last_disconnect_code, 'HOST_NOT_FOUND');
    assert.equal(timers[0].delay, 1000);
    timers[0].callback();
    assert.equal(ports.length, 2);
    releaseSearch([]);
    await Promise.resolve();
    await Promise.resolve();
    assert.deepEqual(ports.map(port => port.sent), [[], []]);
    const args = [];
    callbacks.suggest({id: 11, url, filename: 'foreign.bin'}, (...values) => args.push(values));
    assert.deepEqual(args, [[]]);
  } finally {
    globalThis.setTimeout = oldTimeout;
    delete globalThis.chrome;
    delete globalThis.ffCompanionDiagnostics;
  }
});
