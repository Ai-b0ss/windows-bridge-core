import readline from 'node:readline';
import {pathToFileURL} from 'node:url';
import {BrowserSidecar, BrowserSidecarError} from './cua_browser_sidecar.mjs';
import {PlaywrightEngine} from './cua_browser_playwright.mjs';

export async function dispatchBrowserRpc(sidecar, request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new BrowserSidecarError('REQUEST_INVALID');
  }
  const op = String(request.op || '');
  const args = request.args && typeof request.args === 'object' && !Array.isArray(request.args) ? request.args : {};
  switch (op) {
    case 'health':
      return {ok: true, capabilities: {jsonl_rpc: true, physical_input: false}};
    case 'attach':
      return sidecar.attach(args);
    case 'observe':
      return sidecar.observe(String(args.surface_id || ''), args.options || {});
    case 'find':
      return sidecar.find(String(args.surface_id || ''), args.query || {});
    case 'act':
      return sidecar.act(String(args.surface_id || ''), args.action || {});
    case 'wait':
      return sidecar.wait(String(args.surface_id || ''), args.spec || {}, args.timeout_ms ?? 5000);
    case 'navigate':
      return sidecar.navigate(String(args.surface_id || ''), String(args.url || ''), args.timeout_ms ?? 10000);
    case 'identity':
      return sidecar.identity(String(args.surface_id || ''));
    case 'back':
      return sidecar.back(String(args.surface_id || ''), args.timeout_ms ?? 10000);
    case 'forward':
      return sidecar.forward(String(args.surface_id || ''), args.timeout_ms ?? 10000);
    case 'reload':
      return sidecar.reload(String(args.surface_id || ''), args.timeout_ms ?? 10000);
    case 'list_tabs':
      return sidecar.listTabs(String(args.surface_id || ''));
    case 'claim_tab':
      return sidecar.claimTab(String(args.surface_id || ''), args.selector || {});
    case 'new_tab':
      return sidecar.newTab(String(args.surface_id || ''), String(args.url || 'about:blank'), args.timeout_ms ?? 10000);
    case 'switch_tab':
      return sidecar.switchTab(String(args.surface_id || ''), String(args.page_id || ''));
    case 'close_tab':
      return sidecar.closeTab(String(args.surface_id || ''), String(args.page_id || ''));
    case 'recover':
      return sidecar.recover(String(args.surface_id || ''));
    case 'close':
      return sidecar.close(String(args.surface_id || ''));
    default:
      throw new BrowserSidecarError('RPC_OP_UNSUPPORTED', op);
  }
}

export async function serveBrowserRpc(sidecar, {input = process.stdin, output = process.stdout} = {}) {
  const rl = readline.createInterface({input, crlfDelay: Infinity});
  const lanes = new Map();
  const inFlight = new Set();
  const handleLine = async line => {
    if (!line.trim()) return;
    let request;
    try {
      request = JSON.parse(line);
    } catch {
      output.write(JSON.stringify({id: null, ok: false, error_code: 'REQUEST_JSON_INVALID'}) + '\n');
      return;
    }

    const id = request?.id ?? null;
    const surfaceId = request?.args?.surface_id;
    const laneKey = typeof surfaceId === 'string' && surfaceId ? surfaceId : null;
    const previous = laneKey ? lanes.get(laneKey) : null;
    const start = previous ? previous.catch(() => undefined) : Promise.resolve();
    const execution = start.then(() => dispatchBrowserRpc(sidecar, request));
    if (laneKey) lanes.set(laneKey, execution);

    try {
      const result = await execution;
      output.write(JSON.stringify({id, ok: true, result}) + '\n');
    } catch (error) {
      const code = error?.code || 'INTERNAL_ERROR';
      const details = error?.details && typeof error.details === 'object' ? error.details : {};
      output.write(JSON.stringify({
        id,
        ok: false,
        error_code: code,
        message: String(error?.message || code).slice(0, 1000),
        details,
      }) + '\n');
    } finally {
      if (laneKey && lanes.get(laneKey) === execution) lanes.delete(laneKey);
    }
  };

  for await (const line of rl) {
    const task = handleLine(line);
    inFlight.add(task);
    task.finally(() => inFlight.delete(task));
  }
  await Promise.allSettled([...inFlight]);
}

async function main() {
  const engine = await PlaywrightEngine.create();
  engine.isolatedOnly = process.argv.includes('--isolated-only');
  const sidecar = new BrowserSidecar(engine);
  try { await serveBrowserRpc(sidecar); }
  finally { await Promise.allSettled([...sidecar.surfaces.keys()].map(sid=>sidecar.close(sid))); }
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invoked) {
  main().catch(error => {
    const code = error?.code || 'BROWSER_SIDECAR_START_FAILED';
    process.stderr.write(`${code}: ${String(error?.message || error)}\n`);
    process.exitCode = 2;
  });
}
