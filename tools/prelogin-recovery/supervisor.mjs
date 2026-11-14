import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const root = path.dirname(fileURLToPath(import.meta.url));
const workerFile = path.join(root, 'prelogin-network-worker.mjs');
const stateDir = path.join(root, 'prelogin-network');
const stateFile = path.join(stateDir, 'state.json');
const logFile = path.join(stateDir, 'supervisor.log');
const maxLogBytes = 262144;
const retryBaseMs = 3000;
let stopping = false;
let child = null;
let retryTimer = null;

fs.mkdirSync(stateDir, { recursive: true });

function log(message) {
  try {
    if (fs.existsSync(logFile) && fs.statSync(logFile).size > maxLogBytes) {
      fs.renameSync(logFile, logFile + '.previous');
    }
    fs.appendFileSync(logFile, new Date().toISOString() + ' supervisor_pid=' + process.pid + ' ' + message + '\n', 'utf8');
  } catch (error) {
    process.stderr.write('Supervisor log failure: ' + error.message + '\n');
  }
}

function mark(phase, extra = {}) {
  const data = { phase, pid: process.pid, supervisorPid: process.pid, at: Date.now(), ...extra };
  try {
    const tmp = stateFile + '.' + process.pid + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
    fs.renameSync(tmp, stateFile);
  } catch (error) {
    log('state_write_failed=' + JSON.stringify(error.message));
  }
}

function shutdown(signal) {
  if (stopping) return;
  stopping = true;
  log('signal=' + signal);
  if (retryTimer) clearTimeout(retryTimer);
  if (child && child.exitCode === null) {
    try { child.kill(); } catch (error) { log('child_stop_error=' + JSON.stringify(error.message)); }
  }
}

for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => shutdown(signal));

function runChild() {
  return new Promise(resolve => {
    let done = false;
    const startedAt = Date.now();
    try {
      child = spawn(process.execPath, [workerFile], { windowsHide: true, stdio: 'ignore', shell: false });
    } catch (error) {
      resolve({ error: error.message, uptimeMs: 0 });
      return;
    }
    log('worker_start pid=' + (child.pid ?? 'none'));
    function finish(outcome) {
      if (done) return;
      done = true;
      child = null;
      resolve({ ...outcome, uptimeMs: Date.now() - startedAt });
    }
    child.once('error', error => finish({ error: error.message }));
    child.once('exit', (code, signal) => finish({ code, signal }));
  });
}

async function main() {
  let failures = 0;
  log('supervisor_start');
  while (!stopping) {
    mark('Starting', { attempt: failures + 1 });
    const outcome = await runChild();
    if (stopping) break;
    if (outcome.uptimeMs >= 120000) failures = 0;
    failures++;
    const delayMs = Math.min(60000, retryBaseMs * 2 ** Math.min(failures - 1, 5));
    log('worker_exit ' + JSON.stringify(outcome) + ' retry_in_ms=' + delayMs);
    mark('Retrying', { attempt: failures, lastExit: outcome, retryInMs: delayMs });
    await new Promise(resolve => {
      retryTimer = setTimeout(resolve, delayMs);
    });
    retryTimer = null;
  }
  log('supervisor_stopped');
}

main().catch(error => {
  log('fatal=' + JSON.stringify(error.message));
  process.exitCode = 1;
});
