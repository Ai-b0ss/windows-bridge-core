import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const dirHere = path.dirname(fileURLToPath(import.meta.url));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

test('a Core connect timeout automatically retries and recovers to Ready', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ff-prelogin-recovery-'));
  const service = path.join(dir, 'prelogin-network');
  fs.copyFileSync(path.join(dirHere, 'supervisor.mjs'), path.join(dir, 'prelogin-network-supervisor.mjs'));
  const fakeWorker = [
    "import fs from 'node:fs';",
    "import path from 'node:path';",
    "const d = path.join(process.cwd(), 'prelogin-network');",
    "fs.mkdirSync(d, {recursive:true});",
    "const counter=path.join(d,'counter.txt');",
    "const n=Number(fs.existsSync(counter)?fs.readFileSync(counter,'utf8'):0)+1;",
    "fs.writeFileSync(counter,String(n));",
    "if(n===1){fs.writeFileSync(path.join(d,'state.json'),JSON.stringify({phase:'Failed',error:'Core connect timeout'}));process.exit(1);}",
    "fs.writeFileSync(path.join(d,'state.json'),JSON.stringify({phase:'Ready',pid:process.pid}));",
    "fs.writeFileSync(path.join(d,'ready.marker'),String(n));",
    "setTimeout(()=>process.exit(0),700);"
  ].join('\n');
  fs.writeFileSync(path.join(dir, 'prelogin-network-worker.mjs'), fakeWorker);
  const proc = spawn(process.execPath, [path.join(dir, 'prelogin-network-supervisor.mjs')], {
    cwd: dir, windowsHide: true, stdio: 'ignore'
  });
  try {
    const ready = path.join(service, 'ready.marker');
    const deadline = Date.now() + 11000;
    while (!fs.existsSync(ready) && Date.now() < deadline) await sleep(80);
    assert.ok(fs.existsSync(ready), 'worker must recover after a failed first attempt');
    assert.equal(fs.readFileSync(ready, 'utf8'), '2');
    assert.equal(proc.exitCode, null, 'supervisor remains alive');
    const log = fs.readFileSync(path.join(service, 'supervisor.log'), 'utf8');
    assert.match(log, /"code":1/);
    assert.match(log, /retry_in_ms=3000/);
    await sleep(850);
    assert.equal(JSON.parse(fs.readFileSync(path.join(service, 'state.json'), 'utf8')).phase, 'Retrying');
  } finally {
    if (proc.exitCode === null) proc.kill();
    if (proc.exitCode === null) {
      await Promise.race([
        new Promise(resolve => proc.once('exit', resolve)),
        sleep(3000)
      ]);
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
  }
});
