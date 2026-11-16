import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import {
  FlightController,
  FlightOutcomeUnknownError,
  createFF3FlightCaller,
} from "./flight-controller.mjs";

test("ContextShield v0.5.2 clamps both single-line 150KB JSON and multi-line logs", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fc-v052-"));
  const fc = new FlightController({
    stateDir: tmpDir,
    executor: async (op) => {
      if (op === "list_directory") {
        const items = Array.from({ length: 1800 }, (_, i) => ({
          name: i === 900 ? "ModuleNotFoundError: missing module" : `file_${i}.txt`,
          path: `C:\\Data\\file_${i}.txt`,
          bytes: 1024,
        }));
        return { schema: "ff-win-v3-result-v1", ok: true, result: { path: "C:\\Data", items } };
      }
      const lines = Array.from({ length: 1200 }, (_, i) =>
        i === 600 ? "AssertionError: critical failure at middle line" : `step ${i} ok with padding text here`
      ).join("\n");
      return { schema: "ff-win-v3-result-v1", ok: true, result: { exit_code: 1, stdout: lines, stderr: "" } };
    },
  });

  const singleLineRes = await fc.dispatch("list_directory", { path: "C:\\Data" });
  assert.equal(singleLineRes.context_shield.triggered, true);
  assert.ok(singleLineRes.context_shield.files[0].original_chars > 120000);
  assert.ok(singleLineRes.context_shield.files[0].compacted_chars < 19500);
  assert.match(singleLineRes.result.spillover_digest, /ModuleNotFoundError/);

  const multiLineRes = await fc.dispatch("run_code", { code: "print(1)" });
  assert.equal(multiLineRes.context_shield.triggered, true);
  assert.match(multiLineRes.result.stdout, /AssertionError: critical failure/);
});

test("FlightController soft handover + poll + dedupe replay", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fc-handover-"));
  let executions = 0;
  const fc = new FlightController({
    stateDir: tmpDir,
    executor: async () => {
      executions++;
      await new Promise((r) => setTimeout(r, 120));
      return { schema: "ff-win-v3-result-v1", ok: true, result: { value: 42 } };
    },
  });

  const fast = await fc.dispatch("run_code", { __soft_timeout_ms: 1000, __dedupe_key: "k1" });
  assert.equal(fast.result.value, 42);
  const replay = await fc.dispatch("run_code", { __dedupe_key: "k1" });
  assert.equal(replay.deduped_replay, true);
  assert.equal(executions, 1);
});

test("Sol P1 #2 regression: local HTTP server commits side effect & drops socket — retry never re-executes or changes request_id", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fc-lost-ack-"));
  const secretFile = path.join(tmpDir, "secret");
  fs.writeFileSync(secretFile, "test-secret-123", "utf8");

  let sideEffects = 0;
  const actionRequestIds = [];

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (body.op === "request_status") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, result: { state: "outcome_unknown", retry_safe: false } }));
        return;
      }
      sideEffects++;
      actionRequestIds.push(body.request_id);
      req.socket.destroy();
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const callFF3 = createFF3FlightCaller({
    stateDir: tmpDir,
    secretPath: secretFile,
    selectBackend: async () => `http://127.0.0.1:${port}/rpc`,
  });

  try {
    let err1 = null;
    let err2 = null;
    try {
      await callFF3("write_file", { path: "C:\\test.txt", content: "once", __dedupe_key: "mut-1" });
    } catch (e) {
      err1 = e;
    }
    try {
      await callFF3("write_file", { path: "C:\\test.txt", content: "once", __dedupe_key: "mut-1" });
    } catch (e) {
      err2 = e;
    }

    assert.ok(err1 instanceof FlightOutcomeUnknownError);
    assert.ok(err2 instanceof FlightOutcomeUnknownError);
    assert.equal(sideEffects, 1, "Mutating action must execute strictly once across lost-ACK retry");
    assert.equal(actionRequestIds.length, 1);
    assert.equal(err1.request_id, actionRequestIds[0]);
    assert.equal(err2.request_id, err1.request_id, "Retry must preserve identical request_id");

    const fcReloaded = new FlightController({
      stateDir: tmpDir,
      executor: async () => {
        sideEffects++;
        return { ok: true, result: {} };
      },
    });
    await assert.rejects(
      () => fcReloaded.dispatch("write_file", { path: "C:\\test.txt", __dedupe_key: "mut-1" }),
      (e) => e instanceof FlightOutcomeUnknownError && e.request_id === err1.request_id
    );
    assert.equal(sideEffects, 1);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Sol P1 #2 reconciliation: retry recovers committed Bridge journal response after lost HTTP reply", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fc-reconcile-"));
  const secretFile = path.join(tmpDir, "secret");
  fs.writeFileSync(secretFile, "test-secret-456", "utf8");

  let sideEffects = 0;
  const journal = new Map();

  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (body.op === "request_status") {
        const key = `${body.args.op}:${body.args.dedupe_key}`;
        const saved = journal.get(key);
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            ok: true,
            result: saved
              ? { state: "completed", dedupe_journal_v1: true, response: saved }
              : { state: "not_found", dedupe_journal_v1: true },
          })
        );
        return;
      }
      sideEffects++;
      const committedResponse = {
        schema: "ff-win-v3-result-v1",
        ok: true,
        request_id: body.request_id,
        op: body.op,
        result: { committed_side_effect: sideEffects },
      };
      journal.set(`${body.op}:${body.dedupe_key}`, committedResponse);
      req.socket.destroy();
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const callFF3 = createFF3FlightCaller({
    stateDir: tmpDir,
    secretPath: secretFile,
    selectBackend: async () => `http://127.0.0.1:${port}/rpc`,
  });

  try {
    let err1 = null;
    try {
      await callFF3("run_code", { code: "mutate()", __dedupe_key: "rec-1" });
    } catch (e) {
      err1 = e;
    }
    assert.ok(err1 instanceof FlightOutcomeUnknownError);

    const recovered = await callFF3("run_code", { code: "mutate()", __dedupe_key: "rec-1" });
    assert.equal(recovered.ok, true);
    assert.equal(recovered.reconciled, true);
    assert.equal(recovered.deduped_replay, true);
    assert.equal(recovered.request_id, err1.request_id);
    assert.equal(recovered.result.committed_side_effect, 1);
    assert.equal(sideEffects, 1);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test("Sol P1 #2 cross-backend failover guard: peer backend empty journal never triggers false not_found replay", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fc-failover-"));
  const secretFile = path.join(tmpDir, "secret");
  fs.writeFileSync(secretFile, "test-secret-789", "utf8");

  let primaryEffects = 0;
  let secondaryEffects = 0;

  const primary = http.createServer((req) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      primaryEffects++;
      req.socket.destroy();
    });
  });

  const secondary = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (body.op === "request_status") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, result: { state: "not_found", dedupe_journal_v1: true } }));
        return;
      }
      secondaryEffects++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, result: { ran_on_secondary: true } }));
    });
  });

  await new Promise((resolve) => primary.listen(0, "127.0.0.1", resolve));
  await new Promise((resolve) => secondary.listen(0, "127.0.0.1", resolve));
  const pPort = primary.address().port;
  const sPort = secondary.address().port;

  let primaryAlive = true;
  const callFF3 = createFF3FlightCaller({
    stateDir: tmpDir,
    secretPath: secretFile,
    selectBackend: async () => (primaryAlive ? `http://127.0.0.1:${pPort}/rpc` : `http://127.0.0.1:${sPort}/rpc`),
  });

  try {
    let err1 = null;
    try {
      await callFF3("write_file", { path: "C:\\x.txt", content: "1", __dedupe_key: "fo-1" });
    } catch (e) {
      err1 = e;
    }
    assert.ok(err1 instanceof FlightOutcomeUnknownError);
    assert.equal(primaryEffects, 1);

    // Primary goes completely offline; selectBackend now points to secondary!
    await new Promise((resolve) => primary.close(resolve));
    primaryAlive = false;

    let err2 = null;
    try {
      await callFF3("write_file", { path: "C:\\x.txt", content: "1", __dedupe_key: "fo-1" });
    } catch (e) {
      err2 = e;
    }
    assert.ok(err2 instanceof FlightOutcomeUnknownError);
    assert.equal(err2.request_id, err1.request_id);
    assert.equal(secondaryEffects, 0, "Secondary backend must never execute when primary journal is unreachable");
  } finally {
    await new Promise((resolve) => secondary.close(resolve));
  }
});
