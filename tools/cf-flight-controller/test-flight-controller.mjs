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

test("FlightController batch executes sequential calls, propagates step dedupe keys, and stops on error by default", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fc-batch-"));
  try {
    const seen = [];
    const fc = new FlightController({
      stateDir: tmpDir,
      executor: async (op, args, ctx) => {
        seen.push({ op, args, requestId: ctx.requestId, dedupeKey: ctx.dedupeKey });
        if (op === "fail_step") return { ok: false, error_code: "STEP_FAILED" };
        return { ok: true, result: { echoed: args.value } };
      },
    });

    const okRes = await fc.dispatch("batch", {
      __dedupe_key: "batch-ok-1",
      calls: [
        { op: "ping", args: { value: 1 } },
        { op: "read_file", args: { value: 2, __dedupe_key: "explicit-s1" } },
      ],
    });
    assert.equal(okRes.schema, "ff-win-v3-batch-v1");
    assert.equal(okRes.ok, true);
    assert.equal(okRes.total, 2);
    assert.equal(okRes.dispatched, 2);
    assert.equal(okRes.completed, 2);
    assert.equal(okRes.stopped_on_error, false);
    assert.equal(seen[0].dedupeKey, "batch-ok-1:s0");
    assert.equal(seen[1].dedupeKey, "explicit-s1");

    const stopRes = await fc.dispatch("batch", {
      calls: [
        { op: "ping", args: { value: "a" } },
        { op: "fail_step", args: {} },
        { op: "ping", args: { value: "never-run" } },
      ],
    });
    assert.equal(stopRes.ok, false);
    assert.equal(stopRes.dispatched, 2);
    assert.equal(stopRes.completed, 1);
    assert.equal(stopRes.stopped_on_error, true);
    assert.equal(stopRes.results[1].status, "error");
    assert.equal(stopRes.results[2].status, "not_started");

    const contRes = await fc.dispatch("batch", {
      stop_on_error: false,
      calls: [
        { op: "fail_step", args: {} },
        { op: "ping", args: { value: "runs-anyway" } },
      ],
    });
    assert.equal(contRes.ok, false);
    assert.equal(contRes.dispatched, 2);
    assert.equal(contRes.completed, 1);
    assert.equal(contRes.stopped_on_error, false);
    assert.equal(contRes.results[1].status, "completed");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("FlightController batch validates inputs before dispatch and halts on thrown outcome_unknown", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fc-batch-guard-"));
  try {
    let dispatched = 0;
    const fc = new FlightController({
      stateDir: tmpDir,
      executor: async (op) => {
        dispatched++;
        if (op === "boom") throw new Error("socket reset");
        return { ok: true, result: {} };
      },
    });

    await assert.rejects(() => fc.dispatch("batch", { calls: [] }), /INVALID_BATCH/);
    await assert.rejects(
      () => fc.dispatch("batch", { calls: Array.from({ length: 17 }, () => ({ op: "ping" })) }),
      /INVALID_BATCH/
    );
    await assert.rejects(() => fc.dispatch("batch", { calls: [{ op: "batch" }] }), /INVALID_BATCH_NESTED_OP/);
    await assert.rejects(() => fc.dispatch("batch", { calls: [{ op: "__flight_poll" }] }), /INVALID_BATCH_NESTED_OP/);
    await assert.rejects(() => fc.dispatch("batch", { calls: [{ op: "ping", args: ["bad"] }] }), /INVALID_BATCH_ARGS/);
    assert.equal(dispatched, 0);

    const thrownRes = await fc.dispatch("batch", {
      stop_on_error: false,
      calls: [{ op: "boom" }, { op: "ping" }],
    });
    assert.equal(thrownRes.ok, false);
    assert.equal(thrownRes.stopped_on_error, true);
    assert.equal(thrownRes.dispatched, 1);
    assert.equal(thrownRes.results[0].status, "outcome_unknown");
    assert.match(thrownRes.results[0].error, /socket reset/);
    assert.equal(thrownRes.results[1].status, "not_started");
    assert.equal(dispatched, 1);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("FlightController batch bounds derived step dedupe keys to <=160 chars without prefix collision", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fc-batch-keycap-"));
  try {
    const keys = [];
    const fc = new FlightController({
      stateDir: tmpDir,
      executor: async (op, args, ctx) => {
        keys.push(ctx.dedupeKey);
        return { ok: true, result: {} };
      },
    });
    const baseA = "a".repeat(159) + "1";
    const baseB = "a".repeat(159) + "2";
    await fc.dispatch("batch", { __dedupe_key: baseA, calls: [{ op: "ping" }, { op: "ping" }] });
    await fc.dispatch("batch", { __dedupe_key: baseB, calls: [{ op: "ping" }] });
    assert.equal(keys.length, 3);
    for (const k of keys) {
      assert.ok(k.length <= 160, `Derived step dedupeKey exceeded 160 chars: ${k.length}`);
    }
    assert.notEqual(keys[0], keys[1], "Distinct step indices must produce distinct keys");
    assert.notEqual(keys[0], keys[2], "Distinct 160-char base keys must not collide after truncation");
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("FlightController cancelFlight on running batch never overwrites status to COMPLETED", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fc-batch-cancel-"));
  try {
    const fcClean = new FlightController({
      stateDir: path.join(tmpDir, "clean"),
      executor: async () => {
        await new Promise((resolve) => setTimeout(resolve, 1150));
        return { ok: true, result: {} };
      },
    });
    const ticketClean = await fcClean.dispatch("batch", {
      __soft_timeout_ms: 1000,
      __dedupe_key: "cancel-clean-1",
      calls: [{ op: "slow1" }, { op: "slow2" }],
    });
    assert.equal(ticketClean.status, "RUNNING");
    assert.equal(fcClean.cancelFlight({ flight_id: ticketClean.flight_id }).status, "CANCELLED");
    await new Promise((resolve) => setTimeout(resolve, 250));
    const pollClean = await fcClean.pollFlight({ flight_id: ticketClean.flight_id, wait_ms: 200 });
    assert.equal(pollClean.ok, false);
    assert.equal(pollClean.status, "CANCELLED");

    const fcUnknown = new FlightController({
      stateDir: path.join(tmpDir, "unknown"),
      executor: async (op, args, ctx) => {
        await new Promise((resolve) => setTimeout(resolve, 1150));
        if (ctx.signal?.aborted) throw new Error("ABORTED_IN_FLIGHT");
        return { ok: true, result: {} };
      },
    });
    const ticketUnknown = await fcUnknown.dispatch("batch", {
      __soft_timeout_ms: 1000,
      __dedupe_key: "cancel-unknown-1",
      calls: [{ op: "slow_mut" }, { op: "never" }],
    });
    assert.equal(fcUnknown.cancelFlight({ flight_id: ticketUnknown.flight_id }).status, "CANCELLED");
    await new Promise((resolve) => setTimeout(resolve, 250));
    const pollUnknown = await fcUnknown.pollFlight({ flight_id: ticketUnknown.flight_id, wait_ms: 200 });
    assert.equal(pollUnknown.ok, false);
    assert.equal(pollUnknown.status, "OUTCOME_UNKNOWN");
    assert.equal(pollUnknown.retry_safe, false);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
