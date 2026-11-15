import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { FlightController } from "./flight-controller.mjs";

test("ContextShield v0.5.1 clamps both single-line 150KB JSON and multi-line logs", async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "fc-v051-"));
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
