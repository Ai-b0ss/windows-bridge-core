import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Soft window stays safely under Cloudflare Durable Object's 20,000ms socket limit.
export const DEFAULT_SOFT_WINDOW_MS = 12500;
export const SOFT_WINDOW_MIN_MS = 1000;
export const SOFT_WINDOW_MAX_MS = 14000;
export const DEFAULT_HARD_TIMEOUT_MS = 30 * 60 * 1000;
export const MAX_HARD_TIMEOUT_MS = 2 * 60 * 60 * 1000;
export const FLIGHT_TTL_MS = 60 * 60 * 1000;
export const MAX_STORED_FLIGHTS = 200;
export const DEFAULT_MAX_INLINE_CHARS = 20000;
export const MAX_SPILLOVER_FILES = 60;

const TRANSPORT_META_KEYS = new Set([
  "__soft_timeout_ms",
  "__hard_timeout_ms",
  "__dedupe_key",
  "__max_inline_chars",
  "__raw_full",
  "__no_async_handover",
]);

const LOG_HEAVY_OPS = new Set([
  "run_code",
  "restricted_run_code",
  "start_process",
  "read_process_output",
  "interact_with_process",
  "durable_call",
]);

const RAW_EXEMPT_OPS = new Set([
  "read_file",
  "read_multiple_files",
  "open_file_read_stream",
  "read_file_stream_chunk",
  "gui_screenshot",
  "export_task_evidence",
]);

const DIAG_LINE_RE =
  /\b(error|exception|traceback|fatal|failed|failure|assertionerror|syntaxerror|typeerror|warn|warning)\b/i;

export class FlightOutcomeUnknownError extends Error {
  constructor({ requestId, flightId, dedupeKey, op, causeMessage }) {
    super(
      `FLIGHT_OUTCOME_UNKNOWN:request_id=${requestId}:flight_id=${flightId}:dedupe_key=${dedupeKey ?? ""}:${causeMessage ?? "transport_interrupted"}`
    );
    this.name = "FlightOutcomeUnknownError";
    this.code = "FLIGHT_OUTCOME_UNKNOWN";
    this.request_id = requestId;
    this.flight_id = flightId;
    this.dedupe_key = dedupeKey;
    this.op = op;
    this.retry_safe = false;
  }
}

function ensureDir(dirPath) {
  try {
    fs.mkdirSync(dirPath, { recursive: true });
  } catch {}
}

function clampInt(val, fallback, min, max) {
  const n = Number(val);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(Math.max(Math.trunc(n), min), max);
}

export function extractTransportMeta(rawArgs = {}) {
  const safeInput = rawArgs && typeof rawArgs === "object" && !Array.isArray(rawArgs) ? rawArgs : {};
  const cleanArgs = {};
  for (const [k, v] of Object.entries(safeInput)) {
    if (!TRANSPORT_META_KEYS.has(k)) cleanArgs[k] = v;
  }
  const dedupeCandidate = safeInput.__dedupe_key ?? safeInput.request_key ?? null;
  const dedupeKey =
    typeof dedupeCandidate === "string" && dedupeCandidate.trim().length > 0
      ? dedupeCandidate.trim().slice(0, 160)
      : null;

  return {
    cleanArgs,
    meta: {
      softWindowMs: clampInt(
        safeInput.__soft_timeout_ms,
        DEFAULT_SOFT_WINDOW_MS,
        SOFT_WINDOW_MIN_MS,
        SOFT_WINDOW_MAX_MS
      ),
      hardTimeoutMs: clampInt(
        safeInput.__hard_timeout_ms,
        DEFAULT_HARD_TIMEOUT_MS,
        5000,
        MAX_HARD_TIMEOUT_MS
      ),
      dedupeKey,
      maxInlineChars: clampInt(safeInput.__max_inline_chars, DEFAULT_MAX_INLINE_CHARS, 2000, 200000),
      rawFull: safeInput.__raw_full === true,
      noAsyncHandover: safeInput.__no_async_handover === true,
    },
  };
}

async function raceWithTimeout(promise, ms) {
  let timer = null;
  const timeoutPromise = new Promise((resolve) => {
    timer = setTimeout(() => resolve("TIMEOUT"), ms);
  });
  try {
    return await Promise.race([promise, timeoutPromise]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export class ContextShield {
  constructor(spilloverDir, stats) {
    this.spilloverDir = spilloverDir;
    this.stats = stats;
    ensureDir(this.spilloverDir);
  }

  _rotate() {
    try {
      const entries = fs
        .readdirSync(this.spilloverDir)
        .map((name) => {
          const full = path.join(this.spilloverDir, name);
          return { full, mtimeMs: fs.statSync(full).mtimeMs };
        })
        .sort((a, b) => b.mtimeMs - a.mtimeMs);
      for (const old of entries.slice(MAX_SPILLOVER_FILES)) {
        try {
          fs.unlinkSync(old.full);
        } catch {}
      }
    } catch {}
  }

  summarizeText(rawText, label, flightId, maxChars) {
    if (typeof rawText !== "string" || rawText.length <= maxChars) {
      return { changed: false, text: rawText, record: null };
    }
    const lines = rawText.split(/\r?\n/);
    if (lines.length <= 2 && /^[A-Za-z0-9+/=\r\n]+$/.test(rawText.slice(0, 512))) {
      return { changed: false, text: rawText, record: null };
    }

    ensureDir(this.spilloverDir);
    const safeLabel = String(label || "output").replace(/[^A-Za-z0-9_-]/g, "_");
    const fileName = `${new Date().toISOString().replace(/[:.]/g, "-")}-${flightId}-${safeLabel}.log`;
    const fullPath = path.join(this.spilloverDir, fileName);
    fs.writeFileSync(fullPath, rawText, "utf8");
    this._rotate();
    this.stats.spillovers_created++;

    const headCharBudget = Math.max(800, Math.floor(maxChars * 0.42));
    const tailCharBudget = Math.max(800, Math.floor(maxChars * 0.36));

    const headCount = 35;
    const tailCount = 45;
    let head = lines.slice(0, headCount).join("\n");
    let tail = lines.length > headCount ? lines.slice(-tailCount).join("\n") : "";
    let charClamped = false;

    if (head.length > headCharBudget || tail.length > tailCharBudget || lines.length <= 4) {
      charClamped = true;
      head = rawText.slice(0, headCharBudget);
      tail =
        rawText.length > headCharBudget + tailCharBudget
          ? rawText.slice(-tailCharBudget)
          : rawText.slice(headCharBudget);
    }

    const diagLines = [];
    if (!charClamped) {
      const middleEnd = Math.max(headCount, lines.length - tailCount);
      for (let i = headCount; i < middleEnd; i++) {
        if (DIAG_LINE_RE.test(lines[i])) {
          diagLines.push(`[L${i + 1}] ${lines[i].slice(0, 260)}`);
          if (diagLines.length >= 25) break;
        }
      }
    } else if (rawText.length > headCharBudget + tailCharBudget) {
      const middleSlice = rawText.slice(headCharBudget, rawText.length - tailCharBudget);
      const regex =
        /.{0,80}\b(?:error|exception|traceback|fatal|failed|failure|assertionerror|syntaxerror|typeerror|modulenotfounderror)\b.{0,140}/gi;
      let match;
      while ((match = regex.exec(middleSlice)) !== null && diagLines.length < 15) {
        diagLines.push(`[+${headCharBudget + match.index}c] ${match[0].replace(/\s+/g, " ").trim()}`);
      }
    }

    const parts = [
      `[CONTEXT_SHIELD_SPILLOVER field="${safeLabel}" total_chars=${rawText.length} total_lines=${lines.length} full_log="${fullPath}"]`,
      charClamped
        ? `--- HEAD (first ${head.length} chars) ---`
        : `--- HEAD (first ${Math.min(headCount, lines.length)} lines) ---`,
      head,
    ];
    if (diagLines.length > 0) {
      parts.push(`--- DIAGNOSTIC HIGHLIGHTS (${diagLines.length} middle matches) ---`);
      parts.push(diagLines.join("\n"));
    }
    if (tail) {
      parts.push(
        charClamped
          ? `--- TAIL (last ${tail.length} chars) ---`
          : `--- TAIL (last ${Math.min(tailCount, lines.length - headCount)} lines) ---`
      );
      parts.push(tail);
    }
    parts.push(`[END_SPILLOVER_DIGEST: read "${fullPath}" with offset/length if middle content is needed]`);

    const compacted = parts.join("\n");
    return {
      changed: true,
      text: compacted,
      record: {
        field: safeLabel,
        path: fullPath,
        original_chars: rawText.length,
        original_lines: lines.length,
        compacted_chars: compacted.length,
        diagnostic_matches: diagLines.length,
      },
    };
  }

  apply(op, data, flightId, meta) {
    if (!data || typeof data !== "object" || meta.rawFull || RAW_EXEMPT_OPS.has(op)) {
      return data;
    }
    const maxChars = meta.maxInlineChars;
    const records = [];
    const clone = structuredClone(data);
    const inner = clone.result && typeof clone.result === "object" ? clone.result : null;

    if (inner && LOG_HEAVY_OPS.has(op)) {
      for (const field of ["stdout", "stderr"]) {
        if (typeof inner[field] === "string" && inner[field].length > maxChars) {
          const res = this.summarizeText(inner[field], field, flightId, maxChars);
          if (res.changed) {
            inner[field] = res.text;
            records.push(res.record);
          }
        }
      }
      if (Array.isArray(inner.events)) {
        const joined = inner.events.map((ev) => ev?.text ?? "").join("");
        if (joined.length > maxChars) {
          const res = this.summarizeText(joined, "process_events", flightId, maxChars);
          if (res.changed) {
            inner.events = [
              { seq: inner.buffer_first_seq ?? 1, stream: "stdout", text: res.text, ts: Date.now() },
            ];
            records.push(res.record);
          }
        }
      }
    }

    const serialized = JSON.stringify(clone);
    if (records.length === 0 && serialized.length > maxChars * 2.0) {
      const res = this.summarizeText(serialized, op + "_json", flightId, maxChars);
      if (res.changed) {
        return {
          schema: clone.schema ?? "ff-win-v3-result-v1",
          ok: clone.ok ?? true,
          request_id: clone.request_id ?? flightId,
          device: clone.device ?? os.hostname(),
          op,
          context_shield: { triggered: true, files: [res.record] },
          result: { spillover_digest: res.text, spillover_file: res.record.path },
        };
      }
    }

    if (records.length > 0) {
      clone.context_shield = { triggered: true, files: records };
    }
    return clone;
  }
}

export class FlightController {
  constructor({ executor, reconciler = null, stateDir } = {}) {
    this.executor = executor;
    this.reconciler = reconciler;
    this.stateDir =
      stateDir ?? process.env.FF_CF_STATE_DIR ?? path.join(__dirname, "state", "cf-flight-controller");
    this.journalPath = path.join(this.stateDir, "flights-journal.json");
    this.spilloverDir = path.join(this.stateDir, "spillover");
    this.flights = new Map();
    this.dedupeIndex = new Map();
    this.stats = {
      started_at: new Date().toISOString(),
      total_rpc: 0,
      fast_completed: 0,
      async_handovers: 0,
      poll_calls: 0,
      deduped_hits: 0,
      reconciled_recoveries: 0,
      outcome_unknown_blocks: 0,
      cancelled_flights: 0,
      spillovers_created: 0,
    };
    this.shield = new ContextShield(this.spilloverDir, this.stats);
    ensureDir(this.stateDir);
    this._loadJournal();
  }

  _loadJournal() {
    try {
      if (!fs.existsSync(this.journalPath)) return;
      const parsed = JSON.parse(fs.readFileSync(this.journalPath, "utf8"));
      const now = Date.now();
      for (const item of parsed?.flights ?? []) {
        if (!item?.flight_id || now - (item.created_at ?? 0) > FLIGHT_TTL_MS) continue;
        if (item.status === "RUNNING") {
          item.status = "INTERRUPTED_BY_AGENT_RESTART";
          item.ended_at = now;
        }
        this.flights.set(item.flight_id, item);
        if (
          item.dedupe_key &&
          (item.status === "COMPLETED" ||
            item.status === "OUTCOME_UNKNOWN" ||
            item.status === "INTERRUPTED_BY_AGENT_RESTART")
        ) {
          this.dedupeIndex.set(item.dedupe_key, item.flight_id);
        }
      }
    } catch {}
  }

  _persistJournal() {
    try {
      this._prune();
      const serializable = [];
      for (const f of this.flights.values()) {
        serializable.push({
          flight_id: f.flight_id,
          request_id: f.request_id,
          op: f.op,
          dedupe_key: f.dedupe_key,
          backend_url: f.backend_url ?? null,
          status: f.status,
          created_at: f.created_at,
          ended_at: f.ended_at,
          duration_ms: f.duration_ms,
          poll_count: f.poll_count,
          handover_triggered: f.handover_triggered,
          error: f.error,
          shieldedResult: f.status === "COMPLETED" ? f.shieldedResult : null,
        });
      }
      const tmp = this.journalPath + ".tmp";
      fs.writeFileSync(tmp, JSON.stringify({ updated_at: Date.now(), flights: serializable }), "utf8");
      fs.renameSync(tmp, this.journalPath);
    } catch {}
  }

  _prune() {
    const now = Date.now();
    for (const [id, f] of this.flights.entries()) {
      if (f.status !== "RUNNING" && now - f.created_at > FLIGHT_TTL_MS) {
        this.flights.delete(id);
        if (f.dedupe_key && this.dedupeIndex.get(f.dedupe_key) === id) {
          this.dedupeIndex.delete(f.dedupe_key);
        }
      }
    }
    if (this.flights.size > MAX_STORED_FLIGHTS) {
      const finished = [...this.flights.values()]
        .filter(
          (f) =>
            f.status !== "RUNNING" &&
            f.status !== "OUTCOME_UNKNOWN" &&
            f.status !== "INTERRUPTED_BY_AGENT_RESTART"
        )
        .sort((a, b) => a.created_at - b.created_at);
      for (const victim of finished.slice(0, Math.max(0, this.flights.size - MAX_STORED_FLIGHTS))) {
        this.flights.delete(victim.flight_id);
        if (victim.dedupe_key && this.dedupeIndex.get(victim.dedupe_key) === victim.flight_id) {
          this.dedupeIndex.delete(victim.dedupe_key);
        }
      }
    }
  }

  _buildTicket(flight, note = "Operation exceeded soft synchronous window and continues in background.") {
    return {
      schema: "ff-win-v3-flight-ticket-v1",
      ok: true,
      async_handover: true,
      status: flight.status,
      flight_id: flight.flight_id,
      request_id: flight.request_id,
      op: flight.op,
      elapsed_ms: Date.now() - flight.created_at,
      poll_count: flight.poll_count,
      note,
      next_action: { op: "__flight_poll", args: { flight_id: flight.flight_id, wait_ms: 12000 } },
      cancel_action: { op: "__flight_cancel", args: { flight_id: flight.flight_id } },
    };
  }

  async _executeBatch(cleanArgs, ctx) {
    const calls = cleanArgs?.calls;
    const stopOnError = cleanArgs?.stop_on_error !== false;
    if (!Array.isArray(calls) || calls.length < 1 || calls.length > 16) {
      const err = new Error("INVALID_BATCH: calls must be an array of 1..16 operations");
      err.beforeDispatch = true;
      throw err;
    }
    for (let i = 0; i < calls.length; i++) {
      const c = calls[i];
      if (!c || typeof c !== "object" || Array.isArray(c) || typeof c.op !== "string" || !c.op.trim()) {
        const err = new Error(`INVALID_BATCH_STEP[${i}]: expected { op: string, args?: object }`);
        err.beforeDispatch = true;
        throw err;
      }
      const stepOp = c.op.trim();
      if (stepOp === "batch" || stepOp.startsWith("__flight_")) {
        const err = new Error(`INVALID_BATCH_NESTED_OP[${i}]: "${stepOp}" is not allowed inside batch`);
        err.beforeDispatch = true;
        throw err;
      }
      if (c.args !== undefined && (c.args === null || typeof c.args !== "object" || Array.isArray(c.args))) {
        const err = new Error(`INVALID_BATCH_ARGS[${i}]: args must be a plain object`);
        err.beforeDispatch = true;
        throw err;
      }
    }

    const results = [];
    let stopped = false;
    for (let i = 0; i < calls.length; i++) {
      const stepOp = calls[i].op.trim();
      if (stopped) {
        results.push({ index: i, op: stepOp, status: "not_started" });
        continue;
      }
      if (ctx.signal?.aborted) {
        results.push({ index: i, op: stepOp, status: "aborted" });
        stopped = true;
        continue;
      }
      const { cleanArgs: stepCleanArgs, meta: stepMeta } = extractTransportMeta(calls[i].args ?? {});
      const stepDedupeKey = stepMeta.dedupeKey || (ctx.dedupeKey ? `${ctx.dedupeKey}:s${i}` : null);
      const t0 = Date.now();
      try {
        const res = await this.executor(stepOp, stepCleanArgs, {
          requestId: `${ctx.requestId}_s${i}`,
          dedupeKey: stepDedupeKey,
          signal: ctx.signal,
          setBackendUrl: ctx.setBackendUrl,
        });
        const failed = !res || res.ok === false || res.result?.ok === false;
        results.push({
          index: i,
          op: stepOp,
          status: failed ? "error" : "completed",
          duration_ms: Date.now() - t0,
          result: res,
        });
        if (failed && stopOnError) stopped = true;
      } catch (err) {
        results.push({
          index: i,
          op: stepOp,
          status: "outcome_unknown",
          duration_ms: Date.now() - t0,
          error: err instanceof Error ? err.message : String(err),
        });
        stopped = true;
      }
    }

    return {
      schema: "ff-win-v3-batch-v1",
      ok: results.every((r) => r.status === "completed"),
      total: calls.length,
      dispatched: results.filter((r) => r.status !== "not_started" && r.status !== "aborted").length,
      completed: results.filter((r) => r.status === "completed").length,
      stopped_on_error: stopped,
      results,
    };
  }

  async dispatch(op, rawArgs = {}) {
    if (op === "__flight_poll") return this.pollFlight(rawArgs);
    if (op === "__flight_list") return this.listFlights(rawArgs);
    if (op === "__flight_cancel") return this.cancelFlight(rawArgs);
    if (op === "__flight_stats") return this.getStats();

    this.stats.total_rpc++;
    const { cleanArgs, meta } = extractTransportMeta(rawArgs);
    let reusedRequestId = null;

    if (meta.dedupeKey && this.dedupeIndex.has(meta.dedupeKey)) {
      const existing = this.flights.get(this.dedupeIndex.get(meta.dedupeKey));
      if (existing) {
        if (existing.op !== op) {
          throw new Error(
            `DEDUPE_KEY_CONFLICT: key "${meta.dedupeKey}" is bound to op "${existing.op}", cannot reuse for "${op}"`
          );
        }
        this.stats.deduped_hits++;
        if (existing.status === "COMPLETED") {
          return { ...existing.shieldedResult, deduped_replay: true, flight_id: existing.flight_id };
        }
        if (existing.status === "RUNNING") {
          return this._awaitOrHandover(existing, meta);
        }
        if (
          existing.status === "OUTCOME_UNKNOWN" ||
          existing.status === "INTERRUPTED_BY_AGENT_RESTART"
        ) {
          if (typeof this.reconciler === "function") {
            let rec = null;
            try {
              rec = await this.reconciler({
                op: existing.op,
                cleanArgs,
                requestId: existing.request_id,
                dedupeKey: existing.dedupe_key,
                flightId: existing.flight_id,
                backendUrl: existing.backend_url ?? null,
              });
            } catch {
              rec = null;
            }
            if (rec && rec.state === "completed" && rec.response && typeof rec.response === "object") {
              existing.status = "COMPLETED";
              existing.error = null;
              existing.shieldedResult = this.shield.apply(op, rec.response, existing.flight_id, meta);
              this.stats.reconciled_recoveries++;
              this._persistJournal();
              return {
                ...existing.shieldedResult,
                deduped_replay: true,
                reconciled: true,
                flight_id: existing.flight_id,
              };
            }
            if (rec && rec.state === "not_found" && rec.dedupe_journal_v1 === true) {
              reusedRequestId = existing.request_id;
              this.flights.delete(existing.flight_id);
              this.dedupeIndex.delete(meta.dedupeKey);
            }
          }
          if (!reusedRequestId) {
            this.stats.outcome_unknown_blocks++;
            throw new FlightOutcomeUnknownError({
              requestId: existing.request_id,
              flightId: existing.flight_id,
              dedupeKey: existing.dedupe_key,
              op: existing.op,
              causeMessage: existing.error,
            });
          }
        }
      }
    }

    const flightId = "flt_" + Date.now().toString(36) + "_" + crypto.randomBytes(4).toString("hex");
    const requestId = reusedRequestId ?? crypto.randomUUID();
    const controller = new AbortController();
    const hardTimer = setTimeout(() => controller.abort(new Error("FLIGHT_HARD_TIMEOUT")), meta.hardTimeoutMs);
    if (typeof hardTimer.unref === "function") hardTimer.unref();

    const flight = {
      flight_id: flightId,
      request_id: requestId,
      op,
      dedupe_key: meta.dedupeKey,
      backend_url: null,
      status: "RUNNING",
      created_at: Date.now(),
      ended_at: null,
      duration_ms: null,
      poll_count: 0,
      handover_triggered: false,
      error: null,
      shieldedResult: null,
      controller,
      promise: null,
    };

    if (meta.dedupeKey) this.dedupeIndex.set(meta.dedupeKey, flightId);
    this.flights.set(flightId, flight);

    flight.promise = (async () => {
      try {
        const execCtx = {
          requestId,
          dedupeKey: meta.dedupeKey,
          signal: controller.signal,
          setBackendUrl: (url) => {
            if (typeof url === "string" && url.length > 0) flight.backend_url = url;
          },
        };
        const rawData = op === "batch"
          ? await this._executeBatch(cleanArgs, execCtx)
          : await this.executor(op, cleanArgs, execCtx);
        flight.ended_at = Date.now();
        flight.duration_ms = flight.ended_at - flight.created_at;
        flight.status = "COMPLETED";
        flight.shieldedResult = this.shield.apply(op, rawData, flightId, meta);
        if (flight.handover_triggered || meta.dedupeKey) this._persistJournal();
        return { ok: true };
      } catch (err) {
        flight.ended_at = Date.now();
        flight.duration_ms = flight.ended_at - flight.created_at;
        flight.error = err instanceof Error ? err.message : String(err);
        const beforeDispatch = err && typeof err === "object" && err.beforeDispatch === true;
        if (flight.status === "CANCELLED" || beforeDispatch || !meta.dedupeKey) {
          if (flight.status !== "CANCELLED") flight.status = "FAILED";
          if (meta.dedupeKey && this.dedupeIndex.get(meta.dedupeKey) === flightId) {
            this.dedupeIndex.delete(meta.dedupeKey);
          }
          if (flight.handover_triggered) this._persistJournal();
        } else {
          flight.status = "OUTCOME_UNKNOWN";
          this._persistJournal();
        }
        return { ok: false };
      } finally {
        clearTimeout(hardTimer);
      }
    })();

    return this._awaitOrHandover(flight, meta);
  }

  async _awaitOrHandover(flight, meta) {
    if (meta.noAsyncHandover) {
      const outcome = await flight.promise;
      if (!outcome.ok) {
        if (flight.status === "OUTCOME_UNKNOWN") {
          throw new FlightOutcomeUnknownError({
            requestId: flight.request_id,
            flightId: flight.flight_id,
            dedupeKey: flight.dedupe_key,
            op: flight.op,
            causeMessage: flight.error,
          });
        }
        throw new Error(flight.error || "FF3_CALL_FAILED");
      }
      this.stats.fast_completed++;
      return flight.shieldedResult;
    }

    const winner = await raceWithTimeout(flight.promise, meta.softWindowMs);
    if (winner === "TIMEOUT" && flight.status === "RUNNING") {
      flight.handover_triggered = true;
      this.stats.async_handovers++;
      this._persistJournal();
      return this._buildTicket(flight);
    }

    if (flight.status === "COMPLETED") {
      this.stats.fast_completed++;
      return flight.shieldedResult;
    }
    if (flight.status === "OUTCOME_UNKNOWN") {
      throw new FlightOutcomeUnknownError({
        requestId: flight.request_id,
        flightId: flight.flight_id,
        dedupeKey: flight.dedupe_key,
        op: flight.op,
        causeMessage: flight.error,
      });
    }
    throw new Error(flight.error || `FLIGHT_${flight.status}`);
  }

  async pollFlight(rawArgs = {}) {
    this.stats.poll_calls++;
    const flightId = String(rawArgs?.flight_id ?? "").trim();
    if (!flightId) throw new Error("FLIGHT_ID_REQUIRED");
    const flight = this.flights.get(flightId);
    if (!flight) throw new Error(`FLIGHT_NOT_FOUND:${flightId}`);

    flight.poll_count = (flight.poll_count ?? 0) + 1;
    const waitMs = clampInt(rawArgs?.wait_ms, 12000, 100, 13500);

    if (flight.status === "RUNNING" && flight.promise) {
      await raceWithTimeout(flight.promise, waitMs);
    }

    if (flight.status === "RUNNING") {
      return this._buildTicket(flight, "Flight is still running; call __flight_poll again.");
    }

    if (flight.status === "COMPLETED") {
      return {
        schema: "ff-win-v3-flight-poll-v1",
        ok: true,
        async_handover: false,
        status: "COMPLETED",
        flight_id: flight.flight_id,
        request_id: flight.request_id,
        op: flight.op,
        duration_ms: flight.duration_ms,
        poll_count: flight.poll_count,
        result: flight.shieldedResult,
      };
    }

    return {
      schema: "ff-win-v3-flight-poll-v1",
      ok: false,
      status: flight.status,
      retry_safe: flight.status !== "OUTCOME_UNKNOWN",
      flight_id: flight.flight_id,
      request_id: flight.request_id,
      op: flight.op,
      duration_ms: flight.duration_ms,
      error: flight.error,
    };
  }

  cancelFlight(rawArgs = {}) {
    const flightId = String(rawArgs?.flight_id ?? "").trim();
    if (!flightId) throw new Error("FLIGHT_ID_REQUIRED");
    const flight = this.flights.get(flightId);
    if (!flight) throw new Error(`FLIGHT_NOT_FOUND:${flightId}`);
    if (flight.status === "RUNNING" && flight.controller) {
      flight.status = "CANCELLED";
      flight.ended_at = Date.now();
      flight.duration_ms = flight.ended_at - flight.created_at;
      flight.controller.abort(new Error("CANCELLED_BY_CALLER"));
      this.stats.cancelled_flights++;
      this._persistJournal();
      return { ok: true, flight_id: flightId, status: "CANCELLED" };
    }
    return { ok: true, flight_id: flightId, status: flight.status, note: "Flight already settled" };
  }

  listFlights(rawArgs = {}) {
    this._prune();
    const statusFilter = typeof rawArgs?.status === "string" ? rawArgs.status.toUpperCase() : null;
    const limit = clampInt(rawArgs?.limit, 30, 1, 100);
    const items = [...this.flights.values()]
      .filter((f) => !statusFilter || f.status === statusFilter)
      .sort((a, b) => b.created_at - a.created_at)
      .slice(0, limit)
      .map((f) => ({
        flight_id: f.flight_id,
        request_id: f.request_id,
        op: f.op,
        status: f.status,
        elapsed_ms: (f.ended_at ?? Date.now()) - f.created_at,
        poll_count: f.poll_count,
        handover_triggered: f.handover_triggered,
        error: f.error,
      }));
    return { ok: true, count: items.length, items, stats: this.getStats() };
  }

  getStats() {
    let active = 0;
    for (const f of this.flights.values()) {
      if (f.status === "RUNNING") active++;
    }
    return {
      ok: true,
      module_version: "0.5.2-flight-controller-shield",
      soft_window_ms: DEFAULT_SOFT_WINDOW_MS,
      cloudflare_do_ceiling_ms: 20000,
      default_max_inline_chars: DEFAULT_MAX_INLINE_CHARS,
      active_flights: active,
      stored_flights: this.flights.size,
      ...this.stats,
    };
  }
}

export function createFF3FlightCaller({ selectBackend, secretPath, stateDir } = {}) {
  const fc = new FlightController({
    stateDir,
    executor: async (op, cleanArgs, { requestId, dedupeKey, signal, setBackendUrl }) => {
      let secret;
      let targetUrl;
      try {
        secret = fs.readFileSync(secretPath, "utf8").trim();
        targetUrl = await selectBackend(op, cleanArgs);
        if (typeof setBackendUrl === "function") setBackendUrl(targetUrl);
      } catch (prepErr) {
        const wrapped = prepErr instanceof Error ? prepErr : new Error(String(prepErr));
        wrapped.beforeDispatch = true;
        throw wrapped;
      }
      const payload = { op, args: cleanArgs, request_id: requestId };
      if (dedupeKey) payload.dedupe_key = dedupeKey;
      const response = await fetch(targetUrl, {
        method: "POST",
        headers: { "content-type": "application/json", "X-FF3-Key": secret },
        body: JSON.stringify(payload),
        signal,
      });
      const text = await response.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        throw new Error("FF3_INVALID_JSON:" + text.slice(0, 500));
      }
      if (!response.ok) {
        throw new Error("FF3_HTTP_" + response.status + ":" + JSON.stringify(data));
      }
      return data;
    },
    reconciler: async ({ op, cleanArgs, requestId, dedupeKey, backendUrl }) => {
      if (!dedupeKey) return { state: "outcome_unknown" };
      const secret = fs.readFileSync(secretPath, "utf8").trim();
      // Always reconcile against the exact backend URL that received the original flight so
      // port failover (39073 -> 39076) never misreads a peer's empty journal as not_found.
      const targetUrl = backendUrl || (await selectBackend("request_status", cleanArgs));
      const response = await fetch(targetUrl, {
        method: "POST",
        headers: { "content-type": "application/json", "X-FF3-Key": secret },
        body: JSON.stringify({
          op: "request_status",
          args: { op, dedupe_key: dedupeKey },
          request_id: `reconcile:${requestId}`,
        }),
        signal: AbortSignal.timeout(4000),
      });
      if (!response.ok) return { state: "outcome_unknown" };
      const data = await response.json();
      if (!data?.ok || !data?.result) return { state: "outcome_unknown" };
      return data.result;
    },
  });
  return (op, args = {}) => fc.dispatch(op, args);
}
