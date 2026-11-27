/** Tool behavior metadata and ordered calls. No automatic retries. */
export const READ_OPERATIONS = [
  "capabilities", "device_info", "release_provenance", "list_directory",
  "get_file_info", "read_file", "read_multiple_files", "list_processes",
  "read_process_output", "request_status", "get_usage_stats",
] as const;

export const READ_ANNOTATIONS = {
  readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: true,
};
export const WRITE_ANNOTATIONS = {
  readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true,
};
type Call = { op: string; args?: Record<string, unknown> };
function failed(value: any): boolean {
  return value?.ok === false || value?.isError === true ||
    value?.result?.ok === false;
}
export async function runOrderedBatch(
  calls: Call[],
  dispatch: (op: string, args: Record<string, unknown>) => Promise<unknown>,
) {
  // Validate every entry before the first side effect, including callers outside Zod.
  if (!Array.isArray(calls) || calls.length < 1 || calls.length > 8 ||
      calls.some(c => !c || typeof c.op !== "string" || !c.op.trim() ||
        (c.args !== undefined && (c.args === null || typeof c.args !== "object" || Array.isArray(c.args))))) {
    throw new Error("INVALID_BATCH: expected 1..8 operations with object arguments");
  }
  const results: { index: number; op: string; status: string; result?: unknown; error?: string }[] = [];
  let stopped = false;
  for (const [index, call] of calls.entries()) {
    if (stopped) {
      results.push({ index, op: call.op, status: "not_started" });
      continue;
    }
    try {
      const result = await dispatch(call.op, call.args ?? {});
      const status = failed(result) ? "error" : "completed";
      results.push({ index, op: call.op, status, result });
      stopped = status === "error";
    } catch (error) {
      // Dispatch may already have reached Windows. Preserve uncertainty and stop.
      results.push({ index, op: call.op, status: "outcome_unknown",
        error: error instanceof Error ? error.message : String(error) });
      stopped = true;
    }
  }
  return { ok: !stopped, total: calls.length,
    dispatched: results.filter(r => r.status !== "not_started").length,
    completed: results.filter(r => r.status === "completed").length,
    results };
}
