/**
 * Reproducible WebSocket client connecting a local Windows Bridge v3 RPC server
 * to the Cloudflare Worker DeviceHub (`/ws`).
 *
 * Uses the native `createFF3FlightCaller({ selectBackend, secretPath, stateDir, ... })`
 * contract from `../../tools/cf-flight-controller/flight-controller.mjs` so dedupe
 * journal, exact-backend reconciliation, soft handover, and non-replay of ambiguous
 * mutations are preserved end-to-end.
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import WebSocket from "ws";
import { createFF3FlightCaller } from "../../tools/cf-flight-controller/flight-controller.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEVICE_NAME_RE = /^[A-Za-z0-9_-]{1,100}$/;

const EXEC_TEST_ALLOWLIST = Object.freeze({
  hostname: () => os.hostname(),
  whoami: () => os.userInfo().username,
  node_version: () => process.version,
});

export function runExecTest(action) {
  if (typeof action !== "string" || !Object.prototype.hasOwnProperty.call(EXEC_TEST_ALLOWLIST, action)) {
    return { ok: false, error: "EXEC_TEST_ACTION_NOT_ALLOWED", allowed: Object.keys(EXEC_TEST_ALLOWLIST) };
  }
  const output = String(EXEC_TEST_ALLOWLIST[action]());
  return { ok: true, action, output };
}

export function loadConfig(overrides = {}) {
  const cfgIdx = process.argv.indexOf("--config");
  const cfgPath = overrides.configPath
    || (cfgIdx >= 0 && process.argv[cfgIdx + 1] ? path.resolve(process.argv[cfgIdx + 1]) : path.join(__dirname, "cf-agent-settings.json"));

  let fileCfg = {};
  if (!overrides.skipFile && fs.existsSync(cfgPath)) {
    fileCfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  }

  const readSecret = (directVal, envVal, envFile, cfgFile) => {
    if (directVal && String(directVal).trim()) return String(directVal).trim();
    if (envVal && envVal.trim()) return envVal.trim();
    const p = envFile || cfgFile;
    if (p && fs.existsSync(p)) return fs.readFileSync(p, "utf8").trim();
    return "";
  };

  const workerBaseUrl = String(overrides.workerBaseUrl ?? process.env.FF_MCP_BASE ?? fileCfg.workerBaseUrl ?? "").replace(/\/+$/, "");
  const wsPath = String(overrides.wsPath ?? process.env.FF_WS_PATH ?? fileCfg.wsPath ?? "/ws");
  const deviceName = String(overrides.deviceName ?? process.env.FF_DEVICE_NAME ?? fileCfg.deviceName ?? os.hostname());
  const rpcUrl = String(overrides.rpcUrl ?? process.env.FF_RPC_URL ?? fileCfg.rpcUrl ?? "http://127.0.0.1:39073/rpc");
  const fallbackRpcUrl = String(overrides.fallbackRpcUrl ?? process.env.FF_FALLBACK_RPC_URL ?? fileCfg.fallbackRpcUrl ?? "").trim();
  const stateDir = String(
    overrides.stateDir
    ?? process.env.FF_FLIGHT_STATE_DIR
    ?? fileCfg.stateDir
    ?? path.join(os.tmpdir(), "ff-bridge-cf-flight-state"),
  );
  const deviceToken = readSecret(overrides.deviceToken, process.env.FF_DEVICE_TOKEN, process.env.FF_DEVICE_TOKEN_FILE, fileCfg.deviceTokenFile);
  const rpcSecretFile = String(overrides.rpcSecretFile ?? process.env.FF_RPC_SECRET_FILE ?? fileCfg.rpcSecretFile ?? "").trim();
  const rpcSecretDirect = String(overrides.rpcSecret ?? process.env.FF_RPC_SECRET ?? "").trim();
  const heartbeatMs = Number(overrides.heartbeatMs ?? process.env.FF_HEARTBEAT_MS ?? fileCfg.heartbeatMs ?? 20000);
  const reconnect = overrides.reconnect !== false;

  if (!workerBaseUrl || workerBaseUrl.includes("<YOUR_")) {
    throw new Error("Missing valid workerBaseUrl (set FF_MCP_BASE or cf-agent-settings.json)");
  }
  if (!DEVICE_NAME_RE.test(deviceName)) {
    throw new Error(`Invalid deviceName "${deviceName}" (must match ${DEVICE_NAME_RE})`);
  }
  if (!deviceToken) {
    throw new Error("Missing deviceToken (set FF_DEVICE_TOKEN / FF_DEVICE_TOKEN_FILE or deviceTokenFile)");
  }
  if (!rpcSecretFile && !rpcSecretDirect) {
    throw new Error("Missing rpcSecretFile or FF_RPC_SECRET");
  }

  return {
    workerBaseUrl, wsPath, deviceName, rpcUrl, fallbackRpcUrl, stateDir,
    deviceToken, rpcSecretFile, rpcSecretDirect, heartbeatMs, reconnect,
  };
}

export function startBridgeAgent(overrides = {}) {
  const cfg = loadConfig(overrides);
  fs.mkdirSync(cfg.stateDir, { recursive: true });

  let secretPath = cfg.rpcSecretFile;
  let tempSecretCreated = false;
  if (!secretPath) {
    secretPath = path.join(cfg.stateDir, `.rpc-secret-${process.pid}.tmp`);
    fs.writeFileSync(secretPath, cfg.rpcSecretDirect, { encoding: "utf8", mode: 0o600 });
    tempSecretCreated = true;
  }

  let primaryRefusedUntil = 0;
  const selectBackend = async () => {
    if (cfg.fallbackRpcUrl && Date.now() < primaryRefusedUntil) {
      return cfg.fallbackRpcUrl;
    }
    return cfg.rpcUrl;
  };

  const callFlight = createFF3FlightCaller({
    selectBackend,
    secretPath,
    stateDir: cfg.stateDir,
    onBackendConnectRefused: (failedUrl) => {
      if (cfg.fallbackRpcUrl && failedUrl === cfg.rpcUrl) {
        primaryRefusedUntil = Date.now() + 5000;
      }
    },
    onBackendTransportError: () => {},
  });

  const wsUrl = cfg.workerBaseUrl.replace(/^https:/, "wss:").replace(/^http:/, "ws:") + cfg.wsPath;
  let reconnectDelayMs = 1000;
  let heartbeatTimer = null;
  let reconnectTimer = null;
  let currentWs = null;
  let stopped = false;

  const log = overrides.logger || ((...parts) => console.log(new Date().toISOString(), ...parts));

  function connect() {
    if (stopped) return;
    log("Connecting to", wsUrl, "as", cfg.deviceName);
    const ws = new WebSocket(wsUrl, {
      headers: {
        Authorization: `Bearer ${cfg.deviceToken}`,
        "X-Device-Name": cfg.deviceName,
      },
    });
    currentWs = ws;

    ws.on("open", () => {
      reconnectDelayMs = 1000;
      log("ONLINE", cfg.deviceName);
      ws.send(JSON.stringify({ type: "hello", host: cfg.deviceName, device: cfg.deviceName, version: "0.4.3" }));
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: "heartbeat", host: cfg.deviceName, device: cfg.deviceName, ts: Date.now() }));
        }
      }, cfg.heartbeatMs);
    });

    ws.on("message", async (raw) => {
      let msg;
      try { msg = JSON.parse(String(raw)); } catch { return; }
      const id = msg?.id;
      if (!id) return;
      try {
        if (msg.type === "ping") {
          ws.send(JSON.stringify({
            replyTo: id, ok: true, pong: true,
            host: cfg.deviceName, device: cfg.deviceName,
            message: msg.message ?? null, ts: Date.now(),
          }));
          return;
        }
        if (msg.type === "exec_test") {
          const res = runExecTest(msg.action);
          ws.send(JSON.stringify({ replyTo: id, host: cfg.deviceName, ...res }));
          return;
        }
        if (msg.type === "bridge_rpc" || msg.type === "bridge_call" || typeof msg.op === "string") {
          const result = await callFlight(msg.op, msg.args || {});
          ws.send(JSON.stringify({ replyTo: id, ok: true, bridge: "ff-win-v3", host: cfg.deviceName, result }));
          return;
        }
        ws.send(JSON.stringify({ replyTo: id, ok: false, error: "UNSUPPORTED_MESSAGE_TYPE" }));
      } catch (err) {
        ws.send(JSON.stringify({
          replyTo: id, ok: false,
          error: String(err?.message || err),
          outcome_unknown: Boolean(err?.outcome_unknown),
        }));
      }
    });

    ws.on("close", (code, reason) => {
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      heartbeatTimer = null;
      log(`DISCONNECTED code=${code} reason=${String(reason || "")}`);
      if (!stopped && cfg.reconnect) {
        reconnectTimer = setTimeout(connect, reconnectDelayMs);
        reconnectDelayMs = Math.min(30000, reconnectDelayMs * 2);
      }
    });

    ws.on("error", (err) => log("WS_ERROR", String(err?.message || err)));
  }

  connect();

  return {
    config: cfg,
    stop() {
      stopped = true;
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (currentWs) { try { currentWs.close(); } catch {} }
      if (tempSecretCreated) { try { fs.unlinkSync(secretPath); } catch {} }
    },
  };
}

const isMain = process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (isMain) {
  startBridgeAgent();
}
