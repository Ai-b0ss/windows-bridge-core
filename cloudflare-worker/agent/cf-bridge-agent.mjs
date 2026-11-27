/**
 * Reproducible WebSocket client connecting a local Windows Bridge v3 RPC server
 * to the Cloudflare Worker DeviceHub (`/ws`).
 *
 * Uses FlightController (`../../tools/cf-flight-controller/flight-controller.mjs`)
 * so long operations hand over cleanly without automatic mutation replay.
 */
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import WebSocket from "ws";
import { createFF3FlightCaller } from "../../tools/cf-flight-controller/flight-controller.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadConfig() {
  const cfgIdx = process.argv.indexOf("--config");
  const cfgPath = cfgIdx >= 0 && process.argv[cfgIdx + 1]
    ? path.resolve(process.argv[cfgIdx + 1])
    : path.join(__dirname, "cf-agent-settings.json");

  let fileCfg = {};
  if (fs.existsSync(cfgPath)) {
    fileCfg = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  }

  const readSecret = (envVal, envFile, cfgFile) => {
    if (envVal && envVal.trim()) return envVal.trim();
    const p = envFile || cfgFile;
    if (p && fs.existsSync(p)) return fs.readFileSync(p, "utf8").trim();
    return "";
  };

  const workerBaseUrl = (process.env.FF_MCP_BASE || fileCfg.workerBaseUrl || "").replace(/\/+$/, "");
  const wsPath = process.env.FF_WS_PATH || fileCfg.wsPath || "/ws";
  const deviceName = process.env.FF_DEVICE_NAME || fileCfg.deviceName || os.hostname();
  const rpcUrl = process.env.FF_RPC_URL || fileCfg.rpcUrl || "http://127.0.0.1:39073/rpc";
  const fallbackRpcUrl = process.env.FF_FALLBACK_RPC_URL || fileCfg.fallbackRpcUrl || "";
  const deviceToken = readSecret(process.env.FF_DEVICE_TOKEN, process.env.FF_DEVICE_TOKEN_FILE, fileCfg.deviceTokenFile);
  const rpcSecret = readSecret(process.env.FF_RPC_SECRET, process.env.FF_RPC_SECRET_FILE, fileCfg.rpcSecretFile);
  const heartbeatMs = Number(process.env.FF_HEARTBEAT_MS || fileCfg.heartbeatMs || 20000);

  if (!workerBaseUrl || workerBaseUrl.includes("<YOUR_")) {
    throw new Error("Missing valid workerBaseUrl (set FF_MCP_BASE or cf-agent-settings.json)");
  }
  if (!deviceToken) {
    throw new Error("Missing deviceToken (set FF_DEVICE_TOKEN / FF_DEVICE_TOKEN_FILE or deviceTokenFile)");
  }
  if (!rpcSecret) {
    throw new Error("Missing rpcSecret (set FF_RPC_SECRET / FF_RPC_SECRET_FILE or rpcSecretFile)");
  }

  return { workerBaseUrl, wsPath, deviceName, rpcUrl, fallbackRpcUrl, deviceToken, rpcSecret, heartbeatMs };
}

const cfg = loadConfig();
const wsUrl = cfg.workerBaseUrl.replace(/^https:/, "wss:").replace(/^http:/, "ws:") + cfg.wsPath;

async function callLocalRpc(op, args, timeoutMs = 15000) {
  const urls = [cfg.rpcUrl, cfg.fallbackRpcUrl].filter(Boolean);
  let lastErr = null;
  for (const url of urls) {
    try {
      const resp = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", "X-FF3-Key": cfg.rpcSecret },
        body: JSON.stringify({ op, args: args || {}, request_id: crypto.randomUUID() }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      return await resp.json();
    } catch (err) {
      lastErr = err;
      if (err?.cause?.code !== "ECONNREFUSED") break;
    }
  }
  throw lastErr || new Error("LOCAL_RPC_UNAVAILABLE");
}

const callFlight = createFF3FlightCaller({
  callRaw: async ({ op, args, timeoutMs }) => callLocalRpc(op, args, timeoutMs),
});

let reconnectDelayMs = 1000;
let heartbeatTimer = null;

function log(...parts) {
  console.log(new Date().toISOString(), ...parts);
}

function connect() {
  log("Connecting to", wsUrl, "as", cfg.deviceName);
  const ws = new WebSocket(wsUrl, {
    headers: {
      Authorization: `Bearer ${cfg.deviceToken}`,
      "X-Device-Name": cfg.deviceName,
    },
  });

  ws.on("open", () => {
    reconnectDelayMs = 1000;
    log("ONLINE", cfg.deviceName);
    ws.send(JSON.stringify({ type: "hello", device: cfg.deviceName, version: "0.4.3" }));
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    heartbeatTimer = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "heartbeat", device: cfg.deviceName, ts: Date.now() }));
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
        ws.send(JSON.stringify({ replyTo: id, ok: true, pong: true, device: cfg.deviceName, ts: Date.now() }));
        return;
      }
      if (msg.type === "bridge_call" || msg.op) {
        const result = await callFlight(msg.op, msg.args || {});
        ws.send(JSON.stringify({ replyTo: id, ok: true, bridge: "ff-win-v3", result }));
        return;
      }
      ws.send(JSON.stringify({ replyTo: id, ok: false, error: "UNSUPPORTED_MESSAGE_TYPE" }));
    } catch (err) {
      ws.send(JSON.stringify({ replyTo: id, ok: false, error: String(err?.message || err) }));
    }
  });

  ws.on("close", (code, reason) => {
    if (heartbeatTimer) clearInterval(heartbeatTimer);
    log(`DISCONNECTED code=${code} reason=${String(reason || "")}; reconnecting in ${reconnectDelayMs}ms`);
    setTimeout(connect, reconnectDelayMs);
    reconnectDelayMs = Math.min(30000, reconnectDelayMs * 2);
  });

  ws.on("error", (err) => log("WS_ERROR", String(err?.message || err)));
}

connect();
