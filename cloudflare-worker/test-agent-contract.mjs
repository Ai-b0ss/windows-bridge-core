import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import WebSocket, { WebSocketServer } from "ws";
import { startBridgeAgent } from "./agent/cf-bridge-agent.mjs";

const DEVICE_TOKEN = "test-device-token-0123456789abcdef";
const RPC_SECRET = "test-rpc-secret-fedcba9876543210";
const DEVICE_NAME = "TEST-HOST-01";

function startMockRpcServer() {
  let writeCount = 0;
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      if (req.headers["x-ff3-key"] !== RPC_SECRET) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error_code: "UNAUTHORIZED" }));
        return;
      }
      const payload = JSON.parse(body);
      const { op, args, request_id } = payload;

      if (op === "ping") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, request_id, device: DEVICE_NAME, op, result: { pong: true } }));
        return;
      }
      if (op === "capabilities") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, request_id, device: DEVICE_NAME, op, result: { ops: ["ping", "capabilities", "write_file"] } }));
        return;
      }
      if (op === "slow_op") {
        setTimeout(() => {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, request_id, device: DEVICE_NAME, op, result: { done: "SLOW_OK" } }));
        }, 1450);
        return;
      }
      if (op === "write_file" && args?.simulate_drop) {
        writeCount += 1;
        req.socket.destroy();
        return;
      }
      if (op === "request_status") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, request_id, result: { state: "unknown" } }));
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error_code: "UNKNOWN_OP" }));
    });
  });

  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        server,
        url: `http://127.0.0.1:${port}/rpc`,
        getWriteCount: () => writeCount,
      });
    });
  });
}

function startMockHubServer() {
  const httpServer = http.createServer((req, res) => {
    res.writeHead(404);
    res.end("Not found");
  });
  const wss = new WebSocketServer({ noServer: true });
  let activeSocket = null;
  const pending = new Map();
  let nextId = 1;

  httpServer.on("upgrade", (req, socket, head) => {
    if (req.url !== "/ws") {
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }
    if (req.headers.authorization !== `Bearer ${DEVICE_TOKEN}`) {
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      activeSocket = ws;
      ws.on("message", (raw) => {
        const msg = JSON.parse(String(raw));
        if (msg.replyTo && pending.has(msg.replyTo)) {
          const { resolve } = pending.get(msg.replyTo);
          pending.delete(msg.replyTo);
          resolve(msg);
        }
      });
    });
  });

  function send(type, payload = {}) {
    return new Promise((resolve, reject) => {
      if (!activeSocket || activeSocket.readyState !== WebSocket.OPEN) {
        reject(new Error("NO_ACTIVE_DEVICE"));
        return;
      }
      const id = `req-${nextId++}`;
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`TIMEOUT_${type}`));
      }, 6000);
      pending.set(id, {
        resolve: (val) => { clearTimeout(timer); resolve(val); },
      });
      activeSocket.send(JSON.stringify({ id, type, ...payload }));
    });
  }

  return new Promise((resolve) => {
    httpServer.listen(0, "127.0.0.1", () => {
      const { port } = httpServer.address();
      resolve({
        httpServer,
        wss,
        baseUrl: `http://127.0.0.1:${port}`,
        wsUrl: `ws://127.0.0.1:${port}/ws`,
        isOnline: () => Boolean(activeSocket && activeSocket.readyState === WebSocket.OPEN),
        send,
      });
    });
  });
}

test("WebSocket agent <-> DeviceHub <-> FlightController <-> loopback RPC contract", async () => {
  const rpc = await startMockRpcServer();
  const hub = await startMockHubServer();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "cf-agent-contract-"));
  const secretFile = path.join(tmpDir, "rpc.secret");
  fs.writeFileSync(secretFile, RPC_SECRET, "utf8");

  let agent = null;
  try {
    // 1. Invalid token must be rejected with 401
    await assert.rejects(
      () => new Promise((resolve, reject) => {
        const badWs = new WebSocket(hub.wsUrl, { headers: { Authorization: "Bearer wrong-token" } });
        badWs.on("open", () => { badWs.close(); resolve(); });
        badWs.on("unexpected-response", (_req, res) => reject(new Error(`HTTP_${res.statusCode}`)));
        badWs.on("error", reject);
      }),
      /HTTP_401/,
    );

    // 2. Start real agent against mock hub + mock loopback RPC
    agent = startBridgeAgent({
      skipFile: true,
      workerBaseUrl: hub.baseUrl,
      wsPath: "/ws",
      deviceName: DEVICE_NAME,
      rpcUrl: rpc.url,
      fallbackRpcUrl: "",
      stateDir: path.join(tmpDir, "flight-state"),
      deviceToken: DEVICE_TOKEN,
      rpcSecretFile: secretFile,
      heartbeatMs: 60000,
      reconnect: false,
      logger: () => {},
    });

    for (let i = 0; i < 40 && !hub.isOnline(); i++) {
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.equal(hub.isOnline(), true, "device should be online");

    // 3. DeviceHub.identify() ping contract
    const pingRes = await hub.send("ping", { message: "identify-device" });
    assert.equal(pingRes.ok, true);
    assert.equal(pingRes.host, DEVICE_NAME);
    assert.match(pingRes.host, /^[A-Za-z0-9_-]{1,100}$/);

    // 4. bridge_capabilities & bridge_call(op="ping") through FlightController
    const capRes = await hub.send("bridge_rpc", { op: "capabilities", args: {} });
    assert.equal(capRes.ok, true);
    assert.deepEqual(capRes.result.result.ops, ["ping", "capabilities", "write_file"]);

    const rpcPing = await hub.send("bridge_rpc", { op: "ping", args: {} });
    assert.equal(rpcPing.ok, true);
    assert.equal(rpcPing.result.result.pong, true);

    // 5. device_exec_test allowlist + rejection of disallowed action
    for (const action of ["hostname", "whoami", "node_version"]) {
      const ex = await hub.send("exec_test", { action });
      assert.equal(ex.ok, true, `exec_test ${action} should pass`);
      assert.ok(typeof ex.output === "string" && ex.output.length > 0);
    }
    const badEx = await hub.send("exec_test", { action: "rm_rf" });
    assert.equal(badEx.ok, false);
    assert.equal(badEx.error, "EXEC_TEST_ACTION_NOT_ALLOWED");

    // 6. Long-call soft handover ticket (min soft timeout is 1000ms) + __flight_poll completion
    const ticketRes = await hub.send("bridge_rpc", {
      op: "slow_op",
      args: { __soft_timeout_ms: 1000 },
    });
    assert.equal(ticketRes.ok, true);
    assert.equal(ticketRes.result.async_handover, true);
    const flightId = ticketRes.result.flight_id;
    assert.ok(flightId);

    const pollRes = await hub.send("bridge_rpc", {
      op: "__flight_poll",
      args: { flight_id: flightId, wait_ms: 3000 },
    });
    assert.equal(pollRes.ok, true);
    assert.equal(pollRes.result.status, "COMPLETED");
    assert.equal(pollRes.result.result.result.done, "SLOW_OK");

    // 7. Transport drop after dispatch: mutation must NOT be automatically replayed
    const dropRes = await hub.send("bridge_rpc", {
      op: "write_file",
      args: { path: "dummy.txt", simulate_drop: true, __dedupe_key: "mut-drop-test-1" },
    });
    assert.equal(dropRes.ok, false);
    assert.equal(rpc.getWriteCount(), 1, "mutation after ambiguous drop must execute at most once");
  } finally {
    if (agent) agent.stop();
    hub.wss.close();
    hub.httpServer.close();
    rpc.server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
