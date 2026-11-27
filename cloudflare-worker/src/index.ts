import { DurableObject } from "cloudflare:workers";
import OAuthProvider, { type OAuthHelpers } from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp/server";
import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

const ORIGIN = "https://<YOUR_WORKER_NAME>.<YOUR_SUBDOMAIN>.workers.dev";
const RESOURCE = ORIGIN + "/mcp";
const HOME_DEVICE = "<YOUR_WINDOWS_HOSTNAME>";

type Env = {
  DEVICE_HUB: DurableObjectNamespace<DeviceHub>;
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
  DEVICE_TOKEN: string;
  MCP_TOKEN: string;
};

type Pending = {
  connectionKey: string;
  resolve: (value: unknown) => void;
  reject: (reason?: unknown) => void;
  started: number;
};

function bearer(request: Request) {
  const value = request.headers.get("authorization") ?? "";
  return value.startsWith("Bearer ") ? value.slice(7) : "";
}

async function sha256(value: string) {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64urlEncode(value: string) {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

function b64urlDecode(value: string) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/")
    + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

async function hmacSign(secret: string, value: string) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}
function cookie(request: Request, name: string) {
  const all = request.headers.get("cookie") ?? "";
  for (const part of all.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return "";
}

function esc(value: unknown) {
  return String(value ?? "")
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;").replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function isOwner(request: Request, env: Env) {
  const expected = await sha256(env.MCP_TOKEN);
  return cookie(request, "__Host-FF_OWNER") === expected;
}

// Mobile owner verification with short-lived HMAC codes instead of the permanent MCP secret.
async function mobilePairCode(secret: string, bucket: number) {
  return (await hmacSign(secret, "ff-phone-pair-v1:" + bucket)).slice(0, 24).toUpperCase();
}

async function checkMobilePairCode(code: string, env: Env) {
  const normalized = code.replace(/[\s-]/g, "").toUpperCase();
  if (!/^[0-9A-F]{24}$/.test(normalized)) return null;
  const bucket = Math.floor(Date.now() / 300000);
  for (const candidate of [bucket, bucket - 1]) {
    if (normalized === await mobilePairCode(env.MCP_TOKEN, candidate)) return normalized;
  }
  return null;
}

function mobilePairPage(url: URL, error = "") {
  const back = esc(url.pathname + url.search);
  const html = [
    '<!doctype html><html lang="ru"><meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<title>Windows Bridge — подключение с телефона</title>',
    '<style>body{font:16px system-ui;max-width:480px;margin:10vh auto;padding:0 24px;color:#181818}input{width:100%;box-sizing:border-box;padding:13px;font:20px monospace;letter-spacing:1px;margin:12px 0}button{padding:12px 18px;font:16px system-ui}p{line-height:1.5}.err{color:#a00}</style>',
    '<h2>Windows Bridge — вход с телефона</h2>',
    '<p>Введите одноразовый код подключения из вашего чата ChatGPT. Постоянный секрет MCP сюда вводить не нужно.</p>',
    error ? '<p class="err">' + esc(error) + '</p>' : '',
    '<form method="POST" action="/phone-pair">',
    '<input type="hidden" name="return_to" value="' + back + '">',
    '<label for="code">Одноразовый код</label>',
    '<input id="code" type="text" name="code" minlength="24" maxlength="35" autocomplete="off" spellcheck="false" autocapitalize="characters" required>',
    '<button type="submit">Подтвердить и продолжить</button>',
    '</form><p><small>Код действует ограниченное время и может быть использован только один раз.</small></p>'
  ].join("");
  return new Response(html, {
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
      "cache-control": "no-store",
      "referrer-policy": "no-referrer",
    },
  });
}

export class DeviceHub extends DurableObject<Env> {
  private pending = new Map<string, Pending>();
  private identifying = new Map<string, Promise<string | null>>();
  private retired = new Set<string>();

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("WebSocket required", { status: 426 });
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server);
    server.serializeAttachment({ connectedAt: Date.now(), connectionId: crypto.randomUUID() });
    return new Response(null, { status: 101, webSocket: client });
  }

  private socketMeta(socket: WebSocket) {
    return socket.deserializeAttachment() as
      | { connectedAt?: number; connectionId?: string; device?: string;
          lastSeen?: number; retiredAt?: number; retiredReason?: string } | undefined;
  }

  private connectionKey(socket: WebSocket) {
    const meta = this.socketMeta(socket);
    return meta?.connectionId ?? `legacy:${meta?.connectedAt ?? 0}`;
  }

  private usable(socket: WebSocket) {
    return socket.readyState === WebSocket.OPEN && !this.socketMeta(socket)?.retiredAt &&
      !this.retired.has(this.connectionKey(socket));
  }

  private sockets() {
    return this.ctx.getWebSockets().filter((socket) => this.usable(socket));
  }

  private rejectForSocket(socket: WebSocket, reason: string) {
    const connectionKey = this.connectionKey(socket);
    for (const [id, item] of this.pending) {
      if (item.connectionKey !== connectionKey) continue;
      this.pending.delete(id);
      item.reject(new Error(reason));
    }
  }

  private retire(socket: WebSocket, reason: string, code = 1001) {
    const key = this.connectionKey(socket);
    this.retired.add(key);
    try { socket.serializeAttachment({ ...this.socketMeta(socket), retiredAt: Date.now(), retiredReason: reason }); }
    catch { /* A fully closed socket may no longer accept attachments. */ }
    this.rejectForSocket(socket, reason);
    try { if (socket.readyState !== WebSocket.CLOSED) socket.close(code, reason.slice(0, 100)); }
    catch { /* Routing already excludes this socket, even if close fails. */ }
    console.log(JSON.stringify({ event: "device_socket_retired", connection: key, reason }));
  }

  // Host identity and liveness are different: cached identity never proves online status.
  private async identify(socket: WebSocket, fresh = false): Promise<string | null> {
    if (!this.usable(socket)) return null;
    const meta = this.socketMeta(socket);
    if (!fresh && meta?.device && meta.lastSeen && Date.now() - meta.lastSeen < 2000) return meta.device;
    const key = this.connectionKey(socket);
    const underway = this.identifying.get(key);
    if (underway) return underway;
    const task = (async () => {
      try {
        const response: any = await this.sendTo(socket, "ping", { message: "identify-device" }, 3000);
        if (!response?.ok || typeof response.host !== "string" ||
            !/^[A-Za-z0-9_-]{1,100}$/.test(response.host) ||
            (meta?.device && meta.device.toLowerCase() !== response.host.toLowerCase())) {
          throw new Error("DEVICE_IDENTITY_INVALID");
        }
        if (!this.usable(socket)) return null;
        socket.serializeAttachment({ ...this.socketMeta(socket), device: response.host, lastSeen: Date.now() });
        return response.host as string;
      } catch {
        this.retire(socket, "DEVICE_HEALTH_CHECK_FAILED");
        return null;
      }
    })();
    this.identifying.set(key, task);
    try { return await task; }
    finally { this.identifying.delete(key); }
  }

  private pruneDuplicates() {
    const latest = new Map<string, WebSocket>();
    for (const socket of this.sockets().sort((a,b) =>
      (this.socketMeta(b)?.connectedAt ?? 0) - (this.socketMeta(a)?.connectedAt ?? 0))) {
      const device = this.socketMeta(socket)?.device?.toLowerCase();
      if (!device) continue;
      if (!latest.has(device)) { latest.set(device, socket); continue; }
      // An older connection may still be returning a real command. Let it drain.
      const key = this.connectionKey(socket);
      if ([...this.pending.values()].some((item) => item.connectionKey === key)) continue;
      this.retire(socket, "DEVICE_CONNECTION_SUPERSEDED");
    }
  }

  private async selectSocket(device: string): Promise<WebSocket> {
    const candidates = this.sockets().filter((socket) => {
      const known = this.socketMeta(socket)?.device;
      return !known || known.toLowerCase() === device.toLowerCase();
    });
    await Promise.all(candidates.map((socket) => this.identify(socket)));
    this.pruneDuplicates();
    const matches = this.sockets().filter((socket) =>
      this.socketMeta(socket)?.device?.toLowerCase() === device.toLowerCase());
    if (!matches.length) throw new Error("DEVICE_NOT_CONNECTED: " + device);
    return matches.sort((a,b) =>
      (this.socketMeta(b)?.connectedAt ?? 0) - (this.socketMeta(a)?.connectedAt ?? 0))[0];
  }

  async getStatus() {
    await Promise.all(this.sockets().map((socket) => this.identify(socket, true)));
    this.pruneDuplicates();
    const devices = this.sockets().filter((socket) => this.socketMeta(socket)?.device).map((socket) => ({
      device: this.socketMeta(socket)!.device!, connectedAt: this.socketMeta(socket)?.connectedAt ?? null,
      lastSeen: this.socketMeta(socket)?.lastSeen ?? null,
    }));
    const home = devices.filter((item) => item.device.toLowerCase() === HOME_DEVICE.toLowerCase())
      .sort((a,b) => (b.connectedAt ?? 0) - (a.connectedAt ?? 0))[0];
    return { online: Boolean(home), connections: devices.length, connectedAt: home?.connectedAt ?? null,
      defaultDevice: HOME_DEVICE, devices, transportVersion: "0.4.1" };
  }

  private async sendTo(socket: WebSocket, type: string, payload: Record<string,unknown>, timeoutMs = 20000) {
    if (!this.usable(socket)) throw new Error("DEVICE_DISCONNECTED");
    const id = crypto.randomUUID();
    const started = Date.now();
    return await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        // A timeout after dispatch must never cause a mutation to be replayed.
        reject(new Error(type === "bridge_rpc" ? "DEVICE_REQUEST_OUTCOME_UNKNOWN: DEVICE_TIMEOUT" : "DEVICE_TIMEOUT"));
        this.retire(socket, "DEVICE_RESPONSE_TIMEOUT");
      }, timeoutMs);
      this.pending.set(id, {
        connectionKey: this.connectionKey(socket), started,
        resolve: (value) => { clearTimeout(timer); resolve(value); },
        reject: (error) => {
          clearTimeout(timer);
          reject(type === "bridge_rpc" ? new Error("DEVICE_REQUEST_OUTCOME_UNKNOWN: " + String(error)) : error);
        },
      });
      try { socket.send(JSON.stringify({ id, type, ...payload })); }
      catch (error) {
        clearTimeout(timer); this.pending.delete(id);
        reject(type === "bridge_rpc" ? new Error("DEVICE_REQUEST_OUTCOME_UNKNOWN: " + String(error)) : error);
        this.retire(socket, "DEVICE_SEND_FAILED");
      }
    });
  }

  private async send(type: string, payload: Record<string,unknown>, device = HOME_DEVICE) {
    return this.sendTo(await this.selectSocket(device), type, payload);
  }
  pingDevice(message: string, device = HOME_DEVICE) { return this.send("ping", { message }, device); }
  execTest(action: string, device = HOME_DEVICE) { return this.send("exec_test", { action }, device); }

  bridgeRpc(op: string, args: Record<string,unknown>, device = HOME_DEVICE) {
    const selector = args.__target_device;
    if (selector !== undefined && (typeof selector !== "string" || !/^[A-Za-z0-9_-]{1,100}$/.test(selector))) {
      throw new Error("INVALID_TARGET_DEVICE");
    }
    if (selector && device !== HOME_DEVICE && selector !== device) throw new Error("CONFLICTING_TARGET_DEVICE");
    const { __target_device, ...safeArgs } = args;
    return this.send("bridge_rpc", { op, args: safeArgs }, typeof selector === "string" ? selector : device);
  }
  async putAuthState(state: string, value: string) {
    await this.ctx.storage.put("oauth:" + state, value, { expirationTtl: 3600 });
  }
  async takeAuthState(state: string) {
    const key = "oauth:" + state;
    const value = await this.ctx.storage.get<string>(key);
    if (value !== undefined) await this.ctx.storage.delete(key);
    return value ?? null;
  }
  webSocketMessage(socket: WebSocket, message: string | ArrayBuffer) {
    const text = typeof message === "string" ? message : new TextDecoder().decode(message);
    let data: any;
    try { data = JSON.parse(text); } catch { return; }
    if (!data || typeof data !== "object") return;
    const item = this.pending.get(data.replyTo);
    if (!item || item.connectionKey !== this.connectionKey(socket)) return;
    this.pending.delete(data.replyTo);
    try { socket.serializeAttachment({ ...this.socketMeta(socket), lastSeen: Date.now() }); } catch {}
    item.resolve({ ...data, roundTripMs: Date.now() - item.started });
  }
  webSocketClose(socket: WebSocket, code: number, reason: string, wasClean: boolean) {
    console.log(JSON.stringify({ event: "device_socket_close", code, reason, wasClean, connection: this.connectionKey(socket) }));
    this.retire(socket, "DEVICE_DISCONNECTED", 1000);
  }
  webSocketError(socket: WebSocket) { this.retire(socket, "DEVICE_SOCKET_ERROR", 1011); }
}

function hub(env: Env) {
  return env.DEVICE_HUB.getByName("igor-win");
}

function resultOrError(run: () => Promise<unknown>) {
  return run()
    .then((result) => ({
      content: [{ type: "text" as const, text: JSON.stringify(result) }],
    }))
    .catch((error) => ({
      isError: true,
      content: [{
        type: "text" as const,
        text: error instanceof Error ? error.message : String(error),
      }],
    }));
}

function makeMcp(env: Env) {
  const server = new McpServer({ name: "Windows-Bridge", version: "0.4.3" });
  server.registerTool(
    "device_status",
    {
      description: "Return FF Windows agent connection status.",
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async () => {
      const status = await hub(env).getStatus();
      return { content: [{ type: "text", text: JSON.stringify(status) }] };
    },
  );

  server.registerTool(
    "device_ping",
    {
      description: "Round-trip ping through Cloudflare to the Windows agent.",
      inputSchema: { message: z.string().optional(), target_device: z.string().optional() },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ message, target_device }) =>
      resultOrError(() => hub(env).pingDevice(message ?? "ping", target_device)),
  );

  server.registerTool(
    "device_exec_test",
    {
      description: "Run one safe diagnostic command on the Windows agent.",
      inputSchema: {
        action: z.enum(["hostname", "whoami", "node_version"]),
        target_device: z.string().optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ action, target_device }) => resultOrError(() => hub(env).execTest(action, target_device)),
  );

  server.registerTool(
    "bridge_capabilities",
    {
      description: "Return the live capabilities and operations exposed by the existing FF Windows Bridge v3 runtime.",
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async () => resultOrError(() => hub(env).bridgeRpc("capabilities", {})),
  );

  server.registerTool(
    "bridge_call",
    {
      description: "Execute a selected FF Windows Bridge v3 operation on the specified computer. op is the exact operation name; args contains its operation-specific parameters. Defaults to <YOUR_WINDOWS_HOSTNAME>; target_device specifies another device explicitly. Existing operation checks remain in effect.",
      inputSchema: {
        op: z.string().min(1),
        args: z.record(z.string(), z.unknown()).optional(),
        target_device: z.string().optional(),
      },
      annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
    },
    async ({ op, args, target_device }) => resultOrError(() => hub(env).bridgeRpc(op, args ?? {}, target_device)),
  );

  return server;
}

const mcpApiHandler = {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    return createMcpHandler(() => makeMcp(env))(request, env, ctx);
  },
};
const defaultHandler = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/device/igor-win") {
      if (bearer(request) !== env.DEVICE_TOKEN) {
        return new Response("Unauthorized", { status: 401 });
      }
      return hub(env).fetch(request);
    }

    if (url.pathname === "/bootstrap" && request.method === "POST") {
      const form = await request.formData();
      if (String(form.get("token") ?? "") !== env.MCP_TOKEN) {
        return new Response("Unauthorized", { status: 401 });
      }
      const owner = await sha256(env.MCP_TOKEN);
      return new Response("FF owner browser authorized. You can close this tab.", {
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "set-cookie":
            "__Host-FF_OWNER=" + owner +
            "; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=7776000",
        },
      });
    }

    if (url.pathname === "/phone-pair" && request.method === "POST") {
      const form = await request.formData();
      const rawReturnTo = String(form.get("return_to") ?? "");
      let target: URL;
      try { target = new URL(rawReturnTo, ORIGIN); }
      catch { return new Response("Invalid authorization context", { status: 400 }); }
      if (target.origin !== ORIGIN || target.pathname !== "/authorize" ||
          target.searchParams.get("client_id") !== "https://claude.ai/oauth/mcp-oauth-client-metadata") {
        return new Response("Unsupported authorization context", { status: 400 });
      }
      const code = await checkMobilePairCode(String(form.get("code") ?? ""), env);
      if (!code) return mobilePairPage(target, "Код недействителен или истёк. Получите новый код.");
      const consumedKey = "claude-mobile-phone-pair-v1:" + code;
      if (await env.OAUTH_KV.get(consumedKey)) {
        return mobilePairPage(target, "Этот код уже использован. Получите новый код.");
      }
      await env.OAUTH_KV.put(consumedKey, "used", { expirationTtl: 1800 });
      const owner = await sha256(env.MCP_TOKEN);
      return new Response(null, {
        status: 303,
        headers: {
          location: target.pathname + target.search,
          "set-cookie": "__Host-FF_OWNER=" + owner +
            "; HttpOnly; Secure; Path=/; SameSite=Lax; Max-Age=604800",
          "cache-control": "no-store",
          "referrer-policy": "no-referrer",
        },
      });
    }

    if (url.pathname === "/authorize" && request.method === "GET") {
      if (!(await isOwner(request, env))) {
        return mobilePairPage(url);
      }
      const info = await env.OAUTH_PROVIDER.parseAuthRequest(request);
      const payload = b64urlEncode(JSON.stringify({
        info,
        exp: Date.now() + 10 * 60 * 1000,
      }));
      const sig = await hmacSign(env.MCP_TOKEN, payload);
      const scopes = Array.isArray(info.scope) ? info.scope.join(" ") : info.scope;
      const html = `<!doctype html><meta charset="utf-8">
<title>Windows-Bridge authorization</title>
<style>
body{font:16px system-ui;max-width:620px;margin:60px auto;padding:0 20px}
button{padding:10px 18px;font-size:16px}
code{word-break:break-all}
</style>
<h2>Windows-Bridge</h2>
<p>ChatGPT requests access to your Windows bridge.</p>
<p><b>Client:</b> <code>${esc(info.clientId)}</code></p>
<p><b>Scopes:</b> <code>${esc(scopes || "ff:control")}</code></p>
<p><a href="/approve?payload=${encodeURIComponent(payload)}&sig=${encodeURIComponent(sig)}">Allow</a></p>`;
      return new Response(html, {
        headers: {
          "content-type": "text/html; charset=utf-8",
          "content-security-policy":
            "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
          "cache-control": "no-store",
        },
      });
    }

    if (url.pathname === "/approve" && request.method === "GET") {
      if (!(await isOwner(request, env))) {
        return new Response("Unauthorized", { status: 403 });
      }
      const payload = url.searchParams.get("payload") ?? "";
      const sig = url.searchParams.get("sig") ?? "";
      if (!payload || !sig) {
        return new Response("Invalid authorization request", { status: 400 });
      }
      const expected = await hmacSign(env.MCP_TOKEN, payload);
      if (sig !== expected) {
        return new Response("Invalid authorization signature", { status: 400 });
      }
      let decoded: { info: any; exp: number };
      try {
        decoded = JSON.parse(b64urlDecode(payload));
      } catch {
        return new Response("Invalid authorization payload", { status: 400 });
      }
      if (!decoded.exp || Date.now() > decoded.exp) {
        return new Response("Authorization request expired", { status: 400 });
      }
      const info = decoded.info;
      const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
        request: info,
        userId: "owner",
        metadata: { label: "Windows-Bridge owner" },
        scope: info.scope,
        props: { userId: "owner" },
      });
      return Response.redirect(redirectTo, 302);
    }

    if (url.pathname === "/") {
      return new Response("Windows-Bridge OAuth MCP is running.");
    }

    return new Response("Not found", { status: 404 });
  },
};

export default new OAuthProvider<Env>({
  apiRoute: "/mcp",
  apiHandler: mcpApiHandler,
  defaultHandler,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  scopesSupported: ["ff:control", "offline_access"],
  resourceMetadata: {
    resource: RESOURCE,
    authorization_servers: [ORIGIN],
  },
  requiredScopes: ["ff:control"],
  clientIdMetadataDocumentEnabled: true,
});

