"""Real Windows Chrome/Win32 via scoped CLI, raw HTTP and the MCP Python SDK."""
from __future__ import annotations

import asyncio
import base64
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "tools" / "agent_entry.py"
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
from ff_hub import HubClient, ensure_running
from ff_hub_permissions import Policy
from ff_win_process_identity import process_identity_matches


def command(*args):
    done = subprocess.run([sys.executable, str(CLI), *map(str, args)], check=True, capture_output=True, timeout=70)
    return json.loads(done.stdout)["result"]


def check(condition, code):
    if not condition:
        raise RuntimeError(code)


@contextmanager
def fixture():
    hits = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            hits.append(self.path)
            body = b"<!doctype html><title>FF Entry Fixture</title><p>scoped-browser-fixture</p>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}/entry", hits
        finally:
            server.shutdown()
            thread.join()


def http(port, credential, op, args=None, *, session=None, key=None, origin=None):
    request = {"op": op, "args": args or {}}
    if session:
        request["session_id"] = session
    if key:
        request["request_key"] = key
    headers = {"Content-Type": "application/json"}
    if credential is not None:
        headers["Authorization"] = "Bearer " + credential.read_text(encoding="ascii").strip()
    if origin:
        headers["Origin"] = origin
    prepared = urllib.request.Request(f"http://127.0.0.1:{port}/agent/v1", method="POST",
                                      headers=headers, data=json.dumps(request).encode())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        reply = opener.open(prepared, timeout=70)
    except urllib.error.HTTPError as exc:
        reply = exc
    with reply:
        return json.load(reply)


async def mcp_chrome(port, credential, url):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(command=sys.executable, args=[str(CLI), "mcp", "--port", str(port),
                                                                 "--credential-file", str(credential)])
    async with stdio_client(params) as (Reader, Writer), ClientSession(Reader, Writer) as client:
        await client.initialize()
        check("ff_agent_call" in {tool.name for tool in (await client.list_tools()).tools}, "MCP_DISCOVERY")

        async def call(op, args=None, *, session=None, key=None):
            request = {"op": op, "args": args or {}}
            if session:
                request["session_id"] = session
            if key:
                request["request_key"] = key
            result = await client.call_tool("ff_agent_call", request)
            reply = json.loads(result.content[0].text)
            check(reply["ok"], reply.get("error_code", "MCP_CALL"))
            return reply["result"]

        capabilities = await call("capabilities")
        check(capabilities["schema"] == "ff-agent-entry-v1", "MCP_CAPABILITIES")
        session = (await call("session_open"))["session_id"]
        check((await call("session_open"))["session_id"] == session, "MCP_STABLE_SESSION")
        browser = await call("private_browser", {"command": "open"}, session=session, key="mcp-browser-open")
        check(not {"browser_ws_endpoint", "browser_ws_path", "cdp_endpoint", "cdp_port"}.intersection(browser),
              "MCP_RAW_BROWSER_ENDPOINT")
        browser_id = browser["browser_id"]
        process = browser["pid"], browser["create_time"]
        tabs = await call("private_browser", {"command": "tabs", "browser_id": browser_id}, session=session)
        tab_id = tabs["tabs"][0]["tab_id"]
        nav = {"command": "navigate", "browser_id": browser_id, "tab_id": tab_id, "url": url}
        await call("private_browser", nav, session=session, key="mcp-browser-navigate")
        replay = await call("private_browser", nav, session=session, key="mcp-browser-navigate")
        check(replay["deduplicated"], "MCP_DURABLE_DEDUP")
        for _ in range(40):
            page = await call("private_browser", {**nav, "command": "read"}, session=session)
            if "scoped-browser-fixture" in page["text"]:
                break
            await asyncio.sleep(.1)
        else:
            raise RuntimeError("MCP_CHROME_READBACK")
        cancelled = await call("task_cancel", session=session, key="mcp-browser-cancel")
        check(cancelled["cleanup_verified"] and not process_identity_matches(*process), "MCP_CHROME_CLEANUP")


def run(root):
    state = root / "hub"
    state.mkdir()
    (state / "config.json").write_text('{"port":0}', encoding="utf-8")
    os.environ["FF_BRIDGE_ROOT"] = str(root / "runtime")
    endpoint = ensure_running(state)
    admin = HubClient(state)
    port = endpoint["port"]
    creds = {}
    try:
        for client, scopes in (("http", ["--scope", "private_app", "--app", "charmap", "--scope", "artifacts"]),
                               ("mcp", ["--scope", "private_browser"]),
                               ("cli", ["--scope", "locks"])):
            path = root / f"{client}.credential"
            command("issue", "--state-dir", state, "--credential-file", path, "--client", client,
                    "--agent", f"fixture-{client}", "--task", "isolated-smoke", "--ttl", 600, *scopes)
            creds[client] = path
        policy = Policy(state / "policy.json")
        policy.add_grant(["app_launch"], apps=["charmap.exe"], agents=["fixture-http"], ttl_seconds=600)
        policy.add_grant(["app_launch"], apps=["chrome.exe"], agents=["fixture-mcp"], ttl_seconds=600)
        check(http(port, None, "capabilities")["error_code"] == "ENTRY_UNAUTHORIZED", "HTTP_NO_AUTH")
        check(http(port, creds["http"], "capabilities", origin="https://unrelated.invalid")["error_code"]
              == "ENTRY_ORIGIN_DENIED", "HTTP_ORIGIN")

        session = http(port, creds["http"], "session_open")["result"]["session_id"]
        check(http(port, creds["cli"], "session_status", session=session)["error_code"] == "SESSION_INVALID",
              "HTTP_CROSS_CLIENT")
        opened = http(port, creds["http"], "app_open", {"app": "charmap"}, session=session, key="http-app-open")
        check(opened["ok"], opened.get("error_code", "HTTP_APP_OPEN"))
        app = opened["result"]
        observed = http(port, creds["http"], "app_observe", {"app_id": app["app_id"]}, session=session)
        check(observed["ok"] and observed["result"].get("entities"), "HTTP_WIN32_OBSERVE")
        content = b"scoped artifact\r\n"
        art = {"name": "result.txt", "command": "put", "content_base64": base64.b64encode(content).decode("ascii")}
        check(http(port, creds["http"], "task_file", art, session=session, key="http-artifact-put")["ok"],
              "HTTP_ARTIFACT_PUT")
        readback = http(port, creds["http"], "task_file", {"name": art["name"], "command": "read"}, session=session)
        check(readback["result"]["sha256"] == hashlib.sha256(content).hexdigest(), "HTTP_ARTIFACT_READBACK")

        cli = ("call", "--port", port, "--credential-file", creds["cli"])
        cli_session = command(*cli, "--op", "session_open")["session_id"]
        lock = root / "lock.json"
        lock.write_text(json.dumps({"kind": "custom", "key": "client-smoke"}), encoding="utf-8")
        command(*cli, "--session-id", cli_session, "--op", "resource_claim", "--key", "cli-lock-001",
                "--args-file", lock)
        with fixture() as (url, hits):
            asyncio.run(mcp_chrome(port, creds["mcp"], url))
            check(hits.count("/entry") == 1, "CHROME_NAVIGATION_EFFECT_ONCE")
        check(http(port, creds["http"], "session_status", session=session)["ok"], "HTTP_TASK_SURVIVES_MCP_CANCEL")
        command(*cli, "--session-id", cli_session, "--op", "task_cancel", "--key", "cli-cancel-001")
        cleanup = http(port, creds["http"], "task_cancel", session=session, key="http-window-cancel")
        check(cleanup["ok"] and cleanup["result"]["cleanup_verified"], "HTTP_CLEANUP")
        check(cleanup["result"]["task_files_removed"] == 1, "HTTP_ARTIFACT_CLEANUP")
        check(not process_identity_matches(app["pid"], app["create_time"]), "HTTP_OWNED_APP_STILL_RUNNING")
        status = admin.call("hub_status")
        check(not status["sessions"] and not status["private_desktops"], "HUB_NOT_IDLE")
    finally:
        # Best-effort cleanup only for the fixture credentials and Hub we created.
        for cred in creds.values():
            boot = http(port, cred, "session_open")
            if boot["ok"] and boot["result"]["state"] == "active":
                http(port, cred, "task_cancel", session=boot["result"]["session_id"], key="final-cleanup")
        admin.call("hub_shutdown_idle")
        for _ in range(90):
            if not process_identity_matches(endpoint["pid"], endpoint["create_time"]):
                break
            time.sleep(.1)
        else:
            raise RuntimeError("HUB_FIXTURE_STILL_RUNNING")


if __name__ == "__main__":
    with TemporaryDirectory(prefix="ff-entry-") as temporary:
        run(Path(temporary))
    print(json.dumps({"ok": True, "checks": ["raw_http", "cli", "mcp_sdk", "win32_uia", "chrome",
                                            "three_scoped_tasks", "effect_once", "task_files", "owned_cleanup"]}))
