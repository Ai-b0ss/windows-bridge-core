"""Owner enrollment, scoped HTTP example client and MCP stdio adapter."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"))
from ff_agent_entry import ENTRY_PATH, SAFE_APPS, SCOPES, EntryAuthority, TOKEN
from ff_hub_store import HubError

MCP_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
LIMIT = 2 * 1024 * 1024
TOOL = {
    "name": "ff_agent_call",
    "description": ("Call the task-scoped FF Agent Hub. Discover with capabilities, then session_open. "
                    "Pass a stable request_key for each mutation. Reconcile a lost reply with request_status."),
    "inputSchema": {
        "type": "object", "required": ["op"], "additionalProperties": False,
        "properties": {"op": {"type": "string"}, "args": {"type": "object"},
                       "session_id": {"type": "string"}, "request_key": {"type": "string"}},
    },
}


class AgentClient:
    def __init__(self, credential_file: Path, *, port: int | None = None, endpoint_file: Path | None = None):
        self.credential_file = credential_file
        self.port = port
        self.endpoint_file = endpoint_file
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, request: dict) -> dict:
        try:
            token = self.credential_file.read_text(encoding="ascii").strip()
            if not TOKEN.fullmatch(token):
                raise ValueError
        except (OSError, ValueError):
            return {"ok": False, "error_code": "ENTRY_CREDENTIAL_INVALID", "details": {"execution_started": False}}
        try:
            port = self.port if self.endpoint_file is None else json.loads(
                self.endpoint_file.read_text(encoding="utf-8"))["port"]
            if type(port) is not int or not 0 < port <= 65535:
                raise ValueError
        except (OSError, ValueError, KeyError, TypeError):
            return {"ok": False, "error_code": "ENTRY_ENDPOINT_INVALID", "details": {"execution_started": False}}
        message = urllib.request.Request(
            f"http://127.0.0.1:{port}{ENTRY_PATH}", data=json.dumps(request).encode("utf-8"),
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"}, method="POST")
        try:
            try:
                response = self.opener.open(message, timeout=90)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                body = json.load(response)
                if not isinstance(body, dict) or type(body.get("ok")) is not bool:
                    raise ValueError
                return body
        except (OSError, ValueError):
            return {"ok": False, "error_code": "ENTRY_REPLY_UNAVAILABLE",
                    "details": {"retry_safe": False, "automatic_replay": False}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def mcp(client: AgentClient) -> int:
    initialized = ready = False
    for raw in iter(lambda: sys.stdin.buffer.readline(LIMIT + 1), b""):
        if len(raw) > LIMIT:
            return 2
        try:
            message = json.loads(raw)
        except ValueError:
            _mcp_reply(None, error=(-32700, "Parse error"))
            continue
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            _mcp_reply(None, error=(-32600, "Invalid request"))
            continue
        method, params = message["method"], message.get("params", {})
        if "id" not in message:
            if initialized and method == "notifications/initialized":
                ready = True
            continue
        request_id = message["id"]
        if type(request_id) not in (int, str):
            _mcp_reply(None, error=(-32600, "Invalid request id"))
            continue
        if not isinstance(params, dict):
            _mcp_reply(request_id, error=(-32602, "Invalid params"))
        elif method == "ping":
            _mcp_reply(request_id, result={})
        elif method == "initialize" and not initialized and isinstance(params.get("protocolVersion"), str):
            requested = params["protocolVersion"]
            initialized = True
            _mcp_reply(request_id, result={"protocolVersion": requested if requested in MCP_VERSIONS else MCP_VERSIONS[0],
                                          "serverInfo": {"name": "ff-agent-entry", "version": "1.0.0"},
                                          "capabilities": {"tools": {}}})
        elif not ready:
            _mcp_reply(request_id, error=(-32002, "Server not initialized"))
        elif method == "tools/list":
            _mcp_reply(request_id, result={"tools": [TOOL]})
        elif method == "tools/call":
            args = params.get("arguments")
            if params.get("name") != TOOL["name"] or not isinstance(args, dict):
                _mcp_reply(request_id, error=(-32602, "Unknown tool or invalid arguments"))
                continue
            reply = client.call(args)
            _mcp_reply(request_id, result={"content": [{"type": "text", "text": json.dumps(reply, ensure_ascii=False)}],
                                          "isError": not reply["ok"]})
        else:
            _mcp_reply(request_id, error=(-32601, "Method not found"))
    return 0


def _mcp_reply(request_id, *, result=None, error=None) -> None:
    payload = {"jsonrpc": "2.0", "id": request_id}
    if error is None:
        payload["result"] = result
    else:
        payload["error"] = {"code": error[0], "message": error[1]}
    sys.stdout.buffer.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
    sys.stdout.buffer.flush()


def _write_credential_file(path: Path, token: str, *, overwrite: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not overwrite:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as credential:
            credential.write(token + "\n")
            credential.flush()
            os.fsync(credential.fileno())
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as credential:
            credential.write(token + "\n")
            credential.flush()
            os.fsync(credential.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    issue = commands.add_parser("issue", help="owner only: create a task-scoped bearer")
    renew = commands.add_parser("renew", help="owner only: rotate/extend a task-scoped bearer without changing task_id")
    revoke = commands.add_parser("revoke", help="owner only: end a grant")
    for command in (issue, renew, revoke):
        command.add_argument("--state-dir", type=Path, required=True)
    for command in (issue, renew):
        command.add_argument("--credential-file", type=Path, required=True)
        command.add_argument("--client", required=True)
        command.add_argument("--agent", required=True)
        command.add_argument("--task", required=True)
        command.add_argument("--ttl", type=int, required=True)
        command.add_argument("--scope", action="append", choices=sorted(SCOPES), default=None)
        command.add_argument("--app", action="append", choices=sorted(SAFE_APPS), default=None)
    issue.add_argument("--overwrite", action="store_true",
                       help="atomically replace an existing credential file after reissue")
    renew.add_argument("--grant-id", default=None)
    revoke.add_argument("--grant-id", required=True)
    call = commands.add_parser("call")
    stdio = commands.add_parser("mcp")
    for command in (call, stdio):
        command.add_argument("--credential-file", type=Path, required=True)
        endpoint = command.add_mutually_exclusive_group(required=True)
        endpoint.add_argument("--port", type=int)
        endpoint.add_argument("--endpoint-file", type=Path)
    call.add_argument("--op", required=True)
    call.add_argument("--session-id")
    call.add_argument("--key")
    call.add_argument("--args-file", type=Path, help="JSON object, or - for stdin")
    args = parser.parse_args()
    try:
        if args.action == "issue":
            grant, token = EntryAuthority(args.state_dir).issue(
                client_id=args.client, agent_id=args.agent, task_id=args.task,
                scopes=args.scope or [], apps=args.app or [], ttl=args.ttl)
            _write_credential_file(args.credential_file, token, overwrite=args.overwrite)
            result = {"ok": True, "result": grant}
        elif args.action == "renew":
            grant, token = EntryAuthority(args.state_dir).renew(
                client_id=args.client, agent_id=args.agent, task_id=args.task,
                ttl=args.ttl, grant_id=args.grant_id, scopes=args.scope, apps=args.app)
            _write_credential_file(args.credential_file, token, overwrite=True)
            result = {"ok": True, "result": grant}
        elif args.action == "revoke":
            result = {"ok": True, "result": {"revoked": EntryAuthority(args.state_dir).revoke(args.grant_id)}}
        else:
            client = AgentClient(args.credential_file, port=args.port, endpoint_file=args.endpoint_file)
            if args.action == "mcp":
                return mcp(client)
            request = {"op": args.op, "args": {}}
            if args.args_file:
                request["args"] = json.load(sys.stdin) if args.args_file == Path("-") else json.loads(
                    args.args_file.read_text(encoding="utf-8-sig"))
            if args.session_id:
                request["session_id"] = args.session_id
            if args.key:
                request["request_key"] = args.key
            result = client.call(request)
    except (OSError, ValueError, HubError) as exc:
        result = {"ok": False, "error_code": getattr(exc, "code", "ENTRY_LOCAL_INPUT_ERROR")}
    print(json.dumps(result, ensure_ascii=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
