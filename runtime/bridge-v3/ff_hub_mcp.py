"""Dependency-free MCP stdio adapter for an existing FF Hub.

Owner configuration fixes the endpoint/state and client label. Models never
receive transport keys, session secrets or resume tokens. A disconnected MCP
client leaves its session intact for explicit recovery in a later process.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sys

from ff_hub import HubClient, default_state_dir, ensure_running
from ff_hub_io import atomic_json
from ff_hub_store import HubError, _ident

PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
PUBLIC = {"capabilities", "hub_status"}
OPS = PUBLIC | {"session_open", "session_resume", "session_heartbeat", "session_status", "session_close",
                "resource_claim", "resource_release", "resource_list", "permission_check", "permission_describe",
                "browser", "app_discover", "app_open", "app_windows", "app_observe", "app_find", "app_act",
                "app_capture", "app_close", "files", "terminal", "request_status", "audit_read"}
TOOL = {
    "name": "hub",
    "description": "Shared FF Hub: capabilities first, session_open with a unique task_id, then browser/GUI/files/terminal. "
                   "Use a stable request_key for mutations. After a lost reply call request_status with the same key; "
                   "never replay unknown work. Credentials are saved privately; session_resume is explicit. "
                   "Close only your resources, then session_close. No foreground input, paid model calls or owner grants here.",
    "inputSchema": {"type": "object", "properties": {
        "op": {"type": "string", "enum": sorted(OPS)},
        "task_id": {"type": "string", "description": "Unique task label, required except capabilities/hub_status"},
        "args": {"type": "object", "additionalProperties": True},
        "request_key": {"type": "string", "minLength": 8, "maxLength": 200,
                        "description": "Stable operation ID; required for mutations"}},
        "required": ["op"], "additionalProperties": False},
}


@contextmanager
def credential_lock(path: Path):
    """Serialize session bootstrap between MCP processes sharing one task."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        stream.seek(0)
        if os.name == "nt":
            import msvcrt
            if not stream.read(1):
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)


def public_result(value):
    if isinstance(value, dict):
        return {key: public_result(item) for key, item in value.items()
                if key not in {"session_secret", "resume_token"}}
    if isinstance(value, list):
        return [public_result(item) for item in value]
    return value


class Adapter:
    def __init__(self, state: Path, agent: str, *, client=None, start_if_stopped=False):
        self.state, self.agent = Path(state), _ident(agent, "agent_id")
        self.client = client or HubClient(self.state)
        self.start_if_stopped = start_if_stopped
        self.checkpoints = self.state / "clients" / hashlib.sha256(agent.encode()).hexdigest()[:24]

    def _send(self, op, args=None, session=None, key=None):
        if self.start_if_stopped:
            # Owner opt-in only. Neither MCP arguments nor an RPC can create it.
            try:
                flag = json.loads((self.state.parent / "universal-agent-runtime.json").read_text(encoding="utf-8"))
            except (ValueError, OSError):
                flag = None
            if (not isinstance(flag, dict) or type(flag.get("version")) is not int
                    or flag.get("version") != 1 or flag.get("enabled") is not True):
                raise HubError("HUB_FEATURE_DISABLED", execution_started=False)
            ensure_running(self.state)
        request = {"op": op, "args": args or {}}
        if session:
            request.update(session_id=session["session_id"], session_secret=session["session_secret"])
        if key is not None:
            request["request_key"] = key
        response = self.client.raw(request)
        if not response.get("ok"):
            raise HubError(response.get("error_code") or "HUB_REPLY_INVALID", response.get("message"),
                           **(response.get("details") or {}))
        return response["result"]

    def call(self, params: dict) -> dict:
        if not isinstance(params, dict) or set(params) - {"op", "args", "task_id", "request_key"}:
            raise HubError("MCP_ARGUMENTS_INVALID")
        op, args = params.get("op"), params.get("args", {})
        if not isinstance(op, str) or op not in OPS or not isinstance(args, dict):
            raise HubError("MCP_ARGUMENTS_INVALID")
        if op in PUBLIC:
            return public_result(self._send(op, args))
        task = _ident(params.get("task_id"), "task_id")
        path = self.checkpoints / (hashlib.sha256(task.encode()).hexdigest() + ".json")
        with credential_lock(path.with_suffix(".lock")):
            try:
                session = json.loads(path.read_text(encoding="utf-8"))
                if session.get("agent_id") != self.agent or session.get("task_id") != task:
                    raise HubError("MCP_CHECKPOINT_INVALID")
            except FileNotFoundError:
                session = None
            except (ValueError, OSError):
                raise HubError("MCP_CHECKPOINT_INVALID", automatic_replay=False) from None
            if op == "session_open":
                if session:
                    result = self._send("session_status", session=session)
                    return {**public_result(result), "checkpoint_reused": True}
                session = self._send("session_open", {"agent_id": self.agent, "task_id": task,
                                                      "note": str(args.get("note") or "MCP client")[:500]})
                atomic_json(path, session)
                if os.name != "nt":
                    path.chmod(0o600)
                return public_result(session)
            if session is None:
                raise HubError("MCP_SESSION_REQUIRED", instruction="session_open with a new unique task_id")
            if op == "session_resume":
                session = self._send("session_open", {"agent_id": self.agent, "task_id": task,
                                                      "resume_token": session["resume_token"]})
                atomic_json(path, session)
                return public_result(session)
        result = self._send(op, args, session, params.get("request_key"))
        return public_result(result)


def handle(adapter: Adapter, request: dict):
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
    if "id" not in request:
        return None
    response = {"jsonrpc": "2.0", "id": request["id"]}
    method, params = request.get("method"), request.get("params", {})
    if not isinstance(params, dict):
        return {**response, "error": {"code": -32602, "message": "Invalid params"}}
    if method == "initialize":
        version = params.get("protocolVersion")
        result = {"protocolVersion": version if version in PROTOCOLS else PROTOCOLS[-1],
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "ff-universal-hub", "version": "1.0.0"},
                  "instructions": TOOL["description"]}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [TOOL]}
    elif method == "tools/call":
        if params.get("name") != "hub":
            return {**response, "error": {"code": -32602, "message": "Unknown tool"}}
        try:
            value = adapter.call(params.get("arguments", {}))
            result = {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}], "isError": False}
        except (HubError, OSError) as exc:
            value = {"error_code": exc.code if isinstance(exc, HubError) else "MCP_TRANSPORT_ERROR",
                     "details": public_result(exc.details) if isinstance(exc, HubError) else {"automatic_replay": False}}
            result = {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}], "isError": True}
    else:
        return {**response, "error": {"code": -32601, "message": "Method not found"}}
    return {**response, "result": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=None)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--start-if-stopped", action="store_true",
                        help="owner opt-in: start this installed Hub version if stopped; requires enabled local feature flag")
    options = parser.parse_args()
    adapter = Adapter(options.state_dir or default_state_dir(), options.agent, start_if_stopped=options.start_if_stopped)
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8", newline="\n")
    while True:
        line = sys.stdin.readline(2 * 1024 * 1024 + 1)
        if not line:
            break
        if len(line) > 2 * 1024 * 1024:
            break
        try:
            response = handle(adapter, json.loads(line))
        except ValueError:
            response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
        if response is not None:
            print(json.dumps(response, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
