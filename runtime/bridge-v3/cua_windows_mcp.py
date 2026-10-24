"""Restricted Windows-MCP adapter: direct files and read-only GUI observation."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
from cua_tool_preparation import prepare_windows_mcp

ALLOWED_TOOLS=frozenset({"FileSystem","Snapshot","WaitFor"})
def invoke_windows_mcp(tool,arguments):
    if tool not in ALLOWED_TOOLS or not isinstance(arguments,dict):
        raise ValueError("WINDOWS_MCP_TOOL_NOT_ALLOWED")
    if tool == "FileSystem" and arguments.get("mode") not in {"read", "list", "search", "info"}:
        raise ValueError("WINDOWS_MCP_MUTATION_ROUTE_NOT_VERIFIED")
    arguments = dict(arguments)
    if tool == "Snapshot":
        arguments["use_annotation"] = False
    installation=prepare_windows_mcp()
    python=Path(installation["path"]).with_name("python.exe")
    env=dict(os.environ,ANONYMIZED_TELEMETRY="false",WINDOWS_MCP_WATCHDOG="off",PYTHONIOENCODING="utf-8")
    payload={"tool":tool,"arguments":arguments,"server":installation["path"]}
    result=subprocess.run([str(python),str(Path(__file__).resolve()),"--worker"],input=json.dumps(payload),capture_output=True,text=True,encoding="utf-8",env=env,timeout=45)
    if result.returncode:
        raise RuntimeError("WINDOWS_MCP_ACTION_OUTCOME_UNKNOWN")
    try:return json.loads(result.stdout)
    except ValueError as exc:raise RuntimeError("WINDOWS_MCP_ACTION_OUTCOME_UNKNOWN") from exc

async def _worker(payload):
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport
    transport=StdioTransport(command=payload["server"],args=["serve","--tools","FileSystem,Snapshot,WaitFor"],env=dict(os.environ))
    async with Client(transport) as client:
        response=await client.call_tool(payload["tool"],payload["arguments"],raise_on_error=False)
        return {"ok":not response.is_error,"tool":payload["tool"],"content":[c.model_dump(mode="json") for c in response.content],"physical_input_tools_enabled":False,"backend":"windows-mcp-0.8.5"}
if __name__=="__main__":
    import asyncio
    payload=json.loads(sys.stdin.read())
    if payload.get("tool") not in ALLOWED_TOOLS:raise ValueError("WINDOWS_MCP_TOOL_NOT_ALLOWED")
    print(json.dumps(asyncio.run(_worker(payload)),ensure_ascii=False))
