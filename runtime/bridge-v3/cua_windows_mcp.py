"""Restricted Windows-MCP adapter: files, GUI observation and, only when the caller
proves a granted desktop (allow_physical), a fixed set of input tools.

One long-lived worker process keeps the Windows-MCP server running between calls.
Starting that server takes about 10 s, and element labels from a Snapshot are only
valid inside the server that produced them, so a fresh server per call made label
based clicks impossible. The worker exits after a period without calls.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import uuid
from cua_tool_preparation import prepare_windows_mcp

ALLOWED_TOOLS=frozenset({"FileSystem","Snapshot","WaitFor"})
# Visible-desktop input. Only reachable from ff_win_v3_main after the desktop is in
# dedicated mode for this agent/task (owner chat permission or signed approval).
PHYSICAL_TOOLS=frozenset({"Click","Type","Scroll","Move","Shortcut","Clipboard","MultiSelect","MultiEdit","Wait"})
OUTCOME_UNKNOWN="WINDOWS_MCP_ACTION_OUTCOME_UNKNOWN"
IDLE_SECONDS=180
FIRST_CALL_TIMEOUT=90
CALL_TIMEOUT=45


class WorkerPool:
    """At most one worker process, one call at a time. Any doubt kills the worker."""

    def __init__(self, spawn, idle_seconds=IDLE_SECONDS):
        self._spawn = spawn
        self._idle = idle_seconds
        self._lock = threading.Lock()
        self._proc = None
        self._lines = None
        self._last_used = 0.0
        self._timer = None

    def call(self, request, first_timeout=FIRST_CALL_TIMEOUT, timeout=CALL_TIMEOUT):
        with self._lock:
            reused = self._alive()
            if not reused:
                self._start()
            request = {"id": uuid.uuid4().hex, **request}
            try:
                self._proc.stdin.write((json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8"))
                self._proc.stdin.flush()
                line = self._lines.get(timeout=timeout if reused else first_timeout)
            except (OSError, ValueError, queue.Empty):
                self._stop()
                raise RuntimeError(OUTCOME_UNKNOWN)
            try:
                if line is None:
                    raise ValueError("worker exited")
                answer = json.loads(line)
                if answer.get("id") != request["id"]:
                    raise ValueError("answer for another request")
            except ValueError:
                self._stop()
                raise RuntimeError(OUTCOME_UNKNOWN)
            answer.pop("id", None)
            answer["worker_pid"] = self._proc.pid
            answer["worker_reused"] = reused
            self._last_used = time.monotonic()
            self._arm_idle_timer()
            return answer

    def stop(self):
        with self._lock:
            self._stop()

    def _alive(self):
        return self._proc is not None and self._proc.poll() is None

    def _start(self):
        self._stop()
        self._proc = self._spawn()
        self._lines = queue.Queue()
        proc, lines = self._proc, self._lines

        def read():
            for line in iter(proc.stdout.readline, b""):
                lines.put(line)
            lines.put(None)
        threading.Thread(target=read, daemon=True).start()

    def _stop(self):
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            proc.stdin.close()
        except OSError:
            pass
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        try:
            proc.stdout.close()
        except OSError:
            pass

    def _arm_idle_timer(self):
        if self._timer is not None:
            self._timer.cancel()
        self._timer = threading.Timer(self._idle, self._idle_check)
        self._timer.daemon = True
        self._timer.start()

    def _idle_check(self):
        if not self._lock.acquire(blocking=False):
            self._arm_idle_timer()
            return
        try:
            if self._alive() and time.monotonic() - self._last_used >= self._idle:
                self._stop()
        finally:
            self._lock.release()


def _spawn_real():
    installation = prepare_windows_mcp()
    python = Path(installation["path"]).with_name("python.exe")
    env = dict(os.environ, ANONYMIZED_TELEMETRY="false", WINDOWS_MCP_WATCHDOG="off", PYTHONIOENCODING="utf-8")
    return subprocess.Popen(
        [str(python), str(Path(__file__).resolve()), "--serve", installation["path"]],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


_POOL = WorkerPool(_spawn_real)


def invoke_windows_mcp(tool, arguments, allow_physical=False):
    allowed = ALLOWED_TOOLS | (PHYSICAL_TOOLS if allow_physical else frozenset())
    if tool not in allowed or not isinstance(arguments, dict):
        raise ValueError("WINDOWS_MCP_TOOL_NOT_ALLOWED")
    if tool == "FileSystem" and arguments.get("mode") not in {"read", "list", "search", "info"}:
        raise ValueError("WINDOWS_MCP_MUTATION_ROUTE_NOT_VERIFIED")
    arguments = dict(arguments)
    if tool == "Snapshot":
        arguments["use_annotation"] = False
    return _POOL.call({"tool": tool, "arguments": arguments, "physical": bool(allow_physical)})


# ---- worker side: runs inside the Windows-MCP environment's own Python ----------------
async def _serve(server):
    import asyncio
    from fastmcp import Client
    from fastmcp.client.transports import StdioTransport
    tools = ",".join(sorted(ALLOWED_TOOLS | PHYSICAL_TOOLS))
    transport = StdioTransport(command=server, args=["serve", "--tools", tools], env=dict(os.environ))
    loop = asyncio.get_running_loop()
    async with Client(transport) as client:
        while True:
            line = await loop.run_in_executor(None, sys.stdin.buffer.readline)
            if not line:
                break
            request = json.loads(line.decode("utf-8"))
            try:
                if request.get("tool") not in ALLOWED_TOOLS | PHYSICAL_TOOLS:
                    raise ValueError("WINDOWS_MCP_TOOL_NOT_ALLOWED")
                response = await client.call_tool(request["tool"], request["arguments"], raise_on_error=False)
                out = {"id": request["id"], "ok": not response.is_error, "tool": request["tool"],
                       "content": [c.model_dump(mode="json") for c in response.content],
                       "physical_input_tools_enabled": bool(request.get("physical")),
                       "backend": "windows-mcp-0.8.5"}
            except Exception as exc:
                out = {"id": request.get("id"), "ok": False, "error_code": "WINDOWS_MCP_WORKER_ERROR",
                       "message": type(exc).__name__}
            sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    import asyncio
    if len(sys.argv) == 3 and sys.argv[1] == "--serve":
        sys.stdout.reconfigure(encoding="utf-8")
        asyncio.run(_serve(sys.argv[2]))
    else:
        raise SystemExit(2)
