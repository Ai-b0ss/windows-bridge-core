"""FF Linux Bridge v3 HTTP RPC Server.

Wire-compatible with `cloudflare-worker/agent/cf-bridge-agent.mjs` and
`tools/cf-flight-controller/flight-controller.mjs`:
  - POST /rpc with header `X-FF3-Key: <secret>` and JSON `{ op, args, request_id }`
  - GET  /health (no secrets exposed)
  - Supports `request_status` reconciliation and native `batch`
"""

from __future__ import annotations

import argparse
import collections
import hmac
import json
import os
import secrets
import signal
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import __version__
from .cdp_client import CDPError
from .ops_browser import BrowserManager, BrowserOpError, build_browser_ops
from .ops_files import FILE_OPS, FileOpError
from .ops_system import SYSTEM_OPS, SystemOpError

MAX_BODY_BYTES = 16 * 1024 * 1024
JOURNAL_MAX_ENTRIES = 1024


def ensure_secret(secret_path: Path) -> str:
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    if secret_path.exists():
        val = secret_path.read_text(encoding="utf-8").strip()
        if val:
            return val
    token = secrets.token_urlsafe(36)
    fd = os.open(str(secret_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    os.chmod(secret_path, 0o600)
    return token


class RequestJournal:
    """Bounded thread-safe journal for `request_status` reconciliation with FlightController."""

    def __init__(self, max_entries: int = JOURNAL_MAX_ENTRIES) -> None:
        self._lock = threading.Lock()
        self._by_key: collections.OrderedDict[str, dict[str, Any]] = collections.OrderedDict()
        self._max = max_entries

    def record(self, key: str, op: str, state: str, response: dict[str, Any] | None = None) -> None:
        if not key:
            return
        with self._lock:
            self._by_key[key] = {
                "key": key,
                "op": op,
                "state": state,
                "updated_at": int(time.time()),
                "response": response,
            }
            self._by_key.move_to_end(key)
            while len(self._by_key) > self._max:
                self._by_key.popitem(last=False)

    def lookup(self, key: str) -> dict[str, Any] | None:
        if not key:
            return None
        with self._lock:
            return self._by_key.get(key)


class LinuxBridgeRuntime:
    def __init__(
        self,
        *,
        device_name: str,
        secret: str,
        workspace_root: str | None = None,
    ) -> None:
        self.device_name = device_name
        self.secret = secret
        self.workspace_root = str(Path(workspace_root).resolve()) if workspace_root else None
        self.started_monotonic = time.monotonic()
        self.browser = BrowserManager()
        self.journal = RequestJournal()
        self._ctx = {
            "device_name": self.device_name,
            "workspace_root": self.workspace_root,
            "started_monotonic": self.started_monotonic,
        }
        self._browser_ops = build_browser_ops(self.browser, self.workspace_root)
        self._all_op_names = sorted(
            set(SYSTEM_OPS.keys())
            | set(FILE_OPS.keys())
            | set(self._browser_ops.keys())
            | {"capabilities", "batch", "request_status"}
        )

    def verify_secret(self, provided: str | None) -> bool:
        if not provided:
            return False
        return hmac.compare_digest(provided.strip(), self.secret)

    def dispatch(self, op: str, args: dict[str, Any], request_id: str) -> dict[str, Any]:
        started = time.monotonic()
        dedupe_key = str(args.get("dedupe_key") or request_id or "")

        if op == "request_status":
            lookup_key = str(args.get("dedupe_key") or args.get("request_id") or "")
            rec = self.journal.lookup(lookup_key)
            res = {"found": bool(rec), "record": rec} if rec else {"found": False}
            return self._ok(op, request_id, started, res)

        if op == "capabilities":
            return self._ok(
                op,
                request_id,
                started,
                {
                    "bridge": "ff-linux-v3",
                    "version": __version__,
                    "level": 2,
                    "device": self.device_name,
                    "workspace_root": self.workspace_root,
                    "ops_count": len(self._all_op_names),
                    "ops": self._all_op_names,
                },
            )

        if op == "batch":
            return self._handle_batch(args, request_id, started)

        if dedupe_key:
            self.journal.record(dedupe_key, op, "running")

        try:
            if op in SYSTEM_OPS:
                data = SYSTEM_OPS[op](args, self._ctx)
            elif op in FILE_OPS:
                data = FILE_OPS[op](args, self.workspace_root)
            elif op in self._browser_ops:
                data = self._browser_ops[op](args)
            else:
                envelope = self._err(op, request_id, started, "UNKNOWN_OP", f"Unsupported op: {op}")
                if dedupe_key:
                    self.journal.record(dedupe_key, op, "failed", envelope)
                return envelope

            envelope = self._ok(op, request_id, started, data)
            if dedupe_key:
                self.journal.record(dedupe_key, op, "completed", envelope)
            return envelope
        except (FileOpError, SystemOpError, BrowserOpError, CDPError) as exc:
            envelope = self._err(op, request_id, started, exc.code, exc.message)
            if dedupe_key:
                self.journal.record(dedupe_key, op, "failed", envelope)
            return envelope
        except Exception as exc:
            envelope = self._err(op, request_id, started, "INTERNAL_ERROR", f"{type(exc).__name__}: {exc}")
            if dedupe_key:
                self.journal.record(dedupe_key, op, "failed", envelope)
            return envelope

    def _handle_batch(self, args: dict[str, Any], request_id: str, started: float) -> dict[str, Any]:
        calls = args.get("calls")
        if not isinstance(calls, list) or not (1 <= len(calls) <= 16):
            return self._err("batch", request_id, started, "INVALID_BATCH", "calls must be a list of 1..16 operations")
        stop_on_error = args.get("stop_on_error", True) is not False
        results = []
        stopped = False
        for idx, step in enumerate(calls):
            if not isinstance(step, dict) or not isinstance(step.get("op"), str):
                return self._err("batch", request_id, started, "INVALID_BATCH_STEP", f"Step {idx} must be {{op, args}}")
            step_op = step["op"].strip()
            if step_op == "batch":
                return self._err("batch", request_id, started, "NESTED_BATCH_FORBIDDEN", "Nested batch is not allowed")
            if stopped:
                results.append({"index": idx, "op": step_op, "status": "not_started"})
                continue
            step_args = step.get("args") if isinstance(step.get("args"), dict) else {}
            step_res = self.dispatch(step_op, step_args, f"{request_id}:step:{idx}")
            failed = not step_res.get("ok", False)
            results.append({"index": idx, "op": step_op, "status": "failed" if failed else "ok", "response": step_res})
            if failed and stop_on_error:
                stopped = True
        return self._ok(
            "batch",
            request_id,
            started,
            {
                "schema": "ff-linux-v3-batch-v1",
                "total": len(calls),
                "stopped_on_error": stopped,
                "results": results,
            },
        )

    def _ok(self, op: str, request_id: str, started: float, result: Any) -> dict[str, Any]:
        return {
            "schema": "ff-linux-v3-result-v1",
            "ok": True,
            "request_id": request_id,
            "device": self.device_name,
            "op": op,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "result": result,
        }

    def _err(self, op: str, request_id: str, started: float, code: str, message: str) -> dict[str, Any]:
        return {
            "schema": "ff-linux-v3-result-v1",
            "ok": False,
            "request_id": request_id,
            "device": self.device_name,
            "op": op,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "error": {"code": code, "message": message},
        }

    def shutdown(self) -> None:
        try:
            self.browser.close()
        except Exception:
            pass


def make_handler(runtime: LinuxBridgeRuntime) -> type[BaseHTTPRequestHandler]:
    class BridgeHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            if os.environ.get("FF_LINUX_ACCESS_LOG") == "1":
                super().log_message(format, *args)

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path.split("?", 1)[0] == "/health":
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "bridge": "ff-linux-v3",
                        "version": __version__,
                        "device": runtime.device_name,
                        "uptime_s": int(time.monotonic() - runtime.started_monotonic),
                    },
                )
                return
            self._send_json(404, {"ok": False, "error": "NOT_FOUND"})

        def do_POST(self) -> None:
            if self.path.split("?", 1)[0] != "/rpc":
                self._send_json(404, {"ok": False, "error": "NOT_FOUND"})
                return

            provided_key = self.headers.get("X-FF3-Key") or self.headers.get("X-FF-Secret")
            if not runtime.verify_secret(provided_key):
                self._send_json(401, {"ok": False, "error": "UNAUTHORIZED"})
                return

            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._send_json(400, {"ok": False, "error": "INVALID_CONTENT_LENGTH"})
                return
            if length <= 0 or length > MAX_BODY_BYTES:
                self._send_json(413 if length > MAX_BODY_BYTES else 400, {"ok": False, "error": "INVALID_BODY_SIZE"})
                return

            raw = self.rfile.read(length)
            try:
                req = json.loads(raw.decode("utf-8"))
            except Exception:
                self._send_json(400, {"ok": False, "error": "INVALID_JSON"})
                return

            if not isinstance(req, dict) or not isinstance(req.get("op"), str) or not req["op"].strip():
                self._send_json(400, {"ok": False, "error": "MISSING_OP"})
                return

            op = req["op"].strip()
            args = req.get("args") if isinstance(req.get("args"), dict) else {}
            request_id = str(req.get("request_id") or secrets.token_hex(8))
            resp = runtime.dispatch(op, args, request_id)
            self._send_json(200, resp)

    return BridgeHandler


def create_server(
    *,
    host: str = "127.0.0.1",
    port: int = 39073,
    device_name: str | None = None,
    secret: str | None = None,
    secret_file: str | None = None,
    workspace_root: str | None = None,
    allow_non_loopback: bool = False,
) -> tuple[ThreadingHTTPServer, LinuxBridgeRuntime]:
    if not allow_non_loopback and host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError(f"Refusing to bind non-loopback host {host} without --allow-non-loopback")

    if not secret:
        sec_path = Path(
            secret_file
            or os.environ.get("FF_RPC_SECRET_FILE")
            or str(Path.home() / ".config" / "ff-linux-bridge" / "rpc-secret.txt")
        )
        secret = ensure_secret(sec_path)

    dev_name = device_name or os.environ.get("FF_DEVICE_NAME") or socket.gethostname()
    runtime = LinuxBridgeRuntime(device_name=dev_name, secret=secret, workspace_root=workspace_root)
    httpd = ThreadingHTTPServer((host, port), make_handler(runtime))
    httpd.daemon_threads = True
    return httpd, runtime


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="FF Linux Bridge v3 (Level 2) RPC Server")
    parser.add_argument("--host", default=os.environ.get("FF_LINUX_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("FF_LINUX_PORT", "39073")))
    parser.add_argument("--device-name", default=os.environ.get("FF_DEVICE_NAME"))
    parser.add_argument("--secret-file", default=os.environ.get("FF_RPC_SECRET_FILE"))
    parser.add_argument("--workspace-root", default=os.environ.get("FF_LINUX_WORKSPACE_ROOT") or None)
    parser.add_argument("--allow-non-loopback", action="store_true")
    args = parser.parse_args(argv)

    httpd, runtime = create_server(
        host=args.host,
        port=args.port,
        device_name=args.device_name,
        secret_file=args.secret_file,
        workspace_root=args.workspace_root,
        allow_non_loopback=args.allow_non_loopback,
    )

    def _handle_sig(signum: int, _frame: Any) -> None:
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _handle_sig)
    signal.signal(signal.SIGINT, _handle_sig)

    print(
        f"[ff-linux-bridge] v{__version__} listening on http://{args.host}:{httpd.server_address[1]}/rpc "
        f"(device={runtime.device_name}, ops={len(runtime._all_op_names)})",
        flush=True,
    )
    try:
        httpd.serve_forever()
    finally:
        runtime.shutdown()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
