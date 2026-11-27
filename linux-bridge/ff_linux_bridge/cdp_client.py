"""Pure Python 3 stdlib RFC 6455 WebSocket + Chrome DevTools Protocol (CDP) client.

Zero external pip dependencies — talks directly to Chromium / Google Chrome's
local loopback remote-debugging port (`http://127.0.0.1:<port>`).
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import secrets
import socket
import struct
import threading
import time
from typing import Any
from urllib.parse import urlsplit


class CDPError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def cdp_http_json(port: int, path: str, *, method: str = "GET", timeout_s: float = 5.0) -> Any:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout_s)
    try:
        conn.request(method, path)
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        if resp.status >= 400:
            raise CDPError("CDP_HTTP_ERROR", f"{method} {path} returned HTTP {resp.status}: {body[:200]}")
        if not body.strip():
            return {}
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            return {"text": body}
    except OSError as exc:
        raise CDPError("CDP_CONNECT_ERROR", f"Cannot reach CDP on 127.0.0.1:{port}: {exc}")
    finally:
        conn.close()


class SimpleWebSocket:
    """Minimal synchronous RFC 6455 client over TCP loopback for CDP."""

    def __init__(self, ws_url: str, timeout_s: float = 15.0):
        parsed = urlsplit(ws_url)
        if parsed.scheme != "ws":
            raise CDPError("INVALID_WS_URL", f"Only ws:// loopback URLs are supported: {ws_url}")
        host = parsed.hostname or "127.0.0.1"
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise CDPError("NON_LOOPBACK_CDP", f"Refusing non-loopback CDP WebSocket host: {host}")
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        self._sock = socket.create_connection((host, port), timeout=timeout_s)
        self._sock.settimeout(timeout_s)
        self._lock = threading.Lock()
        self._buf = bytearray()
        self._handshake(host, port, path)

    def _handshake(self, host: str, port: int, path: str) -> None:
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self._sock.sendall(req.encode("ascii"))

        header_end = -1
        while header_end == -1:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise CDPError("WS_HANDSHAKE_EOF", "WebSocket closed during handshake")
            self._buf.extend(chunk)
            header_end = self._buf.find(b"\r\n\r\n")
            if len(self._buf) > 65536:
                raise CDPError("WS_HANDSHAKE_TOO_LARGE", "Handshake header exceeded 64KB")

        raw_header = bytes(self._buf[:header_end]).decode("latin-1")
        del self._buf[: header_end + 4]

        status_line = raw_header.splitlines()[0] if raw_header else ""
        if "101" not in status_line:
            raise CDPError("WS_HANDSHAKE_FAILED", f"Unexpected handshake response: {status_line}")

        expected_accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
        ).decode("ascii")
        if expected_accept not in raw_header:
            raise CDPError("WS_HANDSHAKE_INVALID_ACCEPT", "Sec-WebSocket-Accept mismatch")

    def _recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(max(4096, n - len(self._buf)))
            if not chunk:
                raise CDPError("WS_EOF", "WebSocket connection closed")
            self._buf.extend(chunk)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def send_text(self, text: str) -> None:
        payload = text.encode("utf-8")
        mask_key = secrets.token_bytes(4)
        length = len(payload)
        header = bytearray([0x81])  # FIN + text frame
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        header.extend(mask_key)
        masked = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))
        with self._lock:
            self._sock.sendall(bytes(header) + masked)

    def _send_pong(self, payload: bytes) -> None:
        mask_key = secrets.token_bytes(4)
        header = bytearray([0x8A, 0x80 | len(payload)]) + mask_key
        masked = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))
        with self._lock:
            self._sock.sendall(bytes(header) + masked)

    def recv_text(self, timeout_s: float = 15.0) -> str:
        self._sock.settimeout(timeout_s)
        fragments: list[bytes] = []
        while True:
            b1, b2 = self._recv_exact(2)
            fin = (b1 & 0x80) != 0
            opcode = b1 & 0x0F
            masked = (b2 & 0x80) != 0
            length = b2 & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv_exact(8))[0]
            mask_key = self._recv_exact(4) if masked else b""
            payload = self._recv_exact(length)
            if masked:
                payload = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))

            if opcode == 0x8:  # close
                raise CDPError("WS_CLOSED", "WebSocket closed by peer")
            if opcode == 0x9:  # ping
                self._send_pong(payload)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode in (0x1, 0x0):
                fragments.append(payload)
                if fin:
                    return b"".join(fragments).decode("utf-8", errors="replace")

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


class CDPSession:
    """Short-lived or reusable CDP command runner for a single page WebSocket URL."""

    def __init__(self, ws_url: str, timeout_s: float = 20.0):
        self.ws = SimpleWebSocket(ws_url, timeout_s=timeout_s)
        self._next_id = 1
        self.events: list[dict[str, Any]] = []

    def send(self, method: str, params: dict[str, Any] | None = None, timeout_s: float = 20.0) -> dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        msg = {"id": req_id, "method": method, "params": params or {}}
        self.ws.send_text(json.dumps(msg))

        deadline = time.monotonic() + timeout_s
        while True:
            remaining = max(0.1, deadline - time.monotonic())
            if time.monotonic() >= deadline:
                raise CDPError("CDP_TIMEOUT", f"Timed out waiting for CDP response to {method}")
            try:
                raw = self.ws.recv_text(timeout_s=remaining)
            except socket.timeout:
                raise CDPError("CDP_TIMEOUT", f"Timed out waiting for CDP response to {method}")
            data = json.loads(raw)
            if data.get("id") == req_id:
                if "error" in data:
                    err = data["error"]
                    raise CDPError("CDP_COMMAND_ERROR", f"{method}: {err.get('message', err)}")
                return data.get("result") or {}
            elif "method" in data:
                self.events.append(data)

    def wait_for_event(self, event_name: str, timeout_s: float = 15.0) -> dict[str, Any]:
        for idx, ev in enumerate(self.events):
            if ev.get("method") == event_name:
                return self.events.pop(idx)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            remaining = max(0.1, deadline - time.monotonic())
            try:
                raw = self.ws.recv_text(timeout_s=remaining)
            except socket.timeout:
                break
            data = json.loads(raw)
            if data.get("method") == event_name:
                return data
            if "method" in data:
                self.events.append(data)
        raise CDPError("CDP_EVENT_TIMEOUT", f"Timed out waiting for event {event_name}")

    def close(self) -> None:
        self.ws.close()

    def __enter__(self) -> "CDPSession":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
