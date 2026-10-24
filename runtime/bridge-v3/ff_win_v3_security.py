from __future__ import annotations

import base64
import http.client
import ipaddress
import re
import socket
import ssl
import urllib.parse
from typing import Any

# Content-aware redaction complements key-name redaction in the core agent.
# Keep patterns deliberately bounded to recognizable credential syntax so normal
# command/history metadata remains useful.
_CREDENTIAL_PATTERNS = [
    re.compile(r"(?im)\b(authorization\s*:\s*)[^\r\n]+"),
    re.compile(r"(?im)\b(proxy-authorization\s*:\s*)[^\r\n]+"),
    re.compile(r"(?im)\b(cookie\s*:\s*)[^\r\n]+"),
    re.compile(r"(?im)\b(set-cookie\s*:\s*)[^\r\n]+"),
    re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]{6,}"),
    re.compile(
        r"(?i)\b(api[_-]?key|apikey|token|password|passwd|secret|credential)"
        r"(\s*[:=]\s*)([\"']?)([^\s&;,\"'}]{3,})([\"']?)"
    ),
]


def scrub_text(text: str, bridge_secret: str | None = None) -> str:
    out = text
    if bridge_secret and len(bridge_secret) >= 8:
        out = out.replace(bridge_secret, "<redacted>")
    for index, pattern in enumerate(_CREDENTIAL_PATTERNS):
        if index <= 3:
            out = pattern.sub(lambda m: m.group(1) + "<redacted>", out)
        elif index == 4:
            out = pattern.sub(lambda m: m.group(1) + "<redacted>", out)
        else:
            out = pattern.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", out)
    return out


def make_redactor(core: Any):
    sensitive_parts = tuple(core.SENSITIVE_KEY_PARTS)

    def redact(value: Any, depth: int = 0) -> Any:
        if depth > 6:
            return "<depth-limit>"
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for key, child in value.items():
                normalized = str(key).lower().replace("-", "_")
                if any(part in normalized for part in sensitive_parts):
                    out[str(key)] = "<redacted>"
                else:
                    out[str(key)] = redact(child, depth + 1)
            return out
        if isinstance(value, (list, tuple)):
            return [redact(v, depth + 1) for v in list(value)[:100]]
        if isinstance(value, str):
            cleaned = scrub_text(value, getattr(core.STATE, "secret", None))
            string_redactor = getattr(core, "redact_string", None)
            if callable(string_redactor):
                cleaned = string_redactor(cleaned)
            if len(cleaned) > 4000:
                cleaned = cleaned[:4000] + "...<truncated>"
            return cleaned
        return value

    return redact


def _parse_and_resolve(url: str) -> tuple[urllib.parse.SplitResult, str, int, str]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL_INVALID")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL_USERINFO_BLOCKED")
    host = parsed.hostname.rstrip(".")
    if host.lower() in {"localhost", "localhost.localdomain"}:
        raise ValueError("URL_PRIVATE_HOST_BLOCKED")
    try:
        host_ascii = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("URL_HOST_INVALID") from exc
    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    except ValueError as exc:
        raise ValueError("URL_PORT_INVALID") from exc
    if port < 1 or port > 65535:
        raise ValueError("URL_PORT_INVALID")
    try:
        infos = socket.getaddrinfo(host_ascii, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f"URL_DNS_FAILED:{type(exc).__name__}") from exc
    addresses: list[str] = []
    for info in infos:
        raw = str(info[4][0]).split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ValueError("URL_DNS_ADDRESS_INVALID") from exc
        if not addr.is_global:
            raise ValueError(f"URL_NON_GLOBAL_ADDRESS_BLOCKED:{addr}")
        normalized = str(addr)
        if normalized not in addresses:
            addresses.append(normalized)
    if not addresses:
        raise ValueError("URL_DNS_EMPTY")
    # Strong policy: every DNS answer must be globally routable. Connect to the
    # exact first address we just validated so there is no second DNS lookup.
    return parsed, host_ascii, port, addresses[0]


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, port: int, pinned_ip: str, timeout: float):
        super().__init__(hostname, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, port: int, pinned_ip: str, timeout: float):
        super().__init__(hostname, port=port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = pinned_ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
            sock = self.sock
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def secure_url_read(core: Any, args: dict[str, Any]) -> dict[str, Any]:
    if not core.STATE.config.get("urlReadEnabled", True):
        raise core.RPCError("URL_READ_DISABLED")
    url = args.get("path") or args.get("url")
    if not isinstance(url, str):
        raise core.RPCError("URL_INVALID")
    try:
        parsed, hostname, port, pinned_ip = _parse_and_resolve(url)
    except ValueError as exc:
        raise core.RPCError(str(exc)) from exc

    timeout = min(max(int(args.get("timeout_seconds", 30)), 1), 60)
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    host_header = hostname if port == default_port else f"{hostname}:{port}"
    headers = {
        "Host": host_header,
        "User-Agent": "FF-Windows-Bridge-V3/1",
        "Accept": "*/*",
        "Connection": "close",
    }
    conn: http.client.HTTPConnection
    if parsed.scheme.lower() == "https":
        conn = _PinnedHTTPSConnection(hostname, port, pinned_ip, timeout)
    else:
        conn = _PinnedHTTPConnection(hostname, port, pinned_ip, timeout)
    try:
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        if 300 <= response.status <= 399:
            # Never follow redirects. This makes public->private and scheme-changing
            # redirects fail before the destination is resolved or contacted.
            raise core.RPCError("URL_REDIRECT_BLOCKED", details={"status": response.status})
        raw = response.read(core.MAX_INLINE_BYTES + 1)
        if len(raw) > core.MAX_INLINE_BYTES:
            raise core.RPCError("URL_RESPONSE_TOO_LARGE")
        content_type = response.getheader("Content-Type", "") or ""
        status = int(response.status)
    except core.RPCError:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise core.RPCError("URL_FETCH_FAILED", f"{type(exc).__name__}: {exc}") from exc
    finally:
        try:
            conn.close()
        except Exception:
            pass

    base = {
        "is_url": True,
        "url": url,
        "status": status,
        "content_type": content_type,
        "bytes": len(raw),
        "resolved_ip": pinned_ip,
        "redirect_policy": "reject_all",
    }
    lower_type = content_type.lower()
    if lower_type.startswith("text/") or "json" in lower_type or "xml" in lower_type:
        base["content"] = core.safe_decode(raw)
    else:
        base["base64"] = base64.b64encode(raw).decode("ascii")
    return base


def apply(core: Any, extras: Any) -> None:
    core.redact = make_redactor(core)
    original_read_file = core.OPS["read_file"]

    def hardened_read_file(args: dict[str, Any]) -> dict[str, Any]:
        if bool(args.get("is_url", False)):
            return secure_url_read(core, args)
        return original_read_file(args)

    core.OPS["read_file"] = hardened_read_file

    # extras performs an initial URL validation before delegating to the core
    # reader. Keep that check aligned with the pinned-connect policy.
    def validate_only(url: str) -> None:
        _parse_and_resolve(url)

    extras._public_http_url = validate_only
