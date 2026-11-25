"""Credential broker: agents use a secret, they do not get it.

Values are sealed with Windows DPAPI for the current user (or left in Windows Credential
Manager and only referenced). An agent asks the Hub to perform an allowed operation with a
named secret: an HTTPS request to a host the owner listed, or a listed program started with the
secret in one environment variable. Values are sealed at rest and scrubbed from HTTP responses;
process output is withheld. Recipients and programs must be trusted: this is not a sandbox
against a server or program that transforms a secret or leaks it through a side channel.

Only the owner, locally, can add, change, share or remove a secret. There is no RPC that
reveals a value and nothing here reads another program's credential store (Chrome included).
"""
from __future__ import annotations

import base64
import ctypes
import json
import math
import os
import re
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from ctypes import wintypes
from pathlib import Path
from typing import Any

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
MAX_SECRET_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 512 * 1024
PLACEHOLDER = "{{secret}}"


class SecretError(RuntimeError):
    def __init__(self, code: str, **details: Any):
        super().__init__(code)
        self.code = code
        self.details = details


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _dpapi(data: bytes, *, protect: bool) -> bytes:
    if os.name != "nt":
        raise SecretError("DPAPI_UNAVAILABLE")
    crypt32, kernel32 = ctypes.WinDLL("crypt32", use_last_error=True), ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    source = _Blob(len(data), ctypes.cast(ctypes.create_string_buffer(data, len(data)), ctypes.POINTER(ctypes.c_char)))
    target = _Blob()
    function = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    # 0x1 = CRYPTPROTECT_UI_FORBIDDEN: never raise a prompt on the owner's screen.
    if not function(ctypes.byref(source), None, None, None, None, 0x1, ctypes.byref(target)):
        raise SecretError("DPAPI_FAILED", winerror=ctypes.get_last_error())
    try:
        return ctypes.string_at(target.pbData, target.cbData)
    finally:
        kernel32.LocalFree(target.pbData)


class _Credential(ctypes.Structure):
    _fields_ = [("Flags", wintypes.DWORD), ("Type", wintypes.DWORD), ("TargetName", wintypes.LPWSTR),
                ("Comment", wintypes.LPWSTR), ("LastWritten", wintypes.FILETIME), ("CredentialBlobSize", wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_char)), ("Persist", wintypes.DWORD),
                ("AttributeCount", wintypes.DWORD), ("Attributes", ctypes.c_void_p), ("TargetAlias", wintypes.LPWSTR),
                ("UserName", wintypes.LPWSTR)]


def _read_windows_credential(target: str) -> bytes:
    """One generic credential the owner explicitly referenced by its exact target name."""
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    pointer = ctypes.POINTER(_Credential)()
    if not advapi32.CredReadW(target, 1, 0, ctypes.byref(pointer)):
        raise SecretError("WINDOWS_CREDENTIAL_NOT_FOUND", target=target)
    try:
        raw = ctypes.string_at(pointer.contents.CredentialBlob, pointer.contents.CredentialBlobSize)
    finally:
        advapi32.CredFree(pointer)
    try:
        return raw.decode("utf-16-le").encode("utf-8")
    except UnicodeDecodeError:
        return raw


class Vault:
    def __init__(self, root: str | Path):
        self.root = Path(root)
        self._lock = threading.RLock()

    def _meta_path(self, name: str) -> Path:
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise SecretError("SECRET_NAME_INVALID")
        return self.root / f"{name}.json"

    def _meta(self, name: str) -> dict:
        try:
            return json.loads(self._meta_path(name).read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise SecretError("SECRET_NOT_FOUND", name=name) from None

    # ---- owner side (local CLI only) -----------------------------------------------------
    def put(self, name: str, value: str | None, *, agents: list[str], hosts: list[str] | None = None,
            commands: list[str] | None = None, windows_credential: str | None = None, note: str = "") -> dict:
        path = self._meta_path(name)
        if not agents:
            raise SecretError("SECRET_AGENTS_REQUIRED", hint="name the agents that may use it, or '*'")
        if not hosts and not commands:
            raise SecretError("SECRET_USE_REQUIRED", hint="list allowed hosts and/or allowed programs")
        if (value is None) == (windows_credential is None):
            raise SecretError("SECRET_SOURCE_INVALID", hint="give a value or a Windows Credential Manager target")
        meta = {"name": name, "agents": list(agents), "hosts": [item.lower() for item in (hosts or [])],
                "commands": [os.path.normcase(os.path.abspath(item)) for item in (commands or [])],
                "source": "windows_credential" if windows_credential else "dpapi",
                "windows_credential": windows_credential, "created_at": time.time(), "revoked": False, "note": note[:300]}
        with self._lock:
            self.root.mkdir(parents=True, exist_ok=True)
            if value is not None:
                data = value.encode("utf-8")
                if not 1 <= len(data) <= MAX_SECRET_BYTES:
                    raise SecretError("SECRET_VALUE_INVALID")
                (self.root / f"{name}.dpapi").write_bytes(_dpapi(data, protect=True))
            else:
                _read_windows_credential(windows_credential)  # fail now if it does not exist
            path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
        return {key: meta[key] for key in ("name", "agents", "hosts", "commands", "source")}

    def revoke(self, name: str) -> bool:
        with self._lock:
            meta = self._meta(name)
            meta["revoked"], meta["revoked_at"] = True, time.time()
            self._meta_path(name).write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            sealed = self.root / f"{name}.dpapi"
            if sealed.exists():
                sealed.unlink()
        return True

    # ---- agent side ----------------------------------------------------------------------
    def _allowed(self, name: str, agent_id: str) -> dict:
        meta = self._meta(name)
        if meta.get("revoked"):
            raise SecretError("SECRET_REVOKED", name=name)
        if "*" not in meta["agents"] and agent_id not in meta["agents"]:
            # Same answer as for a missing secret: do not confirm its existence to others.
            raise SecretError("SECRET_NOT_FOUND", name=name)
        return meta

    def list_for(self, agent_id: str) -> list[dict]:
        found = []
        if not self.root.is_dir():
            return found
        for path in sorted(self.root.glob("*.json")):
            try:
                meta = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if meta.get("revoked") or ("*" not in meta.get("agents", []) and agent_id not in meta.get("agents", [])):
                continue
            found.append({"name": meta["name"], "allowed_hosts": meta.get("hosts", []),
                          "allowed_commands": meta.get("commands", []), "value_readable": False})
        return found

    def _value(self, meta: dict) -> str:
        if meta["source"] == "windows_credential":
            return _read_windows_credential(meta["windows_credential"]).decode("utf-8", "replace")
        try:
            sealed = (self.root / f"{meta['name']}.dpapi").read_bytes()
        except FileNotFoundError:
            raise SecretError("SECRET_VALUE_MISSING", name=meta["name"]) from None
        return _dpapi(sealed, protect=False).decode("utf-8")

    @staticmethod
    def _timeout(value: Any, default: float, minimum: float, maximum: float, error_code: str) -> float:
        if value is None:
            return float(default)
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise SecretError(error_code, execution_started=False)
        return min(max(float(value), minimum), maximum)

    @staticmethod
    def _scrub(text: str, value: str) -> str:
        variants = {value, base64.b64encode(value.encode()).decode(), urllib.parse.quote(value, safe="")}
        for variant in sorted((item for item in variants if item), key=len, reverse=True):
            text = text.replace(variant, "[secret]")
        return text

    def use_http(self, agent_id: str, name: str, request: dict) -> dict:
        """One HTTPS request to an allowed host; `{{secret}}` in a header value is replaced."""
        meta = self._allowed(name, agent_id)
        if not isinstance(request, dict) or set(request) - {"method", "url", "headers", "body", "timeout_s"}:
            raise SecretError("SECRET_REQUEST_INVALID", execution_started=False)
        try:
            url = urllib.parse.urlsplit(str(request.get("url") or ""))
            port = url.port
        except ValueError:
            raise SecretError("SECRET_URL_INVALID", execution_started=False) from None
        if url.username is not None or url.password is not None or url.fragment:
            raise SecretError("SECRET_URL_INVALID", execution_started=False)
        loopback = url.hostname in {"127.0.0.1", "localhost"}
        if url.scheme != "https" and not (url.scheme == "http" and loopback):
            raise SecretError("SECRET_HTTPS_REQUIRED", execution_started=False)
        host = (url.hostname or "").lower()
        allowed = host in meta["hosts"] or (port is not None and f"{host}:{port}" in meta["hosts"])
        if not allowed:
            raise SecretError("SECRET_HOST_NOT_ALLOWED", host=host, allowed_hosts=meta["hosts"], execution_started=False)
        method = str(request.get("method") or "GET").upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
            raise SecretError("SECRET_METHOD_INVALID", execution_started=False)
        headers = request.get("headers") or {}
        if not isinstance(headers, dict) or not any(PLACEHOLDER in str(item) for item in headers.values()):
            raise SecretError("SECRET_PLACEHOLDER_REQUIRED", hint="put {{secret}} into a header value", execution_started=False)
        if any(str(key).lower() in {"host", "proxy-authorization", "proxy-connection", "connection"} for key in headers):
            raise SecretError("SECRET_HEADER_FORBIDDEN", execution_started=False)
        if PLACEHOLDER in str(request.get("url")) or PLACEHOLDER in str(request.get("body") or ""):
            raise SecretError("SECRET_PLACEHOLDER_ONLY_IN_HEADERS", execution_started=False)
        body = request.get("body")
        if body is not None and not isinstance(body, str):
            raise SecretError("SECRET_REQUEST_INVALID", execution_started=False)
        timeout = self._timeout(request.get("timeout_s"), 30, 1, 120, "SECRET_REQUEST_INVALID")
        value = self._value(meta)
        data = body.encode("utf-8") if isinstance(body, str) else None
        prepared = urllib.request.Request(url.geturl(), data=data, method=method, headers={
            str(key): str(item).replace(PLACEHOLDER, value) for key, item in headers.items()})

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            # A redirect could carry the credential header to a host the owner never allowed.
            def redirect_request(self, *args: Any, **kwargs: Any) -> None:
                return None

        opener = urllib.request.build_opener(_NoRedirect, *([urllib.request.ProxyHandler({})] if loopback else []))
        try:
            with opener.open(prepared, timeout=timeout) as response:
                status, raw, response_headers = response.status, response.read(MAX_RESPONSE_BYTES + 1), dict(response.headers)
        except urllib.error.HTTPError as exc:
            status, raw, response_headers = exc.code, exc.read(MAX_RESPONSE_BYTES + 1), dict(exc.headers)
        except (urllib.error.URLError, OSError, TimeoutError, ValueError) as exc:
            raise SecretError("SECRET_REQUEST_FAILED", cause=type(exc).__name__, attempted=True, retry_safe=False,
                              outcome_unknown=True) from None
        text = self._scrub(raw[:MAX_RESPONSE_BYTES].decode("utf-8", "replace"), value)
        return {"status": status, "truncated": len(raw) > MAX_RESPONSE_BYTES, "body": text,
                "headers": {key: self._scrub(str(item), value) for key, item in response_headers.items()
                            if key.lower() in {"content-type", "location", "retry-after", "x-ratelimit-remaining"}},
                "secret": name, "secret_value_returned": False}

    def use_process(self, agent_id: str, name: str, spec: dict) -> dict:
        """Run an allowed program with the secret in one environment variable."""
        meta = self._allowed(name, agent_id)
        if not isinstance(spec, dict) or set(spec) - {"argv", "env_name", "cwd", "timeout_s"}:
            raise SecretError("SECRET_PROCESS_INVALID", execution_started=False)
        argv = spec.get("argv")
        if not isinstance(argv, list) or not argv or any(not isinstance(item, str) for item in argv):
            raise SecretError("SECRET_PROCESS_INVALID", execution_started=False)
        executable = os.path.normcase(os.path.abspath(argv[0]))
        if executable not in meta["commands"] or not os.path.isfile(executable):
            raise SecretError("SECRET_COMMAND_NOT_ALLOWED", allowed_commands=meta["commands"], execution_started=False)
        env_name = spec.get("env_name")
        if not isinstance(env_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", env_name):
            raise SecretError("SECRET_ENV_NAME_INVALID", execution_started=False)
        cwd = spec.get("cwd")
        if cwd is not None and (not isinstance(cwd, str) or not os.path.isdir(cwd)):
            raise SecretError("SECRET_CWD_INVALID", execution_started=False)
        timeout = self._timeout(spec.get("timeout_s"), 60, 1, 600, "SECRET_PROCESS_INVALID")
        value = self._value(meta)
        try:
            done = subprocess.run([executable, *argv[1:]], env={**os.environ, env_name: value}, cwd=cwd,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  timeout=timeout, stdin=subprocess.DEVNULL,
                                  creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except subprocess.TimeoutExpired:
            raise SecretError("SECRET_PROCESS_TIMEOUT", attempted=True, retry_safe=False,
                              outcome_unknown=True) from None

        # A caller-controlled command can encode/reorder the value. Redacting a few string
        # variants is insufficient, so no child output crosses the broker RPC boundary.
        return {"exit_code": done.returncode, "output_returned": False,
                "secret": name, "secret_value_returned": False}
