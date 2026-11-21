"""Owned-tab automation in the user's already running Chrome via Playwright Extension.

Safe fallback when FF Windows Bridge browser attach incorrectly chooses an isolated
profile. Uses the pre-existing CurrentUser DPAPI token through the official
cua_browser_extension_rpc.ps1. Does not read, print, or export any token/cookie.
Call only from an authorized Windows Bridge task. Closing ends only this client
session and its owned pages; never terminates the owner's Chrome process.
"""
from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlsplit

BRIDGE_ROOT = Path(__file__).resolve().parent
RPC_SCRIPT = BRIDGE_ROOT / "cua_browser_extension_rpc.ps1"
TIMEOUT_SECONDS = 11.0


class OwnerChromeError(RuntimeError):
    pass


class OwnerChromeSession:
    """Context-managed Playwright Extension client for Chrome's existing Default profile."""

    def __init__(self, client_name: str = "FF Windows Bridge owner Chrome",
                 profile: str = "Default", timeout: float = TIMEOUT_SECONDS,
                 *, background: bool = True) -> None:
        if not re.fullmatch(r"[A-Za-z0-9 ._/-]{4,90}", client_name):
            raise ValueError("CLIENT_NAME_INVALID")
        if not re.fullmatch(r"(Default|Profile [0-9]+)", profile):
            raise ValueError("PROFILE_NAME_INVALID")
        self.client_name = client_name
        self.profile = profile
        self.background = bool(background)
        self.timeout = min(max(float(timeout), 1.0), 15.0)
        self.process: subprocess.Popen[str] | None = None
        self.surface_id: str | None = None
        self.last_close_cleanup: dict | None = None
        self.last_close_error: str | None = None
        self._q: queue.Queue[str] = queue.Queue()
        self._lock = threading.RLock()
        self._counter = 0

    def __enter__(self) -> "OwnerChromeSession":
        if not RPC_SCRIPT.is_file():
            raise OwnerChromeError("INSTALLED_EXTENSION_RPC_NOT_FOUND")
        from cua_playwright_integrity import PlaywrightIntegrityError, assert_playwright_integrity
        try:
            assert_playwright_integrity(BRIDGE_ROOT, require_present=True)
        except PlaywrightIntegrityError as exc:
            raise OwnerChromeError(exc.code) from exc
        env = os.environ.copy()
        env["PLAYWRIGHT_MCP_PROFILE_DIR_NAME"] = self.profile
        self.process = subprocess.Popen(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", str(RPC_SCRIPT)],
            cwd=str(BRIDGE_ROOT), env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        def drain_stdout() -> None:
            assert self.process is not None and self.process.stdout is not None
            try:
                for line in self.process.stdout:
                    self._q.put(line)
            except OSError:
                pass
        def drain_stderr() -> None:
            assert self.process is not None and self.process.stderr is not None
            try:
                for _line in self.process.stderr:
                    pass  # Never surface credentials or browser data from stderr.
            except OSError:
                pass
        threading.Thread(target=drain_stdout, daemon=True).start()
        threading.Thread(target=drain_stderr, daemon=True).start()
        try:
            result = self._call("attach", {
                "ownerBrowser": True, "ownerTransport": "extension",
                "createPage": True, "background": self.background,
                "extensionClientName": self.client_name})
            caps = result.get("capabilities") or {}
            if caps.get("owner_browser") is not True or \
               caps.get("isolated_profile") is not False or \
               caps.get("owner_transport") != "extension":
                raise OwnerChromeError("OWNER_PROFILE_NOT_VERIFIED")
            sid = result.get("surface_id")
            if not isinstance(sid, str) or not sid:
                raise OwnerChromeError("NO_OWNED_BROWSER_SURFACE")
            self.surface_id = sid
            return self
        except BaseException:
            self.close()
            raise

    def _call(self, op: str, args: dict) -> dict:
        with self._lock:
            p = self.process
            if p is None or p.poll() is not None or p.stdin is None:
                raise OwnerChromeError("EXTENSION_PROCESS_NOT_RUNNING")
            self._counter += 1
            rid = "owner-chrome-" + str(self._counter)
            try:
                p.stdin.write(json.dumps({"id": rid, "op": op, "args": args},
                                         ensure_ascii=True) + "\n")
                p.stdin.flush()
            except (BrokenPipeError, OSError) as e:
                raise OwnerChromeError("EXTENSION_IPC_WRITE_FAILED") from e
            try:
                result = json.loads(self._q.get(timeout=self.timeout))
            except queue.Empty as e:
                raise OwnerChromeError("EXTENSION_IPC_TIMEOUT") from e
            except ValueError as e:
                raise OwnerChromeError("EXTENSION_IPC_JSON_INVALID") from e
            if result.get("id") != rid:
                raise OwnerChromeError("EXTENSION_IPC_RESPONSE_MISMATCH")
            if result.get("ok") is not True:
                raise OwnerChromeError(str(result.get("error_code") or "EXTENSION_ACTION_FAILED"))
            data = result.get("result")
            if not isinstance(data, dict):
                raise OwnerChromeError("EXTENSION_RESPONSE_INVALID")
            return data

    def navigate(self, url: str) -> dict:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("ONLY_HTTPS_NAVIGATION_ALLOWED")
        try:
            return self._call("navigate", {"surface_id": self._sid(), "url": url,
                                           "timeout_ms": 10000})
        except OwnerChromeError as exc:
            if str(exc) != "SNAPSHOT_UNSTABLE":
                raise
            # The GET may already have completed; do NOT replay navigation.
            # The sidecar error is about its post-navigation DOM snapshot.
            page = self._call("identity", {"surface_id": self._sid()})
            actual = urlsplit(str(page.get("url") or ""))
            if not (actual.scheme == parsed.scheme and
                    actual.hostname == parsed.hostname and
                    actual.path.rstrip("/") == parsed.path.rstrip("/") and
                    (not parsed.query or actual.query == parsed.query)):
                raise OwnerChromeError("NAVIGATION_URL_NOT_VERIFIED") from exc
            return {"operation": "navigate", "verified": True,
                    "verification": "owned_page_url_after_unstable_snapshot"}

    def observe(self, mode: str = "aria") -> dict:
        if mode not in ("aria", "hybrid"):
            raise ValueError("OBSERVATION_MODE_INVALID")
        import time
        for attempt in range(3):
            try:
                return self._call("observe", {"surface_id": self._sid(),
                                              "options": {"mode": mode}})
            except OwnerChromeError as exc:
                if str(exc) != "SNAPSHOT_UNSTABLE" or attempt == 2:
                    raise
                time.sleep(0.15 * (attempt + 1))
        raise OwnerChromeError("OBSERVATION_FAILED")

    def find(self, query: dict) -> dict:
        return self._call("find", {"surface_id": self._sid(), "query": dict(query)})

    def act(self, action: dict) -> dict:
        """Only actions on pages owned by this extension surface are accepted."""
        return self._call("act", {"surface_id": self._sid(), "action": dict(action)})

    def _sid(self) -> str:
        if self.surface_id is None:
            raise OwnerChromeError("NO_OWNED_BROWSER_SURFACE")
        return self.surface_id

    def close(self) -> None:
        p = self.process
        if p is None:
            return
        self.last_close_cleanup = None
        self.last_close_error = None
        try:
            if self.surface_id and p.poll() is None:
                try:
                    self.last_close_cleanup = self._call("close", {"surface_id": self.surface_id})
                except (OwnerChromeError, OSError) as exc:
                    self.last_close_error = str(exc)
        finally:
            self.surface_id = None
            self.process = None
            try:
                if p.stdin:
                    p.stdin.close()
                p.wait(timeout=2.5)
            except (OSError, subprocess.TimeoutExpired):
                if p.poll() is None:
                    # Kill only this task-owned PowerShell/Node child tree.
                    subprocess.run(["taskkill.exe", "/PID", str(p.pid), "/T", "/F"],
                                   timeout=4, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, check=False)
            for stream in (p.stdout, p.stderr):
                try:
                    if stream:
                        stream.close()
                except OSError:
                    pass

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
