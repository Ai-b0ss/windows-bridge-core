"""FF agent Hub: one small long-lived process that every agent and every Bridge instance shares.

It owns what must outlive an agent client or a Bridge restart and what several agents must not
fight over: agent sessions, ownership of tabs / windows / processes / locks, the connection to
the owner's Chrome, private desktops for GUI applications, standing permissions, brokered
secrets, the idempotent request journal and the audit log.

    python ff_hub.py serve            start (loopback only)
    python ff_hub.py status           what is running, who holds what
    python ff_hub.py grant add ...    owner: allow a class of action once
    python ff_hub.py secret put ...   owner: store a credential for brokered use

Agents never run these owner commands; they talk to the Hub over RPC (directly, or through the
Bridge operation `hub`) and discover everything from `capabilities`.
"""
from __future__ import annotations

import argparse
import hmac
import http.client
import http.server
import json
import math
import os
import secrets as _secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ff_hub_apps as apps
from cua_owner_chrome_secondary import (
    OwnerChromeHiddenSecondaryManager,
    OwnerChromeSecondaryError,
    ROUTE_NAME as OWNER_CHROME_HIDDEN_ROUTE,
)
from ff_agent_entry import ENTRY_PATH, SCHEMA as ENTRY_SCHEMA, EntryArtifacts, EntryAuthority, entry_call
from ff_browser_routes import RouteAffinityStore, route_plan as live_route_plan
from ff_hub_permissions import RISK_CLASSES, PermissionError_, Policy
from ff_hub_secrets import SecretError, Vault
from ff_hub_store import HubError, HubStore, ORPHAN_TTL_SECONDS, RESOURCE_KINDS, SESSION_TTL_SECONDS
from ff_win_process_identity import process_creation_token, process_identity_matches

HUB_VERSION = 1
DEFAULT_PORT = 39090
PACKAGE = Path(__file__).resolve().parent
MAX_HIDDEN_SESSIONS = 6
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MANAGED_BROWSER_OPEN_ARGS = ("url", "sticky", "profile_id", "profile_name", "profile_dir", "persistent_profile")
PRIVATE_BROWSER_OPEN_ARGS = ("profile_id", "profile_name", "persistent_profile")


def default_state_dir() -> Path:
    root = os.environ.get("FF_BRIDGE_ROOT") or str(Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "FF-Windows-Bridge")
    return Path(os.environ.get("FF_HUB_STATE") or Path(root) / "state" / "hub")


def _loopback_opener() -> urllib.request.OpenerDirector:
    # Loopback only: never send a local key through an environment HTTP proxy.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _pid_alive(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False
    import ctypes
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))
    if not handle:
        return False
    try:
        code = ctypes.c_ulong()
        return bool(ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _positive_float(value: Any, default: float) -> float:
    if type(value) in (int, float) and math.isfinite(value) and value > 0:
        return float(value)
    return float(default)


class _BaseNodeRpcClient:
    """Shared lifecycle, exponential backoff and loopback RPC transport for Node managers."""

    def __init__(self, state_dir: Path, *, header_name: str, playwright_root: str | None = None, log_name: str):
        self.state_dir = state_dir
        self.playwright_root = playwright_root or os.environ.get("FF_PLAYWRIGHT_ROOT") or str(PACKAGE)
        self._header_name = header_name
        self._log_name = log_name
        self._lock = threading.RLock()
        self._process: subprocess.Popen | None = None
        self._endpoint: dict | None = None
        self._key: str | None = None
        self._next_start = 0.0
        self._failures = 0
        self.starts = 0

    def _poll_endpoint(
        self,
        process: subprocess.Popen,
        endpoint_file: Path,
        key: str,
        *,
        start_error_code: str,
        start_error_message: str,
        error_details: dict | None = None,
        decorate_endpoint: Callable[[dict], None] | None = None,
    ) -> None:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            if endpoint_file.is_file():
                try:
                    endpoint = json.loads(endpoint_file.read_text(encoding="utf-8"))
                    if decorate_endpoint:
                        decorate_endpoint(endpoint)
                    self._process, self._endpoint, self._key, self._failures = process, endpoint, key, 0
                    self.starts += 1
                    return
                except (OSError, ValueError):
                    pass
            time.sleep(0.05)
        if process.stdin:
            try:
                process.stdin.close()
            except OSError:
                pass
        if process.poll() is None:
            process.kill()
        self._failures += 1
        self._next_start = time.monotonic() + min(2.0 ** self._failures, 120.0)
        tail = ""
        try:
            tail = (self.state_dir / self._log_name).read_bytes()[-600:].decode("utf-8", "replace").strip()
        except OSError:
            pass
        raise HubError(
            start_error_code,
            start_error_message,
            cause=tail.splitlines()[-1][:300] if tail else "no output",
            retry_safe=True,
            **(error_details or {}),
        )

    def _open_log(self):
        log = open(self.state_dir / self._log_name, "ab", buffering=0)
        if log.tell() > 2 * 1024 * 1024:
            log.truncate(0)
        return log

    def call(self, op: str, args: dict | None = None, *, timeout: float = 150.0) -> dict:
        with self._lock:
            if self._process is None or self._process.poll() is not None:
                self._process = None
                self._start()
            endpoint, key = self._endpoint, self._key
        request = urllib.request.Request(
            f"http://127.0.0.1:{endpoint['port']}/rpc",
            method="POST",
            data=json.dumps({"op": op, "args": args or {}}).encode("utf-8"),
            headers={"content-type": "application/json", self._header_name: key},
        )
        try:
            with _loopback_opener().open(request, timeout=timeout) as response:
                reply = json.loads(response.read())
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
            # The request may have reached the browser. Say so instead of guessing.
            raise HubError(
                "BROWSER_MANAGER_UNREACHABLE",
                "no reply from the browser session manager",
                cause=type(exc).__name__,
                attempted=True,
                retry_safe=False,
                outcome_unknown=True,
            ) from None
        if reply.get("ok"):
            return reply["result"]
        raise HubError(reply.get("error_code") or "BROWSER_ERROR", reply.get("message"), **(reply.get("details") or {}))

    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    def _default_shutdown_args(self) -> dict:
        return {"close_tabs": True}

    def stop(self, *, shutdown_args: dict | None = None) -> None:
        with self._lock:
            process, self._process = self._process, None
            if process is None or process.poll() is not None:
                return
            try:
                try:
                    self.call_raw_shutdown(shutdown_args)
                except Exception:
                    pass
                if process.stdin:
                    try:
                        process.stdin.close()
                    except OSError:
                        pass
                try:
                    process.wait(timeout=8)
                except Exception:
                    process.kill()
                    try:
                        process.wait(timeout=3)
                    except Exception:
                        pass
            finally:
                if process.stdin:
                    try:
                        process.stdin.close()
                    except OSError:
                        pass

    def call_raw_shutdown(self, args: dict | None = None) -> None:
        payload = self._default_shutdown_args() if args is None else args
        request = urllib.request.Request(
            f"http://127.0.0.1:{self._endpoint['port']}/rpc",
            method="POST",
            data=json.dumps({"op": "shutdown", "args": payload}).encode("utf-8"),
            headers={"content-type": "application/json", self._header_name: self._key},
        )
        _loopback_opener().open(request, timeout=10).read()


# ---- browser session manager client ------------------------------------------------------
class BrowserManager(_BaseNodeRpcClient):
    """Starts the Node browser hub on demand, keeps it alive, restarts it with backoff."""

    def __init__(self, state_dir: Path, *, playwright_root: str | None = None, profile: str | None = None):
        super().__init__(state_dir / "browser", header_name="x-ff-browser-key",
                         playwright_root=playwright_root, log_name="browser-hub.log")
        self.profile = profile

    def stop(self, *, close_tabs: bool = True) -> None:
        super().stop(shutdown_args={"close_tabs": bool(close_tabs)})

    def _wait_for_prior_manager(self, timeout: float = 10.0) -> None:
        # After a parent Hub crash the old Node process drains its accepted
        # work, preserves pages and releases the relay on stdin EOF. Do not
        # race that ledger writer or replace its endpoint while it retires.
        endpoint = self.state_dir / "endpoint.json"
        try:
            previous = json.loads(endpoint.read_text(encoding="utf-8"))
            pid, token = previous["pid"], previous.get("create_time")
        except (OSError, ValueError, KeyError, TypeError):
            return
        if type(pid) is not int or pid <= 0:
            raise HubError("BROWSER_MANAGER_ENDPOINT_INVALID", execution_started=False)
        deadline = time.monotonic() + timeout
        while endpoint.exists():
            alive = (process_identity_matches(pid, token) if os.name == "nt" and type(token) is int
                     else _pid_alive(pid))
            if not alive:
                return
            if time.monotonic() >= deadline:
                raise HubError("BROWSER_MANAGER_RETIRING", "previous manager has not released the relay yet",
                               execution_started=False, retry_safe=True, retry_after_ms=1000)
            time.sleep(.05)

    def _start(self) -> None:
        now = time.monotonic()
        if now < self._next_start:
            raise HubError("BROWSER_MANAGER_BACKOFF", "the browser manager failed to start; waiting before retrying",
                           retry_after_ms=int((self._next_start - now) * 1000), retry_safe=True)
        powershell = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._wait_for_prior_manager()
        endpoint_file = self.state_dir / "endpoint.json"
        endpoint_file.unlink(missing_ok=True)
        key = _secrets.token_urlsafe(48)
        argv = [powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File",
                str(PACKAGE / "ff_browser_hub.ps1"), "-StateDir", str(self.state_dir), "-EndpointFile", str(endpoint_file),
                "-PlaywrightRoot", self.playwright_root]
        if self.profile:
            argv += ["-ProfileDirName", self.profile]
        with self._open_log() as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=log, stderr=log, cwd=str(PACKAGE),
                                       env={**os.environ, "FF_BROWSER_HUB_KEY": key},
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        from ff_hub_io import atomic_json

        def decorate(ep: dict) -> None:
            ep["create_time"] = process_creation_token(ep["pid"])
            atomic_json(endpoint_file, ep)

        self._poll_endpoint(
            process,
            endpoint_file,
            key,
            start_error_code="BROWSER_MANAGER_START_FAILED",
            start_error_message="the browser session manager did not start",
            error_details={"isolated_fallback": False},
            decorate_endpoint=decorate,
        )


class ManagedBrowserManager(_BaseNodeRpcClient):
    """Starts the persistent headless Playwright manager (`ff_playwright_managed.mjs`)."""

    def __init__(self, state_dir: Path, *, playwright_root: str | None = None):
        super().__init__(state_dir / "managed-playwright", header_name="x-ff-managed-key",
                         playwright_root=playwright_root, log_name="managed-playwright.log")

    def _default_shutdown_args(self) -> dict:
        return {"close_contexts": True}

    def stop(self, *, close_contexts: bool = True) -> None:
        super().stop(shutdown_args={"close_contexts": bool(close_contexts)})

    def _start(self) -> None:
        now = time.monotonic()
        if now < self._next_start:
            raise HubError("MANAGED_BROWSER_BACKOFF", "the managed Playwright process is cooling down",
                           retry_after_ms=int((self._next_start - now) * 1000), retry_safe=True)
        node = shutil.which("node")
        if not node:
            raise HubError("NODE_NOT_INSTALLED", "Node.js is required for persistent Playwright")
        self.state_dir.mkdir(parents=True, exist_ok=True)
        endpoint_file = self.state_dir / "endpoint.json"
        endpoint_file.unlink(missing_ok=True)
        key = _secrets.token_urlsafe(48)
        argv = [node, str(PACKAGE / "ff_playwright_managed.mjs"),
                "--state-dir", str(self.state_dir),
                "--endpoint-file", str(endpoint_file),
                "--playwright-root", self.playwright_root]
        with self._open_log() as log:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=log, stderr=log, cwd=str(PACKAGE),
                                       env={**os.environ, "FF_MANAGED_PW_KEY": key},
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self._poll_endpoint(
            process,
            endpoint_file,
            key,
            start_error_code="MANAGED_BROWSER_START_FAILED",
            start_error_message="the managed Playwright process did not start",
        )


# ---- the hub -----------------------------------------------------------------------------
class Hub:
    def __init__(self, state_dir: str | Path, *, browser: Any = None, managed_browser: Any = None,
                 owner_chrome_secondary: Any = None,
                 hidden_factory: Callable[[], Any] | None = None, store: HubStore | None = None,
                 session_ttl: float | None = None, orphan_ttl: float | None = None,
                 maintain_interval: float | None = None):
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        config = self._config()
        resolved_session_ttl = _positive_float(
            session_ttl if session_ttl is not None else config.get("session_ttl_seconds"),
            SESSION_TTL_SECONDS,
        )
        resolved_orphan_ttl = _positive_float(
            orphan_ttl if orphan_ttl is not None else config.get("orphan_ttl_seconds"),
            ORPHAN_TTL_SECONDS,
        )
        self.store = store or HubStore(
            self.state_dir / "hub.db",
            session_ttl=resolved_session_ttl,
            orphan_ttl=resolved_orphan_ttl,
        )
        default_maintain = min(30.0, max(0.2, (self.store.session_ttl + self.store.orphan_ttl) / 2.0))
        self._maintain_interval = max(
            0.1,
            min(
                300.0,
                _positive_float(
                    maintain_interval if maintain_interval is not None else config.get("maintain_interval_seconds"),
                    default_maintain,
                ),
            ),
        )
        self.entry_authority = EntryAuthority(self.state_dir)
        self.app_catalog = self.entry_authority.catalog
        self.entry_artifacts = EntryArtifacts(self.state_dir)
        self.policy = Policy(self.state_dir / "policy.json")
        self.vault = Vault(self.state_dir / "vault")
        self.browser = browser or BrowserManager(self.state_dir, playwright_root=config.get("playwright_root"),
                                                 profile=config.get("chrome_profile"))
        self.managed_browser = managed_browser or ManagedBrowserManager(
            self.state_dir, playwright_root=config.get("playwright_root")
        )
        self.owner_chrome_secondary = owner_chrome_secondary or OwnerChromeHiddenSecondaryManager(
            self.state_dir,
            profile_dir_name=str(config.get("owner_chrome_profile") or config.get("chrome_profile") or "Profile 1"),
            cdp_endpoint=config.get("owner_chrome_cdp_endpoint"),
            user_data_dir=config.get("owner_chrome_user_data_dir"),
        )
        self.owner_chrome_hidden = self.owner_chrome_secondary
        self.route_affinity = RouteAffinityStore(self.state_dir)
        self._hidden_factory = hidden_factory
        self._hidden: dict[str, Any] = {}
        self._hidden_lock = threading.RLock()
        self._gates_lock = threading.Lock()
        self._gates: dict[str, list[Any]] = {}
        from ff_hub_io import HubIO
        self.io = HubIO(self)
        self.started_at = time.time()
        self._stop = threading.Event()
        self._stopping = False
        # Private desktops and managed browser contexts normally exit with the Hub process.
        # Verify whether a recorded PID incarnation somehow survived before releasing its row;
        # never silently drop a live orphaned process or unverified browser_tab.
        reconcilable_ids: list[str] = []
        for item in self.store.resources(kind="app_session"):
            meta = item.get("meta") or {}
            pid = meta.get("pid") or meta.get("child_pid")
            ctime = meta.get("create_time")
            still_alive = False
            if type(pid) is int and pid > 0:
                still_alive = (
                    process_identity_matches(pid, ctime)
                    if (os.name == "nt" and type(ctime) is int)
                    else _pid_alive(pid)
                )
            if still_alive:
                self.store.audit(
                    "app_session_orphaned_on_hub_restart",
                    agent_id=item["agent_id"],
                    task_id=item["task_id"],
                    session_id=item["session_id"],
                    app_id=item["key"],
                    pid=pid,
                )
            else:
                reconcilable_ids.append(item["resource_id"])
        for item in self.store.release_resources_by_ids(reconcilable_ids):
            self.store.audit("app_session_lost_on_hub_restart", agent_id=item["agent_id"], task_id=item["task_id"],
                             session_id=item["session_id"], app_id=item["key"])
        for candidate in self.entry_artifacts.root.glob("ses-*"):
            if self.store.is_active_entry_session(candidate.name):
                continue
            try:
                self.entry_artifacts.close(candidate.name)
            except (HubError, OSError):
                self.store.audit("entry_artifact_recovery_failed", session_id=candidate.name)

    def _config(self) -> dict:
        try:
            data = json.loads((self.state_dir / "config.json").read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    # ---- permissions ---------------------------------------------------------------------
    def _permit(self, session: dict, risk_class: str, target: dict | None = None, *, action: str = "") -> dict:
        decision = self.policy.decide(session["agent_id"], risk_class, target)
        self.store.audit("permission", agent_id=session["agent_id"], task_id=session["task_id"],
                         session_id=session["session_id"], risk_class=risk_class, action=action,
                         target=target or {}, decision=decision["decision"], reason=decision["reason"],
                         grant_id=decision.get("grant_id"))
        if decision["decision"] == "allow":
            return decision
        pending = self.store.record_permission_request(session, risk_class, target or {}, action)
        raise HubError("PERMISSION_REQUIRED", "the owner has not allowed this class of action for this target",
                       risk_class=risk_class, reason=decision["reason"], target=target or {},
                       standing_grant_possible=decision.get("standing_grant_possible", False),
                       grant_must_name=decision.get("grant_must_name"), owner_request_id=pending["request_id"],
                       already_asked=pending["repeated"], retry_safe=True, execution_started=False,
                       retry_requires="owner_policy_change",
                       next_step="tell the owner once; after `ff_hub.py approve` or `grant add` the whole class runs without asking")

    # ---- owner string shared with the browser manager: stable across session resume ------
    @staticmethod
    def _owner(session: dict) -> str:
        return f"{session['agent_id']}\x1f{session['task_id']}"

    # ---- browser -------------------------------------------------------------------------
    def _browser_tab(self, session: dict, tab_id: Any) -> dict:
        if not isinstance(tab_id, str) or not tab_id:
            raise HubError("TAB_ID_REQUIRED")
        return self.store.require_owned(session, "browser_tab", tab_id)

    def _browser(self, session: dict, args: dict) -> dict:
        command = str(args.get("command") or "")
        if args.get("foreground") is True:
            raise HubError("FOREGROUND_ROUTE_REQUIRED", "use the existing guarded Bridge desktop route",
                           execution_started=False, retry_safe=False,
                           required_guards=["chat_permission", "time_box", "exact_target", "OWNER_ACTIVE", "notice", "Stop"])
        owner = self._owner(session)
        if command == "status":
            status = self.browser.call("status") if getattr(self.browser, "running", lambda: True)() else {"connected": False, "started": False}
            return {**status, "my_tabs": [item["key"] for item in self.store.resources(session_id=session["session_id"], kind="browser_tab")]}
        if command == "list":
            mine = self.store.resources(session_id=session["session_id"], kind="browser_tab")
            running = getattr(self.browser, "running", lambda: True)()
            live = {item["tab_id"]: item for item in self.browser.call("tab_list", {"owner": owner})["tabs"]} if running else {}
            # Popups are attributed by the browser manager to their opener's stable owner.
            # Materialize those records too, so the client can inspect/close its own popup.
            known = {item["key"] for item in mine}
            for tab_id, tab in live.items():
                if tab_id not in known:
                    self.store.claim(session, "browser_tab", tab_id, meta={"url": tab.get("url")})
            mine = self.store.resources(session_id=session["session_id"], kind="browser_tab")
            return {"tabs": [{"tab_id": item["key"], **({"state": live[item["key"]]["state"], "url": live[item["key"]]["url"],
                                                          "title": live[item["key"]]["title"]} if item["key"] in live
                                                         else {"state": "lost", "url": item["meta"].get("url")})} for item in mine]}
        if command == "open":
            url = args.get("url")
            self._permit(session, "browser_own_tabs", {"host": urllib.parse.urlsplit(str(url or "")).hostname or ""}, action="browser.open")
            try:
                tab = self.browser.call("tab_open", {"owner": owner, "url": url})
            except HubError as exc:
                if exc.details.get("cleanup_failed") and isinstance(exc.details.get("tab_id"), str):
                    self.store.claim(session, "browser_tab", exc.details["tab_id"], meta={"url": url})
                raise
            try:
                self.store.claim(session, "browser_tab", tab["tab_id"], meta={"url": tab["url"]})
            except BaseException:
                self.browser.call("tab_close", {"owner": owner, "tab_id": tab["tab_id"]})
                raise
            return tab
        resource = self._browser_tab(session, args.get("tab_id"))
        tab_id = resource["key"]
        base = {"owner": owner, "tab_id": tab_id}
        try:
            if command == "close":
                try:
                    result = self.browser.call("tab_close", base)
                except HubError as exc:
                    if exc.code != "TAB_NOT_FOUND":
                        raise
                    raise HubError("TAB_CLEANUP_UNCONFIRMED", "the manager lost its page handle; physical closure cannot be verified",
                                   tab_id=tab_id, page_closed_in_browser=False, retry_safe=False,
                                   automatic_replay=False) from None
                if result.get("page_closed_in_browser") is False:
                    raise HubError("TAB_CLEANUP_UNCONFIRMED", "the manager cannot verify physical closure",
                                   tab_id=tab_id, page_closed_in_browser=False, retry_safe=False)
                self.store.release(session, resource_id=resource["resource_id"])
                return result
            if command == "restore":
                try:
                    tab = self.browser.call("tab_restore", base)
                except HubError as exc:
                    if exc.code != "TAB_NOT_FOUND":
                        raise
                    # A URL is neither proof of ownership nor proof the old tab was closed.
                    # Retain the durable record, and do not create a duplicate behind the owner.
                    raise HubError("TAB_RECOVERY_UNAVAILABLE", "the manager lost its page handle; automatic adoption or reopening is unsafe",
                                   tab_id=tab_id, last_url=resource["meta"].get("url"), retry_safe=False,
                                   automatic_replay=False, page_state_preserved=False) from None
                if tab["tab_id"] != tab_id:
                    self.store.claim(session, "browser_tab", tab["tab_id"], meta={"url": tab.get("url")})
                    self.store.release(session, resource_id=resource["resource_id"])
                elif tab.get("url") and tab["url"] != resource["meta"].get("url"):
                    self.store.update_resource_meta(resource["resource_id"], {**resource["meta"], "url": tab["url"]})
                return tab
            if command == "navigate":
                self._permit(session, "browser_own_tabs", {"host": urllib.parse.urlsplit(str(args.get("url") or "")).hostname or ""}, action="browser.navigate")
                result = self.browser.call("navigate", {**base, "url": args.get("url"), "timeout_ms": args.get("timeout_ms")})
            elif command in {"snapshot", "read", "wait_for", "screenshot"}:
                self._permit(session, "read_diagnose", action=f"browser.{command}")
                result = self.browser.call(command, {**base, **{key: args[key] for key in
                                                                ("target", "max_chars", "condition", "timeout_ms", "full_page") if key in args}})
            elif command == "act":
                foreground = args.get("foreground") is True
                self._permit(session, "foreground_input" if foreground else "browser_own_tabs",
                             {"host": urllib.parse.urlsplit(str(resource["meta"].get("url") or "")).hostname or ""},
                             action=f"browser.act.{args.get('action')}")
                result = self.browser.call("act", {**base, **{key: args[key] for key in
                                                              ("action", "target", "value", "key", "postcondition", "timeout_ms") if key in args},
                                                   "foreground": foreground,
                                                   "expected_host": urllib.parse.urlsplit(str(resource["meta"].get("url") or "")).hostname or ""})
            elif command == "evaluate":
                self._permit(session, "browser_script",
                             {"host": urllib.parse.urlsplit(str(resource["meta"].get("url") or "")).hostname or ""},
                             action="browser.evaluate")
                result = self.browser.call("evaluate", {**base, "expression": args.get("expression"),
                                                         "expected_host": urllib.parse.urlsplit(str(resource["meta"].get("url") or "")).hostname or ""})
            else:
                raise HubError("BROWSER_COMMAND_UNSUPPORTED", command=command,
                               commands=["status", "open", "list", "navigate", "snapshot", "read", "act", "wait_for",
                                         "screenshot", "evaluate", "restore", "close"])
        except HubError as exc:
            if exc.code == "TAB_NOT_FOUND":
                raise HubError("TAB_LOST", "the tab is gone (the browser manager or Chrome restarted); restore it explicitly",
                               tab_id=tab_id, last_url=resource["meta"].get("url"), next_step="browser restore", retry_safe=False) from None
            raise
        url = result.get("url_after") or result.get("url")
        if url and url != resource["meta"].get("url"):
            self.store.update_resource_meta(resource["resource_id"], {**resource["meta"], "url": url})
        return result

    # ---- owner Chrome Profile 1 hidden secondary target (browser-level loopback CDP) -----
    def _call_owner_chrome_secondary(self, op: str, args: dict | None = None, *, timeout: float = 30.0) -> dict:
        try:
            return self.owner_chrome_secondary.call(op, args or {}, timeout=timeout)
        except OwnerChromeSecondaryError as exc:
            raise HubError(exc.code, exc.message, **exc.details) from None

    def _owner_chrome_hidden(self, session: dict, args: dict) -> dict:
        """Primary owner-auth route: windowless hidden target in already-running Chrome Profile 1."""
        command = str(args.get("command") or "")
        if args.get("foreground") is True:
            raise HubError(
                "FOREGROUND_ROUTE_REQUIRED",
                "owner_chrome_hidden never falls back to foreground input; use the guarded Bridge desktop route",
                execution_started=False,
                retry_safe=False,
            )
        owner = self._owner(session)
        if command == "preflight":
            profile_name = args.get("profile_dir_name")
            payload = {"profile_dir_name": profile_name} if profile_name is not None else {}
            return self._call_owner_chrome_secondary("preflight", payload)
        if command == "status":
            st = self._call_owner_chrome_secondary("status", {})
            mine = [item["key"] for item in self.store.resources(session_id=session["session_id"], kind="owner_chrome_hidden_target")]
            return {**st, "my_targets": mine}
        if command == "list":
            mine = self.store.resources(session_id=session["session_id"], kind="owner_chrome_hidden_target")
            live = {item["tab_id"]: item for item in self._call_owner_chrome_secondary("list", {"owner": owner}).get("tabs", [])}
            return {
                "route": OWNER_CHROME_HIDDEN_ROUTE,
                "tabs": [
                    {
                        "tab_id": item["key"],
                        **(
                            live[item["key"]]
                            if item["key"] in live
                            else {"state": "lost", "url": item["meta"].get("url"), "target_id": item["meta"].get("target_id")}
                        ),
                    }
                    for item in mine
                ],
            }
        if command == "open":
            url = args.get("url")
            host = urllib.parse.urlsplit(str(url or "")).hostname or ""
            self._permit(session, "owner_chrome_hidden_secondary", {"host": host}, action="owner_chrome_hidden.open")
            open_payload = {
                "owner": owner,
                **{k: v for k, v in args.items() if k != "command"},
            }
            tab = self._call_owner_chrome_secondary("open", open_payload)
            tab_id = tab["tab_id"]
            try:
                self.store.claim(
                    session,
                    "owner_chrome_hidden_target",
                    tab_id,
                    meta={
                        "url": tab.get("url"),
                        "target_id": tab.get("target_id"),
                        "profile_dir_name": tab.get("profile_dir_name"),
                        "route": OWNER_CHROME_HIDDEN_ROUTE,
                    },
                )
            except BaseException:
                try:
                    self._call_owner_chrome_secondary("close", {"owner": owner, "tab_id": tab_id})
                except Exception:
                    pass
                raise
            self.route_affinity.record(
                session["agent_id"],
                session["task_id"],
                route=OWNER_CHROME_HIDDEN_ROUTE,
                tab_id=tab_id,
                target_id=tab.get("target_id"),
            )
            return tab

        raw_tab_id = args.get("tab_id") or args.get("target_id")
        if not isinstance(raw_tab_id, str) or not raw_tab_id:
            raise HubError("TAB_ID_REQUIRED", execution_started=False)
        resource = self.store.require_owned(session, "owner_chrome_hidden_target", raw_tab_id)
        tab_id = resource["key"]
        base = {"owner": owner, "tab_id": tab_id}
        if command == "close":
            result = self._call_owner_chrome_secondary("close", base)
            if result.get("closed") is False or result.get("target_closed_in_browser") is False:
                raise HubError(
                    "TARGET_CLEANUP_UNCONFIRMED",
                    "owner Chrome hidden target closure could not be verified",
                    tab_id=tab_id,
                    target_closed_in_browser=False,
                    retry_safe=False,
                )
            self.store.release(session, resource_id=resource["resource_id"])
            if not self.store.resources(session_id=session["session_id"], kind="owner_chrome_hidden_target"):
                self.route_affinity.clear(session["agent_id"], session["task_id"])
            return result
        if command == "screenshot":
            return self._call_owner_chrome_secondary("screenshot", base)
        host = urllib.parse.urlsplit(str(args.get("url") or resource["meta"].get("url") or "")).hostname or ""
        self._permit(session, "owner_chrome_hidden_secondary", {"host": host}, action=f"owner_chrome_hidden.{command}")
        if command == "evaluate":
            self._permit(session, "browser_script", {"host": host}, action="owner_chrome_hidden.evaluate")
        if command not in {"navigate", "observe", "read", "act", "evaluate"}:
            raise HubError(
                "OWNER_CHROME_HIDDEN_COMMAND_UNSUPPORTED",
                command=command,
                commands=["preflight", "status", "open", "list", "navigate", "observe", "read", "act", "evaluate", "screenshot", "close"],
                execution_started=False,
            )
        payload = {**base, **{k: v for k, v in args.items() if k not in {"command", "tab_id", "target_id"}}}
        result = self._call_owner_chrome_secondary(command, payload)
        new_url = result.get("url_after") or result.get("url")
        if isinstance(new_url, str) and new_url and new_url != resource["meta"].get("url"):
            self.store.update_resource_meta(resource["resource_id"], {**resource["meta"], "url": new_url})
        return result

    # ---- GUI applications on a private desktop -------------------------------------------
    def _hidden_session(self, session: dict, create: bool) -> Any:
        key = self._owner(session)
        with self._hidden_lock:
            hidden = self._hidden.get(key)
            if hidden is None and create:
                if len(self._hidden) >= MAX_HIDDEN_SESSIONS:
                    raise HubError("HIDDEN_SESSION_LIMIT", "too many private desktops are open", limit=MAX_HIDDEN_SESSIONS, retry_safe=True)
                if self._hidden_factory:
                    hidden = self._hidden_factory()
                else:
                    from cua_hidden_desktop import HiddenDesktopSession
                    hidden = HiddenDesktopSession(PACKAGE, allow_generic_launch=True)
                self._hidden[key] = hidden
            if hidden is None:
                raise HubError("APP_SESSION_NOT_FOUND", "this agent has no private desktop; app_open first")
            return hidden

    def _hidden_request(self, hidden: Any, payload: dict, timeout: float = 30) -> dict:
        try:
            return hidden.request(payload, timeout_s=timeout)
        except Exception as exc:  # HiddenDesktopError carries code/details
            code = getattr(exc, "code", None)
            if not code:
                raise
            details = {**getattr(exc, "details", {}), "retry_safe": False}
            if code == "HIDDEN_ACTION_OUTCOME_UNKNOWN":
                details.update(outcome_unknown=True, attempted=True)
            if getattr(hidden, "closed", False):
                for owner, value in list(self._hidden.items()):
                    if value is hidden:
                        self._hidden.pop(owner, None)
            raise HubError(code, None, **details) from None

    def _private_browser(self, session: dict, args: dict) -> dict:
        """Owned OS-private Chrome; effects are journaled by dispatch, including submit."""
        command = args.get("command")
        if command == "open":
            self._permit(session, "app_launch", {"app": "chrome.exe"}, action="private_browser.open")
            had_desktop_apps = any(not r["meta"].get("managed_browser") for r in self.store.resources(session_id=session["session_id"], kind="app_session"))
            hidden = self._hidden_session(session, create=True)
            launch_payload = {"command": "browser.launch", **{k: args[k] for k in PRIVATE_BROWSER_OPEN_ARGS if k in args}}
            window = self._hidden_request(hidden, launch_payload, timeout=60)
            browser_id = f"private-browser-{window['pid']}-{window['create_time']}"
            public_window = {key: value for key, value in window.items()
                             if key not in {"browser_ws_endpoint", "cdp_endpoint", "browser_ws_path", "cdp_port"}}
            try:
                self.store.claim(session, "app_session", browser_id, meta={**public_window, "private_browser": True})
            except BaseException:
                if not had_desktop_apps:
                    self._close_hidden(self._owner(session))
                raise
            return {"browser_id": browser_id, **public_window}
        resource = self.store.require_owned(session, "app_session", str(args.get("browser_id") or ""))
        if not resource["meta"].get("private_browser"):
            raise HubError("PRIVATE_BROWSER_NOT_OWNED", execution_started=False)
        hidden = self._hidden_session(session, create=False)
        if command == "close":
            others = [r for r in self.store.resources(session_id=session["session_id"], kind="app_session")
                      if r["key"] != resource["key"] and not r["meta"].get("managed_browser")]
            if others:
                raise HubError("PRIVATE_DESKTOP_HAS_OTHER_APPS", "close apps first, or session_close to cancel the whole task", execution_started=False)
            closed = self._close_hidden(self._owner(session))
            if not closed:
                raise HubError("PRIVATE_BROWSER_CLEANUP_FAILED", outcome_unknown=True, retry_safe=False)
            self.store.release(session, resource_id=resource["resource_id"])
            return {"closed": True, "browser_profile_cleanup": getattr(hidden, "browser_profile_cleanup", [])}
        self._permit(session, "browser_script" if command == "evaluate" else "browser_own_tabs", action="private_browser." + str(command))
        payload = {k: v for k, v in args.items() if k != "browser_id"}
        return self._hidden_request(hidden, {"command": "browser.rpc", "args": payload}, timeout=60)

    def _managed_browser(self, session: dict, args: dict) -> dict:
        """Managed isolated persistent Playwright browser with durable sticky affinity."""
        if args.get("foreground") is True:
            raise HubError("FOREGROUND_ROUTE_REQUIRED", "managed Playwright never falls back to foreground",
                           execution_started=False, retry_safe=False)
        command = str(args.get("command") or "")
        owner = self._owner(session)
        if command == "status":
            return (self.managed_browser.call("status") if getattr(self.managed_browser, "running", lambda: False)()
                    else {"connected": False, "started": False})
        if command == "open":
            host = urllib.parse.urlsplit(str(args.get("url") or "")).hostname or ""
            self._permit(session, "browser_own_tabs", {"host": host}, action="managed_browser.open")
            open_payload = {"owner": owner, **{k: args[k] for k in MANAGED_BROWSER_OPEN_ARGS if k in args}}
            res = self.managed_browser.call("open", open_payload)
            if not any(r["key"] == res["browser_id"] for r in self.store.resources(session_id=session["session_id"], kind="app_session")):
                meta = {
                    "managed_browser": True,
                    "url": res.get("url"),
                    "tab_id": res.get("tab_id"),
                    "target_id": res.get("target_id"),
                }
                for opt in ("persistent_profile", "profile_id", "profile_dir", "child_pid"):
                    if opt in res:
                        meta[opt] = res[opt]
                self.store.claim(session, "app_session", res["browser_id"], meta=meta)
            self.route_affinity.record(
                session["agent_id"],
                session["task_id"],
                route="persistent_playwright",
                browser_id=res["browser_id"],
                tab_id=res.get("tab_id"),
                target_id=res.get("target_id"),
            )
            return res
        resource = self.store.require_owned(session, "app_session", str(args.get("browser_id") or ""))
        if not resource["meta"].get("managed_browser"):
            raise HubError("MANAGED_BROWSER_NOT_OWNED", execution_started=False)
        if command == "close":
            res = self.managed_browser.call("close", {"owner": owner, "browser_id": resource["key"]})
            if (res.get("closed") is False or res.get("profile_cleanup_verified") is False
                    or res.get("child_exited") is False):
                raise HubError(
                    "MANAGED_BROWSER_CLEANUP_UNCONFIRMED",
                    "managed Playwright cleanup could not be verified",
                    browser_id=resource["key"],
                    retry_safe=False,
                    **{k: v for k, v in res.items() if k != "message"},
                )
            self.store.release(session, resource_id=resource["resource_id"])
            self.route_affinity.clear(session["agent_id"], session["task_id"])
            return res
        host = urllib.parse.urlsplit(str(args.get("url") or resource["meta"].get("url") or "")).hostname or ""
        self._permit(session, "browser_script" if command == "evaluate" else "browser_own_tabs",
                     {"host": host}, action=f"managed_browser.{command}")
        payload = {"owner": owner, "browser_id": resource["key"],
                   **{k: v for k, v in args.items() if k not in {"command", "browser_id"}}}
        res = self.managed_browser.call(command, payload)
        if command in {"navigate", "tab_open"}:
            self.route_affinity.record(
                session["agent_id"],
                session["task_id"],
                route="persistent_playwright",
                browser_id=resource["key"],
                tab_id=res.get("tab_id"),
                target_id=res.get("target_id"),
            )
        return res

    def _app(self, session: dict, op: str, args: dict) -> dict:
        if op == "app_discover":
            return apps.plan(str(args.get("app") or ""), catalog=self.app_catalog)
        if op == "app_open":
            query = str(args.get("app") or "")
            plan = apps.plan(query, catalog=self.app_catalog)
            app = plan["app"]
            if not app.get("found"):
                raise HubError("APP_NOT_FOUND", None, **{key: app.get(key) for key in ("query", "reason", "hint")})
            entry = self.app_catalog.get(query, verify_integrity=True)
            hidden_route = next(
                (item for item in plan["routes"]
                 if item["route"] in {"hidden_desktop_msix_alias", "hidden_desktop_electron_isolated", "hidden_desktop_uia"}
                 and item.get("launch_allowed", True) and item["status"] != "unsupported"),
                None,
            )
            if hidden_route is None:
                raise HubError("APP_BACKGROUND_ROUTE_UNSUPPORTED", "this program cannot run on a private desktop",
                               app=app["name"], kind=app["kind"], routes=plan["routes"])
            self._permit(session, "app_launch",
                         {"app": app["executable"], "aliases": [entry["app_id"]] if entry else []},
                         action="app_open")
            if app["kind"] == "office":
                mode = "office"
            elif app["kind"] == "msix_fulltrust_electron":
                mode = "msix_fulltrust_electron"
            elif hidden_route["route"] == "hidden_desktop_electron_isolated":
                mode = "editor_native" if app["kind"] == "electron_editor" and "document_path" in args else "electron_isolated"
            else:
                mode = "uia"
            disallowed = {
                "office": ("arguments", "working_directory", "window_timeout_s", "code_link"),
                "msix_fulltrust_electron": ("arguments", "working_directory", "document_path"),
                "editor_native": ("arguments", "working_directory", "code_link"),
                "electron_isolated": ("working_directory", "document_path", "code_link"),
                "uia": ("code_link", "document_path"),
            }[mode]
            if any(key in args for key in disallowed):
                raise HubError("APP_LAUNCH_OPTIONS_UNSUPPORTED", f"{mode} uses a fixed isolated launch route",
                               execution_started=False)
            if "window_timeout_s" in args:
                raw_timeout = args["window_timeout_s"]
                if type(raw_timeout) not in (int, float) or not math.isfinite(raw_timeout) or not 0.1 <= raw_timeout <= 60:
                    raise HubError("ARGS_INVALID", field="window_timeout_s", execution_started=False)
            editor_app = (entry.get("editor_app") if entry else None) or app.get("known")
            if mode == "office":
                office_app = {"excel.exe": "excel", "winword.exe": "word", "powerpnt.exe": "powerpoint"}[app["name"].lower()]
                payload = {"command": "launch_app", "app": office_app}
                if "document_path" in args:
                    payload["document_path"] = args["document_path"]
            elif mode == "msix_fulltrust_electron":
                payload = {"command": "launch_app", "app": "claude"}
                if "code_link" in args:
                    payload["code_link"] = args["code_link"]
            elif mode == "editor_native":
                payload = {"command": "editor.launch", "app": editor_app, "document_path": args["document_path"]}
            elif mode == "electron_isolated":
                payload = {"command": "launch_electron_isolated", "app": editor_app, "executable": app["executable"]}
                if entry and entry.get("sha256"):
                    payload["expected_executable_sha256"] = entry["sha256"]
                for key in ("arguments", "window_timeout_s"):
                    if key in args:
                        payload[key] = args[key]
            else:
                payload = {"command": "launch_exe", "executable": app["executable"]}
                for key in ("arguments", "working_directory", "window_timeout_s"):
                    if key in args:
                        payload[key] = args[key]
            hidden = self._hidden_session(session, create=True)
            timeout_arg = args.get("window_timeout_s", 25 if mode != "uia" else 15)
            request_timeout = min(max(float(timeout_arg), 1.0) + 10, 70)
            window = self._hidden_request(hidden, payload, timeout=request_timeout)
            if type(window.get("create_time")) is not int or window["create_time"] <= 0:
                raise HubError("APP_IDENTITY_UNAVAILABLE", "the private worker did not return process creation identity",
                               attempted=True, retry_safe=False)
            app_id = f"app-{window['pid']}-{window['create_time']}-{window['hwnd']}"
            self.store.claim(
                session,
                "app_session",
                app_id,
                meta={
                    "pid": window["pid"],
                    "hwnd": window["hwnd"],
                    "create_time": window["create_time"],
                    "executable": app["executable"],
                    "document_path": args.get("document_path"),
                    "editor_native": mode == "editor_native",
                    "catalog_app_id": entry["app_id"] if entry else app.get("known"),
                    "route": hidden_route["route"],
                },
            )
            return {**window, "app_id": app_id, "control_route": hidden_route["route"],
                    "route_status": hidden_route["status"], "route_note": hidden_route.get("note"),
                    "visible_to_owner": False}
        resource = self.store.require_owned(session, "app_session", str(args.get("app_id") or ""))
        if resource["meta"].get("managed_browser") or resource["meta"].get("private_browser"):
            raise HubError("APP_NOT_OWNED", execution_started=False)
        hidden = self._hidden_session(session, create=False)
        hwnd, pid = resource["meta"]["hwnd"], resource["meta"]["pid"]
        # An app_id is authority over one process incarnation, never every window on its
        # agent's desktop. The private worker rechecks the process token on actual use.
        windows = self._hidden_request(hidden, {"command": "describe_owned_windows"}).get("windows", [])
        mine = [item for item in windows if item.get("pid") == pid
                and item.get("create_time") == resource["meta"].get("create_time")]
        if op == "app_windows":
            return {"windows": mine}
        target_hwnd = args.get("hwnd", hwnd)
        if type(target_hwnd) is not int or not any(item.get("hwnd") == target_hwnd for item in mine):
            raise HubError("APP_WINDOW_NOT_OWNED", "window does not belong to this app process incarnation",
                           execution_started=False, retry_safe=False)
        if op == "app_observe":
            self._permit(session, "read_diagnose", action=op)
            return self._hidden_request(hidden, {"command": "ui_observe", "hwnd": args.get("hwnd", hwnd), "options": args.get("options") or {"max_items": 256}})
        if op == "app_find":
            self._permit(session, "read_diagnose", action=op)
            return self._hidden_request(hidden, {"command": "ui_find", "hwnd": args.get("hwnd", hwnd), "generation": args.get("generation"), "query": args.get("query")})
        if op == "app_act":
            self._permit(session, "own_resources", action=op)
            return self._hidden_request(hidden, {"command": "ui_act", "hwnd": args.get("hwnd", hwnd), "generation": args.get("generation"),
                                                 "ref": args.get("ref"), "operation": args.get("operation"),
                                                 "action_args": args.get("action_args"), "postcondition": args.get("postcondition")})
        if op == "app_capture":
            self._permit(session, "read_diagnose", action=op)
            return self._hidden_request(hidden, {"command": "capture_window", "hwnd": args.get("hwnd", hwnd)})
        if op == "app_document":
            self._permit(session, "own_resources", action=op)
            action = args.get("command")
            if action not in {"read", "replace", "save"}:
                raise HubError("APP_DOCUMENT_COMMAND_INVALID", execution_started=False)
            document = resource["meta"].get("document_path")
            if not document:
                raise HubError("APP_DOCUMENT_NOT_BOUND", execution_started=False)
            if resource["meta"].get("editor_native"):
                if action == "read":
                    return self._hidden_request(hidden, {"command": "editor.observe", "hwnd": target_hwnd}, timeout=60)
                if action == "replace":
                    return self._hidden_request(
                        hidden,
                        {
                            "command": "editor.replace_save",
                            "hwnd": target_hwnd,
                            **{k: args[k] for k in ("generation", "ref", "expected_text", "replacement_text") if k in args},
                        },
                        timeout=60,
                    )
                raise HubError("APP_DOCUMENT_COMMAND_INVALID", "editor.replace_save persists edits atomically",
                               execution_started=False)
            return self._hidden_request(
                hidden,
                {
                    "command": "document." + action,
                    "hwnd": target_hwnd,
                    "document_path": document,
                    **{k: args[k] for k in ("expected_text", "replacement_text", "slide_id", "shape_id", "shape_name") if k in args},
                },
                timeout=60,
            )
        if op == "app_close":
            result = self._hidden_request(hidden, {"command": "close_app", "pid": pid,
                                                   "create_time": resource["meta"].get("create_time")})
            self.store.release(session, resource_id=resource["resource_id"])
            if not [r for r in self.store.resources(session_id=session["session_id"], kind="app_session") if not r["meta"].get("managed_browser")]:
                self._close_hidden(self._owner(session))
            return result
        raise HubError("OP_UNSUPPORTED", op=op)

    def _close_hidden(self, owner: str) -> bool:
        with self._hidden_lock:
            hidden = self._hidden.pop(owner, None)
        if hidden is not None:
            try:
                hidden.close()
                cleanup = [*getattr(hidden, "browser_profile_cleanup", []), *getattr(hidden, "editor_profile_cleanup", [])]
                if not getattr(hidden, "job_cleanup_verified", True) or any(item.get("removed") is not True for item in cleanup):
                    return False
            except Exception:
                with self._hidden_lock:
                    self._hidden[owner] = hidden
                return False
        return True

    # ---- cleanup of what a finished session owned ----------------------------------------
    def _cleanup(self, session: dict, held: list[dict]) -> dict:
        owner = self._owner(session)
        report: dict[str, Any] = {
            "browser_tabs_closed": 0,
            "owner_chrome_hidden_targets_closed": 0,
            "app_sessions_closed": 0,
            "locks_released": 0,
            "errors": [],
        }
        report["errors"].extend(self.io.cleanup(held))
        held_secondary = [item for item in held if item["kind"] == "owner_chrome_hidden_target"]
        if held_secondary or getattr(self.owner_chrome_secondary, "running", lambda: False)():
            secondary_errors_before = len(report["errors"])
            if getattr(self.owner_chrome_secondary, "running", lambda: False)():
                try:
                    known_sec = {tab["tab_id"] for tab in self._call_owner_chrome_secondary("list", {"owner": owner}).get("tabs", [])}
                    missing_sec = [item["key"] for item in held_secondary if item["key"] not in known_sec]
                    if missing_sec:
                        report["errors"].append({
                            "kind": "owner_chrome_hidden_target",
                            "code": "TARGET_CLEANUP_UNCONFIRMED",
                            "tab_ids": missing_sec,
                        })
                    closed_sec = self._call_owner_chrome_secondary("close_owner", {"owner": owner, "forget_unconfirmed": False})
                    report["owner_chrome_hidden_targets_closed"] = int(closed_sec.get("closed") or 0)
                    if closed_sec.get("unconfirmed"):
                        report["errors"].append({
                            "kind": "owner_chrome_hidden_target",
                            "code": "TARGET_CLEANUP_UNCONFIRMED",
                            "tab_ids": list(closed_sec["unconfirmed"]),
                        })
                    for err in closed_sec.get("errors") or []:
                        entry = dict(err) if isinstance(err, dict) else {"code": str(err)}
                        report["errors"].append({"kind": "owner_chrome_hidden_target", **entry})
                except HubError as exc:
                    report["errors"].append({"kind": "owner_chrome_hidden_target", "code": exc.code})
            elif held_secondary:
                report["errors"].append({
                    "kind": "owner_chrome_hidden_target",
                    "code": "OWNER_CHROME_HIDDEN_SECONDARY_NOT_RUNNING",
                    "tab_ids": [item["key"] for item in held_secondary],
                })
            if held_secondary and len(report["errors"]) == secondary_errors_before:
                self.route_affinity.clear(session["agent_id"], session["task_id"])
        if getattr(self.browser, "running", lambda: True)():
            try:
                known = {tab["tab_id"] for tab in self.browser.call("tab_list", {"owner": owner})["tabs"]}
                missing = [item["key"] for item in held if item["kind"] == "browser_tab" and item["key"] not in known]
                if missing:
                    report["errors"].append({"kind": "browser_tab", "code": "TAB_CLEANUP_UNCONFIRMED", "tab_ids": missing})
                closed = self.browser.call("tab_close_owner", {"owner": owner, "forget_unconfirmed": False})
                report["browser_tabs_closed"] = int(closed.get("closed") or 0)
                if closed.get("unconfirmed"):
                    report["errors"].append({"kind": "browser_tab", "code": "TAB_CLEANUP_UNCONFIRMED",
                                             "tab_ids": closed["unconfirmed"]})
                for err in closed.get("errors") or []:
                    entry = dict(err) if isinstance(err, dict) else {"code": str(err)}
                    report["errors"].append({"kind": "browser_tab", **entry})
            except HubError as exc:
                report["errors"].append({"kind": "browser_tab", "code": exc.code})
        elif any(item["kind"] == "browser_tab" for item in held):
            report["errors"].append({
                "kind": "browser_tab",
                "code": "BROWSER_MANAGER_NOT_RUNNING",
                "tab_ids": [item["key"] for item in held if item["kind"] == "browser_tab"],
            })
        managed_apps = [item for item in held if item["kind"] == "app_session" and item["meta"].get("managed_browser")]
        if managed_apps:
            errors_before = len(report["errors"])
            if getattr(self.managed_browser, "running", lambda: False)():
                try:
                    closed_pw = self.managed_browser.call("close_owner", {"owner": owner})
                    report["app_sessions_closed"] += int(closed_pw.get("closed") or 0)
                    if closed_pw.get("preserved_profiles"):
                        report["preserved_profiles"] = list(closed_pw["preserved_profiles"])
                    if closed_pw.get("unconfirmed"):
                        report["errors"].append({
                            "kind": "managed_browser",
                            "code": "MANAGED_BROWSER_CLEANUP_UNCONFIRMED",
                            "browser_ids": list(closed_pw["unconfirmed"]),
                        })
                    for err in closed_pw.get("errors") or []:
                        entry = dict(err) if isinstance(err, dict) else {"code": str(err)}
                        report["errors"].append({"kind": "managed_browser", **entry})
                except HubError as exc:
                    report["errors"].append({"kind": "managed_browser", "code": exc.code})
            else:
                report["errors"].append({
                    "kind": "managed_browser",
                    "code": "MANAGED_BROWSER_NOT_RUNNING",
                    "browser_ids": [item["key"] for item in managed_apps],
                })
            if len(report["errors"]) == errors_before:
                self.route_affinity.clear(session["agent_id"], session["task_id"])
        # A launch may create an owned process before returning a window/app_id. Close the
        # private worker even if no app_session record could be materialized.
        desktop_apps = [item for item in held if item["kind"] == "app_session" and not item["meta"].get("managed_browser")]
        if owner in self._hidden:
            hidden = self._hidden[owner]
            if self._close_hidden(owner):
                owned_apps = [item for item in desktop_apps
                              if item["meta"].get("pid") and item["meta"].get("create_time")]
                identities = {(item["meta"]["pid"], item["meta"]["create_time"]) for item in owned_apps}
                deadline = time.monotonic() + 4
                pending = {identity for identity in identities if process_identity_matches(*identity)}
                while pending and time.monotonic() < deadline:
                    time.sleep(.05)
                    pending = {identity for identity in pending if process_identity_matches(*identity)}
                report["app_sessions_closed"] += sum((item["meta"]["pid"], item["meta"]["create_time"])
                                                     not in pending for item in owned_apps)
                if pending:
                    report["errors"].append({"kind": "app_session", "code": "OWNED_PROCESSES_STILL_RUNNING",
                                             "pids": sorted(pid for pid, _ in pending)})
            else:
                report["errors"].append({"kind": "app_session", "code": "HIDDEN_CLEANUP_FAILED"})
            report["profile_cleanup"] = [*getattr(hidden, "browser_profile_cleanup", []), *getattr(hidden, "editor_profile_cleanup", [])]
        elif desktop_apps:
            unconfirmed_apps: list[str] = []
            for item in desktop_apps:
                pid = item["meta"].get("pid")
                ctime = item["meta"].get("create_time")
                if type(pid) is int and pid > 0:
                    alive = (
                        process_identity_matches(pid, ctime)
                        if (os.name == "nt" and type(ctime) is int)
                        else _pid_alive(pid)
                    )
                    if alive:
                        unconfirmed_apps.append(item["key"])
                else:
                    unconfirmed_apps.append(item["key"])
            if unconfirmed_apps:
                report["errors"].append({
                    "kind": "app_session",
                    "code": "APP_SESSION_CLEANUP_UNCONFIRMED",
                    "app_ids": unconfirmed_apps,
                })
        try:
            removed = self.entry_artifacts.close(session["session_id"])
            if removed:
                report["task_files_removed"] = removed
        except (HubError, OSError):
            report["errors"].append({"kind": "task_file", "code": "ENTRY_FILE_CLEANUP_FAILED"})
        return report

    def _finish_cleanup(self, session: dict, held: list[dict], *, state: str = "closed") -> dict:
        # Two-phase cleanup: ownership survives both a crash during cleanup and
        # unconfirmed physical effects. Explicit token-based resume can adopt retained resources.
        report = self._cleanup(session, held)
        error_kinds = {err.get("kind") for err in report["errors"] if isinstance(err, dict)}
        retain_kinds = {kind for kind in error_kinds if kind in RESOURCE_KINDS and kind != "app_session"}
        retain_resource_ids: set[str] = set()
        if "managed_browser" in error_kinds:
            retain_resource_ids.update(
                item["resource_id"]
                for item in held
                if item["kind"] == "app_session" and item["meta"].get("managed_browser")
            )
        if "app_session" in error_kinds:
            retain_resource_ids.update(
                item["resource_id"]
                for item in held
                if item["kind"] == "app_session" and not item["meta"].get("managed_browser")
            )
        self.store.close_session(
            session["session_id"],
            state=state,
            retain_kinds=retain_kinds,
            retain_resource_ids=retain_resource_ids,
        )
        retained_rows = self.store.resources(session_id=session["session_id"])
        retained_ids = {row["resource_id"] for row in retained_rows}
        report["locks_released"] = sum(
            item["kind"] not in {"browser_tab", "owner_chrome_hidden_target", "app_session", "terminal"}
            and item["resource_id"] not in retained_ids
            for item in held
        )
        report["resources_retained"] = len(retained_rows)
        return report

    def _close_session(self, session: dict, *, audit_event: str = "session_close", state: str = "closed") -> dict:
        held = self.store.close_session(session["session_id"], state=state, retain_kinds=RESOURCE_KINDS)
        report = self._finish_cleanup(session, held, state=state)
        cleanup_verified = not report["errors"]
        self.store.audit(
            audit_event,
            agent_id=session["agent_id"],
            task_id=session["task_id"],
            session_id=session["session_id"],
            cleanup_verified=cleanup_verified,
            **report,
        )
        return {"closed": True, "cleanup_verified": cleanup_verified, **report}

    def maintain(self) -> dict:
        report = {"expired_sessions": 0}
        for session in self.store.active_entry_sessions():
            if self.entry_authority.active(session["entry_grant_id"]):
                continue
            with self._owner_gate(self._owner(session)):
                if not self.store.is_active_entry_session(session["session_id"]):
                    continue
                held = self.store.close_session(session["session_id"], state="expired", retain_kinds=RESOURCE_KINDS)
                cleanup = self._finish_cleanup(session, held, state="expired")
                self.store.audit("entry_grant_ended", agent_id=session["agent_id"], task_id=session["task_id"],
                                 session_id=session["session_id"], cleanup_verified=not cleanup["errors"], **cleanup)
                report["expired_sessions"] += 1
        for candidate in self.store.sessions():
            if candidate["idle_seconds"] <= self.store.session_ttl + self.store.orphan_ttl:
                continue
            with self._owner_gate(self._owner(candidate)):
                for item in self.store.expire_sessions(
                    session_id=candidate["session_id"],
                    retain_kinds=RESOURCE_KINDS,
                    state="expired",
                ):
                    report["expired_sessions"] += 1
                    cleanup = self._finish_cleanup(item, item["resources"], state="expired")
                    self.store.audit(
                        "session_expired_cleanup",
                        agent_id=item["agent_id"],
                        task_id=item["task_id"],
                        session_id=item["session_id"],
                        cleanup_verified=not cleanup["errors"],
                        **cleanup,
                    )
        return report

    def run_maintenance(self) -> None:
        last_compact = time.monotonic()
        while not self._stop.wait(self._maintain_interval):
            try:
                self.maintain()
                if time.monotonic() - last_compact > 3600:
                    self.store.maintain()
                    last_compact = time.monotonic()
            except Exception as exc:
                self.store.audit("maintenance_error", error=type(exc).__name__)

    def shutdown(self, *, close_tabs: bool | None = None) -> None:
        self._stop.set()
        closed_hidden_owners: set[str] = set()
        for owner in list(self._hidden):
            if self._close_hidden(owner):
                closed_hidden_owners.add(owner)
        if closed_hidden_owners:
            try:
                release_ids = [
                    item["resource_id"]
                    for item in self.store.resources(kind="app_session")
                    if not item["meta"].get("managed_browser")
                    and f"{item['agent_id']}\x1f{item['task_id']}" in closed_hidden_owners
                ]
                for item in self.store.release_resources_by_ids(release_ids):
                    self.store.audit("app_session_closed_on_hub_shutdown", agent_id=item["agent_id"],
                                     task_id=item["task_id"], session_id=item["session_id"], app_id=item["key"])
            except Exception:
                pass
        managed_was_running = bool(getattr(self.managed_browser, "running", lambda: False)())
        managed_stop = getattr(self.managed_browser, "stop", None)
        if managed_stop:
            managed_stop()
        if managed_was_running:
            try:
                managed_ids = [
                    item["resource_id"]
                    for item in self.store.resources(kind="app_session")
                    if item["meta"].get("managed_browser")
                ]
                for item in self.store.release_resources_by_ids(managed_ids):
                    self.store.audit("managed_browser_closed_on_hub_shutdown", agent_id=item["agent_id"],
                                     task_id=item["task_id"], session_id=item["session_id"], browser_id=item["key"])
            except Exception:
                pass
        browser_stop = getattr(self.browser, "stop", None)
        if browser_stop:
            try:
                held_tabs = self.store.resources(kind="browser_tab")
            except Exception:
                held_tabs = []
            # Keep SQLite and tab-ledger.json consistent: if browser_tab rows are still
            # held in SQLite when the Hub shuts down, detach handles without killing tabs.
            should_close_tabs = (not bool(held_tabs)) if close_tabs is None else bool(close_tabs)
            try:
                browser_stop(close_tabs=should_close_tabs)
            except TypeError:
                browser_stop()
        secondary_shutdown = getattr(self.owner_chrome_secondary, "shutdown", None)
        if secondary_shutdown:
            try:
                held_sec = self.store.resources(kind="owner_chrome_hidden_target")
            except Exception:
                held_sec = []
            should_close_sec = (not bool(held_sec)) if close_tabs is None else bool(close_tabs)
            try:
                secondary_shutdown(close_targets=should_close_sec)
            except TypeError:
                secondary_shutdown()

    # ---- discovery -----------------------------------------------------------------------
    def capabilities(self) -> dict:
        return {
            "schema": "ff-agent-hub-capabilities-v1", "hub_version": HUB_VERSION, "pid": os.getpid(),
            "agent_entry": {"schema": ENTRY_SCHEMA, "http_path": ENTRY_PATH, "bind": "loopback",
                            "auth": "locally-issued task-scoped bearer", "mcp_transport": "stdio"},
            "session_timeouts": {
                "session_ttl_seconds": self.store.session_ttl,
                "orphan_ttl_seconds": self.store.orphan_ttl,
                "maintain_interval_seconds": self._maintain_interval,
            },
            "browser_routes": {
                "primary_owner_auth": OWNER_CHROME_HIDDEN_ROUTE,
                "primary_owner_auth_op": "owner_chrome_hidden",
                "primary_owner_auth_requires_cdp_and_default_context": True,
                "optional_isolated_mode": "isolated_hidden_browser",
                "optional_isolated_ops": ["managed_browser", "private_browser"],
                "optional_isolated_satisfies_owner_auth": False,
                "owner_chrome_visible_tab_op": "browser",
                "owner_chrome_visible_tab_hidden_secondary_supported": False,
                "isolated_substitution_forbidden": True,
                "silent_playwright_fallback": False,
            },
            "purpose": "shared infrastructure for every agent on this PC: sessions, ownership, owner Chrome Profile 1 hidden secondary targets, "
                       "optional isolated hidden browsers, explicit visible-tab owner Chrome extension, private desktops for GUI apps, permissions, brokered secrets, recovery",
            "quickstart": [
                "session_open {agent_id, task_id} -> keep session_id, session_secret, resume_token",
                "send session_id and session_secret with every other call; any call is a heartbeat",
                "route_plan {surface:'browser', capability:'owner_profile_hidden'} -> primary owner Chrome Profile 1 hidden secondary target (owner_chrome_hidden, fail-closed if CDP/Profile 1 default context unavailable; NEVER silently substitutes isolated profile)",
                "optional isolated mode (no owner auth): managed_browser or private_browser; explicit visible-tab extension mode: browser",
                "app_discover {app} -> routes; app_open {app} -> app_id; app_observe / app_act; app_close",
                "give every mutating call a stable request_key; after a lost reply ask request_status, never repeat blindly",
                "PERMISSION_REQUIRED means: tell the owner once; do not look for another way round",
                "session_close (with stable request_key) when finished and verify cleanup_verified=true and resources_retained=0; recovery requires resume_token",
            ],
            "operations": {
                "capabilities": {"session": False}, "hub_status": {"session": False},
                "route_plan": {"session": False, "args": {"surface": "browser|app", "capability": "owner_profile_hidden|dom|extension_bridge|download?", "prefer": "str?", "profile_dir_name": "str?"}},
                "session_open": {"session": False, "args": {"agent_id": "str", "task_id": "str", "resume_token": "str?"}},
                "owner_chrome_hidden": {
                    "route": OWNER_CHROME_HIDDEN_ROUTE,
                    "primary_owner_auth": True,
                    "mutating": "open/navigate/act/evaluate/close",
                    "request_key_required": True,
                    "risk_class": "owner_chrome_hidden_secondary",
                    "commands": ["preflight", "status", "open", "list", "navigate", "observe", "read", "act", "evaluate", "screenshot", "close"],
                    "transport": "Chrome >=158 browser-level loopback CDP Target.createTarget({hidden:true}) inside already-running owner Chrome Profile 1; zero cookie copy; zero visible HWNDs/taskbar/tab-strip side effects; screenshot unsupported; fail-closed if CDP or Profile 1 defaultBrowserContextId unavailable",
                },
                "private_browser": {"mutating": "all except info/tabs/observe/read/screenshot/download_read", "request_key_required": True,
                    "optional_isolated_mode": True, "satisfies_owner_profile_auth": False,
                    "commands": ["open", "close", "tabs", "tab_open", "tab_close", "navigate", "observe", "read", "act", "upload", "download_prepare", "download_read", "screenshot", "evaluate"],
                    "optional_open_args": list(PRIVATE_BROWSER_OPEN_ARGS),
                    "transport": "optional isolated owned Chrome on private Windows Desktop; CDP broker; Hub durable receipts"},
                "managed_browser": {"mutating": "all except status/info/tabs/observe/snapshot/read/screenshot/download_read", "request_key_required": True,
                    "optional_isolated_mode": True, "satisfies_owner_profile_auth": False,
                    "commands": ["status", "open", "close", "info", "tabs", "tab_open", "tab_close", "navigate", "observe", "snapshot", "read", "act", "upload", "download_prepare", "download_read", "screenshot", "evaluate"],
                    "optional_open_args": list(MANAGED_BROWSER_OPEN_ARGS),
                    "transport": "optional isolated headless Playwright persistent context; named isolated profile; sticky task affinity; Hub durable receipts"},
                "app_document": {"commands": ["read", "replace", "save"], "document": "exact path bound at app_open", "mutating": "replace/save"},
                "session_heartbeat": {}, "session_status": {},
                "session_close": {"mutating": True, "durable_receipt_after_close": True,
                                  "returns": ["closed", "cleanup_verified", "resources_retained"]},
                "task_cancel": {"mutating": True, "durable_receipt_after_close": True}, "hub_shutdown_idle": {"session": False, "requires_idle": True},
                "resource_claim": {"mutating": True, "args": {"kind": sorted(RESOURCE_KINDS),
                                                              "key": "str", "mode": "exclusive|shared", "wait_seconds": "0..60"}},
                "resource_release": {"mutating": True}, "resource_list": {},
                "files": {"mutating": "write", "commands": ["read", "stat", "write"],
                          "args": {"path": "absolute path", "text": "UTF-8 string for write",
                                   "expected_sha256": "current hash or null to create"},
                          "locks": "exclusive canonical file lock until release/session_close; cooperative"},
                "terminal": {"mutating": "start/cancel", "commands": ["start", "status", "list", "cancel"],
                             "risk_class": "terminal_execute", "args": {"argv": "string[]; shell=false",
                             "cwd": "absolute directory", "timeout_seconds": "0.1..300", "terminal_id": "exact saved ID"},
                             "recovery": "supervisor survives Hub restart; poll exact ID, never relaunch",
                             "scope": "current user, no sandbox; argv/cwd grants do not confine interpreter effects"},
                "permission_check": {"args": {"risk_class": sorted(RISK_CLASSES), "target": "{path|app|host|secret}"}},
                "permission_describe": {},
                "secret_list": {}, "secret_use": {"mutating": True, "risk_class": "secret_use",
                                                   "args": {"name": "str", "use": "http|process", "request": "{...}"}},
                "browser": {"mutating": "open/navigate/act/evaluate/restore/close", "risk_class": "browser_own_tabs",
                            "explicit_owner_chrome_only": True,
                            "commands": ["status", "open", "list", "navigate", "snapshot", "read", "act", "wait_for",
                                         "screenshot", "evaluate", "restore", "close"],
                            "act": {"action": "click|fill|select|check|uncheck|press",
                                    "target": "{ref}|{selector}|{role,name}|{label}|{text}",
                                    "postcondition": "{url_contains}|{text_present}|{text_absent}|{target,value|checked|state}",
                                    "foreground": "unsupported here; use the existing guarded Bridge desktop route"}},
                "app_discover": {"args": {"app": "name or absolute path"}},
                "app_open": {"mutating": True, "risk_class": "app_launch"}, "app_windows": {}, "app_observe": {},
                "app_find": {}, "app_act": {"mutating": True}, "app_capture": {}, "app_close": {"mutating": True},
                "request_status": {"args": {"request_key": "str"}},
                "audit_read": {"args": {"limit": "1..1000"}, "scope": "own session agent_id/task_id only"},
            },
            "guarantees": {
                "isolated_hidden_default": "default browser automation runs in isolated headless Playwright or OS-private Chrome; "
                                           "never silently falls back to owner Chrome or direct visible Playwright",
                "owner_chrome": "the signed-in profile through the official Playwright extension only when explicitly selected; "
                                "no cookie or password access; no Chrome prompt is answered by software",
                "background": "agent tabs are created hidden and stay hidden; GUI apps run on a private Windows desktop; "
                              "the Hub never offers foreground input; use the guarded Bridge desktop route separately",
                "ownership": "a tab, app window or lock belongs to one agent/task; other agents get *_NOT_OWNED; "
                             "unconfirmed cleanup retains ownership fail-closed until verified",
                "recovery": "lost replies are reconciled through request_status; nothing is replayed automatically",
            },
            "limits": {
                "browser_background_connect": "requires running Chrome >=158.0.8127.2, extension >=0.5.0 and Playwright >=1.65.0; "
                                              "read-only probe: node ff_browser_hub.mjs --preflight; never falls back to foreground",
                "browser_manager_crash": "a durable ledger keeps owner and exact CDP target id of every agent tab; after a manager crash "
                                         "restore/close reattach the same physical tab only on an exact target-id match "
                                         "through the pinned extension relay; occupied foreign targets are never taken over. "
                                         "Without a match: TAB_RECOVERY_UNAVAILABLE / TAB_CLEANUP_UNCONFIRMED, no URL adoption, "
                                         "no duplicate reopening",
                "background_browser_input": "actions are DOM-level (untrusted events); sites that demand real pointer/keyboard "
                                            "input, drag-and-drop or canvas interaction need foreground",
                "background_tab_timers": "Chrome throttles timers and stops animation frames in hidden tabs",
                "gui_apps": "generic packaged (UWP/MSIX) apps cannot start on a private desktop; the only packaged exception is "
                            "the dedicated Claude Desktop alias route, refused while any Claude.exe already runs; "
                            "Chromium/Electron windows are only partly visible to UI Automation; single-instance apps hand "
                            "off to the owner's copy",
                "prompts": "UAC, CAPTCHA, MFA and Chrome/Windows consent dialogs are never answered; the agent stops and reports",
            },
            "permission_classes": {name: spec["about"] for name, spec in RISK_CLASSES.items()},
        }

    def status(self) -> dict:
        return {"hub_version": HUB_VERSION, "pid": os.getpid(), "uptime_seconds": round(time.time() - self.started_at, 1),
                "sessions": self.store.sessions(), "private_desktops": len(self._hidden),
                "browser_manager": {"running": getattr(self.browser, "running", lambda: None)(),
                                    "starts": getattr(self.browser, "starts", None)},
                "owner_chrome_secondary": {"running": getattr(self.owner_chrome_secondary, "running", lambda: False)(),
                                           "route": OWNER_CHROME_HIDDEN_ROUTE},
                "managed_browser": {"running": getattr(self.managed_browser, "running", lambda: None)(),
                                    "starts": getattr(self.managed_browser, "starts", None)},
                "pending_owner_requests": len(self.store.permission_requests()),
                "resources": self.store.resources(),
                "recovery": "resume saved session token; request_status by exact key; terminal status by exact ID"}

    # ---- dispatch ------------------------------------------------------------------------
    @contextmanager
    def _owner_gate(self, owner: str):
        # Resume/close cannot race a request that is still using the old session's objects.
        # This lock is per agent/task: unrelated agents retain concurrency.
        with self._gates_lock:
            entry = self._gates.setdefault(owner, [threading.RLock(), 0])
            entry[1] += 1
        try:
            with entry[0]:
                yield
        finally:
            with self._gates_lock:
                entry[1] -= 1
                if not entry[1]:
                    self._gates.pop(owner, None)

    def open_entry_session(self, scope: dict) -> dict:
        with self._owner_gate(self._owner(scope)), self._hidden_lock:
            if self._stopping:
                raise HubError("HUB_STOPPING", execution_started=False)
            if not self.entry_authority.active(scope["grant_id"]):
                raise HubError("ENTRY_UNAUTHORIZED", execution_started=False)
            supersede = False
            for existing in self.store.active_entry_sessions():
                if (existing["agent_id"], existing["task_id"]) != (scope["agent_id"], scope["task_id"]):
                    continue
                if existing["entry_grant_id"] == scope["grant_id"]:
                    break
                if self.entry_authority.active(existing["entry_grant_id"]):
                    raise HubError("SESSION_ACTIVE_ELSEWHERE", session_id=existing["session_id"], retry_safe=False)
                held = self.store.close_session(existing["session_id"], retain_kinds=RESOURCE_KINDS)
                cleanup = self._finish_cleanup(existing, held)
                self.store.audit("entry_grant_superseded", agent_id=existing["agent_id"], task_id=existing["task_id"],
                                 session_id=existing["session_id"], old_grant_id=existing["entry_grant_id"],
                                 new_grant_id=scope["grant_id"], cleanup_verified=not cleanup["errors"], **cleanup)
                supersede = True
            else:
                supersede = True
            session = self.store.open_session(scope["agent_id"], scope["task_id"],
                                              entry_grant_id=scope["grant_id"], entry_secret=scope["entry_secret"],
                                              supersede_inactive_entry=supersede)
            return {**session, **{key: scope[key] for key in ("client_id", "agent_id", "task_id", "expires_at")}}

    def dispatch(self, request: dict, *, check_access: Callable | None = None) -> dict:
        if not isinstance(request, dict):
            raise HubError("REQUEST_INVALID")
        op = request.get("op")
        raw_args = request.get("args")
        args = {} if raw_args is None else raw_args
        if not isinstance(op, str):
            raise HubError("OP_UNSUPPORTED", "unknown operation; read `capabilities`", op=op)
        if not isinstance(args, dict):
            raise HubError("ARGS_INVALID")
        if op in {"capabilities", "hub_status", "hub_shutdown_idle", "route_plan", "request_status", "session_status", "session_heartbeat",
                  "resource_list", "permission_check", "permission_describe", "secret_list", "audit_read", "app_discover"}:
            if check_access:
                check_access()
            return self._dispatch(request)
        if op == "session_open":
            if not isinstance(args.get("agent_id"), str) or not isinstance(args.get("task_id"), str):
                raise HubError("IDENTITY_INVALID")
            owner = self._owner(args)
        else:
            allow_closed = op in {"task_cancel", "request_status"} or (
                op == "session_close" and request.get("request_key") is not None
            )
            owner = self._owner(
                self.store.authenticate(
                    request.get("session_id"),
                    request.get("session_secret"),
                    allow_closed=allow_closed,
                    touch=False,
                )
            )
        with self._owner_gate(owner):
            if check_access:
                check_access()
            return self._dispatch(request, check_access=check_access)

    def _dispatch(self, request: dict, *, check_access: Callable | None = None) -> dict:
        if not isinstance(request, dict):
            raise HubError("REQUEST_INVALID")
        op = request.get("op")
        raw_args = request.get("args")
        args = {} if raw_args is None else raw_args
        if not isinstance(op, str):
            raise HubError("OP_UNSUPPORTED", "unknown operation; read `capabilities`", op=op)
        if not isinstance(args, dict):
            raise HubError("ARGS_INVALID")
        if op == "capabilities":
            return self.capabilities()
        if op == "hub_status":
            return self.status()
        if op == "route_plan":
            scope = {"agent_id": args.get("agent_id"), "task_id": args.get("task_id")}
            if request.get("session_id") and request.get("session_secret"):
                sess = self.store.authenticate(request.get("session_id"), request.get("session_secret"))
                scope = {"agent_id": sess["agent_id"], "task_id": sess["task_id"]}
            return live_route_plan(
                scope,
                surface=str(args.get("surface") or "browser"),
                hub=self,
                capability=str(args.get("capability") or "dom"),
                prefer=args.get("prefer"),
                profile_dir_name=str(args.get("profile_dir_name") or "Profile 1"),
            )
        if op == "hub_shutdown_idle":
            with self._hidden_lock:
                if self.store.sessions() or self._hidden:
                    raise HubError("HUB_BUSY", "cancel/finish owned tasks before stopping", retry_safe=False)
                callback = getattr(self, "_shutdown_request", None)
                if callback is None:
                    raise HubError("HUB_SHUTDOWN_UNAVAILABLE")
                self._stopping = True
                callback()
            return {"stopping": True, "idle_verified": True}
        if op == "session_open":
            with self._hidden_lock:
                if self._stopping:
                    raise HubError("HUB_STOPPING", execution_started=False)
                return self.store.open_session(args.get("agent_id"), args.get("task_id"),
                                               resume_token=args.get("resume_token"), note=args.get("note"))
        request_key = request.get("request_key")
        allow_closed = op in {"task_cancel", "request_status"} or (
            op == "session_close" and request_key is not None
        )
        session = self.store.authenticate(
            request.get("session_id"),
            request.get("session_secret"),
            allow_closed=allow_closed,
            touch=op not in {"task_cancel", "session_close"},
        )

        def journaled(run: Callable[[], dict]) -> dict:
            return self.store.journal_execute(session, request_key, op, args, run)

        if op == "task_cancel":
            return journaled(lambda: self._close_session(session, audit_event="task_cancel"))

        if op == "session_heartbeat":
            return {"ok": True, **session}
        if op == "session_status":
            return {**session, "resources": self.store.resources(session_id=session["session_id"])}
        if op == "session_close":
            # Legacy unkeyed close remains supported; keyed close is journaled and
            # safely deduplicated even after the session transitions to closed.
            return journaled(lambda: self._close_session(session)) if request_key is not None else self._close_session(session)
        if op == "resource_claim":
            kind = args.get("kind")
            if kind in {"browser_tab", "owner_chrome_hidden_target", "app_session", "terminal"}:
                raise HubError("RESOURCE_KIND_MANAGED", "tabs and app sessions are claimed by opening them")
            if kind in {"file", "directory"}:
                raw_key = args.get("key")
                if not isinstance(raw_key, str) or not raw_key.strip() or len(raw_key) > 1024:
                    raise HubError("RESOURCE_KEY_INVALID", execution_started=False)
                args = {**args, "key": os.path.normcase(os.path.realpath(os.path.abspath(raw_key)))}
            return journaled(lambda: self.store.claim(session, args.get("kind"), args.get("key"), mode=args.get("mode", "exclusive"),
                                                      meta=args.get("meta") if isinstance(args.get("meta"), dict) else None,
                                                      wait_seconds=args.get("wait_seconds", 0), check_access=check_access))
        if op == "resource_release":
            managed = {"browser_tab", "owner_chrome_hidden_target", "app_session", "terminal"}
            resource_id = args.get("resource_id")
            kind = args.get("kind")
            key = args.get("key")
            if resource_id is not None and not isinstance(resource_id, str):
                raise HubError("ARGS_INVALID", field="resource_id")
            if kind is not None and not isinstance(kind, str):
                raise HubError("ARGS_INVALID", field="kind")
            if key is not None and not isinstance(key, str):
                raise HubError("ARGS_INVALID", field="key")
            if kind in managed or (resource_id and any(
                    item["resource_id"] == resource_id and item["kind"] in managed
                    for item in self.store.resources(session_id=session["session_id"]))):
                raise HubError("RESOURCE_KIND_MANAGED", "close managed tabs/apps through their lifecycle operations")
            if kind in {"file", "directory"} and key:
                key = os.path.normcase(os.path.realpath(os.path.abspath(key)))

            def release() -> dict:
                return self.store.release(session, resource_id=resource_id, kind=kind, key=key)
            return journaled(release) if request_key is not None else release()
        if op == "resource_list":
            kind = args.get("kind")
            if kind is not None and not isinstance(kind, str):
                raise HubError("ARGS_INVALID", field="kind")
            return {"resources": self.store.resources(session_id=session["session_id"], kind=kind)}
        if op == "task_file":
            if not self.store.is_active_entry_session(session["session_id"]):
                raise HubError("ENTRY_SESSION_REQUIRED", execution_started=False)

            def artifact() -> dict:
                return self.entry_artifacts.call(session["session_id"], args)
            return journaled(artifact) if args.get("command") == "put" else artifact()
        if op == "permission_check":
            return self.policy.decide(session["agent_id"], str(args.get("risk_class") or ""),
                                      args.get("target") if isinstance(args.get("target"), dict) else None)
        if op == "permission_describe":
            return self.policy.describe()
        if op == "secret_list":
            return {"secrets": self.vault.list_for(session["agent_id"]), "values_readable": False}
        if op == "secret_use":
            name = args.get("name")
            target = {"secret": name}
            if args.get("use") == "http" and isinstance(args.get("request"), dict):
                target["host"] = urllib.parse.urlsplit(str(args["request"].get("url") or "")).hostname or ""
            elif args.get("use") == "process" and isinstance(args.get("request"), dict):
                argv = args["request"].get("argv")
                if isinstance(argv, list) and argv and isinstance(argv[0], str):
                    target["app"] = argv[0]

            def run() -> dict:
                self._permit(session, "secret_use", target, action=f"secret_use.{args.get('use')}")
                try:
                    if args.get("use") == "http":
                        out = self.vault.use_http(session["agent_id"], name, args.get("request"))
                    elif args.get("use") == "process":
                        out = self.vault.use_process(session["agent_id"], name, args.get("request"))
                    else:
                        raise HubError("SECRET_USE_INVALID", uses=["http", "process"], execution_started=False)
                except SecretError as exc:
                    raise HubError(exc.code, None, **exc.details) from None
                self.store.audit("secret_use", agent_id=session["agent_id"], task_id=session["task_id"],
                                 session_id=session["session_id"], secret=name, use=args.get("use"),
                                 status=out.get("status", out.get("exit_code")))
                return out
            return journaled(run)
        if op == "browser":
            if args.get("command") in {"open", "navigate", "act", "evaluate", "restore", "close"}:
                return journaled(lambda: self._browser(session, args))
            return self._browser(session, args)
        if op == "owner_chrome_hidden":
            if args.get("command") in {"open", "navigate", "act", "evaluate", "close"}:
                return journaled(lambda: self._owner_chrome_hidden(session, args))
            return self._owner_chrome_hidden(session, args)
        if op == "files":
            if args.get("command") == "write":
                return journaled(lambda: self.io.files(session, args))
            return self.io.files(session, args)
        if op == "terminal":
            if args.get("command") == "start":
                # Only admission/launch is serialized, never job execution.
                # Another owner must not see a resource before its initial
                # durable status exists or race the global admission limit.
                with self.io.launch_lock:
                    return journaled(lambda: self.io.terminal(session, args, request_key))
            if args.get("command") == "cancel":
                return journaled(lambda: self.io.terminal(session, args, request_key))
            return self.io.terminal(session, args)
        if op == "private_browser":
            from cua_private_browser import READ_COMMANDS
            if args.get("command") in READ_COMMANDS:
                return self._private_browser(session, args)
            return journaled(lambda: self._private_browser(session, args))
        if op == "managed_browser":
            if args.get("command") in {"status", "info", "tabs", "observe", "snapshot", "read", "download_read", "screenshot"}:
                return self._managed_browser(session, args)
            return journaled(lambda: self._managed_browser(session, args))
        if op == "app_document":
            if args.get("command") == "read":
                return self._app(session, op, args)
            return journaled(lambda: self._app(session, op, args))
        if op in {"app_open", "app_act", "app_close"}:
            return journaled(lambda: self._app(session, op, args))
        if op in {"app_discover", "app_windows", "app_observe", "app_find", "app_capture"}:
            return self._app(session, op, args)
        if op == "request_status":
            return self.store.journal_status(session, str(args.get("request_key") or ""))
        if op == "audit_read":
            requested_task = args.get("task_id")
            if requested_task is not None:
                if not isinstance(requested_task, str):
                    raise HubError("ARGS_INVALID", field="task_id", execution_started=False)
                if requested_task != session["task_id"]:
                    raise HubError("RESOURCE_NOT_OWNED", "audit_read is scoped to the active session's own task",
                                   kind="audit", execution_started=False)
            return {"records": self.store.read_audit(agent_id=session["agent_id"], task_id=session["task_id"],
                                                     limit=args.get("limit", 100))}
        raise HubError("OP_UNSUPPORTED", "unknown operation; read `capabilities`", op=op)


# ---- HTTP server -------------------------------------------------------------------------
def make_handler(hub: Hub, key: str) -> type:
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args: Any) -> None:
            return

        def _reply(self, status: int, body: dict) -> None:
            data = json.dumps(body, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                hub.store.audit("client_disconnected", reply_committed=True)

        def do_POST(self) -> None:
            external = self.path == ENTRY_PATH
            if external and self.headers.get("Origin") is not None:
                self.close_connection = True
                return self._reply(403, {"ok": False, "error_code": "ENTRY_ORIGIN_DENIED"})
            if external and self.headers.get("Host") not in {"127.0.0.1", f"127.0.0.1:{self.server.server_port}"}:
                self.close_connection = True
                return self._reply(403, {"ok": False, "error_code": "ENTRY_HOST_DENIED"})
            if not external and not hmac.compare_digest(self.headers.get("X-FF-Hub-Key", "").encode("utf-8"), key.encode("utf-8")):
                self.close_connection = True
                return self._reply(401, {"ok": False, "error_code": "UNAUTHORIZED"})
            if not external and self.path != "/rpc":
                self.close_connection = True
                return self._reply(404, {"ok": False, "error_code": "NOT_FOUND"})
            if external:
                self.connection.settimeout(15)
                if self.headers.get_content_type() != "application/json" or self.headers.get("Transfer-Encoding"):
                    self.close_connection = True
                    return self._reply(415, {"ok": False, "error_code": "ENTRY_CONTENT_TYPE_INVALID"})
                if not self.headers.get("Authorization", "").startswith("Bearer "):
                    self.close_connection = True
                    return self._reply(401, {"ok": False, "error_code": "ENTRY_UNAUTHORIZED"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_REQUEST_BYTES:
                    raise ValueError
                data = self.rfile.read(length)
                if len(data) != length:
                    raise ValueError
                request = json.loads(data)
            except (ValueError, TimeoutError):
                self.close_connection = True
                return self._reply(400, {"ok": False, "error_code": "REQUEST_INVALID"})
            started = time.monotonic()
            status = 200
            try:
                if external:
                    result = entry_call(hub, hub.entry_authority, self.headers.get("Authorization", ""), request)
                else:
                    result = hub.dispatch(request)
                body = {"ok": True, "result": result}
            except HubError as exc:
                if exc.code == "ENTRY_UNAUTHORIZED":
                    status = 401
                body = {"ok": False, "error_code": exc.code, "message": exc.message, "details": exc.details}
            except PermissionError_ as exc:
                body = {"ok": False, "error_code": exc.code, "message": exc.code, "details": exc.details}
            except Exception as exc:
                # Exception strings can include request headers or secret-bearing URLs.
                try:
                    hub.store.audit("internal_error", op=str(request.get("op")) if isinstance(request, dict) else None,
                                    error=type(exc).__name__)
                except Exception:
                    pass
                body = {"ok": False, "error_code": "HUB_INTERNAL_ERROR", "message": type(exc).__name__,
                        "details": {"retry_safe": False}}
            body["duration_ms"] = int((time.monotonic() - started) * 1000)
            self._reply(status, body)

    return Handler


class HubClient:
    """Finds the running Hub through its endpoint file and calls it. Keeps the session for you."""

    def __init__(self, state_dir: str | Path | None = None, *, timeout: float = 180.0):
        self.state_dir = Path(state_dir) if state_dir else default_state_dir()
        self.timeout = timeout
        self.session: dict | None = None

    def endpoint(self) -> dict:
        try:
            data = json.loads((self.state_dir / "endpoint.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise HubError("HUB_NOT_RUNNING", "no Hub endpoint file", state_dir=str(self.state_dir)) from None
        if not isinstance(data, dict) or type(data.get("pid")) is not int or type(data.get("port")) is not int or not 0 < data["port"] <= 65535:
            raise HubError("HUB_ENDPOINT_INVALID", "the Hub endpoint record is invalid")
        alive = (process_identity_matches(data["pid"], data.get("create_time")) if os.name == "nt"
                 else _pid_alive(data["pid"]))
        if not alive:
            raise HubError("HUB_NOT_RUNNING", "the recorded Hub process is gone", pid=data.get("pid"))
        return data

    @staticmethod
    def validate_reply(reply: Any) -> dict:
        if (not isinstance(reply, dict) or type(reply.get("ok")) is not bool
                or (reply["ok"] and not isinstance(reply.get("result"), dict))
                or (not reply["ok"] and (not isinstance(reply.get("error_code"), str)
                                        or not isinstance(reply.get("details", {}), dict)))):
            raise HubError("HUB_REPLY_INVALID", retry_safe=False, automatic_replay=False)
        return reply

    def raw(self, request: dict) -> dict:
        endpoint = self.endpoint()
        try:
            key = (self.state_dir / "hub.key").read_text(encoding="ascii").strip()
        except OSError as exc:
            raise HubError("HUB_NOT_RUNNING", "Hub key file is unavailable", cause=type(exc).__name__) from None
        prepared = urllib.request.Request(f"http://127.0.0.1:{endpoint['port']}/rpc", method="POST",
                                          data=json.dumps(request).encode("utf-8"),
                                          headers={"Content-Type": "application/json", "X-FF-Hub-Key": key})
        try:
            with _loopback_opener().open(prepared, timeout=self.timeout) as response:
                reply = response.read(MAX_REQUEST_BYTES + 1)
        except urllib.error.HTTPError as exc:
            try:
                reply = exc.read(MAX_REQUEST_BYTES + 1)
            except OSError as read_exc:
                raise HubError("HUB_UNREACHABLE", "malformed HTTP error reply from the Hub; the request may have run",
                               status=exc.code, cause=type(read_exc).__name__, retry_safe=False) from None
        except (urllib.error.URLError, OSError, http.client.HTTPException) as exc:
            raise HubError("HUB_UNREACHABLE", "no reply from the Hub; the request may have run",
                           cause=type(exc).__name__, retry_safe=False) from None
        try:
            if len(reply) > MAX_REQUEST_BYTES:
                raise ValueError("oversized")
            return self.validate_reply(json.loads(reply))
        except (ValueError, UnicodeError, RecursionError):
            raise HubError("HUB_REPLY_INVALID", retry_safe=False, automatic_replay=False) from None

    def call(self, op: str, args: dict | None = None, *, request_key: str | None = None) -> dict:
        request: dict[str, Any] = {"op": op, "args": args or {}}
        if self.session:
            request.update(session_id=self.session["session_id"], session_secret=self.session["session_secret"])
        if request_key:
            request["request_key"] = request_key
        reply = self.raw(request)
        if not reply.get("ok"):
            raise HubError(reply.get("error_code") or "HUB_ERROR", reply.get("message"), **(reply.get("details") or {}))
        if op == "session_open":
            self.session = reply["result"]
        return reply["result"]


class _HubLease:
    """An exclusive OS file lock for the full server lifetime; crashes release it.

    Checking an endpoint before spawning is insufficient when two Bridge processes start
    simultaneously. Never unlink this lock file: its inode is the shared lock identity.
    """
    def __init__(self, state_dir: Path):
        self.path = state_dir / "server.lock"
        self.file = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(self.path, "a+b", buffering=0)
        try:
            if os.name == "nt":
                import msvcrt
                self.file.seek(0)
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.file.close()
            self.file = None
            raise HubError("HUB_ALREADY_RUNNING") from None
        return self

    def __exit__(self, *_):
        if self.file is not None:
            try:
                if os.name == "nt":
                    import msvcrt
                    self.file.seek(0)
                    msvcrt.locking(self.file.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
            finally:
                self.file.close()


def serve(state_dir: Path, port: int) -> int:
    try:
        with _HubLease(state_dir):
            return _serve_locked(state_dir, port)
    except HubError as exc:
        if exc.code != "HUB_ALREADY_RUNNING":
            raise
        print("HUB_ALREADY_RUNNING", file=sys.stderr)
        return 3


def _serve_locked(state_dir: Path, port: int) -> int:
    state_dir.mkdir(parents=True, exist_ok=True)
    endpoint_file, key_file = state_dir / "endpoint.json", state_dir / "hub.key"
    try:
        HubClient(state_dir, timeout=3).raw({"op": "hub_status"})
        print("HUB_ALREADY_RUNNING", file=sys.stderr)
        return 3
    except (HubError, OSError, ValueError):
        pass
    if not key_file.is_file():
        temporary = key_file.with_suffix(".tmp")
        temporary.write_text(_secrets.token_urlsafe(48), encoding="ascii")
        os.replace(temporary, key_file)
    key = key_file.read_text(encoding="ascii").strip()
    hub = Hub(state_dir)
    server = HubHTTPServer(("127.0.0.1", port), make_handler(hub, key))
    server.daemon_threads = True
    hub._shutdown_request = lambda: threading.Thread(target=server.shutdown, daemon=True).start()
    record = {"version": HUB_VERSION, "pid": os.getpid(), "create_time": process_creation_token(os.getpid()),
              "port": server.server_address[1], "started_at": time.time(),
              "package": str(PACKAGE)}
    temporary = endpoint_file.with_suffix(".tmp")
    temporary.write_text(json.dumps(record), encoding="utf-8")
    os.replace(temporary, endpoint_file)
    hub.store.audit("hub_start", port=record["port"], boot_id=hub.store.boot_id)
    threading.Thread(target=hub.run_maintenance, daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        hub.shutdown()
        try:
            hub.store.close()
        except Exception:
            pass
        try:
            if json.loads(endpoint_file.read_text(encoding="utf-8")).get("pid") == os.getpid():
                endpoint_file.unlink()
        except (OSError, ValueError):
            pass
    return 0


class HubHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt":
            # Winsock SO_REUSEADDR allows an unrelated Hub to share a live port.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


def ensure_running(state_dir: Path | None = None, *, python: str | None = None, wait_seconds: float = 20.0) -> dict:
    """Start the Hub if it is not running. Safe to call from several Bridge instances at once."""
    state_dir = Path(state_dir) if state_dir else default_state_dir()
    client = HubClient(state_dir, timeout=5)

    def ready():
        endpoint = client.endpoint()
        status = client.call("hub_status")
        if status.get("pid") != endpoint["pid"]:
            raise HubError("HUB_ENDPOINT_IDENTITY_MISMATCH")
        return endpoint

    try:
        return ready()
    except HubError:
        pass
    state_dir.mkdir(parents=True, exist_ok=True)
    with open(state_dir / "hub.log", "ab", buffering=0) as log:
        if log.tell() > 2 * 1024 * 1024:
            log.truncate(0)
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        argv = [python or sys.executable, str(PACKAGE / "ff_hub.py"), "serve", "--state-dir", str(state_dir)]
        options = dict(stdin=subprocess.DEVNULL, stdout=log, stderr=log, cwd=str(PACKAGE), close_fds=True)
        try:
            # Leave the starter's job object so the Hub outlives a Bridge restart (CREATE_BREAKAWAY_FROM_JOB).
            subprocess.Popen(argv, creationflags=flags | 0x01000000, **options)
        except OSError:
            # The job forbids breakaway: the Hub still runs, but ends with its starter; state is on disk either way.
            subprocess.Popen(argv, creationflags=flags, **options)
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        try:
            return ready()
        except HubError:
            time.sleep(0.1)
    raise HubError("HUB_START_FAILED", "the Hub did not start", log=str(state_dir / "hub.log"), retry_safe=True)


# ---- owner CLI ---------------------------------------------------------------------------
def _ttl(text: str | None) -> float | None:
    if not text:
        return None
    unit = {"m": 60, "h": 3600, "d": 86400}.get(text[-1].lower())
    if unit is None:
        raise SystemExit("ttl looks like 30m, 8h or 30d")
    return float(text[:-1]) * unit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ff_hub.py", description=__doc__.split("\n\n")[0])
    parser.add_argument("--state-dir", type=Path, default=None)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("serve")
    run.add_argument("--port", type=int, default=None)
    run.add_argument("--state-dir", type=Path, default=None, dest="serve_state_dir")
    commands.add_parser("status")
    commands.add_parser("policy")
    commands.add_parser("requests")
    approve = commands.add_parser("approve", help="turn a pending agent request into a standing grant")
    approve.add_argument("request_id")
    approve.add_argument("--ttl", default="30d")
    approve.add_argument("--all-agents", action="store_true")
    grant = commands.add_parser("grant").add_subparsers(dest="grant_command", required=True)
    add = grant.add_parser("add")
    add.add_argument("--classes", required=True, help="comma separated")
    for name in ("agents", "paths", "apps", "hosts", "secrets"):
        add.add_argument(f"--{name}", default="")
    add.add_argument("--ttl", default=None)
    add.add_argument("--note", default="")
    grant.add_parser("list")
    grant.add_parser("revoke").add_argument("grant_id")
    default = commands.add_parser("default")
    default.add_argument("risk_class")
    default.add_argument("decision", choices=["allow", "ask"])
    secret = commands.add_parser("secret").add_subparsers(dest="secret_command", required=True)
    put = secret.add_parser("put", help="the value is read from standard input, never from the command line")
    put.add_argument("name")
    put.add_argument("--agents", required=True)
    put.add_argument("--hosts", default="")
    put.add_argument("--commands", default="")
    put.add_argument("--windows-credential", default=None)
    put.add_argument("--note", default="")
    secret.add_parser("revoke").add_argument("name")
    catalog = commands.add_parser("catalog").add_subparsers(dest="catalog_command", required=True)
    catalog.add_parser("list")
    cat_enroll = catalog.add_parser("enroll")
    cat_enroll.add_argument("--app-id", required=True)
    cat_enroll.add_argument("--exe", required=True)
    cat_enroll.add_argument("--aumid", default=None)
    cat_enroll.add_argument("--allow-electron", action="store_true")
    cat_enroll.add_argument("--require-signed", action="store_true")
    cat_enroll.add_argument("--note", default="")
    catalog.add_parser("revoke").add_argument("--app-id", required=True)
    options = parser.parse_args(argv)
    state_dir = getattr(options, "serve_state_dir", None) or options.state_dir or default_state_dir()
    split = lambda text: [item.strip() for item in text.split(",") if item.strip()]
    show = lambda value: print(json.dumps(value, ensure_ascii=False, indent=2, default=str))

    if options.command == "serve":
        config_port = None
        try:
            config_port = json.loads((state_dir / "config.json").read_text(encoding="utf-8")).get("port")
        except (OSError, ValueError):
            pass
        return serve(state_dir, options.port if options.port is not None else
                     (config_port if config_port is not None else DEFAULT_PORT))
    policy, store_path = Policy(state_dir / "policy.json"), state_dir / "hub.db"
    try:
        if options.command == "status":
            show(HubClient(state_dir, timeout=5).call("hub_status"))
        elif options.command == "policy":
            show(policy.describe())
        elif options.command == "requests":
            show(HubStore(store_path).permission_requests())
        elif options.command == "approve":
            store = HubStore(store_path)
            pending = next((item for item in store.permission_requests() if item["request_id"] == options.request_id), None)
            if pending is None:
                raise SystemExit("no such pending request")
            target = pending["target"]
            show(policy.add_grant([pending["risk_class"]], agents=None if options.all_agents else [pending["agent_id"]],
                                  paths=[target["path"]] if target.get("path") else None,
                                  apps=[os.path.basename(target["app"]).lower()] if target.get("app") else None,
                                  hosts=[target["host"]] if target.get("host") else None,
                                  secrets=[target["secret"]] if target.get("secret") else None,
                                  ttl_seconds=_ttl(options.ttl), note=f"approved request {options.request_id}"))
            store.resolve_permission_request(options.request_id, "approved")
        elif options.command == "grant":
            if options.grant_command == "add":
                show(policy.add_grant(split(options.classes), agents=split(options.agents) or None, paths=split(options.paths) or None,
                                      apps=split(options.apps) or None, hosts=split(options.hosts) or None,
                                      secrets=split(options.secrets) or None, ttl_seconds=_ttl(options.ttl), note=options.note))
            elif options.grant_command == "list":
                show(policy.describe()["grants"])
            else:
                show({"revoked": policy.revoke(options.grant_id)})
        elif options.command == "default":
            policy.set_default(options.risk_class, options.decision)
            show(policy.describe()["classes"][options.risk_class])
        elif options.command == "secret":
            vault = Vault(state_dir / "vault")
            if options.secret_command == "put":
                value = None if options.windows_credential else sys.stdin.readline().rstrip("\r\n")
                show(vault.put(options.name, value, agents=split(options.agents), hosts=split(options.hosts) or None,
                               commands=split(options.commands) or None, windows_credential=options.windows_credential,
                               note=options.note))
            else:
                show({"revoked": vault.revoke(options.name)})
        elif options.command == "catalog":
            from ff_app_catalog import AppCatalog
            cat = AppCatalog(state_dir)
            if options.catalog_command == "list":
                show(cat.list_apps())
            elif options.catalog_command == "enroll":
                show(cat.enroll(
                    app_id=options.app_id,
                    executable=options.exe,
                    aumid=options.aumid,
                    allow_electron=options.allow_electron,
                    require_signed=options.require_signed,
                    note=options.note,
                ))
            else:
                show({"revoked": cat.revoke(options.app_id)})
    except (HubError, PermissionError_, SecretError) as exc:
        show({"error": exc.code, **getattr(exc, "details", {})})
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
