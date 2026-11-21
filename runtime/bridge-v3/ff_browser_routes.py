"""Live-probed browser and application route planner with strict isolated-first separation."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

try:
    import winreg
except ImportError:  # non-Windows test hosts
    winreg = None  # type: ignore[assignment]

import ff_hub_apps as apps
from ff_hub_store import HubError

PACKAGE = Path(__file__).resolve().parent

ISOLATED_BROWSER_ROUTES = ("persistent_playwright", "private_cdp")
OWNER_CHROME_ROUTE = "owner_chrome_extension"

KNOWN_EXTENSION_IDS = {
    "mmlmfjhmonkocbjadbfplnigmagldckm": "playwright_mcp",
    "fcoeoabgfenejglbffodgkkbkcdhcgfn": "claude_in_chrome",
    "hehggadaopoacecdllhhajmbjkdcmajg": "chatgpt_extension",
    "mmhkecdcdceeibbhalmfhjleeebgdbhk": "ff_browser_companion",
}


class RouteAffinityStore:
    """Thread-safe sticky (agent_id, task_id) target affinity ledger."""

    def __init__(self, state_dir: Path | None = None):
        self._path = (Path(state_dir) / "route-affinity.json") if state_dir else None
        self._lock = threading.RLock()
        self._records: dict[str, dict[str, Any]] = self._load()

    def _key(self, agent_id: str, task_id: str) -> str:
        return f"{agent_id}\x1f{task_id}"

    def _load(self) -> dict[str, dict[str, Any]]:
        if self._path is None or not self._path.is_file():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self) -> None:
        if self._path is None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_name(f".{self._path.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(self._records, sort_keys=True, indent=2), encoding="utf-8")
        os.replace(tmp, self._path)

    def get(self, agent_id: str, task_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self._records.get(self._key(agent_id, task_id))
            return dict(item) if item else None

    def record(
        self,
        agent_id: str,
        task_id: str,
        *,
        route: str,
        browser_id: str | None = None,
        tab_id: str | None = None,
        target_id: str | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            entry = {
                "agent_id": agent_id,
                "task_id": task_id,
                "route": route,
                "browser_id": browser_id,
                "tab_id": tab_id,
                "target_id": target_id,
                "updated_at": time.time(),
            }
            self._records[self._key(agent_id, task_id)] = entry
            self._save()
            return dict(entry)

    def clear(self, agent_id: str, task_id: str) -> None:
        with self._lock:
            if self._records.pop(self._key(agent_id, task_id), None) is not None:
                self._save()


def _resolve_playwright_root(hub: Any = None, playwright_root: str | Path | None = None) -> str:
    if playwright_root:
        return str(playwright_root)
    managed = getattr(hub, "managed_browser", None) if hub else None
    if managed and getattr(managed, "playwright_root", None):
        return str(managed.playwright_root)
    browser = getattr(hub, "browser", None) if hub else None
    if browser and getattr(browser, "playwright_root", None):
        return str(browser.playwright_root)
    env_root = os.environ.get("FF_PLAYWRIGHT_ROOT")
    if env_root:
        return env_root
    return str(PACKAGE)


def probe_playwright(
    playwright_root: str | Path | None = None,
    *,
    hub: Any = None,
    timeout_s: float = 4.0,
) -> dict[str, Any]:
    """Probe persistent Playwright + Chromium readiness on this host."""
    t0 = time.monotonic()
    resolved_root = _resolve_playwright_root(hub=hub, playwright_root=playwright_root)
    script = PACKAGE / "ff_playwright_managed.mjs"
    if not script.is_file():
        return {"ok": False, "reason": "PLAYWRIGHT_MANAGED_SCRIPT_MISSING", "probe_ms": 0}
    managed = getattr(hub, "managed_browser", None) if hub else None
    if managed and getattr(managed, "running", lambda: False)():
        try:
            st = managed.call("status", timeout=timeout_s)
            if st.get("connected"):
                return {
                    "ok": True,
                    "running": True,
                    "playwright_version": st.get("playwright_version"),
                    "playwright_root": resolved_root,
                    "probe_ms": int((time.monotonic() - t0) * 1000),
                }
        except HubError:
            pass
    node = shutil.which("node")
    if not node:
        return {
            "ok": False,
            "running": False,
            "reason": "NODE_NOT_INSTALLED",
            "probe_ms": int((time.monotonic() - t0) * 1000),
        }
    if not (
        (Path(resolved_root) / "node_modules" / "playwright").is_dir()
        or (PACKAGE / "node_modules" / "playwright").is_dir()
    ):
        return {
            "ok": False,
            "running": False,
            "reason": "PLAYWRIGHT_NODE_MODULES_NOT_PRESENT",
            "playwright_root": resolved_root,
            "probe_ms": int((time.monotonic() - t0) * 1000),
        }
    try:
        proc = subprocess.run(
            [node, str(script), "--preflight", "--playwright-root", resolved_root],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        data = json.loads((proc.stdout or "{}").strip().splitlines()[-1]) if (proc.stdout or "").strip() else {}
        return {
            "ok": proc.returncode == 0 and bool(data.get("ok")),
            "running": False,
            "playwright_version": data.get("playwright_version"),
            "chromium_exists": data.get("chromium_exists"),
            "reason": data.get("error_code") or (None if proc.returncode == 0 else "PLAYWRIGHT_UNAVAILABLE"),
            "playwright_root": resolved_root,
            "probe_ms": int((time.monotonic() - t0) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "running": False,
            "reason": type(exc).__name__,
            "playwright_root": resolved_root,
            "probe_ms": int((time.monotonic() - t0) * 1000),
        }


def probe_owner_chrome(
    *,
    hub: Any = None,
    playwright_root: str | Path | None = None,
    timeout_s: float = 2.5,
) -> dict[str, Any]:
    """Read-only probe of owner Chrome relay preflight without attaching or taking focus."""
    t0 = time.monotonic()
    browser = getattr(hub, "browser", None) if hub else None
    if browser and getattr(browser, "running", lambda: False)():
        try:
            st = browser.call("status", timeout=timeout_s)
            return {
                "ok": bool(st.get("connected")),
                "running": True,
                "state": st,
                "reason": None if st.get("connected") else "BROWSER_NOT_CONNECTED",
                "probe_ms": int((time.monotonic() - t0) * 1000),
            }
        except HubError as exc:
            return {
                "ok": False,
                "running": False,
                "reason": exc.code,
                "probe_ms": int((time.monotonic() - t0) * 1000),
            }
    node = shutil.which("node")
    script = PACKAGE / "ff_browser_hub.mjs"
    if not node or not script.is_file():
        return {"ok": False, "running": False, "reason": "BROWSER_HUB_SCRIPT_UNAVAILABLE", "probe_ms": 0}
    env = {**os.environ, "FF_PLAYWRIGHT_ROOT": _resolve_playwright_root(hub=hub, playwright_root=playwright_root)}
    try:
        proc = subprocess.run(
            [node, str(script), "--preflight"],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        data = json.loads((proc.stdout or "{}").strip().splitlines()[-1]) if (proc.stdout or "").strip() else {}
        return {
            "ok": proc.returncode == 0 and bool(data.get("ok")),
            "running": False,
            "details": data,
            "reason": data.get("error_code") or data.get("reason") or (None if proc.returncode == 0 else "OWNER_CHROME_PREFLIGHT_FAILED"),
            "probe_ms": int((time.monotonic() - t0) * 1000),
        }
    except Exception as exc:
        return {
            "ok": False,
            "running": False,
            "reason": type(exc).__name__,
            "probe_ms": int((time.monotonic() - t0) * 1000),
        }


def _read_hkcu_native_host(name: str) -> dict[str, Any]:
    if winreg is None:
        return {"registered": False, "reason": "NON_WINDOWS_HOST"}
    reg_path = rf"Software\Google\Chrome\NativeMessagingHosts\{name}"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path) as key:
            manifest_path = str(winreg.QueryValueEx(key, None)[0] or "")
    except OSError:
        return {"registered": False, "manifest_path": None}
    mp = Path(manifest_path) if manifest_path else None
    if not mp or not mp.is_file():
        return {"registered": True, "manifest_path": manifest_path, "manifest_exists": False}
    try:
        body = json.loads(mp.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return {"registered": True, "manifest_path": manifest_path, "manifest_exists": True, "manifest_valid": False}
    host_exe = Path(str(body.get("path") or ""))
    return {
        "registered": True,
        "manifest_path": manifest_path,
        "manifest_exists": True,
        "manifest_valid": True,
        "host_path": str(host_exe),
        "host_exists": host_exe.is_file(),
        "allowed_origins": body.get("allowed_origins") or [],
    }


def inspect_extensions_and_companion(
    package_dir: Path | None = None,
    *,
    read_owner_chrome_prefs: bool = False,
) -> dict[str, Any]:
    """Read-only inspection of NativeMessagingHosts & companion package.

    Never reads owner Chrome User Data unless read_owner_chrome_prefs=True is
    explicitly requested; never reads cookies, tokens, or DPAPI data.
    """
    pkg = package_dir or PACKAGE
    detected_extensions: dict[str, dict[str, Any]] = {}
    if read_owner_chrome_prefs:
        chrome_root = Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data"
        if chrome_root.is_dir():
            for prof in ("Default", "Profile 1", "Profile 2", "Profile 3"):
                for fname in ("Preferences", "Secure Preferences"):
                    pref = chrome_root / prof / fname
                    if not pref.is_file():
                        continue
                    try:
                        settings = ((json.loads(pref.read_text(encoding="utf-8")).get("extensions") or {}).get("settings")) or {}
                    except (OSError, ValueError):
                        continue
                    if not isinstance(settings, dict):
                        continue
                    for ext_id, alias in KNOWN_EXTENSION_IDS.items():
                        meta = settings.get(ext_id)
                        if isinstance(meta, dict):
                            manifest = meta.get("manifest") or {}
                            detected_extensions.setdefault(alias, {})[prof] = {
                                "id": ext_id,
                                "version": manifest.get("version"),
                                "state": meta.get("state"),
                                "path": meta.get("path"),
                            }

    ff_host = _read_hkcu_native_host("com.ff.browser_companion")
    claude_host = _read_hkcu_native_host("com.anthropic.claude_browser_extension")
    comp_manifest_file = pkg / "browser_companion" / "manifest.json"
    comp_sw_file = pkg / "browser_companion" / "service_worker.js"
    comp_manifest = {}
    if comp_manifest_file.is_file():
        try:
            comp_manifest = json.loads(comp_manifest_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            comp_manifest = {}
    sw_has_guard = False
    if comp_sw_file.is_file():
        sw_text = comp_sw_file.read_text(encoding="utf-8", errors="replace")
        sw_has_guard = "chrome.runtime.lastError" in sw_text and "suggest()" in sw_text

    return {
        "extensions_detected": detected_extensions,
        "owner_chrome_prefs_inspected": bool(read_owner_chrome_prefs),
        "native_hosts": {
            "com.ff.browser_companion": ff_host,
            "com.anthropic.claude_browser_extension": claude_host,
        },
        "companion": {
            "extension_dir": str(pkg / "browser_companion"),
            "manifest_version": comp_manifest.get("version"),
            "service_worker_error_guards": sw_has_guard,
            "native_host": ff_host,
        },
    }


def choose_route(
    routes: list[dict[str, Any]],
    *,
    capability: str = "dom",
    prefer: str | None = None,
    sticky: dict[str, Any] | None = None,
    allow_owner_chrome: bool = False,
) -> str | None:
    """Deterministically choose an isolated route; never silently fall back to owner Chrome.

    `owner_chrome_extension` is selected ONLY when explicitly requested via
    `capability="extension_bridge"` or `prefer="owner_chrome_extension"` (and
    usable). If a caller explicitly sets `prefer` to a route that is unavailable,
    this function fails closed and returns None rather than silently switching routes.
    """
    by_name = {item["route"]: item for item in routes}

    def usable(name: str) -> bool:
        entry = by_name.get(name)
        return bool(entry and entry.get("state") in {"READY", "ELIGIBLE"})

    owner_explicit = (capability == "extension_bridge") or (prefer == OWNER_CHROME_ROUTE)

    if prefer:
        if prefer == OWNER_CHROME_ROUTE:
            return OWNER_CHROME_ROUTE if usable(OWNER_CHROME_ROUTE) else None
        return prefer if usable(prefer) else None

    if sticky and sticky.get("route") and usable(sticky["route"]):
        sticky_route = str(sticky["route"])
        if sticky_route == OWNER_CHROME_ROUTE:
            if owner_explicit and allow_owner_chrome:
                return OWNER_CHROME_ROUTE
        elif capability != "extension_bridge":
            return sticky_route

    if capability == "extension_bridge":
        return OWNER_CHROME_ROUTE if usable(OWNER_CHROME_ROUTE) else None

    # Default isolated routes only: NEVER fall back to owner_chrome_extension.
    for candidate in ("persistent_playwright", "private_cdp", "private_uia"):
        if usable(candidate):
            return candidate
    return None


def route_plan(
    scope: dict[str, Any],
    surface: str = "browser",
    *,
    hub: Any = None,
    capability: str = "dom",
    prefer: str | None = None,
    probe_owner_preflight: bool = True,
    owner_chrome_authorized: bool | None = None,
) -> dict[str, Any]:
    """Compute a live-probed route plan for either 'browser' or 'app' control surface."""
    t0 = time.monotonic()
    if surface not in ("browser", "app"):
        raise HubError("ENTRY_SURFACE_INVALID", execution_started=False)

    is_entry_token = "scopes" in scope
    scopes = set(scope.get("scopes") or ())
    private_browser = (surface == "browser") and (("private_browser" in scopes) or not is_entry_token)
    private_app = (surface == "app") and (("private_app" in scopes) or not is_entry_token)

    owner_explicit = (capability == "extension_bridge") or (prefer == OWNER_CHROME_ROUTE)
    owner_allowed = (not is_entry_token) and (
        owner_chrome_authorized if owner_chrome_authorized is not None else owner_explicit
    )

    ext_diag = inspect_extensions_and_companion(read_owner_chrome_prefs=False)
    pw_probe = probe_playwright(hub=hub) if surface == "browser" else {"ok": False, "probe_ms": 0, "reason": "APP_SURFACE"}
    chrome_res = apps.resolve("chrome") if surface == "browser" else {"found": False}

    if is_entry_token:
        owner_probe = {"ok": False, "reason": "the scoped entry cannot attach to the owner's Chrome", "probe_ms": 0}
        owner_state = "UNAVAILABLE"
    elif surface != "browser":
        owner_probe = {"ok": False, "reason": "APP_SURFACE", "probe_ms": 0}
        owner_state = "UNAVAILABLE"
    elif not owner_allowed:
        owner_probe = {
            "ok": False,
            "reason": "owner Chrome requires explicit owner-authorized route selection; isolated hidden routes are default",
            "probe_ms": 0,
        }
        owner_state = "UNAVAILABLE"
    elif probe_owner_preflight:
        owner_probe = probe_owner_chrome(hub=hub)
        owner_state = "READY" if owner_probe["ok"] else "UNAVAILABLE"
    else:
        owner_probe = {"ok": False, "reason": "OWNER_PREFLIGHT_SKIPPED", "probe_ms": 0}
        owner_state = "UNAVAILABLE"

    pw_usable = private_browser and bool(pw_probe.get("ok"))
    cdp_usable = private_browser and bool(chrome_res.get("found"))
    native_exts = ext_diag["extensions_detected"]
    claude_host = ext_diag["native_hosts"]["com.anthropic.claude_browser_extension"]

    routes = [
        {
            "route": "api_cli_sdk_com",
            "state": "UNMANAGED",
            "reason": "provider must participate in the broker to supply managed task receipts",
            "probe_ms": 0,
        },
        {
            "route": "native_agent_extension",
            "state": "UNMANAGED",
            "broker_ownership": False,
            "detected_extensions": sorted(native_exts),
            "claude_native_host_registered": bool(claude_host.get("registered")),
            "reason": "no verified broker ownership or persistent platform approval",
            "probe_ms": 0,
        },
        {
            "route": OWNER_CHROME_ROUTE,
            "state": owner_state,
            "explicit_opt_in_only": True,
            "reason": owner_probe.get("reason") or "owner Chrome extension relay passed live preflight",
            "probe_ms": owner_probe.get("probe_ms", 0),
        },
        {
            "route": "persistent_playwright",
            "state": ("READY" if pw_probe.get("running") else "ELIGIBLE") if pw_usable else "UNAVAILABLE",
            "reason": (
                f"managed isolated Playwright persistent context ({pw_probe.get('playwright_version')})"
                if pw_usable else str(pw_probe.get("reason") or "Playwright managed adapter unavailable")
            ),
            "playwright_version": pw_probe.get("playwright_version"),
            "authorization": "managed isolated headless Playwright context; no owner profile",
            "probe_ms": pw_probe.get("probe_ms", 0),
        },
        {
            "route": "private_cdp",
            "state": "ELIGIBLE" if cdp_usable else "UNAVAILABLE",
            "reason": (
                "requires installed Chrome and local app_launch policy"
                if cdp_usable else "private Chrome executable unavailable or scope missing"
            ),
            "authorization": "managed private desktop profile, no owner Chrome grant",
            "probe_ms": 0,
        },
        {
            "route": "private_uia",
            "state": "ELIGIBLE" if private_app else "UNAVAILABLE",
            "reason": "requires a scoped app, local app_launch policy and a supported private launch",
            "probe_ms": 0,
        },
    ]

    affinity_store = getattr(hub, "route_affinity", None) if hub else None
    sticky = (
        affinity_store.get(str(scope.get("agent_id") or ""), str(scope.get("task_id") or ""))
        if affinity_store and scope.get("agent_id") and scope.get("task_id") else None
    )
    selected = choose_route(
        routes,
        capability=capability,
        prefer=prefer,
        sticky=sticky,
        allow_owner_chrome=owner_allowed,
    )

    fallback_refused_reason: str | None = None
    if selected is None and surface == "browser":
        if prefer and prefer != OWNER_CHROME_ROUTE:
            fallback_refused_reason = "PREFERRED_ROUTE_UNAVAILABLE"
        elif owner_explicit and not owner_allowed:
            fallback_refused_reason = "OWNER_CHROME_NOT_AUTHORIZED"
        elif owner_explicit:
            fallback_refused_reason = "OWNER_CHROME_UNAVAILABLE"
        elif not pw_usable and not cdp_usable:
            fallback_refused_reason = "ISOLATED_HIDDEN_ROUTES_UNAVAILABLE_NO_OWNER_FALLBACK"

    return {
        "surface": surface,
        "capability": capability,
        "selected": selected,
        "routes": routes,
        "health_probed": True,
        "probe_ms": int((time.monotonic() - t0) * 1000),
        "foreground_fallback": False,
        "owner_chrome_fallback": False,
        "owner_chrome_explicit_only": True,
        "fallback_refused_reason": fallback_refused_reason,
        "sticky_affinity": sticky,
        "companion": ext_diag["companion"],
        "extensions_detected": native_exts,
    }
