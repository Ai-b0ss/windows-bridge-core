"""Live-probed browser and application route planner with strict P0 route separation.

Route hierarchy & invariants:
1. Primary owner-auth route: `owner_chrome_profile1_hidden_secondary` (already-running
   Chrome 158+ `Profile 1` windowless hidden CDP target with auth inheritance and zero
   visible side effects). When explicitly requested (`capability="owner_profile_hidden"`
   or `prefer="owner_chrome_profile1_hidden_secondary"`), fails closed if unavailable
   and NEVER silently substitutes an isolated profile or visible extension tab.
2. Owner Chrome visible-tab extension route: `owner_chrome_extension` (Playwright MCP
   extension 0.5.0 background tab in owner's primary window tab strip). Explicitly
   reports `hidden_secondary_window_supported: False`, `visible_tab_strip: True` and
   requires explicit `capability="extension_bridge"` or `prefer="owner_chrome_extension"`.
3. Optional isolated modes: `persistent_playwright` and `private_cdp` (fresh or
   persistent isolated agent profiles, zero owner profile access). Explicitly labeled
   `mode: "optional_isolated_mode"`, `satisfies_owner_profile_auth: False`.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any

try:
    import winreg
except ImportError:  # non-Windows test hosts
    winreg = None  # type: ignore[assignment]

import ff_hub_apps as apps
from ff_hub_store import HubError

PACKAGE = Path(__file__).resolve().parent

OWNER_CHROME_HIDDEN_SECONDARY_ROUTE = "owner_chrome_profile1_hidden_secondary"
OWNER_CHROME_ROUTE = "owner_chrome_extension"
OPTIONAL_ISOLATED_BROWSER_ROUTES = ("persistent_playwright", "private_cdp")
ISOLATED_BROWSER_ROUTES = OPTIONAL_ISOLATED_BROWSER_ROUTES
OWNER_AUTH_HIDDEN_CAPABILITIES = frozenset({"owner_profile_hidden", "owner_auth_hidden", "hidden_secondary"})
BACKGROUND_TAB_READ_CAPABILITIES = frozenset({"background_tab_read", "owner_background_tab_read", "no_interruption_site_read"})
BACKGROUND_TAB_FORM_CAPABILITIES = frozenset({"background_tab_form", "owner_background_tab_form", "no_interruption_form"})
SUPPORTED_BACKGROUND_FORM_ACTIONS = ("fill", "click", "select", "check", "uncheck", "press")
VISIBILITY_BACKGROUND_TAB = "background_tab"
VISIBILITY_STRICT_INVISIBLE = "strict_invisible"
VALID_VISIBILITIES = frozenset({VISIBILITY_BACKGROUND_TAB, VISIBILITY_STRICT_INVISIBLE})
COMPANION_EXTENSION_ID = "mmhkecdcdceeibbhalmfhjleeebgdbhk"
PAGE_READ_MANIFEST_PERMISSIONS = frozenset({"tabs", "scripting", "debugger", "activeTab"})
DOWNLOAD_ONLY_PERMISSIONS = frozenset({"downloads", "nativeMessaging"})
COMPANION_ONLY_ALIASES = frozenset({"ff_browser_companion"})

KNOWN_EXTENSION_IDS = {
    "mmlmfjhmonkocbjadbfplnigmagldckm": "playwright_mcp",
    "fcoeoabgfenejglbffodgkkbkcdhcgfn": "claude_in_chrome",
    "hehggadaopoacecdllhhajmbjkdcmajg": "chatgpt_extension",
    COMPANION_EXTENSION_ID: "ff_browser_companion",
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
    """Probe optional isolated persistent Playwright + Chromium readiness on this host."""
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


def probe_owner_chrome_hidden_secondary(
    *,
    hub: Any = None,
    profile_dir_name: str = "Profile 1",
    cdp_endpoint: str | None = None,
    user_data_dir: str | Path | None = None,
    timeout_s: float = 3.0,
    connect_ws: bool = False,
) -> dict[str, Any]:
    """Read-only probe of already-running Chrome hidden secondary CDP readiness."""
    mgr = (getattr(hub, "owner_chrome_hidden", None) or getattr(hub, "owner_chrome_secondary", None)) if hub else None
    if mgr is not None and hasattr(mgr, "preflight"):
        try:
            return mgr.preflight(profile_dir_name=profile_dir_name, timeout_s=timeout_s, connect_ws=connect_ws)
        except TypeError:
            return mgr.preflight(profile_dir_name=profile_dir_name, timeout_s=timeout_s)
    from cua_owner_chrome_secondary import OwnerChromeHiddenSecondaryManager

    probe_mgr = OwnerChromeHiddenSecondaryManager(
        profile_dir_name=profile_dir_name,
        cdp_endpoint=cdp_endpoint,
        user_data_dir=user_data_dir,
    )
    return probe_mgr.preflight(profile_dir_name=profile_dir_name, timeout_s=timeout_s, connect_ws=connect_ws)


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


def inspect_companion_manifest(package_dir: Path | None = None) -> dict[str, Any]:
    """Read-only inspection of the actual FF Browser Companion manifest.json.

    FF Browser Companion 0.1.1 declares only `downloads` and `nativeMessaging`
    and MUST NOT be advertised as a browser page reader.
    """
    pkg = Path(package_dir) if package_dir is not None else PACKAGE
    comp_dir = pkg / "browser_companion"
    comp_manifest_file = comp_dir / "manifest.json"
    comp_sw_file = comp_dir / "service_worker.js"
    comp_manifest: dict[str, Any] = {}
    manifest_valid = False
    if comp_manifest_file.is_file():
        try:
            loaded = json.loads(comp_manifest_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                comp_manifest = loaded
                manifest_valid = True
        except (OSError, ValueError):
            comp_manifest = {}
    raw_perms = comp_manifest.get("permissions")
    permissions = sorted({str(p) for p in raw_perms if isinstance(p, str)}) if isinstance(raw_perms, list) else []
    raw_hosts = comp_manifest.get("host_permissions")
    host_permissions = [str(h) for h in raw_hosts if isinstance(h, str)] if isinstance(raw_hosts, list) else []
    perm_set = set(permissions)
    has_page_read_perm = bool(perm_set & PAGE_READ_MANIFEST_PERMISSIONS)
    page_read_supported = bool(manifest_valid and has_page_read_perm and (bool(host_permissions) or "activeTab" in perm_set))
    downloads_only = bool(manifest_valid and perm_set and perm_set <= DOWNLOAD_ONLY_PERMISSIONS and not host_permissions)
    sw_has_guard = False
    if comp_sw_file.is_file():
        sw_text = comp_sw_file.read_text(encoding="utf-8", errors="replace")
        sw_has_guard = "chrome.runtime.lastError" in sw_text and "suggest()" in sw_text
    return {
        "extension_id": COMPANION_EXTENSION_ID,
        "name": str(comp_manifest.get("name") or "FF Browser Companion"),
        "extension_dir": str(comp_dir),
        "manifest_valid": manifest_valid,
        "manifest_version": comp_manifest.get("version"),
        "permissions": permissions,
        "host_permissions": host_permissions,
        "supported_capabilities": permissions,
        "downloads_only": downloads_only,
        "browser_page_reader": page_read_supported,
        "page_read_supported": page_read_supported,
        "tab_open_supported": bool(manifest_valid and "tabs" in perm_set),
        "background_tab_supported": bool(manifest_valid and "tabs" in perm_set and page_read_supported),
        "service_worker_error_guards": sw_has_guard,
        "non_reader_reason": (
            None if page_read_supported else
            "FF Browser Companion only declares downloads and nativeMessaging permissions in manifest.json; "
            "it cannot open tabs or read browser pages"
        ),
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
                            raw_perms = manifest.get("permissions")
                            perms = sorted({str(p) for p in raw_perms if isinstance(p, str)}) if isinstance(raw_perms, list) else []
                            raw_hosts = manifest.get("host_permissions")
                            hosts = [str(h) for h in raw_hosts if isinstance(h, str)] if isinstance(raw_hosts, list) else []
                            detected_extensions.setdefault(alias, {})[prof] = {
                                "id": ext_id,
                                "version": manifest.get("version"),
                                "state": meta.get("state"),
                                "path": meta.get("path"),
                                "permissions": perms,
                                "host_permissions": hosts,
                                "browser_page_reader": bool(
                                    set(perms) & PAGE_READ_MANIFEST_PERMISSIONS and (bool(hosts) or "activeTab" in perms)
                                ),
                            }

    ff_host = _read_hkcu_native_host("com.ff.browser_companion")
    claude_host = _read_hkcu_native_host("com.anthropic.claude_browser_extension")
    comp_info = inspect_companion_manifest(pkg)

    return {
        "extensions_detected": detected_extensions,
        "owner_chrome_prefs_inspected": bool(read_owner_chrome_prefs),
        "native_hosts": {
            "com.ff.browser_companion": ff_host,
            "com.anthropic.claude_browser_extension": claude_host,
        },
        "companion": {
            **comp_info,
            "native_host": ff_host,
        },
    }


def validate_site_read_url(url: Any) -> tuple[str, str]:
    """Validate a concrete http(s) URL for the read-only site workflow and return (url, host)."""
    if url is None or url == "":
        raise HubError(
            "SITE_URL_REQUIRED",
            "a specifically requested http(s) site URL is required",
            execution_started=False,
        )
    if not isinstance(url, str) or len(url) > 8192 or any(ord(ch) < 32 for ch in url):
        raise HubError("URL_INVALID", "site URL must be a bounded printable string", execution_started=False)
    cleaned = url.strip()
    if not cleaned:
        raise HubError("SITE_URL_REQUIRED", "a specifically requested http(s) site URL is required", execution_started=False)
    try:
        parsed = urllib.parse.urlsplit(cleaned)
    except ValueError:
        raise HubError("URL_INVALID", "malformed site URL", execution_started=False) from None
    if parsed.scheme.lower() not in {"http", "https"}:
        raise HubError(
            "URL_SCHEME_FORBIDDEN",
            "only concrete http(s) URLs are supported for the read-only site workflow (about:blank and internal schemes are forbidden)",
            scheme=parsed.scheme,
            execution_started=False,
        )
    if not parsed.hostname or parsed.username or parsed.password:
        raise HubError(
            "URL_INVALID",
            "site URL must include a concrete hostname and no embedded credentials",
            execution_started=False,
        )
    host = parsed.hostname.lower().rstrip(".")
    if not host:
        raise HubError("URL_INVALID", "site URL hostname is empty", execution_started=False)
    return cleaned, host


def normalize_visibility_mode(
    visibility: Any = None,
    strict_invisibility: Any = None,
) -> tuple[str, bool]:
    """Distinguish ordinary background-tab requests from strict invisibility requests."""
    if strict_invisibility is not None and type(strict_invisibility) is not bool:
        raise HubError(
            "ARGS_INVALID",
            "strict_invisibility must be a boolean",
            field="strict_invisibility",
            execution_started=False,
        )
    vis: str | None = None
    if visibility is not None:
        if not isinstance(visibility, str) or visibility.strip().lower() not in VALID_VISIBILITIES:
            raise HubError(
                "ARGS_INVALID",
                "visibility must be 'background_tab' or 'strict_invisible'",
                field="visibility",
                allowed=sorted(VALID_VISIBILITIES),
                execution_started=False,
            )
        vis = visibility.strip().lower()
    if vis == VISIBILITY_BACKGROUND_TAB and strict_invisibility is True:
        raise HubError(
            "ARGS_INVALID",
            "visibility='background_tab' conflicts with strict_invisibility=true",
            field="visibility",
            execution_started=False,
        )
    if vis == VISIBILITY_STRICT_INVISIBLE and strict_invisibility is False:
        raise HubError(
            "ARGS_INVALID",
            "visibility='strict_invisible' conflicts with strict_invisibility=false",
            field="visibility",
            execution_started=False,
        )
    if vis is not None:
        return vis, vis == VISIBILITY_STRICT_INVISIBLE
    if strict_invisibility is True:
        return VISIBILITY_STRICT_INVISIBLE, True
    return VISIBILITY_BACKGROUND_TAB, False


def evaluate_no_interruption_site_read(
    scope: dict[str, Any],
    url: Any,
    *,
    hub: Any = None,
    visibility: Any = None,
    strict_invisibility: Any = None,
    profile_dir_name: str | None = None,
    package_dir: Path | None = None,
) -> dict[str, Any]:
    """Read-only, non-prompting provider selection for a specifically requested site.

    Invariants:
    - Never creates pending Hub permission requests, never triggers Chrome dialogs,
      never launches Chrome/sidecars, never changes settings or extracts credentials.
    - Never advertises FF Browser Companion 0.1.1 as a browser page reader.
    - Never substitutes a visible tab (owner_chrome_extension) when strict invisibility
      is requested.
    - For an ordinary background-tab request, selects an existing supported provider
      ONLY when authorization, live connection, background open without activation,
      read access, and ownership are all verified.
    - If no eligible provider exists, returns one actionable capability result.
    """
    t0 = time.monotonic()
    validated_url, host = validate_site_read_url(url)
    vis_mode, strict_inv = normalize_visibility_mode(visibility=visibility, strict_invisibility=strict_invisibility)
    comp_manifest = inspect_companion_manifest(package_dir)

    is_entry_token = "scopes" in scope
    scopes = set(scope.get("scopes") or ())
    agent_id = str(scope.get("agent_id") or "").strip()
    policy = getattr(hub, "policy", None) if hub is not None else None

    def _policy_decide(risk_class: str, target: dict[str, Any]) -> dict[str, Any]:
        if not agent_id:
            return {"decision": "needs_owner", "risk_class": risk_class, "reason": "AGENT_IDENTITY_REQUIRED", "grant_id": None}
        if policy is None or not hasattr(policy, "decide"):
            return {"decision": "needs_owner", "risk_class": risk_class, "reason": "HUB_POLICY_UNAVAILABLE", "grant_id": None}
        return dict(policy.decide(agent_id, risk_class, target))

    # --- Candidate 1: owner_chrome_profile1_hidden_secondary (strictly invisible windowless CDP) ---
    mgr = (getattr(hub, "owner_chrome_hidden", None) or getattr(hub, "owner_chrome_secondary", None)) if hub is not None else None
    configured_profile = (
        hub.configured_owner_chrome_profile()
        if (hub is not None and hasattr(hub, "configured_owner_chrome_profile"))
        else getattr(mgr, "profile_dir_name", None)
    )
    effective_hidden_profile = profile_dir_name or configured_profile or "Profile 1"
    hidden_entry: dict[str, Any] = {
        "provider": OWNER_CHROME_HIDDEN_SECONDARY_ROUTE,
        "hub_op": "owner_chrome_hidden",
        "eligible": False,
        "strict_invisibility_supported": True,
        "visible_tab_strip": False,
        "windowless": True,
        "activates_tab": False,
        "profile_dir_name": effective_hidden_profile,
        "authorized": False,
        "connected": False,
        "background_open_without_activation_verified": False,
        "read_access_verified": False,
        "ownership_verified": False,
        "prompts_required": False,
        "reason_code": None,
        "reason": "",
    }
    if is_entry_token and "owner_chrome_hidden" not in scopes:
        hidden_entry["reason_code"] = "ENTRY_OWNER_CHROME_SCOPE_REQUIRED"
        hidden_entry["reason"] = "scoped /agent/v1 token lacks owner_chrome_hidden scope"
    else:
        hidden_dec = _policy_decide("owner_chrome_hidden_secondary", {"host": host})
        hidden_authorized = hidden_dec.get("decision") == "allow"
        hidden_entry["authorized"] = hidden_authorized
        hidden_entry["grant_id"] = hidden_dec.get("grant_id")
        hidden_entry["policy_reason"] = hidden_dec.get("reason")

        already_connected = False
        pf: dict[str, Any] = {}
        if mgr is None:
            pf = {"ok": False, "error_code": "OWNER_CHROME_HIDDEN_SECONDARY_UNAVAILABLE", "reason": "owner_chrome_secondary manager unavailable"}
        else:
            if hasattr(mgr, "status"):
                try:
                    st = mgr.status()
                    already_connected = bool(isinstance(st, dict) and st.get("connected") is True)
                except Exception:
                    already_connected = False
            if hasattr(mgr, "preflight"):
                try:
                    pf = mgr.preflight(
                        profile_dir_name=effective_hidden_profile,
                        timeout_s=2.5,
                        connect_ws=False,
                        allow_new_ws=False,
                    )
                except TypeError:
                    pf = mgr.preflight(profile_dir_name=effective_hidden_profile, timeout_s=2.5, connect_ws=False) if already_connected else {
                        "ok": False,
                        "connected": False,
                        "error_code": "OWNER_CHROME_CDP_NOT_CONNECTED",
                        "reason": "owner Chrome hidden secondary CDP is not already connected",
                    }
            else:
                pf = {"ok": False, "error_code": "OWNER_CHROME_HIDDEN_SECONDARY_UNAVAILABLE", "reason": "preflight unavailable"}

        connected_verified = bool(
            already_connected
            and pf.get("ok") is True
            and pf.get("approval_required") is not True
            and pf.get("confirmation_required") is not True
            and pf.get("hidden_target_supported") is True
            and pf.get("visible_side_effect_free") is True
            and pf.get("profile_context_verified", True) is True
        )
        hidden_entry["connected"] = connected_verified
        hidden_entry["cdp_discovered"] = bool(pf.get("cdp_discovered", connected_verified))
        hidden_entry["discovery_mode"] = pf.get("discovery_mode")
        hidden_entry["http_discovery_status"] = pf.get("http_discovery_status")
        hidden_entry["chrome_version"] = pf.get("chrome_version")
        hidden_entry["approval_required"] = bool(pf.get("approval_required"))
        hidden_entry["prompts_required"] = bool(pf.get("approval_required") or pf.get("confirmation_required"))
        if connected_verified:
            hidden_entry["background_open_without_activation_verified"] = True
            hidden_entry["read_access_verified"] = bool(hidden_authorized)
            hidden_entry["ownership_verified"] = True

        if not hidden_authorized:
            hidden_entry["reason_code"] = str(hidden_dec.get("reason") or "NO_MATCHING_GRANT")
            hidden_entry["consent_gate"] = "hub_policy"
            hidden_entry["reason"] = (
                f"Hub local standing policy (Gate 1) has not granted owner_chrome_hidden_secondary for host '{host}' "
                f"({hidden_entry['reason_code']})"
            )
            hidden_entry["remedy"] = (
                f"ff_hub.py grant add --classes owner_chrome_hidden_secondary "
                f"--agents {agent_id or '<agent>'} --hosts {host} --ttl 1h"
            )
            if not connected_verified and pf.get("error_code"):
                hidden_entry["connection_blocker"] = pf.get("error_code")
                if pf.get("consent_gate"):
                    hidden_entry["separate_chrome_consent_gate"] = pf.get("consent_gate")
        elif not connected_verified:
            hidden_entry["reason_code"] = str(pf.get("error_code") or "OWNER_CHROME_CDP_NOT_CONNECTED")
            if pf.get("consent_gate"):
                hidden_entry["consent_gate"] = pf.get("consent_gate")
            hidden_entry["reason"] = str(
                pf.get("reason") or "owner Chrome hidden secondary CDP is not already connected"
            )
            hidden_entry["remedy"] = (
                str(pf["remedy"]) if pf.get("remedy")
                else "OWNER_CHROME_CONNECT_CDP_EXPLICITLY"
            )
        else:
            hidden_entry["eligible"] = True
            hidden_entry["reason_code"] = None
            hidden_entry["reason"] = (
                f"already authorized and connected windowless hidden target on {effective_hidden_profile} "
                f"(no activation, no visible tab, verified Target.closeTarget teardown)"
            )

    # --- Candidate 2: owner_chrome_extension (Playwright Extension ordinary background tab) ---
    ext_entry: dict[str, Any] = {
        "provider": OWNER_CHROME_ROUTE,
        "hub_op": "browser",
        "eligible": False,
        "strict_invisibility_supported": False,
        "visible_tab_strip": True,
        "windowless": False,
        "activates_tab": None,
        "authorized": False,
        "connected": False,
        "background_open_without_activation_verified": False,
        "read_access_verified": False,
        "ownership_verified": False,
        "prompts_required": False,
        "reason_code": None,
        "reason": "",
    }
    if strict_inv:
        ext_entry["reason_code"] = "VISIBLE_TAB_SUBSTITUTION_FORBIDDEN"
        ext_entry["reason"] = (
            "owner_chrome_extension opens a visible tab in Chrome's tab strip (hidden_secondary_window_supported=false) "
            "and is never substituted when strict invisibility is requested"
        )
    elif is_entry_token:
        ext_entry["reason_code"] = "ENTRY_OWNER_CHROME_FORBIDDEN"
        ext_entry["reason"] = "scoped /agent/v1 token cannot attach to owner Chrome extension"
    else:
        tab_dec = _policy_decide("browser_own_tabs", {"host": host})
        read_dec = _policy_decide("read_diagnose", {"host": host})
        ext_authorized = tab_dec.get("decision") == "allow" and read_dec.get("decision") == "allow"
        ext_entry["authorized"] = ext_authorized
        ext_entry["policy_decisions"] = {
            "browser_own_tabs": tab_dec.get("decision"),
            "read_diagnose": read_dec.get("decision"),
        }
        browser = getattr(hub, "browser", None) if hub is not None else None
        is_running = bool(browser is not None and getattr(browser, "running", lambda: False)())
        st: dict[str, Any] = {}
        status_err: str | None = None
        if is_running:
            try:
                raw_st = browser.call("status", timeout=2.5)
                if isinstance(raw_st, dict):
                    st = raw_st
                else:
                    status_err = "BROWSER_STATUS_INVALID"
            except Exception as exc:
                status_err = getattr(exc, "code", None) or type(exc).__name__

        connected = bool(
            is_running
            and status_err is None
            and st.get("connected") is True
            and st.get("stopping") is not True
            and st.get("circuit_open") is not True
        )
        route = st.get("route") if isinstance(st.get("route"), dict) else {}
        transport = str(route.get("transport") or "")
        ext_id = route.get("extension_id")
        is_companion_transport = (
            transport in {"ff_browser_companion", "browser_companion", "downloads_only"}
            or ext_id == COMPANION_EXTENSION_ID
        )
        raw_ext_perms = route.get("extension_permissions")
        perms_ok = True
        if isinstance(raw_ext_perms, list):
            pset = {str(p) for p in raw_ext_perms}
            perms_ok = "tabs" in pset and ("debugger" in pset or "scripting" in pset)

        bg_verified = bool(
            connected
            and route.get("background") is True
            and route.get("activates_tab") is not True
            and route.get("isolated_profile") is False
        )
        read_transport_ok = bool(
            connected
            and not is_companion_transport
            and route.get("read_supported") is not False
            and perms_ok
            and (transport == "playwright-extension" or route.get("read_supported") is True)
        )
        read_verified = bool(read_transport_ok and read_dec.get("decision") == "allow")
        ledger = st.get("tab_ledger") if isinstance(st.get("tab_ledger"), dict) else {}
        limits = st.get("limits") if isinstance(st.get("limits"), dict) else {}
        limits_ok = (
            isinstance(limits.get("maxTabsPerOwner"), int)
            and limits["maxTabsPerOwner"] > 0
            and isinstance(limits.get("maxTabs"), int)
            and limits["maxTabs"] > 0
        )
        ownership_verified = bool(
            connected
            and ledger.get("enabled") is True
            and not ledger.get("error")
            and route.get("ownership_supported") is not False
            and limits_ok
        )
        owner_prof = route.get("owner_profile")
        profile_ok = (
            profile_dir_name is None
            or (isinstance(owner_prof, str) and owner_prof == profile_dir_name)
        )

        ext_entry["connected"] = connected
        ext_entry["transport"] = transport or None
        ext_entry["owner_profile"] = owner_prof
        ext_entry["activates_tab"] = False if bg_verified else (True if route.get("activates_tab") is True or route.get("background") is False else None)
        ext_entry["background_open_without_activation_verified"] = bg_verified
        ext_entry["read_access_verified"] = read_verified
        ext_entry["ownership_verified"] = ownership_verified

        if not ext_authorized:
            denied_class = "browser_own_tabs" if tab_dec.get("decision") != "allow" else "read_diagnose"
            denied_dec = tab_dec if denied_class == "browser_own_tabs" else read_dec
            ext_entry["reason_code"] = str(denied_dec.get("reason") or "PERMISSION_REQUIRED")
            ext_entry["consent_gate"] = "hub_policy"
            ext_entry["denied_risk_class"] = denied_class
            ext_entry["reason"] = (
                f"Hub local policy does not allow '{denied_class}' for host '{host}' ({ext_entry['reason_code']})"
            )
            ext_entry["remedy"] = (
                f"ff_hub.py grant add --classes {denied_class} "
                f"--agents {agent_id or '<agent>'} --hosts {host} --ttl 1h"
            )
        elif not is_running or not connected:
            ext_entry["reason_code"] = status_err or "PROVIDER_NOT_CONNECTED"
            ext_entry["reason"] = (
                "Playwright Extension browser manager is not already running/connected; "
                "refusing to launch a new connection or risk prompting the user"
            )
            ext_entry["remedy"] = "CONNECT_EXISTING_PLAYWRIGHT_EXTENSION_RELAY"
        elif is_companion_transport or not perms_ok:
            ext_entry["reason_code"] = "PROVIDER_MANIFEST_PAGE_READ_UNSUPPORTED"
            ext_entry["reason"] = "connected extension manifest lacks verified tabs + debugger/scripting page read permissions"
        elif route.get("isolated_profile") is not False:
            ext_entry["reason_code"] = "ISOLATED_PROFILE_SUBSTITUTION_FORBIDDEN"
            ext_entry["reason"] = "connected browser route is an isolated profile rather than the owner's authorized Chrome"
        elif not bg_verified:
            ext_entry["reason_code"] = "BACKGROUND_OPEN_WITHOUT_ACTIVATION_UNVERIFIED"
            ext_entry["reason"] = "connected extension route cannot verify background open without tab activation"
        elif not read_verified:
            ext_entry["reason_code"] = "READ_ACCESS_UNVERIFIED"
            ext_entry["reason"] = "connected extension route cannot verify read-only page access"
        elif not ownership_verified:
            ext_entry["reason_code"] = "OWNERSHIP_UNVERIFIED"
            ext_entry["reason"] = "connected extension route lacks a healthy durable tab-ownership ledger"
        elif not profile_ok:
            ext_entry["reason_code"] = "OWNER_CHROME_PROFILE_MISMATCH"
            ext_entry["reason"] = (
                f"connected extension profile {owner_prof!r} cannot be verified as requested profile {profile_dir_name!r}"
            )
        else:
            ext_entry["eligible"] = True
            ext_entry["reason_code"] = None
            ext_entry["reason"] = (
                "already authorized and connected Playwright Extension background-tab provider "
                "(visible tab strip, no activation, verified read access and tab-ledger ownership)"
            )

    providers = [hidden_entry, ext_entry]
    excluded_providers = [
        {
            "provider": "ff_browser_companion",
            "extension_id": comp_manifest["extension_id"],
            "name": comp_manifest["name"],
            "manifest_version": comp_manifest["manifest_version"],
            "permissions": comp_manifest["permissions"],
            "host_permissions": comp_manifest["host_permissions"],
            "supported_capabilities": comp_manifest["supported_capabilities"],
            "browser_page_reader": comp_manifest["browser_page_reader"],
            "page_read_supported": comp_manifest["page_read_supported"],
            "eligible": False,
            "reason_code": "COMPANION_DOWNLOADS_AND_NATIVE_MESSAGING_ONLY",
            "reason": comp_manifest["non_reader_reason"],
        },
        {
            "provider": "native_agent_extension",
            "eligible": False,
            "broker_ownership": False,
            "background_open_without_activation_verified": False,
            "read_access_verified": False,
            "ownership_verified": False,
            "reason_code": "PROVIDER_UNMANAGED_NO_BROKER_OWNERSHIP",
            "reason": "third-party browser extensions lack verified Hub broker ownership, non-activation guarantees, and teardown receipts",
        },
        {
            "provider": "isolated_hidden_browser",
            "routes": list(OPTIONAL_ISOLATED_BROWSER_ROUTES),
            "eligible": False,
            "satisfies_owner_profile_auth": False,
            "reason_code": "ISOLATED_PROFILE_SUBSTITUTION_FORBIDDEN",
            "reason": "isolated headless/private browser profiles do not inherit owner Chrome sessions and are never silently substituted",
        },
    ]

    selected_entry = next((p for p in providers if p["eligible"]), None)
    selected_provider = selected_entry["provider"] if selected_entry is not None else None

    actionable_next_steps: list[dict[str, Any]] = []
    if selected_provider is None:
        if not hidden_entry["authorized"] and hidden_entry.get("remedy"):
            actionable_next_steps.append({
                "provider": OWNER_CHROME_HIDDEN_SECONDARY_ROUTE,
                "consent_gate": "hub_policy",
                "action": "owner_grant_site_scope",
                "command": hidden_entry["remedy"],
                "automatic": False,
            })
        if not hidden_entry["connected"] and hidden_entry.get("reason_code") not in {None, "ENTRY_OWNER_CHROME_SCOPE_REQUIRED"}:
            conn_action = (
                hidden_entry.get("connection_blocker") or "OWNER_CHROME_CONNECT_CDP_EXPLICITLY"
                if not hidden_entry["authorized"]
                else (hidden_entry.get("remedy") or hidden_entry["reason_code"])
            )
            actionable_next_steps.append({
                "provider": OWNER_CHROME_HIDDEN_SECONDARY_ROUTE,
                "consent_gate": hidden_entry.get("separate_chrome_consent_gate") or hidden_entry.get("consent_gate"),
                "action": conn_action,
                "automatic": False,
            })
        if not strict_inv and not ext_entry["eligible"] and ext_entry.get("remedy"):
            actionable_next_steps.append({
                "provider": OWNER_CHROME_ROUTE,
                "consent_gate": ext_entry.get("consent_gate"),
                "action": ext_entry["remedy"],
                "automatic": False,
            })
        if strict_inv:
            summary = (
                f"No already authorized and connected strictly invisible provider is eligible for '{host}' "
                f"(owner_chrome_profile1_hidden_secondary: {hidden_entry['reason_code']}; "
                "visible-tab owner_chrome_extension is never substituted for strict invisibility)."
            )
        else:
            summary = (
                f"No already authorized and connected supported provider is eligible for '{host}' "
                f"(owner_chrome_profile1_hidden_secondary: {hidden_entry['reason_code']}; "
                f"owner_chrome_extension: {ext_entry['reason_code']})."
            )
    else:
        summary = f"Selected already authorized and connected provider '{selected_provider}' for read-only site '{host}'."

    return {
        "schema": "ff-no-interruption-site-read-v1",
        "ok": selected_provider is not None,
        "eligible": selected_provider is not None,
        "executed": False,
        "execution_started": False,
        "ui_triggered": False,
        "prompts_triggered": False,
        "pending_request_created": False,
        "read_only": True,
        "url": validated_url,
        "host": host,
        "visibility_requested": vis_mode,
        "strict_invisibility": strict_inv,
        "selected_provider": selected_provider,
        "selected_hub_op": selected_entry["hub_op"] if selected_entry is not None else None,
        "visible_tab_strip": selected_entry["visible_tab_strip"] if selected_entry is not None else None,
        "error_code": None if selected_provider is not None else "NO_ELIGIBLE_NO_INTERRUPTION_PROVIDER",
        "summary": summary,
        "providers": providers,
        "excluded_providers": excluded_providers,
        "actionable_next_steps": actionable_next_steps,
        "automatic": False,
        "retry_safe": True,
        "permissions_preserved": True,
        "chrome_settings_modified": False,
        "credentials_extracted": False,
        "probe_ms": int((time.monotonic() - t0) * 1000),
    }


def evaluate_no_interruption_background_form(
    scope: dict[str, Any],
    url: Any,
    *,
    hub: Any = None,
    visibility: Any = None,
    strict_invisibility: Any = None,
    profile_dir_name: str | None = None,
    package_dir: Path | None = None,
) -> dict[str, Any]:
    """Read-only, non-prompting provider selection for background form operations on owned tabs.

    Uses only already authorized and connected supported providers, preserves existing
    Hub policy and browser permissions, never triggers foreground input or prompts,
    never substitutes visible tabs for strict invisibility, and never advertises
    FF Browser Companion 0.1.1 as a form/page automation provider.
    """
    base = evaluate_no_interruption_site_read(
        scope,
        url,
        hub=hub,
        visibility=visibility,
        strict_invisibility=strict_invisibility,
        profile_dir_name=profile_dir_name,
        package_dir=package_dir,
    )
    providers = [dict(item) for item in base["providers"]]
    for item in providers:
        if item["provider"] == OWNER_CHROME_HIDDEN_SECONDARY_ROUTE:
            item["form_operations_supported"] = bool(item["connected"])
            item["supported_actions"] = list(SUPPORTED_BACKGROUND_FORM_ACTIONS)
            item["reload_supported"] = True
            item["wait_for_supported"] = True
        elif item["provider"] == OWNER_CHROME_ROUTE:
            browser = getattr(hub, "browser", None) if hub is not None else None
            form_flag = True
            if item["eligible"] and browser is not None and getattr(browser, "running", lambda: False)():
                try:
                    raw_st = browser.call("status", timeout=2.5)
                    route = raw_st.get("route") if isinstance(raw_st, dict) and isinstance(raw_st.get("route"), dict) else {}
                    if route.get("form_operations_supported") is False:
                        form_flag = False
                except Exception:
                    form_flag = False
            item["form_operations_supported"] = bool(item["connected"] and form_flag)
            item["supported_actions"] = list(SUPPORTED_BACKGROUND_FORM_ACTIONS)
            item["reload_supported"] = True
            item["wait_for_supported"] = True
            if item["eligible"] and not form_flag:
                item["eligible"] = False
                item["reason_code"] = "FORM_OPERATIONS_UNVERIFIED"
                item["reason"] = "connected extension route cannot verify background DOM form operations"

    selected_entry = next((p for p in providers if p["eligible"]), None)
    selected_provider = selected_entry["provider"] if selected_entry is not None else None
    host = base["host"]
    if selected_provider is not None:
        summary = (
            f"Selected already authorized and connected provider '{selected_provider}' "
            f"for background form operations on owned tabs for '{host}'."
        )
    else:
        summary = base["summary"].replace("read-only site", "background form operations")

    return {
        **base,
        "schema": "ff-no-interruption-background-form-v1",
        "ok": selected_provider is not None,
        "eligible": selected_provider is not None,
        "read_only": False,
        "selected_provider": selected_provider,
        "selected_hub_op": selected_entry["hub_op"] if selected_entry is not None else None,
        "visible_tab_strip": selected_entry["visible_tab_strip"] if selected_entry is not None else None,
        "error_code": None if selected_provider is not None else "NO_ELIGIBLE_NO_INTERRUPTION_PROVIDER",
        "summary": summary,
        "providers": providers,
        "supported_form_actions": list(SUPPORTED_BACKGROUND_FORM_ACTIONS),
        "reload_supported": True,
        "wait_for_supported": True,
        "request_key_deduplication": True,
        "foreground_fallback": False,
        "policy_modified": False,
        "browser_permissions_modified": False,
    }


def choose_route(
    routes: list[dict[str, Any]],
    *,
    capability: str = "dom",
    prefer: str | None = None,
    sticky: dict[str, Any] | None = None,
    allow_owner_chrome: bool = False,
) -> str | None:
    """Deterministically choose a route with strict separation and zero silent fallback.

    - Primary owner-auth hidden mode (`capability in OWNER_AUTH_HIDDEN_CAPABILITIES` or
      `prefer == "owner_chrome_profile1_hidden_secondary"`) selects ONLY
      `owner_chrome_profile1_hidden_secondary` when usable, and fails closed (`None`)
      otherwise — NEVER silently substituting `persistent_playwright`, `private_cdp`,
      or visible-tab `owner_chrome_extension`.
    - `owner_chrome_extension` is selected ONLY when explicitly requested via
      `capability == "extension_bridge"` or `prefer == "owner_chrome_extension"`.
    - When `prefer` is explicitly set and unavailable, fails closed (`None`).
    - Default `capability == "dom"` selects isolated routes (`persistent_playwright`,
      `private_cdp`, `private_uia`) and NEVER silently falls back to owner Chrome.
    """
    by_name = {item["route"]: item for item in routes}

    def usable(name: str) -> bool:
        entry = by_name.get(name)
        return bool(entry and entry.get("state") in {"READY", "ELIGIBLE"})

    owner_hidden_req = (capability in OWNER_AUTH_HIDDEN_CAPABILITIES) or (prefer == OWNER_CHROME_HIDDEN_SECONDARY_ROUTE)
    owner_ext_req = (capability == "extension_bridge") or (prefer == OWNER_CHROME_ROUTE)

    if owner_hidden_req:
        return OWNER_CHROME_HIDDEN_SECONDARY_ROUTE if usable(OWNER_CHROME_HIDDEN_SECONDARY_ROUTE) else None

    if prefer:
        if prefer == OWNER_CHROME_ROUTE:
            return OWNER_CHROME_ROUTE if usable(OWNER_CHROME_ROUTE) else None
        return prefer if usable(prefer) else None

    if sticky and sticky.get("route") and usable(sticky["route"]):
        sticky_route = str(sticky["route"])
        if sticky_route == OWNER_CHROME_ROUTE:
            if owner_ext_req and allow_owner_chrome:
                return OWNER_CHROME_ROUTE
        elif sticky_route == OWNER_CHROME_HIDDEN_SECONDARY_ROUTE:
            if owner_hidden_req and allow_owner_chrome:
                return OWNER_CHROME_HIDDEN_SECONDARY_ROUTE
        elif capability != "extension_bridge":
            return sticky_route

    if capability == "extension_bridge":
        return OWNER_CHROME_ROUTE if usable(OWNER_CHROME_ROUTE) else None

    # Optional isolated routes only for default `capability="dom"`: NEVER fall back to owner Chrome.
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
    profile_dir_name: str | None = None,
    url: str | None = None,
    visibility: str | None = None,
    strict_invisibility: bool | None = None,
) -> dict[str, Any]:
    """Compute a live-probed route plan for either 'browser' or 'app' control surface."""
    t0 = time.monotonic()
    if surface not in ("browser", "app"):
        raise HubError("ENTRY_SURFACE_INVALID", execution_started=False)

    effective_profile = profile_dir_name or "Profile 1"
    if surface == "browser" and capability in (BACKGROUND_TAB_READ_CAPABILITIES | BACKGROUND_TAB_FORM_CAPABILITIES):
        ext_diag = inspect_extensions_and_companion(read_owner_chrome_prefs=False)
        is_form_plan = capability in BACKGROUND_TAB_FORM_CAPABILITIES
        site_plan = (
            evaluate_no_interruption_background_form
            if is_form_plan
            else evaluate_no_interruption_site_read
        )(
            scope,
            url,
            hub=hub,
            visibility=visibility,
            strict_invisibility=strict_invisibility,
            profile_dir_name=profile_dir_name,
        )
        plan_key = "background_form_plan" if is_form_plan else "no_interruption_site_read"
        return {
            "surface": surface,
            "capability": capability,
            "selected": site_plan["selected_provider"],
            "primary_owner_auth_route": OWNER_CHROME_HIDDEN_SECONDARY_ROUTE,
            "isolated_substitution_forbidden": True,
            "visibility_requested": site_plan["visibility_requested"],
            "strict_invisibility": site_plan["strict_invisibility"],
            "routes": site_plan["providers"],
            "excluded_providers": site_plan["excluded_providers"],
            "actionable_next_steps": site_plan["actionable_next_steps"],
            "summary": site_plan["summary"],
            plan_key: site_plan,
            "health_probed": True,
            "pending_request_created": False,
            "ui_triggered": False,
            "prompts_triggered": False,
            "probe_ms": int((time.monotonic() - t0) * 1000),
            "foreground_fallback": False,
            "owner_chrome_fallback": False,
            "owner_chrome_explicit_only": True,
            "fallback_refused_reason": site_plan["error_code"],
            "sticky_affinity": None,
            "companion": ext_diag["companion"],
            "extensions_detected": {
                k: v for k, v in ext_diag["extensions_detected"].items() if k not in COMPANION_ONLY_ALIASES
            },
        }

    is_entry_token = "scopes" in scope
    scopes = set(scope.get("scopes") or ())
    private_browser = (surface == "browser") and (("private_browser" in scopes) or not is_entry_token)
    private_app = (surface == "app") and (("private_app" in scopes) or not is_entry_token)
    entry_owner_hidden_scope = is_entry_token and ("owner_chrome_hidden" in scopes)

    owner_hidden_explicit = (capability in OWNER_AUTH_HIDDEN_CAPABILITIES) or (prefer == OWNER_CHROME_HIDDEN_SECONDARY_ROUTE)
    owner_ext_explicit = (capability == "extension_bridge") or (prefer == OWNER_CHROME_ROUTE)

    owner_ext_allowed = (not is_entry_token) and (
        owner_chrome_authorized if owner_chrome_authorized is not None else owner_ext_explicit
    )
    owner_hidden_allowed = (
        (entry_owner_hidden_scope or not is_entry_token)
        and (owner_chrome_authorized if owner_chrome_authorized is not None else owner_hidden_explicit)
    )

    ext_diag = inspect_extensions_and_companion(read_owner_chrome_prefs=False)
    pw_probe = probe_playwright(hub=hub) if surface == "browser" else {"ok": False, "probe_ms": 0, "reason": "APP_SURFACE"}
    chrome_res = apps.resolve("chrome") if surface == "browser" else {"found": False}

    # Probe primary P0 owner Chrome configured-profile hidden secondary route only when authorized/requested.
    if surface != "browser":
        owner_hidden_probe: dict[str, Any] = {"ok": False, "reason": "APP_SURFACE", "probe_ms": 0}
        owner_hidden_state = "UNAVAILABLE"
    elif is_entry_token and not entry_owner_hidden_scope:
        owner_hidden_probe = {
            "ok": False,
            "reason": "the scoped entry lacks owner_chrome_hidden scope",
            "error_code": "ENTRY_OWNER_CHROME_SCOPE_REQUIRED",
            "probe_ms": 0,
        }
        owner_hidden_state = "UNAVAILABLE"
    elif not owner_hidden_allowed:
        owner_hidden_probe = {
            "ok": False,
            "reason": "owner Chrome configured-profile hidden secondary route requires explicit owner-authorized selection",
            "error_code": "OWNER_CHROME_NOT_AUTHORIZED",
            "probe_ms": 0,
        }
        owner_hidden_state = "UNAVAILABLE"
    elif probe_owner_preflight:
        owner_hidden_probe = probe_owner_chrome_hidden_secondary(hub=hub, profile_dir_name=effective_profile)
        if owner_hidden_probe.get("ok"):
            owner_hidden_state = "READY"
        elif owner_hidden_probe.get("approval_required"):
            owner_hidden_state = "APPROVAL_REQUIRED"
        else:
            owner_hidden_state = "UNAVAILABLE"
    else:
        owner_hidden_probe = {"ok": False, "reason": "OWNER_PREFLIGHT_SKIPPED", "probe_ms": 0}
        owner_hidden_state = "UNAVAILABLE"

    if is_entry_token:
        owner_probe = {"ok": False, "reason": "the scoped entry cannot attach to the owner's Chrome", "probe_ms": 0}
        owner_state = "UNAVAILABLE"
    elif surface != "browser":
        owner_probe = {"ok": False, "reason": "APP_SURFACE", "probe_ms": 0}
        owner_state = "UNAVAILABLE"
    elif not owner_ext_allowed:
        owner_probe = {
            "ok": False,
            "reason": "owner Chrome extension route requires explicit owner-authorized selection (adds tab to primary window)",
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
    native_exts = {
        k: v for k, v in ext_diag["extensions_detected"].items() if k not in COMPANION_ONLY_ALIASES
    }
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
            "route": OWNER_CHROME_HIDDEN_SECONDARY_ROUTE,
            "state": owner_hidden_state,
            "mode": "primary_owner_profile_hidden_secondary",
            "profile_dir_name": effective_profile,
            "satisfies_owner_profile_auth": True,
            "auth_inheritance": True,
            "profile_copied": False,
            "visible_side_effect_free": True,
            "hidden_target_supported": bool(owner_hidden_probe.get("hidden_target_supported")),
            "screenshot_supported": False,
            "explicit_opt_in_only": True,
            "cdp_discovered": bool(owner_hidden_probe.get("cdp_discovered", owner_hidden_probe.get("ok"))),
            "discovery_mode": owner_hidden_probe.get("discovery_mode"),
            "http_discovery_status": owner_hidden_probe.get("http_discovery_status"),
            "approval_required": bool(owner_hidden_probe.get("approval_required")),
            "confirmation_required": bool(owner_hidden_probe.get("confirmation_required")),
            "denied": bool(owner_hidden_probe.get("denied")),
            "refused": bool(owner_hidden_probe.get("refused")),
            "chrome_version": owner_hidden_probe.get("chrome_version"),
            **({"consent_gate": owner_hidden_probe["consent_gate"]} if owner_hidden_probe.get("consent_gate") else {}),
            "hub_policy_separate": True,
            "hub_risk_class": "owner_chrome_hidden_secondary",
            "site_scoped_grants_supported": True,
            **({"remedy": owner_hidden_probe["remedy"]} if owner_hidden_probe.get("remedy") else {}),
            **({"automatic": owner_hidden_probe["automatic"]} if "automatic" in owner_hidden_probe else {}),
            "error_code": owner_hidden_probe.get("error_code"),
            "reason": owner_hidden_probe.get("reason") or f"verified Chrome 158+ hidden target on {effective_profile}",
            "probe_ms": owner_hidden_probe.get("probe_ms", 0),
        },
        {
            "route": OWNER_CHROME_ROUTE,
            "state": owner_state,
            "mode": "owner_chrome_visible_tab_strip",
            "hidden_secondary_window_supported": False,
            "visible_tab_strip": True,
            "explicit_opt_in_only": True,
            "reason": owner_probe.get("reason") or "owner Chrome extension relay passed live preflight",
            "probe_ms": owner_probe.get("probe_ms", 0),
        },
        {
            "route": "persistent_playwright",
            "state": ("READY" if pw_probe.get("running") else "ELIGIBLE") if pw_usable else "UNAVAILABLE",
            "mode": "optional_isolated_mode",
            "satisfies_owner_profile_auth": False,
            "reason": (
                f"optional isolated headless Playwright persistent context ({pw_probe.get('playwright_version')}); "
                "does NOT inherit owner Chrome configured-profile auth"
                if pw_usable else str(pw_probe.get("reason") or "Playwright managed adapter unavailable")
            ),
            "playwright_version": pw_probe.get("playwright_version"),
            "authorization": "optional isolated headless Playwright context; no owner profile",
            "probe_ms": pw_probe.get("probe_ms", 0),
        },
        {
            "route": "private_cdp",
            "state": "ELIGIBLE" if cdp_usable else "UNAVAILABLE",
            "mode": "optional_isolated_mode",
            "satisfies_owner_profile_auth": False,
            "reason": (
                "optional isolated Chrome on private Win32 desktop; does NOT inherit owner Chrome configured-profile auth"
                if cdp_usable else "private Chrome executable unavailable or scope missing"
            ),
            "authorization": "optional isolated private desktop profile; no owner Chrome configured-profile access",
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
        allow_owner_chrome=bool(owner_ext_allowed or owner_hidden_allowed),
    )

    fallback_refused_reason: str | None = None
    if selected is None and surface == "browser":
        if owner_hidden_explicit:
            if not owner_hidden_allowed:
                fallback_refused_reason = "OWNER_CHROME_NOT_AUTHORIZED"
            else:
                fallback_refused_reason = (
                    owner_hidden_probe.get("error_code")
                    or "OWNER_CHROME_HIDDEN_SECONDARY_UNAVAILABLE_NO_ISOLATED_FALLBACK"
                )
        elif prefer and prefer != OWNER_CHROME_ROUTE:
            fallback_refused_reason = "PREFERRED_ROUTE_UNAVAILABLE"
        elif owner_ext_explicit and not owner_ext_allowed:
            fallback_refused_reason = "OWNER_CHROME_NOT_AUTHORIZED"
        elif owner_ext_explicit:
            fallback_refused_reason = "OWNER_CHROME_UNAVAILABLE"
        elif not pw_usable and not cdp_usable:
            fallback_refused_reason = "ISOLATED_HIDDEN_ROUTES_UNAVAILABLE_NO_OWNER_FALLBACK"

    return {
        "surface": surface,
        "capability": capability,
        "selected": selected,
        "primary_owner_auth_route": OWNER_CHROME_HIDDEN_SECONDARY_ROUTE,
        "isolated_substitution_forbidden": True,
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
