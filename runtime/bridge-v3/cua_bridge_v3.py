from __future__ import annotations

import hashlib
import threading
import os
import shutil
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping

from cua_app_api import (
    AppApiError, AppApiRegistry, AppApiRouteAdapter,
    CdpAppApiExecutor, ExcelComAppApiExecutor, ExcelPowerShellComAppApiExecutor, WinAppCliAppApiExecutor,
)
from cua_app_resolver import AppResolverError, WindowsInstalledAppResolver
from cua_cli_discovery import discover_cli_candidates, gui_escalation_allowed, issue_gui_fallback_receipt, probe_cli_versions, rank_cli_candidates
from cua_experience_cache import AppRouteExperienceStore
from cua_browser_profiles import ManagedBrowserProfiles
from cua_browser_companion import BrowserCompanionClient, CompanionError
from cua_native_router_adapter import NativeSidecarRouterAdapter
from cua_native_supervisor import NativeSidecarSupervisor
from cua_physical_runtime import PhysicalRuntimeError, WindowsPhysicalRuntime
from cua_router import ControlRouter, ControlRouterError, RouteExecutionError, RoutePolicy
from cua_sidecar_supervisor import JsonLineSidecarSupervisor, SidecarError
from cua_semantic_resources import SemanticResourceCoordinator
from cua_global_resources import CoordinatedResources, GlobalResourceCoordinator, GlobalResourceError
from cua_universal_fastpath import FastPathError, UniversalFastPath
from cua_vision_runtime import VisionRuntimeError, WindowsVisionRuntime


_BROWSER_PREACTION_FAILURES = frozenset({
    "ACTION_UNSUPPORTED", "NO_MATCH", "NO_SEMANTIC_TARGET",
    "STALE_TARGET", "TARGET_AMBIGUOUS", "TARGET_MOVED", "TARGET_DETACHED",
    "SNAPSHOT_REQUIRED", "BROWSER_EXTENSION_DOWNLOAD_UNSUPPORTED",
})

_BROWSER_CONTROL_COMMANDS = frozenset({
    "identity", "wait", "reload", "back", "forward", "list_tabs",
    "claim_tab", "new_tab", "switch_tab", "close_tab", "recover",
})

_VISION_COMMANDS = frozenset({
    "capture", "vision_capture", "vision_detect", "vision_ocr", "vision_observe",
    "vision_ground", "vision_find", "vision_resolve", "vision_validate",
})


class CuaBridgeError(RuntimeError):
    def __init__(self, code: str, message: str | None = None, *, details: Mapping[str, Any] | None = None):
        super().__init__(message or code)
        self.code = code
        self.message = message or code
        self.details = dict(details or {})


def _unwrap(response: Mapping[str, Any], *, browser: bool = False) -> dict[str, Any]:
    if bool(response.get("ok", False)) and isinstance(response.get("result"), Mapping):
        return dict(response["result"])
    if browser:
        code = str(response.get("error_code") or "BROWSER_RPC_FAILED")
        details = response.get("details") if isinstance(response.get("details"), Mapping) else {}
        message = str(response.get("message") or code)
    else:
        error = response.get("error") if isinstance(response.get("error"), Mapping) else {}
        code = str(error.get("code") or "NATIVE_RPC_FAILED")
        details = error.get("details") if isinstance(error.get("details"), Mapping) else {}
        message = str(error.get("message") or code)
    raise CuaBridgeError(code, message, details=details)


class _BrowserRouteAdapter:
    def __init__(self, supervisor: JsonLineSidecarSupervisor, surface_id: str, companion: BrowserCompanionClient | None = None):
        self.supervisor = supervisor
        self.surface_id = surface_id
        self.companion = companion

    def can_handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("surface_kind") != "browser":
            return {"supported": False, "reason": "not_browser"}
        operation = request.get("operation")
        if not isinstance(operation, str) or not operation:
            return {"supported": False, "reason": "operation_missing"}
        return {"supported": True, "background_safe": True, "desktop_exclusive": False}

    def _download_failure(self, code: str, operation_id: str, *, attempted: bool, status: Mapping[str, Any] | None = None, cleanup: Any = None) -> RouteExecutionError:
        status = dict(status or {})
        public_status = dict(status)
        if isinstance(public_status.get("item"), Mapping):
            public_item = dict(public_status["item"])
            if public_item.get("filename"):
                public_item["filename"] = Path(str(public_item["filename"])).name
            public_status["item"] = public_item
        receipt = {
            "operation": "download", "attempted": attempted, "verified": False,
            "physical_input_used": False, "privileged_capability_route": "FF_BROWSER_COMPANION",
            "operation_id": operation_id, "matched": bool(status.get("matched", False)),
            "completed": bool(status.get("completed", False)), "cleanup": cleanup,
            "terminal_failure_reason": code, "retry_safe": False,
        }
        return RouteExecutionError(code, attempted=attempted, details={"receipt": receipt, "companion_status": public_status})

    def _act_download(self, request: Mapping[str, Any], action_args: Mapping[str, Any]) -> dict[str, Any]:
        if self.companion is None:
            raise RouteExecutionError("BROWSER_COMPANION_UNAVAILABLE", attempted=False)
        expected_url = str(action_args.get("expected_url") or "")
        if not expected_url.startswith(("http://", "https://")):
            raise RouteExecutionError("DOWNLOAD_EXPECTED_URL_REQUIRED", attempted=False)
        timeout_ms = min(max(int(action_args.get("timeout_ms", 10000)), 250), 30000)
        operation_id = "dl-" + uuid.uuid4().hex
        try:
            capabilities = self.companion.capabilities()
        except CompanionError as exc:
            raise RouteExecutionError("BROWSER_COMPANION_UNAVAILABLE", exc.message, attempted=False, details=exc.details) from exc
        if capabilities.get("protocol_version") != 1 or capabilities.get("downloads") is not True:
            raise RouteExecutionError("BROWSER_COMPANION_UNAVAILABLE", attempted=False, details={"capabilities": capabilities})
        spec = {"operation_id": operation_id, "expected_url": expected_url, "timeout_ms": timeout_ms}
        for src, dst in (("expected_filename", "expected_filename"), ("expected_mime", "expected_mime"), ("expected_size", "expected_size")):
            if action_args.get(src) is not None:
                spec[dst] = action_args[src]
        try:
            prepared = self.companion.prepare_download(spec)
        except CompanionError as exc:
            raise RouteExecutionError(exc.code, exc.message, attempted=False, details=exc.details) from exc
        if prepared.get("state") != "PREPARED":
            raise RouteExecutionError("BROWSER_COMPANION_PREPARE_FAILED", attempted=False, details={"status": prepared})

        browser_args = dict(action_args)
        browser_args.pop("save_as", None)
        browser_args["_ff_companion_operation_id"] = operation_id
        payload = {"surface_id": self.surface_id, "action": {
            "ref": request.get("ref"), "generation": request.get("generation"),
            "action": "download", "args": browser_args, "verify": None,
        }}
        try:
            semantic = _unwrap(self.supervisor.request("act", payload), browser=True)
        except (SidecarError, CuaBridgeError) as exc:
            try: self.companion.cleanup_download(operation_id)
            except Exception: pass
            code = str(getattr(exc, "code", "BROWSER_DOWNLOAD_SEMANTIC_FAILED"))
            attempted = code not in _BROWSER_PREACTION_FAILURES
            raise RouteExecutionError(code, str(exc), attempted=attempted, details=getattr(exc, "details", {})) from exc

        try:
            status = self.companion.wait_download(operation_id, timeout_ms)
        except CompanionError as exc:
            raise self._download_failure(exc.code, operation_id, attempted=True) from exc
        if status.get("state") != "COMPLETE" or status.get("matched") is not True:
            cleanup = None
            if status.get("state") != "AMBIGUOUS":
                try: cleanup = self.companion.cleanup_download(operation_id)
                except Exception: cleanup = None
            code = {"TIMEOUT": "DOWNLOAD_TIMEOUT", "AMBIGUOUS": "DOWNLOAD_AMBIGUOUS", "INTERRUPTED": "DOWNLOAD_INTERRUPTED"}.get(str(status.get("state")), "DOWNLOAD_FAILED")
            raise self._download_failure(code, operation_id, attempted=True, status=status, cleanup=cleanup)

        item = status.get("item") if isinstance(status.get("item"), Mapping) else {}
        filename = Path(str(item.get("filename") or ""))
        if not filename.is_file():
            try: cleanup = self.companion.cleanup_download(operation_id)
            except Exception: cleanup = None
            raise self._download_failure("DOWNLOAD_FILE_MISSING", operation_id, attempted=True, status=status, cleanup=cleanup)
        size = filename.stat().st_size
        sha256 = hashlib.sha256(filename.read_bytes()).hexdigest()
        expected_size = action_args.get("expected_size")
        expected_sha256 = str(action_args.get("expected_sha256") or "").lower()
        if expected_size is not None and size != int(expected_size):
            try: cleanup = self.companion.cleanup_download(operation_id)
            except Exception: cleanup = None
            raise self._download_failure("DOWNLOAD_SIZE_MISMATCH", operation_id, attempted=True, status=status, cleanup=cleanup)
        if expected_sha256 and sha256.lower() != expected_sha256:
            try: cleanup = self.companion.cleanup_download(operation_id)
            except Exception: cleanup = None
            raise self._download_failure("DOWNLOAD_HASH_MISMATCH", operation_id, attempted=True, status=status, cleanup=cleanup)
        try:
            cleanup = self.companion.cleanup_download(operation_id)
        except CompanionError as exc:
            raise self._download_failure(exc.code, operation_id, attempted=True, status=status) from exc
        cleanup_ok = cleanup.get("cleanup_complete") is True and not filename.exists()
        if not cleanup_ok:
            raise self._download_failure("DOWNLOAD_CLEANUP_UNVERIFIED", operation_id, attempted=True, status=status, cleanup=cleanup)
        return {
            "operation": "download", "verified": True, "attempted": True, "physical_input_used": False,
            "privileged_capability_route": "FF_BROWSER_COMPANION", "operation_id": operation_id,
            "matched": True, "completed": True, "cleanup": True,
            "action_result": {"semantic_route": "BROWSER_PLAYWRIGHT", "privileged_capability_route": "FF_BROWSER_COMPANION", "operation_id": operation_id, "semantic_verified": bool(semantic.get("verified")), "matched": True, "completed": True, "cleanup": True},
            "verification": {"kind": "download", "filename": filename.name, "size": size, "sha256": sha256},
        }

    def act(self, request: Mapping[str, Any]) -> dict[str, Any]:
        action_args = request.get("action_args")
        args = dict(action_args) if isinstance(action_args, Mapping) else {}
        if request.get("operation") == "download" and self.companion is not None:
            return self._act_download(request, args)
        payload = {"surface_id": self.surface_id, "action": {
            "ref": request.get("ref"), "generation": request.get("generation"),
            "action": request.get("operation"), "args": args,
            "verify": dict(request["postcondition"]) if isinstance(request.get("postcondition"), Mapping) else None,
        }}
        try:
            return _unwrap(self.supervisor.request("act", payload), browser=True)
        except SidecarError as exc:
            raise RouteExecutionError(exc.code, attempted=True, details={"sidecar": "browser", **exc.details, "retry_safe": False}) from exc
        except CuaBridgeError as exc:
            attempted = exc.code not in _BROWSER_PREACTION_FAILURES
            raise RouteExecutionError(exc.code, exc.message, attempted=attempted, details=exc.details) from exc


class _VisionAwarePhysicalAdapter:
    """Translate a fresh, generation-bound visual ref into one guarded physical gesture."""

    _LEFT_DOWN = 0x0002
    _LEFT_UP = 0x0004

    def __init__(self, physical_adapter: Any, vision: Any, surface_id: str):
        self.physical_adapter = physical_adapter
        self.vision = vision
        self.surface_id = surface_id

    def can_handle(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("operation") != "visual_click":
            return self.physical_adapter.can_handle(request)
        ref = request.get("ref")
        if not isinstance(ref, str) or not ref:
            return {"supported": False, "reason": "visual_ref_required"}
        return {"supported": True, "background_safe": False, "desktop_exclusive": True}

    @staticmethod
    def _failure_receipt(code: str, request: Mapping[str, Any], details: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "operation": "visual_click", "ref": request.get("ref"),
            "attempted": False, "verified": False, "physical_input_used": False,
            "physical_effect_unknown": False, "background_safe": False,
            "desktop_exclusive": True, "retry_safe": False,
            "fallback_chain": ["VISION_SEMANTIC"],
            "terminal_failure_reason": code,
            "visual_failure": dict(details),
        }

    def act(self, request: Mapping[str, Any]) -> dict[str, Any]:
        if request.get("operation") != "visual_click":
            return self.physical_adapter.act(request)
        args = request.get("action_args") if isinstance(request.get("action_args"), Mapping) else {}
        button = str(args.get("button") or "left").lower()
        if button != "left":
            code = "VISUAL_CLICK_BUTTON_UNSUPPORTED"
            receipt = self._failure_receipt(code, request, {"button": button})
            raise RouteExecutionError(code, attempted=False, details={"receipt": receipt, "retry_safe": False})
        minimum_confidence = args.get("minimum_confidence", 0.90)
        max_drift = args.get("max_center_drift_px", 16.0)
        if isinstance(minimum_confidence, bool) or not isinstance(minimum_confidence, (int, float)):
            code = "VISUAL_CONFIDENCE_INVALID"
            receipt = self._failure_receipt(code, request, {})
            raise RouteExecutionError(code, attempted=False, details={"receipt": receipt, "retry_safe": False})
        if isinstance(max_drift, bool) or not isinstance(max_drift, (int, float)) or float(max_drift) < 0:
            code = "VISUAL_DRIFT_LIMIT_INVALID"
            receipt = self._failure_receipt(code, request, {})
            raise RouteExecutionError(code, attempted=False, details={"receipt": receipt, "retry_safe": False})
        try:
            prepared = self.vision.prepare_action(
                self.surface_id, str(request.get("ref")),
                minimum_confidence=float(minimum_confidence),
                max_center_drift_px=float(max_drift),
            )
        except VisionRuntimeError as exc:
            receipt = self._failure_receipt(exc.code, request, exc.details)
            raise RouteExecutionError(
                exc.code, attempted=False,
                details={"receipt": receipt, "retry_safe": False, **exc.details},
            ) from exc
        point = prepared.get("point_virtual_physical_px")
        if not isinstance(point, list) or len(point) != 2 or any(isinstance(v, bool) or not isinstance(v, int) for v in point):
            code = "VISUAL_POINT_INVALID"
            receipt = self._failure_receipt(code, request, {"point": point})
            raise RouteExecutionError(code, attempted=False, details={"receipt": receipt, "retry_safe": False})
        translated = dict(request)
        translated["operation"] = "physical_sequence"
        translated["action_args"] = {
            "events": [{
                "kind": "mouse_click_at", "x": point[0], "y": point[1],
                "down_flags": self._LEFT_DOWN, "up_flags": self._LEFT_UP,
            }]
        }
        receipt = dict(self.physical_adapter.act(translated))
        receipt.update({
            "operation": "visual_click", "ref": request.get("ref"),
            "fallback_chain": ["VISION_SEMANTIC"],
            "visual_capture_id": prepared.get("capture_id"),
            "visual_generation": prepared.get("generation"),
            "visual_fresh": prepared.get("fresh"),
            "visual_drift_px": prepared.get("visual_drift_px"),
            "visual_target": prepared.get("resolved_target"),
            "wrong_target": 0,
        })
        return receipt


class CuaBridgeControlPlane:
    """Persistent semantic computer-use control plane hosted by Bridge v3."""

    def __init__(
        self,
        package_root: str | Path,
        *,
        browser_factory: Callable[[str], Any] | None = None,
        native_factory: Callable[[str], Any] | None = None,
        physical_factory: Callable[[Path], Any] | None = None,
        companion_factory: Callable[[Path], Any] | None = None,
        vision_factory: Callable[[Path], Any] | None = None,
        fastpath_factory: Callable[[], Any] | None = None,
        app_resolver_factory: Callable[[], Any] | None = None,
        app_api_registry_factory: Callable[[Any], Any] | None = None,
        experience_store_factory: Callable[[Path], Any] | None = None,
        state_dir: str | Path | None = None,
    ):
        self.root = Path(package_root).resolve()
        # Route preferences are mutable runtime state, never package source bytes.
        # Respect the caller's isolated state root; otherwise use this Bridge's
        # FF_BRIDGE_ROOT (not the shared Python source/package directory).
        if state_dir is not None:
            self._experience_state_dir = Path(state_dir)
        else:
            default_root = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "FF-Windows-Bridge"
            self._experience_state_dir = Path(os.environ.get("FF_BRIDGE_ROOT") or default_root) / "state"
        self._browser_factory = browser_factory
        self._native_factory = native_factory
        self._physical_factory = physical_factory
        self._companion_factory = companion_factory
        self._vision_factory = vision_factory
        self._fastpath_factory = fastpath_factory
        self._app_resolver_factory = app_resolver_factory
        self._app_api_registry_factory = app_api_registry_factory
        self._experience_store_factory = experience_store_factory
        self._companion: Any | None = None
        self._physical: Any | None = None
        self._vision: Any | None = None
        self._fastpath: Any | None = None
        self._app_resolver: Any | None = None
        self._app_api_registry: Any | None = None
        self._experience_store: Any | None = None
        self._browser: dict[str, JsonLineSidecarSupervisor] = {}
        self._browser_supervisor_lock = threading.RLock()
        self._browser_profiles = None
        self._native: dict[str, NativeSidecarSupervisor] = {}
        self._surfaces: dict[str, dict[str, Any]] = {}
        self._global_resources = GlobalResourceCoordinator(state_dir, timeout=5.0)
        self._resources = CoordinatedResources(SemanticResourceCoordinator(), self._global_resources)

    def _browser_supervisor(self, transport: str) -> JsonLineSidecarSupervisor:
        with self._browser_supervisor_lock:
            if transport in self._browser:
                return self._browser[transport]
            if self._browser_factory:
                supervisor = self._browser_factory(transport)
            elif transport == "extension":
                powershell = shutil.which("powershell.exe") or shutil.which("powershell")
                if not powershell:
                    raise CuaBridgeError("POWERSHELL_NOT_FOUND")
                supervisor = JsonLineSidecarSupervisor(
                    "browser-extension",
                    [powershell, "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                     str(self.root / "cua_browser_extension_rpc.ps1")],
                    cwd=self.root,
                    timeout_seconds=15.0,
                    multiplex=True,
                )
            elif transport == "isolated":
                node = shutil.which("node.exe") or shutil.which("node")
                if not node:
                    raise CuaBridgeError("NODE_NOT_FOUND")
                self._browser_profiles = ManagedBrowserProfiles(self._global_resources.state_dir)
                supervisor = JsonLineSidecarSupervisor(
                    "browser-isolated",
                    [node, str(self.root / "cua_browser_rpc.mjs"), "--isolated-only"],
                    env={"FF_ISOLATED_BROWSER_PROFILE_ROOT": str(self._browser_profiles.path)},
                    cwd=self.root,
                    timeout_seconds=30.0,
                    multiplex=True,
                )
            else:
                raise CuaBridgeError("BROWSER_TRANSPORT_INVALID", details={"transport": transport})
            self._browser[transport] = supervisor
            return supervisor

    def _browser_companion(self) -> Any:
        if self._companion is None:
            self._companion = self._companion_factory(self.root) if self._companion_factory else BrowserCompanionClient(self.root)
        return self._companion

    def _new_native_supervisor(self, route: str) -> NativeSidecarSupervisor:
        if self._native_factory:
            return self._native_factory(route)
        if route == "HWND_MESSAGE":
            return NativeSidecarSupervisor(self.root / "cua_native_sidecar.py", engine="hwnd")
        if route == "UIA_PATTERN":
            executable = self.root / "cua_native_uia3_sidecar.exe"
            if not executable.is_file():
                raise CuaBridgeError("UIA3_SIDECAR_NOT_INSTALLED", details={"path": str(executable)})
            return NativeSidecarSupervisor(
                self.root / "cua_native_sidecar.py", timeout_seconds=7.0, engine="uia3", uia3_executable=executable
            )
        raise CuaBridgeError("NATIVE_ROUTE_INVALID", details={"route": route})

    @staticmethod
    def _native_target_resource_key(target: Mapping[str, Any]) -> str:
        hwnd = target.get("hwnd")
        if isinstance(hwnd, str):
            try:
                hwnd = int(hwnd, 0)
            except ValueError:
                hwnd = None
        if isinstance(hwnd, int) and not isinstance(hwnd, bool) and hwnd > 0:
            return f"hwnd:{hwnd}"
        pid = target.get("pid")
        if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
            return f"pid:{pid}"
        return "shared"

    @classmethod
    def _native_resource_key(cls, route: str, target: Mapping[str, Any]) -> str:
        return f"{route}:{cls._native_target_resource_key(target)}"

    @classmethod
    def _semantic_native_resource_key(cls, target: Mapping[str, Any]) -> str:
        return f"native:{cls._native_target_resource_key(target)}"

    @staticmethod
    def _surface_resource_keys(surface_id: str, surface: Mapping[str, Any]) -> tuple[str, ...]:
        declared = surface.get("semantic_keys")
        keys: list[str] = []
        if isinstance(declared, (list, tuple)):
            for item in declared:
                if isinstance(item, str) and item.strip() and item.strip() not in keys:
                    keys.append(item.strip())
        key = surface.get("semantic_key")
        if isinstance(key, str) and key.strip() and key.strip() not in keys:
            keys.append(key.strip())
        if keys:
            return tuple(keys)
        return (f"browser-surface/tab:{surface_id}" if surface.get("kind") == "browser" else f"{surface.get('kind', 'surface')}:{surface_id}",)

    @classmethod
    def _surface_resource_key(cls, surface_id: str, surface: Mapping[str, Any]) -> str:
        return cls._surface_resource_keys(surface_id, surface)[0]

    def _native_supervisor(self, route: str, resource_key: str | None = None) -> NativeSidecarSupervisor:
        key = resource_key or route
        if key in self._native:
            return self._native[key]
        if resource_key is not None:
            dedicated = sum(1 for item in self._native if item.startswith(f"{route}:"))
            if dedicated >= 8:
                raise CuaBridgeError("NATIVE_WORKER_LIMIT", details={"route": route, "limit": 8})
        supervisor = self._new_native_supervisor(route)
        self._native[key] = supervisor
        return supervisor

    def _physical_runtime(self) -> Any:
        if self._physical is None:
            self._physical = self._physical_factory(self.root) if self._physical_factory else WindowsPhysicalRuntime(self.root)
        return self._physical

    def _vision_runtime(self) -> Any:
        if self._vision is None:
            self._vision = self._vision_factory(self.root) if self._vision_factory else WindowsVisionRuntime(self.root)
        return self._vision

    def _fastpath_runtime(self) -> Any:
        if self._fastpath is None:
            self._fastpath = self._fastpath_factory() if self._fastpath_factory else UniversalFastPath()
        return self._fastpath

    def _experience_runtime(self) -> Any:
        if self._experience_store is None:
            if self._experience_store_factory is not None:
                self._experience_store = self._experience_store_factory(self.root)
            else:
                path = (self._experience_state_dir / "cua_app_route_experience.json"
                        if self.root.name.casefold() == "bridge-v3" else None)
                self._experience_store = AppRouteExperienceStore(path)
        return self._experience_store

    def _app_api_runtime(self) -> Any:
        if self._app_api_registry is None:
            fastpath = self._fastpath_runtime()
            self._app_api_registry = (
                self._app_api_registry_factory(fastpath)
                if self._app_api_registry_factory
                else AppApiRegistry(
                    [
                        ExcelComAppApiExecutor(fastpath),
                        ExcelPowerShellComAppApiExecutor(fastpath),
                        CdpAppApiExecutor(fastpath),
                        WinAppCliAppApiExecutor(fastpath),
                    ],
                    experience=self._experience_runtime(),
                )
            )
        return self._app_api_registry

    def _installed_apps(self) -> Any:
        if self._app_resolver is None:
            self._app_resolver = self._app_resolver_factory() if self._app_resolver_factory else WindowsInstalledAppResolver()
        return self._app_resolver

    def _companion_health(self) -> dict[str, Any]:
        try:
            capabilities = self._browser_companion().capabilities()
            compatible = capabilities.get("protocol_version") == 1 and capabilities.get("downloads") is True
            return {"running": True, "compatible": bool(compatible), "capabilities": capabilities}
        except CompanionError as exc:
            return {"running": False, "compatible": False, "error_code": exc.code}

    def dispatch(self, args: Mapping[str, Any]) -> dict[str, Any]:
        command = str(args.get("command") or "")
        if command == "windows_mcp":
            from cua_windows_mcp import invoke_windows_mcp
            try:
                return invoke_windows_mcp(args.get("tool"), args.get("arguments"))
            except (ValueError, RuntimeError) as exc:
                raise CuaBridgeError(str(exc), details={"retry_safe": False}) from exc
        if command == "prepare_tool":
            from cua_tool_preparation import prepare_windows_mcp, ToolPreparationError
            if args.get("tool") != "windows-mcp":
                raise CuaBridgeError("TOOL_RECIPE_NOT_VERIFIED")
            try:
                return prepare_windows_mcp()
            except ToolPreparationError as exc:
                raise CuaBridgeError(exc.code) from exc
        if command == "task_preflight":
            return self._task_preflight(args)
        if command == "task_execute":
            if args.get("task") == "antigravity.assistant":
                from cua_antigravity_task import execute_headless_task, VendorTaskError
                from ff_win_v3_agent import BRIDGE_ROOT
                try:
                    # package_root/self.root is SOURCE CODE, not an owned
                    # task workspace. Mutating it breaks installed provenance!
                    # All scratch work belongs under the Bridge's own
                    # per-installation state directory instead.
                    return execute_headless_task(args, bridge_root=BRIDGE_ROOT / "state")
                except VendorTaskError as exc:
                    raise CuaBridgeError(exc.code) from exc
            return self._task_execute(args)
        if command == "plan_action":
            # Uses the existing surface registry and route adapters, not a
            # second parallel router. Planning never performs adapter.act().
            return self._act({**args, "_preflight_only": True})
        if command == "programmatic_plan":
            from cua_tool_preparation import documentation_for
            app = str(args.get("app") or "").strip()
            if not app:
                raise CuaBridgeError("APP_REQUIRED")
            result = self.dispatch({"command": "discover_cli", "app": app,
                                    "probe_versions": args.get("probe_versions") is True})
            result["documentation"] = documentation_for(app)
            if args.get("task"):
                from cua_task_routes import task_routes
                result.update(task_routes(app, args["task"], result["candidates"], probe=args.get("probe_versions") is True))
            result["next_step"] = "check_cli_task_support" if result["preferred_cli"] else "research_or_prepare_programmatic_tool"
            if args.get("task"):
                result["next_step"] = "execute_task_compatible_programmatic_route_and_verify" if result.get("preferred_task_route") else "observe_assistant_ui_after_official_tool_research" if result.get("task_compatibility") == "requires_ui" else "research_task_compatible_cli_api_mcp"
            if (str(app).casefold() in {"git", "git.exe", "git for windows"}
                    and args.get("task") == "git.repository.status"
                    and result.get("potential_task_route") is not None):
                # A discovered CLI is only a candidate; actual task_execute
                # performs the first operation-specific verification.
                result["next_step"] = "RUN_SCOPED_GIT_STATUS_TASK_WITH_REAL_POSTCONDITION"
                result["task_execute_contract"] = {
                    "command": "task_execute", "app": "Git",
                    "task": "git.repository.status", "operation": "status.read",
                    "required_action_args": ["repo_path"],
                    "requires_agent_and_task_ids": True,
                    "execution_performed": False, "task_compatibility_verified": False,
                    "model_called": False, "foreground_required": False,
                }
            result["search_and_reasoning_are_planner_responsibilities"] = True
            return result
        if command == "discover_cli":
            app = str(args.get("app") or "").strip()
            if not app:
                raise CuaBridgeError("APP_REQUIRED")
            candidates = discover_cli_candidates(app)
            if args.get("probe_versions") is True:
                candidates = probe_cli_versions(candidates)
            ranked = rank_cli_candidates(candidates)
            return {"app": app, "candidates": candidates,
                    "preferred_cli": ranked[0] if ranked else None,
                    "task_compatibility": "unknown", "gui_first": False,
                    "diagnostic_receipt": issue_gui_fallback_receipt(candidates, app=app) if args.get("probe_versions") is True else None}
        if command == "health":
            try:
                global_health = {"available": True, **self._global_resources.snapshot()}
            except (GlobalResourceError, OSError) as exc:
                global_health = {"available": False, "fail_closed": True,
                                 "error_code": getattr(exc, "code", "GLOBAL_RESOURCE_STORAGE_UNAVAILABLE")}
            return {
                "ok": True,
                "semantic_default": True,
                "legacy_physical_requires_explicit_opt_in": True,
                "browser": {key: value.health() for key, value in self._browser.items()},
                "browser_companion": self._companion_health(),
                "native": {key: value.health() for key, value in self._native.items()},
                "physical": self._physical.health() if self._physical is not None else {"initialized": False},
                "vision": self._vision.health() if self._vision is not None else {"initialized": False},
                "semantic_resources": self._resources.local.snapshot(),
                "global_resources": global_health,
                "app_api": self._app_api_runtime().health(),
            }
        if command in {"resolve_app", "launch_app", "ensure_app"}:
            return self._app_command(command, args)
        if command == "app_api_probe":
            return self._app_api_probe(args)
        if command == "auto":
            return self._auto(args)
        if command == "attach":
            return self._attach(args)
        if command in _VISION_COMMANDS:
            return self._vision_command(command, args)
        if command in {"observe", "find", "navigate", "wait"}:
            return self._inspect(command, args)
        if command in _BROWSER_CONTROL_COMMANDS:
            return self._browser_command(command, args)
        if command == "act":
            return self._act(args)
        if command == "acquire_physical_lease":
            return self._acquire_physical_lease(args)
        if command == "focus_target":
            _, surface = self._surface(args)
            try:
                pointer_activation = args.get("allow_pointer_activation", False)
                policy = args.get("policy") if isinstance(args.get("policy"), Mapping) else {}
                if type(pointer_activation) is not bool or (pointer_activation and
                    (policy.get("physical_input_allowed") is not True or
                     policy.get("foreground_allowed") is not True or policy.get("background_required") is not False)):
                    raise CuaBridgeError("PHYSICAL_INPUT_POLICY_REJECTED")
                focus_args = {"generation": args.get("generation", surface.get("generation")),
                              "owner_id": str(args.get("agent_id"))}
                if pointer_activation:
                    focus_args["allow_pointer_activation"] = True
                return self._physical_runtime().focus(surface, **focus_args)
            except (PhysicalRuntimeError, __import__("cua_input_arbiter").ArbiterError) as exc:
                raise CuaBridgeError(exc.code, details=exc.details) from exc
        if command == "release_physical_lease":
            return self._release_physical_lease(args)
        if command == "close":
            return self._close(args)
        raise CuaBridgeError("CUA_COMMAND_UNSUPPORTED", details={"command": command})

    @staticmethod
    def _auto_pick(
        entities: list[Any],
        *,
        kind: str,
        target: str = "",
    ) -> Mapping[str, Any] | None:
        target_n = " ".join(target.lower().split())
        ranked: list[tuple[int, Mapping[str, Any]]] = []
        for raw in entities:
            if not isinstance(raw, Mapping):
                continue
            role = str(raw.get("role") or raw.get("control_type") or "").lower()
            name = " ".join(str(raw.get("name") or raw.get("text") or "").lower().split())
            actions = {str(x) for x in (raw.get("actions") or [])}
            score = 0
            if kind == "input":
                if "set_value" not in actions:
                    continue
                if role in {"edit", "textbox", "document"}:
                    score += 40
                if any(x in name for x in ("message", "chat", "prompt", "ask", "сообщ", "вопрос")):
                    score += 50
            else:
                if "invoke" not in actions:
                    continue
                if role in {"button", "hyperlink", "menuitem"}:
                    score += 30
                if target_n and target_n in name:
                    score += 100
                terms = ("send", "submit", "reply", "отправ") if kind == "send" else (
                    "new chat", "new conversation", "start chat", "новый чат", "новая беседа"
                )
                if any(x in name for x in terms):
                    score += 70
            ranked.append((score, raw))
        ranked.sort(key=lambda x: x[0], reverse=True)
        return ranked[0][1] if ranked and ranked[0][0] > 0 else None

    def _app_api_probe(self, args: Mapping[str, Any]) -> dict[str, Any]:
        app = str(args.get("app") or "").strip()
        if not app:
            raise CuaBridgeError("APP_REQUIRED")
        try:
            handle = self._app_api_runtime().probe(app, refresh=bool(args.get("refresh")))
        except AppApiError as exc:
            raise CuaBridgeError(exc.code, exc.message, details=exc.details) from exc
        public_handle = handle.public() if handle is not None else None
        if handle is not None:
            try:
                self._app_api_runtime().close(handle)
            except AppApiError as exc:
                raise CuaBridgeError(exc.code, exc.message, details=exc.details) from exc
        return {
            "ok": True, "available": handle is not None, "app": app,
            "app_api": public_handle,
        }

    def _app_command(self, command: str, args: Mapping[str, Any]) -> dict[str, Any]:
        app = str(args.get("app") or "").strip()
        if not app:
            raise CuaBridgeError("APP_REQUIRED")
        resolver = self._installed_apps()
        refresh = bool(args.get("refresh"))
        visible_launch_allowed = args.get("visible_launch_allowed", False)
        if type(visible_launch_allowed) is not bool:
            raise CuaBridgeError("VISIBLE_LAUNCH_FLAG_INVALID")
        launch_options = {key: args[key] for key in ("expected_app", "launch_arguments") if key in args}
        try:
            if command == "resolve_app":
                return {"ok": True, **resolver.resolve(app, refresh=refresh)}
            if command == "launch_app":
                return {"ok": True, **resolver.launch(app, refresh=refresh, visible_launch_allowed=visible_launch_allowed, **launch_options)}

            fast = self._fastpath_runtime()
            try:
                discovered = fast.discover(app, refresh=refresh)
                if args.get("launch_arguments"):
                    raise CuaBridgeError("APP_ALREADY_RUNNING_WITH_LAUNCH_ARGUMENTS", details={"retry_safe": False})
                return {"ok": True, "running": True, "launched": False, "discovery": discovered}
            except FastPathError as exc:
                if exc.code != "APP_WINDOW_NOT_FOUND":
                    raise

            resolved = resolver.resolve(app, refresh=refresh)
            canonical_name = str(resolved.get("app", {}).get("name") or "").strip()
            if canonical_name and canonical_name.casefold() != app.casefold():
                try:
                    discovered = fast.discover(canonical_name, refresh=True)
                    if args.get("launch_arguments"):
                        raise CuaBridgeError("APP_ALREADY_RUNNING_WITH_LAUNCH_ARGUMENTS", details={"retry_safe": False})
                    return {"ok": True, "running": True, "launched": False, "resolved": resolved, "discovery": discovered}
                except FastPathError as exc:
                    if exc.code != "APP_WINDOW_NOT_FOUND":
                        raise

            timeout_ms = args.get("timeout_ms", 5000)
            if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, (int, float)) or not 1 <= float(timeout_ms) <= 30000:
                raise CuaBridgeError("TIMEOUT_INVALID")
            timeout_ms = int(timeout_ms)
            launch = resolver.launch(app, refresh=False, visible_launch_allowed=visible_launch_allowed, **launch_options)
            candidates = [app, canonical_name]
            deadline = time.monotonic() + timeout_ms / 1000.0
            last_error: FastPathError | None = None
            while True:
                for candidate in candidates:
                    if not candidate:
                        continue
                    try:
                        discovered = fast.discover(candidate, refresh=True)
                        if args.get("launch_arguments") and discovered.get("window", {}).get("pid") != launch["launcher_pid"]:
                            raise CuaBridgeError("APP_LAUNCHED_TARGET_MISMATCH", details={"retry_safe": False, "launch": launch})
                        return {"ok": True, "running": True, **launch, "discovery": discovered}
                    except FastPathError as exc:
                        if exc.code != "APP_WINDOW_NOT_FOUND":
                            raise
                        last_error = exc
                if time.monotonic() >= deadline:
                    break
                time.sleep(0.1)
            raise CuaBridgeError("APP_LAUNCHED_WINDOW_NOT_FOUND", details={"app": app, "launch": launch, "last_error": getattr(last_error, "code", None), "timeout_ms": timeout_ms})
        except AppResolverError as exc:
            raise CuaBridgeError(exc.code, details=exc.details) from exc
        except FastPathError as exc:
            raise CuaBridgeError(exc.code, details=exc.details) from exc

    def _auto(self, args: Mapping[str, Any]) -> dict[str, Any]:
        app = str(args.get("app") or "").strip()
        if not app:
            raise CuaBridgeError("APP_REQUIRED")
        intent = str(args.get("intent") or "discover").strip()
        refresh = bool(args.get("refresh"))
        fast = self._fastpath_runtime()
        discovered: dict[str, Any] | None = None
        fast_error: FastPathError | None = None
        preprobed_handle = None
        preprobe_error: AppApiError | None = None

        try:
            discovered = dict(fast.discover(app, refresh=refresh))
        except FastPathError as exc:
            if exc.code != "APP_WINDOW_NOT_FOUND":
                raise CuaBridgeError(exc.code, details=exc.details) from exc
            fast_error = exc
            try:
                preprobed_handle = self._app_api_runtime().probe(
                    app, refresh=refresh, discovered=None,
                )
            except AppApiError as api_exc:
                preprobe_error = api_exc

        if "expected_window" in args:
            expected = args["expected_window"]
            if not isinstance(expected, Mapping) or set(expected) != {"hwnd", "pid", "created"} or any(type(v) is not int or v <= 0 for v in expected.values()):
                raise CuaBridgeError("APP_TARGET_INVALID", details={"attempted": False, "retry_safe": True})
            actual = (discovered or {}).get("window") or {}
            owner = ((discovered or {}).get("cdp") or {}).get("owner_identity") or {}
            if (discovered or {}).get("route") != "APP_CDP" or any(actual.get(k) != expected[k] for k in ("hwnd", "pid")) or owner.get("created") != expected["created"]:
                raise CuaBridgeError("APP_TARGET_CHANGED", details={"attempted": False, "retry_safe": True})
            if not fast._panel_owner_valid(discovered):
                raise CuaBridgeError("APP_TARGET_CHANGED", details={"attempted": False, "retry_safe": True})

        if intent == "discover":
            handle = preprobed_handle
            if handle is None:
                try:
                    handle = self._app_api_runtime().probe(
                        app, refresh=refresh, discovered=discovered,
                    )
                except AppApiError as exc:
                    preprobe_error = exc
                    handle = None

            public_handle = handle.public() if handle is not None else None
            if handle is not None:
                try:
                    self._app_api_runtime().close(handle)
                except AppApiError as exc:
                    raise CuaBridgeError(
                        exc.code, exc.message, details=exc.details,
                    ) from exc

            if public_handle is not None and public_handle.get("backend_route") != "APP_WINAPP_UIA":
                if discovered is None:
                    discovered = {
                        "app": app,
                        "route": "APP_API",
                        "window": public_handle.get("window"),
                        "cdp": None,
                        "programmatic_candidates": [],
                        "programmatic_discovery_complete": True,
                        "programmatic_discovery_error": None,
                        "cache_hit": False,
                        "cache_validated": False,
                    }
                candidates = list(discovered.get("programmatic_candidates") or [])
                candidates.insert(0, {
                    "kind": "app_api",
                    "status": "verified",
                    "verified": True,
                    "executor": public_handle.get("executor"),
                    "backend_route": public_handle.get("backend_route"),
                    "capabilities": public_handle.get("capabilities"),
                    "evidence": "app_api_probe",
                })
                discovered["programmatic_candidates"] = candidates
                discovered["app_api"] = public_handle
                if public_handle.get("backend_route") != "APP_CDP":
                    discovered["route"] = "APP_API"
                return discovered

            if discovered is not None:
                return discovered
            if public_handle is not None:
                return {
                    "app": app,
                    "route": "APP_API",
                    "window": public_handle.get("window"),
                    "cdp": None,
                    "programmatic_candidates": [{
                        "kind": "app_api",
                        "status": "verified",
                        "verified": True,
                        "executor": public_handle.get("executor"),
                        "backend_route": public_handle.get("backend_route"),
                        "capabilities": public_handle.get("capabilities"),
                        "evidence": "app_api_probe",
                    }],
                    "app_api": public_handle,
                    "programmatic_discovery_complete": True,
                    "programmatic_discovery_error": None,
                    "cache_hit": False,
                    "cache_validated": False,
                }
            if fast_error is not None:
                details = dict(fast_error.details)
                if preprobe_error is not None:
                    details["app_api_error"] = preprobe_error.code
                raise CuaBridgeError(fast_error.code, details=details) from fast_error
            raise CuaBridgeError("APP_WINDOW_NOT_FOUND", details={"app": app})

        if discovered is None:
            if preprobed_handle is None:
                details = dict(fast_error.details) if fast_error is not None else {"app": app}
                if preprobe_error is not None:
                    details["app_api_error"] = preprobe_error.code
                raise CuaBridgeError(
                    fast_error.code if fast_error is not None else "APP_WINDOW_NOT_FOUND",
                    details=details,
                ) from fast_error
            discovered = dict(preprobed_handle.discovery)

        attempts: list[dict[str, Any]] = []
        if discovered.get("route") == "APP_CDP":
            window = discovered.get("window") if isinstance(discovered.get("window"), Mapping) else {}
            resource_key = self._semantic_native_resource_key(window)
            scope = self._resources.read(resource_key) if intent in {"read", "inspect", "panel.inspect", "panel.verify"} else self._resources.write(resource_key)
            try:
                with scope:
                    panel_args = args.get("action_args", {})
                    if intent.startswith("panel.") and not isinstance(panel_args, Mapping):
                        raise CuaBridgeError("INVALID_ARGUMENT", details={"field": "action_args", "attempted": False})
                    result = dict(fast.panel_action(discovered, intent, action_args=panel_args)) if intent.startswith("panel.") else dict(fast.action(
                        discovered, intent,
                        text=str(args.get("text") or ""),
                        target=str(args.get("target") or ""),
                    ))
                if not bool(result.get("verified", False)):
                    receipt = dict(result)
                    receipt.setdefault("route", "APP_CDP")
                    receipt["attempted"] = bool(receipt.get("attempted", True))
                    receipt["retry_safe"] = False
                    receipt["physical_input_used"] = bool(receipt.get("physical_input_used", False))
                    receipt["terminal_failure_reason"] = "ACTION_UNVERIFIED"
                    raise CuaBridgeError(
                        "ACTION_UNVERIFIED",
                        details={"route": "APP_CDP", "receipt": receipt},
                    )
                return result
            except FastPathError as exc:
                raise CuaBridgeError(exc.code, details=exc.details) from exc
        else:
            try:
                handle = preprobed_handle
                if handle is None:
                    handle = self._app_api_runtime().probe(
                        app,
                        refresh=refresh,
                        discovered=discovered,
                    )
            except AppApiError as exc:
                attempts.append({
                    "route": "APP_API", "status": "declined", "reason": exc.code,
                })
            else:
                if handle is not None:
                    capability = handle.capabilities.get(intent)
                    if isinstance(capability, Mapping):
                        if handle.public().get("backend_route") == "APP_WINAPP_UIA" and not gui_escalation_allowed(discovered, args.get("gui_fallback")):
                            self._app_api_runtime().close(handle)
                            raise CuaBridgeError("PROGRAMMATIC_ROUTE_REQUIRES_PLANNER", details={
                                "app": app, "intent": intent,
                                "reason": "WinApp CLI is UI Automation; diagnose app-specific CLI candidates first",
                                "programmatic_candidates": list(discovered.get("programmatic_candidates") or []),
                            })
                        attached = self._register_app_surface(
                            app, handle, prefix="auto-app",
                        )
                        app_surface_id = attached["surface_id"]
                        try:
                            action_args = args.get("action_args")
                            if action_args is None:
                                action_args = {}
                            if not isinstance(action_args, Mapping):
                                raise CuaBridgeError("INVALID_ARGUMENT", details={
                                    "field": "action_args", "route": "APP_API",
                                })
                            try:
                                receipt = self._act({
                                    "surface_id": app_surface_id,
                                    "operation": intent,
                                    "action_args": dict(action_args),
                                })
                            except CuaBridgeError as exc:
                                details = dict(exc.details or {})
                                receipt_details = details.get("receipt")
                                attempted = bool(
                                    receipt_details.get("attempted", False)
                                    if isinstance(receipt_details, Mapping)
                                    else details.get("attempted", False)
                                )
                                if attempted:
                                    raise
                                attempts.append({
                                    "route": "APP_API",
                                    "status": "declined",
                                    "reason": exc.code,
                                    "executor": handle.executor,
                                    "attempted": False,
                                })
                            else:
                                app_window = self._surfaces[app_surface_id].get("target")
                                return {
                                    **receipt,
                                    "window": dict(app_window) if isinstance(app_window, Mapping) else {},
                                    "fallback_chain": attempts,
                                    "app_api_executor": handle.executor,
                                }
                        finally:
                            try:
                                self._close({"surface_id": app_surface_id})
                            except Exception:
                                self._surfaces.pop(app_surface_id, None)
                    if not isinstance(capability, Mapping):
                        try:
                            self._app_api_runtime().close(handle)
                        except AppApiError as exc:
                            raise CuaBridgeError(
                                exc.code, exc.message, details=exc.details,
                            ) from exc
                        attempts.append({
                            "route": "APP_API",
                            "status": "unsupported",
                            "reason": "intent_unsupported",
                            "executor": handle.executor,
                        })
                else:
                    attempts.append({
                        "route": "APP_API", "status": "unavailable",
                    })

        window = discovered.get("window") if isinstance(discovered.get("window"), Mapping) else {}
        hwnd = window.get("hwnd")
        if not gui_escalation_allowed(discovered, args.get("gui_fallback")):
            raise CuaBridgeError(
                "PROGRAMMATIC_ROUTE_REQUIRES_PLANNER",
                details={"app": app, "intent": intent,
                         "programmatic_candidates": list(discovered.get("programmatic_candidates") or []),
                         "reason": "Research task-compatible CLI, API/SDK and MCP routes before GUI fallback; empty CLI inventory is not proof",
                         "route_attempts": attempts},
            )
        if not hwnd:
            raise CuaBridgeError(
                "PROGRAMMATIC_ROUTE_REQUIRES_PLANNER",
                details={
                    "app": app,
                    "intent": intent,
                    "programmatic_candidates": list(discovered.get("programmatic_candidates") or []),
                    "route_attempts": attempts,
                },
            )
        for route in ("UIA_PATTERN", "HWND_MESSAGE"):
            surface_id = None
            try:
                attached = self._attach({
                    "surface_kind": "native", "route": route, "target": {"hwnd": hwnd},
                })
                surface_id = attached["surface_id"]
                observation = attached["observation"]
                entities = list(observation.get("entities") or [])
                if intent == "read":
                    return {
                        "route": route, "verified": True, "physical_input_used": False,
                        "window": window, "observation": observation, "fallback_chain": attempts,
                    }

                # Auto-routing must remain background-only. A failed semantic route
                # may decline, but it must never silently promote itself to foreground.
                policy = {
                    "background_required": True,
                    "foreground_allowed": False,
                    "physical_input_allowed": False,
                }
                receipts: list[dict[str, Any]] = []
                if intent in {"type", "chat.send"}:
                    field = self._auto_pick(entities, kind="input", target=str(args.get("target") or ""))
                    if field is None:
                        raise CuaBridgeError("NO_SEMANTIC_TARGET")
                    value = str(args.get("text") or "")
                    receipts.append(self._act({
                        "surface_id": surface_id, "operation": "set_value",
                        "ref": field.get("ref"), "generation": observation.get("generation"),
                        "action_args": {"value": value},
                        "postcondition": {"type": "value_equals", "value": value},
                        "policy": policy,
                    }))
                    if intent == "type":
                        return {**receipts[-1], "window": window, "fallback_chain": attempts}
                    observation = self._inspect("observe", {"surface_id": surface_id})
                    entities = list(observation.get("entities") or [])
                    button = self._auto_pick(entities, kind="send")
                elif intent in {"click", "chat.new"}:
                    button = self._auto_pick(
                        entities, kind="new",
                        target=str(args.get("target") or ""),
                    )
                else:
                    raise CuaBridgeError("AUTO_INTENT_UNSUPPORTED", details={"intent": intent})

                if button is None:
                    raise CuaBridgeError("NO_SEMANTIC_TARGET")
                receipts.append(self._act({
                    "surface_id": surface_id, "operation": "invoke",
                    "ref": button.get("ref"), "generation": observation.get("generation"),
                    "action_args": {}, "policy": policy,
                }))
                return {
                    **receipts[-1], "window": window, "fallback_chain": attempts,
                    "auto_receipts": receipts,
                }
            except CuaBridgeError as exc:
                attempts.append({"route": route, "status": "declined", "reason": exc.code})
            finally:
                if surface_id:
                    try:
                        self._close({"surface_id": surface_id})
                    except Exception:
                        pass
        # Final bounded fallback: fresh vision capture. Never guess coordinates.
        visual_surface = "auto-vision-" + uuid.uuid4().hex
        self._surfaces[visual_surface] = {
            "kind": "native", "route": "UIA_PATTERN",
            "target": {"hwnd": hwnd}, "generation": 1,
        }
        try:
            capture = self._vision_runtime().capture(visual_surface, int(hwnd), include_image=True)
            attempts.append({"route": "VISION_SEMANTIC", "status": "captured"})

            candidates = args.get("visual_candidates")
            query = args.get("vision_query")
            if not isinstance(candidates, list) or not candidates:
                code = "TEXT_INPUT_ROUTE_UNAVAILABLE" if intent in {"type", "chat.send"} else "VISION_GROUNDING_REQUIRED"
                raise CuaBridgeError(code, details={
                    "app": app, "intent": intent, "window": window,
                    "route_attempts": attempts, "capture": capture,
                    "required": "visual_candidates",
                })

            grounded = self._vision_runtime().ground(
                visual_surface, str(capture["capture_id"]), candidates,
            )
            query_obj = dict(query) if isinstance(query, Mapping) else {}
            if not query_obj:
                if len(grounded.get("candidates") or []) != 1:
                    raise CuaBridgeError("TARGET_AMBIGUOUS", details={
                        "route_attempts": attempts, "grounded": grounded,
                    })
                target_visual = grounded["candidates"][0]
            else:
                target_visual = self._vision_runtime().resolve(
                    visual_surface, query_obj,
                )["resolved_target"]

            if intent not in {"click", "chat.new"}:
                raise CuaBridgeError("TEXT_INPUT_ROUTE_UNAVAILABLE", details={
                    "route_attempts": attempts, "grounded": grounded,
                })
            if not bool(args.get("physical_input_allowed", False)):
                raise CuaBridgeError("VISION_ACTION_REQUIRES_PHYSICAL_OPT_IN", details={
                    "route_attempts": attempts, "grounded": grounded,
                    "resolved_target": target_visual,
                })

            generation = int(grounded["generation"])
            self._surfaces[visual_surface]["generation"] = generation
            lease = self._acquire_physical_lease({
                "surface_id": visual_surface, "generation": generation,
                "owner_id": "auto-vision",
                "policy": {
                    "physical_input_allowed": True,
                    "background_required": False,
                    "foreground_allowed": True,
                },
            })["lease"]
            receipt = self._act({
                "surface_id": visual_surface, "operation": "visual_click",
                "ref": target_visual["ref"], "generation": generation,
                "lease": lease,
                "policy": {
                    "physical_input_allowed": True,
                    "background_required": False,
                    "foreground_allowed": True,
                    "require_verified": True,
                },
            })
            return {
                **receipt, "window": window,
                "fallback_chain": attempts,
                "vision_capture_id": capture["capture_id"],
            }
        except VisionRuntimeError as exc:
            raise CuaBridgeError(exc.code, details={
                **exc.details, "app": app, "intent": intent,
                "window": window, "route_attempts": attempts,
            }) from exc
        finally:
            try:
                self._close({"surface_id": visual_surface})
            except Exception:
                self._surfaces.pop(visual_surface, None)

    def _register_app_surface(
        self,
        app: str,
        handle: Any,
        *,
        prefix: str = "app",
    ) -> dict[str, Any]:
        window = handle.discovery.get("window") if isinstance(handle.discovery.get("window"), Mapping) else {}
        declared_keys = getattr(handle, "resource_keys", ())
        semantic_keys: list[str] = []
        if isinstance(declared_keys, (list, tuple)):
            for item in declared_keys:
                if isinstance(item, str) and item.strip() and item.strip() not in semantic_keys:
                    semantic_keys.append(item.strip())
        primary_key = str(handle.resource_key or "").strip()
        if primary_key and primary_key not in semantic_keys:
            semantic_keys.append(primary_key)
        if not semantic_keys:
            semantic_keys.append(self._semantic_native_resource_key(window))
        semantic_key = semantic_keys[0]
        surface_id = prefix + "-" + uuid.uuid4().hex
        self._surfaces[surface_id] = {
            "kind": "app", "route": "APP_API", "app": app, "target": dict(window),
            "semantic_key": semantic_key, "semantic_keys": tuple(semantic_keys),
            "app_api_handle": handle,
        }
        return {
            "ok": True,
            "surface_id": surface_id,
            "surface_kind": "app",
            "route": "APP_API",
            "app_api": handle.public(),
        }

    def _attach(self, args: Mapping[str, Any]) -> dict[str, Any]:
        kind = str(args.get("surface_kind") or "")
        if kind == "browser":
            transport = str(args.get("transport") or "extension")
            raw_options = args.get("options", {})
            if transport == "isolated":
                if not isinstance(raw_options, Mapping):
                    raise CuaBridgeError("ISOLATED_BROWSER_OPTIONS_INVALID")
                if set(raw_options) - {"headless"}:
                    raise CuaBridgeError("ISOLATED_BROWSER_OPTIONS_FORBIDDEN")
                if raw_options.get("headless", True) is not True:
                    raise CuaBridgeError("ISOLATED_BROWSER_HEADLESS_REQUIRED")
            options = raw_options if isinstance(raw_options, Mapping) else {}
            supervisor = self._browser_supervisor(transport)
            payload = dict(options)
            if transport == "extension":
                payload.update({"ownerBrowser": True, "ownerTransport": "extension"})
                if not bool(args.get("force_new_connection", False)):
                    for existing_id, existing in list(self._surfaces.items()):
                        if existing.get("kind") != "browser" or existing.get("transport") != "extension":
                            continue
                        try:
                            _unwrap(supervisor.request("identity", {"surface_id": existing_id}), browser=True)
                        except Exception:
                            try:
                                _unwrap(supervisor.request("close", {"surface_id": existing_id}), browser=True)
                            except Exception:
                                pass
                            self._surfaces.pop(existing_id, None)
                            continue
                        return {
                            "ok": True,
                            "surface_kind": kind,
                            "surface_id": existing_id,
                            "route": existing.get("route", "BROWSER_PLAYWRIGHT"),
                            "capabilities": dict(existing.get("capabilities") or {}),
                            "reused": True,
                        }
            profile = options.get("chromeUserDataDir") or options.get("userDataDir")
            profile_key = "browser-profile:" + hashlib.sha256(str(profile).encode("utf-8")).hexdigest()[:24] if profile else None
            attach_key = ("browser-surface/tab:attach-" + uuid.uuid4().hex
                          if transport == "isolated" else "browser-surface/tab:attach")
            with self._resources.write(profile_key or attach_key):
                try:
                    result = _unwrap(supervisor.request("attach", payload), browser=True)
                except (CuaBridgeError, SidecarError) as err:
                    if transport == "extension":
                        transport = "isolated"
                        supervisor = self._browser_supervisor("isolated")
                        payload = {"headless": True}
                        result = _unwrap(supervisor.request("attach", payload), browser=True)
                        result["fallback_from_extension"] = True
                    else:
                        raise
            surface_id = str(result["surface_id"])
            surface_key = f"browser-surface/tab:{surface_id}"
            self._surfaces[surface_id] = {
                "kind": "browser", "transport": transport, "semantic_key": surface_key,
                "semantic_keys": tuple([surface_key, profile_key] if profile_key else [surface_key]),
                "route": result.get("route", "BROWSER_PLAYWRIGHT"),
                "capabilities": dict(result.get("capabilities") or {}),
            }
            return {"ok": True, "surface_kind": kind, "reused": False, **result}
        if kind == "app":
            target = args.get("target") if isinstance(args.get("target"), Mapping) else {}
            app = str(args.get("app") or target.get("app") or "").strip()
            if not app:
                raise CuaBridgeError("APP_REQUIRED")
            try:
                handle = self._app_api_runtime().probe(app, refresh=bool(args.get("refresh")))
            except AppApiError as exc:
                raise CuaBridgeError(exc.code, exc.message, details=exc.details) from exc
            if handle is None:
                raise CuaBridgeError("APP_API_UNAVAILABLE", details={"app": app})
            return self._register_app_surface(app, handle)
        if kind == "native":
            route = str(args.get("route") or "UIA_PATTERN")
            target = args.get("target") if isinstance(args.get("target"), Mapping) else {}
            native_key = self._native_resource_key(route, target)
            semantic_key = self._semantic_native_resource_key(target)
            supervisor = self._native_supervisor(route, native_key)
            options = args.get("options") if isinstance(args.get("options"), Mapping) else {}
            with self._resources.read(semantic_key):
                observation = _unwrap(supervisor.request("observe", {
                    "target": dict(target), "options": dict(options),
                }))
            surface_id = "native-" + uuid.uuid4().hex
            self._surfaces[surface_id] = {
                "kind": "native", "route": route, "target": dict(target),
                "native_key": native_key, "semantic_key": semantic_key,
                "generation": observation.get("generation"),
            }
            return {"ok": True, "surface_id": surface_id, "surface_kind": kind, "route": route, "observation": observation}
        raise CuaBridgeError("SURFACE_KIND_INVALID", details={"surface_kind": kind})

    def _surface(self, args: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
        surface_id = args.get("surface_id")
        if not isinstance(surface_id, str) or surface_id not in self._surfaces:
            raise CuaBridgeError("SURFACE_NOT_FOUND")
        return surface_id, self._surfaces[surface_id]

    def _inspect(self, command: str, args: Mapping[str, Any]) -> dict[str, Any]:
        surface_id, surface = self._surface(args)
        resource_keys = self._surface_resource_keys(surface_id, surface)
        if surface["kind"] == "browser":
            supervisor = self._browser_supervisor(surface["transport"])
            payload: dict[str, Any] = {"surface_id": surface_id}
            if command == "observe":
                payload["options"] = dict(args.get("options") or {})
            elif command == "find":
                payload["query"] = dict(args.get("query") or {})
            elif command == "wait":
                payload["spec"] = dict(args.get("spec") or {})
                payload["timeout_ms"] = args.get("timeout_ms", 5000)
            else:
                url = args.get("url")
                if not isinstance(url, str) or not url:
                    raise CuaBridgeError("BROWSER_URL_INVALID")
                payload["url"] = url
            with self._resources.read_many(resource_keys):
                return _unwrap(supervisor.request(command, payload), browser=True)
        if surface["kind"] == "app":
            if command != "observe":
                raise CuaBridgeError("ACTION_UNSUPPORTED", details={"command": command})
            try:
                with self._resources.read_many(resource_keys):
                    result = dict(self._app_api_runtime().action(surface["app_api_handle"], "inspect"))
            except AppApiError as exc:
                raise CuaBridgeError(exc.code, exc.message, details=exc.details) from exc
            result["backend_route"] = surface["app_api_handle"].backend_route
            result["app_api_executor"] = surface["app_api_handle"].executor
            result["route"] = "APP_API"
            return result
        if command == "navigate":
            raise CuaBridgeError("ACTION_UNSUPPORTED")
        supervisor = self._native_supervisor(surface["route"], surface.get("native_key"))
        if command == "observe":
            with self._resources.read_many(resource_keys):
                result = _unwrap(supervisor.request("observe", {
                    "target": surface["target"], "options": dict(args.get("options") or {})
                }))
            if isinstance(result.get("generation"), int):
                surface["generation"] = result["generation"]
            return result
        if command == "wait":
            with self._resources.read_many(resource_keys):
                return _unwrap(supervisor.request("wait", {
                    "target": surface["target"],
                    "condition": dict(args.get("condition") or {}),
                    "timeout_ms": args.get("timeout_ms", 5000),
                    "poll_ms": args.get("poll_ms", 100),
                    "stable_for_ms": args.get("stable_for_ms", 300),
                }))
        generation = args.get("generation")
        with self._resources.read_many(resource_keys):
            return _unwrap(supervisor.request("find", {
                "generation": generation, "query": dict(args.get("query") or {})
            }))

    def _vision_command(self, command: str, args: Mapping[str, Any]) -> dict[str, Any]:
        surface_id, surface = self._surface(args)
        if surface["kind"] != "native":
            raise CuaBridgeError("VISION_SURFACE_UNSUPPORTED", details={"surface_kind": surface["kind"]})
        target = surface.get("target") if isinstance(surface.get("target"), Mapping) else {}
        hwnd = target.get("hwnd")
        if isinstance(hwnd, str):
            try:
                hwnd = int(hwnd, 0)
            except ValueError as exc:
                raise CuaBridgeError("VISION_TARGET_INVALID") from exc
        if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
            raise CuaBridgeError("VISION_TARGET_INVALID")
        runtime = self._vision_runtime()
        try:
            if command in {"capture", "vision_capture"}:
                return runtime.capture(surface_id, hwnd, include_image=bool(args.get("include_image", True)))
            if command == "vision_detect":
                capture_id = args.get("capture_id")
                if not isinstance(capture_id, str) or not capture_id:
                    raise CuaBridgeError("VISUAL_CAPTURE_ID_REQUIRED")
                return runtime.detect(
                    surface_id, capture_id,
                    max_candidates=args.get("max_candidates", 64),
                )
            if command == "vision_ocr":
                capture_id = args.get("capture_id")
                if not isinstance(capture_id, str) or not capture_id:
                    raise CuaBridgeError("VISUAL_CAPTURE_ID_REQUIRED")
                return runtime.ocr(
                    surface_id, capture_id,
                    language=args.get("language", runtime.OCR_DEFAULT_LANGUAGE),
                    max_words=args.get("max_words", 128),
                )
            if command == "vision_observe":
                capture_id = args.get("capture_id")
                if not isinstance(capture_id, str) or not capture_id:
                    raise CuaBridgeError("VISUAL_CAPTURE_ID_REQUIRED")
                return runtime.observe(
                    surface_id, capture_id,
                    language=args.get("language", runtime.OCR_DEFAULT_LANGUAGE),
                    max_words=args.get("max_words", 128),
                    max_candidates=args.get("max_candidates", 64),
                    text_layout=args.get("text_layout", "words"),
                )
            if command == "vision_ground":
                capture_id = args.get("capture_id")
                candidates = args.get("candidates")
                if not isinstance(capture_id, str) or not capture_id or not isinstance(candidates, list):
                    raise CuaBridgeError("VISUAL_CANDIDATES_INVALID")
                return runtime.ground(surface_id, capture_id, candidates)
            if command == "vision_find":
                query = args.get("query") if isinstance(args.get("query"), Mapping) else {}
                return runtime.find(surface_id, query)
            if command == "vision_resolve":
                query = args.get("query") if isinstance(args.get("query"), Mapping) else {}
                return runtime.resolve(surface_id, query)
            if command == "vision_validate":
                ref = args.get("ref")
                if not isinstance(ref, str) or not ref:
                    raise CuaBridgeError("VISUAL_REF_REQUIRED")
                return runtime.validate(surface_id, ref)
        except VisionRuntimeError as exc:
            raise CuaBridgeError(exc.code, details=exc.details) from exc
        raise CuaBridgeError("CUA_COMMAND_UNSUPPORTED", details={"command": command})

    def _browser_command(self, command: str, args: Mapping[str, Any]) -> dict[str, Any]:
        surface_id, surface = self._surface(args)
        if surface["kind"] != "browser":
            raise CuaBridgeError("ACTION_UNSUPPORTED", details={"command": command})
        payload: dict[str, Any] = {"surface_id": surface_id}
        if command == "wait":
            payload["spec"] = dict(args.get("spec") or {})
            payload["timeout_ms"] = args.get("timeout_ms", 5000)
        elif command in {"reload", "back", "forward"}:
            payload["timeout_ms"] = args.get("timeout_ms", 10000)
        elif command == "claim_tab":
            payload["selector"] = dict(args.get("selector") or {})
        elif command == "new_tab":
            payload["url"] = str(args.get("url") or "about:blank")
            payload["timeout_ms"] = args.get("timeout_ms", 10000)
        elif command in {"switch_tab", "close_tab"}:
            page_id = args.get("page_id")
            if not isinstance(page_id, str) or not page_id:
                raise CuaBridgeError("BROWSER_PAGE_ID_INVALID")
            payload["page_id"] = page_id
        resource_keys = self._surface_resource_keys(surface_id, surface)
        readers = {"identity", "wait", "list_tabs"}
        scope = self._resources.read_many(resource_keys) if command in readers else self._resources.write_many(resource_keys)
        with scope:
            response = self._browser_supervisor(surface["transport"]).request(command, payload)
            if command == "list_tabs" and bool(response.get("ok", False)) and isinstance(response.get("result"), list):
                return {"tabs": [dict(item) if isinstance(item, Mapping) else item for item in response["result"]]}
            return _unwrap(response, browser=True)

    def _task_preflight(self, args: Mapping[str, Any]) -> dict[str, Any]:
        """Read-only unified capability investigation before any real action.

        Uses the SAME programmatic discovery and route planner already serving
        normal computer_use calls. It does not run a model, mint owner consent,
        install tools, mutate a file or issue an adapter.act request.
        """
        app = str(args.get("app") or "").strip()
        task = str(args.get("task") or "").strip()
        if not app:
            raise CuaBridgeError("APP_REQUIRED")
        if not task:
            raise CuaBridgeError("TASK_REQUIRED")
        # Request-side flags cannot silently opt into CLI probes that may
        # launch a GUI executable, nor override foreground authorization.
        candidates = self.dispatch({
            "command": "programmatic_plan", "app": app, "task": task,
            "probe_versions": False,
        })
        cli = list(candidates.get("candidates") or [])
        route_preflight = None
        surface_id = args.get("surface_id")
        if surface_id is not None:
            if not isinstance(surface_id, str) or not surface_id:
                raise CuaBridgeError("SURFACE_NOT_FOUND")
            operation = args.get("operation")
            if not isinstance(operation, str) or not operation:
                raise CuaBridgeError("OPERATION_REQUIRED")
            route_preflight = self.dispatch({
                "command": "plan_action", "surface_id": surface_id,
                "operation": operation, "action_args": dict(args.get("action_args") or {}),
                "policy": {
                    "background_required": True,
                    "foreground_allowed": False,
                    "physical_input_allowed": False,
                    "require_verified": True,
                },
            })
        if any(name in args and type(args[name]) is not bool
               for name in ("verify_cli_contract", "include_auth_status", "include_model_listing")):
            raise CuaBridgeError("CLI_CONTRACT_PROBE_FLAG_INVALID")
        if args.get("include_model_listing") is True and args.get("verify_cli_contract") is not True:
            raise CuaBridgeError("CLI_CONTRACT_PROBE_FLAG_INVALID")
        contract = None
        if args.get("verify_cli_contract") is True:
            from cua_cli_contracts import probe_vendor_cli
            contract = probe_vendor_cli(
                app, include_auth_status=args.get("include_auth_status") is True,
                include_model_listing=args.get("include_model_listing") is True
            )
        office_com = None
        if "verify_office_com" in args and type(args["verify_office_com"]) is not bool:
            raise CuaBridgeError("OFFICE_COM_PROBE_FLAG_INVALID")
        if args.get("verify_office_com") is True:
            if "excel" not in app.casefold():
                raise CuaBridgeError("OFFICE_COM_APP_UNSUPPORTED")
            from cua_office_com_probe import excel_registration
            office_com = excel_registration()
        task_compatible = candidates.get("task_compatibility")
        route = route_preflight.get("selected_route") if isinstance(route_preflight, Mapping) else None
        best_task = candidates.get("preferred_task_route")
        if isinstance(best_task, Mapping):
            step = "validate_entitlement_and_execute_verified_programmatic_task"
        elif route:
            step = "verify_background_route_matches_task_then_act_with_postcondition"
        elif office_com and office_com.get("candidate_route") == "EXCEL_COM":
            step = "verify_owned_hidden_excel_com_and_task_postcondition"
        elif cli:
            step = "check_task_specific_cli_support_auth_and_pricing"
        else:
            step = "research_official_api_sdk_mcp_and_optional_hidden_paths"
        from cua_router import task_orchestration_gate
        orchestration = task_orchestration_gate(
            app, task, candidates,
            cli_contract=contract, office_com=office_com,
            semantic_preflight=route_preflight,
        )
        if (app.casefold() in {"git", "git.exe", "git for windows"}
                and task == "git.repository.status"
                and candidates.get("task_execute_contract")):
            step = "run_explicit_git_status_task_execute_with_repo_path_and_check_receipt"
        return {
            "schema": "ff-cua-task-preflight-v1",
            "app": app, "task": task,
            "orchestration": orchestration,
            "programmatic": candidates,
            "cli_contract": contract,
            "office_com_registration": office_com,
            "external_cli_readonly_probe_requested": contract is not None,
            "semantic_preflight": route_preflight,
            "task_compatibility": task_compatible,
            "has_programmatic_candidates": bool(cli),
            "action_executed": False,
            "task_completed": False,
            "verified_task_result": False,
            "foreground_used": False,
            "owner_authorization_verified": False,
            "model_called": False,
            "billing_or_purchase_executed": False,
            "tools_installed": False,
            "next_step": step,
        }

    def _task_execute_git_status(self, args: Mapping[str, Any]) -> dict[str, Any]:
        """Real bounded background Git CLI task with two fresh status observations.

        Git is a no-inference, no-foreground programmatic route. This only
        reads one exact repository root; it does NOT run arbitrary agent
        commands, modify tracked files or claim general app automation.
        """
        from cua_task_authority import identity, AuthorityError
        from pathlib import Path
        import os
        import shutil
        import subprocess

        allowed = {
            "command", "app", "task", "agent_id", "task_id",
            "operation", "action_args", "expected_clean", "expected_changed",
        }
        if set(args) - allowed:
            raise CuaBridgeError("TASK_EXECUTE_ARGUMENT_UNSUPPORTED")
        try:
            agent = identity(args.get("agent_id"))
            task_id = identity(args.get("task_id"))
        except AuthorityError as exc:
            raise CuaBridgeError("TASK_EXECUTE_OWNER_SCOPE_REQUIRED") from exc
        if str(args.get("app") or "").strip().casefold() not in {"git", "git.exe"}:
            raise CuaBridgeError("TASK_EXECUTE_APP_UNSUPPORTED")
        task_name = args.get("task")
        operation = args.get("operation")
        status_task = task_name == "git.repository.status" and operation == "status.read"
        diff_task = task_name == "git.repository.diff" and operation == "diff.stat.read"
        if not (status_task or diff_task):
            raise CuaBridgeError("TASK_EXECUTE_OPERATION_NOT_SUPPORTED")
        if ("expected_clean" in args and
                (not status_task or type(args["expected_clean"]) is not bool)):
            raise CuaBridgeError("TASK_EXECUTE_EXPECTATION_INVALID")
        if ("expected_changed" in args and
                (not diff_task or type(args["expected_changed"]) is not bool)):
            raise CuaBridgeError("TASK_EXECUTE_EXPECTATION_INVALID")
        action = args.get("action_args")
        if (not isinstance(action, Mapping) or
                (set(action) != {"repo_path"} if status_task
                 else set(action) not in ({"repo_path"}, {"repo_path", "scope"}))):
            raise CuaBridgeError("TASK_EXECUTE_REPOSITORY_SCOPE_REQUIRED")
        scope = action.get("scope", "unstaged") if diff_task else None
        if diff_task and (type(scope) is not str or scope not in {"unstaged", "staged", "head"}):
            raise CuaBridgeError("TASK_EXECUTE_DIFF_SCOPE_INVALID")
        raw_path = action.get("repo_path")
        if (not isinstance(raw_path, str) or not 1 <= len(raw_path) <= 1024
                or any(ord(c) < 32 for c in raw_path)):
            raise CuaBridgeError("TASK_EXECUTE_REPOSITORY_SCOPE_REQUIRED")
        target = Path(raw_path)
        if not target.is_absolute() or not target.is_dir():
            raise CuaBridgeError("TASK_EXECUTE_REPOSITORY_NOT_FOUND")
        try:
            root = target.resolve(strict=True)
        except OSError as exc:
            raise CuaBridgeError("TASK_EXECUTE_REPOSITORY_NOT_FOUND") from exc
        # Keep the same filesystem restrictions already enforced by FF Bridge.
        from ff_win_v3_agent import enforce_allowed, RPCError
        try:
            enforce_allowed(root)
        except RPCError as exc:
            raise CuaBridgeError("TASK_EXECUTE_REPOSITORY_NOT_ALLOWED") from exc
        if not (root / ".git").exists():
            raise CuaBridgeError("TASK_EXECUTE_REPOSITORY_ROOT_REQUIRED")
        from cua_cli_contracts import official_git_for_windows
        executable = official_git_for_windows()
        if executable is None:
            raise CuaBridgeError("TASK_EXECUTE_TRUSTED_GIT_CLI_UNAVAILABLE")
        environment = dict(os.environ, GIT_OPTIONAL_LOCKS="0",
                           GIT_TERMINAL_PROMPT="0", GIT_NO_LAZY_FETCH="1",
                           GIT_PAGER="cat")
        common = [
            executable, "--no-optional-locks",
            "-c", "core.fsmonitor=false",
            "-c", "core.untrackedCache=false",
            "-c", "submodule.recurse=false",
            "-C", str(root),
        ]

        def checked_git(arguments: list[str]) -> str:
            try:
                completed = subprocess.run(
                    [*common, *arguments], cwd=str(root), env=environment,
                    capture_output=True, timeout=15, check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except subprocess.TimeoutExpired as exc:
                raise CuaBridgeError("TASK_EXECUTE_GIT_TIMEOUT",
                                     details={"attempted": True, "retry_safe": True}) from exc
            except OSError as exc:
                raise CuaBridgeError("TASK_EXECUTE_GIT_FAILED",
                                     details={"attempted": False, "retry_safe": True}) from exc
            if completed.returncode != 0:
                raise CuaBridgeError("TASK_EXECUTE_GIT_FAILED",
                                     details={"attempted": True, "retry_safe": True})
            if len(completed.stdout) > 65536:
                raise CuaBridgeError("TASK_EXECUTE_GIT_RESPONSE_TOO_LARGE")
            try:
                return completed.stdout.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise CuaBridgeError("TASK_EXECUTE_GIT_ENCODING_UNSUPPORTED") from exc

        # A nested directory or a Git worktree pointing to a different root
        # cannot be accepted as an implicitly expanded task scope.
        observed_root = checked_git(["rev-parse", "--show-toplevel"]).strip()
        if os.path.normcase(str(Path(observed_root).resolve())) != os.path.normcase(str(root)):
            raise CuaBridgeError("TASK_EXECUTE_REPOSITORY_ROOT_MISMATCH")
        if diff_task:
            # Only fixed, non-mutating Git arguments: no filters, hooks,
            # user-supplied revisions, patch command or external diff drivers.
            # -z gives unambiguous paths even with tabs/newlines in filenames.
            command = ["diff"]
            if scope == "staged":
                command.append("--cached")
            elif scope == "head":
                command.append("HEAD")
            command += [
                "--no-ext-diff", "--no-textconv", "--no-renames",
                "--numstat", "-z", "--",
            ]
            first = checked_git(command)
            second = checked_git(command)
            if first != second:
                raise CuaBridgeError(
                    "TASK_EXECUTE_INCONSISTENT_LIVE_READS",
                    details={"attempted": True, "retry_safe": True},
                )
            if second and not second.endswith("\0"):
                raise CuaBridgeError("TASK_EXECUTE_GIT_RESPONSE_INVALID")
            chunks = second[:-1].split("\0") if second else []
            if len(chunks) > 200:
                raise CuaBridgeError("TASK_EXECUTE_GIT_RESPONSE_TOO_LARGE")
            changes: list[dict[str, Any]] = []
            total_added = total_deleted = binary_count = 0
            for chunk in chunks:
                fields = chunk.split("\t", 2)
                if (len(fields) != 3 or not fields[2] or
                        len(fields[2].encode("utf-8")) > 2048):
                    raise CuaBridgeError("TASK_EXECUTE_GIT_RESPONSE_INVALID")
                added, deleted, filename = fields
                binary = added == "-" and deleted == "-"
                if not binary and (
                        not added.isascii() or not deleted.isascii()
                        or not added.isdecimal() or not deleted.isdecimal()
                        or len(added) > 12 or len(deleted) > 12):
                    raise CuaBridgeError("TASK_EXECUTE_GIT_RESPONSE_INVALID")
                num_added = None if binary else int(added)
                num_deleted = None if binary else int(deleted)
                if not binary and (num_added > 100000000 or num_deleted > 100000000):
                    raise CuaBridgeError("TASK_EXECUTE_GIT_RESPONSE_TOO_LARGE")
                if binary:
                    binary_count += 1
                else:
                    total_added += num_added
                    total_deleted += num_deleted
                changes.append({
                    "path": filename,
                    "added": num_added, "deleted": num_deleted, "binary": binary,
                })
            changed = bool(changes)
            if "expected_changed" in args and args["expected_changed"] != changed:
                raise CuaBridgeError(
                    "TASK_EXECUTE_POSTCONDITION_FAILED",
                    details={"attempted": True, "retry_safe": True},
                )
            return {
                "schema": "ff-task-execution-v1", "ok": True,
                "state": "COMPLETED", "task": "git.repository.diff",
                "agent_id": agent, "task_id": task_id,
                "route": "OFFICIAL_GIT_CLI", "operation": "diff.stat.read",
                "scope": scope, "changed": changed,
                "changed_file_count": len(changes), "files": changes,
                "total_added": total_added, "total_deleted": total_deleted,
                "binary_file_count": binary_count,
                "verified": True,
                "orchestration": {
                    "selected_route": "OFFICIAL_GIT_CLI",
                    "actual_stages": ["PROBING", "EXECUTING", "VERIFYING", "COMPLETED"],
                    "visible_last_resort_used": False,
                },
                "verification": {
                    "kind": "two_fresh_real_git_cli_numstat_reads",
                    "exact_repo_root_verified": True,
                    "two_fresh_reads_consistent": True,
                    "user_expectation_supplied": "expected_changed" in args,
                    "independent_saved_artifact_verified": False,
                    "untracked_files_included": False,
                    "no_optional_git_index_lock": True,
                },
                "execution": {
                    "foreground_used": False, "model_called": False,
                    "paid_inference_used": False, "repo_mutated_by_task": False,
                },
                "cleanup": "no_task_owned_process_or_file_persisted",
                "durable_mutation_journal_required": False,
            }
        command = ["status", "--porcelain=v1", "--untracked-files=normal"]
        first = checked_git(command)
        second = checked_git(command)
        if first != second:
            raise CuaBridgeError(
                "TASK_EXECUTE_INCONSISTENT_LIVE_READS",
                details={"attempted": True, "retry_safe": True},
            )
        rows = second.splitlines()
        if len(rows) > 200 or any(len(line) > 2048 for line in rows):
            raise CuaBridgeError("TASK_EXECUTE_GIT_RESPONSE_TOO_LARGE")
        clean = not bool(rows)
        if "expected_clean" in args and args["expected_clean"] != clean:
            raise CuaBridgeError(
                "TASK_EXECUTE_POSTCONDITION_FAILED",
                details={"attempted": True, "retry_safe": True},
            )
        return {
            "schema": "ff-task-execution-v1", "ok": True,
            "state": "COMPLETED", "task": "git.repository.status",
            "agent_id": agent, "task_id": task_id, "route": "OFFICIAL_GIT_CLI",
            "operation": "status.read", "status_lines": rows, "clean": clean,
            "verified": True,
            "orchestration": {
                "selected_route": "OFFICIAL_GIT_CLI",
                "actual_stages": ["PROBING", "EXECUTING", "VERIFYING", "COMPLETED"],
                "visible_last_resort_used": False,
            },
            "verification": {
                "kind": "two_fresh_real_git_cli_status_reads",
                "exact_repo_root_verified": True,
                "two_fresh_reads_consistent": True,
                "user_expectation_supplied": "expected_clean" in args,
                "independent_saved_artifact_verified": False,
                "no_optional_git_index_lock": True,
            },
            "execution": {
                "foreground_used": False, "model_called": False,
                "paid_inference_used": False, "repo_mutated_by_task": False,
            },
            "cleanup": "no_task_owned_process_or_file_persisted",
            "durable_mutation_journal_required": False,
        }

    def _task_execute(self, args: Mapping[str, Any]) -> dict[str, Any]:
        """First bounded real task: a bounded Excel cell or range read with fresh readback.

        Uses an ALREADY ATTACHED COM handle, the canonical ControlRouter and
        its real app executor. No model, installation, worksheet mutation,
        visible input or user session cleanup. Never treats a preflight flag
        as task permission; exact IDs and two consistent fresh reads; caller may also assert an expected result.

        Two fresh COM observations are not independent saved-artifact
        evidence; the report states the narrower actual verification scope.
        """
        if str(args.get("app") or "").strip().casefold() in {"git", "git.exe"}:
            return self._task_execute_git_status(args)
        from cua_task_authority import identity, AuthorityError
        from cua_app_api import _excel_validate_address, _excel_cell_parts, AppApiError
        import math
        allowed = {
            "command", "app", "task", "agent_id", "task_id",
            "surface_id", "operation", "action_args", "expected_value",
        }
        if set(args) - allowed:
            raise CuaBridgeError("TASK_EXECUTE_ARGUMENT_UNSUPPORTED")
        try:
            agent = identity(args.get("agent_id"))
            task_id = identity(args.get("task_id"))
        except AuthorityError as exc:
            raise CuaBridgeError("TASK_EXECUTE_OWNER_SCOPE_REQUIRED") from exc
        if str(args.get("app") or "").strip().casefold() not in {"excel", "microsoft excel", "excel.exe"}:
            raise CuaBridgeError("TASK_EXECUTE_APP_UNSUPPORTED")
        operation = args.get("operation")
        if args.get("task") != "excel.cells" or operation not in {"cell.read", "range.read"}:
            raise CuaBridgeError("TASK_EXECUTE_OPERATION_NOT_SUPPORTED")
        raw_args = args.get("action_args")
        if not isinstance(raw_args, Mapping) or set(raw_args) != {"sheet", "address"}:
            raise CuaBridgeError("TASK_EXECUTE_CELL_SCOPE_REQUIRED")
        sheet, address = raw_args.get("sheet"), raw_args.get("address")
        if not isinstance(sheet, str) or not sheet.strip() or len(sheet) > 31:
            raise CuaBridgeError("TASK_EXECUTE_SHEET_INVALID")
        try:
            address = _excel_validate_address(address, single_cell=operation == "cell.read")
        except AppApiError as exc:
            raise CuaBridgeError(exc.code) from exc
        matrix_shape = None
        if operation == "range.read":
            if ":" not in address:
                raise CuaBridgeError("TASK_EXECUTE_RANGE_EXPECTED")
            left, right = address.replace("$", "").split(":", 1)
            start = _excel_cell_parts(left)
            stop = _excel_cell_parts(right)
            if start is None or stop is None:
                raise CuaBridgeError("TASK_EXECUTE_RANGE_INVALID")
            width, height = stop[0] - start[0] + 1, stop[1] - start[1] + 1
            if width < 1 or height < 1 or width * height > 256 or width > 32 or height > 256:
                raise CuaBridgeError("TASK_EXECUTE_RANGE_TOO_LARGE")
            matrix_shape = (height, width)

        def valid_scalar(value):
            if type(value) not in (str, int, float, bool, type(None)):
                return False
            if isinstance(value, str) and len(value.encode("utf-8")) > 8192:
                return False
            if type(value) is float and not math.isfinite(value):
                return False
            return True

        def valid_value(value):
            if matrix_shape is None:
                return valid_scalar(value)
            rows, columns = matrix_shape
            return (type(value) is list and len(value) == rows
                    and all(type(row) is list and len(row) == columns
                            and all(valid_scalar(item) for item in row)
                            for row in value)
                    and sum(len(str(item).encode("utf-8")) for row in value
                            for item in row) <= 65536)
        has_expectation = "expected_value" in args
        expected = args.get("expected_value")
        if has_expectation and not valid_value(expected):
            raise CuaBridgeError("TASK_EXECUTE_EXPECTATION_INVALID")

        surface_id, surface = self._surface(args)
        handle = surface.get("app_api_handle")
        if (surface.get("kind") != "app" or
                getattr(handle, "executor", None) not in {"excel_com", "excel_powershell_com"} or
                str(getattr(handle, "app", "") or "").casefold() not in
                {"excel", "microsoft excel", "excel.exe"}):
            raise CuaBridgeError("TASK_EXECUTE_EXCEL_COM_SURFACE_REQUIRED")
        capability = getattr(handle, "capabilities", {}).get(operation)
        if (not isinstance(capability, Mapping) or
                capability.get("mutation") is not False or
                capability.get("background_safe") is not True or
                capability.get("desktop_exclusive") is not False):
            raise CuaBridgeError("TASK_EXECUTE_READONLY_CAPABILITY_UNVERIFIED")
        safe_policy = {
            "background_required": True, "foreground_allowed": False,
            "physical_input_allowed": False, "require_verified": True,
        }
        request = {
            "surface_id": surface_id, "operation": operation,
            "action_args": {"sheet": sheet, "address": address},
            "policy": safe_policy,
        }
        preflight = self.dispatch({"command": "plan_action", **request})
        from cua_router import task_orchestration_gate
        gate = task_orchestration_gate(
            "Excel", "excel.cells", {"candidates": []},
            semantic_preflight=preflight,
        )
        if (preflight.get("selected_route") != "APP_API" or
                preflight.get("action_executed") is not False or
                gate.get("next_probe") != "PROBE_BACKGROUND_OPERATION_AND_POSTCONDITION" or
                gate.get("route_exhaustion_proven") is not False or
                gate.get("visible_last_resort_eligible") is not False or
                (gate.get("cost_policy") or {}).get("zero_new_spend") is not True):
            raise CuaBridgeError("TASK_EXECUTE_VERIFIED_BACKGROUND_ROUTE_REQUIRED")

        def equivalent(actual, comparison):
            if type(actual) is list and type(comparison) is list:
                return len(actual) == len(comparison) and all(
                    equivalent(a, b) for a, b in zip(actual, comparison)
                )
            if type(actual) in (int, float) and type(comparison) in (int, float):
                return (math.isfinite(float(actual)) and math.isfinite(float(comparison))
                        and float(actual) == float(comparison))
            return type(actual) is type(comparison) and actual == comparison

        observations = []
        for _ in range(2):
            receipt = self._act(request)
            action = receipt.get("action_result")
            if (receipt.get("route") != "APP_API" or
                    receipt.get("verified") is not True or
                    receipt.get("physical_input_used") is not False or
                    not isinstance(action, Mapping) or
                    action.get("app_api_executor") != handle.executor or
                    action.get("sheet") != sheet or
                    str(action.get("address") or "").replace("$", "").upper() !=
                    address.replace("$", "").upper() or
                    "value" not in action):
                raise CuaBridgeError(
                    "TASK_EXECUTE_READBACK_UNVERIFIED",
                    details={"attempted": True, "retry_safe": True},
                )
            observed = action["value"]
            if not valid_value(observed):
                raise CuaBridgeError("TASK_EXECUTE_READBACK_UNVERIFIED",
                                     details={"attempted": True, "retry_safe": True})
            if has_expectation and not equivalent(observed, expected):
                raise CuaBridgeError(
                    "TASK_EXECUTE_POSTCONDITION_FAILED",
                    details={"attempted": True, "retry_safe": True},
                )
            if observations and not equivalent(observed, observations[-1]):
                raise CuaBridgeError(
                    "TASK_EXECUTE_INCONSISTENT_LIVE_READS",
                    details={"attempted": True, "retry_safe": True},
                )
            observations.append(observed)
        return {
            "schema": "ff-task-execution-v1",
            "ok": True, "state": "COMPLETED", "task": "excel.cells",
            "orchestration": {
                "gate_schema": gate["schema"],
                "selected_next_probe": gate["next_probe"],
                "actual_stages": ["PROBING", "EXECUTING", "VERIFYING", "CLEANING", "COMPLETED"],
                "visible_last_resort_used": False,
                "unproven_model_route_escalation": False,
            },
            "agent_id": agent, "task_id": task_id, "route": "APP_API",
            "operation": operation,
            "value": observations[-1],
            "verified": True,
            "verification": {
                "kind": "two_fresh_excel_com_range_reads" if matrix_shape else
                        "two_fresh_excel_com_cell_reads",
                "two_fresh_reads_consistent": True,
                "user_expectation_supplied": has_expectation,
                "postcondition_matches_expected": True if has_expectation else None,
                "distinct_read_calls": 2,
                "independent_saved_artifact_verified": False,
            },
            "execution": {
                "foreground_used": False, "model_called": False,
                "paid_inference_used": False, "file_or_workbook_mutated": False,
            },
            "cleanup": "no_task_resources_created; existing_workbook_preserved",
            "durable_mutation_journal_required": False,
        }

    def _act(self, args: Mapping[str, Any]) -> dict[str, Any]:
        surface_id, surface = self._surface(args)
        resource_keys = self._surface_resource_keys(surface_id, surface)
        policy_args = args.get("policy") if isinstance(args.get("policy"), Mapping) else {}
        policy = RoutePolicy(
            background_required=bool(policy_args.get("background_required", True)),
            foreground_allowed=bool(policy_args.get("foreground_allowed", False)),
            physical_input_allowed=bool(policy_args.get("physical_input_allowed", False)),
            require_verified=bool(policy_args.get("require_verified", True)),
        )
        raw_action_args = args.get("action_args")
        if raw_action_args is None:
            action_args: dict[str, Any] = {}
        elif isinstance(raw_action_args, Mapping):
            action_args = dict(raw_action_args)
        else:
            raise CuaBridgeError(
                "INVALID_ARGUMENT",
                details={"field": "action_args"},
            )
        request = {
            "surface_id": surface_id,
            "surface_kind": surface["kind"],
            "target": dict(surface.get("target") or {}),
            "operation": args.get("operation"),
            "ref": args.get("ref"),
            "generation": args.get("generation"),
            "action_args": action_args,
            "postcondition": dict(args["postcondition"]) if isinstance(args.get("postcondition"), Mapping) else None,
        }
        router = ControlRouter()
        if surface["kind"] == "browser":
            router.register(
                "BROWSER_PLAYWRIGHT",
                _BrowserRouteAdapter(self._browser_supervisor(surface["transport"]), surface_id, self._browser_companion() if surface["transport"] == "extension" else None),
                background_safe=True,
            )
        elif surface["kind"] == "app":
            router.register(
                "APP_API", AppApiRouteAdapter(self._app_api_runtime(), surface["app_api_handle"]),
                background_safe=True,
            )
        else:
            route = surface["route"]
            router.register(
                route,
                NativeSidecarRouterAdapter(route, self._native_supervisor(route, surface.get("native_key"))),
                background_safe=True,
            )
        physical_runtime = None
        if (surface["kind"] != "app" and policy.physical_input_allowed
                and policy.foreground_allowed and not policy.background_required
                and args.get("_preflight_only") is not True):
            try:
                physical_runtime = self._physical_runtime()
                router.lease_validator = physical_runtime.validator(surface)
                physical_adapter: Any = physical_runtime.adapter(surface)
                if request.get("operation") == "visual_click":
                    if surface["kind"] != "native":
                        raise CuaBridgeError("VISION_SURFACE_UNSUPPORTED", details={"surface_kind": surface["kind"]})
                    physical_adapter = _VisionAwarePhysicalAdapter(
                        physical_adapter, self._vision_runtime(), surface_id,
                    )
                router.register(
                    "PHYSICAL_INPUT", physical_adapter,
                    background_safe=False, physical_input=True,
                )
            except PhysicalRuntimeError as exc:
                raise CuaBridgeError(exc.code, details=exc.details) from exc

        lease_arg = args.get("lease") if isinstance(args.get("lease"), Mapping) else None
        if lease_arg is None and isinstance(args.get("lease_id"), str):
            lease_arg = {"lease_id": args["lease_id"]}
        lease = dict(lease_arg) if lease_arg else None
        lease_id = str((lease or {}).get("lease_id") or "")
        if args.get("_preflight_only") is True:
            result = router.inspect(request, policy=policy, lease=lease)
            # Even if an agent claims to have owner approval, this read-only
            # observation never converts that claim into a capability.
            if not policy.background_required and policy.physical_input_allowed:
                result["foreground_candidate_unverified"] = True
                if result["selected_route"] is None:
                    result["requires_verified_foreground_approval"] = True
                    result["next_step"] = "obtain_trusted_foreground_authorization"
            return result
        resource_scope = self._resources.write_many(resource_keys)
        if surface["kind"] == "app":
            handle = surface.get("app_api_handle")
            capabilities = getattr(handle, "capabilities", None)
            operation = request.get("operation")
            capability = (
                capabilities.get(operation)
                if isinstance(capabilities, Mapping) and isinstance(operation, str)
                else None
            )
            if isinstance(capability, Mapping) and capability.get("mutation") is False:
                resource_scope = self._resources.read_many(resource_keys)
        try:
            with resource_scope:
                return router.act(request, policy=policy, lease=lease)
        except ControlRouterError as exc:
            raise CuaBridgeError(exc.code, exc.message, details=exc.details) from exc
        finally:
            if lease_id and physical_runtime is not None:
                physical_runtime.abort_if_active(lease_id, "ACTION_COMPLETE")

    def _acquire_physical_lease(self, args: Mapping[str, Any]) -> dict[str, Any]:
        _, surface = self._surface(args)
        policy = args.get("policy") if isinstance(args.get("policy"), Mapping) else {}
        if not bool(policy.get("physical_input_allowed", False)):
            raise CuaBridgeError("PHYSICAL_INPUT_EXPLICIT_OPT_IN_REQUIRED")
        if bool(policy.get("background_required", True)) or not bool(policy.get("foreground_allowed", False)):
            raise CuaBridgeError("PHYSICAL_INPUT_POLICY_REJECTED")
        generation = args.get("generation", surface.get("generation"))
        if isinstance(generation, bool) or not isinstance(generation, int):
            raise CuaBridgeError("PHYSICAL_TARGET_GENERATION_REQUIRED")
        owner_id = str(args.get("owner_id") or "bridge-rpc")
        try:
            lease = self._physical_runtime().acquire(surface, generation=generation, owner_id=owner_id)
        except PhysicalRuntimeError as exc:
            raise CuaBridgeError(exc.code, details=exc.details) from exc
        except Exception as exc:
            code = str(getattr(exc, "code", "PHYSICAL_LEASE_ACQUIRE_FAILED"))
            raise CuaBridgeError(code, details=getattr(exc, "details", {})) from exc
        return {"ok": True, "lease": lease}

    def _release_physical_lease(self, args: Mapping[str, Any]) -> dict[str, Any]:
        lease_id = args.get("lease_id")
        if not isinstance(lease_id, str) or not lease_id:
            raise CuaBridgeError("PHYSICAL_LEASE_ID_REQUIRED")
        if self._physical is not None:
            self._physical.release(lease_id)
        return {"ok": True, "lease_id": lease_id}

    def _close(self, args: Mapping[str, Any]) -> dict[str, Any]:
        surface_id, surface = self._surface(args)
        browser_cleanup = None
        if surface["kind"] == "browser":
            with self._resources.write_many(self._surface_resource_keys(surface_id, surface)):
                browser_cleanup = _unwrap(
                    self._browser_supervisor(surface["transport"]).request("close", {"surface_id": surface_id}),
                    browser=True,
                )
        if surface["kind"] == "app":
            handle = surface.get("app_api_handle")
            if handle is not None:
                resource_keys = self._surface_resource_keys(surface_id, surface)
                try:
                    with self._resources.write_many(resource_keys):
                        self._app_api_runtime().close(handle)
                except AppApiError as exc:
                    raise CuaBridgeError(exc.code, exc.message, details=exc.details) from exc
        if self._vision is not None:
            self._vision.clear_surface(surface_id)
        self._surfaces.pop(surface_id, None)
        if surface["kind"] == "native":
            native_key = surface.get("native_key")
            if isinstance(native_key, str):
                still_used = any(item.get("native_key") == native_key for item in self._surfaces.values())
                if not still_used:
                    supervisor = self._native.pop(native_key, None)
                    if supervisor is not None:
                        supervisor.stop()
        result = {"ok": True, "surface_id": surface_id}
        if browser_cleanup is not None:
            result["browser_cleanup"] = browser_cleanup
        return result

    def close(self) -> None:
        for surface_id, surface in list(self._surfaces.items()):
            if surface.get("kind") not in {"app", "browser"}:
                continue
            try:
                self._close({"surface_id": surface_id})
            except Exception:
                self._surfaces.pop(surface_id, None)
        if self._vision is not None:
            try:
                self._vision.stop()
            except Exception:
                pass
        if self._physical is not None:
            try:
                self._physical.close()
            except Exception:
                pass
        for supervisor in [*self._browser.values(), *self._native.values()]:
            try:
                supervisor.stop()
                if supervisor is self._browser.get("isolated") and self._browser_profiles is not None:
                    self._browser_profiles.close()
                    self._browser_profiles = None
            except Exception:
                pass
