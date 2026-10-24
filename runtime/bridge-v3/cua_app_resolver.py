from __future__ import annotations

import json
import hashlib
from pathlib import Path
import os
import subprocess
import time
from typing import Any, Callable, Mapping


class AppResolverError(RuntimeError):
    def __init__(self, code: str, details: Mapping[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


class WindowsInstalledAppResolver:
    def __init__(self, *, cache_ttl_s: float = 30.0, runner: Callable[..., subprocess.CompletedProcess[str]] | None = None):
        self.cache_ttl_s = max(0.0, float(cache_ttl_s))
        self._runner = runner or subprocess.run
        self._cache: list[dict[str, str]] = []
        self._cache_at = 0.0

    @staticmethod
    def _norm(value: Any) -> str:
        return " ".join(str(value or "").casefold().split())

    def list_apps(self, *, refresh: bool = False) -> list[dict[str, str]]:
        now = time.monotonic()
        if not refresh and self._cache and now - self._cache_at <= self.cache_ttl_s:
            return [dict(item) for item in self._cache]
        if os.name != "nt":
            raise AppResolverError("WINDOWS_REQUIRED")
        script = (
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
            "$OutputEncoding=[Console]::OutputEncoding;"
            "Get-StartApps | Select-Object Name,AppID | ConvertTo-Json -Compress"
        )
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            completed = self._runner(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=8, check=False, creationflags=creationflags,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AppResolverError("START_APPS_QUERY_FAILED", {"cause": type(exc).__name__}) from exc
        if completed.returncode != 0:
            raise AppResolverError("START_APPS_QUERY_FAILED", {"exit_code": completed.returncode})
        try:
            raw = json.loads(completed.stdout or "[]")
        except json.JSONDecodeError as exc:
            raise AppResolverError("START_APPS_JSON_INVALID") from exc
        if isinstance(raw, dict):
            raw = [raw]
        if not isinstance(raw, list):
            raise AppResolverError("START_APPS_JSON_INVALID")
        apps: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for item in raw:
            if not isinstance(item, Mapping):
                continue
            name = str(item.get("Name") or "").strip()
            app_id = str(item.get("AppID") or "").strip()
            if not name or not app_id:
                continue
            key = (self._norm(name), self._norm(app_id))
            if key in seen:
                continue
            seen.add(key)
            apps.append({"name": name, "app_id": app_id})
        self._cache = apps
        self._cache_at = now
        return [dict(item) for item in apps]

    def resolve(self, query: str, *, refresh: bool = False) -> dict[str, Any]:
        needle = self._norm(query)
        if not needle:
            raise AppResolverError("APP_REQUIRED")
        if os.path.isabs(query):
            path = Path(query).resolve()
            if path.suffix.casefold() != ".exe" or not path.is_file():
                raise AppResolverError("APP_EXECUTABLE_NOT_FOUND")
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            return {"app": {"name": path.stem, "app_id": str(path), "sha256": digest},
                    "score": 1000, "source": "explicit_executable"}
        ranked: list[tuple[int, dict[str, str]]] = []
        tokens = [part for part in needle.split() if part]
        for item in self.list_apps(refresh=refresh):
            name = self._norm(item["name"])
            app_id = self._norm(item["app_id"])
            score = 0
            if needle == name:
                score = 1000
            elif needle == app_id:
                score = 950
            elif name.startswith(needle):
                score = 850
            elif tokens and all(token in name for token in tokens):
                score = 760
            elif needle in name:
                score = 700
            elif needle in app_id:
                score = 500
            if score:
                ranked.append((score, item))
        if not ranked:
            raise AppResolverError("APP_NOT_INSTALLED", {"app": query})
        ranked.sort(key=lambda pair: (-pair[0], self._norm(pair[1]["name"]), self._norm(pair[1]["app_id"])))
        top = ranked[0][0]
        best = [item for score, item in ranked if score == top]
        if len(best) > 1:
            raise AppResolverError("APP_RESOLUTION_AMBIGUOUS", {"app": query, "matches": best[:10]})
        return {"app": dict(best[0]), "score": top, "source": "Get-StartApps"}

    def launch(self, query: str, *, refresh: bool = False, visible_launch_allowed: bool = False, expected_app: Mapping[str, Any] | None = None, launch_arguments: list[str] | None = None) -> dict[str, Any]:
        if type(visible_launch_allowed) is not bool:
            raise AppResolverError("VISIBLE_LAUNCH_FLAG_INVALID")
        if not visible_launch_allowed:
            raise AppResolverError("APP_LAUNCH_REQUIRES_VISIBLE_OPT_IN", {"app": query})
        if launch_arguments is None:
            launch_arguments = []
        if (not isinstance(launch_arguments, list) or len(launch_arguments) > 32
                or any(not isinstance(v, str) or not v or len(v) > 32768 or "\x00" in v for v in launch_arguments)):
            raise AppResolverError("APP_LAUNCH_ARGUMENTS_INVALID")
        resolved = self.resolve(query, refresh=refresh)
        item = resolved["app"]
        app_id = str(item["app_id"])
        if expected_app is not None:
            if (not isinstance(expected_app, Mapping) or set(expected_app) - {"app_id", "sha256"}
                    or expected_app.get("app_id") != app_id
                    or ("sha256" in expected_app and expected_app["sha256"] != item.get("sha256"))
                    or (resolved["source"] == "explicit_executable" and expected_app.get("sha256") != item["sha256"])):
                raise AppResolverError("APP_LAUNCH_IDENTITY_CHANGED", {"retry_safe": False})
        if launch_arguments and (resolved["source"] != "explicit_executable" or expected_app is None):
            raise AppResolverError("APP_LAUNCH_ARGUMENTS_REQUIRE_EXACT_EXE")
        from cua_task_authority import DESKTOP_ACTION_EXPIRY
        expiry = DESKTOP_ACTION_EXPIRY.get()
        if expiry is not None and expiry <= time.time():
            raise AppResolverError("DESKTOP_MODE_EXPIRED", {"retry_safe": False})
        try:
            if os.path.isabs(app_id) and app_id.casefold().endswith(".exe") and os.path.isfile(app_id):
                proc = subprocess.Popen([app_id, *launch_arguments], close_fds=True)
                strategy = "direct_exe"
            else:
                proc = subprocess.Popen(["explorer.exe", "shell:AppsFolder\\" + app_id], close_fds=True)
                strategy = "shell_appsfolder"
        except OSError as exc:
            raise AppResolverError("APP_LAUNCH_FAILED", {"app": item, "cause": type(exc).__name__}) from exc
        return {
            **resolved,
            "launched": True,
            "launch_strategy": strategy,
            "launcher_pid": int(proc.pid),
            "launch_arguments": list(launch_arguments),
            "background_safe": False,
            "visible_launch_allowed": True,
        }
