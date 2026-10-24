from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping


class AppRouteExperienceStore:
    SCHEMA = "ff-cua-app-route-experience-v1"

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        max_age_s: float = 30 * 24 * 3600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = Path(path) if path is not None else None
        self.max_age_s = max(0.0, float(max_age_s))
        self._clock = clock
        self._lock = threading.RLock()
        self._entries: dict[str, dict[str, Any]] = {}
        self._load()
    @staticmethod
    def _key(app: Any) -> str:
        normalized = " ".join(str(app or "").casefold().split())
        if not normalized:
            return ""
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:24]

    def _load(self) -> None:
        if self.path is None or not self.path.is_file():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(raw, Mapping) or raw.get("schema") != self.SCHEMA:
            return
        entries = raw.get("entries")
        if not isinstance(entries, Mapping):
            return
        for key, value in entries.items():
            if isinstance(key, str) and isinstance(value, Mapping):
                self._entries[key] = dict(value)

    def _persist_locked_unsafe(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema": self.SCHEMA, "entries": self._entries}
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=self.path.parent,
                prefix=self.path.name + ".", suffix=".tmp", delete=False,
            ) as handle:
                temp_name = handle.name
                json.dump(payload, handle, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
        finally:
            if temp_name:
                try:
                    Path(temp_name).unlink(missing_ok=True)
                except OSError:
                    pass

    def _persist_locked(self) -> None:
        try:
            self._persist_locked_unsafe()
        except OSError:
            return

    def preferred_executor(self, app: Any) -> str | None:
        key = self._key(app)
        if not key:
            return None
        with self._lock:
            entry = self._entries.get(key)
            if not isinstance(entry, Mapping):
                return None
            updated_at = entry.get("updated_at")
            if isinstance(updated_at, bool) or not isinstance(updated_at, (int, float)):
                return None
            if self.max_age_s and self._clock() - float(updated_at) > self.max_age_s:
                return None
            executor = str(entry.get("preferred_executor") or "").strip()
            return executor or None

    def note_probe_success(self, handle: Any) -> None:
        app = getattr(handle, "app", "")
        key = self._key(app)
        executor = str(getattr(handle, "executor", "") or "").strip()
        backend_route = str(getattr(handle, "backend_route", "") or "").strip()
        capabilities = getattr(handle, "capabilities", {})
        if not key or not executor or not isinstance(capabilities, Mapping):
            return
        capability_names = sorted(str(name) for name in capabilities)
        verified = sorted(
            str(name) for name, value in capabilities.items()
            if isinstance(value, Mapping) and value.get("verified_capable") is True
        )
        with self._lock:
            previous = self._entries.get(key, {})
            action_successes = previous.get("action_successes")
            now = self._clock()
            stable = (
                previous.get("preferred_executor") == executor
                and previous.get("backend_route") == backend_route
                and previous.get("capabilities") == capability_names
                and previous.get("verified_capabilities") == verified
            )
            updated_at = previous.get("updated_at")
            if stable and isinstance(updated_at, (int, float)) and not isinstance(updated_at, bool) and now - float(updated_at) < 3600:
                return
            self._entries[key] = {
                "preferred_executor": executor,
                "backend_route": backend_route,
                "capabilities": capability_names,
                "verified_capabilities": verified,
                "action_successes": dict(action_successes) if isinstance(action_successes, Mapping) else {},
                "updated_at": now,
            }
            self._persist_locked()

    def note_action_success(
        self,
        handle: Any,
        intent: str,
        result: Mapping[str, Any],
    ) -> None:
        if result.get("verified") is not True:
            return
        key = self._key(getattr(handle, "app", ""))
        if not key:
            return
        with self._lock:
            entry = self._entries.get(key)
            if not isinstance(entry, dict):
                self.note_probe_success(handle)
                entry = self._entries.get(key)
            if not isinstance(entry, dict):
                return
            counts = entry.get("action_successes")
            counts = dict(counts) if isinstance(counts, Mapping) else {}
            name = str(intent or "").strip()
            if name:
                previous = counts.get(name, 0)
                if isinstance(previous, bool) or not isinstance(previous, int) or previous < 0:
                    previous = 0
                counts[name] = previous + 1
            entry["action_successes"] = counts
            entry["updated_at"] = self._clock()
            self._persist_locked()

    def health(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": True,
                "persistent": self.path is not None,
                "entry_count": len(self._entries),
                "max_age_s": self.max_age_s,
            }
