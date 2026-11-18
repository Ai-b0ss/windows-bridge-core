"""Standing, scoped permissions for agents.

The owner decides ONCE which classes of action agents may take, optionally limited to an agent,
a project folder, an application, a site and a period. After that every action of an allowed
class runs without another question. The policy is a local file: it can be read over RPC but
never changed over RPC, so an agent cannot grant itself anything.

Nothing here answers a Windows, Chrome or website prompt. A class that needs the owner's
decision for each single action (money, messages to other people) cannot be made standing.
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

# class -> (default decision, may a standing grant allow it, what a standing grant must name)
RISK_CLASSES: dict[str, dict[str, Any]] = {
    "read_diagnose":      {"default": "allow", "grantable": True,  "scope": None,
                           "about": "reading, inspecting, diagnostics"},
    "own_resources":      {"default": "allow", "grantable": True,  "scope": None,
                           "about": "the agent's own tabs, hidden windows, processes, temporary files"},
    "browser_own_tabs":   {"default": "allow", "grantable": True,  "scope": None,
                           "about": "navigate, read and act inside the agent's own background tabs"},
    "browser_script":     {"default": "ask",   "grantable": True,  "scope": None,
                           "about": "run arbitrary JavaScript in the agent's own tab"},
    "project_write":      {"default": "ask",   "grantable": True,  "scope": "paths",
                           "about": "create or change files inside a named project folder"},
    "terminal_execute":   {"default": "ask",   "grantable": True,  "scope": "paths",
                           "about": "run an owner-authorized executable with a named cwd; not a filesystem sandbox"},
    "app_launch":         {"default": "ask",   "grantable": True,  "scope": "apps",
                           "about": "start a named application on the agent's private desktop"},
    "secret_use":         {"default": "ask",   "grantable": True,  "scope": "secrets",
                           "about": "use a stored credential through the broker (never reveal it)"},
    "foreground_input":   {"default": "ask",   "grantable": False, "scope": None,
                           "about": "use the Bridge desktop route with its chat consent, Stop and activity guards"},
    "system_settings":    {"default": "ask",   "grantable": True,  "scope": None,
                           "about": "change Windows or application settings"},
    "delete_user_data":   {"default": "ask",   "grantable": True,  "scope": "paths",
                           "about": "delete the owner's files or data"},
    "external_send":      {"default": "ask",   "grantable": False, "scope": None,
                           "about": "the owner must approve the exact recipient and text for each external message"},
    "financial":          {"default": "ask",   "grantable": False, "scope": None,
                           "about": "payments, purchases, trades and other significant commitments"},
}
POLICY_VERSION = 1


class PermissionError_(RuntimeError):
    def __init__(self, code: str, **details: Any):
        super().__init__(code)
        self.code = code
        self.details = details


def _norm_path(value: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(value)))


def _under(path: str, root: str) -> bool:
    path, root = _norm_path(path), _norm_path(root)
    return path == root or path.startswith(root.rstrip("\\/") + os.sep)


def _host_matches(host: str, pattern: str) -> bool:
    host, pattern = host.lower().strip("."), pattern.lower().strip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host != pattern[2:]
    return host == pattern


class Policy:
    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time):
        self.path = Path(path)
        self.clock = clock
        self._lock = threading.RLock()

    # ---- storage (local only) ------------------------------------------------------------
    def _load(self) -> dict:
        with self._lock:
            try:
                raw = self.path.read_text(encoding="utf-8")
            except FileNotFoundError:
                return {"version": POLICY_VERSION, "defaults": {}, "grants": []}
            except (OSError, UnicodeError) as exc:
                raise PermissionError_("POLICY_FILE_INVALID", path=str(self.path), cause=str(exc)) from exc
            try:
                # Authorization cannot trust mtime/size: an owner-side revoke may
                # preserve both. Read the small policy on every decision.
                data = json.loads(raw)
                if not isinstance(data, dict) or data.get("version") != POLICY_VERSION:
                    raise ValueError("version")
                if not isinstance(data.get("grants", []), list) or not isinstance(data.get("defaults", {}), dict):
                    raise ValueError("shape")
            except (ValueError, OSError) as exc:
                # A damaged policy must never widen access; decide() fails closed.
                raise PermissionError_("POLICY_FILE_INVALID", path=str(self.path), cause=str(exc)) from exc
            return data

    def _save(self, data: dict) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_name(self.path.name + "." + uuid.uuid4().hex + ".tmp")
            temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.replace(temporary, self.path)

    def add_grant(self, classes: list[str], *, agents: list[str] | None = None, paths: list[str] | None = None,
                  apps: list[str] | None = None, hosts: list[str] | None = None, secrets: list[str] | None = None,
                  ttl_seconds: float | None = None, note: str = "") -> dict:
        """Owner-side only (CLI). Refuses grants that could not be made standing safely."""
        if not classes:
            raise PermissionError_("GRANT_CLASSES_REQUIRED")
        for name in classes:
            spec = RISK_CLASSES.get(name)
            if spec is None:
                raise PermissionError_("RISK_CLASS_UNKNOWN", risk_class=name, known=sorted(RISK_CLASSES))
            if not spec["grantable"]:
                raise PermissionError_("RISK_CLASS_NOT_GRANTABLE", risk_class=name,
                                       reason="each such action needs the owner's own decision")
            needed = spec["scope"]
            if needed and not {"paths": paths, "apps": apps, "hosts": hosts, "secrets": secrets}[needed]:
                raise PermissionError_("GRANT_SCOPE_REQUIRED", risk_class=name, scope=needed)
            if name == "terminal_execute" and not apps:
                raise PermissionError_("GRANT_SCOPE_REQUIRED", risk_class=name, scope="apps")
        if ttl_seconds is not None and (type(ttl_seconds) not in (int, float) or ttl_seconds <= 0):
            raise PermissionError_("GRANT_TTL_INVALID")
        grant = {"grant_id": "grant-" + uuid.uuid4().hex[:12], "classes": list(classes),
                 "agents": list(agents) if agents else ["*"],
                 "paths": [_norm_path(item) for item in (paths or [])], "apps": [item.lower() for item in (apps or [])],
                 "hosts": [item.lower() for item in (hosts or [])], "secrets": list(secrets or []),
                 "created_at": self.clock(), "expires_at": self.clock() + ttl_seconds if ttl_seconds else None,
                 "revoked": False, "note": note[:300]}
        data = self._load()
        data = {**data, "grants": [*data.get("grants", []), grant]}
        self._save(data)
        return grant

    def revoke(self, grant_id: str) -> bool:
        data = self._load()
        found = False
        for grant in data.get("grants", []):
            if grant.get("grant_id") == grant_id and not grant.get("revoked"):
                grant["revoked"], grant["revoked_at"], found = True, self.clock(), True
        if found:
            self._save(data)
        return found

    def set_default(self, risk_class: str, decision: str) -> None:
        spec = RISK_CLASSES.get(risk_class)
        if spec is None or decision not in {"allow", "ask"}:
            raise PermissionError_("DEFAULT_INVALID")
        if decision == "allow" and (not spec["grantable"] or spec["scope"]):
            raise PermissionError_("DEFAULT_ALLOW_REFUSED", risk_class=risk_class,
                                   reason="this class must be granted with an explicit scope")
        data = self._load()
        data = {**data, "defaults": {**data.get("defaults", {}), risk_class: decision}}
        self._save(data)

    # ---- decisions -----------------------------------------------------------------------
    def describe(self) -> dict:
        try:
            data, error = self._load(), None
        except PermissionError_ as exc:
            data, error = {"defaults": {}, "grants": []}, exc.code
        now = self.clock()
        return {"version": POLICY_VERSION, "policy_error": error, "changeable_over_rpc": False,
                "classes": {name: {"default": data.get("defaults", {}).get(name, spec["default"]),
                                   "standing_grant_possible": spec["grantable"], "grant_must_name": spec["scope"],
                                   "about": spec["about"]} for name, spec in RISK_CLASSES.items()},
                "grants": [{key: grant.get(key) for key in ("grant_id", "classes", "agents", "paths", "apps", "hosts",
                                                             "secrets", "expires_at", "note")}
                           for grant in data.get("grants", [])
                           if not grant.get("revoked") and (grant.get("expires_at") is None or grant["expires_at"] > now)]}

    def decide(self, agent_id: str, risk_class: str, target: dict | None = None) -> dict:
        """allow, or needs_owner with the exact reason. Never raises for an ordinary refusal."""
        target = target or {}
        spec = RISK_CLASSES.get(risk_class)
        if spec is None:
            return {"decision": "needs_owner", "risk_class": risk_class, "reason": "RISK_CLASS_UNKNOWN", "grant_id": None}
        try:
            data = self._load()
        except PermissionError_ as exc:
            return {"decision": "needs_owner", "risk_class": risk_class, "reason": exc.code, "grant_id": None}
        if not spec["grantable"]:
            return {"decision": "needs_owner", "risk_class": risk_class, "grant_id": None,
                    "reason": "OWNER_DECISION_PER_ACTION", "standing_grant_possible": False}
        default = data.get("defaults", {}).get(risk_class, spec["default"])
        if default == "allow" and not spec["scope"]:
            return {"decision": "allow", "risk_class": risk_class, "reason": "CLASS_ALLOWED_BY_DEFAULT", "grant_id": None}
        now = self.clock()
        near = "NO_MATCHING_GRANT"
        for grant in data.get("grants", []):
            if grant.get("revoked") or risk_class not in grant.get("classes", []):
                continue
            if risk_class == "terminal_execute" and not grant.get("apps"):
                near = "APP_NOT_GRANTED"
                continue
            if grant.get("expires_at") is not None and grant["expires_at"] <= now:
                near = "GRANT_EXPIRED"
                continue
            agents = grant.get("agents") or ["*"]
            if "*" not in agents and agent_id not in agents:
                near = "GRANT_FOR_OTHER_AGENT"
                continue
            # Every supplied constraint is binding, including optional constraints on
            # classes that do not require a particular scope at grant creation.
            if grant.get("paths") or spec["scope"] == "paths":
                path = target.get("path")
                if not isinstance(path, str) or not any(_under(path, root) for root in grant.get("paths", [])):
                    near = "TARGET_OUTSIDE_GRANTED_PATHS"
                    continue
            if grant.get("apps") or spec["scope"] == "apps":
                app = str(target.get("app") or "").lower()
                names = {app, os.path.basename(app), os.path.splitext(os.path.basename(app))[0]}
                for alias in target.get("aliases") or []:
                    if isinstance(alias, str) and alias:
                        names.add(alias.lower())
                if not names & set(grant.get("apps", [])):
                    near = "APP_NOT_GRANTED"
                    continue
            if grant.get("hosts") or spec["scope"] == "hosts":
                host = str(target.get("host") or "")
                if not host or not any(_host_matches(host, pattern) for pattern in grant.get("hosts", [])):
                    near = "HOST_NOT_GRANTED"
                    continue
            if grant.get("secrets") or spec["scope"] == "secrets":
                if target.get("secret") not in grant.get("secrets", []):
                    near = "SECRET_NOT_GRANTED"
                    continue
            return {"decision": "allow", "risk_class": risk_class, "reason": "STANDING_GRANT",
                    "grant_id": grant["grant_id"], "expires_at": grant.get("expires_at")}
        return {"decision": "needs_owner", "risk_class": risk_class, "reason": near, "grant_id": None,
                "standing_grant_possible": True, "grant_must_name": spec["scope"]}
