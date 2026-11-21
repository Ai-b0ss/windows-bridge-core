"""Opt-in Bridge gateway to the shared Hub; no desktop or browser work at import.

The Hub journal is authoritative for Hub mutations. Forward its request key and
session credentials unchanged; never silently create/resume an agent session.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable


class HubGatewayError(RuntimeError):
    def __init__(self, code: str, **details: Any):
        super().__init__(code)
        self.code, self.details = code, details


class HubGateway:
    def __init__(self, bridge_root: Path, *, client_factory: Callable | None = None,
                 starter: Callable | None = None):
        self.config_path = Path(bridge_root) / "state" / "universal-agent-runtime.json"
        self.state_dir = Path(bridge_root) / "state" / "hub"
        self._client_factory, self._starter = client_factory, starter

    def discovery(self) -> dict:
        enabled, status = False, "disabled"
        try:
            config = json.loads(self.config_path.read_text(encoding="utf-8"))
            if (not isinstance(config, dict) or type(config.get("version")) is not int
                    or config["version"] != 1 or type(config.get("enabled")) is not bool):
                raise ValueError("config")
            enabled = config["enabled"]
            status = "enabled" if enabled else "disabled"
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            status = "invalid_config"
        return {
            "version": 1, "available": True, "enabled": enabled, "status": status,
            "bridge_op": "hub", "starts_on_discovery": False,
            "entry_http_path": "/agent/v1", "mcp_transport": "stdio",
            "request_fields": ["op", "args", "session_id", "session_secret", "request_key"],
            "session_bootstrap": "session_open {agent_id, task_id}; keep returned credentials and resume_token",
            "discovery_op": "capabilities", "route_plan_op": "route_plan",
            "mutation_journal": "hub.request_status",
            "primary_owner_auth_browser_route": "owner_chrome_profile1_hidden_secondary",
            "optional_isolated_browser_route": "isolated_hidden_browser",
            "default_browser_route": "owner_chrome_profile1_hidden_secondary",
            "owner_chrome_requires_explicit_route": True,
            "isolated_substitution_forbidden": True,
            "silent_playwright_fallback": False,
            "cleanup_receipt_fields": ["closed", "cleanup_verified", "resources_retained"],
            "automatic_mutation_replay": False, "foreground_input_available": False,
            "agent_identity": "client labels within trusted same-user transport, not an OS security boundary",
            "live_browser_or_gui_verified": False,
        }

    def call(self, request: dict) -> dict:
        info = self.discovery()
        if not info["enabled"]:
            raise HubGatewayError("HUB_FEATURE_DISABLED", status=info["status"], execution_started=False)
        if (not isinstance(request, dict) or set(request) - set(info["request_fields"])
                or not isinstance(request.get("op"), str) or not request["op"]
                or not isinstance(request.get("args", {}), dict)):
            raise HubGatewayError("HUB_REQUEST_INVALID", execution_started=False)
        # Owner-side configuration/grants/secrets are deliberately absent from
        # the Hub RPC API. Arbitrary endpoints, state roots and keys cannot be
        # selected by the caller of this gateway.
        from ff_hub import HubClient, HubError, ensure_running
        try:
            (self._starter or ensure_running)(self.state_dir)
            client = (self._client_factory or HubClient)(self.state_dir)
            reply = client.raw(dict(request))
        except HubError as exc:
            raise HubGatewayError(exc.code, **exc.details) from None
        except (OSError, ValueError, TypeError):
            raise HubGatewayError("HUB_UNREACHABLE", retry_safe=False) from None
        if not isinstance(reply, dict) or type(reply.get("ok")) is not bool:
            raise HubGatewayError("HUB_REPLY_INVALID", retry_safe=False)
        if reply["ok"] and not isinstance(reply.get("result"), dict):
            raise HubGatewayError("HUB_REPLY_INVALID", retry_safe=False)
        if not reply["ok"]:
            details = reply.get("details") or {}
            if not isinstance(details, dict):
                raise HubGatewayError("HUB_REPLY_INVALID", retry_safe=False)
            raise HubGatewayError(reply.get("error_code") or "HUB_ERROR", **details)
        return reply["result"]
