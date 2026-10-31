from __future__ import annotations

import ctypes
import ctypes.wintypes
import os
import sys
import time
from pathlib import Path
from typing import Any

# Embedded/portable Python can run with an isolated search path that omits the
# script directory. Anchor sibling Bridge v3 imports to this file itself while
# preserving the interpreter's global isolation policy.
_CURRENT_FILE_DIRECTORY = str(Path(__file__).resolve().parent)
try:
    sys.path.remove(_CURRENT_FILE_DIRECTORY)
except ValueError:
    pass
sys.path.insert(0, _CURRENT_FILE_DIRECTORY)

import ff_win_v3_agent as core
import ff_win_v3_extras as extras
import ff_win_v3_documents as documents
import ff_win_v3_security as security
import ff_win_v3_upgrade as upgrade
import cua_bridge_v3
import cua_restricted_rpc
from cua_task_authority import AuthorityStore, AuthorityError, DesktopModes

security.apply(core, extras)
extras.register(core)
documents.register(core, extras)
upgrade.register(core)
_TASK_AUTHORITY = AuthorityStore(core.BRIDGE_ROOT / "state" / "task-authority")
cua_restricted_rpc.install(core, shell_policy="user", authority=_TASK_AUTHORITY)

_CUA_CONTROL_PLANE = cua_bridge_v3.CuaBridgeControlPlane(Path(__file__).resolve().parent)
# Register exact owned CUA surface targets for CLI-first policy; no title guessing.
core.cli_first_surfaces = _CUA_CONTROL_PLANE._surfaces

_INTERACTIVE_GUI_OVERRIDE_ENV = "FF_WIN_INTERACTIVE_GUI_OVERRIDE"
_INTERACTIVE_GUI_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def _interactive_gui_override_enabled() -> bool:
    # Historical env overrides no longer authorize remote desktop input.
    return False


def _desktop_fingerprint(hwnd):
    from cua_physical_runtime import Win32TargetApi
    target = Win32TargetApi().fingerprint(int(hwnd), 0)
    return {"hwnd": target.hwnd, "pid": target.pid, "process_start_ns": target.process_start_ns}


def _stop_desktop_input():
    runtime = _CUA_CONTROL_PLANE._physical
    if runtime is not None:
        runtime.close()
        _CUA_CONTROL_PLANE._physical = None


_DESKTOP_MODES = DesktopModes(core.BRIDGE_ROOT / "state" / "desktop-mode", _TASK_AUTHORITY,
                             _desktop_fingerprint, _stop_desktop_input)


def _set_desktop_mode(args):
    try:
        return _DESKTOP_MODES.transition(args)
    except (AuthorityError, OSError, ValueError) as exc:
        raise core.RPCError(str(exc) if isinstance(exc, AuthorityError) else "DESKTOP_MODE_UNAVAILABLE") from exc


def _deny_interactive_gui(reason: str, *, violations: list[str] | None = None) -> None:
    details: dict[str, Any] = {
        "reason": reason,
        "policy": "coexist",
        "required_mode": "dedicated",
        "next_step": "set_desktop_mode with authenticated task scope",
    }
    if violations:
        details["violations"] = list(violations)
    raise core.RPCError("INTERACTIVE_FOREGROUND_DISABLED", details=details)


def _enforce_computer_use_background_policy(args: dict[str, Any]) -> bool:
    if _interactive_gui_override_enabled():
        return False
    policy = args.get("policy")
    if policy is not None and not isinstance(policy, dict):
        raise core.RPCError("COMPUTER_USE_POLICY_INVALID")
    flags = [(args, "physical_input_allowed")]
    if isinstance(policy, dict):
        flags.extend((policy, name) for name in ("foreground_allowed", "physical_input_allowed", "background_required"))
    for container, name in flags:
        if name in container and type(container[name]) is not bool:
            raise core.RPCError("COMPUTER_USE_POLICY_INVALID", details={"flag": name})
    command = str(args.get("command") or "")
    violations: list[str] = []
    if command in {"acquire_physical_lease", "focus_target"}:
        violations.append(command)
    if args.get("physical_input_allowed") is True:
        violations.append("physical_input_allowed")
    policy = args.get("policy")
    if isinstance(policy, dict):
        if policy.get("foreground_allowed") is True:
            violations.append("policy.foreground_allowed")
        if policy.get("physical_input_allowed") is True:
            violations.append("policy.physical_input_allowed")
        if policy.get("background_required") is False:
            violations.append("policy.background_required=false")
    return bool(violations)


_HIDDEN_SESSIONS: dict[str, Any] = {}
_HIDDEN_LOCK = __import__("threading").Lock()

def _hidden_computer_use(args: dict[str, Any]) -> dict[str, Any]:
    from cua_hidden_desktop import HiddenDesktopSession, HiddenDesktopError
    command = args.get("command")
    try:
        if command == "hidden_start":
            if set(args)-{"command","worker_integrity","webview_debug"}:
                raise core.RPCError("HIDDEN_START_OPTION_INVALID")
            with _HIDDEN_LOCK:
                if len(_HIDDEN_SESSIONS) >= 4:
                    raise core.RPCError("HIDDEN_SESSION_LIMIT")
                session = HiddenDesktopSession(Path(__file__).resolve().parent,
                    worker_integrity=args.get("worker_integrity","owner"),webview_debug=args.get("webview_debug",False))
                _HIDDEN_SESSIONS[session.session_id] = session
            return {"session_id": session.session_id, "desktop": session.desktop_name,
                    "worker_pid": session.pid,
                    "supported_apps": session.supported_apps, "physical_input_used": False,
                    "worker_integrity":session.worker_integrity,"webview_debug_port":session.webview_port}
        session_id = args.get("session_id")
        with _HIDDEN_LOCK:
            session = _HIDDEN_SESSIONS.get(session_id)
            if command == "hidden_close":
                session = _HIDDEN_SESSIONS.pop(session_id, None)
        if session is None:
            raise core.RPCError("HIDDEN_SESSION_NOT_FOUND")
        if command == "hidden_close":
            session.close()
            return {"closed": True, "session_id": session_id,'editor_profile_cleanup':session.editor_profile_cleanup}
        payload = args.get("request")
        if not isinstance(payload, dict):
            raise core.RPCError("HIDDEN_REQUEST_INVALID")
        return session.request(payload,timeout_s=args.get("timeout_s",15))
    except HiddenDesktopError as exc:
        raise core.RPCError(exc.code, details={**exc.details,"retry_safe": False}) from exc

def _computer_use(args: dict[str, Any]) -> dict[str, Any]:
    from cua_cli_first_policy import enforce as enforce_cli_first
    enforce_cli_first(core, "computer_use", args)
    if args.get("command") in {
        "assistant_step", "assistant_task", "assistant_task_status",
        "assistant_task_reconcile",
    }:
        from cua_assistant_workflow import AssistantWorkflow, AssistantError
        from cua_assistant_step_ledger import AssistantStepLedger, WorkflowLedgerError
        ledger = AssistantStepLedger(core.BRIDGE_ROOT / "state" / "assistant-checkpoints")
        try:
            if args["command"] == "assistant_task_status":
                if set(args) != {"command", "agent_id", "task_id"}:
                    raise core.RPCError("ASSISTANT_CHECKPOINT_STATUS_SCOPE_INVALID")
                return ledger.status(args["agent_id"], args["task_id"])
            workflow = AssistantWorkflow(
                _computer_use, step_ledger=ledger if args["command"] == "assistant_task" else None,
            )
            if args["command"] == "assistant_task_reconcile":
                return AssistantWorkflow(_computer_use, step_ledger=ledger).reconcile_final(args)
            return workflow.run(args) if args["command"] == "assistant_task" else workflow.step(args)
        except (AssistantError, WorkflowLedgerError) as exc:
            raise core.RPCError(getattr(exc, "code", str(exc)), details=exc.details) from exc
    if "visible_launch_allowed" in args and type(args["visible_launch_allowed"]) is not bool:
        raise core.RPCError("VISIBLE_LAUNCH_FLAG_INVALID")
    interactive = _enforce_computer_use_background_policy(args)
    if args.get("visible_launch_allowed") is True:
        # A launch has no HWND yet. Its separate exact grant is serialized
        # with mode changes; observed HWNDs still need a fresh input scope.
        try:
            with _DESKTOP_MODES.launch_action(args):
                return _CUA_CONTROL_PLANE.dispatch(args)
        except AuthorityError as exc:
            raise core.RPCError(str(exc), details={"retry_safe": False}) from exc
        except cua_bridge_v3.CuaBridgeError as exc:
            raise core.RPCError(exc.code, exc.message, details=exc.details) from exc
    if args.get("command") in {"hidden_start", "hidden_request", "hidden_close"}:
        return _hidden_computer_use(args)
    try:
        if interactive:
            # Attach/observe first. The server's surface supplies the target,
            # never a caller-written HWND unrelated to the action's ref.
            surface = getattr(_CUA_CONTROL_PLANE, "_surfaces", {}).get(args.get("surface_id"), {})
            hwnd = (surface.get("target") or {}).get("hwnd")
            if not hwnd:
                if _DESKTOP_MODES.status()["mode"] == "coexist":
                    _deny_interactive_gui("explicit dedicated task mode required")
                raise core.RPCError("DESKTOP_SCOPED_SURFACE_REQUIRED")
            with _DESKTOP_MODES.action(args, hwnd):
                return _CUA_CONTROL_PLANE.dispatch(args)
        return _CUA_CONTROL_PLANE.dispatch(args)
    except AuthorityError as exc:
        raise core.RPCError(str(exc), details={"retry_safe": False}) from exc
    except cua_bridge_v3.CuaBridgeError as exc:
        raise core.RPCError(exc.code, exc.message, details=exc.details) from exc


def _gui_resolve_target(args: dict[str, Any]) -> dict[str, Any] | None:
    """Resolve an optional top-level GUI target and return stable geometry."""
    hwnd = args.get("target_hwnd")
    title = args.get("target_title_contains")
    if hwnd is None and not title:
        return None
    if hwnd is not None:
        if isinstance(hwnd, str):
            try:
                hwnd = int(hwnd, 0)
            except ValueError as exc:
                raise core.RPCError("GUI_HWND_INVALID") from exc
        if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
            raise core.RPCError("GUI_HWND_INVALID")
    else:
        matches = core.OPS["gui_list_windows"](
            {
                "visible_only": False,
                "title_contains": str(title),
                "limit": 100,
            }
        )["windows"]
        if not matches:
            raise core.RPCError("GUI_WINDOW_NOT_FOUND", details={"title_contains": str(title)})
        if len(matches) > 1 and not bool(args.get("allow_first_match", False)):
            raise core.RPCError(
                "GUI_WINDOW_TARGET_AMBIGUOUS",
                details={"title_contains": str(title), "matches": len(matches)},
            )
        hwnd = int(matches[0]["hwnd"])

    user32 = ctypes.windll.user32
    if not user32.IsWindow(hwnd):
        raise core.RPCError("GUI_WINDOW_NOT_FOUND", details={"hwnd": hwnd})
    rect = ctypes.wintypes.RECT()
    if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
        raise core.RPCError("GUI_WINDOW_RECT_FAILED", details={"hwnd": hwnd})
    length = int(user32.GetWindowTextLengthW(hwnd))
    buffer = ctypes.create_unicode_buffer(max(1, length + 1))
    user32.GetWindowTextW(hwnd, buffer, len(buffer))
    return {
        "hwnd": int(hwnd),
        "title": buffer.value,
        "rect": {
            "left": int(rect.left),
            "top": int(rect.top),
            "right": int(rect.right),
            "bottom": int(rect.bottom),
        },
    }


def _gui_prepare_target(args: dict[str, Any]) -> dict[str, Any] | None:
    target = _gui_resolve_target(args)
    if target is None:
        return None
    if bool(args.get("focus_before_input", True)):
        focused = core.OPS["gui_focus_window"](
            {
                "hwnd": target["hwnd"],
                "wait_ms": args.get("focus_wait_ms", 100),
                # _gui_prepare_target is reached only from an already opted-in
                # physical-input path. Propagate that authorization to the
                # guarded focus alias instead of bypassing the guard.
                "compatibility_physical_input": bool(args.get("compatibility_physical_input", False)),
            }
        )
        if not focused.get("ok"):
            raise core.RPCError("GUI_TARGET_FOCUS_FAILED", details={"target": target})
    foreground = int(ctypes.windll.user32.GetForegroundWindow())
    if bool(args.get("require_foreground", True)) and foreground != target["hwnd"]:
        raise core.RPCError(
            "GUI_TARGET_NOT_FOREGROUND",
            details={"target_hwnd": target["hwnd"], "foreground_hwnd": foreground},
        )
    target["foreground_hwnd"] = foreground
    return target


def _legacy_scoped_input(args, *, focus=False):
    # Compatibility aliases use the same marked, leased resource path as CUA.
    # Raw mouse_event/keybd_event helpers are never used by the network registry.
    if args.get("compatibility_physical_input") is not True and not (focus and args.get("allow_foreground") is True):
        raise core.RPCError("FOREGROUND_EXPLICIT_OPT_IN_REQUIRED" if focus else "LEGACY_PHYSICAL_INPUT_EXPLICIT_OPT_IN_REQUIRED")
    if _DESKTOP_MODES.status()["mode"] != "dedicated":
        _deny_interactive_gui("explicit dedicated task mode required")
    surface = getattr(_CUA_CONTROL_PLANE, "_surfaces", {}).get(args.get("surface_id"), {})
    hwnd = (surface.get("target") or {}).get("hwnd")
    if not hwnd:
        raise core.RPCError("DESKTOP_SCOPED_SURFACE_REQUIRED")
    requested = args.get("hwnd", args.get("target_hwnd", hwnd))
    if requested != hwnd:
        raise core.RPCError("DESKTOP_TARGET_OUTSIDE_SCOPE")
    policy = {"background_required": False, "foreground_allowed": True, "physical_input_allowed": True}
    payload = {**args, "policy": policy, "command": "focus_target" if focus else "act"}
    if not focus:
        if not isinstance(args.get("postcondition"), dict) or not args["postcondition"]:
            raise core.RPCError("POSTCONDITION_REQUIRED")
        if not args.get("lease") and not args.get("lease_id"):
            raise core.RPCError("PHYSICAL_LEASE_REQUIRED")
        events = args.get("events")
        if events is None and isinstance(args.get("text"), str):
            events = [{"kind": "unicode_char", "text": char} for char in args["text"]]
        if events is None and isinstance(args.get("keys"), list):
            events = [{"kind": "key_chord", "keys": args["keys"]}]
        if events is None and type(args.get("x")) is int and type(args.get("y")) is int:
            if args.get("legacy_mouse_action", args.get("action")) == "move":
                events = [{"kind": "mouse_move_at", "x": args["x"], "y": args["y"]}]
            else:
                flags = {"left": (2,4), "right": (8,16), "middle": (32,64)}.get(args.get("button","left"))
                if not flags or type(args.get("clicks",1)) is not int or not 1 <= args.get("clicks",1) <= 3:
                    raise core.RPCError("GUI_MOUSE_BUTTON_OR_CLICKS_INVALID")
                events = [{"kind": "mouse_click_at", "x": args["x"], "y": args["y"], "down_flags": flags[0], "up_flags": flags[1]}] * args.get("clicks",1)
        payload.update(operation="physical_sequence", action_args={"events": events})
    return _computer_use(payload)


def _gui_guard_mouse(original_mouse, args):
    return _legacy_scoped_input(args)


def _gui_guard_keyboard(original_keyboard, args):
    return _legacy_scoped_input(args)


def _gui_action_sequence(args: dict[str, Any]) -> dict[str, Any]:
    steps = args.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > 100:
        raise core.RPCError("GUI_SEQUENCE_INVALID")
    base: dict[str, Any] = {}
    for key in (
        "target_hwnd",
        "target_title_contains",
        "allow_first_match",
        "focus_before_input",
        "focus_wait_ms",
        "require_foreground",
        "require_inside_target",
        "compatibility_physical_input", "agent_id", "task_id", "mode_generation",
        "surface_id", "generation", "lease", "lease_id", "ref", "postcondition",
    ):
        if key in args:
            base[key] = args[key]
    results: list[dict[str, Any]] = []
    for index, raw_step in enumerate(steps):
        if not isinstance(raw_step, dict):
            raise core.RPCError("GUI_SEQUENCE_STEP_INVALID", details={"index": index})
        kind = str(raw_step.get("type") or raw_step.get("op") or "").lower()
        step = dict(base)
        step.update({key: value for key, value in raw_step.items() if key not in {"type", "op"}})
        if kind == "focus":
            target = _gui_resolve_target(step)
            if target is None:
                raise core.RPCError("GUI_WINDOW_TARGET_INVALID", details={"index": index})
            result = core.OPS["gui_focus_window"](
                {
                    "hwnd": target["hwnd"],
                    "wait_ms": step.get("wait_ms", 100),
                    "compatibility_physical_input": bool(step.get("compatibility_physical_input", False)),
                    "allow_foreground": bool(step.get("allow_foreground", False)),
                    **{key: step[key] for key in ("agent_id", "task_id", "mode_generation", "surface_id", "generation") if key in step},
                }
            )
        elif kind == "mouse":
            result = core.OPS["gui_mouse"](step)
        elif kind == "keyboard":
            result = core.OPS["gui_keyboard"](step)
        elif kind == "screenshot":
            result = core.OPS["gui_screenshot"](step)
        elif kind == "sleep":
            wait_ms = step.get("wait_ms", 0)
            if isinstance(wait_ms, bool) or not isinstance(wait_ms, (int, float)) or not 0 <= float(wait_ms) <= 5000:
                raise core.RPCError("GUI_SEQUENCE_SLEEP_INVALID", details={"index": index})
            time.sleep(float(wait_ms) / 1000.0)
            result = {"ok": True, "wait_ms": float(wait_ms)}
        elif kind == "assert_foreground":
            target = _gui_prepare_target(step)
            if target is None:
                raise core.RPCError("GUI_WINDOW_TARGET_INVALID", details={"index": index})
            result = {"ok": True, "target": target}
        else:
            raise core.RPCError("GUI_SEQUENCE_STEP_UNSUPPORTED", details={"index": index, "type": kind})
        results.append({"index": index, "type": kind, "result": result})
    return {"ok": True, "step_count": len(results), "steps": results}


def _install_gui_guards() -> None:
    original_mouse = core.OPS["gui_mouse"]
    original_keyboard = core.OPS["gui_keyboard"]
    original_focus = core.OPS.get("gui_focus_window")
    original_capabilities = core.OPS.get("capabilities")

    # Guard the canonical physical-input operations first.
    core.OPS["gui_mouse"] = lambda args: _gui_guard_mouse(original_mouse, args)
    core.OPS["gui_keyboard"] = lambda args: _gui_guard_keyboard(original_keyboard, args)

    # Legacy aliases used to bypass gui_mouse/gui_keyboard and call the raw
    # Win32 helpers directly. Wrap every physical alias with the same guard.
    for alias in ("gui_click", "mouse_click", "gui_move", "mouse_move"):
        original = core.OPS.get(alias)
        if original is not None:
            core.OPS[alias] = (lambda kind: (lambda args: _legacy_scoped_input({**args, "legacy_mouse_action": kind})))("move" if "move" in alias else "click")

    for alias in ("gui_type", "keyboard_type", "gui_hotkey", "keyboard_hotkey"):
        original = core.OPS.get(alias)
        if original is not None:
            core.OPS[alias] = (lambda fn: (lambda args: _gui_guard_keyboard(fn, args)))(original)

    # Changing the foreground window is itself intrusive. It needs explicit
    # opt-in and must prove that the target is a real window and became foreground.
    if original_focus is not None:
        def guarded_focus(args: dict[str, Any]) -> dict[str, Any]:
            return _legacy_scoped_input(args, focus=True)

        core.OPS["gui_focus_window"] = guarded_focus
        core.OPS["focus_window"] = guarded_focus

    core.OPS["gui_action_sequence"] = _gui_action_sequence
    core.OPS["computer_use"] = _computer_use

    from cua_agent_workflows import agent_workflows as _agent_workflows
    core.OPS["agent_workflows"] = lambda args: _agent_workflows()

    # Explicit owner-configured Skill-guided trusted agent pilot.
    # Separate from signed approvals; bounded Claude-only navigation or
    # empty-chat creation, never generic gui_mouse/gui_keyboard.
    from cua_trusted_skill_input import TrustedSkillInput, TrustedSkillError
    _trusted_skill = TrustedSkillInput(
        core.BRIDGE_ROOT / "state" / "trusted-skill-input.json",
        mouse=original_mouse,
    )

    def _trusted_skill_call(command, args):
        try:
            return {
                "status": lambda: _trusted_skill.status(),
                "begin": lambda: _trusted_skill.begin(args),
                "act": lambda: _trusted_skill.act(args),
                "end": lambda: _trusted_skill.end(args),
            }[command]()
        except TrustedSkillError as exc:
            raise core.RPCError(str(exc), details={"execution_started": False}) from exc

    core.OPS["trusted_skill_status"] = lambda args: _trusted_skill_call("status", args)
    core.OPS["trusted_skill_begin"] = lambda args: _trusted_skill_call("begin", args)
    core.OPS["trusted_skill_act"] = lambda args: _trusted_skill_call("act", args)
    core.OPS["trusted_skill_end"] = lambda args: _trusted_skill_call("end", args)

    # This is a protocol endpoint, NOT an approval issuer. It can prepare an
    # exact request and accept a separately signed host receipt, but never
    # transforms an agent claim or plain chat text into a grant.
    from cua_chat_consent import ChatConsentBroker, ChatConsentError
    _chat_consent = ChatConsentBroker(core.BRIDGE_ROOT / "state" / "chat-consent", _TASK_AUTHORITY)

    def _chat_consent_rpc(operation, args):
        try:
            if operation == "prepare":
                return _chat_consent.prepare(args.get("operation"), args.get("action"))
            if operation == "status":
                return _chat_consent.status(args.get("challenge_id"))
            if operation == "commit":
                return _chat_consent.commit(args.get("challenge_id"), args.get("signed_approval"))
        except (ChatConsentError, AuthorityError, OSError, ValueError) as exc:
            code = str(exc) if isinstance(exc, (ChatConsentError, AuthorityError)) else "CHAT_CONSENT_STORAGE_ERROR"
            raise core.RPCError(code, details={"execution_started": False}) from exc
        raise core.RPCError("CHAT_CONSENT_OPERATION_UNKNOWN", details={"execution_started": False})

    core.OPS["chat_consent_prepare"] = lambda args: _chat_consent_rpc("prepare", args)
    core.OPS["chat_consent_status"] = lambda args: _chat_consent_rpc("status", args)
    core.OPS["chat_consent_commit"] = lambda args: _chat_consent_rpc("commit", args)

    def capabilities(args: dict[str, Any]) -> dict[str, Any]:
        result = original_capabilities(args) if original_capabilities else {}
        features = result.setdefault("features", {})
        features["gui_target_guard"] = True
        features["cli_first_policy"] = {"version": 2, "active": True, "scope": "bridge_rpc",
                                        "gui_exception": "exact_owner_signed_approval"}
        features["gui_window_relative_coordinates"] = True
        features["gui_atomic_action_sequence"] = True
        features["cua_semantic_control_plane"] = True
        features["legacy_physical_requires_explicit_opt_in"] = True
        features["legacy_physical_aliases_guarded"] = True
        features["foreground_focus_requires_explicit_opt_in"] = True
        features["interactive_foreground_default_denied"] = True
        features["interactive_foreground_operator_override"] = False
        features["desktop_modes"] = ["coexist", "dedicated"]
        features["dedicated_mode_requires_task_approval"] = True
        features["durable_request_outcomes"] = True
        # This attests that the currently loaded dispatcher supports real
        # per-step assistant-task recovery, not that any app task succeeded.
        features["durable_assistant_step_checkpoints"] = {
            "version": 1,
            "status_rpc": "computer_use.assistant_task_status",
            "restart_safe_state_only": True,
            "automatic_mutation_replay_allowed": False,
            "read_only_final_artifact_reconciliation": True,
            "independent_app_task_success_attested": False,
        }
        features["agent_workflows_discovery"] = True
        features["trusted_skill_input_pilot"] = {
            "version": 1,
            "mode": "owner_opted_in_to_skill_guided_agent",
            "enabled": _trusted_skill.status()["enabled"],
            "allowed_app": "Claude Desktop",
            "allowed_purpose": _trusted_skill.status()["allowed_purpose"],
            "allowed_actions": ["focus","move","click","scroll"],
            "keyboard_allowed": False, "arbitrary_shell_allowed": False,
            "max_session_seconds": 600, "max_actions": 12,
            "independent_chat_attestation": False,
            "signed_approval_for_other_routes_unchanged": True,
        }
        features["chat_consent_challenge_protocol"] = {
            "version": 1, "attested_host_issuer_connected": False,
            "owner_grant_from_chat_text": False,
            "requires_signed_receipt": True,
            "operations": ["chat_consent_prepare", "chat_consent_status", "chat_consent_commit"],
        }
        result["agent_workflows"] = _agent_workflows()
        from cua_hidden_apps import available_apps
        features["hidden_desktop_supported_apps"] = available_apps()
        features["hidden_uia_no_focus_msaa_invoke"] = True
        features["hidden_worker_integrity_modes"] = ["owner","medium"]
        features["hidden_owned_panel_commands"] = ["panel.discover","panel.inspect","panel.type","panel.invoke","panel.verify"]
        from cua_owned_editor_launch import available_editors
        features['hidden_owned_editor_apps']=available_editors()
        features['hidden_owned_editor_commands']=['editor.launch','editor.observe','editor.replace_save']
        features['hidden_owned_editor_scope']='own private profile; native editor API; UTF-8 text <=65536 characters; independently verify saved file'
        guide = Path(_CURRENT_FILE_DIRECTORY) / "HIDDEN-PANEL-GUIDE.md"
        features["hidden_agent_guide_file"] = str(guide) if guide.is_file() else None
        features["hidden_excel_document_save"] = "own HWND native COM; save only; exact single workbook path"
        features["restricted_windows_mcp"] = True
        features["privileged_scripts_unrestricted"] = False
        features["run_code_isolation_default"] = "current_user"
        features["restricted_code_execution"] = True
        features["restricted_code_languages"] = ["python"]
        features["restricted_code_network_allowed"] = False
        features["trusted_shell_sessions_unrestricted"] = True
        features["shell_session_scope"] = "agent_id/task_id"
        result["operations"] = sorted(core.OPS)
        return result

    core.OPS["capabilities"] = capabilities
    core.OPS["set_desktop_mode"] = _set_desktop_mode
    core.OPS["desktop_mode_status"] = lambda args: _DESKTOP_MODES.status()


_install_gui_guards()

def _install_durable_requests() -> None:
    from ff_win_request_journal import (
        RequestJournal, RequestJournalError, choose_request_journal_root,
    )
    from ff_win_evidence import TaskEvidence, assess_response
    evidence = TaskEvidence(core.BRIDGE_ROOT / "state" / "evidence")
    journal = RequestJournal(choose_request_journal_root(
        bridge_root=core.BRIDGE_ROOT,
        override=os.environ.get("FF_BRIDGE_ROOT"),
        local_appdata=os.environ.get("LOCALAPPDATA"),
        home=Path.home(),
    ))
    supported = frozenset({
        "ping", "write_file", "copy_path", "move_file", "delete_path",
        "create_directory", "computer_use", "start_process", "run_code", "restricted_run_code",
    })
    def durable_call(args: dict[str, Any]) -> dict[str, Any]:
        op, payload = args.get("op"), args.get("args", {})
        if op not in supported or not isinstance(payload, dict):
            raise core.RPCError("DURABLE_OPERATION_INVALID")
        # Dispatch through the normal guarded registry; this is not a bypass.
        request = {"op": op, "args": payload, "target_device": args.get("target_device")}
        evidence_failed = []
        def record(event, **fields):
            try:
                evidence.append(args.get("agent_id", "unspecified"), args.get("task_id", args.get("request_key")),
                                {"event": event, "request_key": args.get("request_key"), "action": op, **fields})
            except (OSError, __import__("sqlite3").Error, ValueError, TypeError):
                evidence_failed.append(True)
        record("request_received", request=request, verification={"verified": False, "source": "none"})
        def dispatch():
            record("dispatch_started", outcome="pending")
            response = core.dispatch(request)
            record("dispatch_returned", response=response, **assess_response(response))
            return response
        try:
            result = journal.execute(args.get("request_key"), request, dispatch)
            record("outcome", outcome=result["state"], recovery={"deduplicated": result.get("deduplicated", False),
                   "next_step": "request_status and external verification" if result["state"] != "completed" else "verify postcondition"},
                   **(assess_response(result["response"]) if result.get("response") is not None else
                      {"verification": {"verified": False, "source": "none"}, "cleanup": "unknown"}))
            if evidence_failed:
                result["evidence_error"] = "EVIDENCE_UNAVAILABLE"
            return result
        except RequestJournalError as exc:
            raise core.RPCError(exc.code, details={"retry_safe": False}) from exc
    def request_status(args: dict[str, Any]) -> dict[str, Any]:
        try:
            result = journal.status(args.get("request_key"))
            try:
                evidence.append(args.get("agent_id", "unspecified"), args.get("task_id", args.get("request_key")),
                                {"event": "recovery_status", "request_key": args.get("request_key"), "outcome": result["state"],
                                 "recovery": {"automatic_replay": False}, "verification": {"verified": False, "source": "none"}})
            except (OSError, __import__("sqlite3").Error):
                result["evidence_error"] = "EVIDENCE_UNAVAILABLE"
            return result
        except RequestJournalError as exc:
            raise core.RPCError(exc.code, details={"retry_safe": False}) from exc
    def task_recovery_plan(args: dict[str, Any]) -> dict[str, Any]:
        # Trusted journal state is consulted server-side. Caller cannot pass
        # forged completion flags or stored response contents.
        from cua_durable_recovery import RecoveryCoordinator
        try:
            return RecoveryCoordinator(journal).plan(args.get("request_key"))
        except RequestJournalError as exc:
            raise core.RPCError(exc.code, details={"retry_safe": False}) from exc
    core.OPS["task_recovery_plan"] = task_recovery_plan
    core.OPS["durable_call"] = durable_call
    core.OPS["request_status"] = request_status
    core.OPS["request_journal_maintenance"] = lambda args: journal.maintain()
    core.OPS["export_task_evidence"] = lambda args: evidence.export(agent=args.get("agent_id"), task=args.get("task_id"), limit=args.get("limit", 100))

_install_durable_requests()

if __name__ == '__main__':
    raise SystemExit(core.main())
