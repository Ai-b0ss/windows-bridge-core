"""Ordinary current-user shell plus an explicit optional restricted executor."""
import os
from threading import BoundedSemaphore

_RUN_SLOTS = BoundedSemaphore(4)
TRUSTED_SHELL_OVERRIDE_ENV = "FF_WIN_TRUSTED_SHELL_OPERATOR_OVERRIDE"
IDENTITY_HINT = ("pass agent_id and task_id in args: 1 to 128 characters of letters, digits, "
                 "underscore, dot, colon or hyphen; sessions are visible only to the same pair")

from cua_restricted_execution import RestrictedExecutionError, run_python

def install(core, *, shell_policy="restricted", authority=None):
    if shell_policy not in {"restricted", "user"}:
        raise ValueError("SHELL_POLICY_INVALID")
    # Capture local startup policy. Request args/config cannot enable this.
    trusted_shell = shell_policy == "user" or os.environ.get(TRUSTED_SHELL_OVERRIDE_ENV) == "1"
    def scoped_process(name, original):
        from cua_task_authority import identity, AuthorityError, guard_effect
        checked = guard_effect(core, authority, name, original)
        def call(args):
            try:
                owner = (identity(args.get("agent_id")), identity(args.get("task_id")))
            except AuthorityError as exc:
                raise core.RPCError(str(exc), details={"execution_started": False,
                                                       "hint": IDENTITY_HINT}) from exc
            if name != "start_process":
                session = core.get_session(str(args.get("session_id") or ""))
                if getattr(session, "owner_scope", None) != owner:
                    raise core.RPCError("PROCESS_SESSION_OUTSIDE_TASK_SCOPE", details={"execution_started": False})
            result = checked(args)
            return result
        return call
    def guard_shell(original):
        def guarded(args):
            if not trusted_shell:
                raise core.RPCError("TRUSTED_SHELL_LOCAL_OPERATOR_REQUIRED", details={
                    "execution_started": False, "retry_safe": True,
                    "operator_override_env": TRUSTED_SHELL_OVERRIDE_ENV,
                    "restricted_alternative": "restricted_run_code",
                    "supported_restricted_languages": ["python"]})
            return original(args)
        return guarded
    for name in ("start_process", "interact_with_process"):
        original = core.OPS.get(name)
        if original is not None:
            if shell_policy == "user":
                core.OPS[name] = scoped_process(name, original)
            else:
                core.OPS[name] = guard_shell(original)
    original_capabilities = core.OPS.get("capabilities")
    def capabilities(args):
        result = original_capabilities(args) if original_capabilities else {}
        features = result.setdefault("features", {})
        features["trusted_shell_operator_override"] = shell_policy == "restricted" and trusted_shell
        features["trusted_shell_sessions_unrestricted"] = trusted_shell
        features["privileged_scripts_unrestricted"] = False
        features["shell_sessions_default_policy"] = "current_user" if shell_policy == "user" else "local_operator_only"
        features["shell_operator_override_env"] = TRUSTED_SHELL_OVERRIDE_ENV if shell_policy == "restricted" else None
        return result
    core.OPS["capabilities"] = capabilities
    def restricted_run_code(args):
        if not isinstance(args, dict):
            raise core.RPCError("RESTRICTED_ARGS_INVALID")
        unknown = sorted(set(args) - {"language", "code", "timeout_seconds"})
        if unknown:
            raise core.RPCError("RESTRICTED_OPTION_FORBIDDEN", details={"options": unknown})
        if str(args.get("language") or "python").lower() not in {"python", "py"}:
            raise core.RPCError("RESTRICTED_LANGUAGE_UNSUPPORTED", details={"supported": ["python"]})
        if not _RUN_SLOTS.acquire(blocking=False):
            raise core.RPCError("RESTRICTED_EXECUTION_BUSY", details={"execution_started": False})
        try:
            result = run_python(args.get("code"), timeout_seconds=args.get("timeout_seconds", 30))
        except RestrictedExecutionError as error:
            raise core.RPCError(error.code, details=error.details) from error
        finally:
            _RUN_SLOTS.release()
        if result.get("error_code"):
            raise core.RPCError(result["error_code"], details=result)
        return result
    if shell_policy == "user":
        from cua_task_authority import guard_effect
        for name in ("run_code", "delete_path", "kill_process"):
            if name in core.OPS:
                core.OPS[name] = guard_effect(core, authority, name, core.OPS[name])
        if "force_terminate" in core.OPS:
            core.OPS["force_terminate"] = scoped_process("force_terminate", core.OPS["force_terminate"])
        if "read_process_output" in core.OPS:
            core.OPS["read_process_output"] = scoped_process("read_process_output", core.OPS["read_process_output"])
        original_list = core.OPS.get("list_sessions")
        if original_list:
            def list_owned_sessions(args):
                from cua_task_authority import identity, AuthorityError
                try:
                    owner = (identity(args.get("agent_id")), identity(args.get("task_id")))
                except AuthorityError as exc:
                    raise core.RPCError(str(exc), details={"execution_started": False,
                                                           "hint": IDENTITY_HINT}) from exc
                result = original_list(args)
                with core.STATE.lock:
                    owned = {sid for sid, session in core.STATE.sessions.items()
                             if getattr(session, "owner_scope", None) == owner}
                return {**result, "sessions": [row for row in result.get("sessions", [])
                                               if row.get("session_id") in owned],
                        "scope": "agent_id/task_id"}
            core.OPS["list_sessions"] = list_owned_sessions
    else:
        core.OPS["run_code"] = restricted_run_code
    core.OPS["restricted_run_code"] = restricted_run_code
