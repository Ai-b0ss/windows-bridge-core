"""Observe/act/verify assistant steps for Office and Cursor, using live selectors.

No guessed buttons or substituted COM cell operation. The planner supplies a
selector and an observable postcondition from the actual installed UI.
"""
import hashlib
import difflib
import math
import time
from cua_assistant_step_ledger import WorkflowLedgerError
from pathlib import Path

class AssistantError(RuntimeError):
    def __init__(self, code, details=None):
        super().__init__(code)
        self.details = dict(details or {})

def _unwrap(response):
    if response.get("ok") is False:
        raise AssistantError(response.get("error_code", "ASSISTANT_ROUTE_FAILED"), response.get("details") or response.get("error_details"))
    return response

class AssistantWorkflow:
    def __init__(self, dispatch, *, step_ledger=None):
        self.dispatch = dispatch
        # The installed Bridge supplies a durable ledger. Direct unit uses can
        # inject one; no second/parallel assistant execution engine is created.
        self.step_ledger = step_ledger

    def step(self, args):
        if args.get("app", "").casefold() not in {"excel", "microsoft excel", "cursor", "word", "microsoft word", "winword.exe", "powerpoint", "microsoft powerpoint", "powerpnt.exe"}:
            raise AssistantError("ASSISTANT_APP_UNSUPPORTED")
        stage = args.get("stage")
        panel_open = self._open_panel_validate(args)
        context = {k: args[k] for k in ("surface_id", "policy", "agent_id", "task_id", "mode_generation") if k in args}
        if stage == "verify_artifact":
            # Independent verifier supplied by the caller: compare known bytes,
            # not the assistant's claim. No mutation is performed here.
            if not args.get("path") or not args.get("artifact_root"):
                raise AssistantError("ASSISTANT_ARTIFACT_SCOPE_REQUIRED")
            original = Path(args["path"]).absolute()
            root = Path(args["artifact_root"]).absolute()
            for item in (original, *original.parents, root, *root.parents):
                if item.is_symlink() or getattr(item, "is_junction", lambda: False)():
                    raise AssistantError("ASSISTANT_ARTIFACT_LINK_FORBIDDEN")
            try:
                path, root = original.resolve(strict=True), root.resolve(strict=True)
                if root not in path.parents or not path.is_file() or path.stat().st_size > 64*1024*1024:
                    raise AssistantError("ASSISTANT_ARTIFACT_OUTSIDE_SCOPE")
                raw = path.read_bytes()
            except OSError as exc:
                raise AssistantError("ASSISTANT_ARTIFACT_UNAVAILABLE") from exc
            digest = hashlib.sha256(raw).hexdigest()
            semantic = None
            if "artifact_expectation" in args:
                from cua_office_artifacts import verify_office_bytes, ArtifactError
                try:
                    semantic = verify_office_bytes(raw, args["app"], args["artifact_expectation"])
                except ArtifactError as exc:
                    raise AssistantError(str(exc)) from exc
            if ("expected_sha256" in args or semantic is None) and args.get("expected_sha256") != digest:
                raise AssistantError("ASSISTANT_ARTIFACT_POSTCONDITION_FAILED")
            result = {"ok": True, "verified": True, "stage": stage, "sha256": digest, "bytes": len(raw)}
            if semantic is not None: result["semantic_verification"] = semantic
            return result
        if stage not in {"open_panel", "select_assistant", "set_prompt", "send", "read_reply", "accept_edits", "save"}:
            raise AssistantError("ASSISTANT_STAGE_INVALID")
        if args.get("route") == "APP_CDP":
            return self._panel_step(args)
        selector = args.get("selector")
        if not isinstance(selector, dict) or not selector:
            raise AssistantError("ASSISTANT_SELECTOR_REQUIRED")
        snap = _unwrap(self.dispatch({"command": "observe", "options": args.get("observation_options", {}), **context}))
        if panel_open:
            target = args["panel_target"]
            if snap.get("target", {}).get("hwnd") != target["hwnd"] or snap.get("fingerprint", {}).get("process_id") != target["pid"]:
                raise AssistantError("ASSISTANT_PANEL_NATIVE_SCOPE_CHANGED", {"attempted": False, "retry_safe": True})
            existing = self._open_panel_probe(args)
            if existing is not None:
                return {"ok": True, "verified": True, "stage": stage, "route": "APP_CDP",
                        "attempted": False, "retry_safe": True, "already_open": True,
                        "physical_input_used": False, "verification": existing}
        found = _unwrap(self.dispatch({"command": "find", **context, "generation": snap["generation"], "query": selector}))
        matches = found.get("matches", found.get("entities", []))
        if len(matches) != 1:
            raise AssistantError("ASSISTANT_ELEMENT_MISSING" if not matches else "ASSISTANT_ELEMENT_AMBIGUOUS")
        entity = matches[0]
        generation = found.get("generation", snap["generation"])
        if stage == "read_reply":
            text = entity.get("value") or entity.get("name") or entity.get("text") or ""
            if not text or text == args.get("previous_text") or text == args.get("prompt"):
                raise AssistantError("ASSISTANT_REPLY_NOT_YET_OBSERVED")
            if args.get("expected_contains") and args["expected_contains"] not in text:
                raise AssistantError("ASSISTANT_REPLY_POSTCONDITION_FAILED")
            return {"ok": True, "verified": True, "stage": stage, "text": text, "generation": generation}
        postcondition = args.get("postcondition")
        if not isinstance(postcondition, dict) or not postcondition:
            raise AssistantError("ASSISTANT_POSTCONDITION_REQUIRED")
        operation = "set_value" if stage == "set_prompt" else "invoke"
        native_error = None
        try:
            result = _unwrap(self.dispatch({"command": "act", **context, "ref": entity["ref"], "generation": generation,
                                          "operation": args.get("operation", operation), "action_args": args.get("action_args", {}), "postcondition": postcondition}))
            if result.get("verified") is not True:
                raise AssistantError("ASSISTANT_ACTION_UNVERIFIED", {"attempted": result.get("attempted") is True, "retry_safe": False})
        except Exception as exc:
            if not isinstance(exc, AssistantError):
                if not hasattr(exc, "code"): raise
                exc = AssistantError(exc.code, getattr(exc, "details", None))
            if not panel_open or str(exc) not in {"STALE_TARGET", "ASSISTANT_ACTION_UNVERIFIED", "ACTION_UNVERIFIED"} or exc.details.get("attempted") is not True:
                raise exc
            native_error = exc
            result = {}
        if panel_open:
            deadline = time.monotonic() + args.get("panel_timeout_s", 15.0)
            polls = 0
            try:
                while True:
                    polls += 1
                    verified = self._open_panel_probe(args)
                    if verified is not None:
                        return {**result, "ok": True, "verified": True, "stage": stage,
                                "attempted": True, "retry_safe": False,
                                "physical_input_used": ((native_error.details.get("receipt") or {}).get("physical_input_used")
                                                        if native_error else result.get("physical_input_used")),
                                "route": snap.get("route"), "verification_route": "APP_CDP", "verification": verified,
                                "recovery": {"kind": "read_only_panel_verification", "polls": polls,
                                             "native_error": str(native_error) if native_error else None,
                                             "native_details": native_error.details if native_error else None,
                                             "action_replayed": False}}
                    if time.monotonic() >= deadline:
                        raise AssistantError("ASSISTANT_PANEL_OPEN_NOT_OBSERVED")
                    time.sleep(min(0.2, max(0.0, deadline-time.monotonic())))
            except AssistantError as exc:
                exc.details.update(attempted=True, retry_safe=False, native_error=str(native_error) if native_error else None, polls=polls)
                raise
        return {**result, "stage": stage}

    @classmethod
    def _open_panel_validate(cls, args):
        if "panel_postcondition" not in args:
            return False
        if args.get("stage") != "open_panel" or args.get("route") == "APP_CDP":
            raise AssistantError("ASSISTANT_PANEL_OPEN_SCOPE_INVALID")
        timeout = args.get("panel_timeout_s", 15.0)
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0.05 <= timeout <= 30:
            raise AssistantError("ASSISTANT_PANEL_OPEN_TIMEOUT_INVALID")
        probe = {**args, "postcondition": args["panel_postcondition"]}
        cls._panel_validate(probe)
        post = args["panel_postcondition"]
        if post["selector"].get("role") not in {"textbox", "combobox"} or post["state"].get("present") is False:
            raise AssistantError("ASSISTANT_PANEL_COMPOSER_REQUIRED")
        return True

    def _open_panel_probe(self, args):
        context = {k: args[k] for k in ("surface_id", "policy", "agent_id", "task_id", "mode_generation") if k in args}
        try:
            discovered = _unwrap(self.dispatch({"command": "auto", "app": args["app"], "intent": "discover", "refresh": True, **context}))
        except Exception as exc:
            if isinstance(exc, AssistantError): raise
            if hasattr(exc, "code"):
                raise AssistantError(exc.code, getattr(exc, "details", None)) from exc
            raise
        target = args["panel_target"]
        window = discovered.get("window") or {}
        if any(window.get(k) != target[k] for k in ("hwnd", "pid")):
            raise AssistantError("ASSISTANT_PANEL_TARGET_CHANGED")
        cdp = discovered.get("cdp")
        if not cdp:
            return None
        if (cdp.get("owner_identity") or {}).get("created") != target["created"]:
            raise AssistantError("ASSISTANT_PANEL_TARGET_CHANGED")
        try:
            return self._panel_dispatch(args, "panel.verify", action_args={"postcondition": args["panel_postcondition"], "timeout_s": 0.1})
        except AssistantError as exc:
            if str(exc) == "PANEL_POSTCONDITION_NOT_OBSERVED" and exc.details.get("attempted") is not True:
                return None
            raise

    @staticmethod
    def _panel_validate(args):
        from cua_universal_fastpath import UniversalFastPath, FastPathError
        target = args.get("panel_target")
        if not isinstance(target, dict) or set(target) != {"hwnd", "pid", "created"} or any(type(v) is not int or v <= 0 for v in target.values()):
            raise AssistantError("ASSISTANT_PANEL_TARGET_REQUIRED")
        stage = args.get("stage")
        if stage == "read_reply":
            selector = args.get("selector")
            if not isinstance(selector, dict) or not selector or set(selector) - {"name", "text", "role", "tag"} or any(not isinstance(v, str) or not v or len(v)>4096 for v in selector.values()):
                raise AssistantError("ASSISTANT_SELECTOR_REQUIRED")
            timeout = args.get("timeout_s", 30.0)
            if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0.05 <= timeout <= 120:
                raise AssistantError("ASSISTANT_REPLY_TIMEOUT_INVALID")
            if not isinstance(args.get("expected_contains"), str) or not args["expected_contains"]:
                raise AssistantError("ASSISTANT_REPLY_POSTCONDITION_REQUIRED")
            return
        intents = {"open_panel": "panel.verify", "select_assistant": "panel.invoke", "set_prompt": "panel.type",
                   "send": "panel.invoke", "accept_edits": "panel.invoke"}
        if stage not in intents:
            raise AssistantError("ASSISTANT_PANEL_STAGE_UNSUPPORTED")
        payload = {"postcondition": args.get("postcondition")}
        if stage != "open_panel":
            payload["selector"] = args.get("selector")
        if stage == "set_prompt":
            payload["text"] = args.get("prompt")
        try:
            UniversalFastPath.validate_panel_arguments(intents[stage], payload)
        except FastPathError as exc:
            raise AssistantError(exc.code, exc.details) from exc

    @staticmethod
    def _panel_entity(snapshot, selector):
        if snapshot.get("truncated"):
            raise AssistantError("ASSISTANT_PANEL_SNAPSHOT_TRUNCATED")
        matches = [c for c in snapshot.get("controls", []) if all(c.get(k) == v for k,v in selector.items())]
        if len(matches) > 1:
            raise AssistantError("ASSISTANT_ELEMENT_AMBIGUOUS")
        if not matches:
            raise AssistantError("ASSISTANT_ELEMENT_MISSING")
        if matches[0].get("text_truncated"):
            raise AssistantError("ASSISTANT_REPLY_TRUNCATED")
        return matches[0]

    def _panel_dispatch(self, args, intent, **payload):
        context = {k: args[k] for k in ("surface_id", "policy", "agent_id", "task_id", "mode_generation") if k in args}
        try:
            result = _unwrap(self.dispatch({"command": "auto", "app": args["app"], "intent": intent,
                                          "expected_window": args["panel_target"], **context, **payload}))
        except Exception as exc:
            if isinstance(exc, AssistantError): raise
            if hasattr(exc, "code"):
                raise AssistantError(exc.code, getattr(exc, "details", None)) from exc
            raise
        if result.get("verified") is not True or result.get("route") != "APP_CDP":
            raise AssistantError("ASSISTANT_ACTION_UNVERIFIED", {"attempted": result.get("attempted", True), "retry_safe": False})
        return result

    def _panel_step(self, args):
        self._panel_validate(args)
        stage = args["stage"]
        if stage == "read_reply":
            normalize = lambda text: " ".join(str(text or "").split())
            before = normalize(args.get("previous_text"))
            prompt = normalize(args.get("prompt"))
            expected = normalize(args["expected_contains"])
            deadline = time.monotonic() + args.get("timeout_s", 30.0)
            polls = 0
            while True:
                snap = self._panel_dispatch(args, "panel.inspect")
                polls += 1
                try:
                    entity = self._panel_entity(snap, args["selector"])
                except AssistantError as exc:
                    if str(exc) != "ASSISTANT_ELEMENT_MISSING": raise
                    entity = {}
                text = str(entity.get("value") or entity.get("text") or entity.get("name") or "")
                current = normalize(text)
                # The echoed prompt is delivery evidence, never an assistant reply.
                added = " ".join(current[b0:b1] for op,a0,a1,b0,b1 in difflib.SequenceMatcher(None,before,current,autojunk=False).get_opcodes() if op in {"insert","replace"})
                if prompt:
                    added = added.replace(prompt, "")
                if current != before and expected in normalize(added):
                    return {"ok": True, "verified": True, "stage": stage, "text": text,
                            "new_text": added, "polls": polls, "route": "APP_CDP", "physical_input_used": False,
                            "proof_scope": "new-observed-panel-text; independent artifact is still required"}
                if time.monotonic() >= deadline:
                    raise AssistantError("ASSISTANT_REPLY_NOT_YET_OBSERVED", {"attempted": False, "retry_safe": True, "polls": polls})
                time.sleep(min(0.2, max(0.0, deadline-time.monotonic())))
        intent = {"open_panel":"panel.verify","select_assistant":"panel.invoke","set_prompt":"panel.type",
                  "send":"panel.invoke","accept_edits":"panel.invoke"}[stage]
        payload = {"postcondition": args["postcondition"]}
        if stage != "open_panel": payload["selector"] = args["selector"]
        if stage == "set_prompt": payload["text"] = args["prompt"]
        return {**self._panel_dispatch(args, intent, action_args=payload), "stage": stage}

    def run(self, args):
        """Explicit sequence, stopping on the first uncertain/unverified effect.

        Every selector comes from the installed app's observed UI. A licence or
        login challenge remains a failed step; never substitute COM for chat.
        """
        if "observation_options" in args:
            options = args["observation_options"]
            if not isinstance(options, dict) or set(options) != {"max_items"} or type(options["max_items"]) is not int or not 1 <= options["max_items"] <= 512:
                raise AssistantError("ASSISTANT_OBSERVATION_OPTIONS_INVALID")
        plan = args.get("steps")
        if not isinstance(plan, list) or not 1 <= len(plan) <= 24:
            raise AssistantError("ASSISTANT_SEQUENCE_INVALID")
        if any(not isinstance(step, dict) for step in plan):
            raise AssistantError("ASSISTANT_SEQUENCE_INVALID")
        if plan[-1].get("stage") != "verify_artifact":
            raise AssistantError("ASSISTANT_FINAL_ARTIFACT_VERIFICATION_REQUIRED")
        # Validate the whole plan before any effect. A pre-existing file with
        # the expected digest alone cannot prove an assistant interaction.
        stages = [step.get("stage") for step in plan]
        if any(stage not in {"open_panel", "select_assistant", "set_prompt", "send", "read_reply", "accept_edits", "save", "verify_artifact"} for stage in stages):
            raise AssistantError("ASSISTANT_STAGE_INVALID")
        required = ["open_panel", "set_prompt", "send", "read_reply", "save", "verify_artifact"]
        if any(stages.count(stage) != 1 for stage in required):
            raise AssistantError("ASSISTANT_SEQUENCE_INCOMPLETE")
        if [stages.index(stage) for stage in required] != sorted(stages.index(stage) for stage in required):
            raise AssistantError("ASSISTANT_SEQUENCE_ORDER_INVALID")
        for index, step in enumerate(plan):
            if step.get("stage") == "select_assistant" and not stages.index("open_panel") < index < stages.index("set_prompt"):
                raise AssistantError("ASSISTANT_SEQUENCE_ORDER_INVALID")
            if step.get("stage") == "accept_edits" and not stages.index("read_reply") < index < stages.index("save"):
                raise AssistantError("ASSISTANT_SEQUENCE_ORDER_INVALID")
            for field in ("app", "surface_id", "policy", "agent_id", "task_id", "mode_generation", "panel_target"):
                if field in step and step[field] != args.get(field):
                    raise AssistantError("ASSISTANT_SEQUENCE_SCOPE_CHANGED")
        # Reject malformed expectations before any UI/model effect.
        final = {**args, **plan[-1]}
        if "artifact_expectation" in final:
            from cua_office_artifacts import validate_expectation, ArtifactError
            try:
                validate_expectation(final.get("app"), final["artifact_expectation"])
            except ArtifactError as exc:
                raise AssistantError(str(exc)) from exc
        # Preflight all explicit panel actions before opening, typing or sending.
        for step in plan:
            merged = {**args, **step}
            self._open_panel_validate(merged)
            if merged.get("route") == "APP_CDP":
                self._panel_validate(merged)
            elif "route" in step and step["route"] not in {"APP_CDP", "native"}:
                raise AssistantError("ASSISTANT_ROUTE_INVALID")
        panel_reply = next((step for step in plan if step.get("stage") == "read_reply" and {**args, **step}.get("route") == "APP_CDP"), None)
        ledger = self.step_ledger
        agent_id, task_id = args.get("agent_id"), args.get("task_id")
        if ledger is not None:
            try:
                ledger.reserve(args)
            except WorkflowLedgerError as exc:
                raise AssistantError(exc.code, exc.details) from exc
        receipts = []
        previous_text = None
        for index, step in enumerate(plan):
            merged = {**args, **step}
            try:
                # This durable record is committed BEFORE an action can send a
                # prompt, apply edits, save a file, or alter assistant state.
                # After a crash, a new request key cannot replay this stage.
                if ledger is not None:
                    ledger.before(agent_id, task_id, index, step["stage"])
                if step["stage"] == "send" and panel_reply is not None:
                    reply_args = {**args, **panel_reply}
                    snap = self._panel_dispatch(reply_args, "panel.inspect")
                    entity = self._panel_entity(snap, reply_args["selector"])
                    previous_text = entity.get("value") or entity.get("text") or entity.get("name") or ""
                if step["stage"] == "read_reply" and previous_text is not None:
                    merged["previous_text"] = previous_text
                    merged["prompt"] = next({**args, **entry}.get("prompt", "") for entry in plan if entry["stage"] == "set_prompt")
                receipt = self.step(merged)
                if ledger is not None:
                    ledger.after(agent_id, task_id, index, step["stage"], receipt)
                receipts.append(receipt)
            except Exception as exc:
                # Do not return or log prompt text, selector, private path, or
                # model response in persistence/secondary RPC error details.
                if ledger is not None:
                    try:
                        ledger.unknown(agent_id, task_id)
                    except WorkflowLedgerError:
                        pass  # DISPATCHING remains durable; still never replay.
                if isinstance(exc, WorkflowLedgerError):
                    exc = AssistantError(exc.code, exc.details)
                if isinstance(exc, AssistantError):
                    exc.details.update({"failed_stage": step["stage"],
                                        "completed_stages": [r["stage"] for r in receipts],
                                        "workflow_retry_safe": False,
                                        "durable_replay_allowed": False})
                    raise exc
                # A non-AssistantError can occur after the side effect; keep
                # the durable UNKNOWN marker and surface the original error.
                raise
        if ledger is not None:
            try:
                finished = ledger.finish(agent_id, task_id)
            except WorkflowLedgerError as exc:
                raise AssistantError(exc.code, exc.details) from exc
        else:
            finished = None
        result = {"ok": True, "verified": True, "verification": receipts[-1],
                  "steps": receipts, "proof_scope": "observed-ui-and-independent-artifact"}
        if finished is not None:
            result["durable_checkpoint"] = {
                "schema": ledger.SCHEMA,
                "state": "COMPLETED",
                "verified_steps": finished["verified_steps"],
                "automatic_replay_allowed": False,
            }
        return result
