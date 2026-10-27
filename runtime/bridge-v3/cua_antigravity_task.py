"""Bounded real Antigravity headless task for task-owned ephemeral input only.

This is a REAL model invocation, unlike CLI discovery. It uses subscription
baseline quota (never a paid API key or optional purchased credits), with a
pinned model and sandboxed, task-owned workspace. Nothing from arbitrary owner
folders is passed in. A successful model response is *not* task completion
proof without an externally supplied exact expected answer.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile
import threading
from typing import Any, Callable, Mapping

from cua_cli_contracts import _allowed_path, _vendor_target
from cua_task_authority import identity, AuthorityError

MODEL = "gemini-3.8-flash-medium"
MAX_CONTEXT = 32768
MAX_PROMPT = 3000
MAX_OUTPUT = 16000
MAX_RAW = 160000
ENV_KEYS = frozenset({
    "PATH", "PATHEXT", "COMSPEC", "SYSTEMROOT", "WINDIR", "APPDATA",
    "LOCALAPPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "TEMP",
    "TMP", "PROGRAMFILES", "PROGRAMFILES(X86)", "HTTP_PROXY",
    "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "LANG",
})


class VendorTaskError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _subscription_gate(home: Path, local: Path) -> Path:
    """Explicitly close additional-credit and external API-key fallbacks."""
    if os.name != "nt":
        raise VendorTaskError("WINDOWS_REQUIRED")
    target = _vendor_target("antigravity", local)
    if not target:
        raise VendorTaskError("AGY_OFFICIAL_CLI_MISSING")
    vendor, executable = target
    if vendor != "antigravity" or not _allowed_path(local, executable, vendor):
        raise VendorTaskError("AGY_OFFICIAL_CLI_MISSING_OR_UNTRUSTED")
    settings = home / ".gemini" / "antigravity-cli" / "settings.json"
    if not settings.is_file() or settings.is_symlink() or settings.stat().st_size > 100000:
        raise VendorTaskError("AGY_BILLING_SETTINGS_UNVERIFIED")
    try:
        raw = json.loads(settings.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise VendorTaskError("AGY_BILLING_SETTINGS_UNVERIFIED") from exc
    if not isinstance(raw, dict):
        raise VendorTaskError("AGY_BILLING_SETTINGS_UNVERIFIED")
    paid = raw.get("useG1Credits", False)
    provider = raw.get("modelProvider")
    if type(paid) is not bool or paid is True:
        raise VendorTaskError("AGY_PAID_CREDITS_FORBIDDEN")
    if provider not in (None, "google", "antigravity"):
        raise VendorTaskError("AGY_EXTERNAL_API_PROVIDER_FORBIDDEN")
    return executable


def _checked_request(request: Mapping[str, Any]) -> tuple[str, str, str, str, str | None]:
    allowed = {
        "command", "app", "task", "operation", "agent_id", "task_id",
        "prompt", "context", "expected_response",
    }
    if set(request) - allowed:
        raise VendorTaskError("AGY_TASK_UNEXPECTED_ARGUMENT")
    if str(request.get("app") or "").casefold() not in {"antigravity", "agy"}:
        raise VendorTaskError("AGY_TASK_APP_INVALID")
    if request.get("task") != "antigravity.assistant" or request.get("operation") != "headless.answer":
        raise VendorTaskError("AGY_TASK_OPERATION_UNSUPPORTED")
    try:
        agent, task = identity(request.get("agent_id")), identity(request.get("task_id"))
    except AuthorityError as exc:
        raise VendorTaskError("AGY_TASK_OWNER_SCOPE_REQUIRED") from exc
    prompt, context, expected = request.get("prompt"), request.get("context"), request.get("expected_response")
    if not isinstance(prompt, str) or not 1 <= len(prompt) <= MAX_PROMPT or "\x00" in prompt:
        raise VendorTaskError("AGY_TASK_PROMPT_INVALID")
    if not isinstance(context, str) or not 1 <= len(context.encode("utf-8")) <= MAX_CONTEXT:
        raise VendorTaskError("AGY_TASK_CONTEXT_INVALID")
    if "expected_response" in request and (
        not isinstance(expected, str) or len(expected.encode("utf-8")) > MAX_OUTPUT
    ):
        raise VendorTaskError("AGY_TASK_EXPECTATION_INVALID")
    return agent, task, prompt, context, expected


def _collect_pipe(stream, result: dict, key: str):
    n = 0
    pieces = []
    while True:
        chunk = stream.read(8192)
        if not chunk:
            break
        if n < MAX_RAW:
            pieces.append(chunk[: MAX_RAW - n])
        n += len(chunk)
    result[key] = b"".join(pieces)
    result[key + "_truncated"] = n > MAX_RAW


def execute_headless_task(
    request: Mapping[str, Any], *, bridge_root: Path,
    user_home: Path | None = None, local_appdata: Path | None = None,
    process_factory: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Call official AGY only after a hard no-new-spend + task-scope gate."""
    agent, task, prompt, context, expected = _checked_request(request)
    home = user_home if user_home is not None else Path.home()
    local = local_appdata if local_appdata is not None else Path(os.environ.get("LOCALAPPDATA", ""))
    executable = _subscription_gate(Path(home), Path(local))
    from ff_win_owned_job import OwnedJobProcess
    factory = process_factory if process_factory is not None else OwnedJobProcess
    root = Path(bridge_root)
    if not root.is_absolute() or root.is_symlink():
        raise VendorTaskError("AGY_TASK_ROOT_INVALID")
    base = root / "owned-agent-tasks"
    if base.is_symlink():
        raise VendorTaskError("AGY_TASK_ROOT_INVALID")
    base.mkdir(parents=True, exist_ok=True)
    # Caller-supplied content has NO control over directories or executable flags.
    with tempfile.TemporaryDirectory(prefix="agy-owned-", dir=str(base)) as tempdir:
        folder = Path(tempdir)
        source = folder / "context.txt"
        source.write_text(context, encoding="utf-8")
        content_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        argv = [
            str(executable), "-p", prompt, "--model", MODEL,
            "--output-format", "json", "--print-timeout", "90s", "--sandbox",
        ]
        env = {k: v for k, v in os.environ.items() if k.upper() in ENV_KEYS}
        process = None
        captured: dict[str, Any] = {}
        timeout = False
        exit_code = None
        job_cleanup_verified = False
        try:
            process = factory(argv, cwd=str(folder), env=env)
            if process.stdin is not None:
                process.stdin.close()
                process.stdin = None
            reader_out = threading.Thread(
                target=_collect_pipe, args=(process.stdout, captured, "stdout"), daemon=True
            )
            reader_err = threading.Thread(
                target=_collect_pipe, args=(process.stderr, captured, "stderr"), daemon=True
            )
            reader_out.start()
            reader_err.start()
            try:
                exit_code = process.wait(timeout=105)
            except subprocess.TimeoutExpired:
                timeout = True
            if process.active_members():
                receipt = process.terminate_tree(timeout=8)
                job_cleanup_verified = receipt.get("descendant_cleanup_verified") is True
            else:
                job_cleanup_verified = True
            reader_out.join(timeout=5)
            reader_err.join(timeout=5)
            if reader_out.is_alive() or reader_err.is_alive():
                raise VendorTaskError("AGY_TASK_STREAM_CLEANUP_UNVERIFIED")
        except (OSError, subprocess.SubprocessError) as exc:
            raise VendorTaskError("AGY_TASK_PROCESS_FAILED") from exc
        finally:
            if process is not None:
                try:
                    if process.active_members():
                        process.terminate_tree(timeout=5)
                finally:
                    process.close()
        # Never emit raw stdout/stderr, paths, account names or CLI metadata.
        stdout = captured.get("stdout", b"")
        if (timeout or exit_code != 0 or captured.get("stdout_truncated")
                or not job_cleanup_verified):
            raise VendorTaskError("AGY_TASK_EXECUTION_UNVERIFIED")
        try:
            packet = json.loads(stdout.decode("utf-8"))
        except (UnicodeError, ValueError, AttributeError) as exc:
            raise VendorTaskError("AGY_TASK_RESULT_INVALID") from exc
        if not isinstance(packet, dict) or packet.get("status") != "SUCCESS":
            raise VendorTaskError("AGY_TASK_MODEL_DID_NOT_SUCCEED")
        answer = packet.get("response")
        if not isinstance(answer, str) or not 1 <= len(answer.encode("utf-8")) <= MAX_OUTPUT:
            raise VendorTaskError("AGY_TASK_RESPONSE_INVALID")
        answer = answer.strip()
        # A finished subprocess can still have changed its context through
        # an internal tool. Do not certify tasks if the sandbox changed.
        if (source.is_symlink() or not source.is_file()
                or hashlib.sha256(source.read_bytes()).hexdigest() != content_hash
                or {p.name for p in folder.iterdir()} != {"context.txt"}):
            raise VendorTaskError("AGY_TASK_WORKSPACE_MUTATED")
        externally_verified = expected is not None and answer == expected
        return {
            "schema": "ff-vendor-task-result-v1",
            "task": "antigravity.assistant", "operation": "headless.answer",
            "agent_id": agent, "task_id": task,
            "state": "COMPLETED" if externally_verified else "OUTCOME_UNKNOWN",
            "response": answer,
            "model_called": True, "model": MODEL,
            "result_verification": {
                "expected_response_supplied": expected is not None,
                "matches_expected": externally_verified if expected is not None else None,
                "independent_semantic_verification": False,
                "sandbox_context_unchanged": True,
                "owned_process_descendants_cleaned": job_cleanup_verified,
                "execution_status_success": True,
            },
            "billing": {
                "no_new_paid_credits_configured": True,
                "external_api_key_provider_used": False,
                "existing_subscription_quota_consumed": True,
                "account_remaining_quota_independently_verified": False,
                "no_charge_guarantee_from_vendor": False,
            },
            "effects": {
                "foreground_used": False, "physical_input_used": False,
                "caller_files_mutated": False, "workspace_is_ephemeral": True,
            },
        }
