"""REAL local Windows RPC smoke: fresh process, no user profiles or paid APIs.

Run with: python tests/integration/isolated_rpc_smoke.py
It starts ONLY its own loopback Bridge in a TemporaryDirectory and tears it down.
Never accesses a live user's Bridge, API keys or remote transport.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import urllib.error
import urllib.request

REPO=Path(__file__).resolve().parents[2]
SERVER=REPO/"runtime/bridge-v3/ff_win_v3_main.py"
TRACKED=REPO/"runtime/bridge-v3/cua_router.py"


def verify(check: bool,code: str):
    if not check:
        raise RuntimeError(code)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0))
        return int(sock.getsockname()[1])


def rpc(port: int,secret: str,op: str,args: dict,task: str) -> dict:
    body=json.dumps({
        "task_id":task,"target_device":platform.node(),"op":op,"args":args,
    },ensure_ascii=False).encode("utf-8")
    request=urllib.request.Request(
        f"http://127.0.0.1:{port}/rpc",
        data=body,method="POST",
        headers={"X-FF3-Key":secret,"Content-Type":"application/json"},
    )
    # Loopback only; never route an agent secret via environment HTTP proxies.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request,timeout=12) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())


def verify_rpc(port: int,secret: str):
    checks=[]
    ping=rpc(port,secret,"ping",{},"ci-read-ping")
    verify(ping.get("ok") is True,"PING_FAILED")
    checks.append("ping")

    cap=rpc(port,secret,"capabilities",{},"ci-read-capabilities")
    verify(cap.get("ok") is True,"CAPABILITIES_FAILED")
    features=(cap.get("result") or {}).get("features") or {}
    verify((features.get("cli_first_policy") or {}).get("active") is True,
           "CLI_FIRST_GUARD_INACTIVE")
    checks.append("cli_first_guard")

    discovery=rpc(port,secret,"agent_workflows",{},"ci-agent-workflow-bootstrap")
    verify(discovery.get("ok") is True,"AGENT_WORKFLOWS_READ_FAILED")
    flow=discovery.get("result") or {}
    verify(flow.get("schema")=="ff-windows-agent-workflows-v1",
           "AGENT_WORKFLOW_SCHEMA_INVALID")
    verify(flow.get("manifest_is_authorization") is False
           and flow.get("owner_chat_permission_attested") is False
           and flow.get("task_completed") is False,
           "AGENT_WORKFLOW_CLAIMED_UNVERIFIED_CAPABILITY")
    verify(features.get("agent_workflows_discovery") is True
           and (cap.get("result") or {}).get("agent_workflows")==flow,
           "AGENT_WORKFLOW_NOT_ADVERTISED_BY_CAPABILITIES")
    flow_steps = flow.get("flow") or []
    research = next((x for x in flow_steps
                     if x.get("step") == "research_missing_programmatic_interfaces"), None)
    visible = next((x for x in flow_steps
                    if x.get("step") == "request_explicit_chat_foreground_permission_if_needed"), None)
    verify(isinstance(research,dict)
           and research.get("actor") == "chatgpt_agent"
           and research.get("required_before_visible_input") is True
           and research.get("unavailable_web_is_route_exhaustion") is False
           and research.get("research_performed_by_bridge") is False,
           "MANIFEST_MISSING_REAL_EXTERNAL_RESEARCH_REQUIREMENT")
    verify(isinstance(visible,dict)
           and visible.get("required_even_if_owner_away") is True
           and visible.get("owner_confirmation_channel") == "same_chat_text"
           and visible.get("chat_text_alone_is_trusted_grant") is False
           and visible.get("visible_input_allowed_without_host_receipt") is False,
           "MANIFEST_MISSING_ALWAYS_ASK_SAME_CHAT_WITH_TRUSTED_BROKER")
    checks.append("mandatory_web_research_and_explicit_in_chat_foreground_gate")
    checks.append("new_chat_readonly_agent_workflow_bootstrap")

    task=rpc(port,secret,"computer_use",{
        "command":"task_preflight","app":"git",
        "task":"inspect the repository status without modifying files",
    },"ci-task-preflight")
    verify(task.get("ok") is True,"TASK_PREFLIGHT_FAILED")
    info=task.get("result") or {}
    verify(info.get("schema")=="ff-cua-task-preflight-v1","TASK_PREFLIGHT_SCHEMA")
    for field in ("action_executed","task_completed","model_called",
                  "foreground_used","billing_or_purchase_executed",
                  "owner_authorization_verified"):
        verify(info.get(field) is False,"TASK_PREFLIGHT_UNSAFE_"+field)
    decision = info.get("orchestration") or {}
    research_gate = decision.get("programmatic_research") or {}
    chat_gate = decision.get("visible_permission_flow") or {}
    verify(research_gate.get("required_before_visible_fallback") is True
           and research_gate.get("web_research_performed") is False
           and research_gate.get("unavailable_web_is_exhaustion") is False,
           "REAL_PREFLIGHT_FALSE_WEB_RESEARCH_EXHAUSTION")
    verify(chat_gate.get("explicit_chat_question_required") is True
           and chat_gate.get("required_even_when_owner_away") is True
           and chat_gate.get("host_attested_grant_received") is False
           and chat_gate.get("owner_confirmation_channel") == "same_chat_text",
           "REAL_PREFLIGHT_FALSE_CHAT_APPROVAL")
    verify(decision.get("schema") == "ff-task-orchestration-gate-v1",
           "TASK_ORCHESTRATION_GATE_MISSING")
    safety = decision.get("guards") or {}
    for field in ("execution_allowed", "foreground_input_allowed",
                  "paid_inference_allowed", "external_postcondition_verified",
                  "new_mutation_started"):
        verify(safety.get(field) is False, "TASK_ORCHESTRATION_UNSAFE_" + field)
    verify(decision.get("route_exhaustion_proven") is False
           and decision.get("visible_last_resort_eligible") is False
           and (decision.get("cost_policy") or {}).get("zero_new_spend") is True,
           "TASK_ORCHESTRATION_FALSE_CONSENT_OR_EXHAUSTION")
    checks.append("read_only_task_preflight")
    checks.append("task_aware_orchestration_guard")

    # New real RPC recovery surface: no UI/assistant launch, no model,
    # no arbitrary request data or authorization claims accepted.
    checkpoint=rpc(port,secret,"computer_use",{
        "command":"assistant_task_status",
        "agent_id":"ci-owned-task-agent",
        "task_id":"ci-never-created-task",
    },"ci-assistant-task-status")
    verify(checkpoint.get("ok") is True,"ASSISTANT_CHECKPOINT_STATUS_UNAVAILABLE")
    recorded=checkpoint.get("result") or {}
    verify(recorded.get("schema")=="ff-assistant-step-checkpoint-v1"
           and recorded.get("state")=="NOT_FOUND"
           and recorded.get("automatic_replay_allowed") is False
           and recorded.get("retry_safe") is False,
           "ASSISTANT_CHECKPOINT_STATUS_FALSE_REPLAY")
    forged=rpc(port,secret,"computer_use",{
        "command":"assistant_task_status",
        "agent_id":"ci-owned-task-agent",
        "task_id":"ci-never-created-task",
        "approved":True,
    },"ci-assistant-status-forged-grant")
    verify(forged.get("ok") is False
           and forged.get("error_code")=="ASSISTANT_CHECKPOINT_STATUS_SCOPE_INVALID",
           "ASSISTANT_CHECKPOINT_STATUS_SCOPE_BYPASS")
    checks.append("durable_assistant_task_readonly_recovery_status")

    # Optional subprocess probes run only known vendor --help/--version and
    # Cursor's redacted status. In a clean runner, no CLI is expected.
    for app in ("cursor","antigravity"):
        vendor=rpc(port,secret,"computer_use",{
            "command":"task_preflight","app":app,
            "task":"investigate CLI contract without AI inference",
            "verify_cli_contract":True,
            "include_auth_status":app=="cursor",
        },"ci-vendor-cli-contract-"+app)
        verify(vendor.get("ok") is True,"VENDOR_READONLY_PROBE_FAILED_"+app)
        parsed=(vendor.get("result") or {}).get("cli_contract")
        verify(isinstance(parsed,dict) and parsed.get("schema")=="ff-cli-contract-v1",
               "VENDOR_PROBE_SCHEMA_"+app)
        for claim in ("model_called","paid_api_invoked","task_completed",
                      "quota_and_pricing_verified","authenticated_task_execution_verified"):
            verify(parsed.get(claim) is False,"VENDOR_INCORRECT_CLAIM_"+claim)
        # No host pathname, account identity or token is ever returned.
        verify("@" not in json.dumps(parsed),"VENDOR_PROBE_ACCOUNT_LEAK")
        verify("AppData" not in json.dumps(parsed),"VENDOR_PROBE_PROFILE_LEAK")
    checks.append("vendor_cli_help_auth_no_inference")

    office=rpc(port,secret,"computer_use",{
        "command":"task_preflight","app":"Excel",
        "task":"Inspect a temporary workbook using native COM",
        "verify_office_com":True,
    },"ci-office-com-registry")
    verify(office.get("ok") is True,"OFFICE_REGISTRATION_PROBE_FAILED")
    registered=(office.get("result") or {}).get("office_com_registration")
    verify(isinstance(registered,dict) and
           registered.get("schema")=="ff-excel-com-discovery-v1",
           "OFFICE_REGISTRATION_PROBE_SCHEMA")
    for key in ("excel_process_started","user_workbook_accessed",
                "model_called","task_completed","task_support_proven"):
        verify(registered.get(key) is False,
               "OFFICE_REGISTRATION_INCORRECT_TASK_PROOF_"+key)
    checks.append("excel_com_registration_without_launch")

    unsafe=rpc(port,secret,"computer_use",{
        "command":"task_preflight","app":"cursor",
        "task":"read-only analysis","physical_input_allowed":True,
        "approved":True,
    },"ci-forbidden-foreground")
    verify(unsafe.get("ok") is False and
           unsafe.get("error_code")=="INTERACTIVE_FOREGROUND_DISABLED",
           "UNTRUSTED_FOREGROUND_CLAIM_NOT_REJECTED")
    checks.append("untrusted_foreground_denial")

    filename_sha=hashlib.sha256(TRACKED.read_bytes()).hexdigest()
    # Explicit agent/task identity is mandatory for normal process sessions.
    unscoped=rpc(port,secret,"start_process",{
        "command":"git status --porcelain=v1 --untracked-files=no",
        "cwd":str(REPO),"shell":"powershell.exe",
    },"ci-unscoped-process")
    verify(unscoped.get("ok") is False and
           unscoped.get("error_code")=="AUTHORITY_IDENTITY_INVALID",
           "UNSCOPED_PROCESS_WAS_NOT_REJECTED")
    checks.append("process_scope_denial")

    command="git status --porcelain=v1 --untracked-files=no"
    task_id="ci-git-status"
    started=rpc(port,secret,"start_process",{
        "command":command,"cwd":str(REPO),"shell":"powershell.exe",
        "wait_ms":500,"detached":False,
        "agent_id":"ci-readonly-agent","task_id":task_id,
    },"ci-scoped-git-start")
    verify(started.get("ok") is True,
           "SCOPED_READONLY_PROCESS_FAILED_"+str(started.get("error_code")))
    session_id=(started.get("result") or {}).get("session_id")
    verify(isinstance(session_id,str) and len(session_id)>3,"SESSION_ID_MISSING")
    exit_code=None
    for n in range(40):
        output=rpc(port,secret,"read_process_output",{
            "session_id":session_id,"max_chars":10000,
            "agent_id":"ci-readonly-agent","task_id":task_id,
        },"ci-git-read-"+str(n))
        verify(output.get("ok") is True,"SESSION_OUTPUT_UNAVAILABLE")
        exit_code=(output.get("result") or {}).get("exit_code")
        if exit_code is not None:break
        time.sleep(.2)
    verify(exit_code==0,"READONLY_GIT_FAILED_"+str(exit_code))
    independent=subprocess.run(
        ["git","-C",str(REPO),"status","--porcelain=v1","--untracked-files=no"],
        capture_output=True,text=True,timeout=10,check=True,
    )
    verify(independent.returncode==0,"INDEPENDENT_GIT_VERIFY_FAILED")
    verify(hashlib.sha256(TRACKED.read_bytes()).hexdigest()==filename_sha,
           "SOURCE_FILE_MODIFIED")
    checks.append("actual_git_cli_execution_independent_sha_verification")

    # Execute one safe scoped read-only command through the EXISTING
    # persistent durable_call machinery. Repeating the exact request must
    # return the same session id; a conflicting request key must be denied.
    durable={
        "request_key":"ci-owned-durable-git-001",
        "op":"start_process",
        "args":{
            "command":"git status --porcelain=v1 --untracked-files=no",
            "cwd":str(REPO),"shell":"powershell.exe","wait_ms":500,
            "agent_id":"ci-readonly-agent","task_id":"ci-durable-git",
        },
        "target_device":platform.node(),
        "agent_id":"ci-readonly-agent","task_id":"ci-durable-git",
    }
    first=rpc(port,secret,"durable_call",durable,"ci-durable-first")
    verify(first.get("ok") is True,"DURABLE_RPC_INITIAL_FAILED")
    first_result=first.get("result") or {}
    verify(first_result.get("state")=="completed" and first_result.get("cached") is False,
           "DURABLE_FIRST_NOT_COMPLETED")
    response=first_result.get("response") or {}
    verify(response.get("ok") is True,"DURABLE_DISPATCH_NOT_OK")
    first_session=(response.get("result") or {}).get("session_id")
    verify(isinstance(first_session,str) and len(first_session)>3,
           "DURABLE_PROCESS_SESSION_NOT_RECORDED")
    duplicate=rpc(port,secret,"durable_call",durable,"ci-durable-repeated")
    verify(duplicate.get("ok") is True,"DURABLE_REPEAT_CALL_FAILED")
    repeated=duplicate.get("result") or {}
    verify(repeated.get("state")=="completed" and repeated.get("cached") is True,
           "DURABLE_REPLAY_NOT_DEDUPLICATED")
    second_session=((repeated.get("response") or {}).get("result") or {}).get("session_id")
    verify(second_session==first_session,"DURABLE_RETRY_STARTED_ANOTHER_SESSION")
    status=rpc(port,secret,"request_status",{
        "request_key":durable["request_key"],
        "agent_id":"ci-readonly-agent","task_id":"ci-durable-git",
    },"ci-durable-status")
    verify(status.get("ok") is True and
           (status.get("result") or {}).get("state")=="completed",
           "DURABLE_PERSISTENT_STATUS_NOT_FOUND")
    recovery=rpc(port,secret,"task_recovery_plan",{
        "request_key":durable["request_key"],
    },"ci-read-only-recovery")
    verify(recovery.get("ok") is True,"RECOVERY_RPC_MISSING")
    advice=recovery.get("result") or {}
    verify(advice.get("schema")=="ff-task-recovery-decision-v1",
           "RECOVERY_CONTRACT_SCHEMA")
    verify(advice.get("journal_state")=="completed" and
           advice.get("automatic_retry_allowed") is False,
           "RECOVERY_REPLAY_MISCLASSIFIED")
    verify(advice.get("previous_effect_independently_verified") is False,
           "RECOVERY_FALSE_POSTCONDITION_PROOF")
    verify(advice.get("response_contents_returned") is False and
           "session_id" not in json.dumps(advice),
           "RECOVERY_RETURNED_RECORDED_PRIVATE_CONTENT")
    checks.append("trusted_journal_recovery_plan_no_replay_no_response_leak")
    modified={
        **durable,
        "args":{**durable["args"],"command":"git rev-parse HEAD"},
    }
    conflict=rpc(port,secret,"durable_call",modified,"ci-durable-conflict")
    verify(conflict.get("ok") is False and
           conflict.get("error_code")=="REQUEST_KEY_CONFLICT",
           "DURABLE_CONFLICT_DID_NOT_FAIL_CLOSED")
    checks.append("durable_duplicate_dedupes_process_and_conflicting_key_fails_closed")
    return checks


def main() -> int:
    if os.name!="nt":
        print("Requires a Windows runner",file=sys.stderr)
        return 2
    verify(SERVER.is_file(),"SOURCE_SERVER_MISSING")
    with TemporaryDirectory(prefix="ff-p0-isolated-rpc-") as td:
        root=Path(td)/"agent"
        root.mkdir(parents=True)
        port=free_port()
        env={**os.environ,"FF_BRIDGE_ROOT":str(root)}
        process=subprocess.Popen(
            [sys.executable,str(SERVER),"serve","--host","127.0.0.1","--port",str(port)],
            cwd=str(REPO),env=env,
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0),
        )
        try:
            secret_file=root/"bridge-v3/secret"
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                verify(process.poll() is None,"ISOLATED_AGENT_EXITED")
                if secret_file.is_file():
                    try:
                        with socket.create_connection(("127.0.0.1",port),timeout=.2):
                            break
                    except OSError:
                        pass
                time.sleep(.1)
            else:
                raise RuntimeError("ISOLATED_AGENT_NOT_READY")
            secret=secret_file.read_text(encoding="ascii").strip()
            checks=verify_rpc(port,secret)
            print(json.dumps({
                "isolated_agent":True,"all_passed":True,
                "checks":checks,"no_user_desktop":True,
                "no_paid_model_calls":True,
            },sort_keys=True))
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=6)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=6)
    return 0


if __name__=="__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # No host paths or secrets printed by the failure reporter.
        print("ISOLATED_RPC_SMOKE_FAILED:",str(exc).split(":")[0][:150],file=sys.stderr)
        raise SystemExit(1)
