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
    checks.append("read_only_task_preflight")

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
