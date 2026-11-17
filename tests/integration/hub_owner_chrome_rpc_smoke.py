"""Disposable full-chain Bridge RPC -> Hub -> live Chrome extension acceptance.

Uses a temporary Bridge/Hub root, random loopback port, 3 independently owned
tabs on a temporary 127.0.0.1 server. Does not restart installed production
Bridge or Chrome. Run only with --run and FF_PLAYWRIGHT_ROOT set to the pinned
Playwright runtime. Browser extension token stays DPAPI-protected until the
owned Hub browser manager unseals it.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hub_bridge_rpc_smoke import start, start_hub, stop, verify
from isolated_rpc_smoke import rpc

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "runtime/bridge-v3"))
from ff_hub_permissions import Policy, PermissionError_

REPO = Path(__file__).resolve().parents[2]
PAGE = ("""<!doctype html><title>FF Hub full-chain proof</title>
<h1 id=owner>FF Hub test</h1><button id=add onclick="count.textContent=+count.textContent+1">Increment</button>
<output id=count>0</output>""")
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body=PAGE.encode("utf-8")
        self.send_response(200);self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*args):pass

def main():
    if "--run" not in sys.argv:
        print("NOT_RUN: require --run")
        return 0
    if os.name!="nt" or not os.environ.get("FF_PLAYWRIGHT_ROOT"):
        print("NOT_RUN: Windows and pinned FF_PLAYWRIGHT_ROOT required")
        return 2
    root=Path(tempfile.mkdtemp(prefix="ff-hub-real-chrome-rpc-"))
    state=root/"state"
    state.mkdir(parents=True)
    (state/"universal-agent-runtime.json").write_text('{"version":1,"enabled":true}',encoding="utf-8")
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    base=f"http://127.0.0.1:{server.server_port}/"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
    bridge=hub=None
    sessions=[]
    browser_pid=None
    clean=False
    try:
        bridge=start("ff_win_v3_main.py",["serve","--host","127.0.0.1","--port",str(port)],root)
        deadline=time.monotonic()+25
        secret=None
        while time.monotonic()<deadline:
            verify(bridge.poll() is None,"BRIDGE_DIED")
            p=root/"bridge-v3/secret"
            if p.is_file():
                secret=p.read_text(encoding="ascii").strip()
                if rpc(port,secret,"ping",{},"real-hub-ping").get("ok"):break
            time.sleep(.12)
        else:raise RuntimeError("TEST_BRIDGE_NOT_READY")
        hub=start_hub(root)
        def call(op,args=None,session=None,key=None,expect=None):
            request={"op":op,"args":args or {}}
            if session:
                request.update(session_id=session["session_id"],session_secret=session["session_secret"])
            if key:request["request_key"]=key
            result=rpc(port,secret,"hub",request,"hub-real-chrome-rpc")
            if expect:
                verify(result.get("error_code")==expect,
                       "EXPECTED_"+expect+"_GOT_"+str(result.get("error_code")))
                return result
            verify(result.get("ok") is True,"HUB_"+op+"_"+str(result.get("error_code")))
            return result["result"]
        caps=call("capabilities")
        verify("browser" in caps["quickstart"][1] or "Chrome" in caps["purpose"],"BROWSER_NOT_ADVERTISED")
        sessions=[call("session_open",{"agent_id":f"ff-e2e-agent-{i}","task_id":"live-owner-chrome"}) for i in range(3)]
        def open_one(k):
            tab=call("browser",{"command":"open","url":base+str(k)},sessions[k],f"hub-open-agent-{k}")
            verify(tab["durable_identity"] is True,"NO_DURABLE_CHROME_ID")
            return tab
        with ThreadPoolExecutor(max_workers=3) as pool:
            tabs=list(pool.map(open_one,range(3)))
        verify(len({tab["tab_id"] for tab in tabs})==3,"NON_UNIQUE_TAB_IDS")
        status=call("browser",{"command":"status"},sessions[0])
        browser_pid=status.get("pid")
        verify(status.get("connected") is True and status.get("tabs",{}).get("live")==3,"BROWSER_MANAGER_NOT_SHARED")
        print(json.dumps({"step":"THREE_AGENTS","distinct_tabs":3,"owner_profile_used":True}),flush=True)
        for i,session in enumerate(sessions):
            listing=call("browser",{"command":"list"},session)
            verify(len(listing["tabs"])==1 and listing["tabs"][0]["tab_id"]==tabs[i]["tab_id"],"OWNER_ISOLATION_FAIL")
        call("browser",{"command":"read","tab_id":tabs[0]["tab_id"],"target":{"selector":"#count"}},
             sessions[1],expect="RESOURCE_NOT_OWNED")
        own=call("browser",{"command":"act","tab_id":tabs[0]["tab_id"],
                          "action":"click","target":{"selector":"#add"}},sessions[0],"click-agent-0")
        value=call("browser",{"command":"read","tab_id":tabs[0]["tab_id"],"target":{"selector":"#count"}},sessions[0])
        verify(value.get("text")=="1","LIVE_CLICK_NOT_CONFIRMED")
        print(json.dumps({"step":"OWNERSHIP_AND_ACTIONS","foreign_denied":True,"own_click_verified":True}),flush=True)

        # Exercise policy transitions via the REAL local RPC and browser manager.
        # Only this disposable test root has its policy changed. Production grants
        # and Chrome settings are never touched.
        policy=Policy(root/"state/hub/policy.json")
        script={"command":"evaluate","tab_id":tabs[0]["tab_id"],
                "expression":"document.querySelector('#count').textContent"}
        denied=call("browser",script,sessions[0],"canary-script-grant-0",expect="PERMISSION_REQUIRED")
        verify(denied["details"].get("risk_class")=="browser_script","SCRIPT_DENIAL_NOT_SCOPED")
        grant=policy.add_grant(["browser_script"],agents=["ff-e2e-agent-0"],
                               hosts=["127.0.0.1"],ttl_seconds=180,
                               note="isolated Chrome RPC acceptance; no production policy")
        permitted=call("browser",script,sessions[0],"canary-script-grant-0")
        verify("1" in json.dumps(permitted),"GRANTED_SCRIPT_DID_NOT_RUN")
        call("browser",{"command":"evaluate","tab_id":tabs[1]["tab_id"],
                        "expression":"document.title"},sessions[1],
             "canary-script-other",expect="PERMISSION_REQUIRED")
        policy.revoke(grant["grant_id"])
        call("browser",script,sessions[0],"canary-script-revoked",
             expect="PERMISSION_REQUIRED")

        project=root/"project-owned"
        project.mkdir()
        project_grant=policy.add_grant(["project_write"],
            agents=["ff-e2e-agent-0"],paths=[str(project)],
            ttl_seconds=180,note="scoped owner-only canary project")
        app_grant=policy.add_grant(["app_launch"],
            agents=["ff-e2e-agent-0"],apps=["notepad.exe"],
            ttl_seconds=180,note="scoped owner-only canary app")
        verify(policy.decide("ff-e2e-agent-0","project_write",
                            {"path":str(project/"file.txt")})["decision"]=="allow",
               "PROJECT_SCOPED_GRANT_NOT_APPLIED")
        verify(policy.decide("ff-e2e-agent-0","project_write",
                            {"path":str(root/"outside.txt")})["decision"]!="allow",
               "PROJECT_GRANT_ESCAPED_PATH")
        verify(policy.decide("ff-e2e-agent-0","app_launch",
                            {"app":"notepad.exe"})["decision"]=="allow",
               "APP_SCOPED_GRANT_NOT_APPLIED")
        verify(policy.decide("ff-e2e-agent-0","app_launch",
                            {"app":"powershell.exe"})["decision"]!="allow",
               "APP_GRANT_ESCAPED_APP")
        for unsafe in ("financial","external_send","foreground_input"):
            try:
                policy.add_grant([unsafe],agents=["ff-e2e-agent-0"],ttl_seconds=180)
            except PermissionError_ as exc:
                verify(exc.code=="RISK_CLASS_NOT_GRANTABLE","UNSAFE_GRANT_ERROR_INCORRECT")
            else:
                raise RuntimeError("UNSAFE_CLASS_WAS_GRANTED_"+unsafe)
        policy.revoke(project_grant["grant_id"])
        policy.revoke(app_grant["grant_id"])
        print(json.dumps({"step":"STANDING_PERMISSION_PASS","live_grant":True,
                          "live_revocation":True,"agent_and_host_scoped":True,
                          "project_and_app_scope":True,"unsafe_classes_refused":True}),flush=True)
        for i,session in enumerate(sessions):
            result=call("browser",{"command":"close","tab_id":tabs[i]["tab_id"]},session,f"hub-close-agent-{i}")
            verify(result.get("page_closed_in_browser") is True,"UNCONFIRMED_TAB_CLOSE")
        for session in sessions:
            result=call("session_close",session=session)
            verify(result.get("cleanup_verified") is True,"SESSION_CLEANUP_UNCONFIRMED")
        ledger=root/"state/hub/browser/tab-ledger.json"
        if ledger.is_file():
            content=json.loads(ledger.read_text(encoding="utf-8"))
            verify(len(content.get("tabs",[]))==0,"BROWSER_LEDGER_NOT_EMPTY")
        clean=True
        print(json.dumps({"step":"FULL_RPC_PASS","browser_live":True,"sessions":3,
             "all_owned_tabs_physically_closed":True,"ledger_empty":True}),flush=True)
    finally:
        if not clean:
            # Best-effort compensation for a failed test. Never kill Chrome or
            # drop a test ledger whose physical tabs were not verified closed.
            verified=[]
            if "call" in locals():
                for session in sessions:
                    try:
                        outcome=call("session_close",session=session)
                        verified.append(outcome.get("cleanup_verified") is True)
                    except Exception:
                        verified.append(False)
            ledger=root/"state/hub/browser/tab-ledger.json"
            empty=(not ledger.exists()) or (len(json.loads(ledger.read_text(encoding="utf-8")).get("tabs",[]))==0)
            if all(verified) and empty:
                clean=True
                print(json.dumps({"step":"FAILED_TEST_COMPENSATION","owned_resources_cleanup_verified":True}),flush=True)
        # A test-owned Node manager may outlive a terminated Hub on Windows.
        # Kill ONLY the exact PID registered in this temporary test root, and
        # only once the three test tabs have been closed and the ledger cleared.
        if clean:
            endpoint=root/"state/hub/browser/endpoint.json"
            if endpoint.is_file():
                data=json.loads(endpoint.read_text(encoding="utf-8"))
                owned_pid=data.get("pid")
                if isinstance(owned_pid,int) and (browser_pid is None or browser_pid==owned_pid):
                    try:os.kill(owned_pid,signal.SIGTERM)
                    except OSError:pass
        stop(bridge);stop(hub)
        server.shutdown();server.server_close()
        if clean:shutil.rmtree(root,ignore_errors=True)
        else:print(json.dumps({"step":"UNCONFIRMED_TEST_CLEANUP","temporary_root":str(root)}),flush=True)
    return 0

if __name__=="__main__":
    try:raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"step":"FAILED","type":type(exc).__name__,"message":str(exc)[:250]}),flush=True)
        raise SystemExit(1)
