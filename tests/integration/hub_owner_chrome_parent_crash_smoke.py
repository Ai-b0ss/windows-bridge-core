"""Real Python Hub hard kill while its Chrome manager owns unfinished pages.

Only two owned localhost tabs, disposable Hub/state, random ports. Existing
Bridge/Chrome/keepers are not restarted. No browser token is read by this
harness: the existing DPAPI launcher supplies it inside the manager process.
"""
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from hub_bridge_rpc_smoke import PACKAGE, start_hub, stop, verify
sys.path.insert(0, str(PACKAGE))
from ff_hub import HubClient
from ff_hub_permissions import Policy
from ff_win_process_identity import process_creation_token


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<!doctype html><title>FF parent crash owned page</title><input id=held><output id=count>0</output>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    if "--run" not in sys.argv:
        print("NOT_RUN: --run required")
        return 0
    if os.name != "nt" or not os.environ.get("FF_PLAYWRIGHT_ROOT"):
        print("NOT_RUN: Windows and pinned FF_PLAYWRIGHT_ROOT required")
        return 2
    root = Path(tempfile.mkdtemp(prefix="ff-hub-parent-crash-"))
    state = root / "state/hub"
    state.mkdir(parents=True)
    (state / "config.json").write_text(json.dumps({"playwright_root": os.environ["FF_PLAYWRIGHT_ROOT"]}), encoding="utf-8")
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    clients, sessions, tabs, expressions = [], [], [], []
    hub, clean = None, False
    manager_pid = manager_token = None
    try:
        hub = start_hub(root)
        policy = Policy(state / "policy.json")
        policy.add_grant(["browser_script"], agents=["parent-a", "parent-b"], hosts=["127.0.0.1"])
        for index, agent in enumerate(("parent-a", "parent-b")):
            client = HubClient(state)
            session = client.call("session_open", {"agent_id": agent, "task_id": "unfinished-page"})
            clients.append(client)
            sessions.append(session)
            tab = client.call("browser", {"command": "open", "url": f"http://127.0.0.1:{server.server_port}/{index}"},
                              request_key="parent-tab-open-0001")
            tabs.append(tab)
            expression = ("globalThis.__ffEffects=(globalThis.__ffEffects||0)+1;"
                          f"document.querySelector('#held').value='unfinished-{index}';globalThis.__ffEffects")
            expressions.append(expression)
            client.call("browser", {"command": "evaluate", "tab_id": tab["tab_id"], "expression": expression},
                        request_key="parent-effect-0001")
        ledger = state / "browser/tab-ledger.json"
        before = json.loads(ledger.read_text(encoding="utf-8"))
        verify(len(before["tabs"]) == 2 and len({row["target_id"] for row in before["tabs"]}) == 2, "NO_EXACT_IDENTITIES")
        (root / "before-ledger.json").write_text(json.dumps(before), encoding="utf-8")
        endpoint = json.loads((state / "browser/endpoint.json").read_text(encoding="utf-8"))
        manager_pid, manager_token = endpoint["pid"], process_creation_token(endpoint["pid"])
        old_hub_pid = hub.pid
        hub.kill()
        hub.wait(timeout=10)
        # Restart immediately. BrowserManager itself coordinates retirement;
        # the test must not supply a manual grace period to make recovery work.
        hub = start_hub(root)
        verify(hub.pid != old_hub_pid, "HUB_NOT_REPLACED")
        for index, client in enumerate(clients):
            client.session = None
            client.call("session_open", {"agent_id": sessions[index]["agent_id"], "task_id": "unfinished-page",
                                          "resume_token": sessions[index]["resume_token"]})
            restored = client.call("browser", {"command": "restore", "tab_id": tabs[index]["tab_id"]},
                                   request_key="parent-tab-restore-0001")
            verify(restored.get("reattached") and restored.get("evidence") == "cdp_target_id", "EXACT_REATTACH_FAILED")
            proof = client.call("browser", {"command": "evaluate", "tab_id": tabs[index]["tab_id"],
                                "expression": "({effects:globalThis.__ffEffects,input:document.querySelector('#held').value})"},
                                request_key="parent-read-proof-0001")["value"]
            verify(proof == {"effects": 1, "input": f"unfinished-{index}"}, "FORM_OR_MEMORY_LOST")
            replay = client.call("browser", {"command": "evaluate", "tab_id": tabs[index]["tab_id"],
                                 "expression": expressions[index]}, request_key="parent-effect-0001")
            verify(replay.get("deduplicated") is True, "RECOVERY_REPEATED_PAGE_EFFECT")
        after = json.loads(ledger.read_text(encoding="utf-8"))
        verify(process_creation_token(manager_pid) != manager_token, "OLD_MANAGER_DID_NOT_RELEASE_PARENT_PIPE")
        verify({row["target_id"] for row in before["tabs"]} == {row["target_id"] for row in after["tabs"]}, "TARGET_IDENTITIES_CHANGED")
        foreign = clients[1].raw({"op": "browser", "args": {"command": "read", "tab_id": tabs[0]["tab_id"],
                                    "target": {"selector": "#held"}}, "session_id": clients[1].session["session_id"],
                                  "session_secret": clients[1].session["session_secret"]})
        verify(foreign.get("error_code") == "RESOURCE_NOT_OWNED", "FOREIGN_PAGE_ACCESS")
        for client, tab in zip(clients, tabs):
            closed = client.call("browser", {"command": "close", "tab_id": tab["tab_id"]}, request_key="parent-tab-close-0001")
            verify(closed.get("page_closed_in_browser") is True, "PHYSICAL_CLOSE_UNCONFIRMED")
            verify(client.call("session_close")["cleanup_verified"], "SESSION_CLEANUP_UNCONFIRMED")
        verify(not json.loads(ledger.read_text(encoding="utf-8"))["tabs"], "LEDGER_NOT_EMPTY")
        clean = True
        print(json.dumps({"all_passed": True, "python_hub_hard_killed": True, "actual_stdin_eof": True,
                          "same_physical_targets": 2, "forms_and_js_preserved": True,
                          "no_duplicate_effect": True, "foreign_denied": True, "physical_cleanup": True}))
    finally:
        if not clean:
            # Keep exact identity evidence if compensation cannot prove closure.
            for client, tab in zip(clients, tabs):
                try:
                    client.call("browser", {"command": "close", "tab_id": tab["tab_id"]}, request_key="parent-failure-cleanup-0001")
                    client.call("session_close")
                except Exception:
                    pass
        stop(hub)
        server.shutdown()
        if clean:
            endpoint = state / "browser/endpoint.json"
            deadline = time.monotonic() + 10
            while endpoint.exists() and time.monotonic() < deadline:
                time.sleep(.05)
            verify(root.resolve().parent == Path(tempfile.gettempdir()).resolve() and root.name.startswith("ff-hub-parent-crash-"),
                   "CLEANUP_ROOT_INVALID")
            shutil.rmtree(root)
        else:
            print(json.dumps({"recovery_evidence_retained": str(root), "cleanup_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
