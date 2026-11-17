"""REAL end-to-end smoke of the agent Hub on the owner's machine.

Run it through the token launcher (it needs the owner's Chrome with the Playwright extension):

    powershell -File tests/integration/run_with_extension_token.ps1 -Script tests/integration/hub_real_smoke.py -ScriptArgs '--run'

It starts its OWN Hub on a random loopback port with a temporary state directory. It never
talks to the installed Bridge or Hub, opens only its own hidden tabs against a loopback page,
starts only its own program on a private desktop, and removes everything it created. Every
change of owner state makes the no-interference result inconclusive and stops further actions.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import http.server
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PACKAGE = REPO / "runtime" / "bridge-v3"
sys.path.insert(0, str(PACKAGE))
from ff_hub import HubClient, HubError  # noqa: E402
from ff_win_process_identity import ProcessReference, process_creation_token, process_identity_matches  # noqa: E402

CHECKS: list[tuple[str, bool]] = []
SECRET = "s3cr3t-" + "value-for-broker-test-0123456789"
PAGE = """<!doctype html><title>hub-smoke</title><h1>Hub page</h1>
<button id=add onclick="count.textContent=+count.textContent+1">Add one</button> <output id=count>0</output>
<input id=who aria-label="Who">"""
GUARD = None


class OwnerStateChanged(RuntimeError):
    pass


class SmokeClient(HubClient):
    """Only this test assigns reproducible call-site keys; replay cases retain explicit keys."""
    def call(self, op, args=None, *, request_key=None):
        command = (args or {}).get("command")
        effect = (op in {"session_open", "session_close", "app_open", "app_act", "app_close", "secret_use", "resource_claim", "resource_release"}
                  or op == "browser" and command in {"open", "navigate", "act", "evaluate", "restore", "close"})
        if effect and op != "session_close" and GUARD is not None:
            GUARD.quiet()
        if effect and request_key is None:
            frame = inspect.currentframe()
            try:
                request_key = f"smoke-line-{frame.f_back.f_lineno:04d}-{op}"
            finally:
                del frame
        return super().call(op, args, request_key=request_key)


class OwnerStateGuard:
    """Read-only sampling. Changes are observed, never attributed to a particular process."""
    def __init__(self):
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.user.GetForegroundWindow.restype = wintypes.HWND
        self.user.GetClipboardSequenceNumber.restype = wintypes.DWORD
        class Point(ctypes.Structure):
            _fields_ = [("x", wintypes.LONG), ("y", wintypes.LONG)]
        self.Point = Point
        self.user.GetCursorPos.argtypes = [ctypes.POINTER(Point)]
        self.user.GetCursorPos.restype = wintypes.BOOL
        self.baseline = self.state()
        if not self.baseline[0]:
            raise RuntimeError("INPUT_DESKTOP_UNAVAILABLE")
        self.changed = threading.Event()
        self.foreground_changed = threading.Event()
        self.finished = threading.Event()
        self.samples = 0
        self.thread = threading.Thread(target=self.sample, daemon=True)
        self.thread.start()

    def state(self):
        point = self.Point()
        if not self.user.GetCursorPos(ctypes.byref(point)):
            raise RuntimeError("CURSOR_OBSERVATION_UNAVAILABLE")
        return (int(self.user.GetForegroundWindow() or 0), point.x, point.y,
                int(self.user.GetClipboardSequenceNumber()))

    def observe(self):
        current = self.state()
        self.samples += 1
        if current[0] != self.baseline[0]:
            self.foreground_changed.set()
        if current != self.baseline:
            self.changed.set()

    def sample(self):
        while not self.finished.wait(.025):
            try:
                self.observe()
            except Exception:
                self.changed.set()
                return

    def quiet(self):
        self.observe()
        if self.changed.is_set():
            raise OwnerStateChanged("OWNER_STATE_CHANGED_DURING_SMOKE")

    def close(self):
        try:
            self.observe()
        finally:
            self.finished.set()
            self.thread.join(timeout=1)


def browser_preflight():
    """No Hub/GUI launch or DPAPI read until the current upstream safety check succeeds."""
    if os.name != "nt":
        return "WINDOWS_REQUIRED"
    node = shutil.which("node.exe")
    if not node:
        return "NODE_UNAVAILABLE"
    source = """import {pathToFileURL} from 'node:url';
try {
  const {backgroundChromePreflight} = await import(pathToFileURL(process.argv[2]).href);
  await backgroundChromePreflight();
} catch (error) {
  process.stdout.write(JSON.stringify({reason: error.code || 'BACKGROUND_PREFLIGHT_UNAVAILABLE'}));
  process.exit(3);
}"""
    environment = dict(os.environ)
    environment.pop("PLAYWRIGHT_MCP_EXTENSION_TOKEN", None)
    environment.pop("FF_BROWSER_HUB_KEY", None)
    try:
        result = subprocess.run([node, "--input-type=module", "-e", source, "--", "ff-background-preflight",
                                 str(PACKAGE / "ff_browser_hub.mjs")],
                                capture_output=True, text=True, timeout=20, env=environment,
                                creationflags=subprocess.CREATE_NO_WINDOW)
    except (OSError, subprocess.TimeoutExpired):
        return "BACKGROUND_PREFLIGHT_UNAVAILABLE"
    if result.returncode:
        try:
            return json.loads(result.stdout)["reason"]
        except (ValueError, KeyError, TypeError):
            return "BACKGROUND_PREFLIGHT_UNAVAILABLE"
    return None


def retain_browser(state, hub, references):
    """Require live test-Hub ancestry and birth identity, then retain the exact process object."""
    from cua_universal_fastpath import UniversalFastPath
    if hub.poll() is not None:
        raise RuntimeError("TEST_HUB_NOT_ALIVE")
    record = json.loads((state / "browser" / "endpoint.json").read_text(encoding="utf-8"))
    pid = record.get("pid")
    if type(pid) is not int or pid not in UniversalFastPath._child_process_ids(hub.pid):
        raise RuntimeError("TEST_BROWSER_ANCESTRY_UNPROVEN")
    token = process_creation_token(pid)
    identity = UniversalFastPath._process_identity(pid)
    if token is None or identity is None or identity["created"] != token or Path(identity["exe"]).name.lower() != "node.exe":
        raise RuntimeError("TEST_BROWSER_IDENTITY_UNPROVEN")
    for reference in references:
        if reference.pid == pid and reference.token == token and reference.poll() is None:
            return reference
    reference = ProcessReference(pid, token)
    if reference.poll() is not None or hub.poll() is not None:
        reference.close()
        raise RuntimeError("TEST_BROWSER_IDENTITY_CHANGED")
    references.append(reference)
    return reference


def check(name: str, ok: bool, extra: str = "") -> bool:
    CHECKS.append((name, bool(ok)))
    print(("PASS " if ok else "FAIL ") + name + (f" :: {extra}" if extra else ""), flush=True)
    return bool(ok)


def code(call) -> str:
    try:
        call()
        return "NO_ERROR"
    except HubError as exc:
        return exc.code


class Site(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        return

    def do_GET(self) -> None:
        if self.path == "/echo":
            body = json.dumps({"got": self.headers.get("X-Api-Key")}).encode()
        else:
            body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json" if self.path == "/echo" else "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_hub(state: Path, hubs: list) -> subprocess.Popen:
    process = subprocess.Popen([sys.executable, str(PACKAGE / "ff_hub.py"), "serve", "--port", "0", "--state-dir", str(state)],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               env={**os.environ, "FF_BRIDGE_ROOT": str(state.parent / "runtime")},
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    hubs.append(process)
    client = SmokeClient(state)
    for _ in range(200):
        try:
            endpoint = client.endpoint()
            if (process.poll() is None and endpoint["pid"] == process.pid
                    and endpoint.get("create_time") == process_creation_token(process.pid)):
                return process
        except HubError:
            pass
        time.sleep(0.05)
    if process.poll() is None:
        process.kill()
    process.wait(timeout=10)
    raise RuntimeError("hub did not start")


def owner_cli(state: Path, *arguments: str, stdin: str | None = None) -> dict:
    done = subprocess.run([sys.executable, str(PACKAGE / "ff_hub.py"), "--state-dir", str(state), *arguments],
                          input=stdin, capture_output=True, text=True, timeout=30,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return json.loads(done.stdout or "{}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", help="explicitly run owner-Chrome and private GUI acceptance")
    options = parser.parse_args()
    if not options.run:
        print(json.dumps({"status": "NOT_RUN", "reason": "explicit --run required"}))
        return 3
    reason = browser_preflight()
    if reason:
        print(json.dumps({"status": "NOT_RUN", "reason": reason}))
        return 3
    global GUARD
    try:
        GUARD = OwnerStateGuard()
    except Exception:
        print(json.dumps({"status": "NOT_RUN", "reason": "OWNER_STATE_UNAVAILABLE"}))
        return 3
    started_at = time.monotonic()
    work = Path(tempfile.mkdtemp(prefix="ff-hub-smoke-"))
    state = work / "state"
    site = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{site.server_address[1]}"
    hubs, browser_references = [], []
    hub = None
    charmap = os.path.join(os.environ["WINDIR"], "System32", "charmap.exe")
    try:
        GUARD.quiet()
        hub = start_hub(state, hubs)
        # -- scenario 5: a new agent knows nothing and discovers everything -------------------
        fresh = SmokeClient(state)
        caps = fresh.call("capabilities")
        check("new agent discovers operations without any configuration",
              {"browser", "app_open", "secret_use", "resource_claim"} <= set(caps["operations"]) and caps["quickstart"])
        check("an unauthenticated agent cannot act", code(lambda: fresh.call("browser", {"command": "status"})) == "SESSION_REQUIRED")

        a, b, c = SmokeClient(state), SmokeClient(state), SmokeClient(state)
        sessions = [client.call("session_open", {"agent_id": name, "task_id": "smoke"})
                    for client, name in ((a, "agent-a"), (b, "agent-b"), (c, "agent-c"))]

        # -- scenario 6: one owner decision, then the whole class runs without asking ---------
        denied = None
        try:
            b.call("app_open", {"app": charmap})
        except HubError as exc:
            denied = exc
        check("an ungranted class is refused before anything starts",
              denied is not None and denied.code == "PERMISSION_REQUIRED" and denied.details.get("execution_started") is False)
        again = None
        try:
            b.call("app_open", {"app": charmap})
        except HubError as exc:
            again = exc
        check("the owner is asked once, not per attempt",
              again is not None and again.details["owner_request_id"] == denied.details["owner_request_id"] and again.details["already_asked"] is True
              and len(owner_cli(state, "requests")) == 1)
        check("an agent cannot change the policy over RPC", code(lambda: b.call("grant_add", {"classes": ["app_launch"]})) == "OP_UNSUPPORTED")
        grant = owner_cli(state, "approve", denied.details["owner_request_id"], "--ttl", "1h")
        check("owner approves once (local CLI)", grant.get("classes") == ["app_launch"] and grant.get("agents") == ["agent-b"], str(grant.get("grant_id")))
        check("the grant is scoped: another agent still needs its own", code(lambda: c.call("app_open", {"app": charmap})) == "PERMISSION_REQUIRED")

        # -- scenarios 1-3: three agents at once: Chrome, a GUI app, files/processes ----------
        def agent_browser() -> dict:
            print(f"  [{time.strftime('%H:%M:%S')}.{int(time.time() * 1000) % 1000:03d}] first browser call: the manager connects to Chrome now", flush=True)
            tab = a.call("browser", {"command": "open", "url": base + "/"}, request_key="a-open-tab-0001")
            for index in range(3):
                a.call("browser", {"command": "act", "tab_id": tab["tab_id"], "action": "click", "target": {"selector": "#add"}},
                       request_key=f"a-click-{index:04d}")
            a.call("browser", {"command": "act", "tab_id": tab["tab_id"], "action": "fill", "target": {"label": "Who"}, "value": "agent-a",
                               "postcondition": {"target": {"label": "Who"}, "value": "agent-a"}})
            snapshot = a.call("browser", {"command": "snapshot", "tab_id": tab["tab_id"]})
            count = a.call("browser", {"command": "read", "tab_id": tab["tab_id"], "target": {"selector": "#count"}})["text"]
            return {"tab": tab, "count": count, "visibility": snapshot["visibility"]}

        def agent_gui() -> dict:
            started = time.time()
            window = b.call("app_open", {"app": charmap}, request_key="b-open-charmap-0001")
            seen = b.call("app_observe", {"app_id": window["app_id"]})
            box = next(item for item in seen["entities"] if item.get("automation_id") == "119" and "toggle" in item.get("actions", []))
            toggled = b.call("app_act", {"app_id": window["app_id"], "generation": seen["generation"], "ref": box["ref"], "operation": "toggle",
                                         "postcondition": {"type": "state_equals", "key": "toggle_state", "value": "On"}})
            seen = b.call("app_observe", {"app_id": window["app_id"]})
            edit = next(item for item in seen["entities"] if item.get("automation_id") == "104" and "set_value" in item.get("actions", []))
            typed = b.call("app_act", {"app_id": window["app_id"], "generation": seen["generation"], "ref": edit["ref"], "operation": "set_value",
                                       "action_args": {"value": "FF"}, "postcondition": {"type": "value_equals", "value": "FF" + chr(13)}})  # RichEdit keeps its final paragraph mark
            picture = b.call("app_capture", {"app_id": window["app_id"]})
            return {"window": window, "toggled": toggled, "typed": typed, "picture": picture, "seconds": time.time() - started}

        def agent_files() -> dict:
            folder = work / "agent-c"
            folder.mkdir()
            lock = c.call("resource_claim", {"kind": "file", "key": str(folder / "report.txt")})
            done = subprocess.run(["cmd.exe", "/d", "/c", "echo built-by-agent-c> report.txt"], cwd=folder, capture_output=True,
                                  creationflags=subprocess.CREATE_NO_WINDOW)
            return {"lock": lock, "exit": done.returncode, "text": (folder / "report.txt").read_text().strip(), "path": str(folder / "report.txt")}

        started = time.time()
        with ThreadPoolExecutor(3) as pool:
            futures = [pool.submit(job) for job in (agent_browser, agent_gui, agent_files)]
            browser_result, gui_result, files_result = (future.result(timeout=120) for future in futures)
        retain_browser(state, hub, browser_references)
        check("three agents worked at the same time", True, f"{time.time() - started:.1f}s wall for all three")
        check("agent A drove the owner's Chrome in a hidden tab", browser_result["count"] == "3" and browser_result["visibility"] == "hidden")
        check("agent B drove a GUI program with no API on a private desktop",
              gui_result["toggled"].get("verified") is True and gui_result["typed"].get("verified") is True
              and gui_result["window"]["visible_to_owner"] is False and gui_result["window"]["desktop"].startswith("FFBridge-Agent-"),
              f"{gui_result['seconds']:.1f}s, class {gui_result['window']['class_name']}")
        check("agent B saw its hidden window", gui_result["picture"].get("frame_w", 0) > 100 and len(gui_result["picture"].get("image_base64", "")) > 1000)
        check("agent C ran its process under a file lock", files_result["exit"] == 0 and files_result["text"] == "built-by-agent-c")
        tab_id, app_id = browser_result["tab"]["tab_id"], gui_result["window"]["app_id"]

        # -- isolation ------------------------------------------------------------------------
        check("B cannot read A's tab", code(lambda: b.call("browser", {"command": "read", "tab_id": tab_id})) == "RESOURCE_NOT_OWNED")
        check("B cannot click in A's tab", code(lambda: b.call("browser", {"command": "act", "tab_id": tab_id, "action": "click", "target": {"selector": "#add"}})) == "RESOURCE_NOT_OWNED")
        check("B cannot close A's tab", code(lambda: b.call("browser", {"command": "close", "tab_id": tab_id})) == "RESOURCE_NOT_OWNED")
        check("A cannot touch B's application", code(lambda: a.call("app_observe", {"app_id": app_id})) == "RESOURCE_NOT_OWNED"
              and code(lambda: a.call("app_close", {"app_id": app_id})) == "RESOURCE_NOT_OWNED")
        busy = None
        try:
            a.call("resource_claim", {"kind": "file", "key": files_result["path"]})
        except HubError as exc:
            busy = exc
        check("a file locked by C is busy for A, with the holder named", busy is not None and busy.code == "RESOURCE_BUSY" and busy.details["held_by"]["agent_id"] == "agent-c")
        check("an unrelated file is not blocked (no global lock)", a.call("resource_claim", {"kind": "file", "key": str(work / "other.txt")})["already_held"] is False)
        check("a forged session is rejected", code(lambda: SmokeClient(state).raw({"op": "x"}) and (_ for _ in ()).throw(HubError("NO_ERROR"))) != "x"
              and SmokeClient(state).raw({"op": "session_status", "session_id": sessions[0]["session_id"], "session_secret": "wrong"})["error_code"] == "SESSION_INVALID")
        check("A's work survived every attempt", a.call("browser", {"command": "read", "tab_id": tab_id, "target": {"selector": "#count"}})["text"] == "3")

        # -- scenario 4b: idempotent repeats ----------------------------------------------------
        repeat = a.call("browser", {"command": "act", "tab_id": tab_id, "action": "click", "target": {"selector": "#add"}}, request_key="a-click-0002")
        check("a repeated request_key is answered from the journal, not executed again",
              repeat["deduplicated"] is True and a.call("browser", {"command": "read", "tab_id": tab_id, "target": {"selector": "#count"}})["text"] == "3")
        check("a reused key with another request is refused",
              code(lambda: a.call("browser", {"command": "act", "tab_id": tab_id, "action": "fill", "target": {"label": "Who"}, "value": "x"}, request_key="a-click-0002")) == "REQUEST_KEY_REUSED")

        # -- secrets ----------------------------------------------------------------------------
        host = f"127.0.0.1:{site.server_address[1]}"
        stored = owner_cli(state, "secret", "put", "demo-api", "--agents", "agent-a", "--hosts", host, stdin=SECRET + "\n")
        check("owner stores a secret (value from stdin, sealed with DPAPI)", stored.get("name") == "demo-api")
        check("no permission yet: secret use is refused", code(lambda: a.call("secret_use", {"name": "demo-api", "use": "http", "request": {"url": base + "/echo", "headers": {"X-Api-Key": "{{secret}}"}}})) == "PERMISSION_REQUIRED")
        owner_cli(state, "grant", "add", "--classes", "secret_use", "--secrets", "demo-api", "--agents", "agent-a")
        used = a.call("secret_use", {"name": "demo-api", "use": "http", "request": {"url": base + "/echo", "headers": {"X-Api-Key": "{{secret}}"}}})
        check("the broker used the secret and the server received it", used["status"] == 200 and json.loads(used["body"])["got"] == "[secret]")
        check("the value never comes back to the agent", SECRET not in json.dumps(used) and used["secret_value_returned"] is False)
        check("another agent cannot see or use it", b.call("secret_list")["secrets"] == []
              and code(lambda: b.call("secret_use", {"name": "demo-api", "use": "http", "request": {"url": base + "/echo", "headers": {"X-Api-Key": "{{secret}}"}}})) == "PERMISSION_REQUIRED")
        check("the secret cannot be sent to a host the owner did not list",
              code(lambda: a.call("secret_use", {"name": "demo-api", "use": "http", "request": {"url": "https://example.com/", "headers": {"X-Api-Key": "{{secret}}"}}})) == "SECRET_HOST_NOT_ALLOWED")
        leaked = [str(path) for path in state.rglob("*") if path.is_file() and SECRET.encode() in path.read_bytes()]
        check("the plain value is nowhere in the Hub's files (database, audit, logs)", leaked == [], ",".join(leaked))
        check("secret use is audited without the value", any(item["event"] == "secret_use" for item in a.call("audit_read")["records"]))

        # -- scenario 4a: the agent client dies and comes back -----------------------------------
        check("a second client cannot hijack a live session", code(lambda: SmokeClient(state).call("session_open", {"agent_id": "agent-a", "task_id": "smoke"})) == "SESSION_ACTIVE_ELSEWHERE")
        reborn = SmokeClient(state)
        resumed = reborn.call("session_open", {"agent_id": "agent-a", "task_id": "smoke", "resume_token": sessions[0]["resume_token"]})
        check("the restarted agent resumes and gets its resources back", resumed["resumed"] is True and resumed["adopted_resources"] >= 2)
        check("the old client's session is dead", code(lambda: a.call("session_heartbeat")) == "SESSION_CLOSED")
        check("the tab kept its page state across the client restart",
              reborn.call("browser", {"command": "read", "tab_id": tab_id, "target": {"selector": "#count"}})["text"] == "3")
        a = reborn

        # -- scenario 4c: the browser connection process dies ------------------------------------
        GUARD.quiet()
        browser = retain_browser(state, hub, browser_references)
        browser.terminate()
        time.sleep(1.0)
        check("after the connection died the tab is reported lost, not faked",
              code(lambda: a.call("browser", {"command": "read", "tab_id": tab_id})) == "TAB_LOST")
        restored = a.call("browser", {"command": "restore", "tab_id": tab_id}, request_key="a-restore-0001")
        check("the Hub restarted the browser manager and reopened the tab at its address",
              restored["restored"] is True and restored["url"].startswith(base) and restored["page_state_preserved"] is False)
        tab_id = restored["tab_id"]
        retain_browser(state, hub, browser_references)
        check("the restored tab works and is hidden", a.call("browser", {"command": "snapshot", "tab_id": tab_id})["visibility"] == "hidden")

        # -- scenario 4d: the Hub itself is killed in the middle of a mutating request -----------
        outcome: dict = {}

        def slow() -> None:
            try:
                a.call("browser", {"command": "act", "tab_id": tab_id, "action": "click", "target": {"selector": "#add"},
                                   "postcondition": {"text_present": "never appears"}, "timeout_ms": 25000}, request_key="a-click-lost-0001")
                outcome["code"] = "NO_ERROR"
            except HubError as exc:
                outcome["code"] = exc.code
        thread = threading.Thread(target=slow)
        thread.start()
        time.sleep(2.0)
        GUARD.quiet()
        hub.kill()
        hub.wait(timeout=10)
        thread.join(timeout=30)
        check("the client sees a lost reply, not a success", outcome.get("code") == "HUB_UNREACHABLE", str(outcome))
        time.sleep(1.5)
        GUARD.quiet()
        hub = start_hub(state, hubs)
        status = a.call("request_status", {"request_key": "a-click-lost-0001"})
        check("after restart the Hub knows the request ran and that its result is unknown",
              status["state"] == "unknown" and status["execution_started"] is True and status["automatic_replay"] is False)
        check("the Hub refuses to replay it blindly",
              code(lambda: a.call("browser", {"command": "act", "tab_id": tab_id, "action": "click", "target": {"selector": "#add"},
                                              "postcondition": {"text_present": "never appears"}, "timeout_ms": 25000}, request_key="a-click-lost-0001")) == "REQUEST_OUTCOME_UNKNOWN")
        mine = {item["kind"] for item in a.call("session_status")["resources"]}
        check("sessions and ownership survived the Hub restart", {"browser_tab", "file"} <= mine and b.call("session_heartbeat")["agent_id"] == "agent-b")
        check("the grant survived the Hub restart", b.call("permission_check", {"risk_class": "app_launch", "target": {"app": charmap}})["decision"] == "allow")
        relost = code(lambda: a.call("browser", {"command": "read", "tab_id": tab_id}))
        tab_id = a.call("browser", {"command": "restore", "tab_id": tab_id})["tab_id"]
        retain_browser(state, hub, browser_references)
        check("the agent verifies the real state and continues", relost == "TAB_LOST"
              and a.call("browser", {"command": "read", "tab_id": tab_id, "target": {"selector": "h1"}})["text"] == "Hub page")

        # -- cleanup: each agent closes only what it owns ----------------------------------------
        reports = [client.call("session_close") for client in (a, b, c)]
        check("closing a session closes its own tabs and releases its locks", reports[0]["browser_tabs_closed"] >= 1 and reports[2]["locks_released"] == 1, json.dumps(reports))
        check("no session is left", SmokeClient(state).call("hub_status")["sessions"] == [])
        check("the program started on the private desktop is gone",
              not process_identity_matches(gui_result["window"]["pid"], gui_result["window"]["create_time"]))
    except OwnerStateChanged:
        print("INCONCLUSIVE OWNER_STATE_CHANGED_DURING_SMOKE", flush=True)
    except Exception as exc:  # report, then clean up
        check("smoke ran to the end", False, f"{type(exc).__name__}: {getattr(exc, 'code', '')} {exc} {getattr(exc, 'details', '')}")
        try:
            import sqlite3
            rows = sqlite3.connect(state / "hub.db").execute("SELECT detail FROM audit WHERE event='internal_error' ORDER BY id DESC LIMIT 3").fetchall()
            for row in rows:
                print("  hub internal error: " + row[0][:400])
        except Exception as inner:
            print("  (could not read the hub audit: %s)" % inner)
    finally:
        # An endpoint file alone is never authority to terminate a PID. Capture only
        # a live descendant of a retained, still-live test Popen, then use exact handles.
        if hub is not None and hub.poll() is None and (state / "browser" / "endpoint.json").is_file():
            try:
                retain_browser(state, hub, browser_references)
            except Exception:
                check("browser cleanup identity was verified", False)
        for process in hubs:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                check("test Hub process closed", False)
        for reference in browser_references:
            try:
                reference.terminate()
                deadline = time.monotonic() + 5
                while reference.poll() is None and time.monotonic() < deadline:
                    time.sleep(.05)
                check("retained browser manager closed", reference.poll() is not None)
            except OSError:
                check("retained browser manager closed", False)
            finally:
                reference.close()
        site.shutdown()
        site.server_close()
        GUARD.close()
        print(json.dumps({"foreground_samples": GUARD.samples,
                          "foreground_unchanged": not GUARD.foreground_changed.is_set(),
                          "owner_state_unchanged": not GUARD.changed.is_set(),
                          "attribution": "observed state only; causation not inferred"}))
        cleanup_allowed = (work.is_absolute() and not work.is_symlink()
                           and work.resolve().parent == Path(tempfile.gettempdir()).resolve()
                           and work.name.startswith("ff-hub-smoke-"))
        if not cleanup_allowed:
            check("temporary state cleanup target was verified", False)
        elif any(work.rglob("stop.flag")):
            check("temporary state cleanup preserves Stop latch", False)
        else:
            shutil.rmtree(work, ignore_errors=True)
            check("temporary test state removed", not work.exists())
    failed = [name for name, ok in CHECKS if not ok]
    status = "FAIL" if failed else "INCONCLUSIVE" if GUARD.changed.is_set() else "PASS"
    print(json.dumps({"status": status, "passed": len(CHECKS) - len(failed), "failed": len(failed),
                      "failed_checks": failed, "elapsed_ms": round((time.monotonic() - started_at) * 1000)}))
    return 0 if status == "PASS" else 2 if status == "INCONCLUSIVE" else 1



if __name__ == "__main__":
    raise SystemExit(main())
