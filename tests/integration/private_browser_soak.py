"""Run three independent Hub clients against real Chrome on private Windows desktops."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psutil

from private_product_acceptance import ProductGate, RUNTIME, check
from private_observer import Observer
from ff_hub import HubClient, HubError
from ff_win_process_identity import process_creation_token, process_identity_matches
from cua_hidden_chrome import chrome_path


CLIENTS = ("one", "two", "three")
FIXTURE = b"""<!doctype html><title>Soak fixture</title><main>Soak fixture
<button id="counter" onclick="document.querySelector('output').value=++window.count">Count</button>
<output>0</output><script>window.count=0</script></main>"""


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(FIXTURE)))
        self.end_headers()
        self.wfile.write(FIXTURE)


class FixtureServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        if not isinstance(sys.exception(), (ConnectionResetError, BrokenPipeError)):
            super().handle_error(request, client_address)


def write_json(path, data):
    staging = path.with_suffix(".tmp")
    staging.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    staging.replace(path)


def wait_for_file(path, timeout, process=None):
    deadline = time.monotonic() + timeout
    while not path.exists():
        check(process is None or process.poll() is None, "SOAK_CLIENT_EXITED_BEFORE_READY")
        check(time.monotonic() < deadline, "SYNC_TIMEOUT")
        time.sleep(0.1)
    return json.loads(path.read_text(encoding="utf-8"))


def worker(options):
    client = HubClient(options.output / "hub", timeout=70)
    client.call("session_open", {"agent_id": options.worker, "task_id": "browser-soak"})
    checks = 0
    mutations = 0
    latencies = []
    browser = None
    started = None

    def call(command, request_key=None, **args):
        nonlocal checks
        if browser is not None:
            args["browser_id"] = browser["browser_id"]
        before = time.monotonic()
        result = client.call("private_browser", {"command": command, **args},
                             request_key=f"soak-{request_key}" if request_key else None)
        latencies.append((time.monotonic() - before) * 1000)
        checks += 1
        return result

    try:
        browser = call("open", "open")
        tabs = call("tabs")["tabs"]
        check(len(tabs) == 1, "STARTING_TAB_COUNT")
        tab_id = tabs[0]["tab_id"]
        call("navigate", "navigate", tab_id=tab_id, url=options.fixture)
        deadline = time.monotonic() + 10
        while "Soak fixture" not in call("read", tab_id=tab_id)["text"]:
            check(time.monotonic() < deadline, "FIXTURE_NOT_READY")
            time.sleep(0.1)

        write_json(options.output / f"ready-{options.worker}.json", {**browser, "tab_id": tab_id})
        browsers = wait_for_file(options.output / "start.json", 90)
        foreign = next(value for name, value in browsers.items() if name != options.worker)
        try:
            client.call("private_browser", {"command": "tabs", "browser_id": foreign})
        except HubError as exc:
            check(exc.code == "RESOURCE_NOT_OWNED", "WRONG_FOREIGN_RESOURCE_ERROR")
        else:
            raise RuntimeError("FOREIGN_RESOURCE_ACCESS")

        started = time.monotonic()
        next_mutation = started
        while time.monotonic() - started < options.duration_seconds:
            check([tab["tab_id"] for tab in call("tabs")["tabs"]] == [tab_id], "TAB_IDENTITY_OR_COUNT")
            check("Soak fixture" in call("read", tab_id=tab_id)["text"], "FIXTURE_READ_FAILED")
            if time.monotonic() >= next_mutation:
                seen = call("observe", tab_id=tab_id)
                button = next(item for item in seen["controls"] if item.get("id") == "counter")
                mutations += 1
                args = {"tab_id": tab_id, "snapshot": seen["snapshot"], "ref": button["ref"], "operation": "click",
                        "postcondition": {"type": "value_equals", "selector": "output", "value": str(mutations)}}
                check(call("act", f"increment-{mutations}", **args)["verified"], "COUNTER_NOT_VERIFIED")
                next_mutation = time.monotonic() + 30
            time.sleep(min(options.poll_seconds, max(0, started + options.duration_seconds - time.monotonic())))
        end = call("info")
        for key in ("pid", "create_time", "hwnd", "desktop", "profile_path"):
            check(browser[key] == end[key], "BROWSER_AFFINITY_LOST")
    finally:
        measured = time.monotonic() - started if started is not None else 0
        cleanup = client.call("task_cancel", request_key="soak-cancel")
        check(cleanup["cleanup_verified"], "CLIENT_CLEANUP_FAILED")
        if browser is not None:
            check(not Path(browser["profile_path"]).exists(), "PROFILE_LEAK")
            check(not process_identity_matches(browser["pid"], browser["create_time"]), "BROWSER_PROCESS_LEAK")
    write_json(options.output / f"done-{options.worker}.json", {
        "browser_commands": checks,
        "verified_cdp_mutations": mutations,
        "elapsed_seconds": round(measured, 3),
        "p50_command_ms": round(statistics.median(latencies), 3),
        "p95_command_ms": round(sorted(latencies)[int(0.95 * (len(latencies) - 1))], 3),
        "stable_desktop_window_profile_browser_tab": True,
        "final_tab_count": 1,
        "foreign_target_denied": True,
        "profile_removed": True,
    })


def track_children(gate):
    identities = set(gate.owned)
    check(gate.process.poll() is None, "SOAK_HUB_EXITED")
    running = psutil.Process(gate.process.pid).children(recursive=True)
    for child in running:
        token = process_creation_token(child.pid)
        if token is not None:
            identities.add((child.pid, token))
    gate.owned[:] = identities
    return 1 + len(running)


def run(options):
    options.output.mkdir(parents=True, exist_ok=False)
    summary = {"status": "FAIL", "requested_elapsed_seconds": options.duration_seconds}
    summary["runtime_source_sha256_at_launch"] = {
        name: hashlib.sha256((RUNTIME / name).read_bytes()).hexdigest()
        for name in ("ff_hub.py", "ff_hub_store.py", "cua_private_browser.py", "cua_hidden_chrome.py", "cua_hidden_desktop.py")
    }
    with tempfile.TemporaryDirectory(prefix="ff-private-soak-") as sandbox, ExitStack() as stack:
        raw = Path(sandbox)
        gate = ProductGate(raw / "gate")
        observer = Observer()
        server = FixtureServer(("127.0.0.1", 0), FixtureHandler)
        stack.callback(server.server_close)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        stack.callback(server.shutdown)
        logs = {}
        processes = {}
        processes_per_minute = {}
        try:
            gate.start()
            fixture = f"http://127.0.0.1:{server.server_port}/"
            for name in CLIENTS:
                logs[name] = stack.enter_context((raw / f"{name}.log").open("w+", encoding="utf-8"))
                command = [sys.executable, "-X", "utf8", str(Path(__file__).resolve()), "--worker", name,
                           "--output", str(gate.hub_state.parent), "--fixture", fixture,
                           "--duration-seconds", str(options.duration_seconds), "--poll-seconds", str(options.poll_seconds)]
                processes[name] = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=logs[name], stderr=logs[name],
                                                   creationflags=subprocess.CREATE_NO_WINDOW)

            state = gate.hub_state.parent
            browsers = {name: wait_for_file(state / f"ready-{name}.json", 100, proc) for name, proc in processes.items()}
            for key in ("pid", "hwnd", "desktop", "profile_path", "browser_id", "tab_id"):
                check(len({info[key] for info in browsers.values()}) == len(CLIENTS), "SHARED_BROWSER_IDENTITY")
            for info in browsers.values():
                check(process_identity_matches(info["pid"], info["create_time"]), "SOAK_CHROME_PID_CHANGED")
                check(Path(psutil.Process(info["pid"]).exe()).resolve() == chrome_path(), "SOAK_CHROME_IMAGE_CHANGED")
                check(observer.window(info["desktop"], info["hwnd"], info["pid"]), "CHROME_OS_DESKTOP")
            write_json(state / "start.json", {name: info["browser_id"] for name, info in browsers.items()})

            started = time.monotonic()
            deadline = started + options.duration_seconds + 90
            while any(proc.poll() is None for proc in processes.values()):
                current = time.monotonic()
                check(current < deadline, "SOAK_CLIENT_TIMEOUT")
                check(all(proc.returncode in (0, None) for proc in processes.values()), "SOAK_CLIENT_FAILED")
                minute = int((current - started) // 60)
                processes_per_minute[minute] = max(processes_per_minute.get(minute, 0), track_children(gate))
                time.sleep(0.5)
            check(all(proc.returncode == 0 for proc in processes.values()), "SOAK_CLIENT_FAILED")
            status = HubClient(gate.hub_state).call("hub_status")
            summary["hub_idle_after_clients"] = not status["sessions"] and status["private_desktops"] == 0
            check(summary["hub_idle_after_clients"], "HUB_NOT_IDLE_AFTER_SOAK")
            summary["clients"] = {name: wait_for_file(state / f"done-{name}.json", 1) for name in CLIENTS}
            summary["status"] = "PASS"
        except Exception as exc:
            summary["error"] = getattr(exc, "code", str(exc)).replace(str(raw), "<isolated>")
            for name, proc in processes.items():
                if proc.returncode:
                    logs[name].seek(0)
                    lines = logs[name].read().splitlines()
                    summary.setdefault("failed_clients", {})[name] = (lines[-1].replace(str(raw), "<isolated>")
                                                                      if lines else f"exit code {proc.returncode}")
        finally:
            for proc in processes.values():
                if proc.poll() is None:
                    proc.terminate()
                    proc.wait(timeout=8)
            try:
                gate.cleanup()
            except Exception as exc:
                summary.update(status="FAIL", cleanup_error=getattr(exc, "code", str(exc)).replace(str(raw), "<isolated>"))
            gate.log.close()
            observation = observer.finish(gate.out, gate.owned)
            observation["clipboard_sequence_values"] = len({sample["clipboard_sequence"] for sample in observer.samples})
            summary.update(owner_observer=observation, peak_owned_hub_processes=max(processes_per_minute.values(), default=0),
                           peak_owned_hub_processes_per_minute=processes_per_minute,
                           tracked_owned_process_incarnations=len(gate.owned),
                           owned_processes_closed=not any(process_identity_matches(*p) for p in gate.owned))
            if not observation["samples"] or observation["error"] or observation["foreground_owned"] or observation["private_input"]:
                summary.update(status="FAIL", owner_observation_failed=True)
    write_json(options.output / "result.json", summary)
    print(json.dumps(summary, ensure_ascii=False))
    return 0 if summary["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=float, default=1200)
    parser.add_argument("--poll-seconds", type=float, default=5)
    parser.add_argument("--worker", choices=CLIENTS, help=argparse.SUPPRESS)
    parser.add_argument("--fixture", help=argparse.SUPPRESS)
    options = parser.parse_args()
    check(os.name == "nt", "WINDOWS_REQUIRED")
    check(0 < options.poll_seconds <= options.duration_seconds <= 3600, "SOAK_DURATION_INVALID")
    options.output = options.output.resolve()
    if options.worker:
        return worker(options)
    return run(options)


if __name__ == "__main__":
    raise SystemExit(main())
