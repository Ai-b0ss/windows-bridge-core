"""Real Node manager crash/reconnect + Hub journal. Browser/page effects are synthetic.

No owner Chrome, profile, credentials, installed runtime or fixed RPC port is used.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "runtime" / "bridge-v3"))
from ff_hub import BrowserManager, Hub
from ff_hub_store import HubError


class SyntheticManager(BrowserManager):
    def _start(self):
        self.state_dir.mkdir(parents=True, exist_ok=True)
        endpoint = self.state_dir / "endpoint.json"
        endpoint.unlink(missing_ok=True)
        self._key = secrets.token_urlsafe(48)
        self._process = subprocess.Popen(
            ["node", str(Path(__file__).with_name("browser_hub_crash_fixture.mjs")),
             str(endpoint), str(self.state_dir / "effects.txt")],
            env={**os.environ, "FF_BROWSER_HUB_KEY": self._key},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.processes.append(self._process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and self._process.poll() is None:
            if endpoint.exists():
                self._endpoint = json.loads(endpoint.read_text())
                self.starts += 1
                return
            time.sleep(.02)
        raise RuntimeError("SYNTHETIC_MANAGER_START_FAILED")


def main():
    with tempfile.TemporaryDirectory(prefix="ff-browser-crash-") as directory:
        manager = SyntheticManager(Path(directory))
        manager.processes = []
        hub = Hub(Path(directory), browser=manager)
        session = hub.dispatch({"op": "session_open", "args": {"agent_id": "crash-test", "task_id": "synthetic"}})
        def call(op, args=None, key=None):
            return hub.dispatch({"op": op, "args": args or {}, "request_key": key,
                                 "session_id": session["session_id"], "session_secret": session["session_secret"]})
        def denied(code, op, args, key):
            try:call(op, args, key)
            except HubError as exc:
                if exc.code != code:raise
            else:raise RuntimeError("EXPECTED_" + code)
        try:
            # Policy only in the disposable fixture, and only for the synthetic adapter.
            hub.policy.set_default("browser_script", "allow")
            tab = call("browser", {"command": "open", "url": "http://127.0.0.1/synthetic"}, "open-0001")
            args = {"command": "evaluate", "tab_id": tab["tab_id"], "expression": "synthetic-effect"}
            denied("BROWSER_MANAGER_UNREACHABLE", "browser", args, "effect-0001")
            manager._process.wait(timeout=5)
            assert manager._process.returncode == 77
            assert call("request_status", {"request_key": "effect-0001"})["state"] == "unknown"
            denied("REQUEST_OUTCOME_UNKNOWN", "browser", args, "effect-0001")
            assert manager.starts == 1
            denied("TAB_RECOVERY_UNAVAILABLE", "browser", {"command": "restore", "tab_id": tab["tab_id"]}, "restore-0001")
            assert manager.starts == 2
            denied("TAB_CLEANUP_UNCONFIRMED", "browser", {"command": "close", "tab_id": tab["tab_id"]}, "close-0001")
            assert len(call("resource_list")["resources"]) == 1
            assert (manager.state_dir / "effects.txt").read_text().splitlines() == ["effect"]
            report = call("session_close")
            assert report["cleanup_verified"] is False and report["browser_tabs_closed"] == 0
            assert report["errors"][0]["code"] == "TAB_CLEANUP_UNCONFIRMED"
            print(json.dumps({"status": "PASS", "real_node_crash": True, "synthetic_browser": True,
                              "journal_unknown": True, "no_replay": True, "no_url_adoption": True,
                              "no_duplicate_restore": True, "cleanup_unconfirmed": True}))
        finally:
            hub.shutdown()
            hub.store.close()
            for process in manager.processes:
                if process.poll() is None:process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":main()
