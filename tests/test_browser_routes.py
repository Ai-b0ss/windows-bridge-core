from __future__ import annotations

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))

from ff_agent_entry import EntryAuthority, entry_call  # noqa: E402
from ff_browser_routes import (  # noqa: E402
    RouteAffinityStore,
    choose_route,
    inspect_extensions_and_companion,
    route_plan,
)
from ff_hub import Hub  # noqa: E402
from ff_hub_permissions import Policy  # noqa: E402
from ff_hub_store import HubError  # noqa: E402


class _FakeManagedBrowser:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self._running = True
        self.starts = 1

    def running(self) -> bool:
        return self._running

    def stop(self) -> None:
        self._running = False

    def call(self, op: str, args: dict | None = None, *, timeout: float = 150.0) -> dict:
        args = dict(args or {})
        self.calls.append((op, args))
        if op == "status":
            return {"ok": True, "connected": True, "playwright_version": "1.65.1", "contexts": 1}
        if op == "open":
            return {
                "browser_id": "pw-test-1",
                "route": "persistent_playwright",
                "headless": True,
                "isolated_profile": True,
                "affinity_reused": False,
                "tab_id": "pwtab-1",
                "target_id": "TARGET-001",
                "url": args.get("url") or "about:blank",
                "title": "Stand",
            }
        if op == "navigate":
            return {"tab_id": "pwtab-1", "target_id": "TARGET-001", "url": args.get("url"), "title": "Stand"}
        if op == "act":
            return {"ok": True, "action": args.get("action"), "verified": True, "tab_id": "pwtab-1"}
        if op == "download_prepare":
            return {"download_id": "dl-1", "filename": "report.csv", "size": 24, "sha256": "abc"}
        if op == "download_read":
            return {"download_id": "dl-1", "filename": "report.csv", "size": 24, "content_base64": "YQ==", "eof": True}
        if op == "close":
            return {"closed": True, "browser_id": args.get("browser_id"), "profile_cleanup_verified": True}
        if op == "close_owner":
            return {"closed": 1, "errors": []}
        return {"ok": True}


class BrowserRoutesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.tmp.name) / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_affinity_store_persistence(self) -> None:
        store = RouteAffinityStore(self.state_dir)
        rec = store.record("agent-1", "task-1", route="persistent_playwright", browser_id="pw-1", tab_id="t-1", target_id="tgt-1")
        self.assertEqual(rec["route"], "persistent_playwright")
        reloaded = RouteAffinityStore(self.state_dir).get("agent-1", "task-1")
        self.assertIsNotNone(reloaded)
        self.assertEqual(reloaded["target_id"], "tgt-1")
        store.clear("agent-1", "task-1")
        self.assertIsNone(RouteAffinityStore(self.state_dir).get("agent-1", "task-1"))

    def test_choose_route_priority_and_affinity(self) -> None:
        routes = [
            {"route": "owner_chrome_extension", "state": "READY"},
            {"route": "persistent_playwright", "state": "ELIGIBLE"},
            {"route": "private_cdp", "state": "ELIGIBLE"},
        ]
        self.assertEqual(choose_route(routes, capability="dom"), "persistent_playwright")
        self.assertEqual(choose_route(routes, capability="extension_bridge"), "owner_chrome_extension")
        self.assertEqual(choose_route(routes, prefer="private_cdp"), "private_cdp")
        self.assertEqual(
            choose_route(routes, sticky={"route": "private_cdp"}),
            "private_cdp",
        )
        no_pw = [
            {"route": "owner_chrome_extension", "state": "UNAVAILABLE"},
            {"route": "persistent_playwright", "state": "UNAVAILABLE"},
            {"route": "private_cdp", "state": "ELIGIBLE"},
        ]
        self.assertEqual(choose_route(no_pw), "private_cdp")

    def test_route_plan_health_probed_and_scoped_boundaries(self) -> None:
        with mock.patch("ff_browser_routes.probe_playwright", return_value={"ok": True, "running": False, "playwright_version": "1.65.1", "probe_ms": 5}), \
             mock.patch("ff_browser_routes.probe_owner_chrome", return_value={"ok": True, "running": True, "probe_ms": 4}), \
             mock.patch("ff_browser_routes.apps.resolve", return_value={"found": True}):
            scoped = route_plan({"agent_id": "a1", "task_id": "t1", "scopes": {"private_browser"}}, surface="browser")
            self.assertTrue(scoped["health_probed"])
            self.assertFalse(scoped["foreground_fallback"])
            self.assertEqual(scoped["selected"], "persistent_playwright")
            owner_route = next(r for r in scoped["routes"] if r["route"] == "owner_chrome_extension")
            self.assertEqual(owner_route["state"], "UNAVAILABLE")

            owner_session = route_plan({"agent_id": "a1", "task_id": "t1"}, surface="browser", capability="extension_bridge")
            self.assertEqual(owner_session["selected"], "owner_chrome_extension")

        with self.assertRaises(HubError) as ctx:
            route_plan({"agent_id": "a1", "task_id": "t1", "scopes": {"private_browser"}}, surface="invalid")
        self.assertEqual(ctx.exception.code, "ENTRY_SURFACE_INVALID")

        diag = inspect_extensions_and_companion()
        self.assertIn("companion", diag)
        self.assertTrue(diag["companion"]["service_worker_error_guards"])

    def test_managed_browser_entry_lifecycle_and_cleanup(self) -> None:
        managed = _FakeManagedBrowser()
        Policy(self.state_dir / "policy.json").add_grant(
            ["browser_own_tabs"], hosts=["127.0.0.1"], agents=["a-pw"], ttl_seconds=600,
        )
        hub = Hub(self.state_dir, managed_browser=managed)
        try:
            auth = EntryAuthority(self.state_dir)
            _, token = auth.issue(
                client_id="c-pw", agent_id="a-pw", task_id="t-pw",
                scopes=["private_browser"], apps=[], ttl=600,
            )
            bearer = "Bearer " + token

            caps = entry_call(hub, auth, bearer, {"op": "capabilities"})
            self.assertIn("managed_browser", caps["operations"])
            self.assertIn("download_prepare", caps["managed_browser_commands"])

            with mock.patch("ff_browser_routes.probe_playwright", return_value={"ok": True, "running": True, "playwright_version": "1.65.1", "probe_ms": 1}):
                rp = entry_call(hub, auth, bearer, {"op": "route_plan", "args": {"surface": "browser"}})
                self.assertTrue(rp["health_probed"])
                self.assertEqual(rp["selected"], "persistent_playwright")

            sess = entry_call(hub, auth, bearer, {"op": "session_open"})["session_id"]

            # evaluate and foreground are forbidden at the scoped entry
            with self.assertRaises(HubError) as ectx:
                entry_call(hub, auth, bearer, {"op": "managed_browser", "session_id": sess, "args": {"command": "evaluate"}})
            self.assertEqual(ectx.exception.code, "ENTRY_BROWSER_COMMAND_DENIED")

            # Mutating open requires request_key
            with self.assertRaises(HubError) as rk:
                entry_call(hub, auth, bearer, {"op": "managed_browser", "session_id": sess, "args": {"command": "open", "url": "http://127.0.0.1:8080/"}})
            self.assertEqual(rk.exception.code, "REQUEST_KEY_REQUIRED")

            opened = entry_call(hub, auth, bearer, {
                "op": "managed_browser", "session_id": sess, "request_key": "req-pw-open-01",
                "args": {"command": "open", "url": "http://127.0.0.1:8080/"},
            })
            self.assertEqual(opened["browser_id"], "pw-test-1")
            self.assertIsNotNone(hub.route_affinity.get("a-pw", "t-pw"))

            # Read ops succeed without request_key
            dl = entry_call(hub, auth, bearer, {
                "op": "managed_browser", "session_id": sess,
                "args": {"command": "download_read", "browser_id": "pw-test-1", "download_id": "dl-1"},
            })
            self.assertEqual(dl["filename"], "report.csv")

            # task_cancel cleans managed_browser owner via close_owner cleanly
            cancelled = entry_call(hub, auth, bearer, {
                "op": "task_cancel", "session_id": sess, "request_key": "req-pw-cancel-01",
            })
            self.assertTrue(cancelled["cleanup_verified"])
            self.assertEqual(cancelled["errors"], [])
            self.assertTrue(any(op == "close_owner" for op, _ in managed.calls))
            self.assertIsNone(hub.route_affinity.get("a-pw", "t-pw"))
        finally:
            hub.shutdown()
            for obj in vars(hub.store).values():
                if isinstance(obj, sqlite3.Connection):
                    obj.close()


if __name__ == "__main__":
    unittest.main()
