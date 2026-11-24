"""Hub authority and recovery regression tests; no browser or desktop is opened."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

PACKAGE = Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"
sys.path.insert(0, str(PACKAGE))
from ff_hub import Hub, _HubLease
from ff_hub_permissions import PermissionError_, Policy
from ff_hub_secrets import SecretError, Vault
from ff_hub_store import HubError, HubStore
import ff_hub_apps


class Browser:
    def __init__(self):
        self.calls = []

    def running(self):
        return False

    def call(self, op, args=None):
        self.calls.append((op, args))
        if op == "tab_open":
            return {"tab_id": "tab-1", "url": args["url"]}
        if op == "tab_close_owner":
            return {"closed": 1}
        if op == "tab_list":
            return {"tabs": [{"tab_id": "tab-1"}]}
        return {"ok": True}


class Hidden:
    def __init__(self):
        self.calls = []
        self.windows = [{"hwnd": 100, "pid": 20, "create_time": 300},
                        {"hwnd": 101, "pid": 21, "create_time": 301}]

    def request(self, payload, timeout_s=30):
        self.calls.append(payload)
        if payload["command"] == "describe_owned_windows":
            return {"windows": self.windows}
        return {"ok": True}

    def close(self):
        pass


class HubTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name)
        self.browser = Browser()
        self.hub = Hub(self.path, browser=self.browser)
        self.a = self.hub.dispatch({"op": "session_open", "args": {"agent_id": "a", "task_id": "work"}})
        self.b = self.hub.dispatch({"op": "session_open", "args": {"agent_id": "b", "task_id": "work"}})

    def tearDown(self):
        self.hub.shutdown()
        self.hub.store.close()
        self.temp.cleanup()

    def call(self, session, op, args=None, key=None):
        return self.hub.dispatch({"op": op, "args": args or {}, "session_id": session["session_id"],
                                  "session_secret": session["session_secret"], "request_key": key})

    def error(self, code, fn):
        with self.assertRaises(HubError) as caught:
            fn()
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_mutation_requires_key_before_browser_effect(self):
        self.error("REQUEST_KEY_REQUIRED", lambda: self.call(self.a, "browser", {"command": "open", "url": "https://example.com"}))
        self.assertEqual(self.browser.calls, [])

    def test_key_deduplicates_and_rejects_different_payload(self):
        args = {"command": "open", "url": "https://example.com"}
        first = self.call(self.a, "browser", args, "open-0001")
        second = self.call(self.a, "browser", args, "open-0001")
        self.assertFalse(first["deduplicated"])
        self.assertTrue(second["deduplicated"])
        self.assertEqual(len(self.browser.calls), 1)
        self.error("REQUEST_KEY_REUSED", lambda: self.call(self.a, "browser", {**args, "url": "https://example.org"}, "open-0001"))

    def test_same_key_can_proceed_after_permission_denied_before_execution(self):
        self.hub.policy.set_default("browser_own_tabs", "ask")
        args = {"command": "open", "url": "https://example.com"}
        denied = self.error("PERMISSION_REQUIRED", lambda: self.call(self.a, "browser", args, "permission-0001"))
        self.assertFalse(denied.details["execution_started"])
        self.assertEqual(self.browser.calls, [])
        repeated = self.error("PERMISSION_REQUIRED", lambda: self.call(self.a, "browser", args, "permission-0001"))
        self.assertEqual(denied.details["owner_request_id"], repeated.details["owner_request_id"])
        # Owner-side change in this temporary fixture, never an agent RPC grant.
        self.hub.policy.set_default("browser_own_tabs", "allow")
        self.assertFalse(self.call(self.a, "browser", args, "permission-0001")["deduplicated"])
        self.assertTrue(self.call(self.a, "browser", args, "permission-0001")["deduplicated"])
        self.assertEqual(len(self.browser.calls), 1)

    def test_foreign_tab_cannot_read_or_act_or_adopt(self):
        self.call(self.a, "browser", {"command": "open", "url": "https://example.com"}, "open-0001")
        for command in ("read", "act", "close", "restore"):
            self.error("RESOURCE_NOT_OWNED", lambda: self.call(self.b, "browser", {"command": command, "tab_id": "tab-1"}, "foreign-" + command))
        self.error("RESOURCE_KIND_MANAGED", lambda: self.call(self.b, "resource_claim", {"kind": "browser_tab", "key": "tab-1"}, "adopt-0001"))
        self.assertEqual(len(self.browser.calls), 1)

    def test_wrong_secret_cannot_use_labels_to_authenticate(self):
        self.error("SESSION_INVALID", lambda: self.hub.dispatch({"op": "session_status", "session_id": self.a["session_id"],
                                                                "session_secret": self.b["session_secret"], "args": {"agent_id": "a"}}))

    def test_managed_resource_release_cannot_orphan_live_tab(self):
        self.call(self.a, "browser", {"command": "open", "url": "https://example.com"}, "open-0001")
        held = self.call(self.a, "resource_list")["resources"][0]
        self.error("RESOURCE_KIND_MANAGED", lambda: self.call(self.a, "resource_release", {"resource_id": held["resource_id"]}))
        self.assertEqual(len(self.call(self.a, "resource_list")["resources"]), 1)

    def test_failed_open_retains_ownership_until_cleanup_succeeds(self):
        def fail(op, args=None):
            if op == "tab_open":
                raise HubError("NAVIGATION_FAILED", cleanup_failed=True, tab_id="tab-retained", attempted=True)
            if op == "tab_list":
                return {"tabs": [{"tab_id": "tab-retained"}]}
            return {"closed": 1}

        self.browser.call = fail
        self.browser.running = lambda: True
        self.error("NAVIGATION_FAILED", lambda: self.call(self.a, "browser", {"command": "open", "url": "https://example.com"}, "open-0001"))
        self.assertEqual(self.call(self.a, "resource_list")["resources"][0]["key"], "tab-retained")
        self.assertEqual(self.call(self.a, "session_close")["browser_tabs_closed"], 1)

    def test_cleanup_queries_owner_even_without_stored_tab_record(self):
        self.browser.running = lambda: True
        report = self.call(self.a, "session_close")
        self.assertEqual(report["browser_tabs_closed"], 1)
        self.assertEqual(self.browser.calls[-1][0], "tab_close_owner")

    def test_cleanup_closes_private_worker_without_materialized_app_record(self):
        hidden = Hidden()
        self.hub._hidden[self.hub._owner(self.a)] = hidden
        with patch.object(hidden, "close") as close:
            self.call(self.a, "session_close")
            close.assert_called_once()
        self.assertEqual(self.hub._hidden, {})

    def test_manager_handle_loss_cannot_claim_close_or_create_restore_duplicate(self):
        self.call(self.a, "browser", {"command": "open", "url": "https://example.com"}, "open-0001")
        def missing(op, args=None):
            self.browser.calls.append((op, args))
            raise HubError("TAB_NOT_FOUND")
        self.browser.call = missing
        for command, code in (("close", "TAB_CLEANUP_UNCONFIRMED"), ("restore", "TAB_RECOVERY_UNAVAILABLE")):
            args = {"command": command, "tab_id": "tab-1"}
            self.error(code, lambda: self.call(self.a, "browser", args, "lost-" + command))
            calls = len(self.browser.calls)
            self.error(code, lambda: self.call(self.a, "browser", args, "lost-" + command))
            self.assertEqual(len(self.browser.calls), calls)
        self.assertEqual(len(self.call(self.a, "resource_list")["resources"]), 1)
        self.assertEqual(sum(op == "tab_open" for op, _ in self.browser.calls), 1)

    def test_unknown_browser_reply_is_journaled_unknown_and_never_replayed(self):
        def lost_reply(op, args=None):
            self.browser.calls.append((op, args))
            raise HubError("BROWSER_MANAGER_UNREACHABLE", attempted=True, retry_safe=False, outcome_unknown=True)
        self.browser.call = lost_reply
        args = {"command": "open", "url": "https://example.com"}
        self.error("BROWSER_MANAGER_UNREACHABLE", lambda: self.call(self.a, "browser", args, "crash-0001"))
        self.assertEqual(self.call(self.a, "request_status", {"request_key": "crash-0001"})["state"], "unknown")
        self.error("REQUEST_OUTCOME_UNKNOWN", lambda: self.call(self.a, "browser", args, "crash-0001"))
        self.assertEqual(len(self.browser.calls), 1)

    def test_cleanup_reports_missing_handles_and_audits_failure(self):
        self.call(self.a, "browser", {"command": "open", "url": "https://example.com"}, "open-0001")
        self.browser.running = lambda: True
        self.browser.call = lambda op, args=None: {"tabs": []} if op == "tab_list" else {"closed": 0}
        report = self.call(self.a, "session_close")
        self.assertFalse(report["cleanup_verified"])
        self.assertEqual(report["browser_tabs_closed"], 0)
        self.assertEqual(report["errors"][0]["tab_ids"], ["tab-1"])
        audit = self.hub.store.read_audit(agent_id="a")
        self.assertEqual(audit[-1]["event"], "session_close")
        self.assertEqual(audit[-1]["detail"]["errors"], report["errors"])

    def test_foreground_blocked_even_with_legacy_policy_grant(self):
        (self.path / "policy.json").write_text(json.dumps({"version": 1, "defaults": {"foreground_input": "allow"}, "grants": []}), encoding="utf-8")
        self.error("FOREGROUND_ROUTE_REQUIRED", lambda: self.call(self.a, "browser", {"command": "act", "foreground": True, "tab_id": "irrelevant"}, "foreground-0001"))
        self.assertEqual(self.browser.calls, [])

    def test_resume_waits_for_inflight_request_and_invalidates_old_session(self):
        entered, release, resumed = threading.Event(), threading.Event(), threading.Event()
        original = self.browser.call

        def blocking(op, args=None):
            if op == "tab_open":
                entered.set()
                self.assertTrue(release.wait(5))
            return original(op, args)

        self.browser.call = blocking
        errors = []

        def open_tab():
            try:
                self.call(self.a, "browser", {"command": "open", "url": "https://example.com"}, "open-0001")
            except BaseException as exc:
                errors.append(exc)

        outcome = []

        def resume():
            outcome.append(self.hub.dispatch({"op": "session_open", "args": {"agent_id": "a", "task_id": "work", "resume_token": self.a["resume_token"]}}))
            resumed.set()

        writer = threading.Thread(target=open_tab)
        taker = threading.Thread(target=resume)
        writer.start()
        try:
            self.assertTrue(entered.wait(3))
            self.assertEqual(self.call(self.a, "request_status", {"request_key": "open-0001"})["state"], "started")
            self.assertEqual(self.call(self.a, "session_heartbeat")["agent_id"], "a")
            taker.start()
            self.assertFalse(resumed.wait(.1))
        finally:
            release.set()
            writer.join(5)
            taker.join(5)
        self.assertEqual(errors, [])
        self.assertTrue(resumed.is_set())
        self.assertEqual(outcome[0]["adopted_resources"], 1)
        self.error("SESSION_CLOSED", lambda: self.call(self.a, "session_status"))

    def own_app(self):
        hidden = Hidden()
        self.hub._hidden[self.hub._owner(self.a)] = hidden
        self.hub.store.claim(self.a, "app_session", "app-a", meta={"hwnd": 100, "pid": 20, "create_time": 300})
        return hidden

    def test_app_id_cannot_target_another_app_on_same_private_desktop(self):
        hidden = self.own_app()
        self.error("APP_WINDOW_NOT_OWNED", lambda: self.call(self.a, "app_observe", {"app_id": "app-a", "hwnd": 101}))
        self.assertEqual([call["command"] for call in hidden.calls], ["describe_owned_windows"])
        result = self.call(self.a, "app_windows", {"app_id": "app-a"})
        self.assertEqual([item["hwnd"] for item in result["windows"]], [100])

    def test_recycled_pid_or_hwnd_rejected_by_creation_time(self):
        hidden = self.own_app()
        hidden.windows[0]["create_time"] += 1
        self.error("APP_WINDOW_NOT_OWNED", lambda: self.call(self.a, "app_capture", {"app_id": "app-a"}))
        self.assertEqual(len(hidden.calls), 1)

    def test_app_id_of_other_agent_is_rejected_before_private_worker(self):
        hidden = self.own_app()
        self.error("RESOURCE_NOT_OWNED", lambda: self.call(self.b, "app_observe", {"app_id": "app-a"}))
        self.assertEqual(hidden.calls, [])


class StoreRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "state.db"
        self.now = 100.0
        self.store = HubStore(self.path, clock=lambda: self.now, session_ttl=1, orphan_ttl=2)
        self.session = self.store.open_session("agent", "task")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_stale_and_closed_sessions_never_transfer_without_token(self):
        self.store.claim(self.session, "custom", "lease")
        self.now += 2
        with self.assertRaises(HubError) as caught:
            self.store.open_session("agent", "task")
        self.assertEqual(caught.exception.code, "SESSION_ACTIVE_ELSEWHERE")
        self.store.close_session(self.session["session_id"])
        with self.assertRaises(HubError):
            self.store.open_session("agent", "task")
        resumed = self.store.open_session("agent", "task", resume_token=self.session["resume_token"])
        self.assertTrue(resumed["resumed"])

    def test_unknown_operation_is_never_automatically_replayed_after_restart(self):
        executions = []

        def crash():
            executions.append(1)
            raise KeyboardInterrupt()

        with self.assertRaises(KeyboardInterrupt):
            self.store.journal_execute(self.session, "mutate-0001", "op", {}, crash)
        self.store.close()
        self.store = HubStore(self.path, clock=lambda: self.now)
        with self.assertRaises(HubError) as caught:
            self.store.journal_execute(self.session, "mutate-0001", "op", {}, lambda: executions.append(2))
        self.assertEqual(caught.exception.code, "REQUEST_OUTCOME_UNKNOWN")
        self.assertEqual(executions, [1])
        self.assertEqual(self.store.journal_status(self.session, "mutate-0001")["state"], "unknown")

    def test_file_lock_conflict_and_release_are_per_session(self):
        other = self.store.open_session("other", "task")
        held = self.store.claim(self.session, "file", "report")
        with self.assertRaises(HubError) as caught:
            self.store.claim(other, "file", "report")
        self.assertEqual(caught.exception.code, "RESOURCE_BUSY")
        with self.assertRaises(HubError):
            self.store.release(other, resource_id=held["resource_id"])
        self.assertEqual(self.store.claim(other, "file", "other-report")["key"], "other-report")

    def test_authenticate_touch_false_and_atomic_close_session(self):
        before = self.store._session_row(self.session["session_id"])["last_seen_at"]
        self.now += 0.5
        self.store.authenticate(self.session["session_id"], self.session["session_secret"], touch=False)
        self.assertEqual(self.store._session_row(self.session["session_id"])["last_seen_at"], before)
        self.store.claim(self.session, "custom", "atomic-lock")
        held = self.store.close_session(self.session["session_id"])
        self.assertEqual(len(held), 1)
        self.assertEqual(self.store.sessions(), [])
        self.assertEqual(self.store.resources(session_id=self.session["session_id"]), [])

    def test_handler_reply_audits_windows_connection_aborted_cleanly(self):
        from ff_hub import make_handler
        hub = Hub(self.path.parent / "handler-hub", browser=Browser())
        try:
            handler_cls = make_handler(hub, "test-key")
            handler = handler_cls.__new__(handler_cls)
            handler.send_response = lambda *a, **kw: None
            handler.send_header = lambda *a, **kw: None
            handler.end_headers = lambda: None

            class _AbortedWriter:
                def write(self, _data):
                    raise ConnectionAbortedError(10053, "software caused connection abort")

            handler.wfile = _AbortedWriter()
            handler._reply(200, {"ok": True})
            events = [row["event"] for row in hub.store.read_audit(limit=10)]
            self.assertIn("client_disconnected", events)
        finally:
            hub.shutdown()
            hub.store.close()


class PolicyAndBrokerTests(unittest.TestCase):
    def test_policy_revocation_with_same_timestamp_and_size_is_seen(self):
        with tempfile.TemporaryDirectory() as work:
            file = Path(work) / "policy.json"
            policy = Policy(file)
            policy.set_default("browser_own_tabs", "allow")
            self.assertEqual(policy.decide("agent", "browser_own_tabs")["decision"], "allow")
            stamp = file.stat()
            previous = file.read_bytes()
            revoked = previous.replace(b'"allow"', b'"ask"  ')
            self.assertEqual(len(previous), len(revoked))
            file.write_bytes(revoked)
            os.utime(file, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            self.assertEqual(policy.decide("agent", "browser_own_tabs")["decision"], "needs_owner")

    def test_damaged_policy_does_not_restore_builtin_allow_defaults(self):
        with tempfile.TemporaryDirectory() as work:
            file = Path(work) / "policy.json"
            policy = Policy(file)
            policy.set_default("browser_own_tabs", "ask")
            self.assertEqual(policy.decide("agent", "browser_own_tabs")["decision"], "needs_owner")
            file.write_text("{damaged", encoding="utf-8")
            for risk in ("browser_own_tabs", "own_resources", "read_diagnose", "secret_use"):
                decision = policy.decide("agent", risk)
                self.assertEqual(decision["decision"], "needs_owner")
                self.assertEqual(decision["reason"], "POLICY_FILE_INVALID")

    def test_route_recommendation_preserves_programmatic_priority(self):
        app = {"found": True, "kind": "electron_editor", "name": "Cursor.exe", "known": "cursor", "executable": "Cursor.exe"}
        with patch.object(ff_hub_apps, "resolve", return_value=app), patch.object(ff_hub_apps.shutil, "which", return_value="available-cli"):
            self.assertEqual(ff_hub_apps.plan("cursor")["recommended"]["route"], "cli")

    def test_optional_host_scope_on_script_grant_is_binding(self):
        with tempfile.TemporaryDirectory() as work:
            policy = Policy(Path(work) / "policy.json")
            policy.add_grant(["browser_script"], agents=["agent"], hosts=["example.com"])
            self.assertEqual(policy.decide("agent", "browser_script", {"host": "example.com"})["decision"], "allow")
            for target in ({"host": "evil.test"}, {}):
                self.assertEqual(policy.decide("agent", "browser_script", target)["decision"], "needs_owner")

    def test_external_message_and_foreground_never_receive_standing_grants(self):
        with tempfile.TemporaryDirectory() as work:
            policy = Policy(Path(work) / "policy.json")
            for risk in ("external_send", "foreground_input"):
                with self.assertRaises(PermissionError_):
                    policy.add_grant([risk], hosts=["example.com"])
                with self.assertRaises(PermissionError_):
                    policy.set_default(risk, "allow")
                self.assertEqual(policy.decide("agent", risk)["decision"], "needs_owner")

    def test_browser_and_electron_generic_launch_is_not_recommended(self):
        for kind, name in (("chromium_browser", "chrome.exe"), ("electron_editor", "Cursor.exe"), ("electron", "other.exe")):
            options = ff_hub_apps.routes({"found": True, "kind": kind, "name": name, "executable": name})
            hidden = next(item for item in options if item["route"] == "hidden_desktop_uia")
            self.assertFalse(hidden["launch_allowed"])

    def test_secret_short_values_are_redacted(self):
        self.assertEqual(Vault._scrub("value=xy", "xy"), "value=[secret]")

    def test_secret_host_header_override_refused_before_value_is_read(self):
        with tempfile.TemporaryDirectory() as work:
            vault = Vault(work)
            with patch.object(vault, "_allowed", return_value={"hosts": ["example.com"]}), patch.object(vault, "_value") as value:
                with self.assertRaises(SecretError) as caught:
                    vault.use_http("agent", "key", {"url": "https://example.com/", "headers": {"Host": "evil.test", "Authorization": "{{secret}}"}})
                self.assertEqual(caught.exception.code, "SECRET_HEADER_FORBIDDEN")
                value.assert_not_called()

    def test_secret_invalid_port_url_and_timeout_raise_before_value_is_read(self):
        with tempfile.TemporaryDirectory() as work:
            vault = Vault(work)
            allowed = {"hosts": ["example.com"], "commands": [os.path.normcase(os.path.abspath(sys.executable))]}
            with patch.object(vault, "_allowed", return_value=allowed), patch.object(vault, "_value") as value:
                for bad_url in ("https://example.com:99999/", "https://[::1/"):
                    with self.assertRaises(SecretError) as caught:
                        vault.use_http("agent", "key", {"url": bad_url, "headers": {"Authorization": "{{secret}}"}})
                    self.assertEqual(caught.exception.code, "SECRET_URL_INVALID")
                    self.assertFalse(caught.exception.details["execution_started"])
                for bad_timeout in ("bad", True, False, 0, -1, float("nan"), float("inf")):
                    with self.assertRaises(SecretError) as caught:
                        vault.use_http("agent", "key", {
                            "url": "https://example.com/",
                            "headers": {"Authorization": "{{secret}}"},
                            "timeout_s": bad_timeout,
                        })
                    self.assertEqual(caught.exception.code, "SECRET_REQUEST_INVALID")
                    self.assertFalse(caught.exception.details["execution_started"])
                    with self.assertRaises(SecretError) as caught:
                        vault.use_process("agent", "key", {
                            "argv": [sys.executable],
                            "env_name": "TOK",
                            "timeout_s": bad_timeout,
                        })
                    self.assertEqual(caught.exception.code, "SECRET_PROCESS_INVALID")
                    self.assertFalse(caught.exception.details["execution_started"])
                value.assert_not_called()

    def test_secret_use_marks_network_failure_and_process_timeout_unknown_in_journal(self):
        import subprocess
        import urllib.error
        with tempfile.TemporaryDirectory() as work:
            hub = Hub(Path(work), browser=Browser())
            try:
                sess = hub.dispatch({"op": "session_open", "args": {"agent_id": "a", "task_id": "sec-unknown"}})
                hub.policy.add_grant(["secret_use"], agents=["a"], secrets=["demo"])
                allowed = {"hosts": ["api.example.invalid"], "commands": [os.path.normcase(os.path.abspath(sys.executable))]}

                def call(args, key):
                    return hub.dispatch({
                        "op": "secret_use",
                        "args": args,
                        "session_id": sess["session_id"],
                        "session_secret": sess["session_secret"],
                        "request_key": key,
                    })

                http_args = {
                    "name": "demo",
                    "use": "http",
                    "request": {"url": "https://api.example.invalid/", "headers": {"Authorization": "{{secret}}"}},
                }

                class _FailingOpener:
                    def open(self, *args, **kwargs):
                        raise urllib.error.URLError("timed out after connect")

                with patch.object(hub.vault, "_allowed", return_value=allowed), \
                     patch.object(hub.vault, "_value", return_value="secret-val"), \
                     patch("ff_hub_secrets.urllib.request.build_opener", return_value=_FailingOpener()):
                    with self.assertRaises(HubError) as caught:
                        call(http_args, "secret-http-fail-1")
                    self.assertEqual(caught.exception.code, "SECRET_REQUEST_FAILED")
                    self.assertTrue(caught.exception.details["outcome_unknown"])
                st = hub.dispatch({
                    "op": "request_status",
                    "args": {"request_key": "secret-http-fail-1"},
                    "session_id": sess["session_id"],
                    "session_secret": sess["session_secret"],
                })
                self.assertEqual(st["state"], "unknown")
                with self.assertRaises(HubError) as replay:
                    call(http_args, "secret-http-fail-1")
                self.assertEqual(replay.exception.code, "REQUEST_OUTCOME_UNKNOWN")

                proc_args = {
                    "name": "demo",
                    "use": "process",
                    "request": {"argv": [sys.executable, "-c", "pass"], "env_name": "TOK", "timeout_s": 1},
                }
                with patch.object(hub.vault, "_allowed", return_value=allowed), \
                     patch.object(hub.vault, "_value", return_value="secret-val"), \
                     patch("ff_hub_secrets.subprocess.run", side_effect=subprocess.TimeoutExpired([sys.executable], 1)):
                    with self.assertRaises(HubError) as caught:
                        call(proc_args, "secret-proc-timeout-1")
                    self.assertEqual(caught.exception.code, "SECRET_PROCESS_TIMEOUT")
                    self.assertTrue(caught.exception.details["outcome_unknown"])
                st_proc = hub.dispatch({
                    "op": "request_status",
                    "args": {"request_key": "secret-proc-timeout-1"},
                    "session_id": sess["session_id"],
                    "session_secret": sess["session_secret"],
                })
                self.assertEqual(st_proc["state"], "unknown")
                with self.assertRaises(HubError) as replay_proc:
                    call(proc_args, "secret-proc-timeout-1")
                self.assertEqual(replay_proc.exception.code, "REQUEST_OUTCOME_UNKNOWN")

                # Malformed IPv6 URL must not raise HUB_INTERNAL_ERROR in dispatch; journal marks execution_started=False.
                bad_ipv6 = {
                    "name": "demo",
                    "use": "http",
                    "request": {"url": "https://[::1/", "headers": {"Authorization": "{{secret}}"}},
                }
                with patch.object(hub.vault, "_allowed", return_value=allowed):
                    with self.assertRaises(HubError) as caught:
                        call(bad_ipv6, "secret-bad-ipv6-1")
                    self.assertEqual(caught.exception.code, "SECRET_URL_INVALID")
                st_bad = hub.dispatch({
                    "op": "request_status",
                    "args": {"request_key": "secret-bad-ipv6-1"},
                    "session_id": sess["session_id"],
                    "session_secret": sess["session_secret"],
                })
                self.assertEqual(st_bad["state"], "failed")
                self.assertFalse(st_bad["execution_started"])
            finally:
                hub.shutdown()
                hub.store.close()

    def test_singleton_lock_cannot_be_acquired_twice(self):
        with tempfile.TemporaryDirectory() as work:
            with _HubLease(Path(work)):
                with self.assertRaises(HubError) as caught:
                    with _HubLease(Path(work)):
                        self.fail("second Hub took the lock")
                self.assertEqual(caught.exception.code, "HUB_ALREADY_RUNNING")
            with _HubLease(Path(work)):
                pass


if __name__ == "__main__":
    unittest.main()
