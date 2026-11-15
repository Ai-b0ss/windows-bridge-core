"""Offline GitHub routing regressions: no credentials, network or owner runtime."""
import importlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
ABSENT = object()


class GitHubExplicitDeviceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory(prefix="ff-github-device-")
        with patch.dict(os.environ, {"FF_GH_HOME": cls.home.name,
                                    "FF_BRIDGE_ROOT": cls.home.name}), patch.object(sys, "path", sys.path.copy()):
            sys.path.insert(0, str(ROOT / "runtime/github-transport"))
            cls.daemon = importlib.import_module("ff_win_github_comment_daemon")
            cls.client = importlib.import_module("ff_win_github_client")
            cls.core = importlib.import_module("ff_win_transport_core")
            cls.real_rpc = staticmethod(cls.core._rpc)
            sys.path.insert(0, str(ROOT / "tools"))
            cls.remote = importlib.import_module("bridge_remote_gh")

    @classmethod
    def tearDownClass(cls):
        cls.home.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=self.home.name)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name, value in (("DEVICE", "device-a"), ("ALLOWED_SENDERS", {"owner"}),
                            ("trace", Mock())):
            p = patch.object(self.daemon, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.rpc = Mock(return_value=(200, {"ok": True}))
        for name, value in (("FAST_ROOT", self.root), ("DB", self.root / "journal.sqlite3"),
                            ("_rpc", self.rpc)):
            p = patch.object(self.core, name, value)
            p.start()
            self.addCleanup(p.stop)

    def task(self, target_value="device-a", **fields):
        value = {"schema": self.daemon.SCHEMA, "task_id": "task-1", "client_id": "agent-1",
                 "op": "write_file", "args": {"path": "synthetic", "content": "fixture"}}
        if target_value is not ABSENT:
            value["target_device"] = target_value
        return {**value, **fields}

    def comment(self, task=None, cid=101, **fields):
        return {"id": cid, "user": {"login": "Owner"},
                "body": json.dumps(self.task() if task is None else task), **fields}

    def transport(self):
        # Never call __init__: it obtains credentials and starts a publisher.
        t = object.__new__(self.daemon.CommentTransport)
        t.requests, t.outbox = self.root / "pending", self.root / "outbox"
        t.requests.mkdir(exist_ok=True)
        t.outbox.mkdir(exist_ok=True)
        t.active, t.active_lock = set(), threading.Lock()
        t.retry_after, t.last_recover_at = {}, 0
        t.pool, t.publish_result = Mock(), Mock()
        t.publish_queue = queue.Queue()
        t.counters = {"tasks_pass": 0, "tasks_failed": 0, "transient_retries": 0}
        t.inbox, t.etag, t.fast_history_loaded = 1, None, True
        return t

    def test_missing_and_invalid_targets_never_broadcast(self):
        for target in (ABSENT, None, "", " ", "\t\r\n", False, 0, 1, [], {},
                       ["device-a"], {"device": "device-a"}, " device-a", "device-a ",
                       "device-a\n", "*", "all", "device-a.example", "device-a\0"):
            with self.subTest(target=target):
                comment = self.comment(self.task(target))
                for device in ("device-a", "device-b"):
                    with patch.object(self.daemon, "DEVICE", device):
                        self.assertIsNone(self.daemon.parse_task(comment))
        self.rpc.assert_not_called()

    def test_target_is_required_for_reads_aliases_and_execution_contexts(self):
        for op in ("ping", "capabilities", "device_info", "get_config", "list_windows",
                   "write_file", "computer_use", "durable_call", "run_code", "READ_FILE", "unknown"):
            for context in ("auto", "interactive", "background"):
                with self.subTest(op=op, context=context):
                    task = self.task(ABSENT, op=op, execution_context=context,
                                     device="device-a", target="device-a", targetDevice="device-a",
                                     args={"target_device": "device-a", "op": "ping"})
                    self.assertIsNone(self.daemon.parse_task(self.comment(task)))

    def test_only_selected_device_accepts_each_agent_and_preserves_case_compatibility(self):
        for agent in ("agent-1", "agent-2"):
            for target in ("device-a", "device-b"):
                task = self.task(target.upper(), client_id=agent)
                for device in ("device-a", "device-b"):
                    with self.subTest(agent=agent, target=target, device=device), \
                            patch.object(self.daemon, "DEVICE", device):
                        self.assertEqual(self.daemon.parse_task(self.comment(task)),
                                         task if target == device else None)

    def test_other_schemas_and_untrusted_senders_remain_rejected(self):
        for schema in (None, "ff-win-github-comment-v4", self.daemon.RESULT_SCHEMA):
            self.assertIsNone(self.daemon.parse_task(self.comment(self.task(schema=schema))))
        self.assertIsNone(self.daemon.parse_task(self.comment(user={"login": "stranger"})))
        for body in ("null", "[]", "not JSON", '```json\n{}\n```'):
            self.assertIsNone(self.daemon.parse_task(self.comment(body=body)))
        for device in (None, "", " ", 1, " device-a"):
            with self.subTest(local_device=device), patch.object(self.daemon, "DEVICE", device):
                self.assertIsNone(self.daemon.parse_task(self.comment()))

    def test_duplicate_json_keys_cannot_hide_target_ambiguity(self):
        body = json.dumps(self.task())
        for extra in ('"target_device":null', '"target_device":"device-b"',
                      '"target_\\u0064evice":"device-a"'):
            for raw in ("{" + extra + "," + body[1:], body[:-1] + "," + extra + "}"):
                with self.subTest(body=raw):
                    self.assertIsNone(self.daemon.parse_task(self.comment(body=raw)))

    def test_rejection_audit_does_not_include_task_payload(self):
        c = self.comment(self.task(ABSENT, args={"secret": "private-payload"}))
        self.assertIsNone(self.daemon.parse_task(c))
        self.daemon.trace.assert_called_with("task_rejected", comment_id=101,
                                             reason="TARGET_DEVICE_REQUIRED")
        self.assertNotIn("private-payload", repr(self.daemon.trace.call_args_list))

    def test_submit_rejects_before_persisting_or_claiming(self):
        t = self.transport()
        for target in (ABSENT, None, "", "device-b"):
            t.submit(self.comment(self.task(target)))
        t.pool.submit.assert_not_called()
        self.assertEqual(t.active, set())
        self.assertEqual(list(t.requests.iterdir()), [])

    def test_worker_revalidates_comment_and_does_not_trust_separate_task(self):
        t = self.transport()
        for comment, task in ((self.comment(self.task(ABSENT)), self.task(ABSENT)),
                              (self.comment(), self.task("device-b")),
                              (self.comment(self.task("device-b")), self.task()),
                              (self.comment(), self.task(op="run_code"))):
            t.active.add(101)
            with patch.object(self.daemon, "execute_task", return_value=(200, {"ok": True}, {})) as execute:
                t.process(comment, task, 0)
                execute.assert_not_called()
            self.assertNotIn(101, t.active)
        t.publish_result.assert_not_called()

    def test_recovery_keeps_legacy_pending_and_dispatches_valid_pending(self):
        t = self.transport()
        legacy = t.requests / "101.json"
        legacy.write_text(json.dumps(self.comment(self.task(ABSENT))), encoding="utf-8")
        saved = legacy.read_bytes()
        valid = self.comment(cid=102)
        (t.requests / "102.json").write_text(json.dumps(valid), encoding="utf-8")
        t.recover_requests()
        self.assertEqual(legacy.read_bytes(), saved)
        t.pool.submit.assert_called_once()
        self.assertEqual(t.pool.submit.call_args.args[1], valid)

    def test_outbox_preserved_and_valid_results_requeued_without_execution(self):
        t = self.transport()
        item = {"comment_id": 101, "published": False, "body": "synthetic-result"}
        outbox = t.outbox / "101.json"
        outbox.write_text(json.dumps(item), encoding="utf-8")
        saved = outbox.read_bytes()
        t.submit(self.comment(self.task(ABSENT)))
        self.assertEqual(outbox.read_bytes(), saved)
        self.assertTrue(t.publish_queue.empty())
        t.submit(self.comment())
        self.assertEqual(t.publish_queue.get_nowait(), item)
        t.pool.submit.assert_not_called()
        self.rpc.assert_not_called()

    def test_startup_and_archive_scans_use_same_validation(self):
        t = self.transport()
        items = [self.comment(self.task(ABSENT)), self.comment(cid=102)]
        t.poll_api = Mock()
        t.poll_api.request.return_value = (200, {}, json.dumps(items).encode())
        t.resolve_inbox = Mock()
        t.startup_scan()
        self.assertEqual(t.pool.submit.call_count, 1)
        t.archived_inboxes = [{"issue": 2, "since": "synthetic"}]
        t.last_archive_poll, t.archive_cursor, t.archive_cache = 0, 0, {}
        t.scan_archives()
        self.assertEqual(t.pool.submit.call_count, 1)  # valid duplicate stays active

    def test_mutation_idempotency_conflict_and_multiple_agents(self):
        t = self.transport()
        t.pool.submit.side_effect = lambda fn, *args: fn(*args)
        t.submit(self.comment())
        t.submit(self.comment())  # active comment deduplication
        t.submit(self.comment(cid=102))  # same logical task, another comment
        self.assertEqual(self.rpc.call_count, 1)
        self.assertEqual(t.publish_result.call_args.args[2]["route"]["route"], "journal-cache")
        t.submit(self.comment(self.task(args={"content": "changed"}), cid=103))
        self.assertEqual(t.publish_result.call_args.args[2]["http_status"], 409)
        self.assertEqual(self.rpc.call_count, 1)
        t.submit(self.comment(self.task(client_id="agent-2"), cid=104))
        self.assertEqual(self.rpc.call_count, 2)
        with patch.object(self.daemon, "DEVICE", "device-b"):
            t.submit(self.comment(cid=105))
        self.assertEqual(self.rpc.call_count, 2)

    def test_migrated_legacy_journal_keeps_cached_and_unknown_outcomes(self):
        # Seed only the old journal contract, with no remote transport involved.
        for state, expected in (("done", 200), ("uncertain", 409)):
            task_id = "legacy-" + state
            old = self.task(ABSENT, task_id=task_id)
            self.assertEqual(self.core.journal_begin(old)[0], "execute")
            self.core.journal_finish(old, 200, {"ok": True}, state=state)
            t = self.transport()
            t.pool.submit.side_effect = lambda fn, *args: fn(*args)
            t.submit(self.comment(self.task(task_id=task_id)))
            result = t.publish_result.call_args.args[2]
            self.assertEqual(result["http_status"], expected)
            if state == "uncertain":
                self.assertEqual(result["result"]["error_code"], "TASK_OUTCOME_UNKNOWN")
        self.rpc.assert_not_called()

    def test_real_loopback_dispatch_with_separate_device_journals(self):
        effects = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                effects.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                raw = b'{"ok":true,"result":"isolated-fixture"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = self.root
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), self.core._NoRpcRedirect())
        with patch.object(self.core, "_rpc", self.real_rpc), \
                patch.object(self.core, "V3_RPC_URL", f"http://127.0.0.1:{server.server_port}/rpc"), \
                patch.object(self.core, "BACKGROUND_RPC_URL", ""), \
                patch.object(self.core, "_RPC_OPENER", opener):
            for device in ("device-a", "device-b"):
                self.root = base / device
                self.root.mkdir()
                secret = self.root / "secret"
                secret.write_text("isolated-fixture-" * 4, encoding="ascii")
                with patch.object(self.daemon, "DEVICE", device), \
                        patch.object(self.core, "FAST_ROOT", self.root), \
                        patch.object(self.core, "DB", self.root / "journal.sqlite3"), \
                        patch.object(self.core, "SECRET", secret):
                    t = self.transport()
                    t.pool.submit.side_effect = lambda fn, *args: fn(*args)
                    before = len(effects)
                    for target in (ABSENT, None, " ", "device-other"):
                        t.submit(self.comment(self.task(target)))
                    self.assertEqual(len(effects), before)
                    self.assertFalse(self.core.DB.exists())
                    t.submit(self.comment(self.task(device)))
                    t.submit(self.comment(self.task(device), cid=102))
                    self.assertEqual(len(effects), before + 1)
                    result = t.publish_result.call_args.args[2]
                    self.assertEqual(result["route"]["route"], "journal-cache")
                    self.assertEqual(result["device"], device)
                    self.assertEqual(result["task"]["target_device"], device)
        self.assertEqual(len(effects), 2)

    def test_client_submit_requires_target_before_any_api_request(self):
        for target in (ABSENT, None, "", "  ", False, 1, [], {}, " device-a", "device-a\n"):
            with self.subTest(target=target):
                api = Mock()
                with self.assertRaisesRegex(ValueError, "TARGET_DEVICE_REQUIRED"):
                    self.client.submit(api, "owner/repo", 1, self.task(target))
                api.request.assert_not_called()

    def test_client_redirect_preserves_explicit_target(self):
        api = Mock()
        api.request.side_effect = [
            (200, {}, json.dumps({"body": 'FF_GH_INBOX_V2 {"redirect":2}'}).encode()),
            (200, {}, b'{"body":""}'),
            (201, {}, b'{"id":101,"node_id":"fixture"}'),
        ]
        self.client.submit(api, "owner/repo", 1, self.task())
        call = api.request.call_args
        self.assertEqual(call.args[:2], ("POST", "/repos/owner/repo/issues/2/comments"))
        self.assertEqual(json.loads(call.args[2]["body"])["target_device"], "device-a")

    def test_client_cli_invalid_config_fails_before_credentials(self):
        config = self.root / "config.json"
        for target in (ABSENT, None, "", " ", False, 1, [], {}, " device-a", "device-a\n"):
            value = {"repository": "owner/repo", "inbox_issue": 1}
            if target is not ABSENT:
                value["device"] = target
            config.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(target=target), patch.object(self.client, "get_token") as token, \
                    patch.object(self.client, "GitHubREST") as api:
                with self.assertRaisesRegex(ValueError, "TARGET_DEVICE_REQUIRED"):
                    self.client.main(["--config", str(config)])
                token.assert_not_called()
                api.assert_not_called()

    def test_client_cli_uses_configured_device_in_all_contexts(self):
        config = self.root / "config.json"
        config.write_text(json.dumps({"repository": "owner/repo", "inbox_issue": 1,
                                      "device": "device-b"}), encoding="utf-8")
        for context in ("auto", "interactive", "background"):
            with self.subTest(context=context), patch.object(self.client, "get_token", return_value="fixture"), \
                    patch.object(self.client, "GitHubREST"), \
                    patch.object(self.client, "collect"), patch("builtins.print"), \
                    patch.object(self.client, "submit", return_value={"inbox_issue": 1}) as submit:
                self.client.main(["--config", str(config), "--execution-context", context])
                self.assertEqual(submit.call_args.args[3]["target_device"], "device-b")

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell required")
    def test_powershell_smoke_rejects_invalid_config_before_credentials(self):
        # Only invalid inputs reach this script; it must fail before even looking up gh.
        config = self.root / "github_transport_config.json"
        for target in (ABSENT, None, "", " ", False, 1, [], {}, " device-a", "device-a\n"):
            value = {} if target is ABSENT else {"device": target}
            config.write_text(json.dumps(value), encoding="utf-8")
            done = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                                   "-ExecutionPolicy", "Bypass", "-File",
                                   str(ROOT / "runtime/github-transport/ff_win_github_smoke_test.ps1"),
                                   "-Root", str(self.root)], capture_output=True, text=True,
                                  errors="replace", timeout=20)
            with self.subTest(target=target):
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("TARGET_DEVICE_REQUIRED", done.stderr)

    def test_remote_submit_helper_rejects_invalid_target_without_api(self):
        for target in (None, "", " ", False, 1, [], {}, " device-a", "device-a\n", "*"):
            with self.subTest(target=target):
                api = Mock()
                with self.assertRaises(self.remote.BridgeRemoteError):
                    self.remote.submit(api, "owner/repo", 1, target, "write_file", {})
                api.api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
