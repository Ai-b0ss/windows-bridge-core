"""Offline comment transport regression tests; never start the inbox daemon."""
import importlib
import concurrent.futures
import copy
import hashlib
import http.server
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]


class CommentOutboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory(dir=ROOT / ".git" if (ROOT / ".git").is_dir() else None)
        cls.addClassCleanup(cls.home.cleanup)
        with patch.dict(os.environ, {"FF_GH_HOME": cls.home.name,
                                     "FF_BRIDGE_ROOT": cls.home.name}):
            sys.path.insert(0, str(ROOT / "runtime/github-transport"))
            cls.daemon = importlib.import_module("ff_win_github_comment_daemon")
            cls.core = importlib.import_module("ff_win_transport_core")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / ".git" if (ROOT / ".git").is_dir() else None)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.enterContext(patch.object(self.daemon, "GH_HOME", self.root))
        self.enterContext(patch.object(self.core, "FAST_ROOT", self.root / "journal"))
        self.enterContext(patch.object(self.core, "DB", self.root / "journal/tasks.sqlite3"))
        self.real_rpc = self.core._rpc
        self.rpc = self.enterContext(patch.object(self.core, "_rpc", return_value=(200, {"ok": True})))
        with patch.object(self.daemon, "get_token", return_value="offline"), \
             patch("threading.Thread.start"):
            self.transport = self.daemon.CommentTransport()
        self.transport.pool.shutdown(wait=True)
        self.transport.pool = Mock()
        self.task = {"schema": self.daemon.SCHEMA, "client_id": "test-client",
                     "task_id": "test-task", "target_device": self.daemon.DEVICE,
                     "op": "write_file", "args": {"text": "once"}}
        self.comment = {"id": 71, "node_id": "owned-node",
                        "user": {"login": next(iter(self.daemon.ALLOWED_SENDERS))},
                        "body": json.dumps(self.task)}
        self.saved = self.transport.outbox / "71.json"

    def result_item(self, **changes):
        result = {"schema": self.daemon.RESULT_SCHEMA, "transport_version": 5,
                  "comment_id": 71, "device": self.daemon.DEVICE,
                  "inbox_issue": self.transport.inbox, "task": copy.deepcopy(self.task),
                  "outcome": "PASS", "http_status": 200, "route": {"route": "v3"},
                  "result": {"ok": True, "original": "cached"}}
        result.update(changes)
        return {"comment_id": 71, "node_id": "owned-node", "published": False,
                "body": json.dumps(result)}

    def save(self, item):
        self.saved.write_text(json.dumps(item), encoding="utf-8")

    def queued_result(self):
        item = self.transport.publish_queue.get_nowait()
        self.transport.publish_queue.task_done()
        return item, json.loads(item["body"])

    def assert_evidence(self, raw):
        evidence = list((self.transport.outbox / "quarantine").glob("*.bin"))
        self.assertTrue(evidence)
        self.assertIn(raw, [p.read_bytes() for p in evidence])
        for file in evidence:
            metadata = json.loads(file.with_suffix(".json").read_text())
            self.assertEqual(metadata["comment_id"], 71)
            self.assertEqual(metadata["sha256"], hashlib.sha256(file.read_bytes()).hexdigest())

    def drain_publisher(self):
        class Drained(BaseException):
            pass

        original_get = self.transport.publish_queue.get

        def get(**kwargs):
            if self.transport.publish_queue.empty():
                raise Drained()
            return original_get(block=False)

        with patch.object(self.transport.publish_queue, "get", side_effect=get), \
             patch.object(self.daemon, "RESULT_BATCH_WINDOW_SECONDS", 0), \
             patch.object(self.daemon, "RESULT_BATCH_BURST_WINDOW_SECONDS", 0):
            with self.assertRaises(Drained):
                self.transport.publisher_loop()

    def test_bad_json_does_not_leak_active_reservation(self):
        self.saved.write_bytes(b'{"comment_id":71,')
        # Even a second failure (e.g. disk full during quarantine/publication)
        # must release the reservation so the next poll can recover.
        with patch.object(self.transport, "save_outbox", side_effect=OSError("disk full")):
            try:
                self.transport.submit(self.comment)
            except (ValueError, OSError):
                pass
        self.assertNotIn(71, self.transport.active)
        self.transport.pool.submit.assert_not_called()

    def test_corrupt_result_without_journal_publishes_unknown_never_dispatches(self):
        raw = b'{"comment_id":71,'
        self.saved.write_bytes(raw)
        self.transport.submit(self.comment)
        item, result = self.queued_result()
        self.assertEqual(result["outcome"], "FAILED")
        self.assertEqual(result["result"]["error_code"], "TASK_OUTCOME_UNKNOWN")
        self.assertFalse(result["result"]["retry_safe"])
        self.assertEqual(result["task"], self.task)
        self.assertEqual(item["node_id"], self.comment["node_id"])
        self.transport.pool.submit.assert_not_called()
        self.rpc.assert_not_called()
        self.assert_evidence(raw)

    def test_completed_mutation_recovers_exact_journal_response_without_second_effect(self):
        effects = []

        def effect(task, timeout):
            effects.append(task)
            (self.root / "effect.txt").write_text("once")
            return 201, {"ok": True, "value": "original response"}

        self.rpc.side_effect = effect
        original = self.core.execute_task(self.task)
        self.saved.write_bytes(b"\xffnot-utf8")
        self.transport.submit(self.comment)
        _, result = self.queued_result()
        self.assertEqual(result["result"], original[1])
        self.assertEqual(result["http_status"], 201)
        self.assertTrue(result["route"]["deduplicated"])
        self.assertEqual(len(effects), 1)
        self.assertEqual((self.root / "effect.txt").read_text(), "once")

    def test_read_only_retries_exact_task_but_unknown_ops_do_not(self):
        for op, safe in (("read_file", True), ("read_arbitrary_mutation", False),
                         ("write_file", False)):
            with self.subTest(op=op):
                self.task["op"] = op
                self.comment["body"] = json.dumps(self.task)
                self.saved.write_bytes(b"{")
                self.transport.active.clear()
                self.transport.pool.reset_mock()
                self.transport.submit(self.comment)
                if safe:
                    args = self.transport.pool.submit.call_args.args
                    self.assertEqual(args[1:3], (self.comment, self.task))
                else:
                    self.transport.pool.submit.assert_not_called()
                    self.queued_result()
        self.rpc.assert_not_called()

    def test_unreadable_result_keeps_original_and_releases_for_retry(self):
        item = self.result_item()
        self.save(item)
        original = self.saved.read_bytes()
        read_bytes = Path.read_bytes

        def denied(path):
            if path == self.saved:
                raise PermissionError("injected denial")
            return read_bytes(path)

        with patch.object(Path, "read_bytes", denied):
            with self.assertRaises(PermissionError):
                self.transport.submit(self.comment)
        self.assertEqual(self.transport.active, set())
        self.assertIn("PermissionError", self.transport.last_error)
        self.assertEqual(self.saved.read_bytes(), original)
        self.transport.submit(self.comment)
        queued, _ = self.queued_result()
        self.assertEqual(queued, item)
        self.transport.pool.submit.assert_not_called()

    def test_valid_cached_result_is_republished_verbatim_without_execution(self):
        item = self.result_item()
        self.save(item)
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[0], item)
        self.transport.pool.submit.assert_not_called()
        self.rpc.assert_not_called()

    def test_published_cached_result_cleans_pending_request_and_active(self):
        item = self.result_item()
        item["published"] = True
        self.save(item)
        pending = self.transport.requests / "71.json"
        pending.write_text(json.dumps(self.comment))
        self.transport.submit(self.comment)
        self.assertFalse(pending.exists())
        self.assertFalse(self.transport.active)
        self.assertTrue(self.transport.publish_queue.empty())

    def test_malformed_structures_and_conflicting_identity_are_quarantined(self):
        invalid = [None, [], "text", {}, {"comment_id": 71},
                   {**self.result_item(), "comment_id": 72},
                   {**self.result_item(), "comment_id": True},
                   {**self.result_item(), "node_id": "unowned-node"},
                   {**self.result_item(), "published": "false"},
                   {**self.result_item(), "body": "{"},
                   {**self.result_item(), "body": "[]"},
                   self.result_item(comment_id=72), self.result_item(schema="other"),
                   self.result_item(device="other-device"),
                   self.result_item(task={**self.task, "args": {"text": "changed"}}),
                   self.result_item(task={**self.task, "client_id": "other"}),
                   self.result_item(task={**self.task, "task_id": "other"}),
                   self.result_item(task={**self.task, "allow_foreground": True}),
                   self.result_item(task={**self.task, "execution_context": "background"}),
                   self.result_item(http_status="200"), self.result_item(outcome=[]),
                   self.result_item(route=None), self.result_item(result=None),
                   self.result_item(transport_version=True), self.result_item(inbox_issue="1"),
                   self.result_item(result=None, large_result={}),
                   self.result_item(http_status=503), self.result_item(result={"ok": False})]
        for value in invalid:
            with self.subTest(value=value):
                self.transport.active.clear()
                self.save(value)
                raw = self.saved.read_bytes()
                self.transport.submit(self.comment)
                item, result = self.queued_result()
                self.assertEqual(item["comment_id"], 71)
                self.assertEqual(item["node_id"], "owned-node")
                self.assertEqual(result["task"], self.task)
                self.assertEqual(result["result"]["error_code"], "TASK_OUTCOME_UNKNOWN")
                self.assert_evidence(raw)
        self.rpc.assert_not_called()
        self.transport.pool.submit.assert_not_called()

    def test_duplicate_json_fields_are_not_accepted_as_cached_evidence(self):
        raw = json.dumps(self.result_item()).replace('"published": false',
                                                   '"published": true, "published": false').encode()
        self.saved.write_bytes(raw)
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[1]["result"]["error_code"], "TASK_OUTCOME_UNKNOWN")
        self.assert_evidence(raw)

    def test_interrupted_temporary_result_is_reused_without_dispatch(self):
        item = self.result_item()
        self.saved.with_suffix(".tmp").write_text(json.dumps(item))
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[0], item)
        self.assertEqual(json.loads(self.saved.read_text()), item)
        self.assert_evidence(json.dumps(item).encode())
        self.transport.pool.submit.assert_not_called()

    def test_truncated_temporary_result_also_blocks_fresh_mutation(self):
        raw = b'{"comment'
        self.saved.with_suffix(".tmp").write_bytes(raw)
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[1]["result"]["error_code"], "TASK_OUTCOME_UNKNOWN")
        self.assert_evidence(raw)
        self.transport.pool.submit.assert_not_called()

    def test_interrupted_published_temp_is_promoted_and_only_cleans_state(self):
        item = self.result_item()
        item["published"] = True
        self.saved.with_suffix(".tmp").write_text(json.dumps(item))
        (self.transport.requests / "71.json").write_text(json.dumps(self.comment))
        self.transport.submit(self.comment)
        self.assertEqual(json.loads(self.saved.read_bytes()), item)
        self.assertFalse(self.saved.with_suffix(".tmp").exists())
        self.assertFalse((self.transport.requests / "71.json").exists())
        self.assertFalse(self.transport.active)
        self.assertTrue(self.transport.publish_queue.empty())
        self.transport.pool.submit.assert_not_called()

    def test_committed_result_wins_over_conflicting_temp_and_both_bytes_survive(self):
        item = self.result_item()
        self.save(item)
        raw = json.dumps(self.result_item(task={**self.task, "op": "other"})).encode()
        self.saved.with_suffix(".tmp").write_bytes(raw)
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[0], item)
        self.assert_evidence(raw)
        self.assertEqual(json.loads(self.saved.read_text()), item)

    def test_concurrent_submissions_reserve_once(self):
        self.saved.write_bytes(b"{")
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(lambda _: self.transport.submit(self.comment), range(128)))
        self.assertEqual(self.transport.active, {71})
        self.assertEqual(self.transport.publish_queue.qsize(), 1)
        self.transport.pool.submit.assert_not_called()
        self.rpc.assert_not_called()

    def test_concurrent_read_recovery_schedules_only_one_worker(self):
        self.task["op"] = "read_file"
        self.comment["body"] = json.dumps(self.task)
        self.saved.write_bytes(b"{")
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(lambda _: self.transport.submit(self.comment), range(128)))
        self.transport.pool.submit.assert_called_once()

    def test_failure_publication_retries_body_without_executing_task(self):
        self.saved.write_bytes(b"{")
        self.transport.submit(self.comment)
        original = self.saved.read_bytes()
        with patch.object(self.transport, "update_comment", side_effect=OSError("offline")):
            self.drain_publisher()
        self.assertEqual(self.transport.active, set())
        self.assertEqual(self.transport.counters["result_publish_failures"], 1)
        self.assertEqual(self.saved.read_bytes(), original)
        self.transport.submit(self.comment)
        with patch.object(self.transport, "update_comment") as update:
            self.drain_publisher()
            self.assertEqual(update.call_args.args, (71, json.loads(original)["body"]))
        self.assertTrue(json.loads(self.saved.read_bytes())["published"])
        self.transport.pool.submit.assert_not_called()
        self.rpc.assert_not_called()

    def test_cached_known_failure_remains_failed_without_fresh_execution(self):
        item = self.result_item(outcome="FAILED", http_status=503,
                                result={"ok": False, "error_code": "REQUEST_NOT_DELIVERED"})
        self.save(item)
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[0], item)
        self.transport.pool.submit.assert_not_called()

    def test_journal_states_never_authorize_reexecution_after_outbox_damage(self):
        for state in ("claimed", "dispatching", "processing", "uncertain", "retryable", "expired", "done"):
            with self.subTest(state=state):
                self.transport.active.clear()
                self.core.journal_begin(self.task)
                payload = {"ok": False, "error_code": "ORIGINAL_FAILURE"}
                self.core.journal_finish(self.task, 422, payload, state=state)
                self.saved.write_bytes(b"{")
                self.transport.submit(self.comment)
                _, result = self.queued_result()
                expected = ("ORIGINAL_FAILURE" if state == "done" else
                            "TASK_OUTCOME_EXPIRED" if state == "expired" else "TASK_OUTCOME_UNKNOWN")
                self.assertEqual(result["result"]["error_code"], expected)
                con = self.core._db()
                try:
                    self.assertEqual(con.execute("SELECT state FROM tasks").fetchone()[0], state)
                finally:
                    con.close()
        self.rpc.assert_not_called()
        self.transport.pool.submit.assert_not_called()

    def test_journal_conflict_does_not_return_other_task_response(self):
        self.core.execute_task({**self.task, "args": {"text": "previous payload"}})
        self.saved.write_bytes(b"{")
        self.transport.submit(self.comment)
        _, result = self.queued_result()
        self.assertEqual(result["result"]["error_code"], "TASK_ID_PAYLOAD_CONFLICT")
        self.rpc.assert_called_once()

    def test_journal_read_failure_keeps_evidence_and_allows_later_recovery(self):
        self.core.execute_task(self.task)
        raw = b"{"
        self.saved.write_bytes(raw)
        with patch.object(self.core, "_db", side_effect=OSError("journal unavailable")):
            with self.assertRaises(OSError):
                self.transport.submit(self.comment)
        self.assertFalse(self.transport.active)
        self.assertEqual(self.saved.read_bytes(), raw)
        self.assert_evidence(raw)
        self.transport.submit(self.comment)
        self.assertTrue(self.queued_result()[1]["route"]["deduplicated"])
        self.rpc.assert_called_once()

    def test_publication_disk_failure_keeps_original_until_successful_retry(self):
        raw = b"{"
        self.saved.write_bytes(raw)
        with patch.object(self.transport, "save_outbox", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.transport.submit(self.comment)
        self.assertFalse(self.transport.active)
        self.assertEqual(self.saved.read_bytes(), raw)
        self.assert_evidence(raw)
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[1]["result"]["error_code"], "TASK_OUTCOME_UNKNOWN")

    def test_quarantine_failure_leaves_source_and_does_not_dispatch(self):
        raw = b"{"
        self.saved.write_bytes(raw)
        with patch.object(self.daemon.os, "replace", side_effect=OSError("rename denied")):
            with self.assertRaises(OSError):
                self.transport.submit(self.comment)
        self.assertFalse(self.transport.active)
        self.assertEqual(self.saved.read_bytes(), raw)
        self.assertTrue(self.transport.publish_queue.empty())
        self.transport.pool.submit.assert_not_called()
        self.rpc.assert_not_called()

    def test_fresh_request_pool_failure_releases_active_and_retains_request(self):
        self.transport.pool.submit.side_effect = RuntimeError("pool closed")
        with self.assertRaises(RuntimeError):
            self.transport.submit(self.comment)
        self.assertFalse(self.transport.active)
        self.assertTrue((self.transport.requests / "71.json").exists())

    def test_request_write_failure_releases_active(self):
        with patch.object(self.daemon.os, "fsync", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.transport.submit(self.comment)
        self.assertFalse(self.transport.active)
        self.transport.pool.submit.assert_not_called()

    def test_cleanup_failure_releases_active(self):
        item = self.result_item()
        item["published"] = True
        self.save(item)
        with patch.object(Path, "unlink", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                self.transport.submit(self.comment)
        self.assertFalse(self.transport.active)

    def test_large_result_manifest_accepts_only_matching_compacted_task(self):
        large = {"encoding": "gzip+json", "branch": "results", "path": "result.json.gz",
                 "sha256": "a" * 64, "original_bytes": 90000, "stored_bytes": 800}
        compact = {k: v for k, v in self.task.items() if k != "args"}
        compact["args_sha256"] = hashlib.sha256(json.dumps(self.task["args"], sort_keys=True).encode()).hexdigest()
        item = self.result_item(task=compact, result=None, large_result=large)
        self.save(item)
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[0], item)
        self.transport.active.clear()
        compact["args_sha256"] = "b" * 64
        self.save(self.result_item(task=compact, result=None, large_result=large))
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[1]["result"]["error_code"], "TASK_OUTCOME_UNKNOWN")

    def test_boolean_numeric_argument_conflict_is_not_hidden_by_python_equality(self):
        self.task["args"] = {"value": 1}
        self.comment["body"] = json.dumps(self.task)
        self.save(self.result_item(task={**self.task, "args": {"value": True}}))
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[1]["result"]["error_code"], "TASK_OUTCOME_UNKNOWN")

    def test_queue_handoff_failure_releases_active_and_retains_durable_result(self):
        self.saved.write_bytes(b"{")
        with patch.object(self.transport.publish_queue, "put", side_effect=RuntimeError("queue unavailable")):
            with self.assertRaises(RuntimeError):
                self.transport.submit(self.comment)
        self.assertFalse(self.transport.active)
        self.assertTrue((self.transport.requests / "71.json").exists())
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[1]["result"]["error_code"], "TASK_OUTCOME_UNKNOWN")
        self.transport.pool.submit.assert_not_called()

    def test_read_recovery_worker_publication_failure_is_recoverable_from_pending_request(self):
        self.task["op"] = "read_file"
        self.comment["body"] = json.dumps(self.task)
        self.saved.write_bytes(b"{")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            self.transport.pool = pool
            with patch.object(self.transport, "save_outbox", side_effect=OSError("disk full")):
                self.transport.submit(self.comment)
                # Wait for the real worker to finish its failed publication.
                pool.submit(lambda: None).result()
        self.assertFalse(self.transport.active)
        self.assertEqual(self.saved.read_bytes(), b"{")
        self.assertTrue((self.transport.requests / "71.json").exists())
        self.transport.pool = Mock()
        # Bounded transport retry intentionally delays this previously failed
        # publication; force the documented local retry window to elapse.
        self.transport.retry_after[71] = 0
        self.transport.last_recover_at = -100
        self.transport.recover_requests()
        self.transport.pool.submit.assert_called_once()
        self.assertEqual(self.rpc.call_count, 1)

    def test_nested_duplicate_task_keys_are_rejected(self):
        item = self.result_item()
        item["body"] = item["body"].replace('"text": "once"', '"text": "other", "text": "once"')
        self.save(item)
        self.transport.submit(self.comment)
        self.assertEqual(self.queued_result()[1]["result"]["error_code"], "TASK_OUTCOME_UNKNOWN")

    def test_failed_journal_result_recovers_exact_failure_without_second_effect(self):
        self.rpc.return_value = 422, {"ok": False, "error_code": "ORIGINAL_VALIDATION_FAILURE"}
        self.core.execute_task(self.task)
        self.saved.write_bytes(b"{")
        self.transport.submit(self.comment)
        _, result = self.queued_result()
        self.assertEqual(result["outcome"], "FAILED")
        self.assertEqual(result["http_status"], 422)
        self.assertEqual(result["result"]["error_code"], "ORIGINAL_VALIDATION_FAILURE")
        self.rpc.assert_called_once()

    def test_non_object_journal_response_fails_closed(self):
        self.core.execute_task(self.task)
        con = self.core._db()
        try:
            con.execute("UPDATE tasks SET response='[]'")
        finally:
            con.close()
        self.saved.write_bytes(b"{")
        with self.assertRaises(self.core.TransportCoreError):
            self.transport.submit(self.comment)
        self.assertFalse(self.transport.active)
        self.assertEqual(self.saved.read_bytes(), b"{")
        self.rpc.assert_called_once()

    def test_malformed_journal_response_does_not_erase_evidence_or_dispatch(self):
        self.core.execute_task(self.task)
        con = self.core._db()
        try:
            con.execute("UPDATE tasks SET response='['")
        finally:
            con.close()
        self.saved.write_bytes(b"{")
        with self.assertRaises(ValueError):
            self.transport.submit(self.comment)
        self.assertFalse(self.transport.active)
        self.assertEqual(self.saved.read_bytes(), b"{")
        self.rpc.assert_called_once()

    def test_unauthorized_comment_cannot_consume_cached_result(self):
        self.save(self.result_item())
        self.comment["user"]["login"] = "not-an-allowed-sender"
        self.transport.submit(self.comment)
        self.assertFalse(self.transport.active)
        self.assertTrue(self.transport.publish_queue.empty())

    def test_loopback_rpc_mutation_happens_once_after_outbox_damage(self):
        effect = self.root / "loopback-effect.txt"
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(handler):
                request = json.loads(handler.rfile.read(int(handler.headers["Content-Length"])))
                received.append(request)
                with effect.open("a") as stream:
                    stream.write("effect\n")
                response = b'{"ok":true,"origin":"loopback"}'
                handler.send_response(200)
                handler.send_header("Content-Length", str(len(response)))
                handler.end_headers()
                handler.wfile.write(response)

            def log_message(handler, *args):
                pass

        secret = self.root / "fixture-secret"
        secret.write_text("isolated-test-only-" * 3, encoding="ascii")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with patch.object(self.core, "_rpc", self.real_rpc), \
                 patch.object(self.core, "SECRET", secret), \
                 patch.object(self.core, "V3_RPC_URL", f"http://127.0.0.1:{server.server_port}/rpc"), \
                 patch.object(self.core, "BACKGROUND_RPC_URL", ""):
                status, payload, _ = self.core.execute_task(self.task)
                self.assertEqual(status, 200)
                self.assertEqual(payload["origin"], "loopback")
                self.saved.write_bytes(b'{"truncated":')
                self.transport.submit(self.comment)
                self.transport.submit(self.comment)
                with patch.object(self.transport, "update_comment"):
                    self.drain_publisher()
                self.assertTrue(json.loads(self.saved.read_bytes())["published"])
        finally:
            server.shutdown()
            worker.join()
            server.server_close()
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["args"], self.task["args"])
        self.assertEqual(effect.read_text(), "effect\n")

    def test_stress_completed_mutations_concurrent_damage_publication_failure_and_restart(self):
        comments = []
        effects = []

        def effect(task, timeout):
            effects.append(task["task_id"])
            return 200, {"ok": True, "task": task["task_id"]}

        self.rpc.side_effect = effect
        for index in range(64):
            task = {**self.task, "task_id": f"stress-{index}", "args": {"index": index}}
            self.core.execute_task(task)
            cid = 1000 + index
            comment = {**self.comment, "id": cid, "node_id": f"node-{cid}", "body": json.dumps(task)}
            comments.append(comment)
            path = self.transport.outbox / f"{cid}.json"
            path.write_bytes((b"{", b"[]", b"\xff", b'{"published":true}')[index % 4])
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(self.transport.submit, comments * 4))
        self.assertEqual(self.transport.publish_queue.qsize(), 64)
        self.assertEqual(len(self.transport.active), 64)

        def publish(cid, body):
            result = json.loads(body)
            self.assertEqual(result["comment_id"], cid)
            self.assertEqual(result["result"]["task"], result["task"]["task_id"])
            if cid % 7 == 0:
                raise OSError("injected publication outage")

        with patch.object(self.transport, "update_comment", side_effect=publish):
            self.drain_publisher()
        failed = sum(c["id"] % 7 == 0 for c in comments)
        self.assertEqual(self.transport.counters["result_publish_failures"], failed)
        self.assertFalse(self.transport.active)
        self.assertEqual(len(list(self.transport.requests.glob("*.json"))), failed)
        with patch.object(self.daemon, "get_token", return_value="offline"), patch("threading.Thread.start"):
            restarted = self.daemon.CommentTransport()
        restarted.pool.shutdown(wait=True)
        restarted.pool = Mock()
        self.transport = restarted
        self.transport.recover_requests()
        self.assertEqual(self.transport.publish_queue.qsize(), failed)
        with patch.object(self.transport, "update_comment"):
            self.drain_publisher()
        self.assertFalse(self.transport.active)
        self.assertEqual(list(self.transport.requests.glob("*.json")), [])
        self.assertEqual(len(effects), 64)
        self.assertEqual(len(set(effects)), 64)
        self.transport.pool.submit.assert_not_called()
        for comment in comments:
            item = json.loads((self.transport.outbox / f'{comment["id"]}.json').read_bytes())
            self.assertTrue(item["published"])


if __name__ == "__main__":
    unittest.main()
