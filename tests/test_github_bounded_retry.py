"""Isolated transport faults: no GitHub, installed runtime, or user effects."""
import concurrent.futures
import errno
import importlib
import json
import os
import queue
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime/github-transport"))
with tempfile.TemporaryDirectory() as _import_home:
    with patch.dict(os.environ, {"FF_GH_HOME": _import_home,
                                 "FF_BRIDGE_ROOT": _import_home}):
        daemon = importlib.import_module("ff_win_github_comment_daemon")


class AbortOldLoop(BaseException):
    """Let a red regression terminate the old infinite loop safely."""


class BoundedRetryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        # Patch only this daemon's clock, never the global time module used
        # by unrelated background threads in the full test suite.
        clock = SimpleNamespace(**{name: getattr(time, name) for name in
                                   ("sleep", "time", "time_ns", "monotonic", "perf_counter")})
        for name, value in (("GH_HOME", self.home), ("CONFIG", {}),
                            ("MAX_WORKERS", 8),
                            ("time", clock),
                            ("trace", lambda *a, **k: None),
                            ("get_token", lambda: "isolated-test-token")):
            p = patch.object(daemon, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.transport = self.new_transport()

    def dispatch(self, comment, transport=None):
        transport = transport or self.transport
        submit = transport.pool.submit
        futures = []

        def tracked(*args, **kwargs):
            future = submit(*args, **kwargs)
            futures.append(future)
            return future

        with patch.object(transport.pool, "submit", tracked):
            transport.submit(comment)
        for future in futures:
            future.result(timeout=5)
        return futures

    def state(self, cid=1):
        return json.loads((self.transport.retries / (str(cid) + ".json")).read_text(encoding="utf-8"))

    def force_due(self, cid=1):
        self.transport.retry_after[cid] = 0

    def finish_delivery(self, transport=None):
        transport = transport or self.transport
        delivered = []
        while not transport.publish_queue.empty():
            item = transport.publish_queue.get_nowait()
            delivered.append(item)
            transport.mark_published(item)
            transport.active.discard(item["comment_id"])
            transport.publish_queue.task_done()
        return delivered

    def new_transport(self):
        # Suppress only the infinite publisher. Tests drive durable publication
        # explicitly; workers below are real ThreadPoolExecutor threads.
        with patch.object(daemon.threading.Thread, "start"):
            transport = daemon.CommentTransport()
        self.addCleanup(transport.pool.shutdown, wait=True)
        return transport

    def comment(self, cid, op="write_file"):
        return {"id": cid, "node_id": "TEST_NODE_" + str(cid),
                "user": {"login": daemon.OWNER},
                "body": json.dumps({"schema": daemon.SCHEMA,
                                    "client_id": "isolated-test", "task_id": "task-" + str(cid),
                                    "target_device": daemon.DEVICE,
                                    "op": op, "args": {}})}

    def assert_fault_releases_workers(self, count, fault):
        release = threading.Event()
        healthy = threading.Event()
        entered = [threading.Event() for _ in range(count)]

        def execute(task):
            cid = int(task["task_id"].split("-")[-1])
            if cid <= count:
                entered[cid - 1].set()
                if fault == "exception":
                    raise ValueError("permanent invalid local configuration")
                return 503, {"ok": False, "error_code": "REQUEST_NOT_DELIVERED"}, {}
            healthy.set()
            return 200, {"ok": True}, {}

        def old_sleep(_seconds):
            release.wait(3)
            raise AbortOldLoop()

        with patch.object(daemon, "execute_task", execute), patch.object(daemon.time, "sleep", old_sleep):
            try:
                for cid in range(1, count + 1):
                    self.transport.submit(self.comment(cid))
                self.assertTrue(all(event.wait(2) for event in entered))
                self.transport.submit(self.comment(count + 1))
                self.assertTrue(healthy.wait(.5), "poisoned tasks retained every worker slot")
                release.set()
                self.transport.pool.shutdown(wait=True)
                self.assertTrue(all(cid not in self.transport.active for cid in range(1, count + 1)),
                                "failed attempt retained active ownership")
            finally:
                release.set()
                self.transport.pool.shutdown(wait=True)

    def test_permanent_exception_returns_without_worker_sleep(self):
        self.assert_fault_releases_workers(8, "exception")

    def test_eight_retryable_tasks_cannot_starve_ninth(self):
        self.assert_fault_releases_workers(8, "retryable")

    def test_one_poison_with_many_healthy_tasks_soak(self):
        attempts = []

        def execute(task):
            attempts.append(task["task_id"])
            if task["task_id"] == "task-1":
                raise ConnectionRefusedError(errno.ECONNREFUSED, "isolated refusal")
            return 200, {"ok": True}, {}

        with patch.object(daemon, "execute_task", execute):
            self.dispatch(self.comment(1))
            for wave in range(10):
                for cid in range(2 + wave * 20, 22 + wave * 20):
                    self.dispatch(self.comment(cid))
                self.finish_delivery()
                self.force_due()
                self.dispatch(self.comment(1))
        self.assertEqual(attempts.count("task-1"), self.transport.retry_attempts)
        self.assertEqual(len(attempts), 200 + self.transport.retry_attempts)
        self.assertEqual(self.state()["status"], "quarantined")
        self.assertEqual(self.transport.active, set())
        self.assertEqual(set(self.transport.retry_deadlines), {1})

    def test_attempt_budget_persists_across_restart_and_quarantine_is_visible(self):
        self.transport.retry_attempts = 3
        fault = (503, {"ok": False, "error_code": "REQUEST_NOT_DELIVERED"}, {"definitely_not_executed": True})
        with patch.object(daemon, "execute_task", return_value=fault) as execute:
            self.dispatch(self.comment(1))
            self.force_due()
            self.dispatch(self.comment(1))
            reboot = self.new_transport()
            reboot.retry_attempts = 3
            # Load persisted future retry, then make the scheduler due.
            self.assertEqual(self.dispatch(self.comment(1), reboot), [])
            reboot.retry_after[1] = 0
            self.dispatch(self.comment(1), reboot)
            for _ in range(10):
                reboot.retry_after[1] = 0
                self.assertEqual(self.dispatch(self.comment(1), reboot), [])
            self.assertEqual(execute.call_count, 3)
        self.assertEqual(self.state()["quarantine_reason"], "RETRY_BUDGET_EXHAUSTED")
        self.assertTrue((reboot.requests / "1.json").exists())
        with patch.object(daemon, "write_health") as health:
            reboot.health()
        self.assertEqual(health.call_args.args[0]["quarantined_requests"], 1)

    def test_monotonic_deadline_ignores_live_wall_clock_rollback(self):
        mono = [100.0]
        wall = [1000.0]
        with patch.object(daemon.time, "monotonic", side_effect=lambda: mono[0]), \
             patch.object(daemon.time, "time", side_effect=lambda: wall[0]), \
             patch.object(daemon, "execute_task", side_effect=TimeoutError) as execute:
            self.transport.retry_seconds = 2
            self.dispatch(self.comment(1))
            mono[0] += 3
            wall[0] -= 10000
            self.force_due()
            self.dispatch(self.comment(1))
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(self.state()["status"], "quarantined")

    def test_restart_downtime_consumes_remaining_deadline(self):
        with patch.object(daemon, "execute_task", side_effect=TimeoutError) as execute:
            self.dispatch(self.comment(1))
            state = self.state()
            state["saved_at"] -= self.transport.retry_seconds + 1
            state["next_retry_at"] = 0
            (self.transport.retries / "1.json").write_text(json.dumps(state), encoding="utf-8")
            reboot = self.new_transport()
            self.dispatch(self.comment(1), reboot)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(self.state()["status"], "quarantined")

    def test_bounded_exponential_jitter_and_poll_does_not_bypass_delay(self):
        self.transport.retry_attempts = 10
        self.transport.retry_cap = 3
        ceilings = []

        def jitter(low, high):
            ceilings.append(high)
            self.assertEqual(low, high / 2)
            return high

        with patch.object(daemon.random, "uniform", jitter), \
             patch.object(daemon, "execute_task", side_effect=TimeoutError) as execute:
            for attempt in range(5):
                self.force_due()
                self.dispatch(self.comment(1))
                self.assertEqual(self.dispatch(self.comment(1)), [])
                self.assertEqual(execute.call_count, attempt + 1)
        self.assertEqual(ceilings, [1, 2, 3, 3, 3])

    def test_local_config_only_and_bounded(self):
        with patch.object(daemon, "CONFIG", {"task_retry_attempts": 1000, "task_retry_seconds": 999999}):
            transport = self.new_transport()
        self.assertEqual(transport.retry_attempts, 32)
        self.assertEqual(transport.retry_seconds, 3600)
        comment = self.comment(1)
        task = json.loads(comment["body"])
        task.update(task_retry_attempts=999999, retry_seconds=999999)
        comment["body"] = json.dumps(task)
        with patch.object(daemon, "execute_task", side_effect=TimeoutError):
            self.dispatch(comment)
        self.assertLessEqual(self.state()["remaining_seconds"], 300)

    def test_classification_permanent_unknown_and_cached_responses(self):
        cases = [
            (400, "BAD_REQUEST", {}, "write_file"),
            (401, "UNAUTHORIZED", {}, "write_file"),
            (403, "DENIED", {}, "write_file"),
            (422, "VALIDATION", {}, "write_file"),
            (599, "TASK_OUTCOME_UNKNOWN", {"automatic_retry_blocked": True}, "write_file"),
            (409, "TASK_OUTCOME_UNKNOWN", {"route": "journal"}, "write_file"),
            (409, "TASK_ID_PAYLOAD_CONFLICT", {}, "write_file"),
            (503, "REQUEST_NOT_DELIVERED", {"route": "journal-cache"}, "write_file"),
            (503, "SERVER_ERROR", {}, "write_file"),
        ]
        for cid, (status, code, route, op) in enumerate(cases, 1):
            with self.subTest(code=code, route=route), patch.object(
                    daemon, "execute_task", return_value=(status, {"ok": False, "error_code": code}, route)) as execute:
                self.dispatch(self.comment(cid, op))
                self.finish_delivery()
                self.dispatch(self.comment(cid, op))
                self.assertEqual(execute.call_count, 1)
                self.assertFalse((self.transport.retries / (str(cid) + ".json")).exists())

    def test_known_retryable_responses(self):
        for cid, (status, code, op) in enumerate([
                (503, "REQUEST_NOT_DELIVERED", "write_file"),
                (409, "TASK_IN_PROGRESS", "write_file"),
                (503, "INTERACTIVE_SESSION_REQUIRED", "write_file"),
                (503, "SERVER_ERROR", "ping"),
                (429, "RATE_LIMIT", "ping")], 1):
            with patch.object(daemon, "execute_task", return_value=(status, {"error_code": code}, {})):
                self.dispatch(self.comment(cid, op))
            self.assertEqual(self.state(cid)["status"], "waiting")
            self.assertNotIn(cid, self.transport.active)
            self.assertTrue(self.transport.publish_queue.empty())

    def test_permanent_exception_quarantines_without_losing_original(self):
        comment = self.comment(1)
        with patch.object(daemon, "execute_task", side_effect=FileNotFoundError("private path")) as execute:
            self.dispatch(comment)
            self.force_due()
            self.dispatch(comment)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(self.state()["status"], "quarantined")
        self.assertNotIn("private path", json.dumps(self.state()))
        self.assertEqual(json.loads((self.transport.requests / "1.json").read_text()), comment)

    def test_exact_pending_identity_is_not_overwritten_by_comment_edit(self):
        original = self.comment(1)
        with patch.object(daemon, "execute_task", side_effect=TimeoutError) as execute:
            self.dispatch(original)
            edited = self.comment(1, "delete_file")
            # An edit is rejected even while the original is in backoff.
            self.dispatch(edited)
            self.force_due()
            self.dispatch(original)
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(self.state()["error_code"], "PENDING_REQUEST_IDENTITY_CONFLICT")
        self.assertEqual(json.loads((self.transport.requests / "1.json").read_text()), original)

    def test_legacy_pending_and_cached_outbox_do_not_allocate_retry_leaks(self):
        for cid in range(1, 101):
            comment = self.comment(cid)
            (self.transport.requests / (str(cid) + ".json")).write_text(json.dumps(comment))
            self.transport.save_outbox({"comment_id": cid, "body": "cached", "published": cid % 2 == 0})
        with patch.object(daemon, "execute_task") as execute:
            for _ in range(2):
                self.transport.last_recover_at = -100
                self.transport.recover_requests()
                self.finish_delivery()
        execute.assert_not_called()
        self.assertEqual(self.transport.active, set())
        self.assertEqual(self.transport.retry_after, {})
        self.assertEqual(self.transport.retry_deadlines, {})
        self.assertEqual(list(self.transport.retries.glob("*.json")), [])
        self.assertEqual(list(self.transport.requests.glob("*.json")), [])

    def test_corrupt_cached_outbox_releases_active_even_on_repeated_scan(self):
        # Corrupted outbox is recovered rather than raised since A4: no
        # unsafe task may be executed again just to recreate a missing result.
        (self.transport.outbox / "1.json").write_text("{broken")
        with patch.object(daemon, "execute_task") as execute:
            for _ in range(2):
                self.transport.submit(self.comment(1))
                self.finish_delivery()
                self.assertNotIn(1, self.transport.active)
            execute.assert_not_called()
        self.assertTrue(list((self.transport.outbox / "quarantine").glob("*.bin")))

    def test_journal_effect_once_after_publication_failure_restart_and_delivery(self):
        core = importlib.import_module("ff_win_transport_core")
        effects = []

        def rpc(task, timeout):
            effects.append(task["task_id"])
            return 200, {"ok": True, "value": "exact completed result"}

        with patch.object(core, "FAST_ROOT", self.home / "journal"), \
             patch.object(core, "DB", self.home / "journal/tasks.sqlite3"), \
             patch.object(core, "_rpc", rpc):
            with patch.object(self.transport, "publish_result", side_effect=ConnectionResetError):
                self.dispatch(self.comment(1))
            self.assertIn("completed_result", self.state())
            reboot = self.new_transport()
            reboot.load_retry(self.comment(1), daemon.parse_task(self.comment(1)))
            reboot.retry_after[1] = 0
            self.dispatch(self.comment(1), reboot)
            delivered = self.finish_delivery(reboot)
            self.assertEqual(len(delivered), 1)
            self.assertEqual(json.loads(delivered[0]["body"])["result"]["value"], "exact completed result")
            self.dispatch(self.comment(1), reboot)
            # Different comment with the same exact client/task identity also
            # hits the existing transport journal, never the mutating RPC.
            duplicate = self.comment(1)
            duplicate["id"] = 2
            self.dispatch(duplicate, reboot)
            self.finish_delivery(reboot)
        self.assertEqual(effects, ["task-1"])

    def test_ambiguous_mutation_result_does_not_dispatch_again(self):
        core = importlib.import_module("ff_win_transport_core")
        effects = []

        def rpc(task, timeout):
            effects.append("effect")
            raise core.RpcFailure("read", TimeoutError())

        with patch.object(core, "FAST_ROOT", self.home / "journal"), \
             patch.object(core, "DB", self.home / "journal/tasks.sqlite3"), \
             patch.object(core, "_rpc", rpc):
            self.dispatch(self.comment(1))
            delivered = self.finish_delivery()
            self.assertEqual(json.loads(delivered[0]["body"])["result"]["error_code"], "TASK_OUTCOME_UNKNOWN")
            reboot = self.new_transport()
            duplicate = self.comment(1)
            duplicate["id"] = 2
            self.dispatch(duplicate, reboot)
            self.finish_delivery(reboot)
        self.assertEqual(effects, ["effect"])

    def test_local_quarantine_release_can_resume_same_task_without_new_identity(self):
        with patch.object(daemon, "execute_task", side_effect=ValueError):
            self.dispatch(self.comment(1))
        # Documented trusted local repair preserves the record's identity and
        # any completed result; it resets only the local scheduling budget.
        state = self.state()
        state.update(status="waiting", attempts=0, remaining_seconds=300,
                     saved_at=time.time(), next_retry_at=0)
        for field in ("error_code", "quarantine_reason", "retryable"):
            state.pop(field, None)
        (self.transport.retries / "1.json").write_text(json.dumps(state), encoding="utf-8")
        reboot = self.new_transport()
        with patch.object(daemon, "execute_task", return_value=(200, {"ok": True}, {})) as execute:
            self.dispatch(self.comment(1), reboot)
        self.assertEqual(execute.call_args.args[0]["task_id"], "task-1")
        self.assertEqual(len(self.finish_delivery(reboot)), 1)

    def test_publication_quarantine_release_preserves_completed_result(self):
        self.transport.retry_attempts = 1
        with patch.object(daemon, "execute_task", return_value=(200, {"ok": True, "value": "original"}, {})) as execute:
            with patch.object(self.transport, "publish_result", side_effect=TimeoutError):
                self.dispatch(self.comment(1, "ping"))
            state = self.state()
            self.assertEqual(state["status"], "quarantined")
            state.update(status="waiting", attempts=0, remaining_seconds=300,
                         saved_at=time.time(), next_retry_at=0)
            (self.transport.retries / "1.json").write_text(json.dumps(state), encoding="utf-8")
            reboot = self.new_transport()
            self.dispatch(self.comment(1, "ping"), reboot)
            self.assertEqual(execute.call_count, 1)
        item = self.finish_delivery(reboot)[0]
        self.assertEqual(json.loads(item["body"])["result"]["value"], "original")

    def test_eight_real_journal_refusals_allow_ninth_mutation(self):
        core = importlib.import_module("ff_win_transport_core")
        healthy = threading.Event()
        effects = []

        def rpc(task, timeout):
            if task["task_id"] != "task-9":
                raise ConnectionRefusedError(errno.ECONNREFUSED, "isolated refusal")
            effects.append(task["task_id"])
            healthy.set()
            return 200, {"ok": True}, {}

        with patch.object(core, "FAST_ROOT", self.home / "journal"), \
             patch.object(core, "DB", self.home / "journal/tasks.sqlite3"), \
             patch.object(core, "_rpc", rpc):
            for cid in range(1, 10):
                self.transport.submit(self.comment(cid))
            self.assertTrue(healthy.wait(5), "eight real retryable journal claims starved ninth mutation")
            self.transport.pool.shutdown(wait=True)
        for cid in range(1, 9):
            self.assertEqual(self.state(cid)["status"], "waiting")
            self.assertEqual(self.state(cid)["attempts"], 1)
            self.assertNotIn(cid, self.transport.active)
        self.assertEqual(effects, ["task-9"])
        self.assertEqual(len(self.finish_delivery()), 1)

    def test_lost_publication_ack_is_idempotent_without_reexecuting_mutation(self):
        core = importlib.import_module("ff_win_transport_core")
        effects = []
        remote = {}
        with patch.object(core, "FAST_ROOT", self.home / "journal"), \
             patch.object(core, "DB", self.home / "journal/tasks.sqlite3"), \
             patch.object(core, "_rpc", side_effect=lambda *a: (effects.append(1) or (200, {"ok": True}))):
            self.dispatch(self.comment(1))
            item = self.transport.publish_queue.get_nowait()
            updates = []

            def update(cid, body):
                updates.append(body)
                remote[cid] = body  # server applied PATCH, first ACK is lost
                if len(updates) == 1:
                    raise ConnectionResetError()

            with patch.object(self.transport, "update_comment", side_effect=update), \
                 patch.object(self.transport.publish_queue, "get", side_effect=[item, queue.Empty, AbortOldLoop]):
                with self.assertRaises(AbortOldLoop):
                    self.transport.publisher_loop()
            self.assertEqual(len(updates), 2)
            self.assertEqual(updates[0], updates[1])
            reboot = self.new_transport()
            self.dispatch(self.comment(1), reboot)
        self.assertEqual(effects, [1])
        self.assertEqual(len(remote), 1)
        self.assertEqual(reboot.active, set())
        self.assertEqual(reboot.retry_deadlines, {})

    def test_publication_transient_http_retains_exact_checkpoint_for_retry(self):
        with patch.object(daemon, "execute_task", return_value=(200, {"ok": True}, {})) as execute:
            with patch.object(self.transport, "publish_result", side_effect=daemon.GitHubHTTPError(503, "unavailable")):
                self.dispatch(self.comment(1))
            self.assertEqual(self.state()["status"], "waiting")
            self.assertEqual(self.state()["error_code"], "GH_HTTP_503")
            self.force_due()
            self.dispatch(self.comment(1))
            self.assertEqual(execute.call_count, 1)
        self.assertEqual(len(self.finish_delivery()), 1)

    def test_archived_inbox_identity_survives_current_inbox_change(self):
        comment = self.comment(1)
        comment["issue_url"] = "https://api.github.com/repos/" + daemon.REPOSITORY + "/issues/12345"
        with patch.object(daemon, "execute_task", side_effect=TimeoutError):
            self.dispatch(comment)
        self.transport.inbox = 54321
        self.force_due()
        with patch.object(daemon, "execute_task", return_value=(200, {"ok": True}, {})):
            self.dispatch(comment)
        item = self.finish_delivery()[0]
        self.assertEqual(json.loads(item["body"])["inbox_issue"], 12345)

    def test_exception_classification_uses_typed_causes(self):
        core = importlib.import_module("ff_win_transport_core")
        task = {"op": "ping"}
        for exc, expected in [(TimeoutError(), True), (PermissionError(), False),
                              (FileNotFoundError(), False), (ValueError(), False),
                              (OSError(errno.ENOSPC, "disk full"), False),
                              (daemon.GitHubHTTPError(401, "auth"), False),
                              (daemon.GitHubHTTPError(503, "service"), True)]:
            with self.subTest(error=type(exc).__name__, expected=expected):
                self.assertEqual(self.transport.retryable_exception(exc, task), expected)
                wrapped = core.TransportCoreError("V3_UNAVAILABLE:first:second")
                wrapped.__cause__ = exc
                self.assertEqual(self.transport.retryable_exception(wrapped, task), expected)

    def test_unreadable_request_does_not_stop_recovery_of_later_tasks(self):
        (self.transport.requests / "0.json").write_text("{corrupt")
        (self.transport.requests / "1.json").write_text(json.dumps(self.comment(1)))
        with patch.object(daemon, "execute_task", return_value=(200, {"ok": True}, {})):
            self.transport.last_recover_at = -100
            self.transport.recover_requests()
            self.transport.pool.shutdown(wait=True)
        self.assertEqual(len(self.finish_delivery()), 1)
        self.assertTrue((self.transport.requests / "0.json").exists())


if __name__ == "__main__":
    unittest.main()
