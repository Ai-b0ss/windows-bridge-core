"""Deterministic guardrails for independent cold-rollout rollback watchdog."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import cua_cold_recovery_watchdog as watch


class RecoveryWatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ff-watchdog-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.data = {
            "schema": watch.SCHEMA,
            "authorized_cold_rollout": True,
            "deadline_epoch": time.time() + 20,
            "port": 39073,
            "peer_port": 39076,
            "runtime": str(self.root / "runtime"),
            "snapshot": str(self.root / "backup"),
            "candidate_agent_sha256": "a" * 64,
            "old_agent_sha256": "b" * 64,
            "candidate_head": "c" * 40,
            "source_head": "d" * 40,
            "keeper_task": "FF-Bridge-V3-Keeper",
            "candidate_pid": 12345, "candidate_token": 998877,
            "keeper_pid": 22345, "keeper_token": 887766,
        }
        (self.root / "runtime").mkdir()
        (self.root / "backup").mkdir()

    def test_ready_requires_three_confirmations_no_rollback(self):
        state = dict(self.data, deadline_epoch=100)
        with (mock.patch.object(watch, "_state", return_value=state),
              mock.patch.object(watch, "_write_receipt") as receipt):
            recover = mock.Mock()
            output = watch.run(self.root / "arm.json", clock=lambda: 0,
                               sleep=lambda _: None, ready=lambda _: True, recover=recover)
            self.assertEqual(output["status"], "candidate_ready")
            recover.assert_not_called()
            receipt.assert_called_once()

    def test_deadline_triggers_verified_recovery(self):
        state = dict(self.data, deadline_epoch=2)
        counter = iter((0, 1, 2, 3))
        recover = mock.Mock(return_value={"rollback": "restored", "files": 109})
        with (mock.patch.object(watch, "_state", return_value=state),
              mock.patch.object(watch, "_write_receipt") as receipt):
            result = watch.run(self.root / "arm.json", clock=lambda: next(counter),
                               sleep=lambda _: None, ready=lambda _: False, recover=recover)
            self.assertTrue(result["ok"])
            self.assertEqual(result["status"], "rollback_performed")
            recover.assert_called_once_with(state)
            receipt.assert_called_once()

    def test_unsafe_foreign_agent_blocks_before_termination(self):
        with (mock.patch.object(watch, "probe_agent",
                                return_value={"pid": 777, "agent_sha256": "b" * 64}),
              mock.patch.object(watch, "_safe_terminate_known") as terminate,
              mock.patch.object(watch.bundle, "restore") as restore):
            with self.assertRaisesRegex(RuntimeError, "WATCH_UNKNOWN_AGENT_OWNS_PORT"):
                watch.recover_failed_rollout(self.data)
            terminate.assert_not_called()
            restore.assert_not_called()

    def test_recovery_passes_port_scope_to_both_independent_checks(self):
        with (mock.patch.object(watch, "probe_agent", return_value=None),
              mock.patch.object(watch.bundle, "assert_runtime_quiescent",
                                return_value={"peer_pids": [18096], "target_port": 39073}) as guard):
            restore = mock.Mock(return_value={"ok": True, "restored_files": 109})
            restart = mock.Mock()
            result = watch.recover_failed_rollout(self.data, terminate=mock.Mock(),
                                                   restore=restore, restart=restart)
            self.assertEqual(result["rollback"], "restored")
            self.assertEqual(guard.call_args.kwargs,
                             {"target_port": 39073, "peer_port": 39076})
            self.assertEqual(restore.call_args.kwargs,
                             {"offline_confirmed": True, "target_port": 39073,
                              "peer_port": 39076})
            restart.assert_called_once()

    def test_shared_runtime_blocks_restore_even_after_termination(self):
        with (mock.patch.object(watch, "probe_agent", return_value=None),
              mock.patch.object(watch.bundle, "assert_runtime_quiescent",
                                side_effect=RuntimeError("RESTORE_RUNTIME_STILL_RUNNING")),
              mock.patch.object(watch.bundle, "restore") as restore):
            terminate = mock.Mock()
            with self.assertRaisesRegex(RuntimeError, "RESTORE_RUNTIME_STILL_RUNNING"):
                watch.recover_failed_rollout(self.data, terminate=terminate)
            self.assertEqual(terminate.call_count, 2)
            restore.assert_not_called()

    def test_unknown_pid_is_not_terminated(self):
        with mock.patch.object(watch.identity, "process_identity_matches", return_value=False):
            with mock.patch.object(watch.identity, "ProcessReference") as ref:
                self.assertFalse(watch._safe_terminate_known(self.data, "candidate"))
                ref.assert_not_called()

    def test_known_pid_but_foreign_executable_refused(self):
        with (mock.patch.object(watch.identity, "process_identity_matches", return_value=True),
              mock.patch.object(watch, "_known_process_commandline", return_value=False),
              mock.patch.object(watch.identity, "ProcessReference") as ref):
            with self.assertRaisesRegex(RuntimeError, "WATCH_PROCESS_PATH_NOT_OWNED"):
                watch._safe_terminate_known(self.data, "candidate")
            ref.assert_not_called()

    def test_invalid_or_unarmed_state_rejected(self):
        p = self.root / "watch.json"
        p.write_text(json.dumps(self.data), encoding="utf-8")
        with mock.patch.object(watch.bundle, "verify_bundle", return_value={
            "candidate_head": "c" * 40,
            "source_head": "d" * 40,
            "source_files": [{"target": "ff_win_v3_agent.py", "sha256": "b" * 64}],
            "candidate_files": [{"target": "ff_win_v3_agent.py", "sha256": "a" * 64}],
        }):
            self.assertEqual(watch._state(p)["port"], 39073)
            d = dict(self.data, authorized_cold_rollout=False)
            p.write_text(json.dumps(d), encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "WATCH_NOT_AUTHORIZED"):
                watch._state(p)

    def test_watchdog_reports_rollback_blocker_not_success(self):
        state = dict(self.data, deadline_epoch=0)
        with (mock.patch.object(watch, "_state", return_value=state),
              mock.patch.object(watch, "_write_receipt") as receipt):
            result = watch.run(self.root / "arm.json", clock=lambda: 1,
                               ready=lambda _: False,
                               recover=lambda _: (_ for _ in ()).throw(RuntimeError("unsafe")))
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], "rollback_blocked")
            receipt.assert_called_once()


    def test_optional_keeper_launcher_terminated_before_keeper_and_candidate(self):
        data = dict(self.data, keeper_launcher_pid=12128, keeper_launcher_token=776655)
        calls = []
        def fake_term(st, role):
            calls.append(role)
            return True
        restore_mock = mock.Mock(return_value={"ok": True, "restored_files": 109})
        restart_mock = mock.Mock()
        with (mock.patch.object(watch, "probe_agent", return_value=None),
              mock.patch.object(watch.bundle, "assert_runtime_quiescent",
                                return_value={"peer_pids": [18096], "target_port": 39073})):
            watch.recover_failed_rollout(data, terminate=fake_term,
                                         restore=restore_mock, restart=restart_mock)
        self.assertEqual(calls, ["keeper_launcher", "candidate", "keeper"])


if __name__ == "__main__":
    unittest.main()
