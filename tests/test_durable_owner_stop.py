"""Owner Stop regressions; all state and effects are disposable fixtures."""
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime/bridge-v3"))
from cua_chat_permission import ChatPermissionError, ChatPermissionPolicy
from cua_owner_notice import OwnerNotice
from cua_owner_stop import stop_requested
from cua_task_authority import (AuthorityError, AuthorityStore, DesktopModes,
                                DESKTOP_ACTION_CHECK, check_desktop_action,
                                guard_effect, invocation)


class FakeCore:
    class RPCError(RuntimeError):
        def __init__(self, code, details=None):
            super().__init__(code)
            self.details = details

    @staticmethod
    def code_blocked(language, code):
        return False


class DurableOwnerStopTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="durable-stop-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.config = self.root / "chat-permission.json"
        self.config.write_text(json.dumps({"schema": "ff-chat-permission-v1", "enabled": True}))
        self.state = self.root / "chat-permission"
        self.state.mkdir()
        self.stop = self.state / "stop.flag"
        self.policy = ChatPermissionPolicy(self.config, self.state)
        self.store = AuthorityStore(self.root / "authority", device_id="fixture-device")
        self.cancelled = []
        self.fingerprint = {"hwnd": 7, "pid": 9, "process_start_ns": "11"}
        self.modes = self.new_modes()

    def new_modes(self, chat=True):
        return DesktopModes(self.root / "desktop-mode", self.store,
                            lambda hwnd: dict(self.fingerprint),
                            lambda: self.cancelled.append(True),
                            chat_permission=self.policy if chat else None)

    def request(self, agent="agent", task="task"):
        return {"agent_id": agent, "task_id": task, "mode": "dedicated",
                "targets": [{"hwnd": 7}],
                "owner_chat_permission": {"quote": "synthetic yes"}}

    def local_grant(self, op, args, nonce="fixture-nonce"):
        # Trusted local fixture, NOT proof of a signed owner receipt.
        return self.store._record_approval({
            "agent": args["agent_id"], "task": args["task_id"],
            "device": self.store.device_id, "request": invocation(op, args),
            "nonce": nonce, "approval_reference": "local-test-fixture",
            "uses": 1, "expires": time.time() + 120,
        })

    def test_stop_cannot_be_cleared_by_new_quote(self):
        self.stop.write_text("owner stop")
        with self.assertRaisesRegex(ChatPermissionError, "OWNER_STOPPED"):
            self.policy.authorize({"agent_id": "agent", "task_id": "task",
                                   "owner_chat_permission": {"quote": "synthetic yes"}})
        self.assertEqual(self.stop.read_text(), "owner stop")

    def test_stop_covers_other_agents_tasks_and_policy_restart(self):
        self.stop.write_text("")  # even a partial/empty Stop write is binding
        for agent, task in (("agent", "task"), ("agent", "other"), ("other", "task")):
            with self.subTest(agent=agent, task=task):
                restarted = ChatPermissionPolicy(self.config, self.state)
                with self.assertRaisesRegex(ChatPermissionError, "OWNER_STOPPED"):
                    restarted.authorize(self.request(agent, task))
                with self.assertRaisesRegex(AuthorityError, "OWNER_STOPPED"):
                    self.new_modes().transition(self.request(agent, task))
        self.assertTrue(self.policy.status()["owner_stopped"])
        self.assertFalse(self.policy.status()["quote_verified_by_bridge"])

    def test_pre_stop_chat_and_action_remain_compatible(self):
        args = self.request()
        grant = self.modes.transition(args)
        args["mode_generation"] = grant["generation"]
        with self.modes.action(args, 7):
            check_desktop_action()
        self.assertTrue(self.modes.grant_active("agent", "task", grant["generation"]))

    def test_existing_grants_blocked_and_revocation_persisted_after_restart(self):
        first = self.modes.transition(self.request())
        self.modes.transition(self.request("other", "other-task"))
        self.stop.write_text("stop")
        restarted = self.new_modes()
        args = {**self.request(), "mode_generation": first["generation"]}
        effects = []
        with self.assertRaisesRegex(AuthorityError, "OWNER_STOPPED"):
            with restarted.action(args, 7):
                effects.append("input")
        self.assertEqual(effects, [])
        self.assertFalse(restarted.grant_active("agent", "task", first["generation"]))
        self.assertEqual(restarted.status()["grants"], [])
        self.assertEqual(json.loads(restarted.path.read_text())["grants"], [])
        self.assertTrue(self.cancelled)
        self.assertTrue(self.stop.exists())

    def test_signed_only_mode_and_preissued_authorization_cannot_bypass_stop(self):
        args = self.request()
        del args["owner_chat_permission"]
        args["authorization_id"] = self.local_grant("set_desktop_mode", args)
        self.stop.write_text("stop")
        with self.assertRaisesRegex(AuthorityError, "OWNER_STOPPED"):
            self.store.consume(args["authorization_id"], agent="agent", task="task",
                               request=invocation("set_desktop_mode", args))
        for modes in (self.modes, self.new_modes(chat=False)):
            with self.assertRaisesRegex(AuthorityError, "OWNER_STOPPED"):
                modes.transition(args)
        self.assertTrue(self.stop.exists())

    def test_trusted_local_maintenance_preserves_revocation_and_generation(self):
        args = self.request()
        first = self.modes.transition(args)
        exact = {k: v for k, v in args.items() if k != "owner_chat_permission"}
        old = self.local_grant("set_desktop_mode", exact)
        self.stop.write_text("stop")
        # Test-only model of OFFLINE trusted maintenance, not an RPC rearm API.
        # No enrolled signing key exists in this fixture; there are no unseen
        # signed receipts to rotate out. See the operator procedure for that case.
        self.modes.revoke_all()
        self.assertTrue(self.store.revoke(old))
        self.assertTrue(self.stop.exists())
        self.stop.unlink()  # explicit trusted local filesystem step, last
        with self.assertRaisesRegex(AuthorityError, "REVOKED"):
            self.store.consume(old, agent="agent", task="task",
                               request=invocation("set_desktop_mode", exact))
        restarted = self.new_modes()
        self.assertFalse(restarted.grant_active("agent", "task", first["generation"]))
        fresh = restarted.transition(self.request())
        self.assertGreater(fresh["generation"], first["generation"])

    def test_stop_racing_scope_resolution_denies_before_input(self):
        args = self.request()
        args["mode_generation"] = self.modes.transition(args)["generation"]
        def fingerprint(hwnd):
            self.stop.write_text("stop")
            return dict(self.fingerprint)
        with mock.patch.object(self.modes, "target_fingerprint", side_effect=fingerprint):
            with self.assertRaisesRegex(AuthorityError, "OWNER_STOPPED"):
                with self.modes.action(args, 7):
                    self.fail("input dispatched")

    def test_existing_grant_cannot_launch_after_stop(self):
        grant = self.modes.transition(self.request())
        args = {"agent_id": "agent", "task_id": "task", "mode_generation": grant["generation"],
                "command": "launch_app", "visible_launch_allowed": True}
        args["authorization_id"] = self.local_grant("computer_use", args)
        self.stop.write_text("stop")
        with self.assertRaisesRegex(AuthorityError, "OWNER_STOPPED"):
            with self.modes.launch_action(args):
                self.fail("launch dispatched")

    def test_stop_during_action_blocks_next_event_and_postcheck(self):
        args = self.request()
        args["mode_generation"] = self.modes.transition(args)["generation"]
        with self.assertRaisesRegex(AuthorityError, "OWNER_STOPPED"):
            with self.modes.action(args, 7):
                self.stop.write_text("stop")
                with self.assertRaisesRegex(AuthorityError, "OWNER_STOPPED"):
                    check_desktop_action()
        self.assertIsNone(DESKTOP_ACTION_CHECK.get())

    def test_stop_racing_chat_journal_and_grant_publication_fails_closed(self):
        append = self.policy._append
        def stop_after_append(*args, **kwargs):
            append(*args, **kwargs)
            self.stop.write_text("stop")
        with mock.patch.object(self.policy, "_append", side_effect=stop_after_append):
            with self.assertRaisesRegex(ChatPermissionError, "OWNER_STOPPED"):
                self.policy.authorize(self.request())
        # Separate fixture phase: emulate a trusted local reset of the marker.
        self.stop.unlink()
        write = self.modes._write
        def stop_after_write(state):
            write(state)
            self.stop.write_text("stop")
        with mock.patch.object(self.modes, "_write", side_effect=stop_after_write):
            with self.assertRaisesRegex(AuthorityError, "OWNER_STOPPED"):
                self.modes.transition(self.request())
        self.assertIsNone(self.modes.grant_for("agent", "task"))

    def test_effects_blocked_for_chat_signed_and_ordinary_requests(self):
        calls = []
        args = {"agent_id": "agent", "task_id": "task", "code": "fixture",
                "consequences": {"kind": "destructive", "purpose": "fixture",
                                 "targets": ["fixture"], "risk": "none"}}
        signed_args = {**args, "authorization_id": self.local_grant("run_code", args)}
        self.stop.write_text("stop")
        wrapped = guard_effect(FakeCore, self.store, "run_code", calls.append, chat_permission=self.policy)
        for request in (signed_args, {**args, "owner_chat_permission": {"quote": "synthetic yes"}},
                        {"code": "ordinary fixture"}):
            with self.assertRaisesRegex(FakeCore.RPCError, "OWNER_STOPPED") as cm:
                wrapped(request)
            self.assertFalse(cm.exception.details["execution_started"])
        self.assertEqual(calls, [])

    def test_stop_racing_authority_consumption_blocks_effect_dispatch(self):
        args = {"agent_id": "agent", "task_id": "task", "code": "fixture",
                "consequences": {"kind": "destructive", "purpose": "fixture",
                                 "targets": ["fixture"], "risk": "none"}}
        args["authorization_id"] = self.local_grant("run_code", args)
        consume = self.store.consume
        def stop_after_consume(*a, **kw):
            result = consume(*a, **kw)
            self.stop.write_text("stop")
            return result
        wrapped = guard_effect(FakeCore, self.store, "run_code", self.fail, chat_permission=self.policy)
        with mock.patch.object(self.store, "consume", side_effect=stop_after_consume):
            with self.assertRaisesRegex(FakeCore.RPCError, "OWNER_STOPPED"):
                wrapped(args)

    def test_guard_effect_without_store_uses_core_bridge_root_to_enforce_stop(self):
        from types import SimpleNamespace
        root = self.root / "standalone-bridge"
        marker = root / "state" / "chat-permission" / "stop.flag"
        marker.parent.mkdir(parents=True)
        marker.write_text("owner stop")
        core = SimpleNamespace(BRIDGE_ROOT=root, RPCError=FakeCore.RPCError)
        wrapped = guard_effect(core, None, "run_code", self.fail)
        with self.assertRaisesRegex(FakeCore.RPCError, "OWNER_STOPPED"):
            wrapped({"agent_id": "agent", "task_id": "task"})
        self.assertTrue(marker.is_file())

    def test_no_clear_stop_api_and_fake_rearm_fields_do_not_reset(self):
        self.assertFalse(hasattr(OwnerNotice(self.state), "clear_stop"))
        self.stop.write_text("stop")
        args = {**self.request(), "rearm": True, "owner_consented": True,
                "signed_approval": {"approved": True}, "reset_stop": "yes"}
        with self.assertRaisesRegex(AuthorityError, "OWNER_STOPPED"):
            self.modes.transition(args)
        self.assertEqual(self.stop.read_text(), "stop")

    def test_stop_check_fails_closed_on_unknown_state_and_non_file_marker(self):
        self.stop.mkdir()
        self.assertTrue(stop_requested(self.state))
        self.stop.rmdir()
        with mock.patch.object(Path, "lstat", side_effect=PermissionError("fixture")):
            self.assertTrue(stop_requested(self.state))
            with self.assertRaisesRegex(ChatPermissionError, "OWNER_STOPPED"):
                self.policy.authorize(self.request())

    def test_windows_mcp_checks_after_worker_start_before_any_dispatch(self):
        from cua_windows_mcp import WorkerPool
        proc = mock.Mock()
        proc.poll.return_value = None
        def start():
            self.stop.write_text("stop")
            pool._proc = proc
        pool = WorkerPool(lambda: proc)
        token = DESKTOP_ACTION_CHECK.set(self.modes._require_running)
        try:
            with mock.patch.object(pool, "_start", side_effect=start):
                with self.assertRaisesRegex(AuthorityError, "OWNER_STOPPED"):
                    pool.call({"physical": True})
            proc.stdin.write.assert_not_called()
        finally:
            DESKTOP_ACTION_CHECK.reset(token)


if __name__ == "__main__":
    unittest.main()
