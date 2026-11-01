from pathlib import Path
import json
import random
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime/bridge-v3"))
from cua_chat_permission import ChatPermissionPolicy
from cua_resource_leases import ResourceLeases, LeaseError, INPUT, window_resource
from cua_task_authority import AuthorityStore, AuthorityError, DesktopModes


class Clock:
    def __init__(self, now=1_800_000_000): self.now = now
    def __call__(self): return self.now


class World:
    """Fake desktop: hwnd -> live fingerprint."""
    def __init__(self):
        self.windows = {}
    def add(self, hwnd, pid, start="1000"):
        self.windows[hwnd] = {"hwnd": hwnd, "pid": pid, "process_start_ns": start}
    def fingerprint(self, hwnd):
        return dict(self.windows[hwnd])


def ask(agent, task, *hwnds, seconds=600):
    return {"mode": "dedicated", "agent_id": agent, "task_id": task, "targets": [{"hwnd": h} for h in hwnds],
            "owner_chat_permission": {"quote": "да", "duration_seconds": seconds}}


def act(agent, task, generation):
    return {"agent_id": agent, "task_id": task, "mode_generation": generation}


class GrantTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.world = World()
        for hwnd, pid in ((100, 1), (200, 2), (300, 3)):
            self.world.add(hwnd, pid)
        config = self.root / "chat-permission.json"
        config.write_text(json.dumps({"schema": "ff-chat-permission-v1", "enabled": True}), encoding="utf-8")
        self.policy = ChatPermissionPolicy(config, self.root / "log")  # real clock: expiry is relative to now
        self.stopped = []
        self.modes = DesktopModes(self.root / "mode", AuthorityStore(self.root / "auth"), self.world.fingerprint,
                                  stop_input=lambda: self.stopped.append(1), chat_permission=self.policy)

    def tearDown(self):
        self.tmp.cleanup()

    def test_two_agents_hold_grants_for_different_windows_at_once(self):
        a = self.modes.transition(ask("chatgpt-linkedin", "t1", 100))
        b = self.modes.transition(ask("claude-agent", "t2", 200))  # used to be DESKTOP_MODE_BUSY
        self.assertEqual((a["mode"], b["mode"]), ("dedicated", "dedicated"))
        self.assertNotEqual(a["generation"], b["generation"])
        self.assertEqual(len(self.modes.status()["grants"]), 2)
        with self.modes.action(act("chatgpt-linkedin", "t1", a["generation"]), 100):
            pass
        with self.modes.action(act("claude-agent", "t2", b["generation"]), 200):
            pass

    def test_no_access_to_another_agents_window_or_generation(self):
        a = self.modes.transition(ask("a", "t1", 100))
        b = self.modes.transition(ask("b", "t2", 200))
        with self.assertRaisesRegex(AuthorityError, "DESKTOP_TARGET_OUTSIDE_SCOPE"):
            with self.modes.action(act("a", "t1", a["generation"]), 200):
                pass
        with self.assertRaisesRegex(AuthorityError, "DESKTOP_TARGET_OUTSIDE_SCOPE"):
            with self.modes.action(act("b", "t2", b["generation"]), 100):
                pass
        with self.assertRaisesRegex(AuthorityError, "DESKTOP_MODE_SCOPE_MISMATCH"):  # B's generation is not A's
            with self.modes.action(act("a", "t1", b["generation"]), 100):
                pass
        with self.assertRaisesRegex(AuthorityError, "INTERACTIVE_FOREGROUND_DISABLED"):  # no grant at all
            with self.modes.action(act("c", "t3", 1), 300):
                pass
        with self.assertRaisesRegex(AuthorityError, "DESKTOP_TARGET_OUTSIDE_SCOPE"):  # unknown window
            self.modes.check_scope(act("a", "t1", a["generation"]), 999)

    def test_stale_hwnd_pid_or_process_start_is_refused(self):
        a = self.modes.transition(ask("a", "t1", 100))
        self.world.windows[100]["process_start_ns"] = "2000"  # the hwnd now belongs to a newer process
        with self.assertRaisesRegex(AuthorityError, "DESKTOP_TARGET_OUTSIDE_SCOPE"):
            with self.modes.action(act("a", "t1", a["generation"]), 100):
                pass
        self.world.windows[100]["process_start_ns"] = "1000"
        self.world.windows[100]["pid"] = 77
        with self.assertRaisesRegex(AuthorityError, "DESKTOP_TARGET_OUTSIDE_SCOPE"):
            self.modes.check_scope(act("a", "t1", a["generation"]), 100)
        request = ask("b", "t2", 200)
        request["targets"] = [{"hwnd": 200, "pid": 999}]
        with self.assertRaisesRegex(AuthorityError, "DESKTOP_TARGET_CHANGED"):
            self.modes.transition(request)

    def test_release_is_own_only_and_requires_identity(self):
        a = self.modes.transition(ask("a", "t1", 100))
        b = self.modes.transition(ask("b", "t2", 200))
        with self.assertRaisesRegex(AuthorityError, "AUTHORITY_IDENTITY_INVALID"):
            self.modes.transition({"mode": "coexist"})  # nobody can drop everyone's grants
        released = self.modes.transition({"mode": "coexist", "agent_id": "a", "task_id": "t1"})
        self.assertEqual(released["mode"], "coexist")
        self.assertEqual(released["other_grants"], 1)
        with self.assertRaisesRegex(AuthorityError, "INTERACTIVE_FOREGROUND_DISABLED"):
            self.modes.check_scope(act("a", "t1", a["generation"]), 100)
        self.modes.check_scope(act("b", "t2", b["generation"]), 200)  # B untouched
        self.assertEqual(self.stopped, [])  # a release does not cancel other agents' input

    def test_owner_stop_revokes_every_grant_and_cancels_input(self):
        self.modes.transition(ask("a", "t1", 100))
        self.modes.transition(ask("b", "t2", 200))
        self.modes.revoke_all()
        self.assertEqual(self.modes.status()["mode"], "coexist")
        self.assertEqual(self.stopped, [1])

    def test_grants_expire_independently(self):
        a = self.modes.transition(ask("a", "t1", 100, seconds=60))
        b = self.modes.transition(ask("b", "t2", 200, seconds=3600))
        path = self.modes.path
        state = json.loads(path.read_text(encoding="utf-8"))
        for grant in state["grants"]:
            if grant["agent_id"] == "a":
                grant["expires"] = time.time() - 1
        path.write_text(json.dumps(state), encoding="utf-8")
        self.assertEqual([g["agent_id"] for g in self.modes.status()["grants"]], ["b"])
        with self.assertRaisesRegex(AuthorityError, "INTERACTIVE_FOREGROUND_DISABLED"):
            self.modes.check_scope(act("a", "t1", a["generation"]), 100)
        self.modes.check_scope(act("b", "t2", b["generation"]), 200)

    def test_regrant_replaces_own_generation_only(self):
        a1 = self.modes.transition(ask("a", "t1", 100))
        b = self.modes.transition(ask("b", "t2", 200))
        a2 = self.modes.transition(ask("a", "t1", 100, 300))
        self.assertGreater(a2["generation"], a1["generation"])
        with self.assertRaisesRegex(AuthorityError, "DESKTOP_MODE_SCOPE_MISMATCH"):
            self.modes.check_scope(act("a", "t1", a1["generation"]), 100)
        self.modes.check_scope(act("a", "t1", a2["generation"]), 300)
        self.modes.check_scope(act("b", "t2", b["generation"]), 200)
        self.assertEqual(len(self.modes.status()["grants"]), 2)

    def test_two_agents_may_each_be_granted_the_same_window(self):
        a = self.modes.transition(ask("a", "t1", 100))
        b = self.modes.transition(ask("b", "t2", 100))
        self.modes.check_scope(act("a", "t1", a["generation"]), 100)
        self.modes.check_scope(act("b", "t2", b["generation"]), 100)

    def test_an_action_does_not_hold_the_global_state_lock(self):
        a = self.modes.transition(ask("a", "t1", 100))
        done = {}
        with self.modes.action(act("a", "t1", a["generation"]), 100):
            def other():
                done["b"] = self.modes.transition(ask("b", "t2", 200))
            thread = threading.Thread(target=other)
            thread.start()
            thread.join(5)
            self.assertFalse(thread.is_alive(), "another agent's grant was blocked by a running action")
        self.assertEqual(done["b"]["mode"], "dedicated")

    def test_revoked_during_action_is_reported(self):
        a = self.modes.transition(ask("a", "t1", 100))
        with self.assertRaisesRegex(AuthorityError, "DESKTOP_MODE_EXPIRED"):
            with self.modes.action(act("a", "t1", a["generation"]), 100):
                self.modes.revoke_all()

    def test_limit_status_and_old_single_grant_file(self):
        for index in range(16):
            self.world.add(1000 + index, 50 + index)
            self.modes.transition(ask("agent%d" % index, "t", 1000 + index))
        with self.assertRaisesRegex(AuthorityError, "DESKTOP_GRANT_LIMIT"):
            self.modes.transition(ask("one-too-many", "t", 100))
        legacy = DesktopModes(self.root / "old", AuthorityStore(self.root / "auth2"), self.world.fingerprint)
        legacy.root.mkdir()
        legacy.path.write_text(json.dumps({"mode": "dedicated", "agent_id": "x", "task_id": "y", "generation": 5,
                                           "targets": [self.world.fingerprint(100)], "expires": time.time() + 99}),
                               encoding="utf-8")
        self.assertEqual(legacy.status("x", "y")["your_grant"]["generation"], 5)
        legacy.check_scope(act("x", "y", 5), 100)
        self.assertEqual(self.modes.status("agent3", "t")["your_grant"]["agent_id"], "agent3")


class LeaseTests(unittest.TestCase):
    def test_input_is_exclusive_and_served_in_arrival_order(self):
        leases = ResourceLeases()
        order, hold = [], threading.Event()

        def worker(name, started):
            started.set()
            with leases.acquire((name, "t"), [INPUT], timeout=5):
                order.append(name)
                if name == "first":
                    hold.wait(5)

        events = [threading.Event() for _ in range(4)]
        threads = []
        for name, started in zip(["first", "second", "third", "fourth"], events):
            thread = threading.Thread(target=worker, args=(name, started))
            thread.start()
            started.wait(5)
            threads.append(thread)
            for _ in range(200):  # wait until the thread is queued before starting the next one
                if name == "first" or leases.snapshot()["waiting"].get(INPUT, []):
                    break
                time.sleep(0.005)
            time.sleep(0.05)
        self.assertEqual(order, ["first"])
        hold.set()
        for thread in threads:
            thread.join(5)
        self.assertEqual(order, ["first", "second", "third", "fourth"])

    def test_different_windows_do_not_wait_for_each_other(self):
        leases = ResourceLeases()
        inside, gate = [], threading.Barrier(2, timeout=5)

        def worker(name, hwnd):
            with leases.acquire((name, "t"), [window_resource(hwnd)], timeout=2):
                inside.append(name)
                gate.wait()  # both must be inside at the same moment

        threads = [threading.Thread(target=worker, args=("a", 1)), threading.Thread(target=worker, args=("b", 2))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(6)
        self.assertEqual(sorted(inside), ["a", "b"])

    def test_timeout_names_the_holder_and_is_retry_safe(self):
        leases = ResourceLeases()
        release = threading.Event()
        holding = threading.Event()

        def holder():
            with leases.acquire(("slow", "t"), [INPUT], timeout=1):
                holding.set()
                release.wait(5)

        thread = threading.Thread(target=holder)
        thread.start()
        holding.wait(5)
        started = time.monotonic()
        with self.assertRaises(LeaseError) as caught:
            with leases.acquire(("late", "t"), [INPUT], timeout=0.3):
                self.fail("must not run")
        self.assertLess(time.monotonic() - started, 2)
        self.assertEqual(caught.exception.code, "LEASE_TIMEOUT")
        self.assertTrue(caught.exception.details["retry_safe"])
        self.assertEqual(caught.exception.details["blocked_on"][INPUT]["holder_agent"], "slow")
        release.set()
        thread.join(5)
        with leases.acquire(("late", "t"), [INPUT], timeout=1):  # and the queue is clean afterwards
            pass
        self.assertEqual(leases.snapshot(), {"held": {}, "waiting": {}})

    def test_waiting_is_cancelled_when_the_grant_goes_away(self):
        leases = ResourceLeases()
        release, holding, revoked = threading.Event(), threading.Event(), threading.Event()

        def holder():
            with leases.acquire(("slow", "t"), [INPUT], timeout=1):
                holding.set()
                release.wait(5)

        thread = threading.Thread(target=holder)
        thread.start()
        holding.wait(5)
        timer = threading.Timer(0.2, revoked.set)
        timer.start()
        started = time.monotonic()
        with self.assertRaises(LeaseError) as caught:
            with leases.acquire(("waiter", "t"), [INPUT], timeout=10, still_valid=lambda: not revoked.is_set()):
                self.fail("must not run")
        self.assertEqual(caught.exception.code, "LEASE_CANCELLED")
        self.assertLess(time.monotonic() - started, 3)
        release.set()
        thread.join(5)

    def test_a_task_holding_a_lease_cannot_wait_on_another(self):
        leases = ResourceLeases()
        with leases.acquire(("a", "t"), [INPUT]):
            with self.assertRaises(LeaseError) as caught:
                with leases.acquire(("a", "t"), [window_resource(1)]):
                    pass
        self.assertEqual(caught.exception.code, "LEASE_REENTRANT")

    def test_exception_in_the_action_releases_the_lease(self):
        leases = ResourceLeases()
        with self.assertRaises(ZeroDivisionError):
            with leases.acquire(("a", "t"), [INPUT, window_resource(7)]):
                1 / 0
        with leases.acquire(("b", "t"), [INPUT, window_resource(7)], timeout=0.5):
            pass

    def test_many_agents_with_overlapping_resources_never_deadlock(self):
        leases = ResourceLeases(poll_seconds=0.005)
        rng = random.Random(7)
        resources = [INPUT] + [window_resource(i) for i in range(1, 5)]
        finished, errors = [], []

        def worker(index):
            picks = rng.sample(resources, rng.randint(1, 3))
            try:
                for _ in range(15):
                    with leases.acquire(("agent%d" % index, "t"), picks, timeout=20):
                        time.sleep(0.001)
                finished.append(index)
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(repr(exc))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(errors, [])
        self.assertEqual(len(finished), 12)
        self.assertEqual(leases.snapshot(), {"held": {}, "waiting": {}})

    def test_main_takes_the_lease_before_focusing_and_checks_scope_first(self):
        code = (ROOT / "runtime/bridge-v3/ff_win_v3_main.py").read_text(encoding="utf-8")
        block = code[code.index("def _windows_mcp_physical"):code.index("def _computer_use")]
        self.assertLess(block.index("_physical_lease"), block.index("_focus_window"))
        self.assertLess(block.index("check_scope"), block.index("_focus_window"))
        self.assertLess(block.index("_focus_window"), block.index("GetForegroundWindow"))
        self.assertIn("_DESKTOP_MODES.action(args, hwnd)", block)
        self.assertIn("revoke_all", code[code.index("def _owner_stop_check"):code.index("LEASE_WAIT_SECONDS")])


if __name__ == "__main__":
    unittest.main()
