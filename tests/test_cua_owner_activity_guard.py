"""Regression tests for the owner-input guard.

No desktop, keyboard or mouse interaction; all clock and idle values are fake.
Run: python -m unittest test_cua_owner_activity_guard
"""
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime' / 'bridge-v3'))

from cua_owner_activity import OwnerActivityGuard, OwnerActive


class OwnerActivityGuardTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.idle = 3000
        self.guard = OwnerActivityGuard(
            idle_ms=lambda: self.idle,
            clock=lambda: self.now,
            quiet_ms=1500,
            margin_ms=400,
        )

    def test_idle_owner_before_first_agent_action(self):
        self.guard.check()

    def test_recent_owner_input_blocks_first_action(self):
        self.idle = 150
        with self.assertRaises(OwnerActive):
            self.guard.check()

    def test_agents_own_recent_input_is_not_owner_activity(self):
        self.guard.agent_input_done()
        self.now += 0.05
        self.idle = 10
        self.guard.check()

    def test_recent_owner_input_after_agent_blocks(self):
        self.guard.agent_input_done()
        self.now += 2.0
        self.idle = 100
        with self.assertRaises(OwnerActive):
            self.guard.check()

    def test_old_owner_activity_does_not_latch_forever(self):
        self.guard.agent_input_done()
        self.now += 10.0
        self.idle = 1800
        self.guard.check()

    def test_reset_reenables_first_action_quiet_period(self):
        self.guard.agent_input_done()
        self.guard.reset()
        self.idle = 50
        with self.assertRaises(OwnerActive):
            self.guard.check()

    def test_failed_idle_observation_does_not_block(self):
        self.guard._idle_ms = lambda: (_ for _ in ()).throw(OSError("no desktop"))
        self.guard.check()


if __name__ == "__main__":
    unittest.main()
