"""Run Cloudflare FlightController + ContextShield Node test suite inside unittest discovery."""
from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FC_TEST = REPO_ROOT / "tools" / "cf-flight-controller" / "test-flight-controller.mjs"


class TestFlightControllerNodeSuite(unittest.TestCase):
    def test_flight_controller_mjs_suite(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("Node.js runtime not on PATH")
        done = subprocess.run(
            [node, "--test", str(FC_TEST)],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        self.assertEqual(done.returncode, 0, msg=(done.stderr or done.stdout)[-2000:])


if __name__ == "__main__":
    unittest.main()
