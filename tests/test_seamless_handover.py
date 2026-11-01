import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "nt", "needs Windows loopback sockets and PowerShell")
class SeamlessHandoverTests(unittest.TestCase):
    def test_handover_loses_no_request_and_keeps_the_session(self):
        done = subprocess.run([sys.executable, str(ROOT / "tests/integration/seamless_handover.py")],
                              capture_output=True, text=True, timeout=170, cwd=str(ROOT))
        self.assertEqual(done.returncode, 0, done.stdout[-800:] + done.stderr[-800:])
        self.assertIn('"all_passed": true', done.stdout)


if __name__ == "__main__":
    unittest.main()
