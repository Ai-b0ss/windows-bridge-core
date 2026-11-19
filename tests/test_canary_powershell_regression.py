"""Runs the PowerShell canary cutover/rollback regression script under unittest."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PS_TEST = ROOT / "tests" / "test_canary_powershell.ps1"


class TestCanaryPowerShellRegression(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows PowerShell regression suite")
    def test_powershell_canary_cutover_and_rollback_regressions(self):
        cp = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(PS_TEST),
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        self.assertEqual(
            cp.returncode,
            0,
            msg=f"PowerShell test failed ({cp.returncode}):\nSTDOUT:\n{cp.stdout}\nSTDERR:\n{cp.stderr}",
        )
        data = json.loads(cp.stdout)
        self.assertTrue(data.get("ok"))
        self.assertGreaterEqual(data.get("tests_passed", 0), 9)


if __name__ == "__main__":
    unittest.main()
