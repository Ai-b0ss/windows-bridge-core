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
            encoding="utf-8",
            errors="replace",
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

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell non-UTF8 stderr resilience")
    def test_powershell_non_utf8_stderr_does_not_crash_decoder(self):
        # Regression: localized Windows PowerShell stderr bytes (e.g. CP866 0xa7) must
        # never crash subprocess reader threads with UnicodeDecodeError and hide stderr.
        cp = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::OpenStandardError().Write([byte[]]@(0xa7, 0x20, 0x4f, 0x4b, 0x0a), 0, 5); exit 7",
            ],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        self.assertEqual(cp.returncode, 7)
        self.assertIsNotNone(cp.stderr)
        self.assertIn("OK", cp.stderr)


if __name__ == "__main__":
    unittest.main()
