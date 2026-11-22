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

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell ShadowFull UTF-8 and StopAfterVerify honesty")
    def test_powershell_shadow_full_utf8_and_stop_after_verify_honesty(self):
        import hashlib
        import socket
        from tempfile import TemporaryDirectory
        import zipfile

        cutover_ps1 = ROOT / "tools" / "canary_cutover_c1_c2.ps1"
        bridge_src = ROOT / "runtime" / "bridge-v3"

        def _free_ports(n: int) -> list[int]:
            socks = []
            ports = []
            try:
                for _ in range(n):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.bind(("127.0.0.1", 0))
                    socks.append(s)
                    ports.append(int(s.getsockname()[1]))
                return ports
            finally:
                for s in socks:
                    s.close()

        with TemporaryDirectory(prefix="ff-canary-ps-utf8-") as td:
            base = Path(td)
            files = {}
            for src in sorted(bridge_src.glob("*.py")):
                files[f"runtime/bridge-v3/{src.name}"] = src.read_bytes()
            files["tools/agent_entry.py"] = (ROOT / "tools" / "agent_entry.py").read_bytes()
            commit = "7" * 40
            manifest = {
                "schema": "ff-gh-release-v1",
                "source_commit": commit,
                "public_source_commit": commit,
                "source_bytes_verified_against_commit": True,
                "files": {k: hashlib.sha256(v).hexdigest() for k, v in sorted(files.items())},
            }
            c1_zip = base / "c1-utf8.zip"
            with zipfile.ZipFile(c1_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for k, v in sorted(files.items()):
                    zf.writestr(k, v)
                zf.writestr("release-manifest.json", json.dumps(manifest, sort_keys=True, indent=2).encode("utf-8"))
            c1_sha = hashlib.sha256(c1_zip.read_bytes()).hexdigest()
            rpc_port, hub_port = _free_ports(2)
            shadow_root = base / "тень-приёмка"

            cp = subprocess.run(
                [
                    "powershell.exe",
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(cutover_ps1),
                    "-Mode",
                    "ShadowFull",
                    "-SkipC2",
                    "-StopAfterVerify",
                    "-FullCoreZipPath",
                    str(c1_zip),
                    "-FullCoreSha256",
                    c1_sha,
                    "-C1ExpectedCommit",
                    commit,
                    "-ShadowRoot",
                    str(shadow_root),
                    "-C1RpcPort",
                    str(rpc_port),
                    "-C1HubPort",
                    str(hub_port),
                    "-HealthConsecutivePasses",
                    "1",
                    "-RequestKey",
                    "приёмка-shadowfull-utf8",
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
                msg=f"ShadowFull UTF-8 failed ({cp.returncode}):\nSTDOUT:\n{cp.stdout}\nSTDERR:\n{cp.stderr}",
            )
            data = json.loads(cp.stdout)
            self.assertTrue(data.get("ok"))
            self.assertEqual(data.get("mode"), "SHADOW_FULL")
            self.assertFalse(data.get("live_production_mutated"))
            self.assertEqual(data.get("stop_after_verify_exit_code"), 0)
            self.assertIn("тень-приёмка", data["stage"]["shadow_root"])


if __name__ == "__main__":
    unittest.main()
