"""Sol P1 #1 regression tests: unified .cua-cold-maintenance.lock + 300s TTL across inner & outer keepers."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
INNER_KEEPER = REPO_ROOT / "runtime" / "bridge-v3" / "ff_win_v3_keeper.ps1"
OUTER_LAUNCHER = REPO_ROOT / "tools" / "host-wrappers" / "bridge-v3-keeper-launch.ps1"


class TestKeeperMaintenanceLock(unittest.TestCase):
    def _pwsh(self) -> str:
        exe = shutil.which("powershell.exe") or shutil.which("pwsh")
        if not exe:
            self.skipTest("PowerShell runtime not available")
        return exe

    def test_inner_and_outer_keeper_enforce_active_lock_and_expire_stale_lock(self) -> None:
        ps = self._pwsh()
        with tempfile.TemporaryDirectory(prefix="ff-keeper-maint-lock-") as td:
            base = Path(td)
            local_app = base / "LocalAppData"
            prog_data = base / "ProgramData"
            bridge_dir = local_app / "FF-Windows-Bridge" / "bridge-v3"
            bridge_dir.mkdir(parents=True)
            (prog_data / "FF-Windows-Bridge").mkdir(parents=True)
            lock_file = bridge_dir / ".cua-cold-maintenance.lock"

            env = dict(os.environ)
            env["LOCALAPPDATA"] = str(local_app)
            env["ProgramData"] = str(prog_data)

            probe_cmd = (
                f". {str(INNER_KEEPER)!r} -LoadFunctionsOnly; "
                "function Get-FF3AgentProcesses { return @() }; "
                "$innerLock = Test-FF3ColdMaintenanceLockActive; "
                "$innerStart = Test-FF3AgentStartAllowed; "
                f". {str(OUTER_LAUNCHER)!r} -LoadFunctionsOnly; "
                "$outerLock = Test-FF3ColdMaintenanceLockActive; "
                "$outerStart = Test-KeeperLauncherStartAllowed; "
                "@{ "
                "  maintenance_lock_exists = [bool](Test-Path -LiteralPath $maintLock -PathType Leaf); "
                "  inner_lock_active = [bool]$innerLock; "
                "  inner_start_allowed = [bool]$innerStart; "
                "  outer_lock_active = [bool]$outerLock; "
                "  outer_start_allowed = [bool]$outerStart "
                "} | ConvertTo-Json -Compress"
            )

            # Case 1: No lock file -> start allowed in both layers
            r0 = json.loads(subprocess.check_output([ps, "-NoLogo", "-NoProfile", "-Command", probe_cmd], env=env, text=True))
            self.assertFalse(r0["maintenance_lock_exists"])
            self.assertTrue(r0["inner_start_allowed"])
            self.assertTrue(r0["outer_start_allowed"])

            # Case 2: Active lock file (TTL 180s in future) -> BOTH inner and outer block start!
            now = int(time.time())
            lock_file.write_text(json.dumps({
                "schema": "ff-cold-maintenance-lock/v1",
                "created_epoch": now,
                "expires_epoch": now + 180,
                "ttl_seconds": 180,
            }), encoding="utf-8")
            r1 = json.loads(subprocess.check_output([ps, "-NoLogo", "-NoProfile", "-Command", probe_cmd], env=env, text=True))
            self.assertTrue(r1["maintenance_lock_exists"])
            self.assertTrue(r1["inner_lock_active"])
            self.assertFalse(r1["inner_start_allowed"], "Inner keeper must block start when .cua-cold-maintenance.lock is active")
            self.assertTrue(r1["outer_lock_active"])
            self.assertFalse(r1["outer_start_allowed"], "Outer launcher must block start when .cua-cold-maintenance.lock is active")

            # Case 3: Expired JSON lock (expires_epoch in past) -> BOTH inner and outer expire it and allow start!
            lock_file.write_text(json.dumps({
                "schema": "ff-cold-maintenance-lock/v1",
                "created_epoch": now - 400,
                "expires_epoch": now - 100,
                "ttl_seconds": 300,
            }), encoding="utf-8")
            r2 = json.loads(subprocess.check_output([ps, "-NoLogo", "-NoProfile", "-Command", probe_cmd], env=env, text=True))
            self.assertTrue(r2["maintenance_lock_exists"])
            self.assertFalse(r2["inner_lock_active"])
            self.assertTrue(r2["inner_start_allowed"], "Expired maintenance lock must not permanently block inner keeper")
            self.assertFalse(r2["outer_lock_active"])
            self.assertTrue(r2["outer_start_allowed"], "Expired maintenance lock must not permanently block outer launcher")

            # Case 4: Unparseable/stale raw lock file older than 300s mtime -> BOTH allow start!
            lock_file.write_text("raw-orphaned-lock", encoding="utf-8")
            stale_ts = time.time() - 360
            os.utime(lock_file, (stale_ts, stale_ts))
            r3 = json.loads(subprocess.check_output([ps, "-NoLogo", "-NoProfile", "-Command", probe_cmd], env=env, text=True))
            self.assertFalse(r3["inner_lock_active"])
            self.assertTrue(r3["inner_start_allowed"])
            self.assertFalse(r3["outer_lock_active"])
            self.assertTrue(r3["outer_start_allowed"])


if __name__ == "__main__":
    unittest.main()
