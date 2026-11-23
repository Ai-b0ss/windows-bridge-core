import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

RUNTIME = Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"
if str(RUNTIME) not in sys.path:
    sys.path.insert(0, str(RUNTIME))

import ff_win_v3_agent as agent


@unittest.skipUnless(os.name == "nt", "Requires Windows Job Objects")
class TestAgentJobBreakaway(unittest.TestCase):
    def test_ordinary_child_dies_on_job_close_while_breakaway_grandchild_survives(self) -> None:
        job = agent.create_kill_on_close_job()
        self.assertIsNotNone(job)
        grandchild_pid = None
        normal_child = None
        launcher = None
        try:
            with tempfile.TemporaryDirectory() as td:
                pid_file = Path(td) / "breakaway.json"
                # 1. Ordinary child bound to the job (must be killed when job closes).
                normal_child = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                agent.assign_process_to_job(normal_child, job)

                # 2. Child inside the same job spawns a grandchild with CREATE_BREAKAWAY_FROM_JOB
                # (mirroring ff_hub.ensure_running / handover_upgrade invoked from run_code).
                spawn_script = (
                    "import json, pathlib, subprocess, sys; "
                    "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
                    "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, "
                    "creationflags=subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP | 0x01000000); "
                    "pathlib.Path(sys.argv[1]).write_text(json.dumps({'pid': p.pid}), encoding='utf-8')"
                )
                launcher = subprocess.Popen(
                    [sys.executable, "-c", spawn_script, str(pid_file)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                agent.assign_process_to_job(launcher, job)
                _out, err = launcher.communicate(timeout=15)
                self.assertEqual(launcher.returncode, 0, msg=err.decode("utf-8", errors="replace"))
                grandchild_pid = int(json.loads(pid_file.read_text(encoding="utf-8"))["pid"])
                self.assertTrue(agent.is_pid_alive(grandchild_pid))

                # Close the Bridge job (simulating drain linger expiry).
                agent.close_job_handle(job)
                job = None

                # Ordinary child must die promptly; breakaway grandchild must survive.
                deadline = time.monotonic() + 8.0
                while time.monotonic() < deadline and normal_child.poll() is None:
                    time.sleep(0.05)
                self.assertIsNotNone(normal_child.poll(), "ordinary child should die on job close")
                time.sleep(0.3)
                self.assertTrue(
                    agent.is_pid_alive(grandchild_pid),
                    "CREATE_BREAKAWAY_FROM_JOB infrastructure child must survive Bridge job close",
                )
        finally:
            if job is not None:
                agent.close_job_handle(job)
            if normal_child is not None and normal_child.poll() is None:
                normal_child.kill()
            if grandchild_pid is not None and agent.is_pid_alive(grandchild_pid):
                agent.terminate_pid(grandchild_pid)


if __name__ == "__main__":
    unittest.main()
