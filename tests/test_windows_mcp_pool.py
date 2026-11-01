from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
import cua_windows_mcp as mod

FAKE='''
import json, os, sys, time
for raw in sys.stdin.buffer:
    req = json.loads(raw)
    if req["tool"] == "hang":
        time.sleep(30)
    if req["tool"] == "crash":
        os._exit(3)
    print(json.dumps({"id": req["id"], "ok": True, "pid": os.getpid()}), flush=True)
'''


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.script=Path(self.tmp.name)/"fake_worker.py"
        self.script.write_text(FAKE,encoding="utf-8")
        self.spawned=0
        def spawn():
            self.spawned+=1
            return subprocess.Popen([sys.executable,str(self.script)],stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        self.pool=mod.WorkerPool(spawn,idle_seconds=60)

    def tearDown(self):
        self.pool.stop()
        self.tmp.cleanup()

    def test_one_worker_serves_many_calls(self):
        a=self.pool.call({"tool":"Snapshot","arguments":{}})
        b=self.pool.call({"tool":"Snapshot","arguments":{}})
        self.assertEqual(a["pid"],b["pid"])
        self.assertFalse(a["worker_reused"]); self.assertTrue(b["worker_reused"])
        self.assertEqual(self.spawned,1)

    def test_timeout_kills_worker_and_reports_unknown_outcome(self):
        self.pool.call({"tool":"Snapshot","arguments":{}})
        with self.assertRaisesRegex(RuntimeError,mod.OUTCOME_UNKNOWN):
            self.pool.call({"tool":"hang","arguments":{}},timeout=1)
        again=self.pool.call({"tool":"Snapshot","arguments":{}})
        self.assertFalse(again["worker_reused"])   # a fresh worker, not the stuck one
        self.assertEqual(self.spawned,2)

    def test_crash_is_reported_then_recovers(self):
        self.pool.call({"tool":"Snapshot","arguments":{}})
        with self.assertRaisesRegex(RuntimeError,mod.OUTCOME_UNKNOWN):
            self.pool.call({"tool":"crash","arguments":{}})
        self.assertTrue(self.pool.call({"tool":"Snapshot","arguments":{}})["ok"])

    def test_idle_worker_is_stopped(self):
        pool=mod.WorkerPool(lambda: subprocess.Popen([sys.executable,str(self.script)],
                            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL),
                            idle_seconds=1)
        try:
            first=pool.call({"tool":"Snapshot","arguments":{}})
            time.sleep(6)  # idle timer is 1 s; CI runners can be slow to fire it
            second=pool.call({"tool":"Snapshot","arguments":{}})
            self.assertNotEqual(first["pid"],second["pid"])
        finally:
            pool.stop()

    def test_validation_happens_before_any_worker_starts(self):
        with self.assertRaisesRegex(ValueError,"WINDOWS_MCP_TOOL_NOT_ALLOWED"):
            mod.invoke_windows_mcp("Shell",{},allow_physical=True)
        with self.assertRaisesRegex(ValueError,"MUTATION_ROUTE"):
            mod.invoke_windows_mcp("FileSystem",{"mode":"write"})


if __name__=="__main__":
    unittest.main()
