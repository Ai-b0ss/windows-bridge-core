import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

RUNTIME = Path(__file__).resolve().parents[1] / "runtime/bridge-v3"
sys.path.insert(0, str(RUNTIME))
import ff_win_owned_job as job
from ff_win_process_identity import ProcessReference, process_creation_token


class TestJobCreationContract(unittest.TestCase):
    def api(self):
        api = Mock()
        def initialize(attributes, count, flags, size):
            size._obj.value = 256
            return bool(attributes)
        api.InitializeProcThreadAttributeList.side_effect = initialize
        api.UpdateProcThreadAttribute.return_value = True
        api.CreateProcessW.return_value = True
        return api

    def test_job_and_only_three_stdio_handles_are_creation_attributes(self):
        api = self.api()
        job.launch_bound(api, 100, "python.exe", "python.exe", None, "test", [1, 2, 3])
        calls = api.UpdateProcThreadAttribute.call_args_list
        self.assertEqual([call.args[2] for call in calls], [0x20002, 0x2000D])
        self.assertEqual(list(calls[0].args[3]), [1, 2, 3])
        self.assertEqual(list(calls[1].args[3]), [100])
        args = api.CreateProcessW.call_args.args
        self.assertTrue(args[4])
        self.assertEqual(args[5], 0x8080604)  # extended/suspended/unicode/group/no-window
        self.assertFalse(args[5] & 0x1000000)  # no breakaway
        api.AssignProcessToJobObject.assert_not_called()
        api.DeleteProcThreadAttributeList.assert_called_once()

    def test_unsupported_job_attribute_prevents_process_creation(self):
        api = self.api()
        api.UpdateProcThreadAttribute.side_effect = [True, False]
        with patch.object(ctypes, "get_last_error", return_value=87, create=True):
            with self.assertRaisesRegex(OSError, "JOB_CREATION_BIND_FAILED"):
                job.launch_bound(api, 100, "python.exe", "python.exe", None, "test", [1, 2, 3])
        api.CreateProcessW.assert_not_called()
        api.DeleteProcThreadAttributeList.assert_called_once()

    def test_create_failure_destroys_attribute_list_without_fallback(self):
        api = self.api()
        api.CreateProcessW.return_value = False
        with patch.object(ctypes, "get_last_error", return_value=5, create=True):
            with self.assertRaisesRegex(OSError, "OWNED_JOB_CREATE_FAILED"):
                job.launch_bound(api, 100, "python.exe", "python.exe", None, "test", [1, 2, 3])
        self.assertEqual(api.CreateProcessW.call_count, 1)
        api.DeleteProcThreadAttributeList.assert_called_once()


@unittest.skipUnless(os.name == "nt", "Requires actual Windows Job Objects")
class TestActualWindowsOwnedJob(unittest.TestCase):
    def owned(self, code, cwd, *args, env=None):
        process = job.OwnedJobProcess([sys.executable, "-c", code, *args], cwd=str(cwd),
                                      env=env or dict(os.environ))
        self.addCleanup(process.close)
        return process

    def wait_file(self, path):
        deadline = time.monotonic() + 10
        while not path.is_file():
            if time.monotonic() >= deadline:
                self.fail("OWNED_FIXTURE_FILE_TIMEOUT")
            time.sleep(.02)

    def reference(self, pid):
        reference = ProcessReference(pid, process_creation_token(pid))
        def cleanup():
            if reference.poll() is None:
                reference.terminate()
            reference.close()
        self.addCleanup(cleanup)
        return reference

    def wait_stopped(self, reference):
        deadline = time.monotonic() + 10
        while reference.poll() is None:
            if time.monotonic() >= deadline:
                self.fail("OWNED_JOB_MEMBER_SURVIVED")
            time.sleep(.02)

    def test_binary_stdio_unicode_environment_quoting_and_exit37(self):
        with tempfile.TemporaryDirectory() as td:
            env = {**os.environ, "OWNED_JOB_TEST": "unicode-\u03bb"}
            code = ("import sys,os,json; data=sys.stdin.readline(); "
                    "print(json.dumps([sys.argv[1:],os.environ['OWNED_JOB_TEST'],data])); "
                    "print('OWNED_STDERR',file=sys.stderr); sys.exit(37)")
            process = self.owned(code, td, 'space and "quote"', env=env)
            process.stdin.write(b"OWNED_INPUT\n")
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=10), 37)
            self.assertEqual(json.loads(process.stdout.read()), [["space and \"quote\""], "unicode-\u03bb", "OWNED_INPUT\n"])
            self.assertIn(b"OWNED_STDERR", process.stderr.read())

    def test_descendant_cleanup_after_root_exit_does_not_touch_foreign_child(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "child.json"
            code = ("import subprocess,sys,pathlib,json; p=subprocess.Popen([sys.executable,'-c',"
                    "'import time; time.sleep(40)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
                    "stderr=subprocess.DEVNULL); pathlib.Path(sys.argv[1]).write_text(json.dumps(p.pid))")
            foreign = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(40)"])
            def clean_foreign():
                if foreign.poll() is None: foreign.kill()
                foreign.wait(timeout=10)
            self.addCleanup(clean_foreign)
            process = self.owned(code, td, str(path))
            self.wait_file(path)
            reference = self.reference(json.loads(path.read_text()))
            self.assertEqual(process.wait(timeout=10), 0)
            self.assertGreaterEqual(process.active_members(), 1)
            cleanup = process.terminate_tree()
            self.assertTrue(cleanup["descendant_cleanup_verified"])
            self.assertFalse(cleanup["external_broker_children_verified"])
            self.wait_stopped(reference)
            self.assertEqual(process.poll(), 0)  # actual root exit remains intact
            self.assertIsNone(foreign.poll())

    def test_supervisor_hard_crash_closes_job_and_stops_ordinary_descendants(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "members.json"
            code = ("import subprocess,sys,pathlib,json,time,os; "
                    "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(40)']); "
                    "pathlib.Path(sys.argv[1]).write_text(json.dumps([os.getpid(),p.pid])); time.sleep(40)")
            supervisor_code = ("import sys,time; sys.path.insert(0,sys.argv[1]); "
                               "from ff_win_owned_job import OwnedJobProcess; import os; "
                               "p=OwnedJobProcess([sys.executable,'-c',sys.argv[2],sys.argv[3]],"
                               "cwd=sys.argv[4],env=dict(os.environ)); time.sleep(40)")
            supervisor = subprocess.Popen([sys.executable, "-c", supervisor_code,
                                           str(RUNTIME), code, str(path), td])
            try:
                self.wait_file(path)
                references = [self.reference(pid) for pid in json.loads(path.read_text())]
                supervisor.kill()  # exact Popen handle, never taskkill/name/PID lookup
                supervisor.wait(timeout=10)
                for reference in references:
                    self.wait_stopped(reference)
            finally:
                if supervisor.poll() is None: supervisor.kill()
                supervisor.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
