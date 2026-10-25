import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"runtime/bridge-v3"))
from ff_win_process_identity import ProcessReference, process_creation_token


class TestProcessReferenceContract(unittest.TestCase):
    def setup_reference(self, births=(123, 123)):
        api = Mock()
        api.OpenProcess.side_effect = [100, 200]
        api.WaitForSingleObject.return_value = 258
        api.TerminateProcess.return_value = True
        for p in (patch("ff_win_process_identity.os.name", "nt"),
                  patch("ff_win_process_identity._kernel_api", return_value=api),
                  patch("ff_win_process_identity._handle_birth", side_effect=births)):
            p.start()
            self.addCleanup(p.stop)
        reference = ProcessReference(7, 123)
        self.addCleanup(reference.close)
        return reference, api

    def test_termination_uses_the_same_verified_handle(self):
        reference, api = self.setup_reference()
        reference.terminate()
        api.TerminateProcess.assert_called_once_with(200, 1)
        api.CloseHandle.assert_called_once_with(200)

    def test_changed_birth_refuses_termination_and_closes_new_handle(self):
        reference, api = self.setup_reference((123, 124))
        with self.assertRaisesRegex(OSError, "IDENTITY_MISMATCH"):
            reference.terminate()
        api.TerminateProcess.assert_not_called()
        api.CloseHandle.assert_called_once_with(200)

    def test_real_exit_259_is_not_misclassified_as_running(self):
        reference, api = self.setup_reference()
        api.WaitForSingleObject.return_value = 0
        def exit_code(handle, output):
            output._obj.value = 259
            return True
        api.GetExitCodeProcess.side_effect = exit_code
        self.assertEqual(reference.poll(), 259)
        self.assertEqual(reference.poll(), 259)
        api.CloseHandle.assert_called_once_with(100)
        api.GetExitCodeProcess.assert_called_once()

    def test_failed_wait_is_not_a_successful_exit(self):
        reference, api = self.setup_reference()
        api.WaitForSingleObject.return_value = 0xffffffff
        with self.assertRaisesRegex(OSError, "WAIT_FAILED"):
            reference.poll()

    def test_failed_exit_query_is_not_zero(self):
        reference, api = self.setup_reference()
        api.WaitForSingleObject.return_value = 0
        api.GetExitCodeProcess.return_value = False
        with self.assertRaisesRegex(OSError, "EXIT_CODE_UNAVAILABLE"):
            reference.poll()


@unittest.skipUnless(os.name == "nt", "Requires Windows kernel process handles")
class TestActualWindowsProcessReference(unittest.TestCase):
    def launch(self, code):
        process = subprocess.Popen([sys.executable, "-c", code])
        def cleanup():
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
        self.addCleanup(cleanup)
        token = process_creation_token(process.pid)
        self.assertIsInstance(token, int)
        reference = ProcessReference(process.pid, token)
        self.addCleanup(reference.close)
        return process, reference

    def test_nonzero_exit_survives_original_process_handle_release(self):
        process, reference = self.launch("import time,sys; time.sleep(.5); sys.exit(37)")
        self.assertIsNone(reference.poll())
        self.assertEqual(process.wait(timeout=10), 37)
        self.assertEqual(reference.poll(), 37)

    def test_process_exit_259_is_not_infinite_running(self):
        process, reference = self.launch("import time,sys; time.sleep(.5); sys.exit(259)")
        self.assertEqual(process.wait(timeout=10), 259)
        self.assertEqual(reference.poll(), 259)

    def test_terminate_only_owned_test_child_and_verify_exit(self):
        process, reference = self.launch("import time; time.sleep(20)")
        reference.terminate()
        self.assertEqual(process.wait(timeout=10), 1)
        self.assertEqual(reference.poll(), 1)

    def test_wrong_token_never_attaches_to_test_child(self):
        process, reference = self.launch("import time; time.sleep(20)")
        with self.assertRaisesRegex(OSError, "IDENTITY_MISMATCH"):
            ProcessReference(process.pid, reference.token + 1)
        self.assertIsNone(process.poll())


if __name__ == "__main__":
    unittest.main()
