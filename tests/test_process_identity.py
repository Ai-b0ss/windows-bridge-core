import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from ff_win_process_identity import process_creation_token,process_identity_matches


class TestReadOnlyProcessIdentity(unittest.TestCase):
    def test_pid_and_token_both_required(self):
        with patch("ff_win_process_identity.process_creation_token",return_value=987654321):
            self.assertTrue(process_identity_matches(1234,987654321))
            self.assertFalse(process_identity_matches(1234,987654322))
            self.assertFalse(process_identity_matches(1234,None))
            self.assertFalse(process_identity_matches(1234,True))
            self.assertFalse(process_identity_matches(True,987654321))
            self.assertFalse(process_identity_matches(-1,987654321))

    def test_unknown_creation_time_refuses_to_attach(self):
        with patch("ff_win_process_identity.process_creation_token",return_value=None):
            self.assertFalse(process_identity_matches(1234,987654321))

    def test_invalid_pid_never_queried(self):
        self.assertIsNone(process_creation_token(0))
        self.assertIsNone(process_creation_token(-1))
        self.assertIsNone(process_creation_token(True))

    @unittest.skipUnless(os.name=="nt","Windows-only process FILETIME API")
    def test_real_windows_self_creation_token_stable(self):
        token=process_creation_token(os.getpid())
        self.assertIsInstance(token,int)
        self.assertGreater(token,0)
        self.assertTrue(process_identity_matches(os.getpid(),token))
        self.assertFalse(process_identity_matches(os.getpid(),token+1))


if __name__=="__main__":
    unittest.main()
