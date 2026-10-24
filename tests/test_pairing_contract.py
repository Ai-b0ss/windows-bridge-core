import pathlib,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class TestPairingContract(unittest.TestCase):
    def test_private_guard_and_separate_operator(self):
        s=(ROOT/"install.ps1").read_text(encoding="utf-8")
        self.assertIn("REMOTE_GITHUB_REPOSITORY_MUST_BE_PRIVATE",s)
        self.assertIn("REMOTE_OPERATOR_MUST_BE_REPOSITORY_OWNER",s)
        self.assertIn("allowed_senders=@([string]$TrustedOperator)",s)
        self.assertNotIn("allowed_senders=@([string]$userInfo.login)",s)
    def test_disconnect_owned_tasks_only(self):
        s=(ROOT/"STOP-REMOTE-SUPPORT.ps1").read_text(encoding="utf-8")
        self.assertIn("REMOTE_CONFIG_FOREIGN_REPOSITORY",s)
        self.assertIn("Get-ScheduledTask",s)
        self.assertIn("Disable-ScheduledTask",s)
        self.assertIn("Get-CimInstance Win32_Process",s)
        self.assertIn("IndexOf($expected",s)
    def test_consent_before_remote(self):
        s=(ROOT/"PAIR-REMOTE-SUPPORT.cmd").read_text(encoding="utf-8")
        self.assertIn("choice /C YN",s)
        self.assertIn("if errorlevel 2 exit /b 1",s)
        self.assertIn("-Transport GitHub",s)
        self.assertIn("-TrustedOperator Ai-b0ss",s)
        self.assertNotIn("GH_TOKEN=",s)
if __name__=="__main__":unittest.main()
