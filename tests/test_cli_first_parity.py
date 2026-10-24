from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
MODULES=ROOT/"runtime/bridge-v3"
sys.path.insert(0,str(MODULES))
from cua_cli_first_policy import enforce


class SimulatedCore:
    class RPCError(RuntimeError):
        def __init__(self, code, **kwargs):
            super().__init__(code)
            self.code = code


class TestCliFirstRestoration(unittest.TestCase):
    def test_readonly_preflight_never_demands_signature(self):
        core=SimulatedCore()
        for command in ("programmatic_plan","plan_action","discover_cli"):
            enforce(core,"computer_use",{
                "command":command,"app":"Cursor",
                "approved":True,"foreground_allowed":True,
            })

    def test_agent_controlled_approval_bool_fails_closed(self):
        with self.assertRaises(SimulatedCore.RPCError) as cm:
            enforce(SimulatedCore(),"computer_use",{
                "command":"launch_app","app":"Cursor",
                "allow_gui":True,"approved":True,
            })
        self.assertEqual(cm.exception.code,"CLI_FIRST_POLICY_VIOLATION")

    def test_display_names_and_direct_gui_process_are_blocked(self):
        for app in ("Cursor", "Antigravity", "VS Code"):
            with self.subTest(app=app):
                with self.assertRaises(SimulatedCore.RPCError) as cm:
                    enforce(SimulatedCore(), "computer_use", {"command": "launch_app", "app": app})
                self.assertEqual(cm.exception.code, "CLI_FIRST_POLICY_VIOLATION")

    def test_official_programmatic_cli_is_not_blocked(self):
        for executable in ("agent --version", "agy --help", "code --help"):
            enforce(SimulatedCore(), "start_process", {"command": executable})
    def test_source_wraps_actual_computer_use_dispatch(self):
        code=(MODULES/"ff_win_v3_main.py").read_text(encoding="utf-8")
        marker="def _computer_use(args: dict[str, Any]) -> dict[str, Any]:"
        i=code.index(marker)
        self.assertIn('enforce_cli_first(core, "computer_use", args)',code[i:i+240])
        self.assertIn('core.cli_first_surfaces = _CUA_CONTROL_PLANE._surfaces',code)
        self.assertIn('"gui_exception": "exact_owner_signed_approval"',code)

    def test_public_security_redacts_credentials(self):
        src=(MODULES/"ff_win_v3_security.py").read_text(encoding="utf-8")
        self.assertIn("_CREDENTIAL_PATTERNS",src)
        self.assertIn("SENSITIVE_KEY_PARTS",src)
        self.assertIn("redact_string",src)


if __name__=="__main__":
    unittest.main()
