from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
MODULES=ROOT/"runtime/bridge-v3"
sys.path.insert(0,str(MODULES))
import cua_windows_mcp
from cua_cli_first_policy import enforce


class SimulatedCore:
    class RPCError(RuntimeError):
        def __init__(self, code, **kwargs):
            super().__init__(code)
            self.code = code


class WindowsMcpPhysicalTests(unittest.TestCase):
    def test_physical_tools_refused_unless_explicitly_allowed(self):
        for tool in ("Click","Type","Scroll","Move","Shortcut"):
            with self.assertRaisesRegex(ValueError,"WINDOWS_MCP_TOOL_NOT_ALLOWED"):
                cua_windows_mcp.invoke_windows_mcp(tool,{})

    def test_shell_registry_process_never_allowed(self):
        for tool in ("Shell","Registry","Process","App","Notification"):
            with self.assertRaisesRegex(ValueError,"WINDOWS_MCP_TOOL_NOT_ALLOWED"):
                cua_windows_mcp.invoke_windows_mcp(tool,{},allow_physical=True)

    def test_allowed_physical_tool_reaches_the_server_launch(self):
        with mock.patch.object(cua_windows_mcp,"prepare_windows_mcp",side_effect=RuntimeError("REACHED")):
            with self.assertRaisesRegex(RuntimeError,"REACHED"):
                cua_windows_mcp.invoke_windows_mcp("Click",{"loc":[1,1]},allow_physical=True)

    def test_cli_first_exception_only_for_active_grant(self):
        args={"command":"windows_mcp","tool":"Click","arguments":{"app":"Cursor"},
              "agent_id":"chatgpt","task_id":"t1","mode_generation":3}
        core=SimulatedCore()
        with self.assertRaises(SimulatedCore.RPCError) as cm:
            enforce(core,"computer_use",args)
        self.assertEqual(cm.exception.code,"CLI_FIRST_POLICY_VIOLATION")
        core.desktop_grant_active=lambda a: False
        with self.assertRaises(SimulatedCore.RPCError):
            enforce(core,"computer_use",args)
        core.desktop_grant_active=lambda a: a["task_id"]=="t1"
        enforce(core,"computer_use",args)

    def test_main_routes_physical_tools_through_desktop_mode(self):
        code=(MODULES/"ff_win_v3_main.py").read_text(encoding="utf-8")
        i=code.index("def _windows_mcp_physical")
        block=code[i:i+2400]
        self.assertIn("_DESKTOP_MODES.action(args, hwnd)",block)
        self.assertIn("allow_physical=True",block)
        self.assertIn("core.desktop_grant_active = _desktop_grant_active",code)


if __name__=="__main__":
    unittest.main()
