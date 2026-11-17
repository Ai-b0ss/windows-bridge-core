"""Safety and discovery contract for owner-private MSIX Claude Desktop route."""
from __future__ import annotations
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

RUNTIME=Path(__file__).resolve().parents[1]/"runtime"/"bridge-v3"
sys.path.insert(0,str(RUNTIME))
import cua_hidden_apps as apps
import ff_hub_apps as hub


class ClaudeAliasContractTests(unittest.TestCase):
    def test_alias_is_fixed_to_owner_app_execution_alias(self):
        with TemporaryDirectory() as tmp, patch.dict(os.environ,{"LOCALAPPDATA":tmp}):
            alias=Path(tmp)/"Microsoft"/"WindowsApps"/"claude-desktop.exe"
            self.assertEqual(apps.app_path("claude"),alias)
            with self.assertRaisesRegex(ValueError,"HIDDEN_APP_NOT_INSTALLED"):
                apps.launch_spec({"command":"launch_app","app":"claude"})
            alias.parent.mkdir(parents=True)
            alias.write_bytes(b"test-only")
            self.assertEqual(apps.launch_spec({"command":"launch_app","app":"claude"}),("claude",alias))
            with self.assertRaisesRegex(ValueError,"HIDDEN_DOCUMENT_INVALID"):
                apps.launch_spec({"command":"launch_app","app":"claude","document_path":str(alias)})
            with self.assertRaisesRegex(ValueError,"HIDDEN_LAUNCH_OPTION_FORBIDDEN"):
                apps.launch_spec({"command":"launch_app","app":"claude","arguments":["--unsafe"]})

    def test_code_deep_link_requires_exact_scheme_prompt_and_existing_folder(self):
        from urllib.parse import urlencode
        with TemporaryDirectory() as tmp:
            uri="claude://code/new?"+urlencode({"q":"Repair Bridge","folder":tmp})
            self.assertEqual(apps.claude_code_link(uri),uri)
            for invalid in ("https://example.com", "claude://cowork/new?q=X&folder="+tmp,
                            "claude://code/new?"+urlencode({"q":"","folder":tmp}),
                            "claude://code/new?"+urlencode({"q":"Task","folder":tmp,"exec":"cmd"}),
                            "claude://code/new?"+urlencode({"q":"Task","folder":tmp})+"&folder="+tmp):
                with self.subTest(invalid=invalid),self.assertRaisesRegex(ValueError,
                        "HIDDEN_CLAUDE_LINK_INVALID"):
                    apps.claude_code_link(invalid)
            missing="claude://code/new?"+urlencode({"q":"Task","folder":str(Path(tmp)/"missing")})
            with self.assertRaisesRegex(ValueError,"HIDDEN_CLAUDE_FOLDER_INVALID"):
                apps.claude_code_link(missing)
            with patch.dict(os.environ,{"LOCALAPPDATA":tmp}):
                alias=Path(tmp)/"Microsoft"/"WindowsApps"/"claude-desktop.exe"
                alias.parent.mkdir(parents=True,exist_ok=True)
                alias.write_bytes(b"test-only")
                self.assertEqual(apps.launch_spec({"command":"launch_app","app":"claude","code_link":uri}),
                                 ("claude",alias))
            with self.assertRaisesRegex(ValueError,"HIDDEN_LAUNCH_OPTION_FORBIDDEN"):
                apps.launch_spec({"command":"launch_app","app":"notepad","code_link":uri})

    def test_only_exact_owned_claude_frame_can_be_selected(self):
        info={"class_name":"Chrome_WidgetWin_1","title":"Claude",
              "geometry":{"left":0,"right":700,"top":0,"bottom":400}}
        self.assertEqual(apps.main_window_area("claude",info,True,False),280000)
        for wrong in (
            {**info,"title":"Other"},
            {**info,"class_name":"Chrome_WidgetWin_0"},
            {**info,"title":""},
        ):
            self.assertIsNone(apps.main_window_area("claude",wrong,True,False))
        self.assertIsNone(apps.main_window_area("claude",info,False,False))
        self.assertIsNone(apps.main_window_area("claude",info,True,True))

    def test_planner_is_desktop_not_claude_cli(self):
        with TemporaryDirectory() as tmp:
            alias=Path(tmp)/"claude-desktop.exe"
            alias.write_bytes(b"test-only")
            with patch.object(hub.shutil,"which",return_value=str(alias)),patch.object(hub,"count_processes",return_value=0):
                result=hub.plan("Claude Desktop")
            self.assertEqual(result["app"]["kind"],"msix_fulltrust_electron")
            self.assertEqual(result["app"]["known"],"claude-desktop")
            self.assertEqual(result["recommended"]["route"],"hidden_desktop_msix_alias")
            self.assertEqual(result["recommended"]["status"],"partial")
            self.assertFalse(any(item.get("route")=="cli" for item in result["routes"]))


if __name__=="__main__":
    unittest.main()
