"""Non-destructive tests: no real Chrome, Hub or Windows tasks are touched."""
from __future__ import annotations
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import chrome_owner_autorecover as mod


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base=Path(self.tmp.name)
        self.root=base
        self.rec=mod.Recovery(base/"hub",base/"work")
        self.rec.chrome=base/"chrome.exe"
        self.rec.chrome.touch()
        self.rec.user_data=base/"User Data"
        (self.rec.user_data/"Default").mkdir(parents=True)
        (self.rec.user_data/"Local State").write_text(json.dumps({"devtools":{"remote_debugging":{"user-enabled":True}}}),encoding="utf-8")
        (self.rec.user_data/"DevToolsActivePort").write_text("9222\n/devtools/browser/id",encoding="ascii")
        self.owner=SimpleNamespace(pid=1099)
        self.rec.watch_script.write_text("watcher",encoding="utf-8")
        self.base_patches=[
           patch.object(mod,"remote_debugging_enabled",return_value=True),
           patch.object(mod,"hub_status",return_value={"pid":1234,"owner_chrome_secondary":{"connected":False}}),
           patch.object(mod,"owner_processes",return_value=[self.owner]),
           patch.object(mod,"listener_pid",return_value=1099),
           patch.object(mod,"windows_for_owner",return_value=set()),
           patch.object(mod,"watcher_running",return_value=True),
        ]

    def test_when_connected_never_launch_chrome_or_window(self):
        with patch.object(mod,"hub_status",return_value={"pid":1234,"owner_chrome_secondary":{"connected":True}}),\
             patch.object(mod,"owner_processes") as owners,patch.object(mod,"native_support_window") as helper:
            result=self.rec.step()
        self.assertEqual(result["code"],"CDP_CONNECTED")
        owners.assert_not_called()
        helper.assert_not_called()

    def test_disabled_remote_debug_fails_closed(self):
        (self.rec.user_data/"Local State").write_text('{"devtools":{"remote_debugging":{"user-enabled":false}}}',encoding="utf-8")
        with patch.object(mod,"owner_processes") as owners:
            r=self.rec.step()
        self.assertEqual(r["code"],"OWNER_CHROME_REMOTE_DEBUG_DISABLED")
        owners.assert_not_called()

    def test_port_owned_by_another_process_is_not_used(self):
        with patch.object(mod,"hub_status",return_value={"pid":1234,"owner_chrome_secondary":{"connected":False}}),\
             patch.object(mod,"owner_processes",return_value=[self.owner]),\
             patch.object(mod,"listener_pid",return_value=4005),\
             patch.object(mod,"native_support_window") as helper:
            r=self.rec.step()
        self.assertEqual(r["code"],"CDP_PORT_NOT_OWNED_BY_CHROME")
        helper.assert_not_called()

    def test_existing_chrome_user_window_is_not_touched(self):
        with patch.object(mod,"hub_status",return_value={"pid":1234,"owner_chrome_secondary":{"connected":False}}),\
             patch.object(mod,"owner_processes",return_value=[self.owner]),\
             patch.object(mod,"listener_pid",return_value=self.owner.pid),\
             patch.object(mod,"windows_for_owner",return_value={100}),\
             patch.object(mod,"native_support_window") as helper:
            r=self.rec.step()
        self.assertEqual(r["code"],"CHROME_ALREADY_HAS_WINDOW_WAIT_FOR_WATCHER")
        helper.assert_not_called()

    def test_missing_watcher_does_not_create_consent_window(self):
        with patch.object(mod,"hub_status",return_value={"pid":1234,"owner_chrome_secondary":{"connected":False}}),\
             patch.object(mod,"owner_processes",return_value=[self.owner]),\
             patch.object(mod,"listener_pid",return_value=self.owner.pid),\
             patch.object(mod,"windows_for_owner",return_value=set()),\
             patch.object(mod,"watcher_running",return_value=False),\
             patch.object(mod,"native_support_window") as helper:
            r=self.rec.step()
        self.assertEqual(r["code"],"CONSENT_WATCHER_NOT_RUNNING")
        helper.assert_not_called()

    def test_native_dialog_recovery_is_bounded_and_cleanup_exact_window(self):
        fake=SimpleNamespace()
        calls=[]
        fake.IsWindow=lambda hwnd: True
        def getpid(hwnd,output):
            output._obj.value=self.owner.pid
        fake.GetWindowThreadProcessId=getpid
        fake.PostMessageW=lambda hwnd,op,w,l:calls.append((hwnd,op)) or 1
        states=iter([
            {"pid":1234,"owner_chrome_secondary":{"connected":False}},
            {"pid":1234,"owner_chrome_secondary":{"connected":True}}
        ])
        with patch.object(mod,"hub_status",side_effect=lambda *a,**kw:next(states)),\
             patch.object(mod,"owner_processes",return_value=[self.owner]),\
             patch.object(mod,"listener_pid",return_value=self.owner.pid),\
             patch.object(mod,"windows_for_owner",return_value={78}),\
             patch.object(mod,"watcher_running",return_value=True),\
             patch.object(mod,"native_support_window",return_value=78),\
             patch.object(mod,"USER32",fake),patch.object(mod.time,"sleep",return_value=None):
            # Simulate an actual helper window created when baseline was empty.
            with patch.object(mod,"windows_for_owner",side_effect=[set(),{78}]):
                r=self.rec.step()
        self.assertEqual(r["code"],"CDP_RECOVERED")
        self.assertEqual(calls,[(78,mod.WM_CLOSE)])

    def test_support_window_throttled_after_three_attempts(self):
        self.rec.attempts=3
        with patch.object(mod,"hub_status",return_value={"pid":1234,"owner_chrome_secondary":{"connected":False}}),\
             patch.object(mod,"owner_processes",return_value=[self.owner]),\
             patch.object(mod,"listener_pid",return_value=self.owner.pid),\
             patch.object(mod,"windows_for_owner",return_value=set()),\
             patch.object(mod,"watcher_running",return_value=True),\
             patch.object(mod,"native_support_window") as helper:
            r=self.rec.step()
        self.assertEqual(r["code"],"CONSENT_COOLDOWN")
        helper.assert_not_called()


if __name__=="__main__":unittest.main()
