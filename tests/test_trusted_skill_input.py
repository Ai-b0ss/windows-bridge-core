"""Negative and positive regression tests for opt-in Claude-only skill pilot."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from cua_trusted_skill_input import TrustedSkillInput, TrustedSkillError, APPROVAL_SCHEMA, ALLOWED_PURPOSE

class FakeWindows:
    def __init__(self):
        self.pid=42
        self.birth=100
        self.path=(r"C:\Program Files\WindowsApps\Claude_4.4212.0.0_x64__pzs8sxrjxfjjc\app\Claude.exe").lower()
        self.active=0
        self.topmost=True
    def snapshot(self, hwnd):
        return {"hwnd":hwnd, "pid":self.pid, "birth":self.birth,
                "executable":self.path,"rect":(0,0,800,600)}
    def point_on_target(self,hwnd,x,y):
        return self.topmost
    def foreground(self):
        return self.active
    def focus(self,hwnd):
        self.active=hwnd
        return True

class TrustedSkillPilotTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/"opt-in.json"
        self.now=[1000.]
        self.windows=FakeWindows()
        self.events=[]
        self.pilot=TrustedSkillInput(self.path,windows=self.windows,
                                     mouse=self.events.append, clock=lambda:self.now[0])
        self.action={"agent_id":"chatgpt","task_id":"read-claude-usage",
                     "purpose":ALLOWED_PURPOSE,"hwnd":100}
    def enable(self):
        self.path.write_text(json.dumps({"schema":APPROVAL_SCHEMA,"enabled":True,
            "agent_id":"chatgpt","purpose":ALLOWED_PURPOSE,
            "owner_opt_in_until":self.now[0]+7200}))
    def start(self):
        return self.pilot.begin(self.action)["session_id"]
    def act(self, sid, kind, **kw):
        return self.pilot.act({"session_id":sid,"task_id":self.action["task_id"],
                               "action":kind,**kw})
    def test_default_denied_and_no_op_on_request(self):
        self.assertFalse(self.pilot.status()["enabled"])
        with self.assertRaises(TrustedSkillError):
            self.start()
        self.assertFalse(self.events)
    def test_bounded_session_and_no_reprompt(self):
        self.enable()
        sid=self.start()
        self.assertTrue(self.pilot.begin(self.action)["reused"])
        self.act(sid,"focus")
        self.act(sid,"click",x=40,y=50)
        self.assertEqual(self.events[-1]["action"],"click")
        self.assertEqual(self.pilot.status()["actions_remaining"],10)
        self.assertTrue(self.pilot.end({"session_id":sid,"task_id":self.action["task_id"]})["closed"])
        with self.assertRaises(TrustedSkillError):
            self.act(sid,"focus")
    def test_denies_unknown_window_and_changed_pid(self):
        self.enable()
        self.windows.path=r"C:\OtherApps\Unknown.exe"
        with self.assertRaises(TrustedSkillError):
            self.start()
        self.windows.path=(r"C:\Program Files\WindowsApps\Claude_4.4212.0.0_x64__pzs8sxrjxfjjc\app\Claude.exe").lower()
        sid=self.start()
        self.windows.pid=43
        with self.assertRaises(TrustedSkillError):
            self.act(sid,"focus")
    def test_denies_wrong_task_and_obscured_coordinates(self):
        self.enable()
        sid=self.start()
        self.act(sid,"focus")
        with self.assertRaises(TrustedSkillError):
            self.pilot.act({"session_id":sid,"task_id":"different","action":"click","x":10,"y":10})
        with self.assertRaises(TrustedSkillError):
            self.act(sid,"click",x=9999,y=10)
        self.windows.topmost=False
        with self.assertRaises(TrustedSkillError):
            self.act(sid,"click",x=10,y=10)
        self.assertFalse(self.events)
    def test_time_expiry_and_config_revocation(self):
        self.enable()
        sid=self.start()
        self.now[0]+=601
        with self.assertRaises(TrustedSkillError):
            self.act(sid,"focus")
        self.path.write_text(json.dumps({"schema":APPROVAL_SCHEMA,"enabled":False}))
        self.assertFalse(self.pilot.status()["enabled"])
    def test_invalid_actions_and_flags(self):
        self.enable()
        sid=self.start()
        for extra in ({"action":"keyboard","text":"Hi"},
                      {"action":"click","x":100,"y":100,"clicks":10},
                      {"action":"scroll","delta":100000}):
            with self.subTest(extra=extra):
                with self.assertRaises(TrustedSkillError):
                    self.pilot.act({"session_id":sid,"task_id":self.action["task_id"],**extra})
        self.assertFalse(self.events)

if __name__=="__main__":
    unittest.main()
