from pathlib import Path
import json
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
MODULES=ROOT/"runtime/bridge-v3"
sys.path.insert(0,str(MODULES))
from cua_owner_activity import OwnerActivityGuard, OwnerActive
from cua_owner_notice import OwnerNotice
from cua_chat_permission import ChatPermissionPolicy


class FakeClock:
    def __init__(self): self.now=100.0
    def __call__(self): return self.now


class OwnerActivityTests(unittest.TestCase):
    def guard(self, idle):
        clock=FakeClock()
        box={"idle":idle}
        return OwnerActivityGuard(idle_ms=lambda: box["idle"],clock=clock),clock,box

    def test_first_action_needs_owner_to_be_quiet(self):
        guard,_,box=self.guard(200)
        with self.assertRaises(OwnerActive):
            guard.check()
        box["idle"]=5000
        guard.check()

    def test_agents_own_input_is_not_mistaken_for_owner(self):
        guard,clock,box=self.guard(9000)
        guard.check()
        clock.now+=0.2; guard.agent_input_done()
        clock.now+=1.0
        box["idle"]=1000          # the agent's last input was 1 s ago
        guard.check()

    def test_input_after_agent_finished_pauses_agent(self):
        guard,clock,box=self.guard(9000)
        guard.agent_input_done()
        clock.now+=3.0
        box["idle"]=500           # something typed 0.5 s ago, agent was idle for 3 s
        with self.assertRaises(OwnerActive):
            guard.check()

    def test_unobservable_input_does_not_block(self):
        def broken(): raise OSError("no desktop")
        OwnerActivityGuard(idle_ms=broken).check()


class FakeProc:
    def __init__(self): self.alive=True
    def poll(self): return None if self.alive else 0


class NoticeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.calls=[]
        self.proc=FakeProc()
        def popen(cmd,**kw):
            self.calls.append((cmd,kw)); return self.proc
        self.notice=OwnerNotice(self.tmp.name,popen=popen)

    def tearDown(self): self.tmp.cleanup()

    def test_one_window_per_task_and_heartbeat_refreshed(self):
        self.assertTrue(self.notice.action("chatgpt","t1",1))
        self.assertTrue(self.notice.action("chatgpt","t1",1))
        self.assertEqual(len(self.calls),1)
        self.assertTrue(self.notice.heartbeat_path.exists())
        self.notice.action("chatgpt","t2",2)
        self.assertEqual(len(self.calls),2)

    def test_reopens_if_window_was_closed(self):
        self.notice.action("chatgpt","t1",1)
        self.proc.alive=False
        self.notice.action("chatgpt","t1",1)
        self.assertEqual(len(self.calls),2)

    def test_config_and_command(self):
        self.notice.action("chatgpt","t1",1,"Notepad")
        cmd,kw=self.calls[0]
        self.assertIn("-STA",cmd); self.assertEqual(cmd[-2],"-ConfigPath")
        cfg=json.loads(Path(cmd[-1]).read_text(encoding="utf-8"))
        self.assertIn("chatgpt",cfg["text"]); self.assertEqual(cfg["stop_label"],"Стоп")
        self.assertEqual(Path(cfg["stop_path"]).name,"stop.flag")

    def test_spawn_failure_is_reported_not_raised(self):
        def boom(*a,**k): raise OSError("x")
        notice=OwnerNotice(self.tmp.name,popen=boom)
        self.assertFalse(notice.action("a","t",1))

    def test_stop_flag_roundtrip_and_new_grant_clears_it(self):
        self.notice.stop_path.write_text("1")
        self.assertTrue(self.notice.stop_requested())
        cfg=Path(self.tmp.name)/"cfg.json"
        cfg.write_text(json.dumps({"schema":"ff-chat-permission-v1","enabled":True}))
        policy=ChatPermissionPolicy(cfg,self.tmp.name)
        policy.authorize({"agent_id":"a","task_id":"t","owner_chat_permission":{"quote":"да"}})
        self.assertFalse(self.notice.stop_requested())

    def test_script_never_takes_focus_and_main_is_wired(self):
        ps=(MODULES/"cua_owner_notice.ps1").read_text(encoding="utf-8")
        self.assertIn("ShowWithoutActivation",ps); self.assertIn("0x08000000",ps)
        main=(MODULES/"ff_win_v3_main.py").read_text(encoding="utf-8")
        guard=main[main.index("def _owner_stop_check"):main.index("def _windows_mcp_physical")]
        for needle in ("_OWNER_NOTICE.stop_requested()","_OWNER_ACTIVITY.check()",
                       "_OWNER_NOTICE.action(","agent_input_done()","OWNER_ACTIVE","OWNER_STOPPED"):
            self.assertIn(needle,guard)
        # every path that really sends input goes through the same guard
        self.assertEqual(main.count("with _visible_input_guard(args):"),3)
        self.assertEqual(main.count("_owner_stop_check()"),4)  # definition + three call sites


if __name__=="__main__":
    unittest.main()
