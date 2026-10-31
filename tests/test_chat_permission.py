from pathlib import Path
import json
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from cua_chat_permission import ChatPermissionPolicy, ChatPermissionError
from cua_task_authority import AuthorityStore, AuthorityError, DesktopModes


class Clock:
    def __init__(self, now=1_800_000_000): self.now=now
    def __call__(self): return self.now


def request(**permission):
    permission.setdefault("quote","да, можно")
    return {"mode":"dedicated","agent_id":"chatgpt","task_id":"task-1","targets":[],
            "owner_chat_permission":permission}


class ChatPermissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
        self.clock=Clock()
        self.config=self.root/"chat-permission.json"
        self.policy=ChatPermissionPolicy(self.config,self.root/"log",self.clock)

    def tearDown(self):
        self.tmp.cleanup()

    def enable(self, **extra):
        self.config.write_text(json.dumps({"schema":"ff-chat-permission-v1","enabled":True,**extra}),encoding="utf-8")

    def test_disabled_until_owner_enables_local_config(self):
        self.assertFalse(self.policy.status()["enabled"])
        with self.assertRaisesRegex(ChatPermissionError,"CHAT_PERMISSION_DISABLED"):
            self.policy.authorize(request())

    def test_opt_in_expiry_disables_feature(self):
        self.enable(owner_opt_in_until=self.clock.now+10)
        self.assertTrue(self.policy.status()["enabled"])
        self.clock.now+=11
        self.assertFalse(self.policy.status()["enabled"])

    def test_grant_returns_bounded_expiry_and_records_quote(self):
        self.enable(max_ttl_seconds=600)
        expires=self.policy.authorize(request(duration_seconds=99999,apps=["Notepad"]))
        self.assertEqual(expires,self.clock.now+600)
        rows=[json.loads(l) for l in (self.root/"log/chat-permission.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual(rows[0]["quote"],"да, можно")
        self.assertEqual(rows[0]["task_id"],"task-1")

    def test_default_duration_and_validation(self):
        self.enable()
        self.assertEqual(self.policy.authorize(request()),self.clock.now+3600)
        bad=[request(quote=""),request(quote="x"),request(duration_seconds=5),
             request(duration_seconds=True),request(apps="Notepad"),request(extra=1)]
        for item in bad:
            with self.assertRaises(ChatPermissionError, msg=item):
                self.policy.authorize(item)
        missing=request(); missing.pop("task_id")
        with self.assertRaisesRegex(ChatPermissionError,"IDENTITY"):
            self.policy.authorize(missing)

    def test_scope_report_counts_recent_violations_only(self):
        self.enable()
        self.policy.log_violation("VISIBLE_INPUT_WITHOUT_PERMISSION",reason="x")
        self.clock.now+=3600*30
        self.policy.log_violation("OUT_OF_SCOPE_APP",app="Telegram")
        report=self.policy.scope_report(24)
        self.assertEqual(report["violations"],{"OUT_OF_SCOPE_APP":1})
        self.assertEqual(self.policy.scope_report(72)["violation_total"],2)
        with self.assertRaises(ValueError):
            self.policy.log_violation("MADE_UP")

    def test_desktop_mode_accepts_chat_permission_without_signature(self):
        self.enable()
        store=AuthorityStore(self.root/"authority")
        modes=DesktopModes(self.root/"mode",store,lambda hwnd:None,chat_permission=self.policy)
        state=modes.transition(request(duration_seconds=300))
        self.assertEqual(state["mode"],"dedicated")
        self.assertEqual(state["expires"],self.clock.now+300)

    def test_desktop_mode_refuses_chat_permission_when_not_wired_or_disabled(self):
        store=AuthorityStore(self.root/"authority")
        unwired=DesktopModes(self.root/"mode1",store,lambda hwnd:None)
        with self.assertRaisesRegex(AuthorityError,"CHAT_PERMISSION_DISABLED"):
            unwired.transition(request())
        disabled=DesktopModes(self.root/"mode2",store,lambda hwnd:None,chat_permission=self.policy)
        with self.assertRaisesRegex(AuthorityError,"CHAT_PERMISSION_DISABLED"):
            disabled.transition(request())

    def test_plain_dedicated_request_still_needs_a_grant(self):
        self.enable()
        store=AuthorityStore(self.root/"authority")
        modes=DesktopModes(self.root/"mode",store,lambda hwnd:None,chat_permission=self.policy)
        args=request(); args.pop("owner_chat_permission")
        with self.assertRaises(AuthorityError):
            modes.transition(args)


if __name__=="__main__":
    unittest.main()
