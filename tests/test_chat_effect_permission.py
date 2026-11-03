"""Chat permission for protected RPC operations; no Windows effects in tests."""
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from cua_task_authority import AuthorityStore, guard_effect, canonical, invocation, APPROVED_EFFECT
from cua_chat_permission import ChatPermissionPolicy

class FakeCore:
    class RPCError(RuntimeError):
        def __init__(self, code, details=None):
            self.code=code
            self.details=details or {}
            super().__init__(code)
    @staticmethod
    def command_blocked(cmd): return True
    @staticmethod
    def code_blocked(lang,code): return True

class ChatEffectTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.conf=root/"chat-permission.json"
        self.policy=ChatPermissionPolicy(self.conf,root/"logs")
        self.store=AuthorityStore(root/"authority")
        self.calls=[]
        self.args={"agent_id":"agent-a","task_id":"task-a","pid":4242,
                   "consequences":{"kind":"destructive","purpose":"stop the owned fixture",
                                   "targets":["synthetic-test-process"],"risk":"test-only"}}
    def enable(self):
        self.conf.write_text(json.dumps({"schema":"ff-chat-permission-v1","enabled":True,"max_ttl_seconds":7200}))
    def act(self,args):
        self.assertTrue(APPROVED_EFFECT.get())
        self.calls.append(args)
        return {"ok":True}
    def grant(self, args=None, *, op="kill_process", quote="Да, разрешаю остановить тестовый процесс"):
        args=dict(args or self.args)
        exact=invocation(op,args)
        digest=hashlib.sha256(canonical(exact).encode("utf-8")).hexdigest()
        args["owner_chat_permission"]={"quote":quote,"operation":op,"request_digest":digest}
        return args
    def guarded(self, op="kill_process"):
        return guard_effect(FakeCore,self.store,op,self.act,chat_permission=self.policy)
    def expect_code(self,code,args=None,op="kill_process"):
        with self.assertRaises(FakeCore.RPCError) as cm:
            self.guarded(op)(args if args is not None else self.args)
        self.assertEqual(cm.exception.code,code)
        self.assertFalse(cm.exception.details.get("execution_started",True))
        self.assertEqual(self.calls,[])
        self.assertFalse(APPROVED_EFFECT.get())
    def test_protected_requires_extra_permission(self):
        self.enable()
        self.expect_code("OWNER_APPROVAL_REQUIRED")
    def test_valid_exact_permission_allows_one_action_without_signature(self):
        self.enable()
        self.assertEqual(self.guarded()(self.grant()),{"ok":True})
        self.assertEqual(len(self.calls),1)
        self.assertFalse(APPROVED_EFFECT.get())
        rows=(self.policy.state_dir/"effect-permission.jsonl").read_text(encoding="utf-8").splitlines()
        data=json.loads(rows[0])
        self.assertEqual(data["operation"],"kill_process")
        self.assertEqual(data["agent_id"],"agent-a")
        self.assertFalse(data["quote_verified_by_bridge"])
    def test_disabled_does_not_authorize(self):
        self.expect_code("CHAT_PERMISSION_DISABLED",self.grant())
    def test_tampered_target_cannot_reuse_exact_request_digest(self):
        self.enable()
        args=self.grant()
        args["pid"]=9999
        self.expect_code("CHAT_PERMISSION_EFFECT_SCOPE_MISMATCH",args)
    def test_wrong_operation_not_accepted(self):
        self.enable()
        args=self.grant()
        args["owner_chat_permission"]["operation"]="run_code"
        self.expect_code("CHAT_PERMISSION_EFFECT_SCOPE_MISMATCH",args)
    def test_invalid_chat_permission_scope_not_accepted(self):
        self.enable()
        args=self.grant()
        args["owner_chat_permission"].pop("request_digest")
        self.expect_code("CHAT_PERMISSION_EFFECT_SCOPE_REQUIRED",args)
    def test_owner_stop_flag_blocks_effect(self):
        self.enable()
        self.policy.state_dir.mkdir()
        (self.policy.state_dir/"stop.flag").write_text("stop")
        self.expect_code("OWNER_STOPPED",self.grant())
    def test_missing_consequence_scope_blocks_effect(self):
        self.enable()
        args=self.grant()
        del args["consequences"]["targets"]
        self.expect_code("EFFECT_SCOPE_REQUIRED",args)
    def test_no_quote_is_no_permission(self):
        self.enable()
        args=self.grant()
        args["owner_chat_permission"]["quote"]=""
        self.expect_code("CHAT_PERMISSION_QUOTE_REQUIRED",args)
    def test_identity_missing_still_denied(self):
        self.enable()
        args=self.grant()
        del args["task_id"]
        self.expect_code("CHAT_PERMISSION_IDENTITY_INVALID",args)
    def test_no_policy_wiring_remains_signed_only(self):
        self.enable()
        protected=guard_effect(FakeCore,self.store,"kill_process",self.act)
        with self.assertRaises(FakeCore.RPCError) as cm:
            protected(self.grant())
        self.assertEqual(cm.exception.code,"CHAT_PERMISSION_DISABLED")
        self.assertEqual(self.calls,[])
    def test_unprotected_rpc_needs_no_signature_or_chat_permission(self):
        class OrdinaryCore(FakeCore):
            @staticmethod
            def code_blocked(lang,code): return False
        def ordinary(args):
            self.assertFalse(APPROVED_EFFECT.get())
            return {"ok":True}
        wrapped=guard_effect(OrdinaryCore,self.store,"run_code",ordinary,chat_permission=self.policy)
        self.assertEqual(wrapped({"agent_id":"agent-a","task_id":"task-a","code":"print(1)"}),{"ok":True})

if __name__=="__main__":
    unittest.main()
