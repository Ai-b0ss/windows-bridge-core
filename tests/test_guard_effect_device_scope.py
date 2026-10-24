"""Exercise the actual guarded RPC wrapper without mutating Windows."""
import pathlib
import sys
import tempfile
import unittest
import time

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from cua_task_authority import AuthorityStore, AuthorityError, guard_effect, invocation, APPROVED_EFFECT


class FakeCore:
    class RPCError(RuntimeError):
        def __init__(self, code, details=None):
            self.code=code
            self.details=dict(details or {})
            super().__init__(code)

    @staticmethod
    def command_blocked(value):
        return False

    @staticmethod
    def code_blocked(language,code):
        return False


class TestDeviceBoundGuardEffect(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.store=AuthorityStore(self.t.name,device_id="WIN-ONE")
        self.calls=[]
        self.args={
            "agent_id":"agent-a",
            "task_id":"task-a",
            "pid":4242,
            "consequences":{
                "kind":"destructive","purpose":"owned test process termination",
                "targets":["synthetic-pid-4242"],"risk":"test-only",
            },
        }

    def original(self,args):
        self.calls.append(dict(args))
        self.assertTrue(APPROVED_EFFECT.get())
        return {"ok":True}

    def signed_decision_record(self,args):
        request=invocation("kill_process",args)
        decision={
            "schema":"ff-local-desktop-delegation-v1",
            "agent":"agent-a",
            "task":"task-a",
            "request":request,
            "approval_reference":"synthetic-controller-confirmation",
            "device":"WIN-ONE","nonce":"unique-1",
            "expires":time.time()+120,"uses":1,
        }
        # Only this test code reaches the internal fixture. In production the
        # controller must attest the receipt, never use raw agent args.
        return self.store._record_approval(decision)

    def test_guard_does_not_accept_agent_boolean(self):
        guarded=guard_effect(FakeCore,self.store,"kill_process",self.original)
        with self.assertRaises(FakeCore.RPCError) as cm:
            guarded({**self.args,"approved":True})
        self.assertIn(cm.exception.code,{"OWNER_APPROVAL_REQUIRED","APPROVAL_STORAGE_UNAVAILABLE"})
        self.assertEqual(self.calls,[])
        self.assertEqual(cm.exception.details.get("execution_started"),False)

    def test_verified_grant_allows_only_matching_mutation_once(self):
        grant=self.signed_decision_record(self.args)
        guarded=guard_effect(FakeCore,self.store,"kill_process",self.original)
        args={**self.args,"authorization_id":grant}
        self.assertEqual(guarded(args),{"ok":True})
        self.assertFalse(APPROVED_EFFECT.get())
        with self.assertRaises(FakeCore.RPCError) as cm:
            guarded(args)
        self.assertEqual(cm.exception.code,"OWNER_APPROVAL_EXPIRED_OR_CONSUMED")
        self.assertEqual(len(self.calls),1)

    def test_wrong_operation_scope_fails_without_mutation(self):
        grant=self.signed_decision_record(self.args)
        guarded=guard_effect(FakeCore,self.store,"kill_process",self.original)
        wrong={**self.args,"pid":9999,"authorization_id":grant}
        with self.assertRaises(FakeCore.RPCError) as cm:
            guarded(wrong)
        self.assertEqual(cm.exception.code,"OWNER_APPROVAL_SCOPE_MISMATCH")
        self.assertFalse(self.calls)

    def test_device_scope_mismatch_fails_without_mutation(self):
        grant=self.signed_decision_record(self.args)
        b=AuthorityStore(self.t.name,device_id="WIN-TWO")
        guarded=guard_effect(FakeCore,b,"kill_process",self.original)
        with self.assertRaises(FakeCore.RPCError) as cm:
            guarded({**self.args,"authorization_id":grant})
        self.assertEqual(cm.exception.code,"OWNER_APPROVAL_DEVICE_MISMATCH")
        self.assertEqual(self.calls,[])


if __name__=="__main__":
    unittest.main()
