import base64
from pathlib import Path
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from cua_chat_consent import ChatConsentBroker, ChatConsentError, SCHEMA
from cua_task_authority import AuthorityStore, AuthorityError, canonical

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
except ImportError:
    rsa=padding=hashes=None


def action():
    return {"agent_id":"owner-agent","task_id":"claude-usage-20261030",
            "mode":"dedicated","targets":[]}


class ConsentTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix="ff-chat-consent-")
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)

    def make(self, pub=None, device="WIN-TEST"):
        auth=AuthorityStore(self.root/"authority",public_key=pub,device_id=device)
        return ChatConsentBroker(self.root/"consent",auth)

    def test_prepares_scoped_pending_challenge_without_authorizing(self):
        broker=self.make()
        c=broker.prepare("set_desktop_mode",action())
        self.assertEqual(c["schema"],SCHEMA)
        self.assertEqual(c["device"],"WIN-TEST")
        self.assertFalse(c["approved"])
        self.assertIsNone(c["authorization_id"])
        self.assertEqual(broker.status(c["challenge_id"])["status"],"awaiting_attested_host_receipt")
        self.assertEqual(list((self.root/"authority").glob("*")),[])

    def test_spoofing_and_unknown_action_rejected(self):
        broker=self.make()
        for op,payload in (
            ("set_desktop_mode",{**action(),"approved":True}),
            ("set_desktop_mode",{**action(),"signed_approval":"fake"}),
            ("set_desktop_mode",{**action(),"mode":"coexist"}),
            ("delete_path",action()),
            ("computer_use",{**action(),"command":"shell"}),
        ):
            with self.subTest(op=op,payload=payload):
                with self.assertRaises(ChatConsentError):
                    broker.prepare(op,payload)
        with self.assertRaisesRegex(ChatConsentError,"ID_INVALID"):
            broker.status("broken")

    def test_unsigned_model_claim_fails_closed(self):
        broker=self.make()
        c=broker.prepare("set_desktop_mode",action())
        with self.assertRaisesRegex(AuthorityError,"VERIFIER_NOT_CONFIGURED"):
            broker.commit(c["challenge_id"],{"approved":True})
        self.assertEqual(broker.status(c["challenge_id"])["status"],"awaiting_attested_host_receipt")

    def test_expired_challenge_rejected(self):
        broker=self.make()
        c=broker.prepare("set_desktop_mode",action())
        import sqlite3
        from contextlib import closing
        with closing(sqlite3.connect(broker.path)) as con:
            con.execute("UPDATE requests SET expires=? WHERE id=?", (time.time()-1,c["challenge_id"]))
            con.commit()
        with self.assertRaisesRegex(ChatConsentError,"EXPIRED"):
            broker.commit(c["challenge_id"],{})
        self.assertEqual(broker.status(c["challenge_id"])["status"],"expired")

    @unittest.skipUnless(rsa is not None, "optional RSA test package absent")
    def test_signed_host_receipt_bound_to_challenge_and_no_replay(self):
        private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        numbers=private.public_key().public_numbers()
        key={"n":format(numbers.n,"x"),"e":numbers.e}
        broker=self.make(pub=key)
        c=broker.prepare("set_desktop_mode",action())
        payload={
            "schema":"ff-owner-approval-v1",
            "device":c["device"],"agent":c["agent_id"],"task":c["task_id"],
            "request":{"op":"set_desktop_mode","args":action()},
            "approval_reference":"host-chat:"+c["challenge_id"],
            "nonce":c["challenge_id"],"uses":1,"expires":time.time()+60,
        }
        def sign(data):
            return {**data,"signature":base64.b64encode(
                private.sign(canonical(data).encode(),padding.PKCS1v15(),hashes.SHA256())
            ).decode()}
        for name,edit in (
            ("wrong-agent",{"agent":"other"}),
            ("wrong-request",{"request":{"op":"set_desktop_mode","args":{**action(),"targets":[{"hwnd":1}]}}}),
            ("wrong-reference",{"approval_reference":"agent-owned"}),
            ("wrong-device",{"device":"WIN-OTHER"}),
            ("wrong-nonce",{"nonce":"different"}),
            ("multiple-uses",{"uses":5}),
            ("late-expiry",{"expires":c["expires_at"]+5}),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ChatConsentError):
                    broker.commit(c["challenge_id"],sign({**payload,**edit}))
        signed=sign(payload)
        answer=broker.commit(c["challenge_id"],signed)
        self.assertTrue(answer["approval_granted"])
        self.assertEqual(broker.status(c["challenge_id"])["status"],"committed")
        with self.assertRaisesRegex(ChatConsentError,"REPLAY"):
            broker.commit(c["challenge_id"],signed)
        expires=broker.authority.consume(answer["authorization_id"],agent=c["agent_id"],task=c["task_id"],request=payload["request"])
        self.assertGreater(expires,time.time())
        with self.assertRaisesRegex(AuthorityError,"EXPIRED_OR_CONSUMED"):
            broker.authority.consume(answer["authorization_id"],agent=c["agent_id"],task=c["task_id"],request=payload["request"])


if __name__ == "__main__":
    unittest.main()
