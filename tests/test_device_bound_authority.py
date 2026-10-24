"""P0 Device-bound grants: test trust boundary, replay, revocation and expiry."""
import base64
import pathlib
import sys
import tempfile
import time
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from cua_task_authority import AuthorityStore, AuthorityError, canonical

try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes
except ImportError:
    rsa = padding = hashes = None


def payload(device="WIN-A", *, nonce="nonce-01", uses=1, expires=None):
    exact={
        "op":"set_desktop_mode",
        "args":{
            "mode":"dedicated","targets":[],
            "agent_id":"agent-01","task_id":"task-01",
        },
    }
    return {
        "schema":"ff-owner-approval-v1",
        "device":device,
        "agent":"agent-01","task":"task-01",
        "request":exact,"approval_reference":"trusted-owner-chat-confirmation",
        "nonce":nonce,
        "uses":uses,
        "expires":time.time()+240 if expires is None else expires,
    }


class TestBoundAuthority(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="bound-owner-grant-")
        self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name)

    def store(self,device="WIN-A",pubkey=None):
        return AuthorityStore(self.root,device_id=device,public_key=pubkey)

    def test_exact_device_scoped_grant_no_cross_machine_replay(self):
        data=payload()
        a=self.store("WIN-A")
        grant=a._record_approval(data)  # trusted-controller-internal test, NOT signature proof
        b=self.store("WIN-B")
        with self.assertRaisesRegex(AuthorityError,"DEVICE_MISMATCH"):
            b.consume(grant,agent=data["agent"],task=data["task"],request=data["request"])
        self.assertGreater(a.consume(grant,agent=data["agent"],task=data["task"],request=data["request"]),time.time())

    def test_missing_and_wrong_device_denied_before_storage(self):
        store=self.store("WIN-A")
        raw=payload()
        del raw["device"]
        with self.assertRaisesRegex(AuthorityError,"DEVICE_REQUIRED"):
            store._record_approval(raw)
        raw["device"]="WIN-B"
        with self.assertRaisesRegex(AuthorityError,"DEVICE_MISMATCH"):
            store._record_approval(raw)

    def test_wrong_target_and_replay_and_reprovision_no_topup(self):
        a=self.store("WIN-A")
        data=payload(uses=1)
        grant=a._record_approval(data)
        changed={**data["request"],"args":{**data["request"]["args"],"targets":[{"hwnd":1234}]}}
        with self.assertRaisesRegex(AuthorityError,"SCOPE_MISMATCH"):
            a.consume(grant,agent=data["agent"],task=data["task"],request=changed)
        self.assertGreater(a.consume(grant,agent=data["agent"],task=data["task"],request=data["request"]),time.time())
        with self.assertRaisesRegex(AuthorityError,"EXPIRED_OR_CONSUMED"):
            a.consume(grant,agent=data["agent"],task=data["task"],request=data["request"])
        self.assertEqual(a._record_approval(data),grant)
        with self.assertRaisesRegex(AuthorityError,"EXPIRED_OR_CONSUMED"):
            a.consume(grant,agent=data["agent"],task=data["task"],request=data["request"])

    def test_revocation_permanent_even_if_receipt_reimported(self):
        a=self.store("WIN-A")
        data=payload(uses=5)
        grant=a._record_approval(data)
        self.assertTrue(a.revoke(grant))
        with self.assertRaisesRegex(AuthorityError,"REVOKED"):
            a.consume(grant,agent=data["agent"],task=data["task"],request=data["request"])
        a._record_approval(data)
        with self.assertRaisesRegex(AuthorityError,"REVOKED"):
            a.consume(grant,agent=data["agent"],task=data["task"],request=data["request"])
        self.assertFalse(a.revoke("0"*64))

    def test_bad_expiration_and_not_before_types_rejected(self):
        a=self.store()
        for arg in ({"expires":time.time()-1},
                    {"not_before":"tomorrow"},
                    {"not_before":time.time()+60},
                    {"uses":True}):
            with self.subTest(arg=arg):
                data={**payload(),**arg}
                with self.assertRaisesRegex(AuthorityError,"LIMIT_INVALID"):
                    a._record_approval(data)

    def test_existing_legacy_unbound_approvals_never_migrated(self):
        import sqlite3
        db=self.root/"owner-approvals.sqlite3"
        from contextlib import closing
        with closing(sqlite3.connect(db)) as con:
            con.execute("CREATE TABLE approvals (id TEXT PRIMARY KEY, agent TEXT, task TEXT, digest TEXT, expires REAL, uses INTEGER, reference TEXT)")
            con.execute("INSERT INTO approvals VALUES ('old', 'agent-01','task-01','oldhash',?,?,?)",
                        (time.time()+999,3,"old-legacy"))
        data=payload()
        a=self.store()
        with self.assertRaisesRegex(AuthorityError,"OWNER_APPROVAL_REQUIRED"):
            a.consume("old",agent=data["agent"],task=data["task"],request=data["request"])

    def test_unsigned_agent_claim_never_provisions(self):
        store=self.store(pubkey=None)
        # Explicitly missing configured trusted verifier.
        with self.assertRaisesRegex(AuthorityError,"VERIFIER_NOT_CONFIGURED"):
            store.provision(signed_approval={"approved":True,**payload()})

    @unittest.skipUnless(rsa is not None,"cryptography optional; device tests still run")
    def test_real_rsa_signed_receipt_and_tamper_rejection(self):
        private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        public=private.public_key().public_numbers()
        key={"n":format(public.n,"x"),"e":str(public.e)}
        store=self.store(pubkey=key)
        data=payload()
        sig=private.sign(canonical(data).encode(),padding.PKCS1v15(),hashes.SHA256())
        signed={**data,"signature":base64.b64encode(sig).decode("ascii")}
        grant=store.provision(signed_approval=signed)
        self.assertGreater(store.consume(grant,agent=data["agent"],task=data["task"],request=data["request"]),time.time())
        altered={**signed,"device":"WIN-B"}
        with self.assertRaisesRegex(AuthorityError,"SIGNATURE_INVALID"):
            store.provision(signed_approval=altered)
        signed_wrong={**payload(device="WIN-B",nonce="n-2")}
        sig2=private.sign(canonical(signed_wrong).encode(),padding.PKCS1v15(),hashes.SHA256())
        with self.assertRaisesRegex(AuthorityError,"DEVICE_MISMATCH"):
            store.provision(signed_approval={**signed_wrong,"signature":base64.b64encode(sig2).decode("ascii")})


if __name__=="__main__":
    unittest.main()
