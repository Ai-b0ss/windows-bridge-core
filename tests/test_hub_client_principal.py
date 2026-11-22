"""Regression tests for stable connector authorization across changing chat agent_ids.

No live Windows Bridge, Chrome, or credentials are touched.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"
sys.path.insert(0, str(ROOT))

from ff_hub import Hub
from ff_hub_client_identity import (
    PRINCIPAL, PROOF_FIELD, KEY_FILENAME, sign_gateway_request, verify_gateway_request,
)
from ff_hub_rpc import HubGateway, HubGatewayError
from ff_hub_store import HubError


class ClientProofTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        (self.path / KEY_FILENAME).write_text("92" * 32 + "\n", encoding="ascii")
        self.req = {
            "op": "permission_check", "session_id": "fake", "session_secret": "redacted",
            "args": {"risk_class": "owner_chrome_hidden_secondary", "target": {"host": "example.com"}},
        }

    def test_signature_is_bound_to_request_and_timestamp(self):
        signed = sign_gateway_request(self.req, self.path, now=1000)
        self.assertEqual(verify_gateway_request(signed, self.path, now=1004), PRINCIPAL)
        self.assertNotIn(PROOF_FIELD, self.req)
        self.assertIsNone(verify_gateway_request(self.req, self.path, now=1000))
        self.assertRaises(ValueError, verify_gateway_request, signed, self.path, now=1031)
        changed = json.loads(json.dumps(signed))
        changed["args"]["target"]["host"] = "attacker.example"
        self.assertRaises(ValueError, verify_gateway_request, changed, self.path, now=1002)
        changed = json.loads(json.dumps(signed))
        changed["session_id"] = "someone-else"
        self.assertRaises(ValueError, verify_gateway_request, changed, self.path, now=1002)
        changed = json.loads(json.dumps(signed))
        changed["args"]["risk_class"] = "project_write"
        self.assertRaises(ValueError, verify_gateway_request, changed, self.path, now=1002)

    def test_bogus_principal_and_missing_key_fail_closed(self):
        signed = sign_gateway_request(self.req, self.path, now=1000)
        changed = json.loads(json.dumps(signed))
        changed[PROOF_FIELD]["principal"] = "attacker"
        self.assertRaises(ValueError, verify_gateway_request, changed, self.path, now=1000)
        (self.path / KEY_FILENAME).unlink()
        self.assertEqual(sign_gateway_request(self.req, self.path, now=1000), self.req)
        self.assertRaises(ValueError, verify_gateway_request, signed, self.path, now=1000)

    def test_callers_cannot_inject_gateway_attestation_into_signer(self):
        with self.assertRaises(ValueError):
            sign_gateway_request({**self.req, PROOF_FIELD: {}}, self.path)


class StableClientHubTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        (self.path / KEY_FILENAME).write_text("ac" * 32 + "\n", encoding="ascii")
        self.hub = Hub(self.path)
        self.grant = self.hub.policy.add_grant(
            ["owner_chrome_hidden_secondary", "browser_script"],
            agents=[PRINCIPAL], hosts=["example.com"],
            note="isolated test for stable connected Bridge client",
        )
        self.addCleanup(self.close)

    def close(self):
        self.hub.shutdown()
        self.hub.store.close()

    def call(self, request, signed=False):
        if signed:
            request = sign_gateway_request(request, self.path)
        return self.hub.dispatch(request)

    def session(self, agent, signed=True):
        return self.call({"op": "session_open", "args": {"agent_id": agent, "task_id": "verification-" + agent}}, signed)

    def check(self, session, host="example.com", signed=False, risk_class="owner_chrome_hidden_secondary"):
        return self.call({
            "op": "permission_check", "args": {"risk_class": risk_class, "target": {"host": host}},
            "session_id": session["session_id"], "session_secret": session["session_secret"],
        }, signed)

    def test_gateway_signature_is_verified_once_before_owner_lock(self):
        from unittest.mock import patch
        from ff_hub_client_identity import verify_gateway_request
        request = sign_gateway_request({
            "op": "session_open",
            "args": {"agent_id": "queue-safe-chat", "task_id": "queue-test"},
        }, self.path)
        with patch("ff_hub.verify_gateway_request", wraps=verify_gateway_request) as verify:
            session = self.hub.dispatch(request)
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(session.get("verified_client_principal"), PRINCIPAL)

    def test_two_chat_ids_share_automatic_permission_only_with_verified_gateway(self):
        first = self.session("chatgpt-gpt6-owner-browser")
        second = self.session("chatgpt-hidden-browser-verification")
        self.assertNotEqual(first["session_id"], second["session_id"])
        for session in (first, second):
            self.assertEqual(session.get("verified_client_principal"), PRINCIPAL)
            authorized = self.check(session, signed=True)
            self.assertEqual(authorized["decision"], "allow")
            self.assertEqual(authorized["reason"], "TRUSTED_WINDOWS_BRIDGE_GATEWAY")
            self.assertEqual(authorized["verified_client_principal"], PRINCIPAL)
            self.assertEqual(self.check(session, signed=False)["decision"], "needs_owner")
            self.assertEqual(self.check(session, host="other.example", signed=True)["decision"], "allow")
            self.assertEqual(self.check(session, signed=True, risk_class="project_write")["decision"], "allow")

    def test_revoked_legacy_grant_does_not_revoke_authenticated_gateway(self):
        new_chat = self.session("chat-a")
        self.assertEqual(self.check(new_chat,signed=True)["decision"],"allow")
        self.assertTrue(self.hub.policy.revoke(self.grant["grant_id"]))
        forbidden=self.check(new_chat,signed=True)
        self.assertEqual(forbidden["decision"],"allow")
        self.assertEqual(forbidden["reason"],"TRUSTED_WINDOWS_BRIDGE_GATEWAY")
        self.assertEqual(forbidden["grant_id"],None)
        self.assertEqual(self.check(new_chat,signed=False)["decision"],"needs_owner")

    def test_no_host_grant_is_inferred_from_ready_browser_route(self):
        chat=self.session("chat-foreign")
        allowed=self.call({"op":"route_plan","args":{
            "surface":"browser","capability":"background_tab_read",
            "url":"https://other.example/","visibility":"strict_invisible",
            "agent_id":"chat-foreign"
        }},signed=True)
        self.assertNotEqual(allowed.get("selected_provider"),"owner_chrome_profile1_hidden_secondary")

    def test_forbidden_injected_proof_does_not_execute(self):
        session=self.session("new-chat")
        request={"op":"permission_check","args":{"risk_class":"owner_chrome_hidden_secondary",
                 "target":{"host":"example.com"}},"session_id":session["session_id"],
                 "session_secret":session["session_secret"]}
        signed=sign_gateway_request(request,self.path)
        signed["args"]["target"]["host"]="other.example"
        with self.assertRaises(HubError) as exc:
            self.hub.dispatch(signed)
        self.assertEqual(exc.exception.code,"GATEWAY_ATTESTATION_INVALID")

    def test_reserved_principal_name_cannot_be_claimed_as_agent_id(self):
        for signed in (False, True):
            with self.assertRaises(HubError) as exc:
                self.session(PRINCIPAL, signed=signed)
            self.assertEqual(exc.exception.code,"IDENTITY_RESERVED")

    def test_all_sites_and_all_agents_not_implicitly_granted(self):
        anon=self.session("unrelated-local-agent",signed=False)
        self.assertEqual(self.check(anon,signed=False)["decision"],"needs_owner")
        self.assertEqual(self.check(anon,signed=True)["decision"],"allow")
        self.assertNotIn("project_write",self.hub.policy.describe().get("classes",{}).get("owner_chrome_hidden_secondary",{}))

    def test_unverified_session_does_not_persist_a_principal(self):
        session=self.session("anonymous-agent",signed=False)
        self.assertNotIn("verified_client_principal",session)
        self.assertEqual(self.check(session,signed=True)["decision"],"allow")
        self.assertEqual(self.check(session,signed=False)["decision"],"needs_owner")

    def test_hidden_open_read_close_isolated_across_chat_sessions(self):
        class FakeOwner:
            profile_dir_name = "Default"
            calls = []
            def call(self, op, args, timeout=30):
                self.calls.append((op, dict(args)))
                if op == "open":
                    return {
                        "tab_id": "hsec-test-" + str(len(self.calls)),
                        "target_id": "target-test-" + str(len(self.calls)),
                        "url": args["url"], "hidden": True, "windowless": True,
                        "profile_dir_name": "Default",
                    }
                if op == "read":
                    return {"url": "https://example.com/", "text": "Example Domain"}
                if op == "close":
                    return {"closed": True, "target_closed_in_browser": True}
                if op == "list":
                    return {"tabs": []}
                return {"ok": True}
            def status(self):
                return {"connected": True, "profile_dir_name": "Default"}
            def close(self):
                pass
        fake = FakeOwner()
        self.hub.owner_chrome_secondary = fake
        a = self.session("chat-first", signed=True)
        b = self.session("chat-second", signed=True)

        def browser(sess, command, tab_id=None, signed=True, key=None):
            args={"command":command}
            if command=="open":
                args.update(url="https://example.com/",profile_dir_name="Default")
            if tab_id:
                args["tab_id"]=tab_id
            req={"op":"owner_chrome_hidden","args":args,
                 "session_id":sess["session_id"],"session_secret":sess["session_secret"]}
            if key:
                req["request_key"]=key
            return self.call(req,signed=signed)

        with self.assertRaises(HubError) as unauth:
            browser(a,"open",signed=False,key="chat-first-unauth-open")
        self.assertEqual(unauth.exception.code,"PERMISSION_REQUIRED")
        first = browser(a,"open",key="chat-first-open")
        second = browser(b,"open",key="chat-second-open")
        self.assertNotEqual(first["tab_id"],second["tab_id"])
        for sess,tab in ((a,first),(b,second)):
            r=browser(sess,"read",tab["tab_id"])
            self.assertEqual(r["text"],"Example Domain")
        with self.assertRaises(HubError) as foreign:
            browser(a,"read",second["tab_id"])
        self.assertEqual(foreign.exception.code,"RESOURCE_NOT_OWNED")
        for sess,tab in ((a,first),(b,second)):
            closed=browser(sess,"close",tab["tab_id"],key="close-"+tab["tab_id"])
            self.assertTrue(closed["target_closed_in_browser"])
            self.assertEqual(self.hub.store.resources(session_id=sess["session_id"]),[])
        self.assertEqual([op for op,_ in fake.calls].count("open"),2)
        self.assertEqual([op for op,_ in fake.calls].count("close"),2)

    def test_gateway_only_signs_when_owner_local_key_present(self):
        self.temp_bridge=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_bridge.cleanup)
        root=Path(self.temp_bridge.name)
        state=root/"state"/"hub"
        state.mkdir(parents=True)
        (state/KEY_FILENAME).write_bytes((self.path/KEY_FILENAME).read_bytes())
        (root/"state"/"universal-agent-runtime.json").write_text('{"version":1,"enabled":true}',encoding="utf-8")
        observed=[]
        class Client:
            def __init__(self,path): pass
            def raw(self,request):
                observed.append(request)
                return {"ok":True,"result":{"ok":True}}
        gateway=HubGateway(root,client_factory=Client,starter=lambda state:None)
        request={"op":"session_open","args":{"agent_id":"new-chat","task_id":"test"}}
        gateway.call(request)
        self.assertEqual(verify_gateway_request(observed[0],state),PRINCIPAL)
        self.assertNotIn(PROOF_FIELD,request)
        with self.assertRaises(HubGatewayError) as exc:
            gateway.call({**request,PROOF_FIELD:{"forged":True}})
        self.assertEqual(exc.exception.code,"HUB_REQUEST_INVALID")
        self.assertEqual(len(observed),1)


if __name__=="__main__":
    unittest.main()
