"""Scoped hidden-Chrome Hub permission for a verified Windows Bridge gateway.

No running Windows, Chrome or installed key is touched.
"""
from __future__ import annotations
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
RUNTIME=pathlib.Path(__file__).resolve().parents[1]/"runtime"/"bridge-v3"
sys.path.insert(0,str(RUNTIME))
from ff_hub import Hub, AUTO_GATEWAY_RISK_CLASSES
from ff_hub_client_identity import (
    PRINCIPAL, KEY_FILENAME, PROOF_FIELD, ensure_gateway_key,
    sign_gateway_request, verify_gateway_request,
)
from ff_hub_permissions import RISK_CLASSES
from ff_hub_store import HubError


class KeyBootstrap(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name)

    def test_gateway_creates_exactly_one_private_key(self):
        self.assertFalse((self.root/KEY_FILENAME).exists())
        self.assertTrue(ensure_gateway_key(self.root))
        value=(self.root/KEY_FILENAME).read_text(encoding="ascii").strip()
        self.assertEqual(len(bytes.fromhex(value)),32)
        self.assertFalse(ensure_gateway_key(self.root))
        self.assertEqual((self.root/KEY_FILENAME).read_text(encoding="ascii").strip(),value)
        req={"op":"session_open","args":{"agent_id":"chat-A","task_id":"task-1"}}
        signed=sign_gateway_request(req,self.root)
        self.assertEqual(verify_gateway_request(signed,self.root),PRINCIPAL)
        self.assertNotIn(PROOF_FIELD,req)

    @unittest.skipUnless(os.name == "nt", "Windows DACL")
    def test_created_key_has_protected_windows_acl(self):
        import os
        import subprocess
        ensure_gateway_key(self.root)
        path = str(self.root / KEY_FILENAME).replace("'", "''")
        ps = (
            "$a=Get-Acl -LiteralPath '" + path + "';"
            "$d=@{Protected=$a.AreAccessRulesProtected;"
            "Entries=@($a.Access|ForEach-Object {"
            "@{Name=$_.IdentityReference.Value;Inherited=$_.IsInherited;"
            "Rights=$_.FileSystemRights.ToString()}})};"
            "$d|ConvertTo-Json -Compress -Depth 5"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        acl = json.loads(result.stdout)
        self.assertTrue(acl["Protected"])
        entries = acl["Entries"]
        self.assertEqual(len(entries), 3, entries)
        self.assertTrue(all(not entry["Inherited"] for entry in entries))
        self.assertTrue(all(entry["Rights"] == "FullControl" for entry in entries))

    def test_invalid_file_is_never_overwritten(self):
        key=self.root/KEY_FILENAME
        key.write_text("invalid key",encoding="ascii")
        with self.assertRaises(ValueError):
            ensure_gateway_key(self.root)
        self.assertEqual(key.read_text(encoding="ascii"),"invalid key")

    def test_signature_cannot_be_supplied_by_untrusted_caller(self):
        ensure_gateway_key(self.root)
        req={"op":"permission_check","args":{}}
        with self.assertRaises(ValueError):
            sign_gateway_request({**req,PROOF_FIELD:{"principal":PRINCIPAL}},self.root)
        self.assertIsNone(verify_gateway_request(req,self.root))


class FullPermissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=pathlib.Path(self.tmp.name)
        ensure_gateway_key(self.path)
        self.hub=Hub(self.path)
        self.addCleanup(self.close)

    def close(self):
        self.hub.shutdown()
        self.hub.store.close()

    def call(self,data,signed=False):
        return self.hub.dispatch(sign_gateway_request(data,self.path) if signed else data)

    def open(self,agent,signed):
        return self.call({"op":"session_open","args":{"agent_id":agent,"task_id":"task-"+agent}},signed)

    def decision(self,session,risk_class,host="example.com",signed=True):
        return self.call({"op":"permission_check","args":{"risk_class":risk_class,"target":{
            "host":host,"path":r"C:\Owner\Project","app":"notepad.exe","secret":"demo"
        }},"session_id":session["session_id"],"session_secret":session["session_secret"]},signed)

    def test_any_distinct_chat_agents_auto_allowed_without_grants(self):
        a=self.open("chat-auto-A",True)
        b=self.open("chat-auto-B",True)
        self.assertNotEqual(a["session_id"],b["session_id"])
        self.assertEqual(self.hub.policy.describe()["grants"],[])
        for session in (a,b):
            self.assertEqual(AUTO_GATEWAY_RISK_CLASSES, frozenset({
                "owner_chrome_hidden_secondary", "browser_script", "read_diagnose", "own_resources",
            }))
            for risk in RISK_CLASSES:
                result=self.decision(session,risk)
                if risk in AUTO_GATEWAY_RISK_CLASSES:
                    self.assertEqual(result["decision"],"allow",(risk,result))
                    self.assertEqual(result["reason"],"TRUSTED_WINDOWS_BRIDGE_GATEWAY")
                    self.assertIsNone(result["grant_id"])
                else:
                    # Preserve each class's pre-existing base policy; never add
                    # a new gateway-wide allow for classes outside this scope.
                    self.assertNotEqual(result["reason"],"TRUSTED_WINDOWS_BRIDGE_GATEWAY")
                    unsigned=self.decision(session,risk,signed=False)
                    self.assertEqual(result["decision"],unsigned["decision"],(risk,result,unsigned))
            self.assertEqual(self.decision(session,"owner_chrome_hidden_secondary",host="new.example")["decision"],"allow")
            self.assertEqual(self.decision(session,"browser_script",host="any.example")["decision"],"allow")

    def test_sensitive_effects_never_inherit_gateway_permission(self):
        session=self.open("chat-auto-sensitive",True)
        for risk in ("financial", "external_send", "system_settings", "delete_user_data",
                     "secret_use", "project_write", "terminal_execute", "foreground_input",
                     "app_launch"):
            with self.subTest(risk=risk):
                self.assertEqual(self.decision(session,risk)["decision"],"needs_owner")
        baseline=self.decision(session,"browser_own_tabs",signed=False)
        signed=self.decision(session,"browser_own_tabs",signed=True)
        self.assertEqual(signed["decision"],baseline["decision"])
        self.assertNotEqual(signed["reason"],"TRUSTED_WINDOWS_BRIDGE_GATEWAY")

    def test_unverified_client_cannot_inherit_trusted_gateway_even_same_session(self):
        s=self.open("chat-auto-A",True)
        trusted=self.decision(s,"owner_chrome_hidden_secondary",signed=True)
        plain=self.decision(s,"owner_chrome_hidden_secondary",signed=False)
        self.assertEqual(trusted["decision"],"allow")
        self.assertEqual(plain["decision"],"needs_owner")
        self.assertNotIn("verified_client_principal",plain)
        self.assertEqual(self.decision(s,"financial",signed=False)["decision"],"needs_owner")
        self.assertEqual(self.decision(s,"external_send",signed=False)["decision"],"needs_owner")

    def test_spoofed_agent_id_or_signature_is_refused(self):
        with self.assertRaises(HubError):
            self.open(PRINCIPAL,False)
        s=self.open("chat-auto-B",False)
        tampered=sign_gateway_request({"op":"permission_check","args":{"risk_class":"browser_script"},
            "session_id":s["session_id"],"session_secret":s["session_secret"]},self.path)
        tampered["args"]["risk_class"]="financial"
        with self.assertRaises(HubError):
            self.hub.dispatch(tampered)

    def test_all_own_sessions_still_require_correct_secret(self):
        a=self.open("chat-auto-A",True)
        b=self.open("chat-auto-B",True)
        request={"op":"permission_check","args":{"risk_class":"owner_chrome_hidden_secondary"},
           "session_id":a["session_id"],"session_secret":b["session_secret"]}
        with self.assertRaises(HubError):
            self.call(request,True)

    def test_redirect_target_has_fresh_trust_for_authenticated_connector(self):
        self.assertTrue(self.hub._host_allowed_for_provider(PRINCIPAL,
            "owner_chrome_profile1_hidden_secondary","example.com"))


if __name__=="__main__":unittest.main()
