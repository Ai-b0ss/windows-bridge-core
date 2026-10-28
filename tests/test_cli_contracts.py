import pathlib
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from cua_cli_contracts import probe_vendor_cli
from cua_bridge_v3 import CuaBridgeControlPlane,CuaBridgeError


class FakeRunner:
    def __init__(self):
        self.calls=[]

    def __call__(self,argv,**kwargs):
        self.calls.append((tuple(argv),dict(kwargs)))
        if "--version" in argv:
            output=b"2026.10.19-abcdef\n" if "agent.cmd" in str(argv[0]) else b"agy 1.4.7"
            return SimpleNamespace(returncode=0,stdout=output,stderr=b"")
        if "--help" in argv:
            return SimpleNamespace(returncode=0,stdout=b"Usage: agent --print --mode --output-format --sandbox",
                                   stderr=b"")
        if tuple(argv[1:]) == ("models",):
            return SimpleNamespace(returncode=0, stdout=b"composer-2.5  grok-4.7\nsecret-person@example.net\n", stderr=b"")
        if "status" in argv:
            return SimpleNamespace(returncode=0,stdout=b"Logged in as secret-person@example.net\n",
                                   stderr=b"")
        raise AssertionError("Unapproved subprocess flags")


class TestVendorCliContracts(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.root=pathlib.Path(self.t.name)
        cursor=self.root/"cursor-agent"/"agent.cmd"
        cursor.parent.mkdir(parents=True)
        cursor.write_bytes(b"@echo off\r\nexit /b 0\r\n")
        agy=self.root/"agy"/"bin"/"agy.exe"
        agy.parent.mkdir(parents=True)
        agy.write_bytes(b"stub-test-binary")

    def test_cursor_status_redacts_account_and_is_explicit_opt_in(self):
        runner=FakeRunner()
        passive=probe_vendor_cli("Cursor",runner=runner,local_appdata=self.root)
        self.assertEqual(passive["service_auth"],"not_checked")
        self.assertEqual(len(runner.calls),2)
        active=probe_vendor_cli("Cursor",runner=runner,local_appdata=self.root,
                                include_auth_status=True)
        self.assertEqual(active["service_auth"],"authenticated")
        self.assertEqual(active["version"],"2026.10.19")
        self.assertTrue(active["help_checked"])
        self.assertIn("headless_print",active["supported_by_help"])
        self.assertEqual(len(runner.calls),5)
        self.assertNotIn("secret-person",str(active))
        self.assertNotIn(str(self.root),str(active))
        for key in ("model_called","paid_api_invoked","task_completed",
                    "quota_and_pricing_verified","authenticated_task_execution_verified"):
            self.assertFalse(active[key])
        self.assertTrue(all("timeout" in args for _,args in runner.calls))
        self.assertTrue(all(args["stdin"] is subprocess.DEVNULL for _,args in runner.calls))

    def test_cursor_model_inventory_is_explicit_redacted_and_not_entitlement(self):
        runner = FakeRunner()
        passive = probe_vendor_cli("Cursor", runner=runner, local_appdata=self.root)
        self.assertEqual(len(runner.calls), 2)
        self.assertFalse(passive["models_list_checked"])
        self.assertEqual(passive["observed_cursor_models"], [])
        checked = probe_vendor_cli("Cursor", runner=runner, local_appdata=self.root,
                                   include_model_listing=True)
        self.assertTrue(checked["models_list_checked"])
        self.assertEqual(checked["observed_cursor_models"], ["composer-2.5", "grok-4.7"])
        self.assertFalse(checked["quota_and_pricing_verified"])
        self.assertFalse(checked["model_called"])
        self.assertFalse(checked["task_completed"])
        self.assertNotIn("secret-person", str(checked))
        self.assertEqual(runner.calls[-1][0][1:], ("models",))
        self.assertLessEqual(runner.calls[-1][1]["timeout"], 30)

    def test_antigravity_output_flags_and_no_auth_touch(self):
        runner=FakeRunner()
        info=probe_vendor_cli("Antigravity",runner=runner,local_appdata=self.root,
                              include_auth_status=True)
        self.assertEqual(info["app_family"],"antigravity")
        self.assertTrue(info["path_verified"])
        self.assertIn("output_json",info["supported_by_help"])
        self.assertEqual(len(runner.calls),2)
        self.assertEqual(info["service_auth"],"not_checked")

    def test_malicious_app_name_not_executed(self):
        runner=FakeRunner()
        info=probe_vendor_cli("evil-new-app --run",runner=runner,local_appdata=self.root)
        self.assertEqual(info["app_family"],"unknown")
        self.assertFalse(info["path_verified"])
        self.assertEqual(runner.calls,[])

    def test_fake_vendor_path_not_executed(self):
        root=self.root/"test%path"
        tool=root/"cursor-agent"/"agent.cmd"
        tool.parent.mkdir(parents=True)
        tool.write_bytes(b"not a trusted shim")
        runner=FakeRunner()
        info=probe_vendor_cli("Cursor",runner=runner,local_appdata=root)
        self.assertFalse(info["path_verified"])
        self.assertEqual(runner.calls,[])

    def test_missing_vendor_executable_still_no_gui(self):
        runner=FakeRunner()
        (self.root/"agy"/"bin"/"agy.exe").unlink()
        info=probe_vendor_cli("Antigravity",runner=runner,local_appdata=self.root)
        self.assertEqual(info["next_gate"],"official_cli_missing_or_untrusted_path")
        self.assertFalse(info["path_verified"])
        self.assertEqual(runner.calls,[])

    def test_timeout_does_not_invent_support(self):
        def timeout(argv,**kwargs):
            raise subprocess.TimeoutExpired(argv,0.01)
        out=probe_vendor_cli("Cursor",runner=timeout,local_appdata=self.root,
                             include_auth_status=True)
        self.assertFalse(out["help_checked"])
        self.assertIsNone(out["version"])
        self.assertEqual(out["service_auth"],"not_checked")

    def test_status_negative_and_unknown_not_conflated(self):
        class Negative(FakeRunner):
            def __call__(self,argv,**kwargs):
                if "status" in argv:
                    return SimpleNamespace(returncode=0,stdout=b"Not logged in",stderr=b"")
                return super().__call__(argv,**kwargs)
        result=probe_vendor_cli("cursor",runner=Negative(),local_appdata=self.root,
                                include_auth_status=True)
        self.assertEqual(result["service_auth"],"not_authenticated")


class TestUnifiedProbeWiring(unittest.TestCase):
    def test_flag_controls_which_probes_are_allowed(self):
        from test_task_preflight_unified import FakePlane
        plane=FakePlane()
        info={
            "schema":"ff-cli-contract-v1","app_family":"cursor",
            "path_verified":True,"model_called":False,
        }
        with patch("cua_cli_contracts.probe_vendor_cli",return_value=info) as method:
            no_probe=plane._task_preflight({"app":"cursor","task":"read-only"})
            self.assertIsNone(no_probe["cli_contract"])
            self.assertFalse(no_probe["external_cli_readonly_probe_requested"])
            self.assertEqual(method.call_count,0)
            active=plane._task_preflight({
                "app":"Cursor","task":"read-only",
                "verify_cli_contract":True,"include_auth_status":True,
            })
            self.assertEqual(active["cli_contract"],info)
            self.assertTrue(active["external_cli_readonly_probe_requested"])
            method.assert_called_once_with("Cursor",include_auth_status=True,include_model_listing=False)

    def test_bad_flag_fails_closed(self):
        from test_task_preflight_unified import FakePlane
        with self.assertRaises(CuaBridgeError) as cm:
            FakePlane()._task_preflight({"app":"cursor","task":"read",
                                         "verify_cli_contract":"true"})
        self.assertEqual(cm.exception.code,"CLI_CONTRACT_PROBE_FLAG_INVALID")
        with self.assertRaises(CuaBridgeError):
            FakePlane()._task_preflight({"app":"Cursor","task":"read",
                                         "include_model_listing":True})
        with self.assertRaises(CuaBridgeError):
            FakePlane()._task_preflight({"app":"Cursor","task":"read",
                                         "include_model_listing":"yes"})


if __name__=="__main__":
    unittest.main()
