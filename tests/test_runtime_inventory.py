import pathlib
import sys
import tempfile
import unittest
import zipfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from runtime_inventory import compare,TRACKED
import hashlib
from unittest.mock import patch


class TestVersionInventory(unittest.TestCase):
    def test_three_way_readonly_comparison(self):
        with tempfile.TemporaryDirectory() as td:
            temp=pathlib.Path(td)
            source=temp/"source"
            live=temp/"live"
            source.mkdir()
            live.mkdir()
            (source/"cua_router.py").write_bytes(b"public")
            (live/"cua_router.py").write_bytes(b"installed")
            (live/"private-token.json").write_text("KEEP PRIVATE",encoding="utf-8")
            archive=temp/"package.zip"
            with zipfile.ZipFile(archive,"w") as z:
                z.writestr("runtime/bridge-v3/cua_router.py",b"public")
            result=compare(source,live,archive,names=("cua_router.py",))
            self.assertTrue(result["read_only"])
            self.assertFalse(result["all_live_equal_source"])
            self.assertFalse(result["running_process_verified"])
            self.assertEqual(result["inventory_scope"], "allowlisted_installed_files_only")
            self.assertEqual(result["package"]["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(result["package"]["size"], archive.stat().st_size)
            self.assertTrue(result["modules"][0]["matches"]["source_equals_package"])
            self.assertFalse(result["modules"][0]["matches"]["source_equals_live"])
            self.assertNotIn("KEEP PRIVATE",str(result))
            self.assertEqual((live/"private-token.json").read_text(encoding="utf-8"),"KEEP PRIVATE")

    def test_directory_escape_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            temp=pathlib.Path(td)
            (temp/"source").mkdir()
            (temp/"live").mkdir()
            with zipfile.ZipFile(temp/"package.zip","w") as z:
                z.writestr("placeholder",b"")
            with self.assertRaisesRegex(ValueError,"non-allowlisted"):
                compare(temp/"source",temp/"live",temp/"package.zip",names=("../private.json",))

    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = pathlib.Path(temporary.name)
        source, installed, archive = root/"source", root/"installed", root/"package.zip"
        source.mkdir()
        installed.mkdir()
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("placeholder", b"")
        return source, installed, archive

    def test_no_vacuous_success_or_duplicate_selection(self):
        source, installed, archive = self.fixture()
        for names in ((), ("cua_router.py", "cua_router.py")):
            with self.subTest(names=names), self.assertRaises(ValueError):
                compare(source, installed, archive, names=names)

    def test_valid_python_name_outside_explicit_allowlist_denied(self):
        source, installed, archive = self.fixture()
        (installed/"private_credentials.py").write_text("PRIVATE", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "non-allowlisted"):
            compare(source, installed, archive, names=("private_credentials.py",))

    def test_agent_runtime_drift_cannot_be_hidden_by_matching_main(self):
        source, installed, archive = self.fixture()
        for name in TRACKED:
            (source/name).write_bytes(b"same")
            (installed/name).write_bytes(b"same")
        (installed/"ff_win_v3_agent.py").write_bytes(b"older-detached-executor")
        with zipfile.ZipFile(archive, "w") as z:
            for name in TRACKED:
                z.writestr("runtime/bridge-v3/"+name, b"same")
        result = compare(source, installed, archive)
        self.assertFalse(result["all_installed_equal_source"])
        drift = [r["file"] for r in result["modules"] if not r["matches"]["source_equals_live"]]
        self.assertEqual(drift, ["ff_win_v3_agent.py"])

    def test_duplicate_package_members_denied(self):
        source, installed, archive = self.fixture()
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(archive, "w") as z:
                for content in (b"first", b"last"):
                    z.writestr("runtime/bridge-v3/cua_router.py", content)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            compare(source, installed, archive, names=("cua_router.py",))

    def test_oversized_module_denied_before_decompression(self):
        source, installed, archive = self.fixture()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("runtime/bridge-v3/cua_router.py", b"x"*1025)
        with patch("runtime_inventory.MAX_MODULE_BYTES", 1024), \
             self.assertRaisesRegex(ValueError, "size limit"):
            compare(source, installed, archive, names=("cua_router.py",))

    def test_all_missing_is_never_equality(self):
        source, installed, archive = self.fixture()
        result = compare(source, installed, archive)
        self.assertFalse(result["all_installed_equal_source"])
        self.assertFalse(result["all_installed_equal_package"])

    def test_matching_disk_files_do_not_attest_active_process(self):
        source, installed, archive = self.fixture()
        for folder in (source, installed):
            (folder/"cua_router.py").write_bytes(b"same")
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("runtime/bridge-v3/cua_router.py", b"same")
        result = compare(source, installed, archive, names=("cua_router.py",))
        self.assertTrue(result["all_installed_equal_source"])
        self.assertTrue(result["all_installed_equal_package"])
        self.assertFalse(result["running_process_verified"])


    def test_critical_control_and_execution_modules_are_allowlisted(self):
        required = {
            "cua_bridge_v3.py", "cua_cli_discovery.py",
            "cua_input_arbiter.py", "cua_visual_action_gate.py",
            "cua_session_continuation.py", "cua_task_routes.py",
            "cua_runtime_deploy.py", "cua_restricted_execution.py",
            "cua_app_api.py", "cua_global_resources.py",
        }
        self.assertTrue(required.issubset(set(TRACKED)))

    def test_critical_live_drift_and_package_drift_are_independent(self):
        source, installed, archive = self.fixture()
        for name in TRACKED:
            (source/name).write_bytes(b"known-public-source")
            (installed/name).write_bytes(b"known-public-source")
        live_drift = {"cua_bridge_v3.py", "cua_runtime_deploy.py",
                      "cua_visual_action_gate.py"}
        for name in live_drift:
            (installed/name).write_bytes(b"older-live-runtime")
        with zipfile.ZipFile(archive, "w") as z:
            for name in TRACKED:
                payload = (b"wrong-release-version" if name == "cua_input_arbiter.py"
                           else b"known-public-source")
                z.writestr("runtime/bridge-v3/" + name, payload)
        result = compare(source, installed, archive)
        rows = {item["file"]: item["matches"] for item in result["modules"]}
        self.assertEqual({name for name, matches in rows.items()
                          if not matches["source_equals_live"]}, live_drift)
        self.assertEqual({name for name, matches in rows.items()
                          if not matches["source_equals_package"]},
                         {"cua_input_arbiter.py"})
        self.assertFalse(result["all_installed_equal_source"])
        self.assertFalse(result["all_installed_equal_package"])
        self.assertFalse(result["running_process_verified"])


if __name__=="__main__":
    unittest.main()
