"""Transport imports and upgrades use only the sibling Bridge runtime."""
import ast
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TRANSPORT = ROOT / "runtime/github-transport"
BRIDGE = ROOT / "runtime/bridge-v3"
SHARED = (
    "ff_win_v3_security", "ff_win_v3_extras", "ff_win_evidence",
    "cua_global_resources", "cua_task_authority", "ff_win_v3_agent",
)
ENTRYPOINTS = (
    "ff_win_github_comment_daemon", "ff_win_github_background_agent",
    "ff_win_github_client", "ff_win_transport_core",
)


class TestTransportModulePaths(unittest.TestCase):
    def layout(self, root, bridge=True):
        transport = root / "github-transport"
        shutil.copytree(TRANSPORT, transport, ignore=shutil.ignore_patterns("__pycache__"))
        if bridge:
            shutil.copytree(BRIDGE, root / "bridge-v3", ignore=shutil.ignore_patterns("__pycache__"))
        return transport

    def python(self, root, code, *args):
        # -I models embedded Python: neither cwd nor PYTHONPATH supplies imports.
        return subprocess.run([sys.executable, "-I", "-c", code, *map(str, args)],
                              cwd=root, env={**os.environ, "FF_BRIDGE_ROOT": str(root),
                                             "FF_GH_HOME": str(root / "github-transport")},
                              capture_output=True, text=True, timeout=30)

    def powershell(self, root, code, *args):
        return subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                               "-ExecutionPolicy", "Bypass", "-Command", code, *map(str, args)],
                              cwd=root, env={**os.environ, "FF_BRIDGE_ROOT": str(root),
                                             "FF_GH_HOME": str(root / "github-transport")},
                              capture_output=True, text=True, errors="replace", timeout=45)

    def test_no_shared_python_filenames_in_transport(self):
        self.assertFalse({p.name.lower() for p in TRANSPORT.rglob("*.py")} &
                         {p.name.lower() for p in BRIDGE.rglob("*.py")})

    def test_entrypoints_import_shared_modules_from_bridge_in_both_layouts(self):
        for installed in (False, True):
            with self.subTest(installed=installed), tempfile.TemporaryDirectory() as td:
                root = Path(td) / ("installed" if installed else "runtime")
                transport = self.layout(root)
                for entry in ENTRYPOINTS:
                    with self.subTest(entry=entry):
                        result = self.python(root, """
import importlib, json, pathlib, sys
sys.path.insert(0, sys.argv[1])
importlib.import_module(sys.argv[2])
modules = {name: importlib.import_module(name).__file__ for name in sys.argv[3:]}
print(json.dumps(modules))
""", transport, entry, *SHARED, "ff_win_process_identity")
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        for name, file in json.loads(result.stdout).items():
                            self.assertEqual(Path(file).resolve(), root / "bridge-v3" / (name + ".py"))

    def test_missing_bridge_fails_before_entrypoint_dependencies(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            transport = self.layout(root, bridge=False)
            for entry in (*ENTRYPOINTS, "ff_win_transport_paths"):
                with self.subTest(entry=entry):
                    result = self.python(root,
                                         "import sys,importlib; sys.path.insert(0,sys.argv[1]); importlib.import_module(sys.argv[2])",
                                         transport, entry)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("BRIDGE_V3_RUNTIME_MISSING", result.stderr)
                    self.assertNotIn("ModuleNotFoundError", result.stderr)

    def test_bootstrap_keeps_order_without_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            transport = self.layout(root)
            result = self.python(root, """
import importlib, json, sys
transport, bridge = sys.argv[1:]
sys.path[:0] = [bridge, transport, bridge, transport]
import ff_win_transport_paths
importlib.reload(ff_win_transport_paths)
print(json.dumps(sys.path))
""", transport, root / "bridge-v3")
            self.assertEqual(result.returncode, 0, result.stderr)
            paths = json.loads(result.stdout)
            self.assertEqual(paths[:2], [str(transport), str(root / "bridge-v3")])
            self.assertEqual(paths.count(str(transport)), 1)
            self.assertEqual(paths.count(str(root / "bridge-v3")), 1)

    def test_entrypoints_bootstrap_before_other_imports(self):
        entries = {file.stem for file in TRANSPORT.glob("*.py")
                   if "__main__" in file.read_text(encoding="utf-8")}
        self.assertTrue(entries)
        for name in entries | set(ENTRYPOINTS):
            with self.subTest(entry=name):
                tree = ast.parse((TRANSPORT / (name + ".py")).read_text(encoding="utf-8"))
                imports = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
                           and not (isinstance(node, ast.ImportFrom) and node.module in {"__future__", "pathlib"})
                           and not (isinstance(node, ast.Import) and node.names[0].name == "sys")]
                self.assertIsInstance(imports[0], ast.Import)
                self.assertEqual(imports[0].names[0].name, "ff_win_transport_paths")

    def test_entrypoint_scripts_run_without_script_folder_on_path(self):
        # Embedded Python's ._pth never adds the script folder; -I reproduces that.
        entries = sorted(file.name for file in TRANSPORT.glob("*.py")
                         if "__main__" in file.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            transport = self.layout(root)
            for name in entries:
                with self.subTest(entry=name):
                    result = subprocess.run([sys.executable, "-I", str(transport / name), "--help"],
                                            cwd=root, env={**os.environ, "FF_BRIDGE_ROOT": str(root),
                                                           "FF_GH_HOME": str(transport)},
                                            capture_output=True, text=True, timeout=30)
                    self.assertNotIn("ModuleNotFoundError", result.stderr)
                    self.assertNotIn("ImportError", result.stderr)

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell required")
    def test_upgrade_removes_only_legacy_modules_and_their_caches(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            transport = self.layout(root)
            cache = transport / "__pycache__"
            cache.mkdir()
            old = []
            for name in SHARED:
                for file in (transport / (name + ".py"), transport / (name + ".pyc"),
                             cache / (name + ".cpython-313.pyc"),
                             cache / (name + ".cpython-314.opt-1.pyc")):
                    file.write_bytes(b"raise RuntimeError('STALE_TRANSPORT_COPY')\n")
                    old.append(file)
            keep = {transport / "github_transport_config.json": b"{}",
                    cache / "ff_win_transport_core.cpython-313.pyc": b"transport cache",
                    cache / "ff_win_evidence_extra.cpython-313.pyc": b"unrelated cache"}
            for file, data in keep.items():
                file.write_bytes(data)
            bridge_before = {name: (root / "bridge-v3" / (name + ".py")).read_bytes() for name in SHARED}
            result = self.powershell(root, """
& { param($Common,$Transport,$Python)
$ErrorActionPreference='Stop'
. $Common
Remove-FFLegacyTransportModules $Transport
Remove-FFLegacyTransportModules $Transport
Assert-FFTransportImports $Python $Transport
} """, ROOT / "ff-release-common.ps1", transport, sys.executable)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue(all(not file.exists() for file in old))
            for file, data in keep.items():
                self.assertEqual(file.read_bytes(), data)
            for name, data in bridge_before.items():
                self.assertEqual((root / "bridge-v3" / (name + ".py")).read_bytes(), data)

    @unittest.skipUnless(os.name == "nt", "Windows PowerShell required")
    def test_staging_import_gate_reports_missing_shared_runtime(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            transport = self.layout(root, bridge=False)
            result = self.powershell(root, """
& { param($Common,$Transport,$Python)
$ErrorActionPreference='Stop'
. $Common
Assert-FFTransportImports $Python $Transport
} """, ROOT / "ff-release-common.ps1", transport, sys.executable)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("RELEASE_TRANSPORT_IMPORT_FAILED", result.stderr)
            self.assertIn("BRIDGE_V3_RUNTIME_MISSING", result.stderr)

    def test_installer_updates_bridge_and_cleans_transport_before_start(self):
        source = (ROOT / "install.ps1").read_text(encoding="utf-8")
        self.assertLess(source.index("Assert-FFTransportImports $python $transportStage"),
                        source.index("if ($StageOnly)"))
        github = source[source.index("# Stop the background transport"):]
        bridge_copy = github.index("Copy-FFPortableTree $v3Stage $v3Root")
        self.assertLess(github.index("Stop-ScheduledTask -TaskName $backgroundTaskName"), bridge_copy)
        cleanup = github.index("Remove-FFLegacyTransportModules $root")
        gate = github.index("Assert-FFTransportImports $python $root")
        self.assertLess(bridge_copy, cleanup)
        self.assertLess(cleanup, gate)
        self.assertLess(gate, github.index("Register-Keeper $v3TaskName"))

    def test_powershell_scripts_do_not_launch_removed_modules(self):
        for file in TRANSPORT.glob("*.ps1"):
            with self.subTest(script=file.name):
                text = file.read_text(encoding="utf-8")
                for name in SHARED:
                    self.assertNotIn(name + ".py", text)


if __name__ == "__main__":
    unittest.main()
