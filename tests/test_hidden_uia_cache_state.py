"""UIA compilation output is per-install state, never public source bytes."""
from __future__ import annotations

import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
from cua_hidden_apps import prepare_uia


class TestOwnedUiaCache(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory(prefix="wb-uia-state-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = self.root / "source" / "bridge-v3"
        self.package.mkdir(parents=True)
        (self.package / "cua_native_uia3_sidecar.cs").write_bytes(b"class Sidecar {}")
        self.windir = self.root / "fake-windows"
        self.framework = self.windir / "Microsoft.NET/Framework64/v4.0.30319"
        for name in ("csc.exe", "WPF/UIAutomationClient.dll",
                     "WPF/UIAutomationTypes.dll", "System.Web.Extensions.dll"):
            entry = self.framework / name
            entry.parent.mkdir(parents=True, exist_ok=True)
            entry.write_bytes(("fake:" + name).encode("ascii"))
        self.calls = []
        def fake_compiler(argv, **kwargs):
            self.calls.append((tuple(argv), dict(kwargs)))
            output_args = [arg for arg in argv if arg.startswith("/out:")]
            self.assertEqual(len(output_args), 1)
            Path(output_args[0][5:]).write_bytes(b"compiled synthetic executable")
            return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
        self.compiler = patch("cua_hidden_apps.subprocess.run", side_effect=fake_compiler)
        self.compiler.start()
        self.addCleanup(self.compiler.stop)

    def test_default_owned_root_and_reuse_do_not_mutate_package(self):
        owner = self.root / "per-install"
        with patch.dict(os.environ, {"WINDIR": str(self.windir),
                                      "FF_BRIDGE_ROOT": str(owner)}, clear=False):
            first = prepare_uia(self.package)
            second = prepare_uia(self.package)
        self.assertEqual(first, second)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(first.parent, owner / "state" / "uia3-sidecar-cache")
        self.assertTrue(first.is_file())
        self.assertEqual([p.name for p in self.package.iterdir()],
                         ["cua_native_uia3_sidecar.cs"])
        self.assertTrue((first.parent / "build.lock").exists())

    def test_fallback_to_local_app_data_not_cwd_or_source(self):
        local = self.root / "appdata"
        with patch.dict(os.environ, {"WINDIR": str(self.windir),
                                      "LOCALAPPDATA": str(local)}, clear=False):
            with patch.dict(os.environ, {"FF_BRIDGE_ROOT": ""}):
                result = prepare_uia(self.package)
        self.assertEqual(result.parent, local / "FF-Windows-Bridge" / "state" /
                         "uia3-sidecar-cache")
        self.assertFalse((self.package / ".uia3-sidecar-cache").exists())

    def test_deny_relative_source_cache_and_missing_owner_state(self):
        with self.assertRaisesRegex(ValueError, "HIDDEN_UIA_CACHE_ROOT_NOT_ABSOLUTE"):
            prepare_uia(self.package, cache_root=Path("relative-cache"))
        with self.assertRaisesRegex(ValueError, "HIDDEN_UIA_SOURCE_CACHE_FORBIDDEN"):
            prepare_uia(self.package, cache_root=self.package / ".uia3-sidecar-cache")
        with patch.dict(os.environ, {"FF_BRIDGE_ROOT": "", "LOCALAPPDATA": ""}):
            with self.assertRaisesRegex(ValueError, "HIDDEN_UIA_STATE_ROOT_UNAVAILABLE"):
                prepare_uia(self.package)
        self.assertEqual(self.calls, [])
        self.assertEqual([p.name for p in self.package.iterdir()],
                         ["cua_native_uia3_sidecar.cs"])

    def test_symlinked_cache_and_parent_fail_closed(self):
        actual = self.root / "actual"
        actual.mkdir()
        fake = self.root / "link"
        try:
            fake.symlink_to(actual, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation unavailable on this Windows account")
        with patch.dict(os.environ, {"WINDIR": str(self.windir)}):
            with self.assertRaisesRegex(ValueError, "HIDDEN_UIA_CACHE_LINK_FORBIDDEN"):
                prepare_uia(self.package, cache_root=fake)
            with self.assertRaisesRegex(ValueError, "HIDDEN_UIA_CACHE_LINK_FORBIDDEN"):
                prepare_uia(self.package, cache_root=fake / "state")
        self.assertEqual(self.calls, [])

    def test_malformed_cached_manifest_recompiles_not_traverses(self):
        owner = self.root / "per-install"
        with patch.dict(os.environ, {"WINDIR": str(self.windir),
                                      "FF_BRIDGE_ROOT": str(owner)}):
            first = prepare_uia(self.package)
            manifest = next(first.parent.glob("*.json"))
            manifest.write_text('{"schema":1,"output":"../outside.exe"}', encoding="utf-8")
            again = prepare_uia(self.package)
        self.assertEqual(len(self.calls), 2)
        self.assertNotEqual(first, again)
        self.assertFalse((owner / "state" / "outside.exe").exists())


if __name__ == "__main__":
    unittest.main()
