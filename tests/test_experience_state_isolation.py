"""Regression: route experience must never mutate or read source package bytes."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

BRIDGE = Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"
sys.path.insert(0, str(BRIDGE))
from cua_bridge_v3 import CuaBridgeControlPlane


class ExperienceStateIsolationTests(unittest.TestCase):
    @staticmethod
    def _record(plane: CuaBridgeControlPlane) -> Path:
        store = plane._experience_runtime()
        handle = SimpleNamespace(
            app="Excel", executor="excel_com", backend_route="APP_EXCEL_COM",
            capabilities={"cell.read": {"verified_capable": True}},
        )
        store.note_probe_success(handle)
        assert store.preferred_executor("Excel") == "excel_com"
        return store.path

    def test_explicit_isolated_state_dir_preserves_source(self):
        with tempfile.TemporaryDirectory(prefix="wb-route-state-") as temp:
            root = Path(temp)
            package = root / "source" / "bridge-v3"
            package.mkdir(parents=True)
            legacy = package / "cua_app_route_experience.json"
            legacy.write_bytes(b"legacy source bytes must be untouched")
            state = root / "owned-state"
            first = CuaBridgeControlPlane(package, state_dir=state)
            saved = self._record(first)
            self.assertEqual(saved, state / "cua_app_route_experience.json")
            self.assertTrue(saved.is_file())
            self.assertEqual(legacy.read_bytes(), b"legacy source bytes must be untouched")
            second = CuaBridgeControlPlane(package, state_dir=state)
            self.assertEqual(
                second._experience_runtime().preferred_executor("Excel"), "excel_com"
            )
            self.assertEqual(list(package.iterdir()), [legacy])

    def test_default_bridge_root_uses_owned_state_not_package(self):
        with tempfile.TemporaryDirectory(prefix="wb-route-default-") as temp:
            root = Path(temp)
            package = root / "build" / "bridge-v3"
            package.mkdir(parents=True)
            runtime = root / "runtime"
            with patch.dict(os.environ, {"FF_BRIDGE_ROOT": str(runtime),
                                          "LOCALAPPDATA": str(root / "local")}):
                saved = self._record(CuaBridgeControlPlane(package))
            self.assertEqual(saved, runtime / "state" / "cua_app_route_experience.json")
            self.assertFalse((package / "cua_app_route_experience.json").exists())

    def test_nonruntime_package_retains_memory_only_default(self):
        with tempfile.TemporaryDirectory(prefix="wb-route-inmem-") as temp:
            root = Path(temp)
            state = root / "state"
            saved = self._record(CuaBridgeControlPlane(root / "fixture", state_dir=state))
            self.assertIsNone(saved)
            self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main()
