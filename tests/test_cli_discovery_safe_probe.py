"""A generic discovered executable must not run just because it has --version."""
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))

from cua_cli_discovery import probe_cli_versions


class TestBoundedCliVersionProbes(unittest.TestCase):
    def test_untrusted_path_candidate_not_executed_even_when_probe_requested(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            unknown = root / "unknown-agent.cmd"
            unknown.write_text("@echo off\nexit /b 1\n", encoding="utf-8")
            candidate = {"command": "agent", "path": str(unknown),
                         "health": "healthy", "verified": True,
                         "task_compatibility": "compatible"}
            with patch.dict(os.environ, {"LOCALAPPDATA": td}), \
                    patch("subprocess.run", side_effect=AssertionError("UNTRUSTED_EXECUTED")), \
                    patch("cua_cli_contracts.probe_vendor_cli",
                          side_effect=AssertionError("VENDOR_PROBE_WRONG")):
                row = probe_cli_versions([candidate])[0]
            self.assertEqual(row["probe_status"], "untrusted_cli_not_executed")
            self.assertEqual(row["health"], "unprobed")
            self.assertEqual(row["task_compatibility"], "unknown")
            self.assertIsNone(row["version"])
            self.assertIs(row["verified"], False)

    def test_only_exact_pinned_vendor_entrypoint_can_be_probed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            known = root / "cursor-agent" / "agent.cmd"
            known.parent.mkdir(parents=True)
            known.write_text("@echo off\n", encoding="utf-8")
            lookalike = root / "elsewhere" / "agent.cmd"
            lookalike.parent.mkdir()
            lookalike.write_text("@echo off\n", encoding="utf-8")
            expected = {"schema": "ff-cli-contract-v1", "path_verified": True,
                        "help_checked": True, "version": "2026.10.19"}
            with patch.dict(os.environ, {"LOCALAPPDATA": td}), \
                    patch("cua_cli_contracts.probe_vendor_cli", return_value=expected) as probe, \
                    patch("subprocess.run", side_effect=AssertionError("RAW_RUN_USED")):
                rows = probe_cli_versions([
                    {"command": "agent", "path": str(known), "health": "unprobed"},
                    {"command": "agent", "path": str(lookalike), "health": "unprobed"},
                    {"command": "cursor-agent", "path": str(known), "health": "unprobed"},
                ])
            self.assertEqual(probe.call_count, 1)
            probe.assert_called_with("cursor", timeout_s=3.0)
            self.assertEqual(rows[0]["health"], "healthy")
            self.assertEqual(rows[0]["version"], "2026.10.19")
            self.assertEqual(rows[0]["probe_status"], "pinned_vendor_help_checked")
            self.assertEqual(rows[1]["probe_status"], "untrusted_cli_not_executed")
            self.assertIs(rows[0]["verified"], False)
            self.assertEqual(rows[0]["task_compatibility"], "unknown")
            self.assertEqual(rows[2]["health"], "healthy")

    def test_pinned_path_without_successful_contract_is_not_healthy(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            known = root / "agy" / "bin" / "agy.exe"
            known.parent.mkdir(parents=True)
            known.write_bytes(b"not-real-binary")
            with patch.dict(os.environ, {"LOCALAPPDATA": td}), \
                    patch("cua_cli_contracts.probe_vendor_cli", return_value={
                        "path_verified": True, "help_checked": False, "version": None,
                    }):
                row = probe_cli_versions([{"command": "agy", "path": str(known)}])[0]
            self.assertEqual(row["probe_status"], "pinned_vendor_unverified")
            self.assertEqual(row["health"], "unprobed")
            self.assertFalse(row["verified"])

    def test_no_local_appdata_does_not_probe_any_candidate(self):
        with patch.dict(os.environ, {"LOCALAPPDATA": ""}), \
                patch("cua_cli_contracts.probe_vendor_cli",
                      side_effect=AssertionError("PROBED_WITHOUT_ROOT")):
            row = probe_cli_versions([{"command": "agy", "path": "C:\\agy\\bin\\agy.exe"}])[0]
        self.assertEqual(row["probe_status"], "untrusted_cli_not_executed")


if __name__ == "__main__":
    unittest.main()
