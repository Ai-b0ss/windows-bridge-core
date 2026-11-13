"""Unit-level tests for safe owner Chrome attach behavior.

Uses a fake sidecar; never starts or attaches to a real browser.
"""
import contextlib
from types import SimpleNamespace
import unittest
import os
import threading
from unittest.mock import patch
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'runtime' / 'bridge-v3'))

import cua_bridge_v3 as bridge
from cua_bridge_v3 import CuaBridgeControlPlane, CuaBridgeError


GOOD = {
    "ok": True,
    "result": {
        "surface_id": "mock-owner-surface",
        "capabilities": {
            "owner_browser": True,
            "isolated_profile": False,
            "owner_transport": "extension",
        },
    },
}
BAD = {"ok": False, "error_code": "MOCK_EXTENSION_CONNECTION_LOST"}


class FakeSupervisor:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []
        self.restarts = 0

    def request(self, operation, payload):
        self.calls.append((operation, dict(payload)))
        if operation == "identity":
            return {"ok": True, "result": {"url": "https://example.org"}}
        if operation == "close":
            return {"ok": True, "result": {"ok": True, "cleanup": {"detached": True}}}
        if not self.responses:
            raise AssertionError("Unexpected sidecar request")
        return self.responses.pop(0)

    def restart(self):
        self.restarts += 1


def new_plane(supervisor, surfaces=None):
    plane = CuaBridgeControlPlane.__new__(CuaBridgeControlPlane)
    plane._surfaces = dict(surfaces or {})
    plane._resources = SimpleNamespace(write=lambda _: contextlib.nullcontext())
    plane._browser_supervisor = lambda transport: supervisor
    return plane


class OwnerChromeAttachTests(unittest.TestCase):
    def test_normal_owner_attach(self):
        stub = FakeSupervisor(GOOD)
        result = new_plane(stub)._attach({"surface_kind": "browser", "transport": "extension"})
        self.assertEqual(result["surface_id"], "mock-owner-surface")
        self.assertEqual(stub.restarts, 0)
        self.assertEqual(stub.calls[0][1]["ownerTransport"], "extension")

    def test_one_safe_retry_of_disconnected_extension(self):
        stub = FakeSupervisor(BAD, GOOD)
        result = new_plane(stub)._attach({"surface_kind": "browser", "transport": "extension"})
        self.assertEqual(result["surface_id"], "mock-owner-surface")
        self.assertEqual(stub.restarts, 1)
        self.assertEqual([x[0] for x in stub.calls], ["attach", "attach"])

    def test_active_owner_surface_prevents_restart_and_fallback(self):
        stub = FakeSupervisor(BAD)
        plane = new_plane(stub, {"already-open": {"kind": "browser", "transport": "extension"}})
        with self.assertRaises(CuaBridgeError) as ctx:
            plane._attach({"surface_kind": "browser", "transport": "extension",
                           "force_new_connection": True})
        self.assertEqual(ctx.exception.code, "OWNER_CHROME_ATTACH_FAILED")
        self.assertEqual(ctx.exception.details["retry"], "skipped_active_surfaces")
        self.assertFalse(ctx.exception.details["isolated_fallback"])
        self.assertEqual(stub.restarts, 0)

    def test_double_failure_does_not_fall_back_to_isolated(self):
        stub = FakeSupervisor(BAD, BAD)
        with self.assertRaises(CuaBridgeError) as ctx:
            new_plane(stub)._attach({"surface_kind": "browser", "transport": "extension"})
        self.assertEqual(ctx.exception.code, "OWNER_CHROME_ATTACH_FAILED")
        self.assertFalse(ctx.exception.details["isolated_fallback"])
        self.assertEqual(stub.restarts, 1)
        self.assertEqual(len(stub.calls), 2)

    def test_non_owner_profile_capability_is_rejected(self):
        bad_capabilities = {
            "ok": True,
            "result": {"surface_id": "unexpected",
                       "capabilities": {"owner_browser": False, "isolated_profile": True,
                                        "owner_transport": "isolated"}},
        }
        stub = FakeSupervisor(bad_capabilities)
        plane = new_plane(stub)
        with self.assertRaises(CuaBridgeError) as ctx:
            plane._attach({"surface_kind": "browser", "transport": "extension"})
        self.assertEqual(ctx.exception.code, "OWNER_CHROME_PROFILE_MISMATCH")
        self.assertEqual(ctx.exception.details["cleanup"], "confirmed")
        self.assertEqual([x[0] for x in stub.calls], ["attach", "close"])
        self.assertEqual(stub.calls[-1][1]["surface_id"], "unexpected")
        self.assertFalse(plane._surfaces)

    def test_failed_mismatch_cleanup_remains_explicit(self):
        wrong = {"ok": True, "result": {
            "surface_id": "unexpected",
            "capabilities": {"owner_browser": False, "isolated_profile": True,
                             "owner_transport": "isolated"}}}
        class FailClose(FakeSupervisor):
            def request(self, op, args):
                if op == "close":
                    self.calls.append((op, dict(args)))
                    return {"ok": False, "error_code": "CLOSE_FAILED"}
                return super().request(op, args)
        sidecar = FailClose(wrong)
        plane = new_plane(sidecar)
        with self.assertRaises(CuaBridgeError) as exc:
            plane._attach({"surface_kind": "browser", "transport": "extension"})
        self.assertEqual(exc.exception.details["cleanup"], "failed")
        self.assertEqual(sidecar.calls[-1][0], "close")
        self.assertFalse(plane._surfaces)

    def _profile_supervisor(self, profile_env):
        class FakeCtor:
            def __init__(self, *args, **kwargs):
                self.kwargs = kwargs
        plane = CuaBridgeControlPlane.__new__(CuaBridgeControlPlane)
        plane.root = Path("/isolated-configuration-test")
        plane._browser_factory = None
        plane._browser = {}
        plane._browser_supervisor_lock = threading.RLock()
        with patch.dict(os.environ, profile_env), patch.object(
                bridge.shutil, "which", return_value="powershell.exe"), patch.object(
                bridge, "JsonLineSidecarSupervisor", FakeCtor):
            return plane._browser_supervisor("extension")

    def test_legacy_playwright_profile_is_not_overridden(self):
        s = self._profile_supervisor({
            "FF_OWNER_CHROME_PROFILE_DIR_NAME": "",
            "PLAYWRIGHT_MCP_PROFILE_DIR_NAME": "Profile 3"})
        self.assertEqual(s.kwargs["env"]["PLAYWRIGHT_MCP_PROFILE_DIR_NAME"], "Profile 3")
        self.assertEqual(s.kwargs["timeout_seconds"], 15.0)

    def test_explicit_bridge_profile_has_precedence(self):
        s = self._profile_supervisor({
            "FF_OWNER_CHROME_PROFILE_DIR_NAME": "Profile 5",
            "PLAYWRIGHT_MCP_PROFILE_DIR_NAME": "Profile 3"})
        self.assertEqual(s.kwargs["env"]["PLAYWRIGHT_MCP_PROFILE_DIR_NAME"], "Profile 5")

    def test_invalid_profile_is_rejected_before_sidecar_start(self):
        with self.assertRaises(CuaBridgeError) as exc:
            self._profile_supervisor({
                "FF_OWNER_CHROME_PROFILE_DIR_NAME": "../unexpected",
                "PLAYWRIGHT_MCP_PROFILE_DIR_NAME": "Profile 3"})
        self.assertEqual(exc.exception.code, "OWNER_CHROME_PROFILE_INVALID")

    def test_isolated_attach_failure_is_not_retried_as_extension(self):
        stub = FakeSupervisor(BAD)
        with self.assertRaises(CuaBridgeError):
            new_plane(stub)._attach({"surface_kind": "browser", "transport": "isolated"})
        self.assertEqual(stub.restarts, 0)
        self.assertEqual(len(stub.calls), 1)

    def test_known_live_owner_surface_is_reused(self):
        stub = FakeSupervisor()
        plane = new_plane(stub, {"existing": {"kind": "browser", "transport": "extension",
                                               "capabilities": GOOD["result"]["capabilities"]}})
        result = plane._attach({"surface_kind": "browser", "transport": "extension"})
        self.assertTrue(result["reused"])
        self.assertEqual(result["surface_id"], "existing")
        self.assertEqual(stub.calls[0][0], "identity")
        self.assertEqual(stub.restarts, 0)


if __name__ == "__main__":
    unittest.main()

