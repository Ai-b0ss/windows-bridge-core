"""Execute real parent lifecycle methods with fake pipes, Jobs and profiles.

AST extraction avoids importing the Windows-only worker launcher on other hosts;
the request/close and RPC error-handling bodies themselves are production code.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import queue
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

RUNTIME = Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"


def parent_classes():
    path = RUNTIME / "cua_hidden_desktop.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    nodes = []
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "HiddenDesktopError":
            nodes.append(node)
        if isinstance(node, ast.ClassDef) and node.name == "HiddenDesktopSession":
            node.body = [method for method in node.body if isinstance(method, ast.FunctionDef)
                         and method.name in {"request", "close", "closed"}]
            nodes.append(node)
    namespace = {"Path": Path, "os": os, "queue": queue, "json": json, "uuid": uuid}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


class HiddenSessionFailureContracts(unittest.TestCase):
    def setUp(self):
        self.namespace = parent_classes()
        self.Error = self.namespace["HiddenDesktopError"]
        self.session = self.namespace["HiddenDesktopSession"].__new__(self.namespace["HiddenDesktopSession"])
        s = self.session
        s.session_id = "owned-session"
        s._lock = threading.Lock()
        s._closed = False
        s._job, s._process, s._desktop = "owned-job", "owned-worker", "owned-desktop"
        s._writer, s._stderr = Mock(), Mock()
        s._editor_profiles, s._chrome_profile = [], None
        s.browser_profile_cleanup, s.editor_profile_cleanup = [], []
        self.writer = s._writer
        self.events = []
        self.namespace["_close_windows_job_handle"] = lambda handle: self.events.append(("job", handle))
        s._k = SimpleNamespace(TerminateProcess=Mock(side_effect=lambda *a: self.events.append(("worker", a[0]))),
                               WaitForSingleObject=Mock(), CloseHandle=Mock())
        s._u = SimpleNamespace(CloseDesktop=Mock())
        self.profile = SimpleNamespace(path=Path("/owned-fixture/worker-profile"),
            close=Mock(side_effect=lambda: self.events.append(("profile", True)) or True))
        self.factory = Mock(return_value=self.profile)
        self.reply = {"ok": True, "result": {"verified": True}}
        def receive(**kwargs):
            packet = json.loads(self.writer.write.call_args.args[0])
            return {"id": packet["id"], **self.reply}
        s._queue = Mock(get=Mock(side_effect=receive))
        self.profiles_patch = patch.dict(sys.modules, {"cua_browser_profiles": SimpleNamespace(ManagedBrowserProfiles=self.factory)})
        self.profiles_patch.start()
        self.addCleanup(self.profiles_patch.stop)
        self.env_patch = patch.dict(os.environ, {"FF_BRIDGE_ROOT": str(RUNTIME.parent)})
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)

    def test_dispatched_launch_error_closes_job_before_profile_and_preserves_error(self):
        self.reply = {"ok": False, "error_code": "HIDDEN_CHROME_LISTENER_NOT_OWNED", "details": {"attempted": True}}
        with self.assertRaises(self.Error) as raised:
            self.session.request({"command": "browser.launch"})
        self.assertEqual(raised.exception.code, "HIDDEN_CHROME_LISTENER_NOT_OWNED")
        self.assertEqual(raised.exception.details, {"attempted": True})
        self.assertTrue(self.session.closed)
        self.assertEqual(self.events, [("job", "owned-job"), ("worker", "owned-worker"), ("profile", True)])
        self.profile.close.assert_called_once_with()
        self.assertEqual(self.session.browser_profile_cleanup,
                         [{"root": str(self.profile.path), "removed": True}])
        self.assertIsNone(self.session._chrome_profile)

    def test_internal_profile_injection_is_rejected_before_allocation_or_dispatch(self):
        for field, code in (("__owned_browser_root", "BROWSER_INTERNAL_ROOT_FORBIDDEN"),
                            ("__owned_editor_root", "EDITOR_INTERNAL_ROOT_FORBIDDEN")):
            with self.subTest(field=field), self.assertRaisesRegex(self.Error, code):
                self.session.request({"command": "browser.launch", field: "/foreign"})
        self.factory.assert_not_called()
        self.writer.write.assert_not_called()
        self.assertFalse(self.session.closed)
        self.assertEqual(self.events, [])

    def test_closed_session_cannot_dispatch_or_create_a_profile(self):
        self.session._closed = True
        with self.assertRaisesRegex(self.Error, "HIDDEN_WORKER_CLOSED"):
            self.session.request({"command": "browser.launch"})
        self.factory.assert_not_called()
        self.writer.write.assert_not_called()
        self.session._queue.get.assert_not_called()

    def test_timeout_after_launch_dispatch_is_unknown_and_closes_job_profile(self):
        self.session._queue.get.side_effect = queue.Empty
        with self.assertRaisesRegex(self.Error, "HIDDEN_ACTION_OUTCOME_UNKNOWN"):
            self.session.request({"command": "browser.launch"}, timeout_s=.1)
        self.writer.write.assert_called_once()
        self.assertTrue(self.session.closed)
        self.assertEqual(self.events[0], ("job", "owned-job"))
        self.assertEqual(self.events[-1], ("profile", True))
        with self.assertRaisesRegex(self.Error, "HIDDEN_WORKER_CLOSED"):
            self.session.request({"command": "browser.launch"})
        self.writer.write.assert_called_once()  # Unknown mutation is never replayed.

    def test_wrong_reply_id_closes_without_replaying(self):
        self.reply = {"id": "some-other-request", "ok": True, "result": {}}
        with self.assertRaisesRegex(self.Error, "HIDDEN_ACTION_OUTCOME_UNKNOWN"):
            self.session.request({"command": "health"})
        self.assertTrue(self.session.closed)
        self.writer.write.assert_called_once()
        self.assertEqual(self.events[0], ("job", "owned-job"))

    def test_broken_pipe_after_profile_allocation_closes_and_reports_unknown(self):
        self.writer.write.side_effect = BrokenPipeError("owned worker pipe closed")
        with self.assertRaisesRegex(self.Error, "HIDDEN_ACTION_OUTCOME_UNKNOWN"):
            self.session.request({"command": "browser.launch"})
        self.assertTrue(self.session.closed)
        self.session._queue.get.assert_not_called()
        self.profile.close.assert_called_once_with()
        self.session.close()  # Reconciliation/cleanup may safely repeat close, never launch.
        self.profile.close.assert_called_once_with()
        self.assertEqual(self.events, [("job", "owned-job"), ("worker", "owned-worker"), ("profile", True)])

    def test_predispatch_options_or_existing_browser_do_not_destroy_live_session(self):
        with self.assertRaisesRegex(self.Error, "HIDDEN_CHROME_OPTION_FORBIDDEN"):
            self.session.request({"command": "browser.launch", "arguments": ["--no-sandbox"]})
        self.session._chrome_profile = self.profile
        with self.assertRaisesRegex(self.Error, "HIDDEN_CHROME_ALREADY_LAUNCHED"):
            self.session.request({"command": "browser.launch"})
        self.factory.assert_not_called()
        self.writer.write.assert_not_called()
        self.assertFalse(self.session.closed)
        self.assertEqual(self.events, [])

    def test_known_nonlaunch_error_keeps_unrelated_owned_session(self):
        self.reply = {"ok": False, "error_code": "HIDDEN_WINDOW_NOT_OWNED"}
        with self.assertRaisesRegex(self.Error, "HIDDEN_WINDOW_NOT_OWNED"):
            self.session.request({"command": "read_text", "hwnd": 999})
        self.assertFalse(self.session.closed)
        self.assertEqual(self.events, [])


class HiddenRpcSlotRecoveryContracts(unittest.TestCase):
    def setUp(self):
        self.parent = parent_classes()
        self.Error = self.parent["HiddenDesktopError"]
        class RpcError(RuntimeError):
            def __init__(self, code, details=None):
                super().__init__(code)
                self.code, self.details = code, details or {}
        self.RpcError = RpcError
        path = RUNTIME / "ff_win_v3_main.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        node = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_hidden_computer_use")
        self.namespace = {"Any": object, "Path": Path, "__file__": str(path),
                          "core": SimpleNamespace(RPCError=RpcError),
                          "_HIDDEN_LOCK": threading.Lock(), "_HIDDEN_SESSIONS": {}}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), self.namespace)
        self.patcher = patch.dict(sys.modules, {"cua_hidden_desktop": SimpleNamespace(
            HiddenDesktopSession=Mock(), HiddenDesktopError=self.Error)})
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_closed_failed_session_is_evicted_and_foreign_session_is_preserved(self):
        cleanup = [{"root": "/owned-fixture/worker-profile", "removed": True}]
        failed = SimpleNamespace(session_id="failed", closed=True, browser_profile_cleanup=cleanup,
            request=Mock(side_effect=self.Error("HIDDEN_ACTION_OUTCOME_UNKNOWN", {"attempted": True})))
        foreign = SimpleNamespace(session_id="foreign", closed=False)
        slots = self.namespace["_HIDDEN_SESSIONS"]
        slots.update({"failed": failed, "foreign": foreign})
        with self.assertRaises(self.RpcError) as raised:
            self.namespace["_hidden_computer_use"]({"command": "hidden_request", "session_id": "failed", "request": {"command": "health"}})
        self.assertEqual(raised.exception.code, "HIDDEN_ACTION_OUTCOME_UNKNOWN")
        self.assertFalse(raised.exception.details["retry_safe"])
        self.assertTrue(raised.exception.details["session_closed"])
        self.assertEqual(raised.exception.details["browser_profile_cleanup"], cleanup)
        self.assertEqual(slots, {"foreign": foreign})
        with self.assertRaisesRegex(self.RpcError, "HIDDEN_SESSION_NOT_FOUND"):
            self.namespace["_hidden_computer_use"]({"command": "hidden_request", "session_id": "failed", "request": {"command": "health"}})
        failed.request.assert_called_once()

    def test_known_denial_does_not_evict_a_still_live_session(self):
        live = SimpleNamespace(session_id="live", closed=False,
            request=Mock(side_effect=self.Error("HIDDEN_WINDOW_NOT_OWNED")))
        self.namespace["_HIDDEN_SESSIONS"]["live"] = live
        with self.assertRaisesRegex(self.RpcError, "HIDDEN_WINDOW_NOT_OWNED"):
            self.namespace["_hidden_computer_use"]({"command": "hidden_request", "session_id": "live", "request": {"command": "health"}})
        self.assertIs(self.namespace["_HIDDEN_SESSIONS"]["live"], live)


if __name__ == "__main__":
    unittest.main()
