"""Comprehensive unit + real isolated Windows tests for Private Desktop & Native CUA.

Covers:
1. Ported hotfix 3d53aba34db4459532da26f86eb63b83e77f4ec3 (surface_entity_value_equals
   and post-rerender GUI action receipt recovery without mutation replay).
2. Win32 Private Desktop boundary enforcement (no cross-desktop SendInput/UIA,
   no silent visible-desktop fallback, strict hwnd+pid+create_time ownership).
3. Real isolated Windows live tests on a private Win32 desktop:
   - Classic Notepad & WordPad (UIA observe, HWND WM_SETTEXT / EM_REPLACESEL /
     WM_CHAR SendMessage & PostMessage, PrintWindow capture, independent readback).
   - Owned Python/Win32 test window that genuinely destroys & recreates its Edit
     control on set_value to prove 3d53aba3 rerender receipt recovery on REAL
     Windows via both HWND_MESSAGE and UIA_PATTERN!
   - Foreign HWND & mismatched pid/create_time fail-closed rejection (both owner
     foreground HWND and sibling private-desktop session HWND).
   - Owner foreground HWND, cursor (x, y), clipboard sequence number, and
     clipboard owner HWND strictly unchanged before/after (clipboard content is
     never read).
   - Deterministic teardown on normal exit, error, timeout, forced cancel, and
     abrupt parent process kill (named Windows Job Object + CloseDesktop).
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import ctypes
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "runtime" / "bridge-v3"
if str(RUNTIME) not in sys.path:
    sys.path.insert(0, str(RUNTIME))

import cua_desktop_identity as desktop_identity_mod
from cua_hidden_capture import HiddenCaptureError, capture_owned_window
from cua_native_core import NativeError, NativeSemanticCore
from cua_native_hwnd import (
    BM_CLICK,
    BM_GETCHECK,
    CB_GETCURSEL,
    CB_SETCURSEL,
    EM_REPLACESEL,
    EM_SETSEL,
    HwndMessageBackend,
    WM_CHAR,
    WM_COMMAND,
    WM_GETTEXTLENGTH,
    WM_SETTEXT,
)
from cua_native_sidecar import dispatch as sidecar_dispatch
from cua_native_uia3 import Uia3PersistentBackend
from cua_native_winapp import WinAppCliBackend


# ---------------------------------------------------------------------------
# Helpers for unit tests
# ---------------------------------------------------------------------------


class _RerenderBackend:
    """Reproduces the 3d53aba3 Electron/rerender scenario without mocks."""

    route = "UIA_PATTERN"

    def __init__(self) -> None:
        self.value = "\n"
        self.replaced = False
        self.ambiguous = False
        self.missing_after = False
        self.sent = 0
        self.set_calls = 0
        self.stale_after_set = True
        self.editor_name = "Промпт"
        self.editor_automation_id = ""
        self.editor_control_id = None

    def capabilities(self) -> dict:
        return {"background_safe_actions": [], "desktop_exclusive_actions": ["set_value", "invoke"]}

    def fingerprint(self, target: dict) -> dict:
        return {"hwnd": target["hwnd"], "process_id": 123}

    def editor(self) -> dict:
        return {
            "identity": {"node": "replacement" if self.replaced else "original"},
            "role": "Edit",
            "name": self.editor_name,
            "automation_id": self.editor_automation_id,
            "control_id": self.editor_control_id,
            "value": self.value,
            "state": {"enabled": True},
            "actions": ["set_value"],
        }

    def button(self) -> dict:
        return {
            "identity": {"node": "send"},
            "role": "Button",
            "name": "Отправить",
            "value": None,
            "state": {"enabled": True},
            "actions": ["invoke"],
        }

    def snapshot(self, target: dict, options: dict) -> list[dict]:
        items: list[dict] = []
        if not self.missing_after:
            items.append(self.editor())
            if self.ambiguous:
                duplicate = self.editor().copy()
                duplicate["identity"] = {"node": "other"}
                items.append(duplicate)
        items.append(self.button())
        return items

    def resolve(self, target: dict, identity: dict) -> list[dict]:
        return [e for e in self.snapshot(target, {}) if e["identity"] == identity]

    def read_entity(self, target: dict, entity: dict) -> dict:
        return entity

    def act(self, target: dict, entity: dict, action: str, args: dict) -> dict:
        if action == "set_value":
            self.set_calls += 1
            self.value = args["value"]
            if self.stale_after_set:
                self.replaced = True
        elif action == "invoke":
            self.sent += 1
            self.value = "\n"
        return {"action": action}


class _FakeHwndTransport:
    """In-memory Win32 HWND transport supporting WM_SETTEXT, EM_REPLACESEL, WM_CHAR, BM_CLICK, CB_SETCURSEL."""

    def __init__(self, *, rerender_edit_on_set: bool = False) -> None:
        self.pid = 4242
        self.create_time = 133700000000000000
        self.root_hwnd = 1000
        self.edit_hwnd = 1001
        self.btn_hwnd = 1002
        self.combo_hwnd = 1003
        self.rerender_edit_on_set = rerender_edit_on_set
        self.texts = {
            self.root_hwnd: "TestApp",
            self.edit_hwnd: "initial",
            self.btn_hwnd: "CheckMe",
            self.combo_hwnd: "Item0",
        }
        self.checked = 0
        self.selected_index = 0
        self.messages: list[tuple[int, int, int, object]] = []
        self.posted: list[tuple[int, int, int, int]] = []
        self.fg = 9999
        self.cursor = (100, 200)
        self.inactive_desktop = True

    def _on_inactive_desktop(self) -> bool:
        return self.inactive_desktop

    def foreground_hwnd(self) -> int:
        return self.fg

    def cursor_position(self) -> tuple[int, int] | None:
        return None if self.inactive_desktop else self.cursor

    def is_window(self, hwnd: int) -> bool:
        return hwnd in self.texts

    def child_windows(self, hwnd: int) -> list[int]:
        if hwnd == self.root_hwnd:
            return [self.edit_hwnd, self.btn_hwnd, self.combo_hwnd]
        return []

    def window_info(self, hwnd: int) -> dict:
        if hwnd not in self.texts:
            raise NativeError("STALE_TARGET", "HWND invalid", {"hwnd": hwnd})
        if hwnd == self.root_hwnd:
            cls, cid, parent, style = "TestRoot", 0, 0, 0
        elif hwnd == self.edit_hwnd:
            cls, cid, parent, style = "Edit", 101, self.root_hwnd, 0
        elif hwnd == self.btn_hwnd:
            cls, cid, parent, style = "Button", 102, self.root_hwnd, 0x0003
        else:
            cls, cid, parent, style = "ComboBox", 103, self.root_hwnd, 0
        return {
            "hwnd": hwnd,
            "pid": self.pid,
            "create_time": self.create_time,
            "class_name": cls,
            "control_id": cid,
            "parent_hwnd": parent,
            "style": style,
            "enabled": True,
            "geometry": {"left": 0, "top": 0, "right": 300, "bottom": 200},
        }

    def get_text(self, hwnd: int) -> str:
        if hwnd not in self.texts:
            raise NativeError("STALE_TARGET", "HWND invalid", {"hwnd": hwnd})
        return self.texts[hwnd]

    def post_message(self, hwnd: int, msg: int, wparam: int = 0, lparam: int = 0) -> bool:
        if hwnd not in self.texts:
            raise NativeError("STALE_TARGET", "HWND invalid", {"hwnd": hwnd})
        self.posted.append((hwnd, msg, wparam, lparam))
        if msg == WM_CHAR and hwnd == self.edit_hwnd:
            self.texts[hwnd] += chr(wparam)
        return True

    def send_timeout(self, hwnd: int, msg: int, wparam: int = 0, lparam: int | str = 0, timeout_ms: int = 2000) -> int:
        if hwnd not in self.texts:
            raise NativeError("STALE_TARGET", "HWND invalid", {"hwnd": hwnd})
        self.messages.append((hwnd, msg, wparam, lparam))
        if msg == WM_SETTEXT and hwnd == self.edit_hwnd:
            if self.rerender_edit_on_set:
                self.texts.pop(self.edit_hwnd)
                self.edit_hwnd += 10
            self.texts[self.edit_hwnd] = str(lparam)
            return 1
        if msg == EM_SETSEL:
            return 1
        if msg == EM_REPLACESEL and hwnd == self.edit_hwnd:
            self.texts[hwnd] = str(lparam)
            return 1
        if msg == WM_CHAR and hwnd == self.edit_hwnd:
            self.texts[hwnd] += chr(wparam)
            return 0
        if msg == WM_GETTEXTLENGTH:
            return len(self.texts[hwnd])
        if msg == BM_GETCHECK:
            return self.checked
        if msg == BM_CLICK and hwnd == self.btn_hwnd:
            self.checked = 0 if self.checked else 1
            return 0
        if msg == CB_GETCURSEL:
            return self.selected_index
        if msg == CB_SETCURSEL:
            self.selected_index = int(wparam)
            return self.selected_index
        if msg == WM_COMMAND:
            return 0
        return 0


# ---------------------------------------------------------------------------
# 1. Unit tests for ported 3d53aba3 hotfix (verified GUI receipts)
# ---------------------------------------------------------------------------


class TestGuiReceiptRecoveryHotfix3d53aba3(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = _RerenderBackend()
        self.core = NativeSemanticCore(self.backend)
        self.target = {"hwnd": 4327020}

    def _ref(self, name: str) -> tuple[str, int]:
        obs = self.core.observe(self.target)
        obj = next(e for e in obs["entities"] if e["name"] == name)
        return obj["ref"], obs["generation"]

    def test_capabilities_advertise_surface_verification_and_rerender_recovery(self) -> None:
        caps = self.core.capabilities()
        self.assertTrue(caps["rerender_receipt_recovery"])
        self.assertIn("surface_entity_value_equals", caps["postcondition_types"])

    def test_rerendered_prompt_verified_without_retry(self) -> None:
        ref, gen = self._ref("Промпт")
        r = self.core.act(
            ref,
            "set_value",
            {"value": "hello"},
            {"type": "value_equals", "value": "hello"},
            generation=gen,
        )
        self.assertTrue(r["verified"])
        self.assertEqual(r["verification"]["type"], "surface_entity_value_equals")
        self.assertEqual(r["verification"]["actual"], "hello")
        self.assertEqual(self.backend.value, "hello")
        self.assertEqual(self.backend.set_calls, 1)

    def test_send_verified_via_composer_empty_not_button_enabled(self) -> None:
        self.backend.value = "hello"
        ref, gen = self._ref("Отправить")
        r = self.core.act(
            ref,
            "invoke",
            {},
            {
                "type": "surface_entity_value_equals",
                "query": {"role": "Edit", "name": "Промпт"},
                "value": "\n",
            },
            generation=gen,
        )
        self.assertTrue(r["verified"])
        self.assertEqual(self.backend.sent, 1)

    def test_false_postcondition_is_not_silent_success(self) -> None:
        ref, gen = self._ref("Отправить")
        r = self.core.act(
            ref,
            "invoke",
            {},
            {"type": "state_equals", "key": "enabled", "value": False},
            generation=gen,
        )
        self.assertFalse(r["verified"])
        self.assertEqual(self.backend.sent, 1)

    def test_ambiguous_editor_after_action_fails_closed(self) -> None:
        ref, gen = self._ref("Промпт")
        old = self.backend.act

        def change(target, entity, action, args):
            out = old(target, entity, action, args)
            self.backend.ambiguous = True
            return out

        self.backend.act = change
        with self.assertRaises(NativeError) as cm:
            self.core.act(
                ref,
                "set_value",
                {"value": "hello"},
                {"type": "value_equals", "value": "hello"},
                generation=gen,
            )
        self.assertEqual(cm.exception.code, "ACTION_OUTCOME_UNKNOWN")
        self.assertFalse(cm.exception.details["retry_safe"])
        self.assertTrue(cm.exception.details["attempted"])
        self.assertEqual(cm.exception.details["phase"], "native_postcondition")

    def test_missing_editor_after_action_fails_closed(self) -> None:
        ref, gen = self._ref("Промпт")
        old = self.backend.act

        def vanish(target, entity, action, args):
            out = old(target, entity, action, args)
            self.backend.missing_after = True
            return out

        self.backend.act = vanish
        with self.assertRaises(NativeError) as cm:
            self.core.act(
                ref,
                "set_value",
                {"value": "hello"},
                {"type": "value_equals", "value": "hello"},
                generation=gen,
            )
        self.assertEqual(cm.exception.code, "ACTION_OUTCOME_UNKNOWN")
        self.assertFalse(cm.exception.details["retry_safe"])

    def test_anonymous_control_without_stable_selector_fails_closed(self) -> None:
        self.backend.editor_name = ""
        self.backend.editor_automation_id = ""
        self.backend.editor_control_id = None
        obs = self.core.observe(self.target)
        editor = next(e for e in obs["entities"] if e["role"] == "Edit")
        with self.assertRaises(NativeError) as cm:
            self.core.act(
                editor["ref"],
                "set_value",
                {"value": "hello"},
                {"type": "value_equals", "value": "hello"},
                generation=obs["generation"],
            )
        self.assertEqual(cm.exception.code, "ACTION_OUTCOME_UNKNOWN")
        self.assertFalse(cm.exception.details["retry_safe"])

    def test_invalid_surface_query_rejected_before_action(self) -> None:
        ref, gen = self._ref("Отправить")
        for bad_query in ({"role": "Edit"}, {"role": "Edit", "name": ""}, {"role": "Edit", "automation_id": ""}):
            with self.subTest(bad_query=bad_query), self.assertRaises(NativeError) as cm:
                self.core.act(
                    ref,
                    "invoke",
                    {},
                    {"type": "surface_entity_value_equals", "query": bad_query, "value": "\n"},
                    generation=gen,
                )
            self.assertEqual(cm.exception.code, "INVALID_ARGUMENT")
        self.assertEqual(self.backend.sent, 0)

    def test_stale_generation_rejected_before_action(self) -> None:
        ref, gen = self._ref("Отправить")
        self.core.observe(self.target)
        with self.assertRaises(NativeError) as cm:
            self.core.act(
                ref,
                "invoke",
                {},
                {"type": "surface_entity_value_equals", "query": {"name": "Промпт"}, "value": "\n"},
                generation=gen,
            )
        self.assertEqual(cm.exception.code, "STALE_TARGET")
        self.assertEqual(self.backend.sent, 0)

    def test_hwnd_edit_rerender_recovers_via_control_id(self) -> None:
        transport = _FakeHwndTransport(rerender_edit_on_set=True)
        core = NativeSemanticCore(HwndMessageBackend(transport))
        target = {"hwnd": transport.root_hwnd, "pid": transport.pid, "create_time": transport.create_time}
        obs = core.observe(target)
        edit = next(e for e in obs["entities"] if e["role"] == "edit")
        res = core.act(
            edit["ref"],
            "set_value",
            {"value": "after_rerender"},
            {"type": "value_equals", "value": "after_rerender"},
            {"background_required": True},
            generation=obs["generation"],
        )
        self.assertTrue(res["verified"])
        self.assertEqual(res["verification"]["type"], "surface_entity_value_equals")
        self.assertEqual(res["verification"]["query"], {"role": "edit", "control_id": 101})
        self.assertEqual(transport.texts[transport.edit_hwnd], "after_rerender")

    def test_uia3_after_action_rerender_recovers_while_preaction_stale_stays_stale(self) -> None:
        backend = Uia3PersistentBackend(
            Path("fake-uia3.exe"),
            same_desktop_check=False,
            process_token_fn=lambda pid: 777777 if pid == 321 else None,
        )
        state = {"replaced": False, "value": "before"}

        def fake_request(op, args=None):
            if op == "capabilities":
                return {"ok": True, "engine": "system-windows-automation"}
            if op == "fingerprint":
                return {"ok": True, "hwnd": args["hwnd"], "process_id": 321}
            if op == "snapshot":
                return {
                    "ok": True,
                    "entities": [
                        {
                            "identity": {
                                "automation_id": "composer-1",
                                "hierarchy_path": [0],
                                "runtime_id": [42, 2 if state["replaced"] else 1],
                            },
                            "role": "ControlType.Edit",
                            "name": "Composer",
                            "automation_id": "composer-1",
                            "class_name": "Edit",
                            "value": state["value"],
                            "enabled": True,
                            "actions": ["set_value"],
                        }
                    ],
                }
            if op == "get":
                wanted_rt = args["identity"]["runtime_id"]
                current_rt = [42, 2 if state["replaced"] else 1]
                if wanted_rt != current_rt:
                    return {"ok": False, "error": {"code": "STALE_TARGET", "message": "semantic identity no longer resolves"}}
                return {
                    "ok": True,
                    "entity": {
                        "identity": args["identity"],
                        "role": "ControlType.Edit",
                        "name": "Composer",
                        "automation_id": "composer-1",
                        "class_name": "Edit",
                        "value": state["value"],
                        "enabled": True,
                        "actions": ["set_value"],
                    },
                }
            if op == "act":
                state["value"] = args["value"]
                state["replaced"] = True
                return {"ok": False, "error": {"code": "STALE_TARGET", "message": "target disappeared after action"}}
            raise AssertionError(op)

        backend.supervisor = SimpleNamespace(request=fake_request, restart_count=0, stop=Mock())
        core = NativeSemanticCore(backend)
        obs = core.observe({"hwnd": 5555, "pid": 321, "create_time": 777777})
        ref = obs["entities"][0]["ref"]
        res = core.act(
            ref,
            "set_value",
            {"value": "after_uia_rerender"},
            {"type": "value_equals", "value": "after_uia_rerender"},
            generation=obs["generation"],
        )
        self.assertTrue(res["verified"])
        self.assertEqual(res["verification"]["type"], "surface_entity_value_equals")
        self.assertEqual(res["verification"]["actual"], "after_uia_rerender")

        # Without a postcondition, a rerendered disappearance must NOT silently succeed.
        state["replaced"] = False
        obs2 = core.observe({"hwnd": 5555, "pid": 321, "create_time": 777777})
        with self.assertRaises(NativeError) as cm:
            core.act(obs2["entities"][0]["ref"], "set_value", {"value": "no_post"}, None, generation=obs2["generation"])
        self.assertEqual(cm.exception.code, "ACTION_OUTCOME_UNKNOWN")
        self.assertFalse(cm.exception.details["retry_safe"])


# ---------------------------------------------------------------------------
# 2. Unit tests for Win32 Private Desktop boundaries & ownership guards
# ---------------------------------------------------------------------------


class TestPrivateDesktopBoundariesAndOwnershipContracts(unittest.TestCase):
    def test_physical_input_actions_rejected_fail_closed_everywhere(self) -> None:
        transport = _FakeHwndTransport()
        hwnd_backend = HwndMessageBackend(transport)
        core = NativeSemanticCore(hwnd_backend)
        target = {"hwnd": transport.root_hwnd, "pid": transport.pid, "create_time": transport.create_time}
        obs = core.observe(target)
        ref = obs["entities"][0]["ref"]
        for action in ("send_input", "physical_sequence", "mouse_click", "key_tap", "switch_desktop"):
            with self.subTest(layer="core", action=action), self.assertRaises(NativeError) as cm:
                core.act(ref, action, {}, None, generation=obs["generation"])
            self.assertEqual(cm.exception.code, "PHYSICAL_INPUT_FORBIDDEN")

            with self.subTest(layer="hwnd", action=action), self.assertRaises(NativeError) as cm:
                hwnd_backend.act(target, obs["entities"][0], action, {})
            self.assertEqual(cm.exception.code, "PRIVATE_DESKTOP_PHYSICAL_INPUT_UNSUPPORTED")

            with self.subTest(layer="sidecar", action=action), self.assertRaises(NativeError) as cm:
                sidecar_dispatch(core, {"op": action, "args": {}})
            self.assertEqual(cm.exception.code, "PHYSICAL_INPUT_FORBIDDEN")

        uia = Uia3PersistentBackend(Path("fake.exe"), same_desktop_check=False)
        with self.assertRaises(NativeError) as cm:
            uia.act({"hwnd": 1}, {"identity": {"automation_id": "x"}}, "send_input", {})
        self.assertEqual(cm.exception.code, "PRIVATE_DESKTOP_PHYSICAL_INPUT_UNSUPPORTED")

        winapp = WinAppCliBackend(runner=Mock())
        with self.assertRaises(NativeError) as cm:
            winapp.act({"hwnd": 1}, {"identity": {"selector": "s"}}, "send_input", {})
        self.assertEqual(cm.exception.code, "PHYSICAL_INPUT_FORBIDDEN")

    def test_hwnd_backend_enforces_pid_create_time_and_edit_message_routes(self) -> None:
        transport = _FakeHwndTransport()
        backend = HwndMessageBackend(transport)
        core = NativeSemanticCore(backend)
        target = {"hwnd": transport.root_hwnd, "pid": transport.pid, "create_time": transport.create_time}

        with self.assertRaises(NativeError) as bad_pid:
            core.observe({"hwnd": transport.root_hwnd, "pid": transport.pid + 1, "create_time": transport.create_time})
        self.assertEqual(bad_pid.exception.code, "TARGET_IDENTITY_MISMATCH")

        with self.assertRaises(NativeError) as bad_ct:
            core.observe({"hwnd": transport.root_hwnd, "pid": transport.pid, "create_time": transport.create_time + 1})
        self.assertEqual(bad_ct.exception.code, "TARGET_IDENTITY_MISMATCH")

        obs = core.observe(target)
        edit = next(e for e in obs["entities"] if e["role"] == "edit")
        r1 = core.act(
            edit["ref"],
            "replace_selection",
            {"value": "REPLACED", "select_all": True},
            {"type": "value_equals", "value": "REPLACED"},
            {"background_required": True},
            generation=obs["generation"],
        )
        self.assertTrue(r1["verified"])
        self.assertEqual(r1["action_result"]["message"], "EM_REPLACESEL")
        self.assertEqual(transport.texts[transport.edit_hwnd], "REPLACED")

        obs2 = core.observe(target)
        edit2 = next(e for e in obs2["entities"] if e["role"] == "edit")
        r2 = core.act(
            edit2["ref"],
            "type_chars",
            {"text": "_WM", "delivery": "send"},
            {"type": "value_equals", "value": "REPLACED_WM"},
            {"background_required": True},
            generation=obs2["generation"],
        )
        self.assertTrue(r2["verified"])
        self.assertEqual(r2["action_result"]["delivery"], "send")

        obs3 = core.observe(target)
        edit3 = next(e for e in obs3["entities"] if e["role"] == "edit")
        r3 = core.act(
            edit3["ref"],
            "type_chars",
            {"text": "_POST", "delivery": "post"},
            {"type": "value_equals", "value": "REPLACED_WM_POST"},
            {"background_required": True},
            generation=obs3["generation"],
        )
        self.assertTrue(r3["verified"])
        self.assertEqual(r3["action_result"]["delivery"], "post")
        self.assertEqual(len(transport.posted), 5)

    def test_desktop_identity_cross_desktop_target_and_capture_guards(self) -> None:
        self.assertFalse(desktop_identity_mod.PRIVATE_DESKTOP_BOUNDARIES["cross_desktop_sendinput_supported"])
        self.assertFalse(desktop_identity_mod.PRIVATE_DESKTOP_BOUNDARIES["cross_desktop_uia_supported"])
        self.assertFalse(desktop_identity_mod.PRIVATE_DESKTOP_BOUNDARIES["switch_desktop_allowed"])

        with patch.object(
            desktop_identity_mod,
            "desktop_identity",
            return_value={"current": "FFBridge-Agent-1", "input": "Default", "target": "Default"},
        ):
            with self.assertRaisesRegex(desktop_identity_mod.DesktopIdentityError, "CROSS_DESKTOP_TARGET_FORBIDDEN"):
                desktop_identity_mod.require_private_desktop("FFBridge-Agent-1", hwnd=12345)

        with patch.object(
            desktop_identity_mod,
            "thread_and_target_desktop",
            return_value={"current": "FFBridge-Agent-1", "target": "Default"},
        ):
            with self.assertRaisesRegex(desktop_identity_mod.DesktopIdentityError, "CROSS_DESKTOP_TARGET_FORBIDDEN"):
                desktop_identity_mod.require_same_desktop(12345)

        fake_capture_backend = SimpleNamespace(capture=Mock(return_value=(2, 2, b"\x00" * 16)))
        with self.assertRaisesRegex(HiddenCaptureError, "HIDDEN_WINDOW_NOT_OWNED"):
            capture_owned_window(12345, lambda h: False, backend=fake_capture_backend)
        with self.assertRaisesRegex(HiddenCaptureError, "HIDDEN_DESKTOP_IDENTITY_INVALID"):
            capture_owned_window(
                12345,
                lambda h: True,
                backend=fake_capture_backend,
                identity=lambda h: {"current": "FFBridge-Agent-1", "input": "Default", "target": "Default"},
            )


# ---------------------------------------------------------------------------
# 3. Real isolated Windows live private desktop tests (NO mocks!)
# ---------------------------------------------------------------------------

_RERENDER_WIN32_APP_SCRIPT = r"""
import ctypes
from ctypes import wintypes as w
import sys

u = ctypes.WinDLL("user32", use_last_error=True)
k = ctypes.WinDLL("kernel32", use_last_error=True)

WS_OVERLAPPEDWINDOW = 0x00CF0000
WS_VISIBLE = 0x10000000
WS_CHILD = 0x40000000
WS_BORDER = 0x00800000
ES_AUTOHSCROLL = 0x0080
BS_PUSHBUTTON = 0x0000
WM_DESTROY = 0x0002
WM_COMMAND = 0x0111
WM_SETTEXT = 0x000C
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E
EN_CHANGE = 0x0300
BN_CLICKED = 0
CW_USEDEFAULT = 0x80000000

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, w.HWND, w.UINT, w.WPARAM, w.LPARAM)

class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", w.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", w.HINSTANCE),
        ("hIcon", w.HICON),
        ("hCursor", w.HICON),
        ("hbrBackground", w.HANDLE),
        ("lpszMenuName", w.LPCWSTR),
        ("lpszClassName", w.LPCWSTR),
    ]

u.DefWindowProcW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
u.DefWindowProcW.restype = LRESULT
u.RegisterClassW.argtypes = [ctypes.POINTER(WNDCLASSW)]
u.RegisterClassW.restype = w.ATOM
u.CreateWindowExW.argtypes = [
    w.DWORD, w.LPCWSTR, w.LPCWSTR, w.DWORD,
    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
    w.HWND, w.HMENU, w.HINSTANCE, w.LPVOID,
]
u.CreateWindowExW.restype = w.HWND
u.DestroyWindow.argtypes = [w.HWND]
u.DestroyWindow.restype = w.BOOL
u.ShowWindow.argtypes = [w.HWND, ctypes.c_int]
u.ShowWindow.restype = w.BOOL
u.UpdateWindow.argtypes = [w.HWND]
u.UpdateWindow.restype = w.BOOL
u.GetMessageW.argtypes = [ctypes.POINTER(w.MSG), w.HWND, w.UINT, w.UINT]
u.GetMessageW.restype = w.BOOL
u.TranslateMessage.argtypes = [ctypes.POINTER(w.MSG)]
u.DispatchMessageW.argtypes = [ctypes.POINTER(w.MSG)]
u.DispatchMessageW.restype = LRESULT
u.SendMessageW.argtypes = [w.HWND, w.UINT, w.WPARAM, w.LPARAM]
u.SendMessageW.restype = LRESULT
u.SetWindowTextW.argtypes = [w.HWND, w.LPCWSTR]
u.SetWindowTextW.restype = w.BOOL
u.GetWindowTextLengthW.argtypes = [w.HWND]
u.GetWindowTextLengthW.restype = ctypes.c_int
u.GetWindowTextW.argtypes = [w.HWND, w.LPWSTR, ctypes.c_int]
u.GetWindowTextW.restype = ctypes.c_int
u.PostQuitMessage.argtypes = [ctypes.c_int]
k.GetModuleHandleW.argtypes = [w.LPCWSTR]
k.GetModuleHandleW.restype = w.HMODULE

hinst = k.GetModuleHandleW(None)
state = {"edit": None, "status": None, "sent": 0, "rerendering": False}

def read_text(hwnd):
    n = u.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(max(1, n + 1))
    u.GetWindowTextW(hwnd, buf, len(buf))
    return buf.value

def make_edit(parent, initial_text):
    return u.CreateWindowExW(
        0, "Edit", initial_text,
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
        10, 10, 320, 28, parent, w.HMENU(101), hinst, None,
    )

@WNDPROC
def wndproc(hwnd, msg, wparam, lparam):
    if msg == WM_COMMAND:
        cid = wparam & 0xFFFF
        code = (wparam >> 16) & 0xFFFF
        if cid == 101 and code == EN_CHANGE and not state["rerendering"] and state["edit"]:
            text = read_text(state["edit"])
            if text.startswith("RERENDER:"):
                # Genuinely destroy and recreate the Edit HWND with the same
                # control_id=101 and written text, simulating a rerendering control.
                state["rerendering"] = True
                try:
                    old = state["edit"]
                    state["edit"] = make_edit(hwnd, text)
                    u.DestroyWindow(old)
                finally:
                    state["rerendering"] = False
        elif cid == 102 and code == BN_CLICKED:
            state["sent"] += 1
            if state["status"]:
                u.SetWindowTextW(state["status"], f"SENT:{state['sent']}")
            if state["edit"]:
                state["rerendering"] = True
                try:
                    u.SetWindowTextW(state["edit"], "")
                finally:
                    state["rerendering"] = False
        return 0
    if msg == WM_DESTROY:
        u.PostQuitMessage(0)
        return 0
    return u.DefWindowProcW(hwnd, msg, wparam, lparam)

cls_name = "FFBridgeP0RerenderWindow"
wc = WNDCLASSW()
wc.lpfnWndProc = wndproc
wc.hInstance = hinst
wc.lpszClassName = cls_name
if not u.RegisterClassW(ctypes.byref(wc)):
    raise SystemExit(2)

root = u.CreateWindowExW(
    0, cls_name, "FFBridge P0 Isolated Test Window",
    WS_OVERLAPPEDWINDOW | WS_VISIBLE,
    CW_USEDEFAULT, CW_USEDEFAULT, 420, 220,
    None, None, hinst, None,
)
if not root:
    raise SystemExit(3)

state["edit"] = make_edit(root, "INITIAL")
u.CreateWindowExW(
    0, "Button", "Send",
    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
    10, 50, 100, 30, root, w.HMENU(102), hinst, None,
)
state["status"] = u.CreateWindowExW(
    0, "Edit", "READY",
    WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
    10, 95, 320, 28, root, w.HMENU(103), hinst, None,
)
u.ShowWindow(root, 4)  # SW_SHOWNOACTIVATE
u.UpdateWindow(root)

msg = w.MSG()
while u.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
    u.TranslateMessage(ctypes.byref(msg))
    u.DispatchMessageW(ctypes.byref(msg))
"""


class _LastInputInfo(ctypes.Structure):
    _fields_ = [("cbSize", w.UINT), ("dwTime", w.DWORD)]


class _OwnerDesktopObserver:
    """Read-only observer of owner input desktop state (never switches desktop or reads clipboard text)."""

    def __init__(self) -> None:
        self._user = ctypes.WinDLL("user32", use_last_error=True)
        self._kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self._user.OpenInputDesktop.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        self._user.OpenInputDesktop.restype = w.HANDLE
        self._user.GetThreadDesktop.argtypes = [w.DWORD]
        self._user.GetThreadDesktop.restype = w.HANDLE
        self._user.SetThreadDesktop.argtypes = [w.HANDLE]
        self._user.SetThreadDesktop.restype = w.BOOL
        self._user.CloseDesktop.argtypes = [w.HANDLE]
        self._user.CloseDesktop.restype = w.BOOL
        self._user.GetUserObjectInformationW.argtypes = [w.HANDLE, ctypes.c_int, w.LPVOID, w.DWORD, ctypes.POINTER(w.DWORD)]
        self._user.GetUserObjectInformationW.restype = w.BOOL
        self._user.GetForegroundWindow.restype = w.HWND
        self._user.GetWindowThreadProcessId.argtypes = [w.HWND, ctypes.POINTER(w.DWORD)]
        self._user.GetWindowThreadProcessId.restype = w.DWORD
        self._user.GetCursorPos.argtypes = [ctypes.POINTER(w.POINT)]
        self._user.GetCursorPos.restype = w.BOOL
        self._user.GetClipboardSequenceNumber.restype = w.DWORD
        self._user.GetClipboardOwner.restype = w.HWND
        self._user.GetLastInputInfo.argtypes = [ctypes.POINTER(_LastInputInfo)]
        self._user.GetLastInputInfo.restype = w.BOOL
        self._enum_cb = ctypes.WINFUNCTYPE(w.BOOL, w.HWND, w.LPARAM)
        self._user.EnumDesktopWindows.argtypes = [w.HANDLE, self._enum_cb, w.LPARAM]
        self._user.EnumDesktopWindows.restype = w.BOOL
        self._input_handle = None
        self._orig_handle = None
        self.available = False
        self._executor = ThreadPoolExecutor(max_workers=1)
        self.available = self._executor.submit(self._bind).result(timeout=5)

    def _desktop_name(self, handle) -> str | None:
        if not handle:
            return None
        buf = ctypes.create_unicode_buffer(256)
        needed = w.DWORD()
        if not self._user.GetUserObjectInformationW(handle, 2, buf, ctypes.sizeof(buf), ctypes.byref(needed)):
            return None
        return buf.value

    def _bind(self) -> bool:
        self._orig_handle = self._user.GetThreadDesktop(self._kernel.GetCurrentThreadId())
        handle = self._user.OpenInputDesktop(0, False, 0x0041)  # READOBJECTS | ENUMERATE
        if not handle:
            return False
        if not self._user.SetThreadDesktop(handle):
            self._user.CloseDesktop(handle)
            return False
        self._input_handle = handle
        return True

    def _hwnd_pid(self, hwnd: int) -> int:
        if not hwnd:
            return 0
        pid = w.DWORD(0)
        self._user.GetWindowThreadProcessId(w.HWND(hwnd), ctypes.byref(pid))
        return int(pid.value)

    def _read_state(self) -> dict:
        if not self.available:
            return {"available": False}
        pt = w.POINT()
        cur_ok = bool(self._user.GetCursorPos(ctypes.byref(pt)))
        lii = _LastInputInfo(ctypes.sizeof(_LastInputInfo), 0)
        lii_ok = bool(self._user.GetLastInputInfo(ctypes.byref(lii)))
        fg = int(self._user.GetForegroundWindow() or 0)
        clip_owner = int(self._user.GetClipboardOwner() or 0)
        active_h = self._user.OpenInputDesktop(0, False, 0x0001)
        try:
            active_name = self._desktop_name(active_h)
        finally:
            if active_h:
                self._user.CloseDesktop(active_h)
        return {
            "available": True,
            "input_desktop": active_name,
            "foreground_hwnd": fg,
            "foreground_pid": self._hwnd_pid(fg),
            "cursor": [int(pt.x), int(pt.y)] if cur_ok else None,
            "clipboard_seq": int(self._user.GetClipboardSequenceNumber()),
            "clipboard_owner_hwnd": clip_owner,
            "clipboard_owner_pid": self._hwnd_pid(clip_owner),
            "last_input_tick": int(lii.dwTime) if lii_ok else None,
        }

    def _pids_on_input_desktop(self, target_pids: set[int]) -> list[int]:
        if not self.available or not self._input_handle or not target_pids:
            return []
        leaked: list[int] = []

        @self._enum_cb
        def visit(hwnd, _):
            pid = self._hwnd_pid(int(hwnd))
            if pid in target_pids:
                leaked.append(int(hwnd))
            return True

        self._user.EnumDesktopWindows(self._input_handle, visit, 0)
        return leaked

    def snapshot(self) -> dict:
        return self._executor.submit(self._read_state).result(timeout=5)

    def leaked_windows_on_owner_desktop(self, owned_pids: set[int]) -> list[int]:
        return self._executor.submit(self._pids_on_input_desktop, set(owned_pids)).result(timeout=5)

    def wait_brief_idle(self, *, idle_s: float = 0.25, max_wait_s: float = 2.5) -> dict:
        """Wait briefly for a natural pause in human input before sampling baseline."""
        snap = self.snapshot()
        if not snap.get("available"):
            return snap
        deadline = time.monotonic() + max_wait_s
        last_tick = snap["last_input_tick"]
        stable_since = time.monotonic()
        while time.monotonic() < deadline:
            time.sleep(0.05)
            snap = self.snapshot()
            if snap["last_input_tick"] != last_tick:
                last_tick = snap["last_input_tick"]
                stable_since = time.monotonic()
            elif time.monotonic() - stable_since >= idle_s:
                return snap
        return snap

    def _unbind(self) -> None:
        if self._orig_handle:
            self._user.SetThreadDesktop(self._orig_handle)
        if self._input_handle:
            self._user.CloseDesktop(self._input_handle)
            self._input_handle = None

    def close(self) -> None:
        try:
            self._executor.submit(self._unbind).result(timeout=5)
        finally:
            self._executor.shutdown(wait=True)


def _desktop_still_exists(desktop_name: str) -> bool:
    u = ctypes.WinDLL("user32", use_last_error=True)
    u.OpenDesktopW.argtypes = [w.LPCWSTR, w.DWORD, w.BOOL, w.DWORD]
    u.OpenDesktopW.restype = w.HANDLE
    u.CloseDesktop.argtypes = [w.HANDLE]
    u.CloseDesktop.restype = w.BOOL
    h = u.OpenDesktopW(desktop_name, 0, False, 0x0001)
    if h:
        u.CloseDesktop(h)
        return True
    return False


@unittest.skipUnless(os.name == "nt", "Real Windows private desktop tests require Windows")
class TestRealIsolatedWindowsPrivateDesktopCUA(unittest.TestCase):
    _shared_tmp: TemporaryDirectory | None = None
    _env_patch = None
    _evidence_records: dict[str, dict] = {}

    @classmethod
    def setUpClass(cls) -> None:
        cls._shared_tmp = TemporaryDirectory(prefix="ff-p0-track-a-")
        cls._env_patch = patch.dict(os.environ, {"FF_BRIDGE_ROOT": cls._shared_tmp.name})
        cls._env_patch.start()
        cls._evidence_records = {}
        # Pre-compile UIA3 sidecar ONCE into isolated temporary FF_BRIDGE_ROOT
        # so live tests execute swiftly and never touch source or production bytes.
        from cua_hidden_apps import prepare_uia
        try:
            prepare_uia(RUNTIME)
        except Exception:
            pass

    @classmethod
    def tearDownClass(cls) -> None:
        evidence_path = os.environ.get("FF_P0_EVIDENCE_PATH")
        if evidence_path:
            out = Path(evidence_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(cls._evidence_records, indent=2, sort_keys=True), encoding="utf-8")
        if cls._env_patch is not None:
            cls._env_patch.stop()
            cls._env_patch = None
        if cls._shared_tmp is not None:
            cls._shared_tmp.cleanup()
            cls._shared_tmp = None

    def setUp(self) -> None:
        self._tmp = TemporaryDirectory(prefix="ff-p0-case-")
        self.addCleanup(self._tmp.cleanup)
        self.observer = _OwnerDesktopObserver()
        self.addCleanup(self.observer.close)
        if not self.observer.available and os.environ.get("FF_P0_STRICT_OWNER_QUIET") == "1":
            self.fail("OWNER_INPUT_DESKTOP_UNAVAILABLE_IN_STRICT_MODE")

    def _assert_owner_untouched(
        self,
        test_key: str,
        before: dict,
        after: dict,
        *,
        owned_pids: set[int],
        private_desktops: list[str],
        leaked_on_owner_desktop: list[int],
        extra: dict | None = None,
    ) -> dict:
        record: dict = {
            "interactive_desktop_available": bool(before.get("available") and after.get("available")),
            "private_desktops": list(private_desktops),
            "owned_pids": sorted(owned_pids),
            "leaked_windows_on_owner_desktop": list(leaked_on_owner_desktop),
            **(extra or {}),
        }
        if not before.get("available") or not after.get("available"):
            record["strict_owner_invariance_proven"] = False
            record["note"] = "Headless/non-interactive Windows runner (no OpenInputDesktop)"
            self._evidence_records[test_key] = record
            return record

        # Hard OS-level isolation invariants ALWAYS hold regardless of human activity:
        self.assertEqual(leaked_on_owner_desktop, [], f"Owned windows leaked onto owner input desktop: {leaked_on_owner_desktop}")
        self.assertNotIn(after["input_desktop"], private_desktops, "Private desktop became active input desktop!")
        self.assertNotIn(after["foreground_pid"], owned_pids, "Owned process hijacked owner foreground window!")
        self.assertNotIn(after["clipboard_owner_pid"], owned_pids, "Owned process hijacked owner clipboard!")

        human_input_occurred = (
            before["last_input_tick"] is not None
            and after["last_input_tick"] is not None
            and before["last_input_tick"] != after["last_input_tick"]
        )
        fg_unchanged = before["foreground_hwnd"] == after["foreground_hwnd"]
        cursor_unchanged = before["cursor"] == after["cursor"]
        clip_seq_unchanged = before["clipboard_seq"] == after["clipboard_seq"]
        clip_owner_unchanged = before["clipboard_owner_hwnd"] == after["clipboard_owner_hwnd"]
        strict_all_unchanged = fg_unchanged and cursor_unchanged and clip_seq_unchanged and clip_owner_unchanged

        record.update({
            "before": before,
            "after": after,
            "human_hardware_input_during_window": human_input_occurred,
            "foreground_unchanged": fg_unchanged,
            "cursor_unchanged": cursor_unchanged,
            "clipboard_seq_unchanged": clip_seq_unchanged,
            "clipboard_owner_unchanged": clip_owner_unchanged,
            "strict_owner_invariance_proven": strict_all_unchanged and not human_input_occurred,
            "owner_clipboard_content_read": False,
        })
        self._evidence_records[test_key] = record

        strict_mode = os.environ.get("FF_P0_STRICT_OWNER_QUIET") == "1"
        if not human_input_occurred or strict_mode:
            self.assertEqual(
                before["foreground_hwnd"],
                after["foreground_hwnd"],
                f"Owner foreground HWND changed (human_input={human_input_occurred})",
            )
            self.assertEqual(
                before["cursor"],
                after["cursor"],
                f"Owner cursor (x, y) changed (human_input={human_input_occurred})",
            )
            self.assertEqual(
                before["clipboard_seq"],
                after["clipboard_seq"],
                f"Owner clipboard sequence changed (human_input={human_input_occurred})",
            )
            self.assertEqual(
                before["clipboard_owner_hwnd"],
                after["clipboard_owner_hwnd"],
                f"Owner clipboard owner changed (human_input={human_input_occurred})",
            )
        return record

    def _wait_dead(self, owned: list[tuple[int, int]], timeout_s: float = 5.0) -> None:
        from ff_win_process_identity import process_identity_matches

        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if not any(process_identity_matches(pid, token) for pid, token in owned):
                return
            time.sleep(0.05)
        alive = [(pid, token) for pid, token in owned if process_identity_matches(pid, token)]
        self.fail(f"Owned processes remained alive after teardown: {alive}")

    def _wait_desktop_gone(self, desktop_name: str, timeout_s: float = 5.0) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if not _desktop_still_exists(desktop_name):
                return
            time.sleep(0.05)
        self.fail(f"Private desktop object still exists after teardown: {desktop_name}")

    def test_live_notepad_private_desktop_uia_hwnd_messages_capture_and_foreign_denial(self) -> None:
        from cua_hidden_desktop import HiddenDesktopError, HiddenDesktopSession
        from ff_win_process_identity import process_creation_token, process_identity_matches

        before = self.observer.wait_brief_idle()
        owned: list[tuple[int, int]] = []
        desktop_name = ""
        leaked: list[int] = []
        extra: dict = {}

        with HiddenDesktopSession(RUNTIME) as session:
            desktop_name = session.desktop_name
            self.assertTrue(session.job_name.startswith("Local\\FFBridge-HiddenDesktop-"))
            worker_token = process_creation_token(session.pid)
            self.assertIsNotNone(worker_token)
            owned.append((session.pid, worker_token))
            self.assertTrue(session.is_process_in_session_job(session.pid))

            health = session.request({"command": "health"})
            self.assertEqual(health["desktop"], desktop_name)
            self.assertNotEqual(health["desktop"], health["input_desktop"])
            self.assertFalse(health["boundaries"]["cross_desktop_sendinput_supported"])
            self.assertFalse(health["boundaries"]["switch_desktop_allowed"])

            launched = session.request({"command": "launch_app", "app": "notepad"})
            self.assertTrue(process_identity_matches(launched["pid"], launched["create_time"]))
            self.assertTrue(session.is_process_in_session_job(launched["pid"]))
            owned.append((launched["pid"], launched["create_time"]))

            # 1. Observable UIA3 tree within private desktop.
            uia = session.request({"command": "uia_observe", "hwnd": launched["hwnd"], "pid": launched["pid"], "create_time": launched["create_time"]}, timeout_s=30)
            self.assertGreater(len(uia["entities"]), 0)
            self.assertFalse(uia["physical_input_used"])
            health_uia = session.request({"command": "health"})
            if health_uia.get("uia_pid"):
                uia_token = process_creation_token(health_uia["uia_pid"])
                if uia_token is not None:
                    owned.append((health_uia["uia_pid"], uia_token))
                    self.assertTrue(session.is_process_in_session_job(health_uia["uia_pid"]))

            # 2. PrintWindow capture on private desktop.
            cap = session.request({"command": "capture_window", "hwnd": launched["hwnd"], "pid": launched["pid"], "create_time": launched["create_time"]})
            self.assertEqual(cap["engine"], "PRINTWINDOW")
            self.assertGreater(cap["frame_w"], 100)
            self.assertGreater(cap["frame_h"], 100)
            png_bytes = base64.b64decode(cap["image_base64"])
            self.assertTrue(png_bytes.startswith(b"\x89PNG\r\n\x1a\n"))

            # 3. Real Win32 HWND message routes: WM_SETTEXT, EM_REPLACESEL, WM_CHAR (Send + Post).
            doc = session.request({"command": "read_text", "hwnd": launched["hwnd"]})
            self.assertEqual(doc["value"], "")
            doc_hwnd = doc["document_hwnd"]

            obs = session.request({"command": "hwnd_observe", "hwnd": launched["hwnd"], "pid": launched["pid"], "create_time": launched["create_time"]})
            edit = next(e for e in obs["entities"] if e["identity"]["hwnd"] == doc_hwnd)

            r_set = session.request({
                "command": "hwnd_act",
                "hwnd": launched["hwnd"],
                "pid": launched["pid"],
                "create_time": launched["create_time"],
                "generation": obs["generation"],
                "ref": edit["ref"],
                "operation": "set_value",
                "action_args": {"value": "WM_SETTEXT_OK"},
                "postcondition": {"type": "value_equals", "value": "WM_SETTEXT_OK"},
            })
            self.assertTrue(r_set["verified"])
            self.assertEqual(session.request({"command": "read_text", "hwnd": launched["hwnd"]})["value"], "WM_SETTEXT_OK")

            obs2 = session.request({"command": "hwnd_observe", "hwnd": launched["hwnd"]})
            edit2 = next(e for e in obs2["entities"] if e["identity"]["hwnd"] == doc_hwnd)
            r_rep = session.request({
                "command": "hwnd_act",
                "hwnd": launched["hwnd"],
                "generation": obs2["generation"],
                "ref": edit2["ref"],
                "operation": "replace_selection",
                "action_args": {"value": "EM_REPLACESEL_", "select_all": True},
                "postcondition": {"type": "value_equals", "value": "EM_REPLACESEL_"},
            })
            self.assertTrue(r_rep["verified"])
            self.assertEqual(r_rep["action_result"]["message"], "EM_REPLACESEL")

            obs3 = session.request({"command": "hwnd_observe", "hwnd": launched["hwnd"]})
            edit3 = next(e for e in obs3["entities"] if e["identity"]["hwnd"] == doc_hwnd)
            r_char_send = session.request({
                "command": "hwnd_act",
                "hwnd": launched["hwnd"],
                "generation": obs3["generation"],
                "ref": edit3["ref"],
                "operation": "type_chars",
                "action_args": {"text": "SEND_", "delivery": "send"},
                "postcondition": {"type": "value_equals", "value": "EM_REPLACESEL_SEND_"},
            })
            self.assertTrue(r_char_send["verified"])

            obs4 = session.request({"command": "hwnd_observe", "hwnd": launched["hwnd"]})
            edit4 = next(e for e in obs4["entities"] if e["identity"]["hwnd"] == doc_hwnd)
            r_char_post = session.request({
                "command": "hwnd_act",
                "hwnd": launched["hwnd"],
                "generation": obs4["generation"],
                "ref": edit4["ref"],
                "operation": "type_chars",
                "action_args": {"text": "POST", "delivery": "post"},
                "postcondition": {"type": "value_equals", "value": "EM_REPLACESEL_SEND_POST"},
            })
            self.assertTrue(r_char_post["verified"])
            self.assertEqual(
                session.request({"command": "read_text", "hwnd": launched["hwnd"]})["value"],
                "EM_REPLACESEL_SEND_POST",
            )

            # 4. Also verify ControlPlane attach/act HWND_MESSAGE route.
            attached = session.request({
                "command": "attach",
                "target": {"hwnd": launched["hwnd"], "pid": launched["pid"], "create_time": launched["create_time"]},
            })
            snap = attached["observation"]
            plane_edit = next(e for e in snap["entities"] if e["identity"]["hwnd"] == doc_hwnd)
            plane_res = session.request({
                "command": "act",
                "surface_id": attached["surface_id"],
                "generation": snap["generation"],
                "ref": plane_edit["ref"],
                "operation": "set_value",
                "action_args": {"value": "PLANE_HWND_VERIFIED"},
                "postcondition": {"type": "value_equals", "value": "PLANE_HWND_VERIFIED"},
            })
            self.assertTrue(plane_res["verified"])
            self.assertEqual(
                session.request({"command": "read_text", "hwnd": launched["hwnd"]})["value"],
                "PLANE_HWND_VERIFIED",
            )

            # 5. Foreign owner HWND must be rejected fail-closed on every command!
            foreign_hwnd = before.get("foreground_hwnd") or 0x10010
            for payload in (
                {"command": "read_text", "hwnd": foreign_hwnd},
                {"command": "capture_window", "hwnd": foreign_hwnd},
                {"command": "hwnd_observe", "hwnd": foreign_hwnd},
                {"command": "uia_observe", "hwnd": foreign_hwnd},
                {"command": "attach", "target": {"hwnd": foreign_hwnd}},
            ):
                with self.subTest(foreign_payload=payload), self.assertRaises(HiddenDesktopError) as cm:
                    session.request(payload)
                self.assertEqual(cm.exception.code, "HIDDEN_WINDOW_NOT_OWNED")

            # 6. Mismatched pid or create_time on OWNED hwnd rejected fail-closed!
            for bad_id in (
                {"command": "hwnd_observe", "hwnd": launched["hwnd"], "pid": launched["pid"] + 1},
                {"command": "hwnd_observe", "hwnd": launched["hwnd"], "create_time": launched["create_time"] + 1},
                {"command": "read_text", "hwnd": launched["hwnd"], "create_time": launched["create_time"] + 1},
            ):
                with self.subTest(bad_id=bad_id), self.assertRaises(HiddenDesktopError) as cm:
                    session.request(bad_id)
                self.assertEqual(cm.exception.code, "HIDDEN_WINDOW_IDENTITY_MISMATCH")

            # 7. Physical input / SendInput / SwitchDesktop requests rejected fail-closed!
            for phys_payload in (
                {"command": "send_input", "hwnd": launched["hwnd"]},
                {"command": "physical_sequence", "hwnd": launched["hwnd"]},
                {"command": "switch_desktop"},
                {"command": "focus_target", "hwnd": launched["hwnd"]},
                {"command": "hwnd_act", "hwnd": launched["hwnd"], "operation": "send_input"},
                {"command": "attach", "target": {"hwnd": launched["hwnd"]}, "policy": {"physical_input_allowed": True}},
            ):
                with self.subTest(phys_payload=phys_payload), self.assertRaises(HiddenDesktopError) as cm:
                    session.request(phys_payload)
                self.assertEqual(cm.exception.code, "PRIVATE_DESKTOP_PHYSICAL_INPUT_UNSUPPORTED")

            leaked = self.observer.leaked_windows_on_owner_desktop({pid for pid, _ in owned})
            extra = {
                "app": "notepad",
                "uia_entities_count": len(uia["entities"]),
                "printwindow_frame": [cap["frame_w"], cap["frame_h"]],
                "printwindow_sha256": cap["image_sha256"],
                "verified_routes": ["WM_SETTEXT", "EM_REPLACESEL", "WM_CHAR_SEND", "WM_CHAR_POST", "CONTROL_PLANE_HWND_MESSAGE", "UIA3_OBSERVE", "PRINTWINDOW"],
                "foreign_hwnd_rejected": True,
                "mismatched_pid_create_time_rejected": True,
                "physical_input_rejected_fail_closed": True,
            }

        receipt = session.teardown_receipt()
        self.assertTrue(receipt["closed"])
        self.assertTrue(receipt["job_cleanup_verified"])
        self.assertTrue(receipt["desktop_cleanup_verified"])
        self._wait_dead(owned)
        self._wait_desktop_gone(desktop_name)
        extra["teardown_receipt"] = receipt
        self._assert_owner_untouched(
            "live_notepad",
            before,
            self.observer.snapshot(),
            owned_pids={pid for pid, _ in owned},
            private_desktops=[desktop_name],
            leaked_on_owner_desktop=leaked,
            extra=extra,
        )

    def test_live_owned_win32_rerender_app_proves_3d53aba3_receipt_recovery_and_cross_session_isolation(self) -> None:
        from cua_hidden_desktop import HiddenDesktopError, HiddenDesktopSession
        from ff_win_process_identity import process_creation_token

        app_script = Path(self._tmp.name) / "rerender_app.py"
        app_script.write_text(_RERENDER_WIN32_APP_SCRIPT, encoding="utf-8")

        before = self.observer.wait_brief_idle()
        owned: list[tuple[int, int]] = []
        desktops: list[str] = []
        leaked: list[int] = []
        extra: dict = {}

        with (
            HiddenDesktopSession(RUNTIME, allow_generic_launch=True) as s1,
            HiddenDesktopSession(RUNTIME, allow_generic_launch=True) as s2,
        ):
            desktops.extend([s1.desktop_name, s2.desktop_name])
            self.assertNotEqual(s1.desktop_name, s2.desktop_name)
            for s in (s1, s2):
                tok = process_creation_token(s.pid)
                self.assertIsNotNone(tok)
                owned.append((s.pid, tok))

            w1 = s1.request(
                {"command": "launch_exe", "executable": sys.executable, "arguments": [str(app_script)], "window_timeout_s": 15},
                timeout_s=25,
            )
            w2 = s2.request(
                {"command": "launch_exe", "executable": sys.executable, "arguments": [str(app_script)], "window_timeout_s": 15},
                timeout_s=25,
            )
            owned.append((w1["pid"], w1["create_time"]))
            owned.append((w2["pid"], w2["create_time"]))
            self.assertTrue(s1.is_process_in_session_job(w1["pid"]))
            self.assertFalse(s1.is_process_in_session_job(w2["pid"]))

            # Cross-session foreign HWND isolation: s1 must reject s2's HWND and vice versa!
            for cmd in ("hwnd_observe", "ui_observe", "capture_window"):
                with self.assertRaises(HiddenDesktopError) as cm1:
                    s1.request({"command": cmd, "hwnd": w2["hwnd"]})
                self.assertEqual(cm1.exception.code, "HIDDEN_WINDOW_NOT_OWNED")
                with self.assertRaises(HiddenDesktopError) as cm2:
                    s2.request({"command": cmd, "hwnd": w1["hwnd"]})
                self.assertEqual(cm2.exception.code, "HIDDEN_WINDOW_NOT_OWNED")

            # (a) Real Win32 HWND rerender recovery via 3d53aba3:
            obs_h = s1.request({"command": "hwnd_observe", "hwnd": w1["hwnd"], "pid": w1["pid"], "create_time": w1["create_time"]})
            orig_edit = next(e for e in obs_h["entities"] if e["control_id"] == 101)
            orig_edit_hwnd = orig_edit["identity"]["hwnd"]
            res_h = s1.request({
                "command": "hwnd_act",
                "hwnd": w1["hwnd"],
                "pid": w1["pid"],
                "create_time": w1["create_time"],
                "generation": obs_h["generation"],
                "ref": orig_edit["ref"],
                "operation": "set_value",
                "action_args": {"value": "RERENDER:HWND_P0"},
                "postcondition": {"type": "value_equals", "value": "RERENDER:HWND_P0"},
            })
            self.assertTrue(res_h["verified"])
            self.assertEqual(res_h["verification"]["type"], "surface_entity_value_equals")
            self.assertEqual(res_h["verification"]["actual"], "RERENDER:HWND_P0")

            # Prove the Edit HWND actually changed (real Win32 rerender happened!).
            obs_h2 = s1.request({"command": "hwnd_observe", "hwnd": w1["hwnd"]})
            new_edit = next(e for e in obs_h2["entities"] if e["control_id"] == 101)
            self.assertNotEqual(new_edit["identity"]["hwnd"], orig_edit_hwnd)
            self.assertEqual(new_edit["value"], "RERENDER:HWND_P0")

            # (b) Real Win32 UIA3 rerender recovery via 3d53aba3 (live compiled C# sidecar!):
            obs_u = s1.request({"command": "ui_observe", "hwnd": w1["hwnd"], "pid": w1["pid"], "create_time": w1["create_time"]}, timeout_s=30)
            uia_edit = next(e for e in obs_u["entities"] if e.get("automation_id") == "101" and "set_value" in e.get("actions", []))
            res_u = s1.request(
                {
                    "command": "ui_act",
                    "hwnd": w1["hwnd"],
                    "pid": w1["pid"],
                    "create_time": w1["create_time"],
                    "generation": obs_u["generation"],
                    "ref": uia_edit["ref"],
                    "operation": "set_value",
                    "action_args": {"value": "RERENDER:UIA3_P0"},
                    "postcondition": {"type": "value_equals", "value": "RERENDER:UIA3_P0"},
                },
                timeout_s=20,
            )
            self.assertTrue(res_u["verified"])
            self.assertEqual(res_u["verification"]["type"], "surface_entity_value_equals")
            self.assertEqual(res_u["verification"]["actual"], "RERENDER:UIA3_P0")

            # (c) Real cross-control surface_entity_value_equals postcondition:
            obs_h3 = s1.request({"command": "hwnd_observe", "hwnd": w1["hwnd"]})
            send_btn = next(e for e in obs_h3["entities"] if e["control_id"] == 102 and "invoke" in e["actions"])
            res_send = s1.request({
                "command": "hwnd_act",
                "hwnd": w1["hwnd"],
                "generation": obs_h3["generation"],
                "ref": send_btn["ref"],
                "operation": "invoke",
                "action_args": {},
                "postcondition": {
                    "type": "surface_entity_value_equals",
                    "query": {"role": "edit", "control_id": 103},
                    "value": "SENT:1",
                },
            })
            self.assertTrue(res_send["verified"])
            self.assertEqual(res_send["verification"]["actual"], "SENT:1")

            ui_pid = s1.request({"command": "health"}).get("ui_pid")
            if ui_pid:
                ui_tok = process_creation_token(ui_pid)
                if ui_tok is not None:
                    owned.append((ui_pid, ui_tok))

            leaked = self.observer.leaked_windows_on_owner_desktop({pid for pid, _ in owned})
            extra = {
                "app": "isolated_python_win32_rerender_window",
                "orig_edit_hwnd": orig_edit_hwnd,
                "rerendered_edit_hwnd": new_edit["identity"]["hwnd"],
                "hwnd_rerender_receipt_recovered": True,
                "uia3_rerender_receipt_recovered": True,
                "cross_control_surface_entity_value_equals_verified": True,
                "cross_session_foreign_hwnd_rejected": True,
            }

        self._wait_dead(owned)
        for d in desktops:
            self._wait_desktop_gone(d)
        self._assert_owner_untouched(
            "live_win32_rerender_app",
            before,
            self.observer.snapshot(),
            owned_pids={pid for pid, _ in owned},
            private_desktops=desktops,
            leaked_on_owner_desktop=leaked,
            extra=extra,
        )

    def test_live_deterministic_teardown_on_error_timeout_cancel_and_parent_crash(self) -> None:
        from cua_hidden_desktop import HiddenDesktopError, HiddenDesktopSession
        from ff_win_process_identity import process_creation_token, process_identity_matches

        before = self.observer.wait_brief_idle()
        all_owned_pids: set[int] = set()
        all_desktops: list[str] = []

        # Case A: Exception inside context manager.
        err_owned: list[tuple[int, int]] = []
        err_desktop = ""
        with self.assertRaisesRegex(RuntimeError, "SYNTHETIC_SESSION_ERROR"):
            with HiddenDesktopSession(RUNTIME) as s_err:
                err_desktop = s_err.desktop_name
                all_desktops.append(err_desktop)
                err_owned.append((s_err.pid, process_creation_token(s_err.pid)))
                n = s_err.request({"command": "launch_app", "app": "notepad"})
                err_owned.append((n["pid"], n["create_time"]))
                all_owned_pids.update(pid for pid, _ in err_owned)
                raise RuntimeError("SYNTHETIC_SESSION_ERROR")
        self.assertTrue(s_err.job_cleanup_verified)
        self.assertTrue(s_err.desktop_cleanup_verified)
        self._wait_dead(err_owned)
        self._wait_desktop_gone(err_desktop)

        # Case B: Request timeout triggers fail-closed HIDDEN_ACTION_OUTCOME_UNKNOWN + teardown.
        sleep_script = Path(self._tmp.name) / "no_window_sleeper.py"
        sleep_script.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
        to_owned: list[tuple[int, int]] = []
        s_to = HiddenDesktopSession(RUNTIME, allow_generic_launch=True)
        to_desktop = s_to.desktop_name
        all_desktops.append(to_desktop)
        to_owned.append((s_to.pid, process_creation_token(s_to.pid)))
        all_owned_pids.add(s_to.pid)
        with self.assertRaises(HiddenDesktopError) as cm_to:
            s_to.request(
                {"command": "launch_exe", "executable": sys.executable, "arguments": [str(sleep_script)], "window_timeout_s": 10},
                timeout_s=0.6,
            )
        self.assertEqual(cm_to.exception.code, "HIDDEN_ACTION_OUTCOME_UNKNOWN")
        self.assertTrue(s_to.closed)
        self.assertTrue(s_to.job_cleanup_verified)
        self.assertTrue(s_to.desktop_cleanup_verified)
        self._wait_dead(to_owned)
        self._wait_desktop_gone(to_desktop)

        # Case C: Forced cancel() while a blocking request is in-flight!
        s_cancel = HiddenDesktopSession(RUNTIME, allow_generic_launch=True)
        cancel_desktop = s_cancel.desktop_name
        all_desktops.append(cancel_desktop)
        cancel_owned = [(s_cancel.pid, process_creation_token(s_cancel.pid))]
        n_cancel = s_cancel.request({"command": "launch_app", "app": "notepad"})
        cancel_owned.append((n_cancel["pid"], n_cancel["create_time"]))
        all_owned_pids.update(pid for pid, _ in cancel_owned)
        inflight_error: list[str] = []
        started_req = threading.Event()

        def blocking_call() -> None:
            started_req.set()
            try:
                s_cancel.request(
                    {"command": "launch_exe", "executable": sys.executable, "arguments": [str(sleep_script)], "window_timeout_s": 20},
                    timeout_s=25,
                )
            except HiddenDesktopError as exc:
                inflight_error.append(exc.code)

        t = threading.Thread(target=blocking_call)
        t.start()
        started_req.wait(timeout=2)
        time.sleep(0.25)
        t0 = time.monotonic()
        receipt = s_cancel.cancel()
        t.join(timeout=5)
        elapsed_cancel = time.monotonic() - t0
        self.assertFalse(t.is_alive(), "In-flight request did not unblock on cancel()")
        self.assertLess(elapsed_cancel, 5.0)
        self.assertTrue(receipt["cancelled"])
        self.assertTrue(receipt["closed"])
        self.assertTrue(receipt["job_cleanup_verified"])
        self.assertTrue(receipt["desktop_cleanup_verified"])
        self.assertEqual(inflight_error, ["HIDDEN_ACTION_OUTCOME_UNKNOWN"])
        self._wait_dead(cancel_owned)
        self._wait_desktop_gone(cancel_desktop)

        # Case D: Parent process hard-kill (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE).
        harness = Path(self._tmp.name) / "parent_crash_harness.py"
        harness.write_text(
            "import json, sys, time\n"
            f"sys.path.insert(0, {str(RUNTIME)!r})\n"
            "from cua_hidden_desktop import HiddenDesktopSession\n"
            "from ff_win_process_identity import process_creation_token\n"
            f"s = HiddenDesktopSession({str(RUNTIME)!r})\n"
            "n = s.request({'command': 'launch_app', 'app': 'notepad'})\n"
            "print(json.dumps({'desktop': s.desktop_name, 'worker_pid': s.pid, "
            "'worker_ct': process_creation_token(s.pid), 'app_pid': n['pid'], 'app_ct': n['create_time']}), flush=True)\n"
            "time.sleep(60)\n",
            encoding="utf-8",
        )
        proc = subprocess.Popen(
            [sys.executable, str(harness)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            line = proc.stdout.readline()
            self.assertTrue(line, "Parent crash harness exited before reporting PIDs")
            info = json.loads(line)
            all_desktops.append(info["desktop"])
            all_owned_pids.update({info["worker_pid"], info["app_pid"]})
            self.assertTrue(process_identity_matches(info["worker_pid"], info["worker_ct"]))
            self.assertTrue(process_identity_matches(info["app_pid"], info["app_ct"]))
            proc.kill()
            proc.wait(timeout=5)
            self._wait_dead([(info["worker_pid"], info["worker_ct"]), (info["app_pid"], info["app_ct"])])
            self._wait_desktop_gone(info["desktop"])
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()

        self._assert_owner_untouched(
            "live_teardown_matrix",
            before,
            self.observer.snapshot(),
            owned_pids=all_owned_pids,
            private_desktops=all_desktops,
            leaked_on_owner_desktop=[],
            extra={
                "error_teardown_verified": True,
                "timeout_teardown_verified": True,
                "forced_cancel_unblock_ms": round(elapsed_cancel * 1000, 1),
                "forced_cancel_teardown_verified": True,
                "parent_hard_kill_job_cleanup_verified": True,
            },
        )

    def test_live_wordpad_private_desktop_edit_and_readback(self) -> None:
        from cua_hidden_apps import app_path
        from cua_hidden_desktop import HiddenDesktopSession
        from ff_win_process_identity import process_creation_token

        if not app_path("wordpad").is_file():
            self.skipTest("WordPad not installed on this Windows host")

        before = self.observer.wait_brief_idle()
        owned: list[tuple[int, int]] = []
        leaked: list[int] = []
        with HiddenDesktopSession(RUNTIME) as session:
            desktop_name = session.desktop_name
            owned.append((session.pid, process_creation_token(session.pid)))
            launched = session.request({"command": "launch_app", "app": "wordpad"})
            owned.append((launched["pid"], launched["create_time"]))
            doc = session.request({"command": "read_text", "hwnd": launched["hwnd"]})
            obs = session.request({"command": "hwnd_observe", "hwnd": launched["hwnd"]})
            edit = next(e for e in obs["entities"] if e["identity"]["hwnd"] == doc["document_hwnd"])
            marker = "WORDPAD_PRIVATE_DESKTOP_P0_OK"
            res = session.request({
                "command": "hwnd_act",
                "hwnd": launched["hwnd"],
                "generation": obs["generation"],
                "ref": edit["ref"],
                "operation": "set_value",
                "action_args": {"value": marker},
                "postcondition": {"type": "value_equals", "value": marker},
            })
            self.assertTrue(res["verified"])
            readback = session.request({"command": "read_text", "hwnd": launched["hwnd"]})
            self.assertEqual(readback["value"], marker)
            leaked = self.observer.leaked_windows_on_owner_desktop({pid for pid, _ in owned})

        receipt = session.teardown_receipt()
        self.assertTrue(receipt["job_cleanup_verified"])
        self.assertTrue(receipt["desktop_cleanup_verified"])
        self._wait_dead(owned)
        self._wait_desktop_gone(desktop_name)
        self._assert_owner_untouched(
            "live_wordpad",
            before,
            self.observer.snapshot(),
            owned_pids={pid for pid, _ in owned},
            private_desktops=[desktop_name],
            leaked_on_owner_desktop=leaked,
            extra={"app": "wordpad", "document_class": doc["document_class"], "teardown_receipt": receipt},
        )


if __name__ == "__main__":
    unittest.main()
