"""Regression tests for windowless hidden-target scheduler liveness and press keyboard fidelity."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"))
from cua_owner_chrome_secondary import (
    OwnerChromeHiddenSecondaryManager,
    _HIDDEN_TARGET_LIVENESS_JS,
    _parse_press_key,
)

URL = "https://gemini.google.com/app"
OWNER = "test-agent\x1ftest-task"
TAB = "hsec-liveness"


class FakeCDP:
    def __init__(self):
        self.calls: list[tuple[str, dict, str | None]] = []

    def send(self, method: str, params: dict | None = None, *, session_id: str | None = None, timeout: float = 10.0):
        self.calls.append((method, dict(params or {}), session_id))
        if method == "Target.createTarget":
            return {"targetId": "TID-1"}
        if method == "Browser.getWindowForTarget":
            from cua_owner_chrome_secondary import OwnerChromeSecondaryError
            raise OwnerChromeSecondaryError("OWNER_CHROME_CDP_REJECTED", "No browser window")
        if method == "Target.attachToTarget":
            return {"sessionId": "SID-1"}
        if method == "Page.navigate":
            return {"frameId": "F1"}
        if method == "Runtime.evaluate":
            expr = str((params or {}).get("expression") or "")
            if "document.readyState" in expr:
                return {"result": {"value": {"rs": "complete", "url": URL, "title": "Gemini"}}}
            return {"result": {"value": True}}
        return {}


class HiddenTargetLivenessAndPressTests(unittest.TestCase):
    def test_open_installs_liveness_preload_script_before_navigate(self):
        mgr = OwnerChromeHiddenSecondaryManager(profile_dir_name="Default")
        cdp = FakeCDP()
        mgr._cdp = cdp
        verified = {
            "default_browser_context_id": "CTX-DEFAULT",
            "chrome_version": "Chrome/158.0.8127.36",
        }
        with patch.object(mgr, "_ensure_connected", return_value=verified):
            opened = mgr.call("open", {"owner": OWNER, "url": URL})

        self.assertEqual(opened["url"], URL)
        methods = [m for m, _, _ in cdp.calls]
        self.assertIn("Page.enable", methods)
        self.assertIn("Emulation.setFocusEmulationEnabled", methods)
        self.assertIn("Page.addScriptToEvaluateOnNewDocument", methods)
        self.assertIn("Page.navigate", methods)
        enable_idx = methods.index("Page.enable")
        focus_idx = methods.index("Emulation.setFocusEmulationEnabled")
        add_idx = methods.index("Page.addScriptToEvaluateOnNewDocument")
        nav_idx = methods.index("Page.navigate")
        self.assertLess(enable_idx, add_idx, "Page.enable must run before addScriptToEvaluateOnNewDocument")
        self.assertLess(focus_idx, nav_idx, "focus emulation must enable before Page.navigate")
        self.assertLess(add_idx, nav_idx, "liveness preload script must install before Page.navigate")
        _, focus_params, focus_sid = cdp.calls[focus_idx]
        self.assertEqual(focus_sid, "SID-1")
        self.assertEqual(focus_params, {"enabled": True})
        _, params, sid = cdp.calls[add_idx]
        self.assertEqual(sid, "SID-1")
        self.assertEqual(params.get("source"), _HIDDEN_TARGET_LIVENESS_JS)
        self.assertIn("requestIdleCallback", _HIDDEN_TARGET_LIVENESS_JS)
        self.assertIn("cancelIdleCallback", _HIDDEN_TARGET_LIVENESS_JS)
        self.assertIn("requestAnimationFrame", _HIDDEN_TARGET_LIVENESS_JS)
        self.assertIn("cancelAnimationFrame", _HIDDEN_TARGET_LIVENESS_JS)

    def test_open_about_blank_also_evaluates_liveness_immediately(self):
        mgr = OwnerChromeHiddenSecondaryManager(profile_dir_name="Default")
        cdp = FakeCDP()
        mgr._cdp = cdp
        verified = {
            "default_browser_context_id": "CTX-DEFAULT",
            "chrome_version": "Chrome/158.0.8127.36",
        }
        with patch.object(mgr, "_ensure_connected", return_value=verified):
            mgr.call("open", {"owner": OWNER, "url": "about:blank"})

        eval_calls = [p.get("expression", "") for m, p, _ in cdp.calls if m == "Runtime.evaluate"]
        self.assertTrue(any("__ff_hidden_target_liveness_v1__" in expr for expr in eval_calls))

    def test_parse_press_key_populates_keycode_which_and_modifiers(self):
        self.assertEqual(
            _parse_press_key("Enter"),
            {
                "key": "Enter",
                "code": "Enter",
                "keyCode": 13,
                "which": 13,
                "ctrlKey": False,
                "shiftKey": False,
                "altKey": False,
                "metaKey": False,
            },
        )
        self.assertEqual(
            _parse_press_key("Shift+Enter"),
            {
                "key": "Enter",
                "code": "Enter",
                "keyCode": 13,
                "which": 13,
                "ctrlKey": False,
                "shiftKey": True,
                "altKey": False,
                "metaKey": False,
            },
        )
        self.assertEqual(
            _parse_press_key("Ctrl+Shift+k"),
            {
                "key": "k",
                "code": "KeyK",
                "keyCode": 75,
                "which": 75,
                "ctrlKey": True,
                "shiftKey": True,
                "altKey": False,
                "metaKey": False,
            },
        )
        self.assertEqual(_parse_press_key("Escape")["keyCode"], 27)
        self.assertEqual(_parse_press_key("Tab")["keyCode"], 9)
        self.assertEqual(_parse_press_key("Space")["code"], "Space")
        self.assertEqual(_parse_press_key("Space")["keyCode"], 32)
        self.assertEqual(_parse_press_key("+")["key"], "+")
        self.assertEqual(_parse_press_key("Ctrl++")["ctrlKey"], True)
        self.assertEqual(_parse_press_key("Ctrl++")["key"], "+")
        for punct in (".", "-", "'", "(", "&", "%", "!"):
            parsed = _parse_press_key(punct)
            self.assertEqual(parsed["key"], punct)
            self.assertEqual(parsed["keyCode"], 0)
            self.assertEqual(parsed["which"], 0)

    def test_press_action_focuses_element_and_gates_form_submit_on_unmodified_enter(self):
        mgr = OwnerChromeHiddenSecondaryManager(profile_dir_name="Default")
        mgr._targets[TAB] = {
            "tab_id": TAB,
            "target_id": "T",
            "owner": OWNER,
            "url": URL,
            "title": "Gemini",
            "snapshot": None,
        }
        with patch.object(
            mgr,
            "_eval",
            return_value={"acted": True, "url": URL, "title": "Gemini", "detail": "prevented_by_page"},
        ) as ev:
            out = mgr.call(
                "act",
                {
                    "owner": OWNER,
                    "tab_id": TAB,
                    "operation": "press",
                    "selector": ".ql-editor",
                    "key": "Shift+Enter",
                },
            )
        self.assertTrue(out["acted"])
        expr = ev.call_args.args[1]
        self.assertIn("e.focus({preventScroll:true})", expr)
        self.assertIn('"keyCode": 13', expr)
        self.assertIn('"which": 13', expr)
        self.assertIn('"shiftKey": true', expr)
        self.assertIn("!hasMods", expr)


if __name__ == "__main__":
    unittest.main()
