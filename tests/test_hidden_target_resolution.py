"""Regression tests for snapshot contract and bounded semantic resolution."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"))
from cua_owner_chrome_secondary import OwnerChromeHiddenSecondaryManager, OwnerChromeSecondaryError

URL = "https://example.com/task"
OWNER = "test-agent\x1ftest-task"
TAB = "hsec-test"
TARGET = {"accessible_name": "Task", "tag": "button", "type": "submit", "document_url": URL}
SUCCESS = {"acted": True, "url": URL, "title": "test", "detail": {"mode": "dom-click"}}

class TargetResolutionTests(unittest.TestCase):
    def setUp(self):
        self.mgr = OwnerChromeHiddenSecondaryManager(profile_dir_name="Default")
        self.rec = {"tab_id": TAB, "target_id": "T", "owner": OWNER, "url": URL,
                    "title": "test", "snapshot": "fresh"}
        self.mgr._targets[TAB] = self.rec

    def act(self, target, **extra):
        return self.mgr.call("act", {"owner": OWNER, "tab_id": TAB,
                                    "operation": "click", "target": target, **extra})

    def test_nested_snapshot_is_accepted(self):
        with patch.object(self.mgr, "_eval", return_value=SUCCESS) as ev:
            out = self.act({"ref": "0", "snapshot": "fresh"})
        self.assertTrue(out["acted"])
        self.assertEqual(ev.call_count, 1)
        self.assertIn('s.token!=="fresh"', ev.call_args.args[1])

    def test_legacy_top_level_snapshot_is_accepted(self):
        with patch.object(self.mgr, "_eval", return_value=SUCCESS):
            self.assertTrue(self.act({"ref": "0"}, snapshot="fresh")["acted"])

    def test_conflicting_snapshot_and_ref_are_rejected_before_eval(self):
        for target, extra in [
            ({"ref": "0", "snapshot": "other"}, {"snapshot": "fresh"}),
            ({"ref": "1", "snapshot": "fresh"}, {"ref": "0"}),
        ]:
            with self.subTest(target=target), patch.object(self.mgr, "_eval") as ev:
                with self.assertRaises(OwnerChromeSecondaryError) as err:
                    self.act(target, **extra)
                self.assertEqual(err.exception.code, "TARGET_INVALID")
                ev.assert_not_called()

    def test_old_numeric_ref_remains_fail_closed(self):
        with patch.object(self.mgr, "_eval") as ev:
            with self.assertRaises(OwnerChromeSecondaryError) as err:
                self.act({"ref": "0", "snapshot": "old"})
            self.assertEqual(err.exception.code, "TARGET_STALE")
            ev.assert_not_called()

    def test_observe_returns_snapshot_independent_locator(self):
        data = {"url": URL, "title": "test", "controls": [
            {"ref": "2", "tag": "button", "type": "submit", "name": "Task"},
            {"ref": "3", "tag": "button", "type": "", "name": ""},
        ]}
        with patch.object(self.mgr, "_eval", return_value=data):
            obs = self.mgr.call("observe", {"owner": OWNER, "tab_id": TAB})
        self.assertEqual(obs["controls"][0]["locator"], TARGET)
        self.assertNotIn("locator", obs["controls"][1])

    def test_semantic_resolution_waits_only_before_action(self):
        with patch.object(self.mgr, "_eval", side_effect=[
            {"error": "TARGET_NOT_FOUND"}, SUCCESS
        ]) as ev, patch("cua_owner_chrome_secondary.time.sleep"):
            result = self.act(TARGET)
        self.assertTrue(result["acted"])
        self.assertEqual(result["resolution_attempts"], 2)
        self.assertEqual(ev.call_count, 2)
        expression = ev.call_args.args[1]
        self.assertIn("TAB_DOCUMENT_CHANGED", expression)
        self.assertIn("TARGET_AMBIGUOUS", expression)
        self.assertIn("aria-disabled", expression)
        self.assertIn("getClientRects", expression)

    def test_semantic_retries_are_bounded(self):
        with patch.object(self.mgr, "_eval", return_value={"error": "TARGET_NOT_FOUND"}) as ev, patch("cua_owner_chrome_secondary.time.sleep"):
            with self.assertRaises(OwnerChromeSecondaryError) as err:
                self.act(TARGET)
            self.assertEqual(err.exception.code, "TARGET_NOT_FOUND")
            self.assertEqual(ev.call_count, 4)

    def test_ambiguity_document_change_and_attempted_failure_never_replay(self):
        for outcome in [
            {"error": "TARGET_AMBIGUOUS"}, {"error": "TAB_DOCUMENT_CHANGED"},
            {"error": "TARGET_NOT_FOUND", "attempted": True},
            {"error": "ACTION_NO_EFFECT", "attempted": True},
        ]:
            with self.subTest(outcome=outcome), patch.object(self.mgr, "_eval", return_value=outcome) as ev:
                with self.assertRaises(OwnerChromeSecondaryError) as err:
                    self.act(TARGET)
                self.assertEqual(err.exception.code, outcome["error"])
                self.assertEqual(ev.call_count, 1)

    def test_unknown_transport_outcome_never_replays(self):
        with patch.object(self.mgr, "_eval", side_effect=OwnerChromeSecondaryError("OWNER_CHROME_CDP_TIMEOUT")) as ev:
            with self.assertRaises(OwnerChromeSecondaryError):
                self.act(TARGET)
            self.assertEqual(ev.call_count, 1)

    def test_other_owner_cannot_resolve(self):
        with patch.object(self.mgr, "_eval") as ev:
            with self.assertRaises(OwnerChromeSecondaryError) as err:
                self.mgr.call("act", {"owner": "other", "tab_id": TAB, "operation": "click", "target": TARGET})
            self.assertEqual(err.exception.code, "TARGET_NOT_OWNED")
            ev.assert_not_called()

if __name__ == "__main__":
    unittest.main()
