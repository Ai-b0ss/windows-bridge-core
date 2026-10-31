"""Exact window fingerprint over JSON transports that cannot preserve uint64 integers."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
from cua_task_authority import AuthorityStore, AuthorityError, DesktopModes
from cua_chat_permission import ChatPermissionPolicy

BIRTH = 13437938351337299800
TARGET = {"hwnd": 197976, "pid": 8704, "process_start_ns": BIRTH,
          "rect": [-8, -8, 1928, 1048], "generation": 0}


class ExactWindowFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        config = self.root / "chat-permission.json"
        config.write_text(json.dumps({"schema": "ff-chat-permission-v1",
                                      "enabled": True}), encoding="utf-8")
        policy = ChatPermissionPolicy(config, self.root / "state")
        self.modes = DesktopModes(self.root / "mode", AuthorityStore(self.root / "auth"),
                                  lambda hwnd: dict(TARGET), chat_permission=policy)

    def request(self, target):
        return {"mode": "dedicated", "agent_id": "chatgpt", "task_id": "usage-read",
                "targets": [target],
                "owner_chat_permission": {"quote": "Да", "apps": ["Claude Desktop"],
                                          "duration_seconds": 120}}

    def test_exact_decimal_string_preserves_fingerprint_and_authorized_action(self):
        target = {**TARGET, "process_start_ns": str(BIRTH)}
        mode = self.modes.transition(self.request(target))
        self.assertEqual(mode["targets"], [TARGET])
        with self.modes.action({"agent_id": "chatgpt", "task_id": "usage-read",
                                "mode_generation": mode["generation"]}, TARGET["hwnd"]):
            pass

    def test_exact_integer_still_accepted(self):
        mode = self.modes.transition(self.request(dict(TARGET)))
        self.assertEqual(mode["targets"], [TARGET])

    def test_rounded_or_edited_fingerprints_remain_rejected(self):
        corrupted = [
            {**TARGET, "process_start_ns": 13437938351337300000},
            {**TARGET, "process_start_ns": str(BIRTH + 1)},
            {**TARGET, "process_start_ns": float(BIRTH)},
            {**TARGET, "process_start_ns": "0" + str(BIRTH)},
            {**TARGET, "process_start_ns": "1e19"},
            {**TARGET, "process_start_ns": "-1"},
            {**TARGET, "process_start_ns": str(2**64)},
            {**TARGET, "pid": TARGET["pid"] + 1},
            {**TARGET, "hwnd": TARGET["hwnd"] + 1},
            {**TARGET, "rect": [0, 0, 1, 1]},
            {**TARGET, "unexpected": True},
        ]
        for target in corrupted:
            with self.subTest(target=target):
                with self.assertRaisesRegex(AuthorityError, "DESKTOP_TARGET_CHANGED"):
                    self.modes.transition(self.request(target))
                self.assertFalse(self.modes.path.exists())


if __name__ == "__main__":
    unittest.main()
