"""Tests for backup-transport poll default and health heartbeat throttling."""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "github-transport"))


class GitHubCommentDaemonThrottleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.home = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.home.cleanup)
        env = {"FF_GH_HOME": cls.home.name, "FF_BRIDGE_ROOT": cls.home.name}
        with patch.dict(os.environ, env, clear=False):
            os.environ.pop("FF_GH_POLL_SECONDS", None)
            os.environ.pop("FF_GH_HEALTH_HEARTBEAT", None)
            cls.daemon = importlib.import_module("ff_win_github_comment_daemon")

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.health_path = self.root / "comment_transport_health.json"
        self.enterContext(patch.object(self.daemon, "GH_HOME", self.root))
        self.enterContext(patch.object(self.daemon, "HEALTH", self.health_path))
        self.enterContext(patch.object(self.daemon, "_last_health_at", 0.0))
        self.enterContext(patch.object(self.daemon, "_last_health_key", None))

    def test_defaults_keep_backup_transport_throttled(self) -> None:
        self.assertEqual(self.daemon.POLL_SECONDS, 1.0)
        self.assertEqual(self.daemon.HEALTH_HEARTBEAT_SECONDS, 2.0)

    def test_write_health_throttles_identical_state_and_flushes_on_change_or_heartbeat(self) -> None:
        clock = [100.0]
        writes = []
        real_replace = os.replace

        def counting_replace(src: Path, dst: Path) -> None:
            writes.append((clock[0], json.loads(Path(src).read_text(encoding="utf-8"))))
            real_replace(src, dst)

        base_payload = {
            "last_error": None,
            "active": 0,
            "durable_pending": 0,
            "quarantined_requests": 0,
            "waiting_for_login": False,
            "scheduled_retries": 0,
            "ts": 1,
        }

        with patch.object(self.daemon.time, "monotonic", side_effect=lambda: clock[0]), \
             patch.object(self.daemon.os, "replace", side_effect=counting_replace):
            # Initial write always succeeds.
            self.daemon.write_health({**base_payload, "ts": 1})
            # Identical state within HEALTH_HEARTBEAT_SECONDS is skipped.
            clock[0] = 100.5
            self.daemon.write_health({**base_payload, "ts": 2})
            # State transition flushes immediately.
            clock[0] = 101.0
            self.daemon.write_health({**base_payload, "active": 1, "ts": 3})
            # Heartbeat expiry (>= 2.0 s) flushes even with identical state.
            clock[0] = 103.1
            self.daemon.write_health({**base_payload, "active": 1, "ts": 4})
            # If the health file was removed externally, rewrite immediately.
            self.health_path.unlink()
            clock[0] = 103.2
            self.daemon.write_health({**base_payload, "active": 1, "ts": 5})

        self.assertEqual([w[1]["ts"] for w in writes], [1, 3, 4, 5])
        self.assertTrue(self.health_path.is_file())


if __name__ == "__main__":
    unittest.main()
