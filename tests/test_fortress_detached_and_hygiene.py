from __future__ import annotations

import sys
from pathlib import Path
_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_ROOT / 'runtime' / 'bridge-v3'))
sys.path.insert(0, str(_ROOT / 'tools'))


import os
import tempfile
import time
import unittest
from pathlib import Path

from detached_log_guard import (
    compute_initial_tail_offset,
    compact_runaway_log_file,
    read_bounded_lines,
    sweep_orphan_detached_logs,
)
from ff_win_detached_job import detached_job_name


class FortressDetachedGuardTests(unittest.TestCase):
    def test_job_name_validation(self):
        self.assertEqual(
            detached_job_name("0c2b74fdce914f5c"),
            r"Local\FFWinBridgeDetached_0c2b74fdce914f5c",
        )
        for bad in ("", "0c2b74fd", "../0c2b74fdce914f", "0C2B74FDCE914F5C", "zzzzzzzzzzzzzzzz"):
            with self.assertRaises(ValueError):
                detached_job_name(bad)

    def test_initial_tail_offset_prevents_oom_on_huge_log(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "0c2b74fdce914f5c.log"
            line = b"FileNotFoundError: [WinError 3] Path not found in _pyrepl\r\n"
            repeats = (6 * 1024 * 1024) // len(line)
            with open(p, "wb") as f:
                f.write(line * repeats)
            offset, skipped = compute_initial_tail_offset(p, max_replay_bytes=2 * 1024 * 1024)
            self.assertGreater(offset, 3 * 1024 * 1024)
            self.assertEqual(offset, skipped)
            with open(p, "rb") as f:
                f.seek(offset - 1)
                prev_byte = f.read(1)
                first_line = f.readline()
            self.assertEqual(prev_byte, b"\n")
            self.assertEqual(first_line, line)

    def test_bounded_chunk_reader_handles_partial_lines(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "abcd1234abcd1234.log"
            p.write_bytes(b"alpha\nbeta\ngamma_partial")
            lines, pos, carry = read_bounded_lines(p, 0, b"", chunk_size=8, max_chunks_per_tick=10)
            self.assertEqual(lines, [b"alpha\n", b"beta\n"])
            self.assertEqual(carry, b"gamma_partial")
            with open(p, "ab") as f:
                f.write(b"_done\ndelta\n")
            lines2, pos2, carry2 = read_bounded_lines(p, pos, carry, chunk_size=16, max_chunks_per_tick=10)
            self.assertEqual(lines2, [b"gamma_partial_done\n", b"delta\n"])
            self.assertEqual(carry2, b"")
            self.assertEqual(pos2, p.stat().st_size)

    def test_runaway_log_compaction_preserves_head_and_tail(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "0c2b74fdce914f5c.log"
            head_marker = b"HEAD_MARKER_START\n"
            tail_marker = b"\nTAIL_MARKER_END\n"
            body = b"X" * (4 * 1024 * 1024)
            p.write_bytes(head_marker + body + tail_marker)
            res = compact_runaway_log_file(p, head_bytes=64 * 1024, tail_bytes=128 * 1024)
            self.assertTrue(res["compacted"])
            self.assertGreater(res["reclaimed_bytes"], 3 * 1024 * 1024)
            compacted_bytes = p.read_bytes()
            self.assertTrue(compacted_bytes.startswith(head_marker))
            self.assertTrue(compacted_bytes.endswith(tail_marker))
            self.assertIn(b"FF-BRIDGE-LOG-QUOTA-GUARD", compacted_bytes)

    def test_sweep_orphan_logs_preserves_active_persisted_and_recent(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            now = time.time()
            active_id = "1111111111111111"
            persisted_id = "2222222222222222"
            recent_orphan = "3333333333333333"
            old_orphan_1 = "4444444444444444"
            old_orphan_2 = "5555555555555555"
            for sid in (active_id, persisted_id, recent_orphan, old_orphan_1, old_orphan_2):
                (d / f"{sid}.log").write_bytes(b"log")
            old_mtime = now - 7200
            for sid in (active_id, persisted_id, old_orphan_1, old_orphan_2):
                os.utime(d / f"{sid}.log", (old_mtime, old_mtime))
            keep_other = d / "notes.txt"
            keep_other.write_text("keep")
            os.utime(keep_other, (old_mtime, old_mtime))

            removed = sweep_orphan_detached_logs(
                d,
                active_session_ids={active_id},
                persisted_session_ids={persisted_id},
                older_than_seconds=3600,
                now_epoch=now,
            )
            self.assertEqual(removed, [old_orphan_1, old_orphan_2])
            self.assertTrue((d / f"{active_id}.log").exists())
            self.assertTrue((d / f"{persisted_id}.log").exists())
            self.assertTrue((d / f"{recent_orphan}.log").exists())
            self.assertTrue(keep_other.exists())


if __name__ == "__main__":
    unittest.main()



import tempfile
import unittest
from pathlib import Path

from workstation_hygiene_engine import (
    check_silent_cleanup_cooldown,
    is_hard_protected,
    select_ring_buffer_prune,
    select_superseded_semver_dirs,
    verify_extracted_zst_redundant,
)


class WorkstationHygieneEngineTests(unittest.TestCase):
    def test_hard_protected_paths_never_allowed(self):
        self.assertTrue(is_hard_protected(r"K:\фоточки 10\IMG_001.JPG"))
        self.assertTrue(is_hard_protected(r"K:\C-DISK-ARCHIVE\Фото iCloud (2).zip"))
        self.assertTrue(is_hard_protected(r"K:\nn-release-keys\keystore.jks"))
        self.assertTrue(is_hard_protected(r"C:\Users\user\Documents\MISIS-Moodle-Bridge\.moodle_credentials.dpapi"))
        self.assertTrue(is_hard_protected(r"K:\FF-Windows-Bridge\recovery\staged-rollout-1acf4f13-20261116"))
        self.assertFalse(is_hard_protected(r"C:\Users\user\AppData\Local\npm-cache"))

    def test_ring_buffer_keeps_two_newest(self):
        items = [
            {"name": "b1.bin", "mtime": 100.0, "bytes": 100},
            {"name": "b2.bin", "mtime": 400.0, "bytes": 100},
            {"name": "b3.bin", "mtime": 300.0, "bytes": 100},
            {"name": "b4.bin", "mtime": 200.0, "bytes": 100},
        ]
        pruned = select_ring_buffer_prune(items, keep_newest=2)
        self.assertEqual([x["name"] for x in pruned], ["b1.bin", "b4.bin"])

    def test_verify_extracted_zst_requires_valid_unpacked_image(self):
        with tempfile.TemporaryDirectory() as td:
            b = Path(td)
            (b / "initrd.zst").write_bytes(b"z" * 1024)
            self.assertEqual(verify_extracted_zst_redundant(b), [])
            (b / "initrd").write_bytes(b"r" * (6 * 1024 * 1024))
            self.assertEqual(verify_extracted_zst_redundant(b), [b / "initrd.zst"])

    def test_superseded_semver_dirs_keeps_highest_version(self):
        with tempfile.TemporaryDirectory() as td:
            r = Path(td)
            for v in ("2.1.320", "2.1.325", "2.1.321"):
                (r / v).mkdir()
            old = select_superseded_semver_dirs(r)
            self.assertEqual([p.name for p in old], ["2.1.321", "2.1.320"])

    def test_silent_cleanup_24h_cooldown(self):
        now = 1_794_789_000.0
        self.assertTrue(check_silent_cleanup_cooldown({}, now))
        self.assertFalse(check_silent_cleanup_cooldown({"last_silent_cleanup_epoch": now - 300}, now))
        self.assertTrue(check_silent_cleanup_cooldown({"last_silent_cleanup_epoch": now - 90000}, now))


if __name__ == "__main__":
    unittest.main()
