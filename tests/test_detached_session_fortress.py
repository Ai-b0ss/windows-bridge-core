"""Unit and Windows Job integration tests for detached_log_guard and ff_win_detached_job."""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = REPO_ROOT / "runtime" / "bridge-v3"
if str(RUNTIME_DIR) not in sys.path:
    sys.path.insert(0, str(RUNTIME_DIR))

import detached_log_guard as dlg
import ff_win_detached_job as dj


class TestDetachedLogGuard(unittest.TestCase):
    def test_initial_tail_offset_and_bounded_lines(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            lp = Path(td) / "0123456789abcdef.log"
            payload = b"".join(f"line-{i:05d}\n".encode("ascii") for i in range(2000))
            lp.write_bytes(payload)

            off, skipped = dlg.compute_initial_tail_offset(lp, max_replay_bytes=4096)
            self.assertGreater(off, 0)
            self.assertEqual(off, skipped)

            lines, pos, carry = dlg.read_bounded_lines(lp, off, b"", chunk_size=1024, max_chunks_per_tick=8)
            self.assertEqual(pos, len(payload))
            self.assertEqual(carry, b"")
            self.assertTrue(lines[-1].endswith(b"line-01999\n"))

    def test_sol_p2_3_newline_less_8mib_stream_bounds_carry_memory(self) -> None:
        """Sol P2 #3 regression: 8 MiB text without '\\n' must never accumulate >= chunk_size in carry."""
        with tempfile.TemporaryDirectory() as td:
            lp = Path(td) / "9999999999999999.log"
            total_bytes = 8 * 1024 * 1024  # 8 MiB with ZERO newline bytes
            pattern = b"0123456789ABCDEF" * (total_bytes // 16)
            lp.write_bytes(pattern)

            pos = 0
            carry = b""
            reconstructed = bytearray()
            ticks = 0
            while pos < total_bytes:
                ticks += 1
                lines, pos, carry = dlg.read_bounded_lines(
                    lp, pos, carry, chunk_size=dlg.TAILER_READ_CHUNK_BYTES, max_chunks_per_tick=8
                )
                self.assertLess(
                    len(carry),
                    dlg.TAILER_READ_CHUNK_BYTES,
                    msg=f"carry grew to {len(carry)} bytes on tick {ticks}",
                )
                self.assertGreater(
                    len(lines),
                    0,
                    msg="8 MiB stream without newlines must emit bounded chunks rather than buffering silently",
                )
                for chunk in lines:
                    self.assertLessEqual(len(chunk), dlg.TAILER_READ_CHUNK_BYTES)
                    reconstructed.extend(chunk)

            reconstructed.extend(carry)
            self.assertEqual(len(reconstructed), total_bytes)
            self.assertEqual(bytes(reconstructed), pattern)

    def test_compact_runaway_log_and_orphan_sweep(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)
            runaway = d / "aaaaaaaaaaaaaaaa.log"
            runaway.write_bytes(b"H" * 16384 + b"M" * 65536 + b"T" * 16384)
            res = dlg.compact_runaway_log_file(runaway, head_bytes=4096, tail_bytes=4096)
            self.assertTrue(res["compacted"])
            self.assertLess(res["after_bytes"], res["before_bytes"])
            compacted_bytes = runaway.read_bytes()
            self.assertIn(b"FF-BRIDGE-LOG-QUOTA-GUARD", compacted_bytes)

            keep_active = d / "bbbbbbbbbbbbbbbb.log"
            keep_active.write_bytes(b"ok\n")
            orphan = d / "cccccccccccccccc.log"
            orphan.write_bytes(b"stale\n")
            old_ts = time.time() - 7200
            os.utime(orphan, (old_ts, old_ts))
            os.utime(keep_active, (old_ts, old_ts))

            removed = dlg.sweep_orphan_detached_logs(
                d,
                active_session_ids={"bbbbbbbbbbbbbbbb"},
                persisted_session_ids={"aaaaaaaaaaaaaaaa"},
                older_than_seconds=3600,
            )
            self.assertEqual(removed, ["cccccccccccccccc"])
            self.assertFalse(orphan.exists())
            self.assertTrue(keep_active.exists())


class TestDetachedJobModule(unittest.TestCase):
    def test_detached_job_name_validation(self) -> None:
        self.assertEqual(dj.detached_job_name("0123456789abcdef"), r"Local\FFWinBridgeDetached_0123456789abcdef")
        with self.assertRaises(ValueError):
            dj.detached_job_name("bad-id")

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects require NT")
    def test_detached_job_eof_stdin_and_tree_termination(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            lp = Path(td) / "fedcba9876543210.log"
            proc = dj.DetachedJobProcess(
                [sys.executable, "-c", "import sys; print('isatty=' + str(sys.stdin.isatty())); print('eof=' + repr(sys.stdin.read()))"],
                cwd=td,
                env=dict(os.environ),
                session_id="fedcba9876543210",
                log_file=lp,
            )
            try:
                rc = proc.wait(timeout=10)
                self.assertEqual(rc, 0)
                out = lp.read_text(encoding="utf-8", errors="replace")
                self.assertIn("isatty=False", out)
                self.assertIn("eof=''", out)
            finally:
                proc.close()


if __name__ == "__main__":
    unittest.main()
