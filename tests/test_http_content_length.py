"""Reject malformed HTTP framing without dispatching Bridge RPC effects."""
from __future__ import annotations

import io
import os
from email.message import Message
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
os.environ.setdefault("FF_BRIDGE_ROOT", str(Path(tempfile.gettempdir()) / "ff-http-length-test-root"))
import ff_win_v3_agent as agent


class HTTPContentLengthTests(unittest.TestCase):
    def invoke(self, value, *, body=b"{}", extra=()):
        h = object.__new__(agent.Handler)
        headers = Message()
        if value is not None:
            headers.add_header("Content-Length", value)
        for key, val in extra:
            headers.add_header(key, val)
        h.headers = headers
        h.rfile = io.BytesIO(body)
        h.close_connection = False
        responses = []
        dispatched = []
        h.auth_ok = lambda: True
        h.send_json = lambda status, payload: responses.append((status, payload))
        h._handle_rpc = lambda raw: dispatched.append(raw)
        h.do_POST()
        return responses, dispatched, h.close_connection

    def test_valid_single_decimal_length(self):
        for value in ("2", " 2 ", "0002"):
            with self.subTest(value=value):
                responses, dispatched, closed = self.invoke(value)
                self.assertEqual(responses, [])
                self.assertEqual(dispatched, [b"{}"])
                self.assertFalse(closed)

    def test_malformed_and_ambiguous_framing_is_rejected(self):
        for value, extra in (
            (None, ()),
            ("", ()),
            ("+2", ()),
            ("-2", ()),
            ("2.0", ()),
            ("2, 2", ()),
            ("0x2", ()),
            ("2\n", ()),
            ("２", ()),
            ("2", (("Content-Length", "2"),)),
            ("2", (("Content-Length", "3"),)),
            ("2", (("Transfer-Encoding", "chunked"),)),
        ):
            with self.subTest(value=value, extra=extra):
                responses, dispatched, closed = self.invoke(value, extra=extra)
                self.assertEqual(responses[0][0], 400)
                self.assertEqual(responses[0][1]["error_code"], "REQUEST_LENGTH_INVALID")
                self.assertEqual(dispatched, [])
                self.assertTrue(closed)

    def test_zero_oversize_and_huge_decimal_are_rejected(self):
        for value in ("0", str(agent.MAX_REQUEST_BYTES + 1), "9" * 8000):
            with self.subTest(value=value[:30]):
                responses, dispatched, closed = self.invoke(value)
                self.assertEqual(responses[0][0], 413)
                self.assertEqual(responses[0][1]["error_code"], "REQUEST_SIZE_INVALID")
                self.assertEqual(dispatched, [])
                self.assertTrue(closed)

    def test_short_body_is_never_dispatched(self):
        responses, dispatched, closed = self.invoke("3", body=b"{}")
        self.assertEqual(responses[0][0], 400)
        self.assertEqual(responses[0][1]["error_code"], "REQUEST_BODY_INCOMPLETE")
        self.assertEqual(dispatched, [])
        self.assertTrue(closed)


if __name__ == "__main__":
    unittest.main()
