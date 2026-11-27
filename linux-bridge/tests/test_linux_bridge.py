"""End-to-end & unit test suite for FF Linux Bridge v3 (Level 2)."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from ff_linux_bridge.ops_browser import BROWSER_CANDIDATES
from ff_linux_bridge.server import create_server


def _has_browser() -> bool:
    return any(shutil.which(b) for b in BROWSER_CANDIDATES)


class TestFixturePageHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        html = """<!doctype html>
<html>
<head><title>FF Linux Bridge Test Page</title></head>
<body>
  <h1>Linux Bridge Level 2</h1>
  <input id="name" type="text" placeholder="Your name" />
  <button id="go" onclick="document.getElementById('out').textContent = 'Hello, ' + document.getElementById('name').value;">Submit</button>
  <input id="up" type="file" />
  <div id="out">waiting</div>
</body>
</html>""".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)


class LinuxBridgeTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory(prefix="ff-linux-test-")
        self.secret = "test-secret-1234567890"
        self.httpd, self.runtime = create_server(
            host="127.0.0.1",
            port=0,
            device_name="linux-ci-box",
            secret=self.secret,
            workspace_root=self.tmpdir.name,
        )
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.runtime.shutdown()
        self.httpd.server_close()
        self.tmpdir.cleanup()

    def rpc(self, op: str, args: dict | None = None, *, key: str | None = None, request_id: str = "req-1") -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            body = json.dumps({"op": op, "args": args or {}, "request_id": request_id}).encode("utf-8")
            headers = {"Content-Type": "application/json"}
            if key is not None:
                headers["X-FF3-Key"] = key
            else:
                headers["X-FF3-Key"] = self.secret
            conn.request("POST", "/rpc", body=body, headers=headers)
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read().decode("utf-8"))
        finally:
            conn.close()

    def test_health_and_auth(self) -> None:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/health")
        r = conn.getresponse()
        data = json.loads(r.read().decode("utf-8"))
        conn.close()
        self.assertEqual(r.status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["bridge"], "ff-linux-v3")

        status, body = self.rpc("ping", key="wrong-secret")
        self.assertEqual(status, 401)
        self.assertFalse(body["ok"])

        status, body = self.rpc("ping", {"message": "hello"})
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["result"]["host"], "linux-ci-box")
        self.assertEqual(body["result"]["message"], "hello")

    def test_capabilities_and_system_ops(self) -> None:
        _, caps = self.rpc("capabilities")
        self.assertTrue(caps["ok"])
        self.assertEqual(caps["result"]["level"], 2)
        self.assertGreaterEqual(caps["result"]["ops_count"], 35)
        self.assertIn("browser_launch", caps["result"]["ops"])
        self.assertIn("patch_file", caps["result"]["ops"])

        _, status = self.rpc("device_status")
        self.assertTrue(status["ok"])
        self.assertEqual(status["result"]["device"], "linux-ci-box")

        _, sysinfo = self.rpc("system_info")
        self.assertTrue(sysinfo["ok"])
        self.assertIn("kernel", sysinfo["result"])

        _, sh = self.rpc("run_shell", {"command": "echo linux-ok && pwd"})
        self.assertTrue(sh["ok"])
        self.assertEqual(sh["result"]["exit_code"], 0)
        self.assertIn("linux-ok", sh["result"]["stdout"])

        _, py = self.rpc("run_code", {"language": "python", "code": "print(21 * 2)"})
        self.assertTrue(py["ok"])
        self.assertEqual(py["result"]["stdout"].strip(), "42")

        _, timed = self.rpc("run_shell", {"command": "sleep 5", "timeout_s": 1})
        self.assertTrue(timed["ok"])
        self.assertTrue(timed["result"]["timed_out"])

        _, procs = self.rpc("process_list", {"limit": 10})
        self.assertTrue(procs["ok"])
        self.assertGreater(procs["result"]["count"], 0)

    def test_file_ops_and_workspace_jail(self) -> None:
        _, w = self.rpc("write_file", {"path": "sub/demo.txt", "content": "line1\nhello world\nline3\n"})
        self.assertTrue(w["ok"])
        sha = w["result"]["sha256"]

        # SHA-256 mismatch rejected
        _, bad_w = self.rpc("write_file", {"path": "sub/demo.txt", "content": "x", "expected_sha256": "0" * 64})
        self.assertFalse(bad_w["ok"])
        self.assertEqual(bad_w["error"]["code"], "SHA256_CONFLICT")

        # Patch with matching SHA-256
        _, p = self.rpc("patch_file", {"path": "sub/demo.txt", "old_str": "hello world", "new_str": "hello linux", "expected_sha256": sha})
        self.assertTrue(p["ok"])
        self.assertEqual(p["result"]["replacements"], 1)

        _, r = self.rpc("read_file", {"path": "sub/demo.txt", "start_line": 2, "end_line": 2})
        self.assertTrue(r["ok"])
        self.assertEqual(r["result"]["content"].strip(), "hello linux")

        _, found = self.rpc("find_files", {"path": ".", "pattern": "*.txt"})
        self.assertTrue(found["ok"])
        self.assertEqual(found["result"]["count"], 1)

        _, srch = self.rpc("search_text", {"path": ".", "query": "hello linux"})
        self.assertTrue(srch["ok"])
        self.assertEqual(srch["result"]["count"], 1)
        self.assertEqual(srch["result"]["matches"][0]["line"], 2)

        # Workspace traversal blocked
        _, esc = self.rpc("read_file", {"path": "../../etc/passwd"})
        self.assertFalse(esc["ok"])
        self.assertEqual(esc["error"]["code"], "PATH_OUTSIDE_WORKSPACE")

    def test_batch_and_request_status(self) -> None:
        _, b = self.rpc(
            "batch",
            {
                "calls": [
                    {"op": "make_dir", "args": {"path": "bdir"}},
                    {"op": "write_file", "args": {"path": "bdir/a.txt", "content": "abc"}},
                    {"op": "read_file", "args": {"path": "bdir/a.txt"}},
                ]
            },
            request_id="batch-1",
        )
        self.assertTrue(b["ok"])
        self.assertFalse(b["result"]["stopped_on_error"])
        self.assertEqual(b["result"]["results"][2]["response"]["result"]["content"], "abc")

        _, w = self.rpc("write_file", {"path": "j.txt", "content": "ok", "dedupe_key": "dk-42"}, request_id="r-42")
        self.assertTrue(w["ok"])
        _, st = self.rpc("request_status", {"dedupe_key": "dk-42"})
        self.assertTrue(st["ok"])
        self.assertTrue(st["result"]["found"])
        self.assertEqual(st["result"]["record"]["state"], "completed")

    @unittest.skipUnless(_has_browser(), "No Chromium/Chrome binary available in PATH")
    def test_browser_cdp_e2e(self) -> None:
        fixture_srv = HTTPServer(("127.0.0.1", 0), TestFixturePageHandler)
        fixture_port = fixture_srv.server_address[1]
        fixture_thread = threading.Thread(target=fixture_srv.serve_forever, daemon=True)
        fixture_thread.start()
        try:
            url = f"http://127.0.0.1:{fixture_port}/"
            _, launch = self.rpc("browser_launch", {"headless": True, "no_sandbox": True})
            self.assertTrue(launch["ok"], launch)
            self.assertTrue(launch["result"]["connected"])

            _, nav = self.rpc("browser_navigate", {"url": url})
            using_http = True
            if not nav["ok"] and "ERR_BLOCKED_BY_ADMINISTRATOR" in str(nav.get("error", {})):
                using_http = False
                from urllib.parse import quote
                html_doc = (
                    "<!doctype html><html><head><title>FF Linux Bridge Test Page</title></head>"
                    "<body><h1>Linux Bridge Level 2</h1>"
                    "<input id='name' type='text' placeholder='Your name' />"
                    "<button id='go' onclick=\"document.getElementById('out').textContent = 'Hello, ' + document.getElementById('name').value;\">Submit</button>"
                    "<input id='up' type='file' /><div id='out'>waiting</div></body></html>"
                )
                _, nav = self.rpc("browser_navigate", {"url": "data:text/html;charset=utf-8," + quote(html_doc)})
            self.assertTrue(nav["ok"], nav)
            self.assertEqual(nav["result"]["title"], "FF Linux Bridge Test Page")

            _, snap = self.rpc("browser_snapshot")
            self.assertTrue(snap["ok"], snap)
            self.assertGreaterEqual(snap["result"]["count"], 3)

            _, typed = self.rpc("browser_type", {"selector": "#name", "text": "LinuxUser"})
            self.assertTrue(typed["ok"], typed)

            _, clicked = self.rpc("browser_click", {"selector": "#go"})
            self.assertTrue(clicked["ok"], clicked)

            _, waited = self.rpc("browser_wait", {"expression": "document.getElementById('out').textContent === 'Hello, LinuxUser'"})
            self.assertTrue(waited["ok"], waited)

            _, txt = self.rpc("browser_text", {"selector": "#out"})
            self.assertTrue(txt["ok"], txt)
            self.assertEqual(txt["result"]["text"], "Hello, LinuxUser")

            # Cookies (only applicable on http(s) origins)
            if using_http:
                _, cset = self.rpc("browser_cookies", {"action": "set", "cookie": {"name": "ff_test", "value": "v1", "url": url}})
                self.assertTrue(cset["ok"] and cset["result"]["success"])
                _, cget = self.rpc("browser_cookies", {"action": "get", "urls": [url]})
                self.assertTrue(any(c["name"] == "ff_test" and c["value"] == "v1" for c in cget["result"]["cookies"]))

            # File upload
            up_file = Path(self.tmpdir.name) / "upload.txt"
            up_file.write_text("upload payload", encoding="utf-8")
            _, up = self.rpc("browser_upload", {"selector": "#up", "files": ["upload.txt"]})
            self.assertTrue(up["ok"], up)
            _, ev = self.rpc("browser_eval", {"expression": "document.getElementById('up').files[0].name"})
            self.assertEqual(ev["result"]["value"], "upload.txt")

            # Screenshot & PDF
            _, shot = self.rpc("browser_screenshot", {"path": "page.png"})
            self.assertTrue(shot["ok"] and shot["result"]["size_bytes"] > 1000)
            self.assertTrue((Path(self.tmpdir.name) / "page.png").exists())

            _, pdf = self.rpc("browser_pdf", {"path": "page.pdf"})
            self.assertTrue(pdf["ok"] and pdf["result"]["size_bytes"] > 1000)
            self.assertTrue((Path(self.tmpdir.name) / "page.pdf").read_bytes().startswith(b"%PDF"))

            # Tabs
            _, new_tab = self.rpc("browser_open", {"url": "about:blank"})
            self.assertTrue(new_tab["ok"])
            _, tabs = self.rpc("browser_tabs")
            self.assertGreaterEqual(tabs["result"]["count"], 2)
            _, closed_tab = self.rpc("browser_close_tab", {"target_id": new_tab["result"]["target_id"]})
            self.assertTrue(closed_tab["ok"])

            _, closed = self.rpc("browser_close")
            self.assertTrue(closed["ok"] and closed["result"]["closed"])
        finally:
            fixture_srv.shutdown()
            fixture_srv.server_close()


if __name__ == "__main__":
    unittest.main()
