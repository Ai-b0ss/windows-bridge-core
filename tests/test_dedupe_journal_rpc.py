"""End-to-end verification of Bridge SQLite dedupe_key journaling + FlightController v0.5.2 reconciliation."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_MAIN = REPO_ROOT / "runtime" / "bridge-v3" / "ff_win_v3_main.py"
FC_MJS = REPO_ROOT / "tools" / "cf-flight-controller" / "flight-controller.mjs"
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _rpc(port: int, secret: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/rpc",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-FF3-Key": secret},
        method="POST",
    )
    try:
        with OPENER.open(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


class TestBridgeDedupeJournalRpc(unittest.TestCase):
    def test_bridge_dedupe_key_journal_and_flight_controller_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ff-dedupe-e2e-") as td:
            root = Path(td) / "agent"
            root.mkdir(parents=True)
            secret_file = root / "bridge-v3" / "secret"
            port = _free_port()

            env = dict(os.environ)
            env["FF_BRIDGE_ROOT"] = str(root)
            proc = subprocess.Popen(
                [sys.executable, str(RUNTIME_MAIN), "serve", "--host", "127.0.0.1", "--port", str(port)],
                cwd=str(REPO_ROOT),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            try:
                ready = False
                secret = ""
                for _ in range(80):
                    if proc.poll() is not None:
                        break
                    if secret_file.is_file():
                        secret = secret_file.read_text(encoding="utf-8").strip()
                        try:
                            code, body = _rpc(port, secret, {"op": "ping", "args": {}, "request_id": "boot"})
                            if code == 200 and body.get("ok") is True:
                                ready = True
                                break
                        except OSError:
                            pass
                    time.sleep(0.15)
                self.assertTrue(ready, "Isolated ff_win_v3_main.py failed to start")

                counter_file = root / "side_effect_counter.txt"
                py_snippet = (
                    f"from pathlib import Path; p = Path({str(counter_file)!r}); "
                    "n = int(p.read_text()) + 1 if p.exists() else 1; "
                    "p.write_text(str(n)); print(n)"
                )

                # 1. Unknown dedupe_key returns state=not_found + dedupe_journal_v1=True
                code0, st0 = _rpc(port, secret, {"op": "request_status", "args": {"op": "run_code", "dedupe_key": "dk-alpha"}})
                self.assertEqual(code0, 200)
                self.assertEqual(st0["result"]["state"], "not_found")
                self.assertTrue(st0["result"]["dedupe_journal_v1"])

                # 2. First execution with dedupe_key runs once; second returns cached result without running again!
                code1, r1 = _rpc(port, secret, {
                    "op": "run_code",
                    "args": {"language": "python", "code": py_snippet},
                    "request_id": "req-1",
                    "dedupe_key": "dk-alpha",
                })
                self.assertEqual(code1, 200)
                self.assertTrue(r1["ok"])
                self.assertEqual(r1["result"]["stdout"].strip(), "1")

                code2, r2 = _rpc(port, secret, {
                    "op": "run_code",
                    "args": {"language": "python", "code": py_snippet},
                    "request_id": "req-2",
                    "dedupe_key": "dk-alpha",
                })
                self.assertEqual(code2, 200)
                self.assertEqual(r2["result"]["stdout"].strip(), "1")
                self.assertEqual(counter_file.read_text(encoding="utf-8").strip(), "1")

                # 3. Payload mismatch on same dedupe_key is rejected with REQUEST_CONFLICT
                code3, r3 = _rpc(port, secret, {
                    "op": "run_code",
                    "args": {"language": "python", "code": "print('different')"},
                    "request_id": "req-3",
                    "dedupe_key": "dk-alpha",
                })
                self.assertEqual(code3, 400)
                self.assertFalse(r3["ok"])
                self.assertEqual(r3["error_code"], "REQUEST_KEY_CONFLICT")

                # 4. request_status(op, dedupe_key) returns state=completed + stored envelope
                code4, st1 = _rpc(port, secret, {"op": "request_status", "args": {"op": "run_code", "dedupe_key": "dk-alpha"}})
                self.assertEqual(code4, 200)
                self.assertEqual(st1["result"]["state"], "completed")
                self.assertTrue(st1["result"]["dedupe_journal_v1"])
                self.assertEqual(st1["result"]["response"]["result"]["stdout"].strip(), "1")

                # 5. If Node and flight-controller.mjs are present, verify real createFF3FlightCaller against live ff_win_v3_main.py!
                node = shutil.which("node")
                if node and FC_MJS.is_file():
                    fc_state = root / "fc-state"
                    js = (
                        f"import {{ createFF3FlightCaller }} from {FC_MJS.as_uri()!r};\n"
                        f"const call = createFF3FlightCaller({{ stateDir: {str(fc_state)!r}, secretPath: {str(secret_file)!r}, "
                        f"selectBackend: async () => 'http://127.0.0.1:{port}/rpc' }});\n"
                        f"const a = await call('run_code', {{ language: 'python', code: {py_snippet!r}, __dedupe_key: 'dk-node-1' }});\n"
                        f"const b = await call('run_code', {{ language: 'python', code: {py_snippet!r}, __dedupe_key: 'dk-node-1' }});\n"
                        "console.log(JSON.stringify({ a_out: a.result.stdout.trim(), b_replay: b.deduped_replay }));\n"
                    )
                    done = subprocess.run([node, "--input-type=module", "-e", js], capture_output=True, text=True, timeout=20, check=True)
                    parsed = json.loads(done.stdout.strip())
                    self.assertEqual(parsed["a_out"], "2")
                    self.assertTrue(parsed["b_replay"])
                    self.assertEqual(counter_file.read_text(encoding="utf-8").strip(), "2")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()


if __name__ == "__main__":
    unittest.main()
