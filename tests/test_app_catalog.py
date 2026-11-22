from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
sys.path.insert(0, str(ROOT / "tools"))

import ff_hub  # noqa: E402
from ff_agent_entry import EntryAuthority, entry_call  # noqa: E402
from ff_app_catalog import AppCatalog, DISALLOWED_INTERPRETER_EXES  # noqa: E402
from ff_hub import Hub  # noqa: E402
from ff_hub_permissions import Policy  # noqa: E402
from ff_hub_store import HubError  # noqa: E402
import agent_entry as agent_entry_cli  # noqa: E402


class _FakeHidden:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.closed = False
        self.job_cleanup_verified = True
        self.editor_profile_cleanup: list[dict] = []
        self.browser_profile_cleanup: list[dict] = []
        self._pids: dict[int, int] = {}

    def request(self, payload: dict, timeout_s: float = 30) -> dict:
        self.calls.append({"payload": payload, "timeout_s": timeout_s})
        cmd = payload.get("command")
        if cmd in {"launch_app", "launch_exe", "launch_electron_isolated", "editor.launch"}:
            pid = 4100 + len(self.calls)
            hwnd = 9100 + len(self.calls)
            ctime = 123456789 + len(self.calls)
            self._pids[pid] = ctime
            return {"pid": pid, "hwnd": hwnd, "create_time": ctime, "desktop": "FFBridge-Agent-test",
                    "route": "NATIVE_EDITOR_API" if cmd == "editor.launch" else "HIDDEN_TEST"}
        if cmd == "describe_owned_windows":
            return {"windows": [
                {"pid": 4101, "hwnd": 9101, "create_time": self._pids.get(4101, 123456790), "class_name": "TestWnd"}
            ]}
        if cmd == "editor.observe":
            return {"document": {"text": "hello", "version": 1, "file_sha256": "abc"},
                    "hwnd": payload["hwnd"], "generation": 1, "ref": "r1", "route": "NATIVE_EDITOR_API"}
        if cmd == "editor.replace_save":
            return {"saved": True, "hwnd": payload["hwnd"], "route": "NATIVE_EDITOR_API"}
        if cmd in {"document.read", "document.replace", "document.save"}:
            return {"ok": True, "command": cmd, "hwnd": payload["hwnd"]}
        if cmd == "close_app":
            return {"pid": payload["pid"], "closed": True}
        return {"ok": True}

    def close(self) -> None:
        self.closed = True


class AppCatalogUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.tmp.name) / "state"
        self.app_dir = Path(self.tmp.name) / "apps"
        self.app_dir.mkdir(parents=True, exist_ok=True)
        self.catalog = AppCatalog(self.state_dir)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_dummy_exe(self, folder: Path, name: str, body: bytes = b"MZ-TEST-EXE") -> Path:
        folder.mkdir(parents=True, exist_ok=True)
        exe = folder / name
        exe.write_bytes(body)
        return exe

    def test_builtin_aliases_and_unknown_rejection(self) -> None:
        self.assertEqual(self.catalog.canonical_id("charmap.exe"), "charmap")
        self.assertEqual(self.catalog.canonical_id("WINWORD.EXE"), "word")
        self.assertEqual(self.catalog.canonical_id("agy"), "antigravity")
        self.assertEqual(self.catalog.canonical_id("code.exe"), "vscode")
        self.assertEqual(self.catalog.canonical_id("claude-desktop.exe"), "claude")
        self.assertEqual(self.catalog.canonical_id("Claude_pzs8sxrjxfjjc!Claude"), "claude")
        self.assertEqual(
            self.catalog.validate_entry_apps(["charmap.exe", "agy", "charmap"]),
            ["charmap", "antigravity"],
        )
        with self.assertRaises(HubError) as ctx:
            self.catalog.validate_entry_apps(["unknown-tool"])
        self.assertEqual(ctx.exception.code, "ENTRY_SCOPE_INVALID")

    def test_enroll_rejects_interpreters_collisions_and_electron_opt_in(self) -> None:
        exe = self._make_dummy_exe(self.app_dir / "win32", "CustomTool.exe")
        with self.assertRaises(HubError) as ctx:
            self.catalog.enroll(app_id="BAD ID!", executable=str(exe))
        self.assertEqual(ctx.exception.code, "APP_CATALOG_ID_INVALID")

        with self.assertRaises(HubError) as ctx:
            self.catalog.enroll(app_id="charmap", executable=str(exe))
        self.assertEqual(ctx.exception.code, "APP_CATALOG_BUILTIN_IMMUTABLE")

        for bad_name in ("python.exe", "powershell.exe", "cmd.exe", "node.exe"):
            self.assertIn(bad_name, DISALLOWED_INTERPRETER_EXES)
            bad_exe = self._make_dummy_exe(self.app_dir / "bad", bad_name)
            with self.assertRaises(HubError) as ictx:
                self.catalog.enroll(app_id="bad-interp", executable=str(bad_exe))
            self.assertEqual(ictx.exception.code, "APP_CATALOG_INTERPRETER_FORBIDDEN")

        electron_dir = self.app_dir / "electron"
        (electron_dir / "resources").mkdir(parents=True, exist_ok=True)
        (electron_dir / "resources" / "app.asar").write_bytes(b"asar")
        el_exe = self._make_dummy_exe(electron_dir, "MyElectron.exe")
        with self.assertRaises(HubError) as ectx:
            self.catalog.enroll(app_id="my-electron", executable=str(el_exe), allow_electron=False)
        self.assertEqual(ectx.exception.code, "APP_CATALOG_ELECTRON_REQUIRES_ISOLATION_OPT_IN")

        enrolled = self.catalog.enroll(app_id="my-electron", executable=str(el_exe), allow_electron=True, note="isolated")
        self.assertEqual(enrolled["kind"], "electron")
        self.assertEqual(enrolled["route"], "hidden_desktop_electron_isolated")

        with self.assertRaises(HubError) as sctx:
            self.catalog.enroll(app_id="signed-req", executable=str(exe), require_signed=True)
        self.assertEqual(sctx.exception.code, "APP_CATALOG_SIGNATURE_REQUIRED")

    def test_enroll_integrity_mismatch_and_revoke(self) -> None:
        exe = self._make_dummy_exe(self.app_dir / "custom", "BenchWin32.exe", b"MZ-ORIGINAL-1")
        record = self.catalog.enroll(app_id="bench-win32", executable=str(exe), note="bench")
        self.assertEqual(record["kind"], "win32")
        self.assertEqual(record["route"], "hidden_desktop_uia")
        self.assertTrue(record["sha256"])

        loaded = self.catalog.get("bench-win32", verify_integrity=True)
        self.assertEqual(loaded["app_id"], "bench-win32")
        self.assertEqual(self.catalog.canonical_id("BenchWin32.exe"), "bench-win32")

        # Tamper executable -> fail closed on verify_integrity=True
        exe.write_bytes(b"MZ-TAMPERED-2")
        with self.assertRaises(HubError) as ctx:
            self.catalog.get("bench-win32", verify_integrity=True)
        self.assertEqual(ctx.exception.code, "APP_CATALOG_INTEGRITY_MISMATCH")

        self.assertTrue(self.catalog.revoke("bench-win32"))
        self.assertFalse(self.catalog.revoke("bench-win32"))
        self.assertIsNone(self.catalog.get("bench-win32"))

    def test_hub_dispatch_routes_and_entry_catalog_enforcement(self) -> None:
        custom_exe = self._make_dummy_exe(self.app_dir / "custom2", "MyWin32.exe", b"MZ-WIN32")
        unenrolled_el_dir = self.app_dir / "unenrolled_el"
        (unenrolled_el_dir / "resources").mkdir(parents=True, exist_ok=True)
        (unenrolled_el_dir / "resources" / "app.asar").write_bytes(b"asar")
        unenrolled_el = self._make_dummy_exe(unenrolled_el_dir, "UnenrolledElectron.exe")

        enrolled_el_dir = self.app_dir / "enrolled_el"
        (enrolled_el_dir / "resources").mkdir(parents=True, exist_ok=True)
        (enrolled_el_dir / "resources" / "app.asar").write_bytes(b"asar")
        enrolled_el = self._make_dummy_exe(enrolled_el_dir, "EnrolledElectron.exe", b"MZ-EL")

        doc = Path(self.tmp.name) / "sample.txt"
        doc.write_text("hello", encoding="utf-8")

        fake_claude = self._make_dummy_exe(self.app_dir / "claude", "claude-desktop.exe")
        fake_code = self._make_dummy_exe(self.app_dir / "vscode", "Code.exe")
        fake_agy = self._make_dummy_exe(self.app_dir / "agy", "Antigravity.exe")

        cat = AppCatalog(self.state_dir)
        cat.enroll(app_id="my-win32", executable=str(custom_exe))
        el_rec = cat.enroll(app_id="my-electron", executable=str(enrolled_el), allow_electron=True)

        Policy(self.state_dir / "policy.json").add_grant(
            ["app_launch", "read_diagnose", "own_resources"],
            apps=["my-win32", "my-electron", "vscode", "antigravity", "claude"],
            agents=["agent-a"],
            ttl_seconds=600,
        )

        # Direct Hub: unenrolled Electron must be rejected
        hidden = _FakeHidden()
        hub = Hub(self.state_dir, hidden_factory=lambda: hidden)
        try:
            session = hub.dispatch({"op": "session_open", "args": {"agent_id": "agent-a", "task_id": "t-direct"}})
            with self.assertRaises(HubError) as uctx:
                hub.dispatch({
                    "op": "app_open", "session_id": session["session_id"], "session_secret": session["session_secret"],
                    "request_key": "req-k-unenrolled", "args": {"app": str(unenrolled_el)},
                })
            self.assertEqual(uctx.exception.code, "APP_BACKGROUND_ROUTE_UNSUPPORTED")

            # Entry Authority scoped to my-win32, vscode, my-electron, claude, antigravity
            auth = EntryAuthority(self.state_dir)
            _, token = auth.issue(
                client_id="c1", agent_id="agent-a", task_id="t-entry",
                scopes=["private_app"], apps=["my-win32", "my-electron", "vscode", "agy", "claude-desktop"], ttl=600,
            )
            bearer = "Bearer " + token
            esess = entry_call(hub, auth, bearer, {"op": "session_open"})["session_id"]

            # 1. Enrolled Win32 launches via launch_exe
            res_win32 = entry_call(hub, auth, bearer, {
                "op": "app_open", "session_id": esess, "request_key": "req-open-win32", "args": {"app": "my-win32"}
            })
            self.assertEqual(res_win32["control_route"], "hidden_desktop_uia")
            self.assertEqual(hidden.calls[-1]["payload"], {"command": "launch_exe", "executable": str(custom_exe.resolve())})

            # 2. Enrolled Electron launches via launch_electron_isolated with expected SHA-256
            res_el = entry_call(hub, auth, bearer, {
                "op": "app_open", "session_id": esess, "request_key": "req-open-el", "args": {"app": "my-electron"}
            })
            self.assertEqual(res_el["control_route"], "hidden_desktop_electron_isolated")
            self.assertEqual(hidden.calls[-1]["payload"]["command"], "launch_electron_isolated")
            self.assertEqual(hidden.calls[-1]["payload"]["expected_executable_sha256"], el_rec["sha256"])

            # 3. Mock resolved executables for vscode/antigravity/claude on any host state
            def fake_resolve(query, *, catalog=None):
                q = (catalog.canonical_id(query) if catalog else None) or str(query).lower()
                if q == "vscode":
                    return {"found": True, "query": query, "name": "Code.exe", "executable": str(fake_code),
                            "kind": "electron_editor", "known": "vscode", "running_instances": 0}
                if q == "antigravity":
                    return {"found": True, "query": query, "name": "Antigravity.exe", "executable": str(fake_agy),
                            "kind": "electron", "known": "antigravity", "running_instances": 1}
                if q == "claude":
                    return {"found": True, "query": query, "name": "claude-desktop.exe", "executable": str(fake_claude),
                            "kind": "msix_fulltrust_electron", "known": "claude-desktop", "running_instances": 0}
                return {"found": False, "query": query}

            with mock.patch("ff_hub_apps.resolve", side_effect=fake_resolve):
                # 3a. Antigravity without document_path -> isolated UIA launch
                res_agy = entry_call(hub, auth, bearer, {
                    "op": "app_open", "session_id": esess, "request_key": "req-open-agy", "args": {"app": "agy"}
                })
                self.assertEqual(res_agy["control_route"], "hidden_desktop_electron_isolated")
                self.assertEqual(hidden.calls[-1]["payload"]["command"], "launch_electron_isolated")
                self.assertEqual(hidden.calls[-1]["payload"]["app"], "antigravity")

                # 3b. VS Code with document_path -> editor.launch + app_document native routing
                res_code = entry_call(hub, auth, bearer, {
                    "op": "app_open", "session_id": esess, "request_key": "req-open-code",
                    "args": {"app": "code", "document_path": str(doc)}
                })
                self.assertEqual(hidden.calls[-1]["payload"], {
                    "command": "editor.launch", "app": "vscode", "document_path": str(doc)
                })
                first_app_pid = res_win32["pid"]
                hidden._pids[res_code["pid"]] = res_code["create_time"]
                orig_describe = hidden.request

                def req_with_windows(payload, timeout_s=30):
                    if payload.get("command") == "describe_owned_windows":
                        return {"windows": [
                            {"pid": first_app_pid, "hwnd": res_win32["hwnd"], "create_time": res_win32["create_time"]},
                            {"pid": res_code["pid"], "hwnd": res_code["hwnd"], "create_time": res_code["create_time"]},
                        ]}
                    return orig_describe(payload, timeout_s)

                with mock.patch.object(hidden, "request", side_effect=req_with_windows):
                    read_doc = entry_call(hub, auth, bearer, {
                        "op": "app_document", "session_id": esess,
                        "args": {"app_id": res_code["app_id"], "command": "read"}
                    })
                    self.assertEqual(read_doc["document"]["text"], "hello")
                    with self.assertRaises(HubError) as rk_ctx:
                        entry_call(hub, auth, bearer, {
                            "op": "app_document", "session_id": esess,
                            "args": {"app_id": res_code["app_id"], "command": "replace",
                                     "generation": 1, "ref": "r1", "expected_text": "hello", "replacement_text": "world"}
                        })
                    self.assertEqual(rk_ctx.exception.code, "REQUEST_KEY_REQUIRED")
                    rep_doc = entry_call(hub, auth, bearer, {
                        "op": "app_document", "session_id": esess, "request_key": "req-rep-001",
                        "args": {"app_id": res_code["app_id"], "command": "replace",
                                 "generation": 1, "ref": "r1", "expected_text": "hello", "replacement_text": "world"}
                    })
                    self.assertTrue(rep_doc["saved"])

                # 3c. Claude Desktop MSIX alias -> hidden_desktop_msix_alias
                res_claude = entry_call(hub, auth, bearer, {
                    "op": "app_open", "session_id": esess, "request_key": "req-open-claude",
                    "args": {"app": "claude", "code_link": "claude://code/new?q=hi&folder=" + str(self.tmp.name)}
                })
                self.assertEqual(res_claude["control_route"], "hidden_desktop_msix_alias")
                self.assertEqual(hidden.calls[-1]["payload"]["command"], "launch_app")
                self.assertEqual(hidden.calls[-1]["payload"]["app"], "claude")
                self.assertIn("code_link", hidden.calls[-1]["payload"])

            # Tampered enrolled binary fails on verify_integrity inside app_open
            custom_exe.write_bytes(b"MZ-MODIFIED")
            with self.assertRaises(HubError) as mctx:
                entry_call(hub, auth, bearer, {
                    "op": "app_open", "session_id": esess, "request_key": "req-open-tampered", "args": {"app": "my-win32"}
                })
            self.assertEqual(mctx.exception.code, "APP_CATALOG_INTEGRITY_MISMATCH")
        finally:
            import sqlite3
            for obj in vars(hub.store).values():
                if isinstance(obj, sqlite3.Connection):
                    obj.close()

    def test_cli_catalog_commands(self) -> None:
        exe = self._make_dummy_exe(self.app_dir / "cli", "CliApp.exe")
        buf = io.StringIO()
        with mock.patch.object(sys, "argv", [
            "agent_entry.py", "catalog", "enroll", "--state-dir", str(self.state_dir),
            "--app-id", "cli-app", "--exe", str(exe), "--note", "from-cli"
        ]), redirect_stdout(buf):
            rc = agent_entry_cli.main()
        self.assertEqual(rc, 0)
        enrolled = json.loads(buf.getvalue())
        self.assertTrue(enrolled["ok"])
        self.assertEqual(enrolled["result"]["app_id"], "cli-app")

        buf2 = io.StringIO()
        with mock.patch.object(sys, "argv", [
            "ff_hub.py", "--state-dir", str(self.state_dir), "catalog", "list"
        ]), redirect_stdout(buf2):
            ff_hub.main(["--state-dir", str(self.state_dir), "catalog", "list"])
        listed = json.loads(buf2.getvalue())
        self.assertIn("cli-app", listed["enrolled"])
        self.assertIn("antigravity", listed["builtin"])

        buf3 = io.StringIO()
        with mock.patch.object(sys, "argv", [
            "agent_entry.py", "catalog", "revoke", "--state-dir", str(self.state_dir), "--app-id", "cli-app"
        ]), redirect_stdout(buf3):
            rc2 = agent_entry_cli.main()
        self.assertEqual(rc2, 0)
        self.assertTrue(json.loads(buf3.getvalue())["result"]["revoked"])


if __name__ == "__main__":
    unittest.main()
