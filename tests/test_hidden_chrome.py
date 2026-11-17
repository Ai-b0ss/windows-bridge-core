"""Ownership and fail-closed launch contracts; real Chrome is an opt-in Windows gate."""
from __future__ import annotations

import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

RUNTIME = Path(__file__).resolve().parents[1] / "runtime" / "bridge-v3"
sys.path.insert(0, str(RUNTIME))
import cua_hidden_chrome as chrome


class HiddenChromeContracts(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory(prefix="ff-hidden-chrome-contract-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / ("worker-" + "a" * 32)
        self.root.mkdir()
        self.owner = {"schema": 1, "kind": "ff-isolated-browser-worker", "pid": 123,
                      "creation": "win:456", "nonce": "a" * 32}
        (self.root / "owner.json").write_text(json.dumps(self.owner), encoding="utf-8")
        self.executable = Path(temporary.name) / "chrome.exe"
        self.executable.write_bytes(b"contract fixture; never executed")
        self.proc = SimpleNamespace(pid=234, poll=Mock(return_value=None), wait=Mock(), kill=Mock())
        self.desktop = "FFBridge-Agent-" + "b" * 32
        self.window = {"pid": 234, "class_name": "Chrome_WidgetWin_1",
                       "geometry": {"left": 0, "top": 0, "right": 800, "bottom": 600}}
        self.owns = Mock(return_value=True)
        self.info = Mock(return_value=self.window)
        self.register = Mock()
        def spawn(*args, **kwargs):
            (self.root / "chrome-profile" / "DevToolsActivePort").write_text(
                "12345\n/devtools/browser/owned-fixture\n", encoding="ascii")
            return self.proc
        self.popen = self.enter(patch.object(chrome.subprocess, "Popen", side_effect=spawn))
        self.enter(patch.object(chrome.subprocess, "STARTUPINFO", create=True,
                               return_value=SimpleNamespace()))
        self.enter(patch.object(chrome.subprocess, "STARTF_USESHOWWINDOW", 1, create=True))
        self.enter(patch.object(chrome.subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True))
        self.enter(patch.object(chrome, "chrome_path", return_value=self.executable))
        self.enter(patch.object(chrome, "desktop_identity", return_value={
            "current": self.desktop, "input": "Default", "target": self.desktop}))
        self.enter(patch.object(chrome, "process_is_same", return_value=True))
        self.creation = self.enter(patch.object(chrome, "process_creation_token", return_value=987))
        self.listeners = self.enter(patch.object(chrome, "owned_tcp_listeners", return_value=[{
            "pid": 234, "port": 12345, "address": "127.0.0.1"}]))
        self.version = self.enter(patch.object(chrome, "_version", return_value={
            "Browser": "Chrome/160.0", "webSocketDebuggerUrl": "ws://127.0.0.1:12345/devtools/browser/owned-fixture"}))

    def enter(self, item):
        result = item.start()
        self.addCleanup(item.stop)
        return result

    def launch(self, **kwargs):
        return chrome.launch_chrome(self.root, {"command": "browser.launch"},
            register=self.register, windows=lambda pid: [456], owns=self.owns,
            window_info=self.info, desktop=self.desktop, **kwargs)

    def test_exact_launch_has_fresh_profile_native_window_and_owned_endpoint(self):
        ctx = self.launch()
        result = chrome.verify_chrome(ctx, owns=self.owns, desktop=self.desktop)
        self.assertEqual(result["hwnd"], 456)
        self.assertEqual(result["create_time"], 987)
        self.assertEqual(result["cdp_endpoint"], "http://127.0.0.1:12345")
        self.assertFalse(result["headless"])
        self.assertFalse(result["physical_input_used"])
        self.register.assert_called_once_with(self.proc)
        argv = self.popen.call_args.args[0]
        self.assertEqual(argv, [str(self.executable), "--user-data-dir=" + str(self.root / "chrome-profile"),
            "--remote-debugging-address=127.0.0.1", "--remote-debugging-port=0",
            "--no-first-run", "--no-default-browser-check", "--new-window", "about:blank"])

    def test_caller_cannot_supply_flags_profile_endpoint_or_executable(self):
        for key in ("arguments", "profile", "executable", "cdpEndpoint", "headless", "__owned_browser_root"):
            with self.subTest(key=key), self.assertRaisesRegex(chrome.HiddenChromeError, "HIDDEN_CHROME_OPTION_INVALID"):
                chrome.launch_chrome(self.root, {"command": "browser.launch", key: "untrusted"},
                    register=self.register, windows=lambda pid: [], owns=self.owns,
                    window_info=self.info, desktop=self.desktop)
        self.popen.assert_not_called()

    def test_existing_profile_or_invalid_owner_prevents_launch(self):
        (self.root / "chrome-profile").mkdir()
        with self.assertRaisesRegex(chrome.HiddenChromeError, "HIDDEN_CHROME_PROFILE_NOT_FRESH"):
            self.launch()
        (self.root / "chrome-profile").rmdir()
        (self.root / "owner.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(chrome.HiddenChromeError, "HIDDEN_CHROME_PROFILE_OWNER_INVALID"):
            self.launch()
        self.popen.assert_not_called()

    def test_wildcard_or_foreign_listener_kills_only_created_process(self):
        self.listeners.return_value = [{"pid": 234, "port": 12345, "address": "0.0.0.0"}]
        with self.assertRaisesRegex(chrome.HiddenChromeError, "HIDDEN_CHROME_LISTENER_NOT_OWNED"):
            self.launch()
        self.proc.kill.assert_called_once_with()
        self.proc.wait.assert_called_once_with(timeout=5)

    def test_external_or_wrong_browser_websocket_is_refused(self):
        self.version.return_value["webSocketDebuggerUrl"] = "ws://example.invalid:12345/devtools/browser/owned-fixture"
        with self.assertRaisesRegex(chrome.HiddenChromeError, "HIDDEN_CHROME_ENDPOINT_INVALID"):
            self.launch()
        self.proc.kill.assert_called_once_with()

    def test_info_rechecks_process_window_profile_endpoint_and_desktop(self):
        ctx = self.launch()
        self.creation.return_value = 988
        with self.assertRaisesRegex(chrome.HiddenChromeError, "HIDDEN_CHROME_PROCESS_CHANGED"):
            chrome.verify_chrome(ctx, owns=self.owns, desktop=self.desktop)
        self.creation.return_value = 987
        self.owns.return_value = False
        with self.assertRaisesRegex(chrome.HiddenChromeError, "HIDDEN_CHROME_WINDOW_CHANGED"):
            chrome.verify_chrome(ctx, owns=self.owns, desktop=self.desktop)
        self.owns.return_value = True
        with patch.object(chrome, "desktop_identity", return_value={"current": self.desktop, "input": self.desktop}):
            with self.assertRaisesRegex(chrome.HiddenChromeError, "HIDDEN_DESKTOP_IDENTITY_INVALID"):
                chrome.verify_chrome(ctx, owns=self.owns, desktop=self.desktop)
        marker = self.root / "chrome-profile" / "DevToolsActivePort"
        marker.write_text("23456\n/devtools/browser/owned-fixture\n", encoding="ascii")
        with self.assertRaisesRegex(chrome.HiddenChromeError, "HIDDEN_CHROME_ENDPOINT_CHANGED"):
            chrome.verify_chrome(ctx, owns=self.owns, desktop=self.desktop)
        marker.write_text("12345\n/devtools/browser/owned-fixture\n", encoding="ascii")
        (self.root / "owner.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(chrome.HiddenChromeError, "HIDDEN_CHROME_PROFILE_OWNER_CHANGED"):
            chrome.verify_chrome(ctx, owns=self.owns, desktop=self.desktop)

    def test_marker_rejects_injected_hosts_paths_and_invalid_ports(self):
        profile = self.root / "chrome-profile"
        profile.mkdir()
        for contents in ("0\n/devtools/browser/a", "65536\n/devtools/browser/a", "12345\nws://evil/a",
                         "12345\n/devtools/browser/a?x=y", "12345\n/devtools/browser/a\nthird"):
            with self.subTest(contents=contents):
                (profile / "DevToolsActivePort").write_text(contents, encoding="ascii")
                with self.assertRaisesRegex(chrome.HiddenChromeError, "HIDDEN_CHROME_ENDPOINT_INVALID"):
                    chrome._active_port(profile)


if __name__ == "__main__":
    unittest.main()
