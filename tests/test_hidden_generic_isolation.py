"""Generic launch must not turn an ambient flag into permission or join a singleton."""
from __future__ import annotations

import ast
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

RUNTIME=Path(__file__).resolve().parents[1]/"runtime"/"bridge-v3"
sys.path.insert(0,str(RUNTIME))
from cua_hidden_apps import GENERIC_LAUNCH_ENV, generic_launch_spec, hidden_worker_environment


class GenericLaunchIsolation(unittest.TestCase):
    def setUp(self):
        self.temporary=TemporaryDirectory(prefix="ff-generic-policy-")
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name)

    def executable(self,name="owned.exe"):
        path=self.root/name
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(b"test-only, never executed")
        return path

    def spec(self,path,**args):
        with patch.dict(os.environ,{GENERIC_LAUNCH_ENV:"1"}):
            return generic_launch_spec({"command":"launch_exe","executable":str(path),**args})

    def test_ambient_permission_does_not_enable_unrelated_worker(self):
        parent={"PATH":"unchanged",GENERIC_LAUNCH_ENV:"1"}
        default=hidden_worker_environment(parent)
        enabled=hidden_worker_environment(parent,allow_generic_launch=True)
        self.assertNotIn(GENERIC_LAUNCH_ENV,default)
        self.assertEqual(enabled[GENERIC_LAUNCH_ENV],"1")
        self.assertEqual(parent,{"PATH":"unchanged",GENERIC_LAUNCH_ENV:"1"})
        self.assertIsNot(parent,enabled)
        for invalid in (1,"1",None):
            with self.subTest(invalid=invalid),self.assertRaisesRegex(ValueError,"HIDDEN_START_OPTION_INVALID"):
                hidden_worker_environment(parent,allow_generic_launch=invalid)

    def test_generic_route_is_off_by_default(self):
        path=self.executable()
        with patch.dict(os.environ,{GENERIC_LAUNCH_ENV:""}):
            with self.assertRaisesRegex(ValueError,"HIDDEN_GENERIC_LAUNCH_DISABLED"):
                generic_launch_spec({"executable":str(path)})

    def test_default_profile_browsers_editors_office_never_reach_popen(self):
        for name in ("chrome.exe","msedge.exe","Code.exe","Cursor.exe","EXCEL.EXE","WINWORD.EXE","POWERPNT.EXE"):
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,"HIDDEN_APP_ISOLATION_ROUTE_REQUIRED"):
                self.spec(self.executable(name))

    def test_electron_chromium_or_packaged_app_detected_under_other_name(self):
        for marker in ("resources/app.asar","resources/app/dummy","chrome_elf.dll","chrome_100_percent.pak"):
            with TemporaryDirectory(dir=self.root) as folder:
                package=Path(folder)
                executable=package/"renamed.exe";executable.write_bytes(b"test-only")
                asset=package/marker;asset.parent.mkdir(parents=True,exist_ok=True);asset.write_bytes(b"marker")
                with self.subTest(marker=marker),self.assertRaisesRegex(ValueError,"HIDDEN_APP_ISOLATION_ROUTE_REQUIRED"):
                    self.spec(executable)
        with self.assertRaisesRegex(ValueError,"HIDDEN_APP_ISOLATION_ROUTE_REQUIRED"):
            self.spec(self.executable("WindowsApps/owned.exe"))

    def test_classic_app_arguments_and_timeout_validated_before_launch(self):
        path=self.executable()
        expected=["space separated",'a"quote']
        self.assertEqual(self.spec(path,arguments=expected,working_directory=str(self.root),window_timeout_s=2),
                         (path.resolve(),expected,str(self.root),2.0))
        for arguments in ("argument",["a\0b"],[False],["a"]*33):
            with self.subTest(arguments=arguments),self.assertRaisesRegex(ValueError,"HIDDEN_ARGUMENTS_INVALID"):
                self.spec(path,arguments=arguments)
        for timeout in (True,0,61,float("nan"),float("inf")):
            with self.subTest(timeout=timeout),self.assertRaisesRegex(ValueError,"HIDDEN_WINDOW_TIMEOUT_INVALID"):
                self.spec(path,window_timeout_s=timeout)


class WorkerProcessIdentity(unittest.TestCase):
    """Exercise production ownership helpers without importing a desktop worker."""
    def setUp(self):
        tree=ast.parse((RUNTIME/"cua_hidden_worker.py").read_text(encoding="utf-8"))
        helpers=[node for node in tree.body if isinstance(node,(ast.FunctionDef,ast.ClassDef))
                 and node.name in {"register_app","live_app","owns","HiddenLaunchError"}]
        self.process=SimpleNamespace(pid=42,poll=Mock(return_value=None),kill=Mock(),wait=Mock())
        self.creation=Mock(return_value=123456)
        def window_pid(hwnd,pid):pid._obj.value=42
        self.namespace={"apps":{},"app_tokens":{},"process_creation_token":self.creation,
                        "w":wintypes,"ctypes":ctypes,"U":SimpleNamespace(GetWindowThreadProcessId=window_pid),
                        "windows":Mock(return_value=[100])}
        exec(compile(ast.Module(body=helpers,type_ignores=[]),str(RUNTIME/"cua_hidden_worker.py"),"exec"),self.namespace)

    def test_process_birth_and_window_must_still_match_registered_child(self):
        self.namespace["register_app"](self.process)
        self.assertTrue(self.namespace["owns"](100))
        self.assertFalse(self.namespace["owns"](101))
        self.creation.return_value=987654
        self.assertFalse(self.namespace["owns"](100))
        self.creation.return_value=123456
        self.process.poll.return_value=0
        self.assertFalse(self.namespace["owns"](100))
        for invalid in (True,"100",0,-1):self.assertFalse(self.namespace["owns"](invalid))

    def test_unknown_process_birth_cleans_only_child_and_never_claims_it(self):
        self.creation.return_value=None
        with self.assertRaisesRegex(RuntimeError,"HIDDEN_APP_IDENTITY_UNAVAILABLE"):
            self.namespace["register_app"](self.process)
        self.process.kill.assert_called_once_with()
        self.process.wait.assert_called_once_with(timeout=5)
        self.assertEqual(self.namespace["apps"],{})
        self.assertEqual(self.namespace["app_tokens"],{})


if __name__=="__main__":unittest.main()
