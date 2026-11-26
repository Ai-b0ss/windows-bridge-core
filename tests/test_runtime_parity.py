from pathlib import Path
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import runtime_parity


@unittest.skipUnless(shutil.which("git"),"needs git")
class ParityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.repo=Path(self.tmp.name)/"repo"
        (self.repo/"runtime/bridge-v3").mkdir(parents=True)
        (self.repo/"runtime/bridge-v3/a.py").write_bytes(b"print(1)\n")
        (self.repo/"runtime/bridge-v3/b.py").write_bytes(b"print(2)\n")
        run=lambda *a: subprocess.run(["git","-C",str(self.repo),*a],check=True,capture_output=True)
        run("init","-q"); run("config","user.email","t@example.com"); run("config","user.name","t")
        run("config","core.autocrlf","false"); run("add","."); run("commit","-qm","x")
        self.live=Path(self.tmp.name)/"live"; self.live.mkdir()

    def tearDown(self): self.tmp.cleanup()

    def test_identical_install_is_parity(self):
        (self.live/"a.py").write_bytes(b"print(1)\n"); (self.live/"b.py").write_bytes(b"print(2)\n")
        r=runtime_parity.compare(self.repo,self.live,"HEAD")
        self.assertEqual((r["identical"],r["different"],r["missing_in_installed"]),(2,[],[]))
        self.assertEqual(r["reparse_points"],[])
        self.assertFalse(r["ref_is_stale"])

    def test_difference_and_missing_are_named_without_contents(self):
        (self.live/"a.py").write_bytes(b"print('changed')\n")
        r=runtime_parity.compare(self.repo,self.live,"HEAD")
        self.assertEqual(r["different"],["a.py"]); self.assertEqual(r["missing_in_installed"],["b.py"])
        self.assertNotIn("changed",str(r))

    def test_empty_tracked_runtime_tree_fails_closed(self):
        empty_repo=Path(self.tmp.name)/"empty_repo"
        empty_repo.mkdir()
        (empty_repo/"README.md").write_bytes(b"no runtime tree\n")
        run=lambda *a: subprocess.run(["git","-C",str(empty_repo),*a],check=True,capture_output=True)
        run("init","-q"); run("config","user.email","t@example.com"); run("config","user.name","t")
        run("config","core.autocrlf","false"); run("add","."); run("commit","-qm","empty")
        cp=subprocess.run(
            [sys.executable,str(ROOT/"tools/runtime_parity.py"),"--installed",str(self.live),"--ref","HEAD","--repo",str(empty_repo)],
            capture_output=True,text=True,check=False,
        )
        self.assertEqual(cp.returncode,1)
        report=json.loads(cp.stdout)
        self.assertEqual(report["tracked"],0)
        self.assertFalse(report["parity"])

    def test_reparse_point_junction_in_installed_tree_fails_closed(self):
        (self.repo/"runtime/bridge-v3/sub").mkdir(parents=True)
        (self.repo/"runtime/bridge-v3/sub/c.py").write_bytes(b"print(3)\n")
        run=lambda *a: subprocess.run(["git","-C",str(self.repo),*a],check=True,capture_output=True)
        run("add","."); run("commit","-qm","add sub")
        (self.live/"a.py").write_bytes(b"print(1)\n")
        (self.live/"b.py").write_bytes(b"print(2)\n")
        link_dir=self.live/"sub"
        if os.name=="nt":
            subprocess.run(["cmd","/c","mklink","/J",str(link_dir),str(self.repo/"runtime/bridge-v3/sub")],check=True,capture_output=True)
            self.addCleanup(lambda: os.rmdir(link_dir) if link_dir.exists() else None)
        else:
            os.symlink(self.repo/"runtime/bridge-v3/sub",link_dir)
        cp=subprocess.run(
            [sys.executable,str(ROOT/"tools/runtime_parity.py"),"--installed",str(self.live),"--ref","HEAD","--repo",str(self.repo)],
            capture_output=True,text=True,check=False,
        )
        self.assertEqual(cp.returncode,1)
        report=json.loads(cp.stdout)
        self.assertFalse(report["parity"])
        self.assertEqual(report["reparse_points"],["sub/c.py"])
        self.assertNotIn(str(self.tmp.name),cp.stdout)

    def test_known_stale_ref_commit_fails_closed(self):
        (self.live/"a.py").write_bytes(b"print(1)\n"); (self.live/"b.py").write_bytes(b"print(2)\n")
        stale_sha=next(iter(runtime_parity._deploy.KNOWN_STALE_COMMITS))
        with patch.object(runtime_parity,"resolve_commit",return_value=stale_sha):
            rc=runtime_parity.main(["--installed",str(self.live),"--ref","HEAD","--repo",str(self.repo)])
        self.assertEqual(rc,1)


if __name__=="__main__":
    unittest.main()
