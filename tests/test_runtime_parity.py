from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

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

    def test_difference_and_missing_are_named_without_contents(self):
        (self.live/"a.py").write_bytes(b"print('changed')\n")
        r=runtime_parity.compare(self.repo,self.live,"HEAD")
        self.assertEqual(r["different"],["a.py"]); self.assertEqual(r["missing_in_installed"],["b.py"])
        self.assertNotIn("changed",str(r))


if __name__=="__main__":
    unittest.main()
