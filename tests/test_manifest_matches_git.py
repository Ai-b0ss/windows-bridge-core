from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import build_portable_release as builder


@unittest.skipUnless(shutil.which("git") and (ROOT/".git").exists(),"needs a git checkout")
class ManifestMatchesGit(unittest.TestCase):
    def test_every_manifest_hash_is_the_stored_git_bytes(self):
        """The portable builder verifies against `git archive` (LF), not the working tree
        (CRLF on a Windows checkout with core.autocrlf=true). Hashing disk bytes breaks releases."""
        manifest=json.loads((ROOT/"release-manifest.json").read_text(encoding="utf-8"))["files"]
        wrong=[]
        for name in builder.source_tree(ROOT):
            stored=subprocess.run(["git","show",":"+name],cwd=ROOT,capture_output=True).stdout
            if not stored:
                continue   # not tracked yet
            if hashlib.sha256(stored).hexdigest()!=manifest.get(name):
                wrong.append(name)
        self.assertEqual(wrong,[],"refresh release-manifest.json from the index (git add, then hash `git show :path`)")


if __name__=="__main__":
    unittest.main()
