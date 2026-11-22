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
        source_names=set(builder.source_tree(ROOT))
        for name in sorted(source_names):
            stored=subprocess.run(["git","show",":"+name],cwd=ROOT,capture_output=True).stdout
            if not stored:
                continue   # not tracked yet
            if hashlib.sha256(stored).hexdigest()!=manifest.get(name):
                wrong.append(name)
        stale_source=[
            name for name in sorted(manifest)
            if (name.startswith(("runtime/","tests/")) or name in builder.ROOT_FILES|builder.TOOL_FILES)
            and name not in source_names
        ]
        self.assertEqual(wrong,[],"refresh release-manifest.json from the index (git add, then hash `git show :path`)")
        self.assertEqual(stale_source,[],"remove stale source entries via build_portable_release.py --refresh-source-manifest")

    def test_manifest_provenance_is_not_stale_or_forged(self):
        """Checked-in release-manifest.json must not retain stale ancestor SHAs like c034e527/abd6666."""
        manifest=json.loads((ROOT/"release-manifest.json").read_text(encoding="utf-8"))
        source_commit=manifest.get("source_commit")
        self.assertNotIn(str(source_commit).lower(),builder.KNOWN_STALE_COMMITS)
        result=builder.verify_release_manifest_provenance(manifest,repo=ROOT,mode="template")
        self.assertTrue(result["ok"])
        self.assertEqual(result["source_commit"],builder.TEMPLATE_SOURCE_COMMIT)


if __name__=="__main__":
    unittest.main()
