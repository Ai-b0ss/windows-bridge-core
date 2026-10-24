from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
import build_portable_release as builder


class TestReleaseBuildContract(unittest.TestCase):
    def test_no_old_private_repo_history_or_transport_logs(self):
        contents=builder.source_tree(ROOT)
        self.assertIn("tools/optional_addons.py",contents)
        self.assertIn("ADDONS.cmd",contents)
        self.assertIn("runtime/bridge-v3/ff_win_v3_main.py",contents)
        self.assertTrue(all(not name.startswith((".git/","astra_transport/","K:/")) for name in contents))
        self.assertTrue(all(not name.endswith((".jsonl",".sqlite3",".db",".pfx")) for name in contents))
        self.assertEqual(len(contents),len(set(contents)))

    def test_vendor_assets_have_explicit_sha256(self):
        self.assertEqual(len(builder.ASSET_HASHES),3)
        self.assertTrue(all(x.startswith("assets/") and x.endswith(".zip") for x in builder.ASSET_HASHES))
        self.assertTrue(all(len(x)==64 for x in builder.ASSET_HASHES.values()))
        self.assertEqual(len(builder.PREVIOUS_RELEASE_SHA),64)


if __name__=="__main__":
    unittest.main()
