from pathlib import Path
import json
import shutil
import subprocess
import unittest

ROOT=Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("node"),"node is required")
class ObservedChangeTests(unittest.TestCase):
    def test_click_that_changed_the_page_is_not_reported_as_failure(self):
        done=subprocess.run(["node",str(ROOT/"tests/sidecar_observed_change.test.mjs")],
                            capture_output=True,text=True,timeout=60)
        self.assertEqual(done.returncode,0,done.stderr[-400:])
        out=json.loads(done.stdout.strip().splitlines()[-1])
        self.assertIs(out["click_changed"],True)
        self.assertEqual(out["click_changed_kind"],"observed_change")
        self.assertIs(out["click_unchanged"],False)
        self.assertIs(out["hover_changed"],False)
        self.assertIs(out["explicit_postcondition"],False)


if __name__=="__main__":
    unittest.main()
