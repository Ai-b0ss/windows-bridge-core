from pathlib import Path
import os
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('node'), 'node required')
class AriaLinkTests(unittest.TestCase):
    def test_real_isolated_browser(self):
        runtime = ROOT / 'runtime/bridge-v3/node_modules/playwright'
        if not os.environ.get('FF_TEST_PLAYWRIGHT_MODULE') and not runtime.exists():
            self.skipTest('install pinned browser runtime or set FF_TEST_PLAYWRIGHT_MODULE')
        done = subprocess.run(['node', '--test', str(ROOT / 'tests/browser_aria_link.test.mjs')],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, (done.stdout + done.stderr)[-4000:])


if __name__ == '__main__':
    unittest.main()
