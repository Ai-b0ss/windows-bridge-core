import pathlib
import sys
import tempfile
import unittest
import zipfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tools"))
from runtime_inventory import compare,TRACKED


class TestVersionInventory(unittest.TestCase):
    def test_three_way_readonly_comparison(self):
        with tempfile.TemporaryDirectory() as td:
            temp=pathlib.Path(td)
            source=temp/"source"
            live=temp/"live"
            source.mkdir()
            live.mkdir()
            (source/"cua_router.py").write_bytes(b"public")
            (live/"cua_router.py").write_bytes(b"installed")
            (live/"private-token.json").write_text("KEEP PRIVATE",encoding="utf-8")
            archive=temp/"package.zip"
            with zipfile.ZipFile(archive,"w") as z:
                z.writestr("runtime/bridge-v3/cua_router.py",b"public")
            result=compare(source,live,archive,names=("cua_router.py",))
            self.assertTrue(result["read_only"])
            self.assertFalse(result["all_live_equal_source"])
            self.assertTrue(result["modules"][0]["matches"]["source_equals_package"])
            self.assertFalse(result["modules"][0]["matches"]["source_equals_live"])
            self.assertNotIn("KEEP PRIVATE",str(result))
            self.assertEqual((live/"private-token.json").read_text(encoding="utf-8"),"KEEP PRIVATE")

    def test_directory_escape_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            temp=pathlib.Path(td)
            (temp/"source").mkdir()
            (temp/"live").mkdir()
            with zipfile.ZipFile(temp/"package.zip","w") as z:
                z.writestr("placeholder",b"")
            with self.assertRaisesRegex(ValueError,"non-allowlisted"):
                compare(temp/"source",temp/"live",temp/"package.zip",names=("../private.json",))


if __name__=="__main__":
    unittest.main()
