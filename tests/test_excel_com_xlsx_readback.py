"""Structural Excel COM artifact acceptance without Excel or extra packages."""
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"tests/integration"))
from excel_com_verify_ooxml import verify


class TestOfficeOOXMLReadback(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/"owned-smoke.xlsx"

    def create(self,formula="SUM(A1:A2)",value="42",a1="20",a2="22"):
        ns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
        xml=(f'<worksheet xmlns="{ns}"><sheetData>'
             f'<row r="1"><c r="A1"><v>{a1}</v></c></row>'
             f'<row r="2"><c r="A2"><v>{a2}</v></c></row>'
             f'<row r="3"><c r="A3"><f>{formula}</f><v>{value}</v></c></row>'
             '</sheetData></worksheet>')
        with zipfile.ZipFile(self.path,"w",zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("xl/worksheets/sheet1.xml",xml)

    def test_independent_formula_and_cache(self):
        self.create()
        result=verify(self.path)
        self.assertTrue(result["independent_readback"])
        self.assertEqual(result["calculated_result"],42)

    def test_wrong_computed_value_rejected(self):
        self.create(value="41")
        with self.assertRaisesRegex(ValueError,"FORMULA_CACHE_WRONG"):
            verify(self.path)

    def test_wrong_formula_rejected(self):
        self.create(formula="A1+A2")
        with self.assertRaisesRegex(ValueError,"FORMULA_WRONG"):
            verify(self.path)

    def test_wrong_input_rejected(self):
        self.create(a1="19")
        with self.assertRaisesRegex(ValueError,"INPUTS_WRONG"):
            verify(self.path)

    def test_invalid_zip_rejected(self):
        self.path.write_bytes(b"not an xlsx")
        with self.assertRaises(zipfile.BadZipFile):
            verify(self.path)


if __name__ == "__main__":
    unittest.main()
