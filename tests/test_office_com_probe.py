import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"runtime/bridge-v3"))
from cua_office_com_probe import excel_registration
from cua_bridge_v3 import CuaBridgeError

GUID="{00024500-0000-0000-C000-000000000046}"


class TestExcelComRegistration(unittest.TestCase):
    def test_registration_bounded_read_only_candidate(self):
        calls=[]
        def query(key):
            calls.append(key)
            return GUID if key==r"Excel.Application\CLSID" else r'"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE" /automation'
        present=excel_registration(query=query,file_exists=lambda _:True)
        self.assertTrue(present["registration_found"])
        self.assertTrue(present["registered_executable_present"])
        self.assertEqual(present["candidate_route"],"EXCEL_COM")
        self.assertEqual(len(calls),2)
        for key in ("excel_process_started","user_workbook_accessed",
                    "model_called","task_completed","task_support_proven"):
            self.assertFalse(present[key])
        self.assertNotIn("C:\\Program Files",str(present))

    def test_broken_executable_not_treated_as_route(self):
        def query(key):
            return GUID if key==r"Excel.Application\CLSID" else r'"C:\fake\EXCEL.EXE" /automation'
        result=excel_registration(query=query,file_exists=lambda _:False)
        self.assertTrue(result["registration_found"])
        self.assertIsNone(result["candidate_route"])

    def test_invalid_registration_fails_closed(self):
        result=excel_registration(query=lambda key:"{invalid-guid}" if key.endswith("CLSID") else "ignored")
        self.assertFalse(result["registration_found"])
        self.assertIsNone(result["candidate_route"])

    def test_missing_office_registry_fails_closed(self):
        def no_key(_):
            raise FileNotFoundError("not present")
        result=excel_registration(query=no_key)
        self.assertFalse(result["registration_found"])
        self.assertFalse(result["task_support_proven"])

    def test_dispatch_explicit_opt_in_only(self):
        from test_task_preflight_unified import FakePlane
        plane=FakePlane()
        data={"schema":"ff-excel-com-discovery-v1","candidate_route":"EXCEL_COM",
              "excel_process_started":False,"task_support_proven":False}
        with patch("cua_office_com_probe.excel_registration",return_value=data) as probe:
            default=plane._task_preflight({"app":"Excel","task":"read cell metadata"})
            self.assertIsNone(default["office_com_registration"])
            self.assertEqual(probe.call_count,0)
            opt=plane._task_preflight({"app":"Microsoft Excel","task":"inspect test book",
                                       "verify_office_com":True})
            self.assertEqual(opt["office_com_registration"],data)
            self.assertEqual(opt["next_step"],"verify_owned_hidden_excel_com_and_task_postcondition")
            probe.assert_called_once_with()

    def test_non_excel_or_wrong_type_rejected(self):
        from test_task_preflight_unified import FakePlane
        for arg,code in [
            ({"app":"Cursor","task":"read","verify_office_com":True},"OFFICE_COM_APP_UNSUPPORTED"),
            ({"app":"Excel","task":"read","verify_office_com":"yes"},"OFFICE_COM_PROBE_FLAG_INVALID"),
        ]:
            with self.subTest(arg=arg):
                with self.assertRaises(CuaBridgeError) as ctx:
                    FakePlane()._task_preflight(arg)
                self.assertEqual(ctx.exception.code,code)


if __name__=="__main__":
    unittest.main()
