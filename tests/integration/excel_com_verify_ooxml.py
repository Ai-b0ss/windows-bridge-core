"""Independent OOXML readback for a temporary Excel COM smoke workbook.

No Excel/COM involvement, no file edits, no third-party spreadsheet packages.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import zipfile

XML_NS = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}


def verify(path: Path) -> dict:
    if not path.is_file() or path.suffix.casefold() != ".xlsx":
        raise ValueError("OFFICE_SMOKE_FILE_MISSING")
    if path.stat().st_size > 5_000_000:
        raise ValueError("OFFICE_SMOKE_OVERSIZE")
    with zipfile.ZipFile(path, "r") as document:
        members=document.infolist()
        if len(members)>128 or sum(info.file_size for info in members)>20_000_000:
            raise ValueError("OFFICE_SMOKE_ZIP_LIMIT_EXCEEDED")
        sheet_info=document.getinfo("xl/worksheets/sheet1.xml") if "xl/worksheets/sheet1.xml" in document.namelist() else None
        if sheet_info is None or sheet_info.file_size>500_000:
            raise ValueError("OFFICE_SMOKE_SHEET_MISSING_OR_OVERSIZE")
        if document.testzip() is not None:
            raise ValueError("OFFICE_SMOKE_ZIP_CRC_BAD")
        if "xl/worksheets/sheet1.xml" not in document.namelist():
            raise ValueError("OFFICE_SMOKE_SHEET_MISSING")
        root = ET.fromstring(document.read("xl/worksheets/sheet1.xml"))
        cells = {cell.attrib.get("r"): cell
                 for cell in root.findall(".//x:c", XML_NS)}
        def text(ref, child):
            element=cells[ref].find("x:"+child,XML_NS)
            return element.text if element is not None else None
        if (float(text("A1","v")),float(text("A2","v"))) != (20.0,22.0):
            raise ValueError("OFFICE_SMOKE_INPUTS_WRONG")
        if text("A3","f") != "SUM(A1:A2)":
            raise ValueError("OFFICE_SMOKE_FORMULA_WRONG")
        if float(text("A3","v")) != 42.0:
            raise ValueError("OFFICE_SMOKE_FORMULA_CACHE_WRONG")
    return {
        "schema":"ff-excel-com-smoke-v1",
        "zip_crc_verified":True,
        "inputs_verified":True,
        "formula_verified":True,
        "calculated_result":42,
        "independent_readback":True,
    }


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("xlsx",type=Path)
    options=parser.parse_args()
    print(json.dumps(verify(options.xlsx),sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError,ValueError,KeyError,zipfile.BadZipFile) as exc:
        print("EXCEL_COM_OOXML_VERIFY_FAILED:"+type(exc).__name__,file=sys.stderr)
        raise SystemExit(2)
