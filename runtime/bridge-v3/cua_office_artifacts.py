"""Bounded read-only Office artifact checks; never executes/extracts documents.

Schemas cover main DOCX paragraphs, ordered PPTX slide text runs and typed XLSX
cells. They do not claim document-wide visual/formatting or macro verification.
"""
import io
import posixpath
import re
import stat
import zipfile
from decimal import Decimal, InvalidOperation
import xml.etree.ElementTree as ET

class ArtifactError(ValueError):
    pass

_LIMIT = 32 * 1024 * 1024
_KINDS = {"word": "docx.paragraphs", "microsoft word": "docx.paragraphs",
          "winword.exe": "docx.paragraphs", "powerpoint": "pptx.slides",
          "microsoft powerpoint": "pptx.slides", "powerpnt.exe": "pptx.slides",
          "excel": "xlsx.cells", "microsoft excel": "xlsx.cells"}
_S = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_R = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
_P = "{http://schemas.openxmlformats.org/package/2006/relationships}"
_W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"

def _invalid():
    raise ArtifactError("ASSISTANT_ARTIFACT_EXPECTATION_INVALID")

def _texts(values):
    if not isinstance(values, list) or len(values) > 4096:
        _invalid()
    if any(not isinstance(v, str) or len(v) > 65536 for v in values):
        _invalid()

def _number(value):
    if not isinstance(value, str) or len(value) > 128:
        _invalid()
    try:
        n = Decimal(value)
    except InvalidOperation:
        _invalid()
    if not n.is_finite():
        _invalid()
    return n

def _cell(c):
    if not isinstance(c, dict) or set(c) != {"type", "value"}:
        _invalid()
    t, v = c["type"], c["value"]
    if t == "string":
        if not isinstance(v, str) or len(v) > 65536: _invalid()
    elif t == "number":
        _number(v)
    elif t == "boolean":
        if type(v) is not bool: _invalid()
    else: _invalid()

def validate_expectation(app, expected):
    if not isinstance(expected, dict) or expected.get("kind") != _KINDS.get(str(app).casefold()) or not expected.get("kind"):
        _invalid()
    kind = expected["kind"]
    if kind == "docx.paragraphs":
        if set(expected) != {"kind", "paragraphs"}: _invalid()
        _texts(expected["paragraphs"])
    elif kind == "pptx.slides":
        if set(expected) != {"kind", "slides"} or not isinstance(expected["slides"], list) or not 1 <= len(expected["slides"]) <= 256: _invalid()
        for texts in expected["slides"]: _texts(texts)
    else:
        if set(expected) != {"kind", "sheets"} or not isinstance(expected["sheets"], list) or not 1 <= len(expected["sheets"]) <= 256: _invalid()
        names = []
        for sheet in expected["sheets"]:
            if not isinstance(sheet, dict) or set(sheet) != {"name", "cells"}: _invalid()
            name, cells = sheet["name"], sheet["cells"]
            if not isinstance(name, str) or not 1 <= len(name) <= 31 or not isinstance(cells, dict) or len(cells) > 4096: _invalid()
            names.append(name)
            for address, value in cells.items():
                if not isinstance(address, str) or not re.fullmatch(r"[A-Z]{1,3}[1-9][0-9]{0,6}", address): _invalid()
                col, row = re.fullmatch(r"([A-Z]+)([0-9]+)", address).groups()
                n = 0
                for char in col: n = n * 26 + ord(char) - 64
                if n > 16384 or int(row) > 1048576: _invalid()
                _cell(value)
        if len(set(names)) != len(names): _invalid()
    return expected

def _xml(z, name):
    data = z.read(name)
    if b"<!DOCTYPE" in data.replace(b"\x00", b"").upper() or b"<!ENTITY" in data.replace(b"\x00", b"").upper():
        raise ArtifactError("ASSISTANT_ARTIFACT_UNSAFE_XML")
    return ET.fromstring(data)

def _target(base, target):
    # Accept only a bounded package-relative relationship, never external paths.
    if not isinstance(target, str) or not target or "\\" in target or ":" in target or target.startswith("/"):
        raise ArtifactError("ASSISTANT_ARTIFACT_RELATIONSHIP_INVALID")
    name = posixpath.normpath(posixpath.join(base, target))
    if not name.startswith(base + "/") or "/../" in name:
        raise ArtifactError("ASSISTANT_ARTIFACT_RELATIONSHIP_INVALID")
    return name

def _relationships(z, name, base, expected_type):
    result = {}
    for rel in _xml(z, name):
        if rel.tag != _P + "Relationship": continue
        if rel.get("Type", "").endswith("/" + expected_type):
            rid = rel.get("Id")
            if not rid or rid in result or rel.get("TargetMode", "Internal") != "Internal":
                raise ArtifactError("ASSISTANT_ARTIFACT_RELATIONSHIP_INVALID")
            result[rid] = _target(base, rel.get("Target"))
    return result

def _read_docx(z):
    body = _xml(z, "word/document.xml").find(_W + "body")
    if body is None: raise ArtifactError("ASSISTANT_ARTIFACT_INVALID")
    # Includes table paragraphs in document order. Ignores headers/footers/styles.
    return {"kind": "docx.paragraphs", "paragraphs": [
        "".join((n.text or "") if n.tag == _W + "t" else
                "\t" if n.tag == _W + "tab" else "\n"
                for n in p.iter() if n.tag in {_W + "t", _W + "tab", _W + "br", _W + "cr"})
        for p in body.iter(_W + "p")]}

def _read_pptx(z):
    ns = "{http://schemas.openxmlformats.org/presentationml/2006/main}"
    pres = _xml(z, "ppt/presentation.xml")
    rels = _relationships(z, "ppt/_rels/presentation.xml.rels", "ppt", "slide")
    ids = pres.find(ns + "sldIdLst")
    slides = []
    if ids is None: raise ArtifactError("ASSISTANT_ARTIFACT_INVALID")
    for item in ids:
        name = rels[item.attrib[_R + "id"]]
        slides.append([t.text or "" for t in _xml(z, name).iter(_A + "t")])
    return {"kind": "pptx.slides", "slides": slides}

def _read_xlsx(z):
    strings = []
    if "xl/sharedStrings.xml" in z.namelist():
        strings = ["".join(t.text or "" for t in si.iter(_S + "t"))
                   for si in _xml(z, "xl/sharedStrings.xml")]
    rels = _relationships(z, "xl/_rels/workbook.xml.rels", "xl", "worksheet")
    sheets = []
    root = _xml(z, "xl/workbook.xml").find(_S + "sheets")
    if root is None: raise ArtifactError("ASSISTANT_ARTIFACT_INVALID")
    names = set()
    for item in root:
        name = item.attrib["name"]
        if name in names: raise ArtifactError("ASSISTANT_ARTIFACT_INVALID")
        names.add(name)
        xml = _xml(z, rels[item.attrib[_R + "id"]])
        cells = {}
        for c in xml.iter(_S + "c"):
            address = c.attrib["r"]
            if address in cells: raise ArtifactError("ASSISTANT_ARTIFACT_INVALID")
            if c.find(_S + "f") is not None:
                raise ArtifactError("ASSISTANT_ARTIFACT_FORMULA_NOT_SUPPORTED")
            t, v = c.get("t", "n"), c.find(_S + "v")
            if t == "inlineStr":
                value = {"type": "string", "value": "".join(n.text or "" for n in c.iter(_S + "t"))}
            elif v is None: continue  # Blank/formatted cells, not populated data.
            elif t == "s":
                index = int(v.text)
                if not 0 <= index < len(strings): raise ArtifactError("ASSISTANT_ARTIFACT_INVALID")
                value = {"type": "string", "value": strings[index]}
            elif t == "b" and v.text in {"0", "1"}:
                value = {"type": "boolean", "value": v.text == "1"}
            elif t == "n":
                value = {"type": "number", "value": v.text}
                _number(v.text)
            else: raise ArtifactError("ASSISTANT_ARTIFACT_CELL_NOT_SUPPORTED")
            cells[address] = value
        sheets.append({"name": name, "cells": cells})
    return {"kind": "xlsx.cells", "sheets": sheets}

def _matches(actual, expected):
    if expected["kind"] != "xlsx.cells": return actual == expected
    if [s["name"] for s in actual["sheets"]] != [s["name"] for s in expected["sheets"]]: return False
    for a, e in zip(actual["sheets"], expected["sheets"]):
        if set(a["cells"]) != set(e["cells"]): return False
        for key, want in e["cells"].items():
            got = a["cells"][key]
            if got["type"] != want["type"]: return False
            if want["type"] == "number":
                if _number(got["value"]) != _number(want["value"]): return False
            elif got["value"] != want["value"]: return False
    return True

def verify_office_bytes(raw, app, expected):
    validate_expectation(app, expected)
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            infos = z.infolist()
            if not 1 <= len(infos) <= 2048 or sum(i.file_size for i in infos) > _LIMIT:
                raise ArtifactError("ASSISTANT_ARTIFACT_ARCHIVE_LIMIT")
            names = set()
            for i in infos:
                name = i.filename
                if name != i.orig_filename or name in names or "\\" in name or name.startswith("/") or ":" in name or ".." in name.split("/") or stat.S_ISLNK(i.external_attr >> 16) or i.flag_bits & 1:
                    raise ArtifactError("ASSISTANT_ARTIFACT_ARCHIVE_INVALID")
                names.add(name)
            parser = {"docx.paragraphs": _read_docx, "pptx.slides": _read_pptx, "xlsx.cells": _read_xlsx}[expected["kind"]]
            actual = parser(z)
            validate_expectation(app, actual)
            if not _matches(actual, expected):
                raise ArtifactError("ASSISTANT_ARTIFACT_POSTCONDITION_FAILED")
            return {"kind": expected["kind"], "matched": True, "actual": actual,
                    "scope": "declared-office-content; not visual formatting or document-wide security"}
    except ArtifactError: raise
    except (zipfile.BadZipFile, ET.ParseError, KeyError, ValueError, TypeError, RuntimeError, OSError, RecursionError, OverflowError) as exc:
        raise ArtifactError("ASSISTANT_ARTIFACT_INVALID") from exc
