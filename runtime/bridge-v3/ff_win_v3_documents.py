from __future__ import annotations

import html
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

W_NS='http://schemas.openxmlformats.org/wordprocessingml/2006/main'
X_NS='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
ET.register_namespace('w',W_NS)
ET.register_namespace('',X_NS)


def _atomic_zip_replace(path:Path,replacements:dict[str,bytes])->None:
    tmp=path.with_suffix(path.suffix+'.tmp')
    with zipfile.ZipFile(path,'r') as src, zipfile.ZipFile(tmp,'w') as dst:
        for info in src.infolist():
            data=replacements.get(info.filename,src.read(info.filename))
            dst.writestr(info,data)
    os.replace(tmp,path)


def _col_letters(n:int)->str:
    out=''
    while n:
        n,rem=divmod(n-1,26); out=chr(65+rem)+out
    return out


def _parse_rows(content:Any)->list[list[Any]]:
    if isinstance(content,list):
        if not all(isinstance(r,list) for r in content): raise ValueError('EXCEL_ROWS_INVALID')
        return content
    if not isinstance(content,str): raise ValueError('EXCEL_CONTENT_INVALID')
    text=content.strip()
    if not text: return []
    if text.startswith('['):
        rows=json.loads(text)
        if not isinstance(rows,list) or not all(isinstance(r,list) for r in rows): raise ValueError('EXCEL_JSON_2D_ARRAY_REQUIRED')
        return rows
    delim='\t' if '\t' in text else ','
    return [[cell for cell in line.split(delim)] for line in text.splitlines()]


def _xlsx_sheet_xml(rows:list[list[Any]])->bytes:
    root=ET.Element(f'{{{X_NS}}}worksheet')
    data=ET.SubElement(root,f'{{{X_NS}}}sheetData')
    for ri,row in enumerate(rows,1):
        r=ET.SubElement(data,f'{{{X_NS}}}row',{'r':str(ri)})
        for ci,value in enumerate(row,1):
            if value is None or value=='': continue
            ref=f'{_col_letters(ci)}{ri}'
            c=ET.SubElement(r,f'{{{X_NS}}}c',{'r':ref})
            if isinstance(value,(int,float)) and not isinstance(value,bool):
                v=ET.SubElement(c,f'{{{X_NS}}}v'); v.text=str(value)
            elif isinstance(value,bool):
                c.set('t','b'); v=ET.SubElement(c,f'{{{X_NS}}}v'); v.text='1' if value else '0'
            else:
                c.set('t','inlineStr'); isel=ET.SubElement(c,f'{{{X_NS}}}is'); t=ET.SubElement(isel,f'{{{X_NS}}}t'); t.text=str(value)
    return ET.tostring(root,encoding='utf-8',xml_declaration=True)


def create_xlsx(path:Path,rows:list[list[Any]],sheet_name:str='Sheet1')->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    safe_sheet=sheet_name[:31].replace('&','and').replace('<','').replace('>','') or 'Sheet1'
    content_types='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'''
    rels='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'''
    workbook=f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="{X_NS}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="{html.escape(safe_sheet,quote=True)}" sheetId="1" r:id="rId1"/></sheets></workbook>'''
    wb_rels='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>'''
    tmp=path.with_suffix(path.suffix+'.tmp')
    with zipfile.ZipFile(tmp,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml',content_types); z.writestr('_rels/.rels',rels); z.writestr('xl/workbook.xml',workbook); z.writestr('xl/_rels/workbook.xml.rels',wb_rels); z.writestr('xl/worksheets/sheet1.xml',_xlsx_sheet_xml(rows))
    os.replace(tmp,path)


def _set_xlsx_range(path:Path,range_value:str,values:list[list[Any]],extras:Any)->dict[str,Any]:
    sheet_name,r1,r2,c1,c2=extras._parse_excel_range(range_value)
    if r1 is None: raise ValueError('EXCEL_RANGE_REQUIRED')
    expected_rows=r2-r1+1; expected_cols=c2-c1+1
    if len(values)!=expected_rows or any(len(row)!=expected_cols for row in values): raise ValueError(f'EXCEL_RANGE_SHAPE_MISMATCH:{expected_rows}x{expected_cols}')
    with zipfile.ZipFile(path,'r') as zf:
        mapping=extras._xlsx_sheet_map(zf); chosen=None
        if sheet_name:
            chosen=next(((n,p) for n,p in mapping if n==sheet_name),None)
        else:
            chosen=mapping[0] if mapping else None
        if not chosen: raise ValueError('EXCEL_SHEET_NOT_FOUND')
        _,sheet_path=chosen; root=ET.fromstring(zf.read(sheet_path))
    sheet_data=root.find(f'{{{X_NS}}}sheetData')
    if sheet_data is None: sheet_data=ET.SubElement(root,f'{{{X_NS}}}sheetData')
    rows_by_num={int(r.attrib.get('r','0')):r for r in sheet_data.findall(f'{{{X_NS}}}row') if r.attrib.get('r','').isdigit()}
    for roff,row_values in enumerate(values):
        rn=r1+roff; row=rows_by_num.get(rn)
        if row is None:
            row=ET.Element(f'{{{X_NS}}}row',{'r':str(rn)}); sheet_data.append(row); rows_by_num[rn]=row
        cells={c.attrib.get('r',''):c for c in row.findall(f'{{{X_NS}}}c')}
        for coff,value in enumerate(row_values):
            cn=c1+coff; ref=f'{_col_letters(cn)}{rn}'; cell=cells.get(ref)
            if cell is None: cell=ET.SubElement(row,f'{{{X_NS}}}c',{'r':ref})
            for child in list(cell): cell.remove(child)
            cell.attrib.pop('t',None)
            if value is None or value=='': continue
            if isinstance(value,(int,float)) and not isinstance(value,bool):
                v=ET.SubElement(cell,f'{{{X_NS}}}v'); v.text=str(value)
            else:
                cell.set('t','inlineStr'); isel=ET.SubElement(cell,f'{{{X_NS}}}is'); t=ET.SubElement(isel,f'{{{X_NS}}}t'); t.text=str(value)
    xml=ET.tostring(root,encoding='utf-8',xml_declaration=True); _atomic_zip_replace(path,{sheet_path:xml})
    return {'ok':True,'path':str(path),'range':range_value,'rows':expected_rows,'columns':expected_cols}


def create_docx(path:Path,markdown:str)->None:
    path.parent.mkdir(parents=True,exist_ok=True)
    def para(text:str,style:str|None=None)->str:
        ppr=f'<w:pPr><w:pStyle w:val="{style}"/></w:pPr>' if style else ''
        return f'<w:p>{ppr}<w:r><w:t xml:space="preserve">{html.escape(text)}</w:t></w:r></w:p>'
    body=[]
    for line in markdown.splitlines():
        if line.startswith('# '): body.append(para(line[2:],'Heading1'))
        elif line.startswith('## '): body.append(para(line[3:],'Heading2'))
        elif line.startswith('### '): body.append(para(line[4:],'Heading3'))
        else: body.append(para(line))
    document=f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="{W_NS}"><w:body>{''.join(body)}<w:sectPr/></w:body></w:document>'''
    styles=f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="{W_NS}"><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/></w:style><w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/></w:style></w:styles>'''
    content='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>'''
    rels='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'''
    docrels='''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'''
    tmp=path.with_suffix(path.suffix+'.tmp')
    with zipfile.ZipFile(tmp,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml',content); z.writestr('_rels/.rels',rels); z.writestr('word/document.xml',document); z.writestr('word/styles.xml',styles); z.writestr('word/_rels/document.xml.rels',docrels)
    os.replace(tmp,path)


def edit_docx(path:Path,old:str,new:str,expected:int)->dict[str,Any]:
    replacements={}; found=0
    with zipfile.ZipFile(path,'r') as zf:
        names=['word/document.xml']+[n for n in zf.namelist() if re.match(r'word/(header|footer)\d+\.xml$',n)]
        for name in names:
            if name not in zf.namelist(): continue
            root=ET.fromstring(zf.read(name)); changed=False
            for p in root.findall(f'.//{{{W_NS}}}p'):
                texts=p.findall(f'.//{{{W_NS}}}t'); combined=''.join(t.text or '' for t in texts)
                count=combined.count(old)
                if not count: continue
                found+=count
                if found>expected: break
                replaced=combined.replace(old,new,count)
                if texts:
                    texts[0].text=replaced
                    for t in texts[1:]: t.text=''
                    changed=True
            if changed: replacements[name]=ET.tostring(root,encoding='utf-8',xml_declaration=True)
    if found!=expected: raise ValueError(f'EDIT_MATCH_COUNT_MISMATCH:{found}:{expected}')
    _atomic_zip_replace(path,replacements)
    return {'ok':True,'path':str(path),'replacements':found,'parts_changed':sorted(replacements)}


def _find_browser()->str|None:
    names=['msedge.exe','chrome.exe','chromium.exe']
    for name in names:
        p=shutil.which(name)
        if p: return p
    candidates=[]
    for base in [os.environ.get('PROGRAMFILES'),os.environ.get('PROGRAMFILES(X86)'),os.environ.get('LOCALAPPDATA')]:
        if not base: continue
        candidates += [Path(base)/'Microsoft/Edge/Application/msedge.exe',Path(base)/'Google/Chrome/Application/chrome.exe']
    return str(next((p for p in candidates if p.is_file()),None)) if any(p.is_file() for p in candidates) else None


def _markdown_html(md:str,css:str='')->str:
    out=[]
    for raw in md.splitlines():
        line=html.escape(raw)
        if raw.startswith('# '): out.append(f'<h1>{html.escape(raw[2:])}</h1>')
        elif raw.startswith('## '): out.append(f'<h2>{html.escape(raw[3:])}</h2>')
        elif raw.startswith('### '): out.append(f'<h3>{html.escape(raw[4:])}</h3>')
        elif not raw.strip(): out.append('<br>')
        else: out.append(f'<p>{line}</p>')
    return f'<!doctype html><meta charset="utf-8"><style>body{{font-family:Arial,sans-serif;margin:28mm;color:#111}}pre{{white-space:pre-wrap}}{css}</style>{"".join(out)}'


def create_pdf(path:Path,markdown:str,css:str='')->dict[str,Any]:
    browser=_find_browser()
    if not browser: raise ValueError('PDF_BROWSER_ENGINE_NOT_FOUND')
    path.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ff3-pdf-') as td:
        html_path=Path(td)/'input.html'; html_path.write_text(_markdown_html(markdown,css),encoding='utf-8')
        argv=[browser,'--headless','--disable-gpu','--no-first-run','--no-default-browser-check',f'--print-to-pdf={path}',html_path.as_uri()]
        cp=subprocess.run(argv,capture_output=True,timeout=90)
        if cp.returncode!=0 or not path.is_file(): raise ValueError('PDF_RENDER_FAILED:'+cp.stderr.decode('utf-8',errors='replace')[-500:])
    return {'ok':True,'path':str(path),'bytes':path.stat().st_size,'engine':Path(browser).name}


def register(core:Any,extras:Any)->None:
    original_write=core.OPS['write_file']; original_edit=core.OPS['edit_block']

    def smart_write(args:dict[str,Any])->dict[str,Any]:
        path=core.normalize_path(str(args.get('path') or '')); core.enforce_allowed(path); ext=path.suffix.lower()
        if ext in {'.xlsx','.xlsm'}:
            rows=_parse_rows(args.get('rows',args.get('content'))); create_xlsx(path,rows,str(args.get('sheet_name','Sheet1'))); return {'ok':True,'path':str(path),'kind':'xlsx','rows':len(rows),'columns':max((len(r) for r in rows),default=0),'bytes':path.stat().st_size}
        if ext=='.docx':
            content=args.get('content');
            if not isinstance(content,str): raise core.RPCError('FILE_CONTENT_INVALID')
            create_docx(path,content); return {'ok':True,'path':str(path),'kind':'docx','bytes':path.stat().st_size}
        return original_write(args)

    def smart_edit(args:dict[str,Any])->dict[str,Any]:
        path=core.normalize_path(str(args.get('path') or '')); core.enforce_allowed(path); ext=path.suffix.lower()
        if ext in {'.xlsx','.xlsm'}:
            rng=args.get('range'); values=args.get('values')
            if values is None: values=_parse_rows(args.get('new_text',args.get('content','')))
            try:return _set_xlsx_range(path,str(rng or ''),values,extras)
            except ValueError as exc: raise core.RPCError(str(exc)) from exc
        if ext=='.docx':
            old=args.get('old_text'); new=args.get('new_text'); expected=int(args.get('expected_replacements',1))
            if not isinstance(old,str) or not old or not isinstance(new,str): raise core.RPCError('EDIT_ARGUMENT_INVALID')
            try:return edit_docx(path,old,new,expected)
            except ValueError as exc: raise core.RPCError(str(exc)) from exc
        return original_edit(args)

    def write_pdf(args:dict[str,Any])->dict[str,Any]:
        path=core.normalize_path(str(args.get('path') or '')); core.enforce_allowed(path)
        if path.suffix.lower()!='.pdf': raise core.RPCError('PDF_PATH_REQUIRED')
        action=str(args.get('action','create'))
        if action=='create':
            content=args.get('content'); css=str(args.get('css') or '')
            if not isinstance(content,str): raise core.RPCError('PDF_CONTENT_INVALID')
            try:return create_pdf(path,content,css)
            except ValueError as exc: raise core.RPCError(str(exc)) from exc
        try: import pypdf  # type: ignore
        except Exception as exc: raise core.RPCError('PDF_MUTATION_ENGINE_UNAVAILABLE') from exc
        source=core.normalize_path(str(args.get('source') or path)); core.enforce_allowed(source)
        reader=pypdf.PdfReader(str(source)); writer=pypdf.PdfWriter()
        if action=='delete_pages':
            delete={int(x) for x in args.get('pages',[])}
            for idx,page in enumerate(reader.pages,1):
                if idx not in delete: writer.add_page(page)
        elif action=='insert_pdf':
            insert=core.normalize_path(str(args.get('insert_path') or '')); core.enforce_allowed(insert); at=max(int(args.get('at_page',len(reader.pages)+1)),1); other=pypdf.PdfReader(str(insert))
            for idx,page in enumerate(reader.pages,1):
                if idx==at:
                    for p in other.pages: writer.add_page(p)
                writer.add_page(page)
            if at>len(reader.pages):
                for p in other.pages: writer.add_page(p)
        else: raise core.RPCError('PDF_ACTION_UNSUPPORTED')
        with path.open('wb') as f: writer.write(f)
        return {'ok':True,'path':str(path),'action':action,'pages':len(writer.pages),'bytes':path.stat().st_size}

    core.OPS['write_file']=smart_write
    core.OPS['edit_block']=smart_edit
    core.OPS['write_pdf']=write_pdf
