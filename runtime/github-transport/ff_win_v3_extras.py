from __future__ import annotations

import base64
import fnmatch
import ipaddress
import json
import mimetypes
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import zipfile
from collections import Counter, deque
from pathlib import Path
from typing import Any
import xml.etree.ElementTree as ET

HISTORY: deque[dict[str, Any]] = deque(maxlen=500)
USAGE: Counter[str] = Counter()
SEARCHES: dict[str, dict[str, Any]] = {}
SEARCH_LOCK = threading.RLock()
SEARCH_COUNTER = 0

IMAGE_EXTS = {'.png','.jpg','.jpeg','.gif','.webp','.bmp','.ico'}
DOCX_EXTS = {'.docx'}
XLSX_EXTS = {'.xlsx','.xlsm'}
PDF_EXTS = {'.pdf'}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _public_http_url(url: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {'http','https'} or not parsed.hostname:
        raise ValueError('URL_INVALID')
    host = parsed.hostname
    if host.lower() in {'localhost','localhost.localdomain'}:
        raise ValueError('URL_PRIVATE_HOST_BLOCKED')
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == 'https' else 80), type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError(f'URL_DNS_FAILED:{exc}') from exc
    for info in infos:
        addr = ipaddress.ip_address(info[4][0].split('%')[0])
        if not addr.is_global:
            raise ValueError(f'URL_PRIVATE_ADDRESS_BLOCKED:{addr}')


def _zip_text_docx(path: Path) -> tuple[str, dict[str, Any]]:
    ns = {'w':'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
    parts: list[tuple[str,str]] = []
    with zipfile.ZipFile(path, 'r') as zf:
        names = ['word/document.xml'] + sorted(n for n in zf.namelist() if re.match(r'word/(header|footer)\d+\.xml$', n))
        for name in names:
            if name not in zf.namelist():
                continue
            root = ET.fromstring(zf.read(name))
            paras = []
            for p in root.findall('.//w:p', ns):
                text = ''.join((t.text or '') for t in p.findall('.//w:t', ns))
                if text:
                    paras.append(text)
            parts.append((name, '\n'.join(paras)))
    text = '\n\n'.join(f'[{name}]\n{body}' for name, body in parts if body)
    return text, {'parts':[name for name,_ in parts], 'paragraphs':sum(body.count('\n')+1 for _,body in parts if body)}


def _xlsx_shared_strings(zf: zipfile.ZipFile) -> list[str]:
    name = 'xl/sharedStrings.xml'
    if name not in zf.namelist():
        return []
    ns = {'a':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
    root = ET.fromstring(zf.read(name))
    out = []
    for si in root.findall('a:si', ns):
        out.append(''.join((t.text or '') for t in si.findall('.//a:t', ns)))
    return out


def _xlsx_sheet_map(zf: zipfile.ZipFile) -> list[tuple[str,str]]:
    main = 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
    relns = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
    pkgrel = 'http://schemas.openxmlformats.org/package/2006/relationships'
    wb = ET.fromstring(zf.read('xl/workbook.xml'))
    relroot = ET.fromstring(zf.read('xl/_rels/workbook.xml.rels'))
    rels = {r.attrib.get('Id'):r.attrib.get('Target','') for r in relroot.findall(f'{{{pkgrel}}}Relationship')}
    out=[]
    for sheet in wb.findall(f'.//{{{main}}}sheet'):
        name=sheet.attrib.get('name','Sheet')
        rid=sheet.attrib.get(f'{{{relns}}}id')
        target=rels.get(rid,'')
        if target.startswith('/'):
            path=target.lstrip('/')
        else:
            path='xl/' + target.lstrip('/')
        path=str(Path(path)).replace('\\','/')
        out.append((name,path))
    return out


def _col_num(letters: str) -> int:
    n=0
    for ch in letters.upper(): n=n*26+(ord(ch)-64)
    return n


def _cell_parts(ref: str) -> tuple[int,int]:
    m=re.match(r'^([A-Za-z]+)(\d+)$',ref)
    if not m: return (0,0)
    return int(m.group(2)),_col_num(m.group(1))


def _parse_excel_range(value: str | None) -> tuple[str|None,int|None,int|None,int|None,int|None]:
    if not value: return None,None,None,None,None
    raw=value.strip()
    sheet=None
    cells=raw
    if '!' in raw:
        sheet,cells=raw.rsplit('!',1)
        sheet=sheet.strip().strip("'")
    if ':' in cells:
        a,b=cells.split(':',1)
    else:
        a=b=cells
    ar,ac=_cell_parts(a); br,bc=_cell_parts(b)
    if not all((ar,ac,br,bc)): raise ValueError('EXCEL_RANGE_INVALID')
    return sheet,min(ar,br),max(ar,br),min(ac,bc),max(ac,bc)


def _xlsx_read(path: Path, range_value: str|None=None, max_cells: int=10000) -> tuple[str,dict[str,Any]]:
    ns='http://schemas.openxmlformats.org/spreadsheetml/2006/main'
    sheet_sel,r1,r2,c1,c2=_parse_excel_range(range_value)
    rows_out=[]; sheet_meta=[]; cell_count=0
    with zipfile.ZipFile(path,'r') as zf:
        shared=_xlsx_shared_strings(zf)
        for sheet_name,sheet_path in _xlsx_sheet_map(zf):
            if sheet_sel and sheet_name != sheet_sel: continue
            if sheet_path not in zf.namelist(): continue
            root=ET.fromstring(zf.read(sheet_path))
            current=[]; max_row=0; max_col=0; count=0
            for c in root.findall(f'.//{{{ns}}}c'):
                ref=c.attrib.get('r',''); row,col=_cell_parts(ref)
                if not row or not col: continue
                max_row=max(max_row,row); max_col=max(max_col,col)
                if r1 is not None and not (r1<=row<=r2 and c1<=col<=c2): continue
                t=c.attrib.get('t'); v=c.find(f'{{{ns}}}v'); inline=c.find(f'{{{ns}}}is')
                val=''
                if t=='s' and v is not None and v.text:
                    try: val=shared[int(v.text)]
                    except Exception: val=v.text
                elif t=='inlineStr' and inline is not None:
                    val=''.join((x.text or '') for x in inline.findall(f'.//{{{ns}}}t'))
                elif v is not None and v.text is not None: val=v.text
                if val!='': current.append((row,col,ref,val)); count+=1; cell_count+=1
                if cell_count>=max_cells: break
            sheet_meta.append({'name':sheet_name,'max_row':max_row,'max_col':max_col,'nonempty_cells':count})
            if current:
                rows_out.append(f'[{sheet_name}]')
                for row,col,ref,val in current: rows_out.append(f'{ref}\t{val}')
            if cell_count>=max_cells: break
    return '\n'.join(rows_out), {'sheets':sheet_meta,'returned_cells':cell_count,'truncated':cell_count>=max_cells}


def _pdf_read(path: Path) -> tuple[str,dict[str,Any]]:
    try:
        import pypdf  # type: ignore
        reader=pypdf.PdfReader(str(path))
        texts=[]
        for i,page in enumerate(reader.pages): texts.append(f'[page {i+1}]\n{page.extract_text() or ""}')
        return '\n\n'.join(texts), {'pages':len(reader.pages),'engine':'pypdf'}
    except Exception:
        exe=shutil.which('pdftotext.exe') or shutil.which('pdftotext')
        if not exe: raise ValueError('PDF_READER_UNAVAILABLE')
        cp=subprocess.run([exe,'-layout',str(path),'-'],capture_output=True,timeout=60)
        if cp.returncode!=0: raise ValueError('PDF_READ_FAILED')
        text=cp.stdout.decode('utf-8',errors='replace')
        return text, {'engine':'pdftotext'}


def _smart_extract(path: Path, range_value: str|None=None) -> tuple[str,dict[str,Any]]:
    ext=path.suffix.lower()
    if ext in DOCX_EXTS: return _zip_text_docx(path)
    if ext in XLSX_EXTS: return _xlsx_read(path,range_value)
    if ext in PDF_EXTS: return _pdf_read(path)
    raw=path.read_bytes()
    if len(raw)>8*1024*1024: raise ValueError('SEARCH_FILE_TOO_LARGE')
    for enc in ('utf-8-sig','utf-8','utf-16','cp1251','cp866'):
        try: return raw.decode(enc), {'encoding':enc}
        except UnicodeDecodeError: pass
    raise ValueError('TEXT_DECODE_FAILED')


def _next_search_id() -> str:
    global SEARCH_COUNTER
    with SEARCH_LOCK:
        SEARCH_COUNTER += 1
        return f'search-{int(time.time())}-{SEARCH_COUNTER}'


def register(core: Any) -> None:
    original_dispatch = core.dispatch
    original_read_file = core.OPS['read_file']
    original_get_file_info = core.OPS['get_file_info']
    original_list_directory = core.OPS['list_directory']

    def set_config_values(args: dict[str,Any]) -> dict[str,Any]:
        values=args.get('values')
        if not isinstance(values,dict) or not values: raise core.RPCError('CONFIG_VALUES_INVALID')
        previous=dict(core.STATE.config)
        changed={}
        try:
            for key,value in values.items():
                result=core.op_set_config_value({'key':key,'value':value})
                changed[key]=result.get('value')
        except Exception:
            core.STATE.config=previous; core.save_config(previous); raise
        return {'ok':True,'changed':changed}

    def recursive_list(args: dict[str,Any]) -> dict[str,Any]:
        depth=int(args.get('depth',1)); max_items=min(max(int(args.get('max_items',1000)),1),10000)
        if depth<=1: return original_list_directory(args)
        if depth>20: raise core.RPCError('LIST_DEPTH_TOO_LARGE')
        root=core.normalize_path(str(args.get('path') or '')); core.enforce_allowed(root)
        if not root.is_dir(): raise core.RPCError('DIRECTORY_NOT_FOUND')
        items=[]
        def walk(path:Path,level:int)->None:
            if len(items)>=max_items or level>depth: return
            try: children=sorted(path.iterdir(),key=lambda p:(not p.is_dir(),p.name.lower()))
            except OSError: return
            for child in children:
                if len(items)>=max_items: return
                try:
                    st=child.stat(); rel=child.relative_to(root).as_posix()
                    items.append({'name':child.name,'relative_path':rel,'path':str(child),'depth':level,'is_dir':child.is_dir(),'bytes':None if child.is_dir() else st.st_size,'mtime':int(st.st_mtime*1000)})
                    if child.is_dir() and not child.is_symlink(): walk(child,level+1)
                except OSError: pass
        walk(root,1)
        return {'path':str(root),'depth':depth,'items':items,'truncated':len(items)>=max_items}

    def copy_path(args: dict[str,Any])->dict[str,Any]:
        src=core.normalize_path(str(args.get('source') or '')); dst=core.normalize_path(str(args.get('destination') or ''))
        core.enforce_allowed(src); core.enforce_allowed(dst)
        if not src.exists(): raise core.RPCError('SOURCE_NOT_FOUND')
        if src.is_dir(): shutil.copytree(src,dst,dirs_exist_ok=bool(args.get('merge',False)))
        else: dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(src,dst)
        return {'ok':True,'source':str(src),'destination':str(dst)}

    def delete_path(args: dict[str,Any])->dict[str,Any]:
        path=core.normalize_path(str(args.get('path') or '')); core.enforce_allowed(path)
        if not path.exists(): return {'ok':True,'path':str(path),'existed':False}
        if path.is_dir():
            if not bool(args.get('recursive',False)) and any(path.iterdir()): raise core.RPCError('DIRECTORY_NOT_EMPTY')
            if bool(args.get('recursive',False)): shutil.rmtree(path)
            else: path.rmdir()
        else: path.unlink()
        return {'ok':True,'path':str(path),'existed':True}

    def smart_read_file(args: dict[str,Any])->dict[str,Any]:
        if bool(args.get('is_url',False)):
            url=args.get('path') or args.get('url')
            try: _public_http_url(str(url))
            except ValueError as exc: raise core.RPCError(str(exc)) from exc
            return original_read_file(args)
        path=core.normalize_path(str(args.get('path') or '')); core.enforce_allowed(path)
        if not path.is_file(): raise core.RPCError('FILE_NOT_FOUND')
        ext=path.suffix.lower()
        if ext in IMAGE_EXTS:
            raw=path.read_bytes()
            if len(raw)>10*1024*1024: raise core.RPCError('IMAGE_TOO_LARGE')
            return {'path':str(path),'kind':'image','mime':mimetypes.guess_type(path.name)[0] or 'application/octet-stream','bytes':len(raw),'base64':base64.b64encode(raw).decode('ascii')}
        if ext in DOCX_EXTS|XLSX_EXTS|PDF_EXTS:
            try: text,meta=_smart_extract(path,args.get('range'))
            except ValueError as exc: raise core.RPCError(str(exc)) from exc
            lines=text.splitlines(keepends=True); off=int(args.get('offset',0)); length=min(int(args.get('length',core.STATE.config.get('fileReadLineLimit',2000))),int(core.STATE.config.get('fileReadLineLimit',2000)))
            start=max(0,len(lines)+off) if off<0 else min(max(off,0),len(lines))
            return {'path':str(path),'kind':ext.lstrip('.'),'offset':start,'length':len(lines[start:start+length]),'total_lines':len(lines),'content':' '.join([]) if False else ''.join(lines[start:start+length]),'bytes':path.stat().st_size,'metadata':meta}
        if path.stat().st_size > core.MAX_INLINE_BYTES:
            digest=core.hashlib.sha256()
            with path.open('rb') as handle:
                for chunk in iter(lambda: handle.read(1024*1024), b''):
                    digest.update(chunk)
            meta={'path':str(path),'bytes':path.stat().st_size,'sha256':digest.hexdigest(),'kind':'local_file_reference'}
            return {'path':str(path),'kind':'large-file','bytes':path.stat().st_size,'artifact':meta}
        return original_read_file(args)

    def smart_info(args:dict[str,Any])->dict[str,Any]:
        info=original_get_file_info(args)
        path=core.normalize_path(str(args.get('path') or ''))
        if path.is_file() and path.suffix.lower() in DOCX_EXTS|XLSX_EXTS|PDF_EXTS:
            try:
                _,meta=_smart_extract(path,args.get('range')); info['document']=meta
            except Exception as exc: info['document_error']=str(exc)[:500]
        return info

    def search_worker(search_id:str, spec:dict[str,Any])->None:
        with SEARCH_LOCK: entry=SEARCHES[search_id]
        try:
            root=core.normalize_path(str(spec.get('path') or '')); core.enforce_allowed(root)
            if not root.exists(): raise core.RPCError('PATH_NOT_FOUND')
            pattern=str(spec.get('pattern') or '')
            if not pattern: raise core.RPCError('SEARCH_QUERY_INVALID')
            search_type=str(spec.get('search_type','files')).lower(); ignore=bool(spec.get('ignore_case',True)); literal=bool(spec.get('literal',True)); file_pattern=str(spec.get('file_pattern') or '*'); include_hidden=bool(spec.get('include_hidden',False)); max_results=min(max(int(spec.get('max_results',1000)),1),10000); context=min(max(int(spec.get('context_lines',0)),0),20)
            flags=re.I if ignore else 0
            regex=None if literal else re.compile(pattern,flags)
            needle=pattern.lower() if ignore and literal else pattern
            def matcher(text:str)->bool:
                if regex: return bool(regex.search(text))
                hay=text.lower() if ignore else text
                return needle in hay
            candidates=[]
            if root.is_file(): candidates=[root]
            else:
                for base,dirs,files in os.walk(root):
                    dirs[:]=[d for d in dirs if include_hidden or not d.startswith('.')]
                    for name in files:
                        if include_hidden or not name.startswith('.'): candidates.append(Path(base)/name)
                    if search_type in {'files','name'}:
                        for name in dirs:
                            if matcher(name):
                                with SEARCH_LOCK: entry['results'].append({'path':str(Path(base)/name),'type':'directory'})
                                if len(entry['results'])>=max_results: break
                    if len(entry['results'])>=max_results: break
            for path in candidates:
                with SEARCH_LOCK:
                    if entry['stop']: break
                if not fnmatch.fnmatch(path.name,file_pattern): continue
                if search_type in {'files','name'}:
                    if matcher(path.name):
                        with SEARCH_LOCK: entry['results'].append({'path':str(path),'type':'file'})
                else:
                    try: text,_=_smart_extract(path)
                    except Exception: continue
                    lines=text.splitlines()
                    for i,line in enumerate(lines):
                        if matcher(line):
                            item={'path':str(path),'line':i+1,'text':line[:2000]}
                            if context:
                                item['context_before']=lines[max(0,i-context):i]
                                item['context_after']=lines[i+1:i+1+context]
                            with SEARCH_LOCK: entry['results'].append(item)
                            if len(entry['results'])>=max_results: break
                with SEARCH_LOCK:
                    if len(entry['results'])>=max_results: break
            with SEARCH_LOCK:
                entry['status']='stopped' if entry['stop'] else 'completed'; entry['ended_at']=_now_ms(); entry['truncated']=len(entry['results'])>=max_results
        except Exception as exc:
            with SEARCH_LOCK: entry['status']='error'; entry['error']=f'{type(exc).__name__}: {exc}'[:1000]; entry['ended_at']=_now_ms()

    def start_search(args:dict[str,Any])->dict[str,Any]:
        sid=_next_search_id(); entry={'search_id':sid,'status':'running','started_at':_now_ms(),'ended_at':None,'results':[],'stop':False,'truncated':False,'spec':core.redact(args)}
        with SEARCH_LOCK: SEARCHES[sid]=entry
        threading.Thread(target=search_worker,args=(sid,dict(args)),daemon=True).start()
        initial_wait=min(max(int(args.get('initial_wait_ms',100)),0),3000)
        if initial_wait: time.sleep(initial_wait/1000)
        with SEARCH_LOCK: return {'search_id':sid,'status':entry['status'],'available':len(entry['results'])}

    def get_more_search_results(args:dict[str,Any])->dict[str,Any]:
        sid=str(args.get('search_id') or ''); offset=max(int(args.get('offset',0)),0); length=min(max(int(args.get('length',100)),1),1000)
        with SEARCH_LOCK:
            e=SEARCHES.get(sid)
            if not e: raise core.RPCError('SEARCH_NOT_FOUND')
            results=list(e['results'][offset:offset+length])
            return {'search_id':sid,'status':e['status'],'offset':offset,'length':len(results),'available':len(e['results']),'next_offset':offset+len(results),'truncated':e.get('truncated',False),'error':e.get('error'),'results':results}

    def stop_search(args:dict[str,Any])->dict[str,Any]:
        sid=str(args.get('search_id') or '')
        with SEARCH_LOCK:
            e=SEARCHES.get(sid)
            if not e: raise core.RPCError('SEARCH_NOT_FOUND')
            e['stop']=True
            return {'ok':True,'search_id':sid,'status':e['status']}

    def list_searches(args:dict[str,Any])->dict[str,Any]:
        with SEARCH_LOCK:
            items=[{'search_id':sid,'status':e['status'],'started_at':e['started_at'],'ended_at':e.get('ended_at'),'available':len(e['results']),'truncated':e.get('truncated',False),'spec':e.get('spec')} for sid,e in SEARCHES.items()]
        return {'searches':items[-200:]}

    def get_usage_stats(args:dict[str,Any])->dict[str,Any]:
        return {'total_calls':sum(USAGE.values()),'by_operation':dict(sorted(USAGE.items())),'history_size':len(HISTORY),'search_count':len(SEARCHES),'session_count':len(core.STATE.sessions)}

    def get_recent_tool_calls(args:dict[str,Any])->dict[str,Any]:
        limit=min(max(int(args.get('limit',50)),1),500); op=args.get('op')
        records=[r for r in HISTORY if not op or r.get('op')==op]
        items=core.redact(records[-limit:])
        return {'records':items,'items':items}

    core.OPS.update({
        'set_config_values':set_config_values,
        'copy_path':copy_path,
        'delete_path':delete_path,
        'start_search':start_search,
        'get_more_search_results':get_more_search_results,
        'stop_search':stop_search,
        'list_searches':list_searches,
        'get_usage_stats':get_usage_stats,
        'get_recent_tool_calls':get_recent_tool_calls,
    })
    core.OPS['list_directory']=recursive_list
    core.OPS['read_file']=smart_read_file
    core.OPS['get_file_info']=smart_info

    def dispatch_with_history(request:dict[str,Any])->dict[str,Any]:
        started=_now_ms(); op=str(request.get('op') or '')
        try:
            result=original_dispatch(request)
        except Exception as exc:
            USAGE[op]+=1
            code=getattr(exc,'code',type(exc).__name__)
            error_preview=json.dumps(core.redact({'error_code':code,'message':str(exc)[:1000]}),ensure_ascii=False,separators=(',',':'))
            HISTORY.append({'ts':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'op':op,'duration_ms':_now_ms()-started,'ok':False,'args':core.redact(request.get('args',{})),'result_preview':error_preview})
            raise
        USAGE[op]+=1
        safe_result=core.redact(result)
        preview=json.dumps(safe_result,ensure_ascii=False,separators=(',',':'))
        if len(preview)>8000: preview=preview[:8000]+'...<truncated>'
        HISTORY.append({'ts':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'op':op,'duration_ms':_now_ms()-started,'ok':bool(result.get('ok')),'args':core.redact(request.get('args',{})),'result_preview':preview})
        return result

    core.dispatch=dispatch_with_history