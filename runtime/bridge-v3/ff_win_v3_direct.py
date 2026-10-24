from __future__ import annotations
import argparse
import json
import os
import platform
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

PORT = 39073
ROOT = Path(os.environ.get('LOCALAPPDATA', str(Path.home()))) / 'FF-Windows-Bridge' / 'bridge-v3'
SECRET_PATH = ROOT / 'secret'

def request(op: str, args: dict[str, Any], host: str='127.0.0.1', port: int=PORT) -> dict[str, Any]:
    secret=SECRET_PATH.read_text(encoding='ascii').strip()
    payload={
        'task_id': f'direct-{uuid.uuid4().hex[:12]}',
        'target_device': platform.node(),
        'op': op,
        'args': args,
    }
    raw=json.dumps(payload,ensure_ascii=False,separators=(',',':')).encode('utf-8')
    req=urllib.request.Request(f'http://{host}:{port}/rpc',data=raw,method='POST',headers={'X-FF3-Key':secret,'Content-Type':'application/json; charset=utf-8'})
    try:
        with urllib.request.urlopen(req,timeout=30) as response:
            return json.loads(response.read().decode('utf-8-sig'))
    except urllib.error.HTTPError as exc:
        body=exc.read().decode('utf-8',errors='replace')
        try: return json.loads(body)
        except Exception: raise RuntimeError(f'HTTP_{exc.code}:{body[:1000]}') from exc
def main() -> int:
    parser=argparse.ArgumentParser(description='Direct local client for FF Windows Bridge V3')
    parser.add_argument('op',nargs='?',default='ping')
    parser.add_argument('--args-json',default='{}')
    parser.add_argument('--args-file')
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=PORT)
    ns=parser.parse_args()
    if ns.args_file:
        args=json.loads(Path(ns.args_file).read_text(encoding='utf-8-sig'))
    else:
        args=json.loads(ns.args_json)
    if not isinstance(args,dict):
        raise SystemExit('ARGS_MUST_BE_JSON_OBJECT')
    result=request(ns.op,args,ns.host,ns.port)
    print(json.dumps(result,ensure_ascii=False,separators=(',',':')))
    return 0 if result.get('ok') else 2

if __name__=='__main__':
    raise SystemExit(main())
