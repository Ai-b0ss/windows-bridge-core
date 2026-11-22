"""Daily local client: persistent session credentials, no automatic mutation replay."""
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/bridge-v3'))
from ff_hub import HubClient,HubError

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--state-dir',type=Path,required=True);p.add_argument('--session-file',type=Path,required=True)
    sub=p.add_subparsers(dest='action',required=True)
    op=sub.add_parser('open');op.add_argument('--agent',required=True);op.add_argument('--task',required=True)
    sub.add_parser('resume');sub.add_parser('status');sub.add_parser('cancel')
    call=sub.add_parser('call');call.add_argument('--op',required=True);call.add_argument('--args-file',type=Path);call.add_argument('--key')
    receipt=sub.add_parser('receipt');receipt.add_argument('--key',required=True)
    a=p.parse_args();client=HubClient(a.state_dir,timeout=75);saved={}
    if a.session_file.exists():saved=json.loads(a.session_file.read_text(encoding='utf-8'));client.session=saved.get('session')
    try:
        if a.action in {'open','resume'}:
            if a.action=='open' and saved:raise HubError('CLIENT_SESSION_EXISTS','use resume or another session file')
            args={'agent_id':a.agent,'task_id':a.task} if a.action=='open' else {'agent_id':saved['agent'],'task_id':saved['task'],'resume_token':saved['session']['resume_token']}
            session=client.call('session_open',args)
            a.session_file.parent.mkdir(parents=True,exist_ok=True)
            a.session_file.write_text(json.dumps({'agent':args['agent_id'],'task':args['task_id'],'session':session}),encoding='utf-8')
            print(json.dumps({'session_id':session['session_id'],'credentials_saved':True}));return 0
        if not client.session:raise HubError('CLIENT_SESSION_REQUIRED')
        if a.action=='status':result=client.call('session_status')
        elif a.action=='cancel':result=client.call('task_cancel',request_key='cancel-'+client.session['session_id'])
        elif a.action=='receipt':result=client.call('request_status',{'request_key':a.key})
        else:
            args=json.loads(a.args_file.read_text(encoding='utf-8')) if a.args_file else json.load(sys.stdin)
            result=client.call(a.op,args,request_key=a.key)
        print(json.dumps(result,ensure_ascii=False,default=str));return 0
    except HubError as exc:
        print(json.dumps({'error_code':exc.code,'details':exc.details,'automatic_replay':False},ensure_ascii=False));return 1

if __name__=='__main__':raise SystemExit(main())
