"""Isolated legacy->candidate migration guard. Never drains installed production.

Requires --legacy-script and a new --output. Probes private-session preservation,
which is distinct from terminal-session forwarding in seamless_handover.py.
"""
import argparse,json,os,subprocess,sys,time
from pathlib import Path
from seamless_handover import free_port,rpc,wait_ready
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'runtime/bridge-v3'))
from ff_win_process_identity import process_creation_token,process_identity_matches

def main():
    p=argparse.ArgumentParser();p.add_argument('--legacy-script',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(exist_ok=False,parents=True)
    root=out/'state';root.mkdir();public,ac,bc=free_port(),free_port(),free_port();processes=[];owned=[];result={}
    def launch(script,check,standby=False):
        cmd=[sys.executable,str(script),'serve','--host','127.0.0.1','--port',str(public),'--also-listen',str(check)]
        if standby:cmd.append('--standby')
        proc=subprocess.Popen(cmd,env={**os.environ,'FF_BRIDGE_ROOT':str(root),'FF_DRAIN_LINGER_SECONDS':'2','PYTHONDONTWRITEBYTECODE':'1'},stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,creationflags=subprocess.CREATE_NO_WINDOW);processes.append(proc);return proc
    try:
        old=launch(a.legacy_script,ac);secretfile=root/'bridge-v3/secret';wait_ready(old,ac,secretfile,'legacy');secret=secretfile.read_text().strip()
        s=rpc(public,secret,'computer_use',{'command':'hidden_start'})['result'];token=process_creation_token(s['worker_pid']);owned.append((s['worker_pid'],token))
        new=launch(Path(__file__).resolve().parents[2]/'runtime/bridge-v3/ff_win_v3_main.py',bc,True);wait_ready(new,bc,secretfile,'candidate')
        drain=rpc(public,secret,'drain',{'standby_port':bc});assert drain['ok'];time.sleep(.8)
        reply=rpc(public,secret,'computer_use',{'command':'hidden_request','session_id':s['session_id'],'request':{'command':'health'}})
        deadline=time.monotonic()+8
        while old.poll() is None and time.monotonic()<deadline:time.sleep(.1)
        preserved=bool(reply.get('ok')) and old.poll() is None and process_identity_matches(*owned[0])
        result={'probe_completed':True,'deployment_safe':preserved,'hidden_request_error':reply.get('error_code'),'old_instance_exited_with_private_session':old.poll() is not None,'old_worker_alive':process_identity_matches(*owned[0]),'old_pid':old.pid,'new_pid':new.pid,'worker_pid':s['worker_pid'],'production_touched':False,
            'blocker':None if preserved else 'Legacy socket handover only forwards/counts terminal sessions; active private Desktop session is not preserved. Existing production hidden work cannot be certified safe to migrate.'}
    finally:
        for proc in processes:
            if proc.poll() is None:proc.terminate();proc.wait(timeout=8)
        time.sleep(.3)
        result['owned_workers_closed']=not any(process_identity_matches(*x) for x in owned)
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result))
    return 0 if result.get('probe_completed') and result['owned_workers_closed'] else 1

if __name__=='__main__':raise SystemExit(main())
