import ast, importlib.util, json, os, sys, tempfile, threading, time, unittest, uuid
from pathlib import Path
from unittest.mock import patch
RUNTIME=Path(__file__).resolve().parents[1]/"runtime/bridge-v3"
sys.path.insert(0,str(RUNTIME))
import detached_log_guard as dlg
import ff_win_detached_job as dj

class QuotaReviewTests(unittest.TestCase):
    def test_no_newline_has_fixed_carry_bound(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"x";p.write_bytes(b"x"*8388608)
            pos=0;carry=b"";seen=0
            for _ in range(16):
                lines,pos,carry=dlg.read_bounded_lines(p,pos,carry)
                seen+=sum(map(len,lines))
                self.assertLess(len(carry),dlg.TAILER_READ_CHUNK_BYTES)
            self.assertEqual(seen+len(carry),p.stat().st_size)

    def harness(self,p,lp):
        tree=ast.parse((RUNTIME/"ff_win_v3_agent.py").read_text())
        cl=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=="Session")
        methods=[n for n in cl.body if isinstance(n,ast.FunctionDef) and n.name in ("is_running","_log_tailer","poll")]
        ns={"os":os,"time":time,"now_ms":lambda:int(time.time()*1000),"safe_decode":lambda b:b.decode(errors="replace"),
            "terminate_owned_session":lambda s:s.process.terminate_tree()}
        exec(compile(ast.fix_missing_locations(ast.Module(body=methods,type_ignores=[])),"installed_methods","exec"),ns)
        class H:
            is_running=ns["is_running"];_log_tailer=ns["_log_tailer"];poll=ns["poll"]
            def append_event(self,s,t): self.events.append(t)
        h=H();h.id=p.session_id;h.process=p;h.detached=True;h.pid=p.pid;h.log_path=lp
        h.max_log_bytes=65536;h.quota_exceeded=False;h.closed_at=None;h.events=[]
        return h,ns

    @unittest.skipUnless(os.name=="nt","Windows job integration")
    def test_child_writer_outliving_root_is_stopped(self):
        with tempfile.TemporaryDirectory() as td:
            lp=Path(td)/"x.log"
            child="import sys,time;time.sleep(.6);sys.stdout.buffer.write(b'x'*1048576);sys.stdout.flush();time.sleep(20)"
            parent="import subprocess,sys;subprocess.Popen([sys.executable,'-c',"+repr(child)+"])"
            p=dj.DetachedJobProcess([sys.executable,"-c",parent],cwd=td,env=dict(os.environ),session_id=uuid.uuid4().hex[:16],log_file=lp)
            try:
                h,ns=self.harness(p,lp);t=threading.Thread(target=h._log_tailer,daemon=True);t.start()
                t.join(10)
                self.assertFalse(t.is_alive())
                self.assertTrue(h.quota_exceeded)
                self.assertEqual(p.active_members(),0)
            finally:p.terminate_tree();p.close()

    @unittest.skipUnless(os.name=="nt","Windows job integration")
    def test_failed_termination_does_not_compact_or_claim_success(self):
        with tempfile.TemporaryDirectory() as td:
            lp=Path(td)/"x.log"
            p=dj.DetachedJobProcess([sys.executable,"-c","import time;time.sleep(20)"],cwd=td,env=dict(os.environ),session_id=uuid.uuid4().hex[:16],log_file=lp)
            try:
                lp.write_bytes(b"x"*4194304)
                h,ns=self.harness(p,lp)
                def fail(s):
                    raise OSError("injected failure")
                ns["terminate_owned_session"]=fail
                t=threading.Thread(target=h._log_tailer,daemon=True);t.start()
                time.sleep(.5)
                self.assertEqual(lp.stat().st_size,4194304)
                self.assertTrue(any("termination failed" in e for e in h.events))
                self.assertFalse(any("process terminated" in e for e in h.events))
                p.terminate_tree();t.join(3)
                self.assertFalse(t.is_alive())
            finally:p.terminate_tree();p.close()


    def test_custom_quota_survives_session_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            spec=importlib.util.spec_from_file_location("quota_recovery_agent",RUNTIME/"ff_win_v3_agent.py")
            a=importlib.util.module_from_spec(spec)
            with patch.dict(os.environ,{"FF_BRIDGE_ROOT":td}):
                spec.loader.exec_module(a)
            sid="0123456789abcdef"
            lp=a.V3_ROOT/"state/detached_logs"/(sid+".log")
            lp.parent.mkdir(parents=True,exist_ok=True);lp.write_bytes(b"ok")
            from types import SimpleNamespace
            sess=SimpleNamespace(id=sid,pid=123,log_path=lp,command="fixture",cwd=td,shell="python",
                                 created_at=1,owner_scope=("review","quota"),max_log_bytes=131072)
            with patch.object(a,"process_creation_token",return_value=42):
                a.save_detached_session(sess)
            record=json.loads(a.DETACHED_STATE_PATH.read_text("utf-8"))[sid]
            self.assertEqual(record["max_log_bytes"],131072)
            with patch.object(a,"process_identity_matches",return_value=True), \
                 patch.object(a,"DetachedProcessStub"),patch.object(a,"Session") as ctor:
                a.recover_detached_sessions()
                self.assertEqual(ctor.call_args.kwargs["max_log_bytes"],131072)

if __name__=="__main__":unittest.main()
