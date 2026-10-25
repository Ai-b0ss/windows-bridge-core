"""Windows Bridge detached process identity recovery: isolated self PID only.

No user process is attached to, killed, or started. Only the test Python PID
is used, with its own temporary empty log and metadata.
"""
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

REPO=Path(__file__).resolve().parents[2]


def main():
    if os.name!="nt":
        print("Windows only",file=sys.stderr)
        return 2
    with TemporaryDirectory(prefix="ff-process-identity-smoke-") as td:
        os.environ["FF_BRIDGE_ROOT"]=td
        sys.path.insert(0,str(REPO/"runtime/bridge-v3"))
        import ff_win_v3_agent as agent
        from ff_win_process_identity import (
            process_creation_token,process_identity_matches,
        )
        pid=os.getpid()
        token=process_creation_token(pid)
        assert type(token) is int and token>0
        assert process_identity_matches(pid,token)
        assert not process_identity_matches(pid,token+1)
        sid="0123456789abcdef"
        log=agent.V3_ROOT/"state"/"detached_logs"/(sid+".log")
        log.parent.mkdir(parents=True,exist_ok=True)
        log.write_text("OWNED_TEST_LOG\n",encoding="utf-8")
        record={
            "session_id":sid,"pid":pid,"pid_creation_token":token,
            "command":"owned-pid-identity-check","cwd":td,
            "shell":"powershell.exe","log_path":str(log),
            "created_at":agent.now_ms(),
        }
        file=agent.DETACHED_STATE_PATH
        from types import SimpleNamespace
        owned=SimpleNamespace(
            id=sid,pid=pid,log_path=log,
            command=record["command"],cwd=record["cwd"],
            shell=record["shell"],created_at=record["created_at"],
            owner_scope=("ci-identity-agent", "ci-identity-task"),
        )
        agent.save_detached_session(owned)
        saved=json.loads(file.read_text(encoding="utf-8"))
        assert saved[sid]["pid_creation_token"]==token
        assert saved[sid]["owner_scope"]==["ci-identity-agent", "ci-identity-task"]
        recovered=agent.recover_detached_sessions()
        assert sid in recovered
        assert recovered[sid].owner_scope==("ci-identity-agent", "ci-identity-task")
        assert recovered[sid].is_running()
        assert recovered[sid].poll() is None
        # A retained kernel reference prevents later PID lookups selecting a
        # different process. Lost reference state must never fabricate exit 0.
        from unittest.mock import patch
        with patch.object(recovered[sid].process._reference,"poll",side_effect=OSError("lost reference")):
            assert not recovered[sid].is_running()
            assert recovered[sid].poll()==-1
            assert recovered[sid].snapshot()["exit_code"] is None
            assert recovered[sid].snapshot()["exit_code_known"] is False
        recovered[sid].process._reference.close()
        mismatched={**record,"pid_creation_token":token+1}
        file.write_text(json.dumps({sid:mismatched}),encoding="utf-8")
        assert sid not in agent.recover_detached_sessions()
        legacy={k:v for k,v in record.items() if k!="pid_creation_token"}
        file.write_text(json.dumps({sid:legacy}),encoding="utf-8")
        assert sid not in agent.recover_detached_sessions()
        poison={**record,"log_path":str(agent.V3_ROOT/"secret")}
        file.write_text(json.dumps({sid:poison}),encoding="utf-8")
        assert sid not in agent.recover_detached_sessions()
        assert process_identity_matches(pid,token)
        print(json.dumps({
            "schema":"ff-detached-process-identity-smoke-v1",
            "all_passed":True,"self_process_creation_verified":True,
            "same_pid_wrong_start_denied":True,"legacy_pid_only_denied":True,
            "untrusted_log_path_denied":True,
            "owner_process_untouched":True,
        },sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
