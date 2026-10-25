"""Kill the dispatch owner between a real side effect and journal completion.

Child writes ONE owned temporary marker then exits via os._exit(17).
A fresh process must observe outcome_unknown and refuse automatic replay.
Only a temp SQLite DB and owned temp marker are used.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

REPO=Path(__file__).resolve().parents[2]
BRIDGE=REPO/"runtime"/"bridge-v3"
sys.path.insert(0,str(BRIDGE))
from ff_win_request_journal import RequestJournal
from cua_durable_recovery import RecoveryCoordinator


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ff-crash-no-replay-") as td:
        root=Path(td)
        marker=root/"owned-effect-count.txt"
        db=root/"isolated-journal"
        child_source="""
import os,sys
from pathlib import Path
from ff_win_request_journal import RequestJournal
root=Path(sys.argv[1])
marker=Path(sys.argv[2])
journal=RequestJournal(root)
def dispatch():
    with marker.open('ab') as f:
        f.write(b'X')
        f.flush()
        os.fsync(f.fileno())
    # Simulate a sudden power loss / hard process death AFTER effect committed.
    os._exit(17)
journal.execute('crashed-once',{'op':'synthetic-nonidempotent-effect'},dispatch)
"""
        env=dict(os.environ)
        env["PYTHONPATH"]=str(BRIDGE)
        child=subprocess.run([sys.executable,"-c",child_source,str(db),str(marker)],
                             env=env,cwd=str(root),capture_output=True,timeout=12)
        if child.returncode != 17:
            raise AssertionError("DISPATCH_OWNER_DID_NOT_CRASH_AFTER_EFFECT")
        if marker.read_bytes()!=b"X":
            raise AssertionError("EXTERNAL_EFFECT_NOT_COMMITTED_EXACTLY_ONCE")
        reboot=RequestJournal(db)
        actual=reboot.status("crashed-once")
        if actual["state"]!="outcome_unknown":
            raise AssertionError("UNKNOWN_OUTCOME_NOT_PRESERVED_ACROSS_PROCESS_CRASH")
        advice=RecoveryCoordinator(reboot).plan("crashed-once")
        if advice["automatic_retry_allowed"] or advice["journal_state"]!="outcome_unknown":
            raise AssertionError("UNSAFE_RECOVERY_RETRY")
        attempts=[]
        def forbidden():
            attempts.append("executed")
            marker.write_bytes(marker.read_bytes()+b"X")
            return {"ok":True}
        duplicate=reboot.execute("crashed-once",{"op":"synthetic-nonidempotent-effect"},forbidden)
        if duplicate["state"]!="outcome_unknown" or attempts or marker.read_bytes()!=b"X":
            raise AssertionError("DUPLICATE_SIDE_EFFECT_AFTER_LOST_REPLY")
        print(json.dumps({
            "schema":"ff-durable-crash-smoke-v1",
            "status":"PASS",
            "child_hard_exited":True,
            "effect_count":1,
            "outcome_after_restart":"outcome_unknown",
            "replay_prevented":True,
            "read_only_recovery_advice":True,
            "isolated_temp_root":True,
            "owner_device_unmodified":True,
        },sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
