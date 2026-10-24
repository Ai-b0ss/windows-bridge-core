"""Headless V3 base operations in Session 0; no Commander or GUI startup."""
import argparse
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "bridge-v3"))
import ff_win_v3_agent as core
import ff_win_v3_security as security
import ff_win_v3_extras as extras

security.apply(core, extras)
core.PID_PATH = HERE / "background-agent.pid"
core.AUDIT_PATH = HERE / "background-agent-audit.jsonl"
original_ping = core.op_ping
def ping(args):
    result = original_ping(args)
    result["execution_context"] = "background"
    result["interactive_session"] = False
    return result
core.op_ping = ping
core.OPS["ping"] = ping
original_dispatch = core.dispatch
def dispatch(request):
    op = str(request.get("op", ""))
    if request.get("allow_foreground") or op not in core.OPS:
        return {"ok": False, "error_code": "INTERACTIVE_SESSION_REQUIRED", "execution_context": "background"}
    result = original_dispatch(request)
    result["execution_context"] = "background"
    return result
core.dispatch = dispatch
if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--port",type=int,default=39075)
    opts=parser.parse_args()
    raise SystemExit(core.serve("127.0.0.1",opts.port))
