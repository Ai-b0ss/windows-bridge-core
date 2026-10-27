"""Real Windows acceptance: completed terminal root must not orphan task-owned children.

Runs with an isolated FF_BRIDGE_ROOT, owns every spawned process and file,
and never touches the user's live Bridge, shell sessions, desktop or models.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

RUNTIME = Path(__file__).resolve().parents[2] / "runtime" / "bridge-v3"
sys.path.insert(0, str(RUNTIME))


def require(condition, code):
    if not condition:
        raise RuntimeError(code)


def wait_file(path):
    deadline = time.monotonic() + 10
    while not path.is_file():
        require(time.monotonic() < deadline, "CHILD_PID_MARKER_NOT_CREATED")
        time.sleep(.02)


def wait_exit(proc):
    deadline = time.monotonic() + 10
    while proc.poll() is None:
        require(time.monotonic() < deadline, "OWNED_DESCENDANT_SURVIVED")
        time.sleep(.02)


def main():
    require(os.name == "nt", "WINDOWS_ONLY")
    with tempfile.TemporaryDirectory(prefix="ff-owned-job-cleanup-") as td:
        os.environ["FF_BRIDGE_ROOT"] = td
        from ff_win_owned_job import OwnedJobProcess
        from ff_win_process_identity import ProcessReference, process_creation_token
        import ff_win_v3_agent as agent

        marker = Path(td) / "child-pid.json"
        code = ("import subprocess,sys,pathlib,json; "
                "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(50)'],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                "pathlib.Path(sys.argv[1]).write_text(json.dumps(p.pid))")
        foreign = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(50)"],
                                   stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        process = None
        child = None
        session = None
        try:
            process = OwnedJobProcess([sys.executable, "-c", code, str(marker)],
                                      cwd=td, env=dict(os.environ))
            wait_file(marker)
            child_pid = json.loads(marker.read_text(encoding="utf-8"))
            child = ProcessReference(child_pid, process_creation_token(child_pid))
            require(process.wait(timeout=10) == 0, "ROOT_NONZERO_EXIT")
            require(process.active_members() >= 1, "MISSING_LIVE_DESCENDANT")
            require(foreign.poll() is None, "FOREIGN_FIXTURE_EXITED_EARLY")
            session = agent.Session(process, command="owned-test-fixture", cwd=td,
                                    shell="python", owner_scope=("ci-agent", "ci-task"))
            with agent.STATE.lock:
                agent.STATE.sessions[session.id] = session
            result = agent.op_cleanup_sessions({"older_than_seconds": 0, "agent_id": "ci-agent", "task_id": "ci-task"})
            require(session.id in result["removed"], "SESSION_NOT_REMOVED")
            require(session.id in result["owned_job_descendants_verified"],
                    "DESCENDANT_CLEANUP_NOT_VERIFIED")
            require(result["cleanup_failed"] == [], "CLEANUP_REPORTED_FAILURE")
            wait_exit(child)
            require(process.poll() == 0, "ACTUAL_ROOT_EXIT_CODE_CHANGED")
            require(foreign.poll() is None, "FOREIGN_PROCESS_KILLED")
            require(process._job is None, "OWNED_JOB_HANDLE_NOT_CLOSED")
            print(json.dumps({"all_passed": True,
                              "completed_root_exit_preserved": True,
                              "owned_descendant_terminated": True,
                              "foreign_process_preserved": True,
                              "job_handle_closed": True,
                              "isolated_root": True}, sort_keys=True))
        finally:
            if session is not None:
                with agent.STATE.lock:
                    agent.STATE.sessions.pop(session.id, None)
            if process is not None:
                process.close()
            if child is not None:
                if child.poll() is None:
                    child.terminate()
                child.close()
            if foreign.poll() is None:
                foreign.kill()
            foreign.wait(timeout=10)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("OWNED_JOB_CLEANUP_SMOKE_FAILED:", type(exc).__name__, file=sys.stderr)
        raise SystemExit(1)
