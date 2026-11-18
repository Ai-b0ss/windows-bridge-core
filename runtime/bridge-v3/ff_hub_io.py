"""Cooperative files and supervised, restart-surviving terminal jobs for the Hub.

These operations run as the Windows owner, not in a sandbox. File locks only
coordinate participating Hub clients. Shells/interpreters can access anything
the owner can; a cwd grant does not confine their side effects.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ff_hub_store import HubError

MAX_FILE_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def absolute_path(value) -> Path:
    if not isinstance(value, str) or not value or not Path(value).is_absolute():
        raise HubError("ABSOLUTE_PATH_REQUIRED", execution_started=False)
    return Path(os.path.normcase(os.path.realpath(value)))


class HubIO:
    def __init__(self, hub):
        self.hub = hub
        self.root = hub.state_dir / "terminal"
        self.launch_lock = threading.Lock()

    def files(self, session: dict, args: dict) -> dict:
        command = args.get("command")
        if command not in {"read", "stat", "write"}:
            raise HubError("FILE_COMMAND_INVALID", commands=["read", "stat", "write"])
        path = absolute_path(args.get("path"))
        risk = "project_write" if command == "write" else "read_diagnose"
        self.hub._permit(session, risk, {"path": str(path)}, action="files." + command)
        self.hub.store.claim(session, "file", str(path))
        try:
            if path.exists() and (not path.is_file() or path.stat().st_size > MAX_FILE_BYTES):
                raise HubError("FILE_SIZE_OR_TYPE_UNSUPPORTED", max_bytes=MAX_FILE_BYTES, execution_started=False)
            data = None
            if path.exists():
                with path.open("rb") as stream:
                    data = stream.read(MAX_FILE_BYTES + 1)
            if data is not None and len(data) > MAX_FILE_BYTES:
                raise HubError("FILE_SIZE_OR_TYPE_UNSUPPORTED", max_bytes=MAX_FILE_BYTES, execution_started=False)
            digest = hashlib.sha256(data).hexdigest() if data is not None else None
            if command == "write":
                text = args.get("text")
                if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_FILE_BYTES:
                    raise HubError("FILE_TEXT_INVALID", max_bytes=MAX_FILE_BYTES, execution_started=False)
                if "expected_sha256" not in args or args["expected_sha256"] != digest:
                    raise HubError("FILE_PRECONDITION_FAILED", actual_sha256=digest, execution_started=False,
                                   instruction="read current bytes; null expected_sha256 means create only")
                new_data = text.encode("utf-8")
                temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
                try:
                    with temporary.open("xb") as stream:
                        stream.write(new_data)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, path)
                finally:
                    temporary.unlink(missing_ok=True)
                data, digest = new_data, hashlib.sha256(new_data).hexdigest()
            result = {"path": str(path), "exists": data is not None,
                      "bytes": len(data) if data is not None else 0, "sha256": digest}
            if command == "read":
                result["text"] = data.decode("utf-8") if data is not None else None
            self.hub.store.audit("files." + command, **session, path=str(path), sha256=digest)
            return result
        except (OSError, UnicodeError) as exc:
            raise HubError("FILE_IO_FAILED", cause=type(exc).__name__, retry_safe=False) from None

    def terminal(self, session: dict, args: dict, request_key: str | None = None) -> dict:
        command = args.get("command")
        if command == "list":
            return {"terminals": [self._status(row["key"]) for row in
                                  self.hub.store.resources(session_id=session["session_id"], kind="terminal")]}
        if command == "start":
            argv = args.get("argv")
            if (not isinstance(argv, list) or not 1 <= len(argv) <= 128
                    or not all(isinstance(item, str) and "\0" not in item for item in argv)):
                raise HubError("TERMINAL_ARGV_INVALID", execution_started=False)
            cwd = absolute_path(args.get("cwd"))
            executable = shutil.which(argv[0])
            if not executable or not cwd.is_dir():
                raise HubError("TERMINAL_EXECUTABLE_OR_CWD_MISSING", execution_started=False)
            executable = str(absolute_path(executable))
            timeout = args.get("timeout_seconds", 60)
            if type(timeout) not in (int, float) or not 0.1 <= timeout <= 300:
                raise HubError("TERMINAL_TIMEOUT_INVALID", execution_started=False)
            self.hub._permit(session, "terminal_execute", {"path": str(cwd), "app": executable}, action="terminal.start")
            held = self.hub.store.resources(kind="terminal")
            live = []
            for row in held:
                try:
                    state = self._status(row["key"])["state"]
                except HubError:
                    state = "unknown"
                if state in {"prepared", "running", "unknown"}:
                    live.append(row)
            if len(live) >= 24 or sum(row["session_id"] == session["session_id"] for row in live) >= 8:
                raise HubError("TERMINAL_QUOTA_EXCEEDED", execution_started=False, max_per_session=8, max_total=24)
            # Known before launch, and present in resource_list even if the reply is lost.
            token = hashlib.sha256((session["agent_id"] + "\x1f" + session["task_id"] + "\x1f" + str(request_key)).encode()).hexdigest()[:16]
            terminal_id = "term-" + token
            directory = self.root / terminal_id
            directory.mkdir(parents=True, exist_ok=True)
            spec = {"terminal_id": terminal_id, "job_token": token, "argv": [executable, *argv[1:]],
                    "cwd": str(cwd), "timeout_seconds": timeout, "output_limit": MAX_OUTPUT_BYTES}
            resource = self.hub.store.claim(session, "terminal", terminal_id,
                                            meta={"cwd": str(cwd), "app": executable, "timeout_seconds": timeout})
            atomic_json(directory / "spec.json", spec)
            atomic_json(directory / "status.json", {"terminal_id": terminal_id, "state": "prepared",
                                                    "automatic_replay": False})
            try:
                worker = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--worker", str(directory)],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                          close_fds=True, creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
                                          start_new_session=os.name != "nt")
            except OSError as exc:
                atomic_json(directory / "status.json", {"terminal_id": terminal_id, "state": "launch_failed",
                                                        "cause": type(exc).__name__})
                raise HubError("TERMINAL_LAUNCH_FAILED", execution_started=False) from None
            threading.Thread(target=worker.wait, daemon=True).start()
            self.hub.store.update_resource_meta(resource["resource_id"],
                                               {**resource["meta"], "supervisor_pid": worker.pid})
            self.hub.store.audit("terminal.start", **session, terminal_id=terminal_id, supervisor_pid=worker.pid,
                                 app=executable, cwd=str(cwd))
            return {"terminal_id": terminal_id, "state": "starting", "supervisor_pid": worker.pid,
                    "recovery": "terminal status with this exact terminal_id; never auto-relaunch"}
        if command not in {"status", "cancel"}:
            raise HubError("TERMINAL_COMMAND_INVALID", commands=["start", "status", "list", "cancel"])
        terminal_id = args.get("terminal_id")
        self.hub.store.require_owned(session, "terminal", terminal_id)
        if command == "cancel":
            # Only the already-owned supervisor interprets this signal. No PID guessing.
            (self.root / terminal_id / "cancel.flag").touch()
            self._reconcile_cancel(terminal_id)
        return self._status(terminal_id)

    def _status(self, terminal_id: str) -> dict:
        directory = self.root / terminal_id
        try:
            result = json.loads((directory / "status.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise HubError("TERMINAL_STATE_UNAVAILABLE", terminal_id=terminal_id, automatic_replay=False) from None
        if os.name == "nt" and result.get("state") == "running":
            from ff_win_process_identity import process_identity_matches
            if not process_identity_matches(result.get("supervisor_pid"), result.get("supervisor_create_time")):
                result.update(state="unknown", reason="TERMINAL_SUPERVISOR_LOST", automatic_replay=False)
        log = directory / "output.log"
        if log.exists():
            with log.open("rb") as stream:
                stream.seek(max(0, log.stat().st_size - 65536))
                result["output"] = stream.read(65536).decode("utf-8", errors="replace")
            result["output_tail_only"] = log.stat().st_size > 65536
        return result

    def _reconcile_cancel(self, terminal_id: str) -> None:
        status = self._status(terminal_id)
        if os.name == "nt" and status.get("reason") == "TERMINAL_SUPERVISOR_LOST":
            from ff_win_detached_job import terminate_detached_job_by_name
            token = terminal_id.removeprefix("term-")
            try:
                proof = terminate_detached_job_by_name(token)
            except OSError:
                raise HubError("TERMINAL_CLEANUP_UNCONFIRMED", terminal_id=terminal_id) from None
            # A named job persists while a member exists. Its absence confirms
            # that no member of this exact job remains, not a guess by PID/name.
            atomic_json(self.root / terminal_id / "status.json",
                        {**status, "state": "cancelled", "cleanup_verified": True,
                         "termination_evidence": proof or "exact_named_job_absent", "finished_at": time.time()})

    def cleanup(self, held: list[dict]) -> list[dict]:
        terminals = [row for row in held if row["kind"] == "terminal"]
        for row in terminals:
            (self.root / row["key"] / "cancel.flag").touch()
            try:
                self._reconcile_cancel(row["key"])
            except HubError:
                pass
        deadline = time.monotonic() + 12
        errors = []
        for row in terminals:
            while True:
                try:
                    status = self._status(row["key"])
                except HubError:
                    status = {"state": "unknown"}
                if status["state"] in {"completed", "cancelled", "timed_out", "output_limit", "launch_failed", "failed"}:
                    if status.get("cleanup_verified") is not False:
                        break
                if time.monotonic() >= deadline:
                    errors.append({"kind": "terminal", "terminal_id": row["key"], "code": "TERMINAL_CLEANUP_UNCONFIRMED"})
                    break
                time.sleep(0.05)
        return errors


def run_worker(directory: Path) -> int:
    spec = json.loads((directory / "spec.json").read_text(encoding="utf-8"))
    log = directory / "output.log"
    result = {"terminal_id": spec["terminal_id"], "state": "running", "supervisor_pid": os.getpid(),
              "started_at": time.time(), "automatic_replay": False}
    from ff_win_process_identity import process_creation_token
    result["supervisor_create_time"] = process_creation_token(os.getpid())
    process = None
    try:
        if os.name == "nt":
            from ff_win_detached_job import DetachedJobProcess
            process = DetachedJobProcess(spec["argv"], cwd=spec["cwd"], env=dict(os.environ),
                                         session_id=spec["job_token"], log_file=log)
        else:
            with log.open("ab", buffering=0) as stream:
                process = subprocess.Popen(spec["argv"], cwd=spec["cwd"], stdin=subprocess.DEVNULL,
                                           stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        result["pid"] = process.pid
        result["create_time"] = process_creation_token(process.pid)
        atomic_json(directory / "status.json", result)
        deadline = time.monotonic() + spec["timeout_seconds"]
        state = "completed"
        while True:
            if (directory / "cancel.flag").exists():
                state = "cancelled"
                break
            if log.exists() and log.stat().st_size > spec["output_limit"]:
                state = "output_limit"
                break
            if time.monotonic() >= deadline:
                state = "timed_out"
                break
            if process.poll() is not None:
                break
            time.sleep(0.025)
        result["exit_code"] = process.poll()
        # Close descendants even if the root exited first. Named Job identity is
        # independent of PID reuse and remains alive while any member exists.
        if os.name == "nt":
            process.terminate_tree(timeout=5)
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        if log.exists() and log.stat().st_size > spec["output_limit"]:
            with log.open("r+b") as stream:
                stream.truncate(spec["output_limit"])
            result["output_truncated"] = True
        result.update(state=state, cleanup_verified=True, finished_at=time.time())
    except BaseException as exc:
        cleaned = process is None
        if process is not None:
            try:
                if os.name == "nt":
                    process.terminate_tree(timeout=5)
                else:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                cleaned = True
            except Exception:
                cleaned = False
        result.update(state="failed", cause=type(exc).__name__, cleanup_verified=cleaned, finished_at=time.time())
    finally:
        if os.name == "nt" and process is not None:
            process.close()
        atomic_json(directory / "status.json", result)
    return 0 if result.get("cleanup_verified") else 1


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--worker":
    raise SystemExit(run_worker(Path(sys.argv[2])))
