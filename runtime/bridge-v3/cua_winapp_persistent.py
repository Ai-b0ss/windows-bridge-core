from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Any, Sequence

from cua_sidecar_supervisor import (
    _bind_windows_kill_on_close_job,
    _close_windows_job_handle,
)


@dataclass(frozen=True)
class WinAppSidecarResult:
    stdout: bytes
    stderr: bytes
    returncode: int
    elapsed_ms: int


class WinAppSidecarError(RuntimeError):
    def __init__(
        self,
        code: str,
        *,
        attempted: bool,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.attempted = bool(attempted)
        self.details = dict(details or {})


class WinAppPersistentRunner:
    """Persistent, fail-closed transport for the FF WinApp argv sidecar.

    The sidecar accepts one JSON argv array per line and terminates each command
    with an __FF_END__:<exit-code> marker. Calls are serialized per child so
    command output cannot interleave. A timeout, EOF, malformed sentinel or write
    failure invalidates the child; the next request starts a fresh process.
    This class never replays a request internally, which is important for
    mutations whose outcome may be unknown after a transport failure.
    """

    READY = "__FF_READY__"
    EXIT = "__FF_EXIT__"
    END_PREFIX = "__FF_END__:"

    def __init__(
        self,
        argv: Sequence[str],
        *,
        startup_timeout_seconds: float = 4.0,
        max_line_chars: int = 4_000_000,
    ) -> None:
        if not argv:
            raise ValueError("argv is required")
        if startup_timeout_seconds <= 0:
            raise ValueError("startup_timeout_seconds must be positive")
        self.argv = [str(x) for x in argv]
        self.startup_timeout_seconds = float(startup_timeout_seconds)
        self.max_line_chars = int(max_line_chars)
        self._lock = threading.Lock()
        self._proc: subprocess.Popen[str] | None = None
        self._job_handle: int | None = None
        self._stdout: queue.Queue[str | None] = queue.Queue()
        self._stderr: queue.Queue[str | None] = queue.Queue()
        self.start_count = 0
        self.request_count = 0
        self.crash_count = 0
        self.timeout_count = 0
        self.protocol_error_count = 0

    @property
    def pid(self) -> int | None:
        proc = self._proc
        return int(proc.pid) if proc is not None and proc.poll() is None else None

    def health(self) -> dict[str, Any]:
        return {
            "running": self.pid is not None,
            "pid": self.pid,
            "start_count": self.start_count,
            "request_count": self.request_count,
            "crash_count": self.crash_count,
            "timeout_count": self.timeout_count,
            "protocol_error_count": self.protocol_error_count,
        }

    def execute(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: float,
    ) -> WinAppSidecarResult:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        argv = [str(x) for x in command]
        if not argv:
            raise ValueError("command is required")

        with self._lock:
            started = time.perf_counter()
            attempted = False
            self._ensure_started()
            proc = self._proc
            assert proc is not None and proc.stdin is not None
            self._drain_queue(self._stderr)
            self.request_count += 1
            try:
                proc.stdin.write(json.dumps(argv, separators=(",", ":")) + "\n")
                proc.stdin.flush()
                attempted = True
            except (BrokenPipeError, OSError, ValueError) as exc:
                self.crash_count += 1
                self._invalidate()
                raise WinAppSidecarError(
                    "WINAPP_SIDECAR_WRITE_FAILED",
                    attempted=False,
                    details={"exception": type(exc).__name__},
                ) from exc

            stdout_lines: list[str] = []
            deadline = time.monotonic() + float(timeout_seconds)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    self.timeout_count += 1
                    self._invalidate()
                    raise WinAppSidecarError(
                        "WINAPP_SIDECAR_TIMEOUT",
                        attempted=attempted,
                    )
                try:
                    line = self._stdout.get(timeout=remaining)
                except queue.Empty as exc:
                    self.timeout_count += 1
                    self._invalidate()
                    raise WinAppSidecarError(
                        "WINAPP_SIDECAR_TIMEOUT",
                        attempted=attempted,
                    ) from exc

                if line is None:
                    self.crash_count += 1
                    self._invalidate()
                    raise WinAppSidecarError(
                        "WINAPP_SIDECAR_EXITED",
                        attempted=attempted,
                    )
                if len(line) > self.max_line_chars:
                    self.protocol_error_count += 1
                    self._invalidate()
                    raise WinAppSidecarError(
                        "WINAPP_SIDECAR_LINE_TOO_LARGE",
                        attempted=attempted,
                    )
                if not line.startswith(self.END_PREFIX):
                    stdout_lines.append(line)
                    continue

                raw_code = line[len(self.END_PREFIX):].strip()
                try:
                    exit_code = int(raw_code)
                except ValueError as exc:
                    self.protocol_error_count += 1
                    self._invalidate()
                    raise WinAppSidecarError(
                        "WINAPP_SIDECAR_BAD_SENTINEL",
                        attempted=attempted,
                        details={"sentinel": line[:200]},
                    ) from exc

                stderr_lines = self._collect_stderr(exit_code)
                elapsed_ms = int((time.perf_counter() - started) * 1000)
                return WinAppSidecarResult(
                    stdout=("\n".join(stdout_lines)).encode("utf-8"),
                    stderr=("\n".join(stderr_lines)).encode("utf-8"),
                    returncode=exit_code,
                    elapsed_ms=elapsed_ms,
                )

    def close(self) -> None:
        with self._lock:
            proc = self._proc
            if proc is None:
                return
            try:
                if proc.poll() is None and proc.stdin is not None:
                    proc.stdin.write(self.EXIT + "\n")
                    proc.stdin.flush()
                    proc.wait(timeout=1.0)
            except Exception:
                pass
            finally:
                self._invalidate()

    def _ensure_started(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            return
        self._invalidate()
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        try:
            proc = subprocess.Popen(
                self.argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                shell=False,
                creationflags=flags,
            )
        except OSError as exc:
            raise WinAppSidecarError(
                "WINAPP_SIDECAR_UNAVAILABLE",
                attempted=False,
                details={"exception": type(exc).__name__},
            ) from exc

        stdout_queue: queue.Queue[str | None] = queue.Queue()
        stderr_queue: queue.Queue[str | None] = queue.Queue()
        self._proc = proc
        self._stdout = stdout_queue
        self._stderr = stderr_queue
        try:
            self._job_handle = _bind_windows_kill_on_close_job(proc)
        except Exception as exc:
            self._job_handle = None
            try:
                proc.kill()
            except Exception:
                pass
            self._proc = None
            raise WinAppSidecarError(
                "WINAPP_SIDECAR_CONTAINMENT_FAILED",
                attempted=False,
                details={"exception": type(exc).__name__},
            ) from exc

        assert proc.stdout is not None and proc.stderr is not None
        threading.Thread(
            target=self._read_loop,
            args=(proc.stdout, stdout_queue),
            name="winapp-sidecar-stdout",
            daemon=True,
        ).start()
        threading.Thread(
            target=self._read_loop,
            args=(proc.stderr, stderr_queue),
            name="winapp-sidecar-stderr",
            daemon=True,
        ).start()

        try:
            ready = stdout_queue.get(timeout=self.startup_timeout_seconds)
        except queue.Empty as exc:
            self.timeout_count += 1
            self._invalidate()
            raise WinAppSidecarError(
                "WINAPP_SIDECAR_START_TIMEOUT",
                attempted=False,
            ) from exc
        if ready != self.READY:
            self.protocol_error_count += 1
            self._invalidate()
            raise WinAppSidecarError(
                "WINAPP_SIDECAR_BAD_READY",
                attempted=False,
                details={"ready": ready},
            )
        self.start_count += 1

    @staticmethod
    def _read_loop(stream: Any, output: queue.Queue[str | None]) -> None:
        try:
            for line in stream:
                output.put(line.rstrip("\r\n"))
        finally:
            output.put(None)

    @staticmethod
    def _drain_queue(items: queue.Queue[str | None]) -> list[str]:
        out: list[str] = []
        while True:
            try:
                item = items.get_nowait()
            except queue.Empty:
                return out
            if item is not None:
                out.append(item)

    def _collect_stderr(self, exit_code: int) -> list[str]:
        rows = self._drain_queue(self._stderr)
        if exit_code == 0 or rows:
            return rows
        try:
            item = self._stderr.get(timeout=0.05)
        except queue.Empty:
            return rows
        if item is not None:
            rows.append(item)
        rows.extend(self._drain_queue(self._stderr))
        return rows

    def _invalidate(self) -> None:
        proc = self._proc
        job_handle = self._job_handle
        self._proc = None
        self._job_handle = None

        if job_handle is not None:
            try:
                _close_windows_job_handle(job_handle)
            except Exception:
                pass
        if proc is not None and proc.poll() is None:
            try:
                proc.kill()
            except Exception:
                pass
            try:
                proc.wait(timeout=1.0)
            except Exception:
                pass
