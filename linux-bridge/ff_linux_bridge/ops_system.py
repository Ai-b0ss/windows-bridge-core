"""System, shell, code execution, and process operations for FF Linux Bridge v3."""

from __future__ import annotations

import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from . import __version__


class SystemOpError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _truncate_text(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars] + f"\n...[truncated {len(text) - max_chars} chars]", True


def _run_subprocess(
    cmd: list[str] | str,
    *,
    shell: bool = False,
    cwd: str | None = None,
    timeout_s: float = 60.0,
    env_extra: dict[str, str] | None = None,
    max_output_chars: int = 120_000,
) -> dict[str, Any]:
    timeout_s = max(1.0, min(float(timeout_s), 600.0))
    env = os.environ.copy()
    if env_extra:
        for k, v in env_extra.items():
            env[str(k)] = str(v)

    started = time.monotonic()
    proc = subprocess.Popen(
        cmd,
        shell=shell,
        cwd=cwd or None,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        start_new_session=True,
    )
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            stdout, stderr = proc.communicate(timeout=3.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, stderr = proc.communicate()

    elapsed_ms = int((time.monotonic() - started) * 1000)
    out_text, out_trunc = _truncate_text(stdout or "", max_output_chars)
    err_text, err_trunc = _truncate_text(stderr or "", max_output_chars)
    return {
        "exit_code": proc.returncode,
        "timed_out": timed_out,
        "duration_ms": elapsed_ms,
        "stdout": out_text,
        "stderr": err_text,
        "stdout_truncated": out_trunc,
        "stderr_truncated": err_trunc,
    }


def op_ping(args: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    return {
        "pong": True,
        "bridge": "ff-linux-v3",
        "version": __version__,
        "host": ctx["device_name"],
        "message": args.get("message", "ok"),
        "timestamp": int(time.time()),
    }


def op_device_status(args: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    load1, load5, load15 = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)
    disk = shutil.disk_usage(ctx.get("workspace_root") or "/")
    return {
        "bridge": "ff-linux-v3",
        "version": __version__,
        "device": ctx["device_name"],
        "hostname": socket.gethostname(),
        "user": os.environ.get("USER") or os.environ.get("LOGNAME") or "",
        "pid": os.getpid(),
        "uptime_s": int(time.monotonic() - ctx["started_monotonic"]),
        "platform": platform.platform(),
        "arch": platform.machine(),
        "python": platform.python_version(),
        "loadavg": [round(load1, 2), round(load5, 2), round(load15, 2)],
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "workspace_root": ctx.get("workspace_root"),
    }


def op_system_info(args: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    mem_info: dict[str, int] = {}
    meminfo_path = Path("/proc/meminfo")
    if meminfo_path.exists():
        for line in meminfo_path.read_text(encoding="utf-8", errors="replace").splitlines():
            for key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
                if line.startswith(key + ":"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        mem_info[key] = int(parts[1]) // 1024  # MB

    os_release: dict[str, str] = {}
    osrel = Path("/etc/os-release")
    if osrel.exists():
        for line in osrel.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                os_release[k] = v.strip().strip('"')

    return {
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "arch": platform.machine(),
        "cpu_count": os.cpu_count(),
        "distro": os_release.get("PRETTY_NAME", platform.platform()),
        "memory_mb": mem_info,
        "display": os.environ.get("DISPLAY") or "",
        "wayland_display": os.environ.get("WAYLAND_DISPLAY") or "",
        "tools": {
            name: shutil.which(name)
            for name in ("python3", "node", "npm", "git", "bash", "chromium", "chromium-browser", "google-chrome", "systemctl")
            if shutil.which(name)
        },
    }


def op_env_info(args: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    names = args.get("names")
    secret_re_keys = ("TOKEN", "SECRET", "KEY", "PASSWORD", "PASS", "AUTH", "COOKIE")
    if isinstance(names, list) and names:
        out = {str(k): os.environ.get(str(k)) for k in names}
    else:
        out = {}
        for k, v in sorted(os.environ.items()):
            upper = k.upper()
            if any(s in upper for s in secret_re_keys):
                out[k] = "<REDACTED>"
            else:
                out[k] = v
    return {"cwd": os.getcwd(), "env": out}


def op_run_shell(args: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    command = args.get("command") or args.get("cmd")
    if not isinstance(command, str) or not command.strip():
        raise SystemOpError("INVALID_ARGS", "command must be a non-empty string")
    cwd = args.get("cwd") or ctx.get("workspace_root") or None
    timeout_s = float(args.get("timeout_s", args.get("timeout", 60)))
    env_extra = args.get("env") if isinstance(args.get("env"), dict) else None
    max_output = int(args.get("max_output_chars", 120_000))
    shell_bin = shutil.which("bash") or "/bin/sh"
    return _run_subprocess(
        [shell_bin, "-lc", command],
        shell=False,
        cwd=cwd,
        timeout_s=timeout_s,
        env_extra=env_extra,
        max_output_chars=max_output,
    )


def op_run_code(args: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    language = str(args.get("language") or "python").strip().lower()
    code = args.get("code")
    if not isinstance(code, str) or not code.strip():
        raise SystemOpError("INVALID_ARGS", "code must be a non-empty string")

    cwd = args.get("cwd") or ctx.get("workspace_root") or None
    timeout_s = float(args.get("timeout_s", args.get("timeout", 60)))
    env_extra = args.get("env") if isinstance(args.get("env"), dict) else None

    if language in ("python", "python3", "py"):
        suffix, runner = ".py", [sys.executable]
    elif language in ("bash", "sh", "shell"):
        suffix, runner = ".sh", [shutil.which("bash") or "/bin/sh"]
    elif language in ("node", "js", "javascript"):
        node_bin = shutil.which("node")
        if not node_bin:
            raise SystemOpError("RUNTIME_NOT_FOUND", "node is not installed on this host")
        suffix, runner = ".mjs", [node_bin]
    else:
        raise SystemOpError("UNSUPPORTED_LANGUAGE", f"Unsupported language: {language} (use python, bash, node)")

    fd, tmp_path = tempfile.mkstemp(prefix="ff-code-", suffix=suffix)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(code)
        return _run_subprocess(
            runner + [tmp_path],
            shell=False,
            cwd=cwd,
            timeout_s=timeout_s,
            env_extra=env_extra,
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def op_process_list(args: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    filter_text = str(args.get("filter") or "").lower().strip()
    limit = max(1, min(int(args.get("limit", 100)), 500))
    res = _run_subprocess(["ps", "-eo", "pid,ppid,user,%cpu,%mem,stat,comm,args", "--no-headers"], timeout_s=10)
    procs = []
    for line in res["stdout"].splitlines():
        parts = line.strip().split(None, 7)
        if len(parts) < 7:
            continue
        item = {
            "pid": int(parts[0]),
            "ppid": int(parts[1]),
            "user": parts[2],
            "cpu": parts[3],
            "mem": parts[4],
            "stat": parts[5],
            "comm": parts[6],
            "args": parts[7] if len(parts) > 7 else parts[6],
        }
        if filter_text and filter_text not in item["comm"].lower() and filter_text not in item["args"].lower():
            continue
        procs.append(item)
        if len(procs) >= limit:
            break
    return {"count": len(procs), "processes": procs}


def op_process_kill(args: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    pid = args.get("pid")
    if not isinstance(pid, int) or pid <= 1:
        raise SystemOpError("INVALID_PID", "pid must be an integer > 1")
    if pid == os.getpid():
        raise SystemOpError("REFUSED_SELF_KILL", "Refusing to kill the bridge process itself")
    sig_name = str(args.get("signal") or "TERM").upper().removeprefix("SIG")
    sig_map = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL, "INT": signal.SIGINT, "HUP": signal.SIGHUP}
    if sig_name not in sig_map:
        raise SystemOpError("INVALID_SIGNAL", f"Unsupported signal: {sig_name}")
    try:
        os.kill(pid, sig_map[sig_name])
    except ProcessLookupError:
        raise SystemOpError("NOT_FOUND", f"No such process: {pid}")
    except PermissionError as exc:
        raise SystemOpError("PERMISSION_DENIED", str(exc))
    return {"pid": pid, "signal": sig_name, "sent": True}


def op_service_status(args: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
    name = str(args.get("name") or "").strip()
    if not name:
        raise SystemOpError("INVALID_ARGS", "name is required")
    user_scope = bool(args.get("user", False))
    systemctl = shutil.which("systemctl")
    if not systemctl:
        raise SystemOpError("SYSTEMCTL_NOT_FOUND", "systemctl is not available on this host")
    cmd = [systemctl] + (["--user"] if user_scope else []) + ["show", name, "--no-page", "--property=Id,LoadState,ActiveState,SubState,MainPID,Description"]
    res = _run_subprocess(cmd, timeout_s=10)
    props = {}
    for line in res["stdout"].splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k] = v
    return {"name": name, "user_scope": user_scope, "exit_code": res["exit_code"], "properties": props}


SYSTEM_OPS = {
    "ping": op_ping,
    "device_status": op_device_status,
    "system_info": op_system_info,
    "env_info": op_env_info,
    "run_shell": op_run_shell,
    "run_code": op_run_code,
    "process_list": op_process_list,
    "process_kill": op_process_kill,
    "service_status": op_service_status,
}
