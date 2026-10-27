"""Verify an owned, freshly installed candidate, never the user's live Bridge.

The caller must first run install.ps1 -Transport Local -NoStartup into an
empty CI-owned directory. No startup registration or paid inference is used.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import socket
import subprocess
import sys
import time

from isolated_rpc_smoke import free_port, rpc, verify, verify_rpc


def verify_installed(package: Path, installed: Path, expected_commit: str):
    manifest = json.loads((package / "release-manifest.json").read_text("utf-8"))
    verify(manifest.get("schema") == "ff-gh-release-v1", "MANIFEST_SCHEMA")
    verify(manifest.get("source_bytes_verified_against_commit") is True, "SOURCE_NOT_VERIFIED")
    verify(manifest.get("source_commit") == expected_commit == manifest.get("public_source_commit"),
           "INSTALL_SOURCE_IDENTITY_MISMATCH")
    marker = json.loads((installed / "bridge-v3/ff-local-owned-runtime.json").read_text("utf-8-sig"))
    verify(marker.get("schema") == "ff-local-owned-runtime-v1" and
           marker.get("source_commit") == expected_commit, "INSTALL_MARKER_SOURCE_MISMATCH")
    count = 0
    for name, expected in manifest["files"].items():
        if not name.startswith("runtime/bridge-v3/"):
            continue
        parts = PurePosixPath(name).parts
        verify(not PurePosixPath(name).is_absolute() and ".." not in parts and
               "\\" not in name and ":" not in name, "MANIFEST_PATH_INVALID")
        target = installed / "bridge-v3" / Path(*parts[2:])
        verify(target.is_file() and not target.is_symlink(), "INSTALLED_SOURCE_MISSING")
        verify(hashlib.sha256(target.read_bytes()).hexdigest() == expected, "INSTALLED_SOURCE_SHA_MISMATCH")
        count += 1
    verify(count > 20, "INSUFFICIENT_INSTALLED_SOURCE_COVERAGE")
    return manifest, count


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--install-root", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--report", type=Path, required=True)
    opts = parser.parse_args(argv)
    verify(os.name == "nt", "WINDOWS_REQUIRED")
    installed, package = opts.install_root.resolve(), opts.package_root.resolve()
    manifest, count = verify_installed(package, installed, opts.source_commit)
    python = installed / "tools" / ("python-" + manifest["python_version"] + "-embed") / "python.exe"
    server = installed / "bridge-v3/ff_win_v3_main.py"
    port = free_port()
    env = {**os.environ, "FF_BRIDGE_ROOT": str(installed)}
    # Bind an actual child HANDLE, not a process-name or PID search on cleanup.
    process = subprocess.Popen([str(python), str(server), "serve", "--host", "127.0.0.1", "--port", str(port)],
                               env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        deadline = time.monotonic() + 25
        secret_path = installed / "bridge-v3/secret"
        while time.monotonic() < deadline:
            verify(process.poll() is None, "INSTALLED_RUNTIME_EXITED")
            if secret_path.is_file():
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.2):
                        break
                except OSError:
                    pass
            time.sleep(.1)
        else:
            raise RuntimeError("INSTALLED_RUNTIME_NOT_READY")
        secret = secret_path.read_text("ascii").strip()
        device = rpc(port, secret, "device_info", {}, "ci-installed-provenance")
        actual = device.get("result") or {}
        verify(device.get("ok") is True and actual.get("pid") == process.pid, "WRONG_RUNNING_PROCESS")
        expected_agent = manifest["files"]["runtime/bridge-v3/ff_win_v3_agent.py"]
        verify(actual.get("agent_sha256") == expected_agent, "LOADED_AGENT_SHA_MISMATCH")
        checks = verify_rpc(port, secret)
        # Regression: a normal local reinstall (even -NoStartup) must NEVER
        # replace runtime bytes beneath a running, previously installed agent.
        # Use only this isolated CI-owned install and its exact child process.
        before_agent_sha = hashlib.sha256(server.read_bytes()).hexdigest()
        attempt = subprocess.run([
            "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-File", str(package / "install.ps1"),
            "-NoStartup", "-Transport", "Local", "-InstallRoot", str(installed),
        ], capture_output=True, text=True, errors="replace", timeout=65,
           creationflags=subprocess.CREATE_NO_WINDOW)
        verify(attempt.returncode != 0 and
               "LIVE_RUNTIME_RUNNING_SWITCH_REQUIRED" in
               (attempt.stdout + attempt.stderr),
               "ACTIVE_RUNTIME_REINSTALL_NOT_BLOCKED_BEFORE_WRITE")
        verify(process.poll() is None, "REINSTALL_STOPPED_OWNED_RUNNING_AGENT")
        verify(hashlib.sha256(server.read_bytes()).hexdigest() == before_agent_sha,
               "REINSTALL_MODIFIED_RUNNING_AGENT_SOURCE")
        alive = rpc(port, secret, "ping", {}, "ci-after-denied-active-reinstall")
        verify(alive.get("ok") is True, "DENIED_REINSTALL_BROKE_RUNNING_AGENT")
        checks.append("running_bridge_reinstall_denied_before_write")
        verify_installed(package, installed, opts.source_commit)
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    report = {"schema": "ff-installed-candidate-smoke-v1", "all_passed": True,
              "source_commit": opts.source_commit, "verified_installed_source_files": count,
              "loaded_agent_sha256": expected_agent, "owned_child_pid_matched": True,
              "owned_runtime_stopped": process.poll() is not None, "checks": checks,
              "live_user_installation_modified": False, "model_called": False,
              "scope": "isolated nonproduction candidate; not reboot/full master acceptance",
              "test_host_environment_attested": False}
    opts.report.write_text(json.dumps(report, sort_keys=True, indent=2), encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print("INSTALLED_PACKAGE_SMOKE_FAILED:" + (str(exc) if isinstance(exc, RuntimeError)
                                                   else type(exc).__name__)[:150], file=sys.stderr)
        raise SystemExit(1)
