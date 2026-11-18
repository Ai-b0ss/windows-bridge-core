"""Verify isolated install/update/rollback of two commit-bound private-runtime ZIPs."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import zipfile

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_TOOL = ROOT / "tools" / "private_desktop_runtime.py"
sys.path.insert(0, str(ROOT / "runtime" / "bridge-v3"))
from ff_hub import HubClient


def run(tool, arguments):
    process = subprocess.run([sys.executable, "-X", "utf8", str(tool), *map(str, arguments)],
                             capture_output=True, timeout=70)
    return process.returncode, json.loads(process.stdout)


def must(tool, *arguments):
    code, result = run(tool, arguments)
    if code:
        raise RuntimeError(str(result.get("error_code", "CANARY_COMMAND_FAILED")))
    return result


def check(condition, code):
    if not condition:
        raise RuntimeError(code)


def archive(commit, destination):
    subprocess.run(["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "archive",
                    "--format=zip", "-o", str(destination), commit], check=True, cwd=ROOT)
    with zipfile.ZipFile(destination) as z:
        check(z.testzip() is None, "ZIP_CRC_FAILED")
        manifest = json.loads(z.read("release-manifest.json"))["files"]
        for name in z.namelist():
            if name.startswith("runtime/") and not name.endswith("/"):
                check(hashlib.sha256(z.read(name)).hexdigest() == manifest[name], "CANARY_SOURCE_MANIFEST_MISMATCH")
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def canary(home, old_zip, old_sha, new_zip, new_sha):
    state = home / "state" / "hub"
    admin = HubClient(state)

    def runtime(*args):
        return must(RUNTIME_TOOL, "--home", home, *args)

    runtime("install", "--source-zip", old_zip, "--sha256", old_sha)
    runtime("start")
    old = runtime("doctor")
    check(old["installed_hashes_verified"] and old["release"] == old_sha[:20], "BASE_HASHES")
    check("agent_entry" not in admin.call("capabilities"), "BASE_ALREADY_HAS_ENTRY")
    admin.call("session_open", {"agent_id": "canary", "task_id": "busy-base"})
    try:
        code, denied = run(RUNTIME_TOOL, ["--home", home, "install", "--source-zip", new_zip, "--sha256", new_sha])
        check(code != 0 and denied["error_code"] == "HUB_BUSY", "INSTALLED_WHILE_BUSY")
        check(runtime("doctor")["release"] == old["release"], "BASE_CHANGED_WHILE_BUSY")
    finally:
        admin.call("task_cancel", request_key="cancel-busy-base")
    runtime("install", "--source-zip", new_zip, "--sha256", new_sha)
    runtime("start")
    installed = runtime("doctor")
    check(installed["installed_hashes_verified"] and installed["release"] == new_sha[:20], "CANDIDATE_HASHES")
    check(admin.call("capabilities")["agent_entry"]["schema"] == "ff-agent-entry-v1", "CANDIDATE_DISCOVERY")
    cli = home / "releases" / installed["release"] / "tools" / "agent_entry.py"
    credential = home / "canary.credential"
    must(cli, "issue", "--state-dir", state, "--credential-file", credential, "--client", "canary-cli",
         "--agent", "canary", "--task", "release-e2e", "--ttl", "600", "--scope", "artifacts")

    def scoped(op, *arguments):
        return must(cli, "call", "--endpoint-file", state / "endpoint.json", "--credential-file", credential,
                    "--op", op, *arguments)["result"]

    session = scoped("session_open")["session_id"]
    fixture = home / "fixture.json"
    fixture.write_text('{"command":"put","name":"proof.txt","content_base64":"Y2FuYXJ5"}', encoding="ascii")
    scoped("task_file", "--session-id", session, "--key", "artifact-canary", "--args-file", fixture)
    code, denied = run(RUNTIME_TOOL, ["--home", home, "rollback"])
    check(code != 0 and denied["error_code"] == "HUB_BUSY", "ROLLBACK_WHILE_BUSY")
    cancel = scoped("task_cancel", "--session-id", session, "--key", "cancel-canary")
    check(cancel["cleanup_verified"] and cancel["task_files_removed"] == 1, "CANARY_CLEANUP")
    runtime("rollback")
    runtime("start")
    check(runtime("doctor")["release"] == old["release"], "ROLLBACK_HASHES")
    check("agent_entry" not in admin.call("capabilities"), "ROLLBACK_DISCOVERY")
    runtime("rollback")
    runtime("start")
    reopened = scoped("session_open")
    check(reopened["session_id"] == session and reopened["state"] == "closed", "RESUME_AFTER_ROLLBACK")
    fixture.write_text('{"request_key":"artifact-canary"}', encoding="ascii")
    receipt = scoped("request_status", "--session-id", session, "--args-file", fixture)
    check(receipt["state"] == "completed" and receipt["response"]["sha256"] == hashlib.sha256(b"canary").hexdigest(),
          "RECEIPT_LOST_AFTER_ROLLBACK")
    runtime("stop")
    return {"ok": True, "idle_stop": True, "busy_update_denied": True, "busy_rollback_denied": True,
            "rollback_receipt_preserved": True, "base_sha256": old_sha, "candidate_sha256": new_sha}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", default="HEAD")
    parser.add_argument("--output", required=True, type=Path)
    options = parser.parse_args()
    options.output.mkdir(parents=True, exist_ok=False)
    old, new = options.output / "base-source.zip", options.output / "candidate-source.zip"
    old_sha, new_sha = archive(options.base, old), archive(options.candidate, new)
    with TemporaryDirectory(prefix="ff-entry-canary-") as folder:
        report = canary(Path(folder) / "runtime", old, old_sha, new, new_sha)
    report["commit"] = subprocess.check_output(["git", "rev-parse", options.candidate], cwd=ROOT, text=True).strip()
    (options.output / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
