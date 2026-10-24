"""Authenticated client: ChatGPT -> private GitHub issue -> consented Windows Bridge."""
import argparse
import json
import re
import subprocess
import sys
import time
import uuid

DEFAULT_REPO = "Ai-b0ss/windows-bridge-support-20261024"
REQ = "ff-win-github-comment-v5"
RESP = "ff-win-github-comment-result-v5"


class BridgeRemoteError(Exception):
    pass


class GitHub:
    def api(self, path, body=None):
        cmd = ["gh", "api", path]
        if body is not None:
            cmd += ["-X", "POST", "--input", "-"]
        try:
            result = subprocess.run(
                cmd, input=json.dumps(body) if body is not None else None,
                capture_output=True, text=True, timeout=45, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise BridgeRemoteError("GitHub CLI missing or timed out") from e
        if result.returncode:
            raise BridgeRemoteError("GitHub API failed; verify repository access and gh login")
        try:
            return json.loads(result.stdout)
        except ValueError as e:
            raise BridgeRemoteError("Invalid GitHub API response") from e


def verify(api, repo):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise BridgeRemoteError("Invalid repo")
    owner = repo.split("/")[0]
    info = api.api("repos/" + repo)
    if not isinstance(info, dict) or info.get("private") is not True:
        raise BridgeRemoteError("Remote support REQUIRES a private repository")
    if str((info.get("owner") or {}).get("login", "")).lower() != owner.lower():
        raise BridgeRemoteError("Owner mismatch")
    user = api.api("user")
    if str(user.get("login", "")).lower() != owner.lower():
        raise BridgeRemoteError("Local GitHub CLI must be authenticated as repository owner")


def discover(api, repo):
    issues = api.api("repos/" + repo + "/issues?state=open&per_page=100")
    if not isinstance(issues, list):
        raise BridgeRemoteError("Could not enumerate devices")
    devices = {}
    for issue in issues:
        if not isinstance(issue, dict) or issue.get("pull_request"):
            continue
        line = str(issue.get("body") or "").split("\n", 1)[0]
        if not line.startswith("FF_GH_INBOX_V2 "):
            continue
        try:
            m = json.loads(line[len("FF_GH_INBOX_V2 "):])
        except ValueError:
            continue
        dev, num = m.get("device"), issue.get("number")
        if m.get("redirect") or not isinstance(dev, str) or not isinstance(num, int):
            continue
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,100}", dev):
            continue
        if not str(issue.get("title") or "").startswith("[FF-GH-INBOX] "):
            continue
        devices[dev] = max(num, devices.get(dev, 0))
    return devices


def submit(api, repo, issue, device, op, args):
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,99}", op):
        raise BridgeRemoteError("Invalid Bridge RPC operation")
    task_id = "chatgpt-" + uuid.uuid4().hex
    task = {"schema": REQ, "task_id": task_id, "client_id": "chatgpt-bridge-owner",
            "target_device": device, "op": op, "args": args}
    response = api.api(f"repos/{repo}/issues/{issue}/comments", {"body": json.dumps(task)})
    cid = response.get("id") if isinstance(response, dict) else None
    if not isinstance(cid, int) or cid <= 0:
        raise BridgeRemoteError("GitHub did not create command comment")
    return cid, task_id


def await_result(api, repo, cid, task_id, device, timeout, interval=1.2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        raw = api.api(f"repos/{repo}/issues/comments/{cid}")
        try:
            data = json.loads(raw.get("body", ""))
        except (ValueError, AttributeError, TypeError):
            data = None
        if isinstance(data, dict) and data.get("schema") == RESP:
            if (data.get("task") or {}).get("task_id") != task_id:
                raise BridgeRemoteError("Response task ID mismatch")
            if str(data.get("device", "")).lower() != device.lower():
                raise BridgeRemoteError("Response device mismatch")
            return data
        time.sleep(max(0.1, interval))
    raise BridgeRemoteError("No reply yet. Inspect the private inbox before retrying; task may still run.")


def main(argv=None, api=None):
    p = argparse.ArgumentParser(description="Run Windows Bridge operations on an explicitly paired GitHub device")
    p.add_argument("--repo", default=DEFAULT_REPO)
    p.add_argument("--list", action="store_true")
    p.add_argument("--device")
    p.add_argument("--op")
    p.add_argument("--args-json", default="{}")
    p.add_argument("--timeout", type=float, default=90)
    p.add_argument("--no-wait", action="store_true")
    x = p.parse_args(argv)
    api = api or GitHub()
    verify(api, x.repo)
    devices = discover(api, x.repo)
    if x.list:
        print(json.dumps({"repo": x.repo, "devices": devices}, ensure_ascii=False))
        return 0
    if not x.device or not x.op or x.device not in devices:
        raise BridgeRemoteError("Specify exact paired --device from --list and --op; no fallback")
    try:
        args = json.loads(x.args_json)
    except ValueError as e:
        raise BridgeRemoteError("Invalid args JSON") from e
    if not isinstance(args, dict):
        raise BridgeRemoteError("Args must be a JSON object")
    if not 0 < x.timeout <= 3600:
        raise BridgeRemoteError("Timeout out of range")
    cid, task = submit(api, x.repo, devices[x.device], x.device, x.op, args)
    if x.no_wait:
        print(json.dumps({"status": "submitted", "task_id": task, "comment_id": cid}))
        return 0
    result = await_result(api, x.repo, cid, task, x.device, x.timeout)
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("outcome") == "PASS" else 3


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BridgeRemoteError as e:
        print("BRIDGE_REMOTE_ERROR: " + str(e), file=sys.stderr)
        sys.exit(2)
