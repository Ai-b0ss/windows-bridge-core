"""GitHub client: redirect discovery, independent fast result reads, bounded fallback."""
import argparse
import json
import time
import uuid
from pathlib import Path
from ff_win_github_comment_daemon import GitHubREST, get_token, FAST_RESULT_MARKER, SCHEMA, RESULT_SCHEMA

def resolve(api, repository, issue):
    for _ in range(100):
        status, _, raw = api.request("GET", f"/repos/{repository}/issues/{issue}")
        if status != 200:
            raise RuntimeError(f"INBOX_HTTP_{status}")
        value = json.loads(raw)
        first = str(value.get("body") or "").splitlines()
        meta = json.loads(first[0][len("FF_GH_INBOX_V2 "):]) if first and first[0].startswith("FF_GH_INBOX_V2 ") else {}
        if not meta.get("redirect"):
            return issue, value
        issue = int(meta["redirect"])
    raise RuntimeError("INBOX_REDIRECT_LOOP")

def collect(api, repository, issue, rows, timeout=120):
    pending = {int(row["comment_id"]): row for row in rows}
    deadline = time.monotonic() + timeout
    etag = None
    next_fallback = time.monotonic() + 5
    while pending and time.monotonic() < deadline:
        if len(rows) == 1 or len(pending) == 1:
            cid = next(iter(pending))
            status, headers, raw = api.request("GET", f"/repos/{repository}/issues/comments/{cid}", extra={"If-None-Match": etag} if etag else {})
            if status == 200:
                etag = headers.get("etag")
                try:
                    value = json.loads(json.loads(raw).get("body") or "{}")
                except (ValueError, TypeError):
                    value = {}
                if value.get("schema") == RESULT_SCHEMA:
                    pending[cid].update(result=value, seen_ms=time.time_ns() // 1_000_000, via="comment")
                    pending.pop(cid)
            elif status != 304:
                raise RuntimeError(f"RESULT_HTTP_{status}")
            time.sleep(.25)
            continue
        status, headers, raw = api.request("GET", f"/repos/{repository}/issues/{issue}", extra={"If-None-Match": etag} if etag else {})
        if status == 200:
            etag = headers.get("etag")
            body = str(json.loads(raw).get("body") or "")
            if FAST_RESULT_MARKER in body:
                for result in json.loads(body.split(FAST_RESULT_MARKER, 1)[1]).get("results", []):
                    cid = int(result.get("comment_id", 0))
                    if cid in pending:
                        pending[cid].update(result=result, seen_ms=time.time_ns() // 1_000_000, via="issue-body")
                        pending.pop(cid)
        elif status != 304:
            raise RuntimeError(f"RESULT_HTTP_{status}")
        if pending and time.monotonic() >= next_fallback:
            nodes = [row["node_id"] for row in pending.values()]
            query = "query($ids:[ID!]!){nodes(ids:$ids){... on IssueComment{id databaseId body}} rateLimit{cost remaining resetAt}}"
            status, _, raw = api.request("POST", "/graphql", {"query": query, "variables": {"ids": nodes}})
            if status == 200:
                data = json.loads(raw)
                if data.get("errors"):
                    raise RuntimeError("RESULT_GRAPHQL_ERRORS")
                for node in data.get("data", {}).get("nodes", []):
                    if not node:
                        continue
                    try:
                        result = json.loads(node["body"])
                    except (ValueError, TypeError):
                        continue
                    cid = int(node["databaseId"])
                    if result.get("schema") == RESULT_SCHEMA and cid in pending:
                        pending[cid].update(result=result, seen_ms=time.time_ns() // 1_000_000, via="comment-node")
                        pending.pop(cid)
            next_fallback = time.monotonic() + 5
        time.sleep(0.25)
    if pending:
        raise TimeoutError("RESULT_TIMEOUT:" + ",".join(map(str, pending)))
    return rows

def submit(api, repository, issue, task):
    issue, _ = resolve(api, repository, issue)
    started = time.time_ns() // 1_000_000
    status, _, raw = api.request("POST", f"/repos/{repository}/issues/{issue}/comments", {"body": json.dumps(task, separators=(",", ":"))}, retries=0)
    if status != 201:
        raise RuntimeError(f"SUBMIT_HTTP_{status}")
    comment = json.loads(raw)
    return {"comment_id": int(comment["id"]), "node_id": comment["node_id"], "sent_ms": started, "ack_ms": time.time_ns() // 1_000_000, "inbox_issue": issue}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("github_transport_config.json"))
    parser.add_argument("--op", default="ping")
    parser.add_argument("--args", default="{}")
    parser.add_argument("--task-id", default=None)
    parser.add_argument("--client-id", default="github-client")
    parser.add_argument("--execution-context", choices=["auto", "interactive", "background"], default="auto")
    opts = parser.parse_args()
    config = json.loads(opts.config.read_text(encoding="utf-8-sig"))
    api = GitHubREST(get_token())
    task = {"schema": SCHEMA, "op": opts.op, "args": json.loads(opts.args), "task_id": opts.task_id or uuid.uuid4().hex, "client_id": opts.client_id, "target_device": config["device"]}
    if opts.execution_context != "auto":
        task["execution_context"] = opts.execution_context
    row = submit(api, config["repository"], config["inbox_issue"], task)
    collect(api, config["repository"], row["inbox_issue"], [row])
    print(json.dumps(row, ensure_ascii=False))
