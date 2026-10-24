from __future__ import annotations

import base64
import concurrent.futures
import gzip
import hashlib
import http.client
import json
import msvcrt
import os
import platform
import queue
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

# Keep the shared idempotency journal, but allow this transport to receive
# larger bridge responses than the old issue/comment transport.
GH_HOME = Path(os.environ.get("FF_GH_HOME") or HERE)
CONFIG_PATH = GH_HOME / "github_transport_config.json"
CONFIG = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig")) if CONFIG_PATH.exists() else {}
os.environ.setdefault("FF_BRIDGE_ROOT", str(GH_HOME.parent))
if CONFIG.get("rpc_url"):
    os.environ.setdefault("FF_V3_RPC_URL", CONFIG["rpc_url"])
if CONFIG.get("background_rpc_url"):
    os.environ.setdefault("FF_V3_BACKGROUND_RPC_URL", CONFIG["background_rpc_url"])
os.environ.setdefault("FF_TRANSPORT_MAX_RESULT_BYTES", str(2 * 1024 * 1024))
from ff_win_transport_core import execute_task
from ff_win_transport_faults import barrier

REPOSITORY = os.environ.get("FF_GH_REPOSITORY") or CONFIG.get("repository", "Ai-b0ss/windows-agent-bridge")
if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", REPOSITORY):
    raise ValueError("INVALID_REPOSITORY")
OWNER, REPO = REPOSITORY.split("/")
ALLOWED_SENDERS = {str(x).lower() for x in CONFIG.get("allowed_senders", [OWNER])}
DEVICE = str(CONFIG.get("device") or platform.node())
SOURCE_BRANCH = str(CONFIG.get("branch") or "main")
SCHEMA = "ff-win-github-comment-v5"
RESULT_SCHEMA = "ff-win-github-comment-result-v5"
INBOX_ISSUE = int(os.environ.get("FF_GH_INBOX_ISSUE") or CONFIG.get("inbox_issue", 3807))
POLL_SECONDS = float(os.environ.get("FF_GH_POLL_SECONDS", "0.25"))
MAX_WORKERS = int(os.environ.get("FF_GH_MAX_WORKERS", "8"))
RESULT_BATCH_WINDOW_SECONDS = float(os.environ.get("FF_GH_RESULT_BATCH_WINDOW", "0.05"))
RESULT_BATCH_BURST_WINDOW_SECONDS = float(os.environ.get("FF_GH_RESULT_BATCH_BURST_WINDOW", "0.35"))
RESULT_BATCH_MAX = max(2, min(16, int(os.environ.get("FF_GH_RESULT_BATCH_MAX", "16"))))
MAX_INLINE_COMMENT_BYTES = 60_000
RESULTS_BRANCH = os.environ.get("FF_GH_RESULTS_BRANCH") or CONFIG.get("results_branch", "ff-transport-results")
PER_PAGE = 100
API_VERSION = "2026-03-10"
API_HOST = "api.github.com"
if os.environ.get("FF_TRANSPORT_TEST_MODE") == "isolated-fault-test":
    override = os.environ.get("FF_GH_API_HOST", "").strip()
    if override:
        if override.split(":", 1)[0] not in {"127.0.0.1", "localhost"}:
            raise ValueError("TEST_API_HOST_MUST_BE_LOOPBACK")
        API_HOST = override
TASK_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")
FAST_RESULT_MARKER = "FF_GH_FAST_RESULTS_V1\n"
FAST_RESULT_HISTORY = 32
FAST_RESULT_BODY_MAX_BYTES = 55_000
INBOX_BODY_PREFIX = (
    "Persistent inbox for GitHub-only Windows transport. "
    "Task comments are replaced in place with result envelopes after processing. "
    "Do not delete this issue."
)

GH_HOME = Path(os.environ.get("FF_GH_HOME") or HERE)
HEALTH = GH_HOME / "comment_transport_health.json"
LOCK = GH_HOME / "comment_transport.lock"


def now_ms() -> int:
    return time.time_ns() // 1_000_000


_trace_lock = threading.Lock()
_trace_error_count = 0
_rate_gate_lock = threading.Lock()
_rate_gate_until = 0.0


def rate_cooldown(seconds):
    global _rate_gate_until
    with _rate_gate_lock:
        _rate_gate_until = max(_rate_gate_until, time.monotonic() + seconds)
    trace("github_cooldown", seconds=round(seconds, 2))


def trace(stage: str, **fields: Any) -> None:
    """Bounded local timing evidence; never include task payloads or credentials."""
    global _trace_error_count
    if os.environ.get("FF_GH_TRACE", "1") != "1":
        return
    with _trace_lock:
        try:
            path = GH_HOME / "latency.jsonl"
            GH_HOME.mkdir(parents=True, exist_ok=True)
            if path.exists() and path.stat().st_size > 8 * 1024 * 1024:
                os.replace(path, path.with_suffix(".previous.jsonl"))
            with path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps({"at_ms": now_ms(), "stage": stage, **fields}, separators=(",", ":")) + "\n")
        except OSError:
            # Optional diagnostics must not turn a successful HTTP mutation
            # into a retry. Durable journal/outbox failures still fail closed.
            _trace_error_count += 1


def get_token() -> str:
    value = os.environ.get("GH_TOKEN", "").strip()
    if value:
        return value
    cp = subprocess.run([CONFIG.get("gh_path") or "gh", "auth", "token"], capture_output=True, text=True, timeout=15)
    token = cp.stdout.strip()
    if cp.returncode or not token:
        raise RuntimeError("GH_AUTH_TOKEN_UNAVAILABLE")
    return token


class GitHubREST:
    def __init__(self, token: str):
        self.token = token
        self.lock = threading.Lock()
        self.conn: http.client.HTTPSConnection | None = None
        self.metrics = {"attempts": 0, "requests": 0, "http_200": 0, "http_304": 0, "errors": 0, "mutations": 0}
        self.rate = {}

    def _reset(self) -> None:
        try:
            if self.conn:
                self.conn.close()
        finally:
            self.conn = None

    def request(
        self,
        method: str,
        path: str,
        payload: Any = None,
        extra: dict[str, str] | None = None,
        retries: int = 3,
    ) -> tuple[int, dict[str, str], bytes]:
        raw = None if payload is None else json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "ff-windows-github-comment-transport-v5",
        }
        if raw is not None:
            headers["Content-Type"] = "application/json"
        if extra:
            headers.update(extra)

        last: Exception | None = None
        for attempt in range(retries + 1):
            response_seen = False
            try:
                while time.monotonic() < _rate_gate_until:
                    time.sleep(min(1.0, _rate_gate_until - time.monotonic()))
                with self.lock:
                    self.metrics["attempts"] += 1
                    if self.conn is None:
                        self.conn = http.client.HTTPSConnection(API_HOST, timeout=10)
                    self.conn.request(method, path, body=raw, headers=headers)
                    response = self.conn.getresponse()
                    body = response.read()
                    meta = {k.lower(): v for k, v in response.getheaders()}
                    status = response.status
                    response_seen = True
                    self.metrics["requests"] += 1
                    self.metrics["errors"] += int(status >= 400)
                    self.metrics[f"http_{status}"] = self.metrics.get(f"http_{status}", 0) + 1
                    self.metrics["mutations"] += int(method not in {"GET", "HEAD"})
                    resource = meta.get("x-ratelimit-resource", "unknown")
                    self.rate[resource] = {k: meta.get("x-ratelimit-" + k) for k in ("limit", "remaining", "used", "reset")}
                    if method != "GET" or status != 304:
                        trace("api_response", method=method, path=path, status=status, resource=resource, rate=self.rate[resource])
                if status in (502, 503, 504):
                    raise RuntimeError(f"GH_HTTP_{status}")
                if status in (403, 429):
                    message = body.decode("utf-8", "replace").lower()
                    retry_after = meta.get("retry-after")
                    if retry_after:
                        rate_cooldown(max(float(retry_after), 1.0))
                        if attempt < retries:
                            continue
                    if meta.get("x-ratelimit-remaining") == "0":
                        reset = float(meta.get("x-ratelimit-reset") or 0)
                        wait = max(1.0, reset - time.time() + 1.0)
                        rate_cooldown(wait)
                        if attempt < retries:
                            continue
                    if "rate limit" in message or "abuse" in message:
                        rate_cooldown(60.0 * (2 ** attempt))
                        if attempt < retries:
                            continue
                return status, meta, body
            except (OSError, http.client.HTTPException, RuntimeError) as exc:
                last = exc
                with self.lock:
                    if not response_seen:
                        self.metrics["errors"] += 1
                    self._reset()
                trace("api_error", method=method, path=path, attempt=attempt + 1,
                      error_type=type(exc).__name__, response_received=response_seen)
                if attempt >= retries:
                    raise
                time.sleep((0.20, 0.50, 1.50, 3.00)[min(attempt, 3)])
        raise last or RuntimeError("GH_REQUEST_FAILED")


def parse_json(body: bytes) -> Any:
    return json.loads(body.decode("utf-8-sig")) if body else None


def parse_task(comment: dict[str, Any]) -> dict[str, Any] | None:
    if str((comment.get("user") or {}).get("login", "")).lower() not in ALLOWED_SENDERS:
        return None
    body = comment.get("body")
    if not isinstance(body, str):
        return None
    try:
        task = json.loads(body.lstrip("\ufeff").strip())
    except Exception:
        return None
    if not isinstance(task, dict) or task.get("schema") != SCHEMA:
        return None
    task_id = task.get("task_id")
    if not isinstance(task_id, str) or not TASK_ID_RE.fullmatch(task_id):
        return None
    client_id = task.get("client_id")
    if not isinstance(client_id, str) or not client_id or len(client_id) > 100:
        return None
    op = task.get("op")
    if not isinstance(op, str) or not op or len(op) > 100:
        return None
    if not isinstance(task.get("args", {}), dict):
        return None
    target = task.get("target_device")
    if target and str(target).lower() != DEVICE.lower():
        return None
    return task


def write_health(payload: dict[str, Any]) -> None:
    GH_HOME.mkdir(parents=True, exist_ok=True)
    tmp = HEALTH.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    os.replace(tmp, HEALTH)


class CommentTransport:
    def __init__(self) -> None:
        self.api = GitHubREST(get_token())
        self.poll_api = GitHubREST(self.api.token)
        self.inbox = INBOX_ISSUE
        self.inbox_prefix = INBOX_BODY_PREFIX
        self.last_rotation_check = 0.0
        self.archived_inboxes = list(CONFIG.get("archived_inboxes", []))
        self.last_archive_poll = 0.0
        self.archive_cursor = 0
        self.archive_cache: dict[str, tuple[str | None, int]] = {}
        self.page = 1
        self.etag: str | None = None
        self.poll_interval = POLL_SECONDS
        self.pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=MAX_WORKERS, thread_name_prefix="ff-gh-comment"
        )
        self.active: set[int] = set()
        self.active_lock = threading.Lock()
        self.result_store_lock = threading.Lock()
        self.mutation_lock = threading.Lock()
        self.last_mutation_at = 0.0
        budget_file = GH_HOME / "mutation-budget.json"
        self.mutation_times = json.loads(budget_file.read_text()) if budget_file.exists() else []
        self.publish_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self.retry_after: dict[int, float] = {}
        self.fast_results: dict[str, dict[str, Any]] = {}
        self.recent_singletons: list[dict[str, Any]] = []
        self.fast_history_loaded = False
        self.last_received_at = 0.0
        self.durable_pending = []
        self.outbox = GH_HOME / "outbox"
        self.outbox.mkdir(parents=True, exist_ok=True)
        self.requests = GH_HOME / "pending-requests"
        self.requests.mkdir(parents=True, exist_ok=True)
        self.last_recover_at = 0.0
        self.counters = {
            "poll_200": 0,
            "poll_304": 0,
            "tasks_pass": 0,
            "tasks_failed": 0,
            "transient_retries": 0,
            "api_errors": 0,
            "result_batches": 0,
            "result_batch_items": 0,
            "result_batch_fallbacks": 0,
            "result_publish_failures": 0,
            "fast_result_batches": 0,
            "fast_result_items": 0,
            "fast_result_failures": 0,
            "fast_result_skipped": 0,
        }
        self.last_error: str | None = None
        self.rate_remaining: int | None = None
        self.publisher_thread = threading.Thread(
            target=self.publisher_loop,
            name="ff-gh-result-publisher",
            daemon=True,
        )
        self.publisher_thread.start()

    def comments_path(self, page: int) -> str:
        return (
            f"/repos/{OWNER}/{REPO}/issues/{self.inbox}/comments"
            f"?per_page={PER_PAGE}&page={page}"
        )

    @staticmethod
    def inbox_metadata(body):
        first = str(body or "").splitlines()
        if first and first[0].startswith("FF_GH_INBOX_V2 "):
            return json.loads(first[0][len("FF_GH_INBOX_V2 "):])
        return {}

    def set_inbox_config(self, issue):
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig")) if CONFIG_PATH.exists() else dict(CONFIG)
        config["inbox_issue"] = issue
        config["archived_inboxes"] = self.archived_inboxes
        tmp = CONFIG_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(config, indent=2), encoding="utf-8")
        os.replace(tmp, CONFIG_PATH)

    def resolve_inbox(self):
        # Redirect remains authoritative if power is lost between remote
        # activation and replacing the local config file.
        for _ in range(100):
            status, _, raw = self.poll_api.request("GET", f"/repos/{OWNER}/{REPO}/issues/{self.inbox}")
            if status != 200:
                raise RuntimeError(f"GH_INBOX_HTTP_{status}")
            issue = parse_json(raw)
            meta = self.inbox_metadata(issue.get("body"))
            target = meta.get("redirect")
            if not target:
                self.inbox_prefix = str(issue.get("body") or INBOX_BODY_PREFIX).split(FAST_RESULT_MARKER, 1)[0].strip()
                self.set_inbox_config(self.inbox)
                return
            # Rotation occurs only after a complete drain. Keep the old
            # generation and its results in GitHub; never delete comments.
            if not any(x["issue"] == self.inbox for x in self.archived_inboxes):
                self.archived_inboxes.append({"issue": self.inbox, "since": meta["since"]})
            self.inbox = int(target)
        raise RuntimeError("INBOX_REDIRECT_LOOP")

    def scan_archives(self):
        # Only comments updated since cutover, including requests that raced
        # the redirect or were posted by an old client. Never scan old history.
        if time.monotonic() - self.last_archive_poll < 30:
            return
        self.last_archive_poll = time.monotonic()
        count = len(self.archived_inboxes)
        selected = [self.archived_inboxes[(self.archive_cursor + i) % count] for i in range(min(4, count))]
        self.archive_cursor = (self.archive_cursor + len(selected)) % count if count else 0
        for archived in selected:
            for page in range(1, 51):
                path = (f"/repos/{OWNER}/{REPO}/issues/{archived['issue']}/comments"
                        f"?since={quote(archived['since'], safe='')}&per_page=100&page={page}")
                etag, previous_count = self.archive_cache.get(path, (None, 0))
                status, headers, raw = self.poll_api.request("GET", path, extra={"If-None-Match": etag} if etag else {})
                if status == 304:
                    if previous_count < 100:
                        break
                    continue
                if status != 200:
                    raise RuntimeError(f"GH_ARCHIVE_SCAN_HTTP_{status}")
                items = parse_json(raw)
                self.archive_cache[path] = (headers.get("etag"), len(items))
                for comment in items:
                    self.submit(comment)
                if len(items) < 100:
                    break

    def maybe_rotate(self):
        minimum = 1 if os.environ.get("FF_TRANSPORT_TEST_MODE") == "isolated-fault-test" else 100
        threshold = max(minimum, int(CONFIG.get("rotation_comments", 1000)))
        if self.page * PER_PAGE <= threshold or time.monotonic() - self.last_rotation_check < 30:
            return
        self.last_rotation_check = time.monotonic()
        with self.active_lock:
            if self.active:
                return
        if not self.publish_queue.empty() or self.durable_pending:
            return
        # Re-scan before cutover so an unfinished task on an earlier page
        # cannot be discarded merely because the current tail is quiet.
        self.startup_scan()
        with self.active_lock:
            if self.active:
                return
        status, _, raw = self.poll_api.request("GET", f"/repos/{OWNER}/{REPO}/issues/{self.inbox}")
        if status != 200:
            raise RuntimeError("INBOX_ROTATION_READ_FAILED")
        old = parse_json(raw)
        if int(old.get("comments", 0)) < threshold:
            return
        previous = self.inbox
        generation = int(self.inbox_metadata(old.get("body")).get("generation", 0)) + 1
        title = f"[FF-GH-INBOX] {DEVICE} generation {generation}"
        # Discover a prepared generation after an ambiguous create/crash.
        prepared = None
        for page in range(1, 51):
            status, _, raw = self.poll_api.request("GET", f"/repos/{OWNER}/{REPO}/issues?state=open&per_page=100&page={page}")
            if status != 200:
                raise RuntimeError("INBOX_ROTATION_DISCOVERY_FAILED")
            issues = parse_json(raw)
            for candidate in issues:
                if candidate.get("title") == title and self.inbox_metadata(candidate.get("body")).get("previous") == previous:
                    prepared = candidate
                    break
            if prepared or len(issues) < 100:
                break
        metadata = {"device": DEVICE, "generation": generation, "previous": previous}
        if prepared is None:
            status, _, raw = self.paced_mutation("POST", f"/repos/{OWNER}/{REPO}/issues", {
                "title": title, "body": "FF_GH_INBOX_V2 " + json.dumps(metadata) + "\n" + INBOX_BODY_PREFIX})
            if status != 201:
                raise RuntimeError("INBOX_ROTATION_CREATE_FAILED")
            prepared = parse_json(raw)
        target = int(prepared["number"])
        barrier("rotation_prepared", {"task_id": "rotation"})
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 60))
        if not any(x["issue"] == previous for x in self.archived_inboxes):
            self.archived_inboxes.append({"issue": previous, "since": since})
        # Persist the recovery cursor before redirect activation.
        self.set_inbox_config(previous)
        redirect = {"device": DEVICE, "generation": generation - 1, "redirect": target, "drained": True, "since": since}
        old_body = "FF_GH_INBOX_V2 " + json.dumps(redirect) + "\n" + str(old.get("body") or INBOX_BODY_PREFIX).split("\n", 1)[-1]
        redirect_path = f"/repos/{OWNER}/{REPO}/issues/{previous}"
        redirect_payload = {"body": old_body, "state": "closed"}
        try:
            status, _, _ = self.paced_mutation("PATCH", redirect_path, redirect_payload)
        except (OSError, http.client.HTTPException):
            status, _, _ = self.paced_mutation("PATCH", redirect_path, redirect_payload)
        if status != 200:
            raise RuntimeError("INBOX_ROTATION_ACTIVATE_FAILED")
        barrier("rotation_redirected", {"task_id": "rotation"})
        self.inbox = target
        self.set_inbox_config(target)
        self.page = 1
        self.etag = None
        self.fast_history_loaded = False
        self.fast_results = {}
        self.recent_singletons = []
        trace("inbox_rotated", previous=previous, active=target, generation=generation)
        self.startup_scan()
        self.last_archive_poll = 0
        self.scan_archives()

    def startup_scan(self) -> None:
        self.resolve_inbox()
        # Scan all existing pages once. Result comments are ignored by parse_task,
        # while any raw task left by a crash is recovered.
        if not self.fast_history_loaded:
            try:
                self.load_fast_history()
            except Exception:
                # Fast burst results are an optimization only. Durable task
                # comments remain authoritative even if issue-body loading fails.
                pass
        page = 1
        while True:
            status, meta, body = self.poll_api.request("GET", self.comments_path(page))
            if status != 200:
                raise RuntimeError(f"GH_STARTUP_SCAN_HTTP_{status}:{body[:300]!r}")
            items = parse_json(body)
            if not isinstance(items, list):
                raise RuntimeError("GH_COMMENTS_NOT_LIST")
            for comment in items:
                self.submit(comment)
            if len(items) < PER_PAGE:
                self.page = page
                self.etag = meta.get("etag")
                return
            page += 1

    def poll(self) -> list[dict[str, Any]]:
        headers = {"If-None-Match": self.etag} if self.etag else {}
        status, meta, body = self.poll_api.request("GET", self.comments_path(self.page), extra=headers)
        if meta.get("x-ratelimit-remaining", "").isdigit():
            self.rate_remaining = int(meta["x-ratelimit-remaining"])
        poll_header = meta.get("x-poll-interval")
        if poll_header:
            try:
                self.poll_interval = max(POLL_SECONDS, float(poll_header))
            except ValueError:
                pass
        if status == 304:
            self.counters["poll_304"] += 1
            return []
        if status != 200:
            raise RuntimeError(f"GH_POLL_HTTP_{status}:{body[:300]!r}")
        self.counters["poll_200"] += 1
        self.etag = meta.get("etag")
        items = parse_json(body)
        if not isinstance(items, list):
            raise RuntimeError("GH_COMMENTS_NOT_LIST")
        if len(items) >= PER_PAGE:
            # Poll the next (currently empty) page so the 101st, 201st, ...
            # comment cannot be hidden behind a full immutable page.
            self.page += 1
            self.etag = None
        return items

    def transient(self, status: int, result: Any) -> bool:
        if status == 503 and isinstance(result, dict) and result.get("error_code") == "REQUEST_NOT_DELIVERED":
            return True
        if status == 409 and isinstance(result, dict) and result.get("error_code") == "TASK_IN_PROGRESS":
            return True
        return False

    def paced_mutation(
        self, method: str, path: str, payload: Any = None
    ) -> tuple[int, dict[str, str], bytes]:
        with self.mutation_lock:
            cost = 1
            if path == "/graphql" and isinstance(payload, dict):
                cost = max(1, str(payload.get("query", "")).count("updateIssueComment("))
            # GitHub content limits span REST, GraphQL and the web UI. Reserve
            # headroom for task creation and other legitimate account activity.
            while True:
                wall = time.time()
                self.mutation_times = [x for x in self.mutation_times if x > wall - 3600]
                minute = [x for x in self.mutation_times if x > wall - 60]
                hour_limit = max(25, min(350, int(CONFIG.get("mutation_hour_budget", 200))))
                if len(self.mutation_times) + cost <= hour_limit and len(minute) + cost <= 40:
                    break
                wait = max(.1, min((minute[0] + 60 - wall) if len(minute) + cost > 40 else (self.mutation_times[0] + 3600 - wall), 30))
                trace("mutation_budget_wait", seconds=round(wait, 2), cost=cost)
                time.sleep(wait)
            self.mutation_times.extend([wall] * cost)
            budget_file = GH_HOME / "mutation-budget.json"
            temp = budget_file.with_suffix(".tmp")
            temp.write_text(json.dumps(self.mutation_times), encoding="utf-8")
            os.replace(temp, budget_file)
            trace("mutation_wait", method=method, path=path)
            elapsed = time.monotonic() - self.last_mutation_at
            if elapsed < 1.0:
                time.sleep(1.0 - elapsed)
            try:
                trace("mutation_start", method=method, path=path)
                # Retry at the durable publisher/recovery layer so each actual
                # attempt is counted by the mutation budget.
                response = self.api.request(method, path, payload, retries=0)
                trace("mutation_end", method=method, path=path, status=response[0])
                return response
            finally:
                self.last_mutation_at = time.monotonic()

    @staticmethod
    def rate_limited(status: int, meta: dict[str, str], raw: bytes) -> bool:
        if status not in (403, 429):
            return False
        message = raw.decode("utf-8", "replace").lower()
        return (
            meta.get("x-ratelimit-remaining") == "0"
            or "rate limit" in message
            or "abuse" in message
        )

    def update_comment(self, comment_id: int, body: str) -> None:
        path = f"/repos/{OWNER}/{REPO}/issues/comments/{comment_id}"
        delay = 1.0
        while True:
            try:
                status, meta, raw = self.paced_mutation(
                    "PATCH", path, {"body": body}
                )
            except Exception as exc:
                self.counters["api_errors"] += 1
                self.last_error = f"{type(exc).__name__}:{exc}"[:500]
                time.sleep(delay)
                delay = min(delay * 2.0, 30.0)
                continue

            if status == 200:
                return
            if self.rate_limited(status, meta, raw):
                self.counters["api_errors"] += 1
                self.last_error = f"GH_RESULT_RATE_LIMIT_{status}"[:500]
                wait = float(meta.get("retry-after") or 60)
                time.sleep(min(max(wait, 60.0), 300.0))
                continue
            if status in (401, 403, 404, 422):
                raise RuntimeError(f"GH_RESULT_PATCH_HTTP_{status}:{raw[:500]!r}")
            self.counters["api_errors"] += 1
            self.last_error = f"GH_RESULT_PATCH_HTTP_{status}"[:500]
            time.sleep(delay)
            delay = min(delay * 2.0, 30.0)

    def load_fast_history(self) -> None:
        status, _, raw = self.api.request(
            "GET", f"/repos/{OWNER}/{REPO}/issues/{self.inbox}"
        )
        if status != 200:
            raise RuntimeError(f"GH_FAST_HISTORY_HTTP_{status}:{raw[:300]!r}")
        issue = parse_json(raw)
        body = issue.get("body") if isinstance(issue, dict) else None
        if isinstance(body, str):
            self.inbox_prefix = body.split(FAST_RESULT_MARKER, 1)[0].strip() or INBOX_BODY_PREFIX
        loaded: dict[str, dict[str, Any]] = {}
        if isinstance(body, str) and FAST_RESULT_MARKER in body:
            payload_text = body.split(FAST_RESULT_MARKER, 1)[1].strip()
            try:
                payload = json.loads(payload_text)
            except Exception:
                payload = None
            if isinstance(payload, dict):
                for result in payload.get("results") or []:
                    if not isinstance(result, dict):
                        continue
                    task = result.get("task")
                    task_id = task.get("task_id") if isinstance(task, dict) else None
                    if isinstance(task_id, str):
                        loaded[str(result.get("comment_id"))] = result
        self.fast_results = dict(list(loaded.items())[-FAST_RESULT_HISTORY:])
        self.fast_history_loaded = True

    def publish_fast_batch(self, items: list[dict[str, Any]]) -> bool:
        parsed: list[dict[str, Any]] = []
        for item in self.recent_singletons + items:
            try:
                result = json.loads(str(item["body"]))
            except Exception:
                return False
            if not isinstance(result, dict) or result.get("schema") != RESULT_SCHEMA:
                return False
            task = result.get("task")
            task_id = task.get("task_id") if isinstance(task, dict) else None
            if not isinstance(task_id, str):
                return False
            parsed.append(result)

        if not self.fast_history_loaded:
            try:
                self.load_fast_history()
            except Exception:
                self.fast_history_loaded = True

        for result in parsed:
            key = str(result["comment_id"])
            self.fast_results.pop(key, None)
            self.fast_results[key] = result

        while len(self.fast_results) > FAST_RESULT_HISTORY:
            oldest = next(iter(self.fast_results))
            self.fast_results.pop(oldest, None)

        while True:
            payload = {
                "schema": "ff-win-github-fast-results-v1",
                "generated_at_ms": now_ms(),
                "results": list(self.fast_results.values()),
            }
            body = (
                self.inbox_prefix
                + "\n\n"
                + FAST_RESULT_MARKER
                + json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
            )
            if len(body.encode("utf-8")) <= FAST_RESULT_BODY_MAX_BYTES:
                break
            if len(self.fast_results) <= len(parsed):
                self.counters["fast_result_skipped"] += len(parsed)
                return False
            oldest = next(iter(self.fast_results))
            self.fast_results.pop(oldest, None)

        status, _, raw = self.paced_mutation(
            "PATCH",
            f"/repos/{OWNER}/{REPO}/issues/{self.inbox}",
            {"body": body},
        )
        if status != 200:
            raise RuntimeError(f"GH_FAST_RESULT_HTTP_{status}:{raw[:500]!r}")
        self.counters["fast_result_batches"] += 1
        self.counters["fast_result_items"] += len(parsed)
        return True

    def update_comments_batch(self, items: list[dict[str, Any]]) -> None:
        variables: dict[str, Any] = {}
        declarations: list[str] = []
        fields: list[str] = []
        for index, item in enumerate(items):
            node_id = item.get("node_id")
            if not node_id:
                raise RuntimeError("GH_BATCH_NODE_ID_MISSING")
            declarations.extend([f"$id{index}:ID!", f"$body{index}:String!"])
            variables[f"id{index}"] = str(node_id)
            variables[f"body{index}"] = str(item["body"])
            fields.append(
                f"c{index}:updateIssueComment("
                f"input:{{id:$id{index},body:$body{index}}})"
                "{issueComment{id}}"
            )
        query_text = (
            "mutation(" + ",".join(declarations) + "){"
            + " ".join(fields)
            + "}"
        )
        status, meta, raw = self.paced_mutation(
            "POST", "/graphql", {"query": query_text, "variables": variables}
        )
        if status != 200:
            raise RuntimeError(f"GH_BATCH_HTTP_{status}:{raw[:500]!r}")
        response = parse_json(raw)
        if not isinstance(response, dict):
            raise RuntimeError("GH_BATCH_RESPONSE_INVALID")
        if response.get("errors"):
            raise RuntimeError(
                "GH_BATCH_GRAPHQL_ERRORS:"
                + json.dumps(response["errors"], ensure_ascii=False)[:1000]
            )
        data = response.get("data")
        if not isinstance(data, dict):
            raise RuntimeError("GH_BATCH_DATA_INVALID")
        for index in range(len(items)):
            if not isinstance(data.get(f"c{index}"), dict):
                raise RuntimeError(f"GH_BATCH_ITEM_MISSING:{index}")

    def publisher_loop(self) -> None:
        while True:
            try:
                first = self.publish_queue.get(timeout=0.1)
            except queue.Empty:
                # Keep slow GraphQL maintenance out of the initial burst path.
                # One small batch limits how long a new fast result can wait.
                if self.durable_pending and time.monotonic() - self.last_received_at > 1.0:
                    pending = self.durable_pending[:4]
                    del self.durable_pending[:4]
                    try:
                        self.update_comments_batch(pending)
                        for item in pending:
                            self.mark_published(item)
                            with self.active_lock:
                                self.active.discard(int(item["comment_id"]))
                    except Exception as exc:
                        self.last_error = f"{type(exc).__name__}:{exc}"[:500]
                        self.durable_pending.extend(pending)
                        time.sleep(1)
                continue
            batch = [first]
            with self.active_lock:
                active_count = len(self.active)
            batch_window = (
                RESULT_BATCH_BURST_WINDOW_SECONDS
                if active_count > 1
                else RESULT_BATCH_WINDOW_SECONDS
            )
            deadline = time.monotonic() + batch_window
            while len(batch) < RESULT_BATCH_MAX:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    batch.append(self.publish_queue.get(timeout=remaining))
                except queue.Empty:
                    break

            try:
                trace("publisher_batch", comments=[x["comment_id"] for x in batch], window_ms=round(batch_window * 1000))
                if len(batch) > 1 and all(item.get("node_id") for item in batch):
                    try:
                        try:
                            fast = self.publish_fast_batch(batch)
                        except (OSError, http.client.HTTPException):
                            fast = self.publish_fast_batch(batch)
                    except Exception as fast_exc:
                        self.counters["fast_result_failures"] += 1
                        self.last_error = f"{type(fast_exc).__name__}:{fast_exc}"[:500]
                        fast = False
                    if fast:
                        self.durable_pending.extend(batch)
                    else:
                        self.update_comments_batch(batch)
                        for item in batch:
                            self.mark_published(item)
                    self.counters["result_batches"] += 1
                    self.counters["result_batch_items"] += len(batch)
                else:
                    for item in batch:
                        self.update_comment(int(item["comment_id"]), str(item["body"]))
                        self.recent_singletons.append(item)
                        self.recent_singletons = self.recent_singletons[-8:]
                        self.mark_published(item)
            except Exception as exc:
                if len(batch) > 1:
                    self.counters["result_batch_fallbacks"] += 1
                self.last_error = f"{type(exc).__name__}:{exc}"[:500]
                # A GraphQL request can be partially applied. Repeating the same
                # bodies with idempotent REST PATCHes is safe and closes every gap.
                for item in batch:
                    try:
                        self.update_comment(int(item["comment_id"]), str(item["body"]))
                        self.mark_published(item)
                    except Exception as fallback_exc:
                        item["error"] = fallback_exc
            finally:
                for item in batch:
                    if item.get("error") is not None:
                        self.counters["result_publish_failures"] += 1
                    with self.active_lock:
                        if not any(x["comment_id"] == item["comment_id"] for x in self.durable_pending):
                            self.active.discard(int(item["comment_id"]))
                    self.publish_queue.task_done()

    def queue_comment_update(self, comment: dict[str, Any], body: str) -> None:
        trace("publish_queued", comment_id=int(comment["id"]))
        item = {
                "comment_id": int(comment["id"]),
                "node_id": comment.get("node_id"),
                "body": body,
                "published": False,
            }
        self.save_outbox(item)
        self.publish_queue.put(item)

    def save_outbox(self, item):
        path = self.outbox / (str(item["comment_id"]) + ".json")
        tmp = path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as stream:
            json.dump(item, stream, ensure_ascii=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)

    def mark_published(self, item):
        item["published"] = True
        self.save_outbox(item)
        (self.requests / (str(item["comment_id"]) + ".json")).unlink(missing_ok=True)
        trace("durable_published", comment_id=item["comment_id"])

    def ensure_results_branch(self) -> None:
        ref = quote(RESULTS_BRANCH, safe="")
        status, _, raw = self.api.request("GET", f"/repos/{OWNER}/{REPO}/git/ref/heads/{ref}")
        if status == 200:
            return
        if status != 404:
            raise RuntimeError(f"GH_RESULTS_REF_HTTP_{status}:{raw[:300]!r}")

        status, _, raw = self.api.request("GET", f"/repos/{OWNER}/{REPO}/git/ref/heads/{quote(SOURCE_BRANCH, safe='')}")
        if status != 200:
            raise RuntimeError(f"GH_MAIN_REF_HTTP_{status}:{raw[:300]!r}")
        main_sha = parse_json(raw)["object"]["sha"]
        status, _, raw = self.paced_mutation(
            "POST",
            f"/repos/{OWNER}/{REPO}/git/refs",
            {"ref": f"refs/heads/{RESULTS_BRANCH}", "sha": main_sha},
        )
        if status not in (201, 422):
            raise RuntimeError(f"GH_RESULTS_REF_CREATE_HTTP_{status}:{raw[:300]!r}")

    def store_large_result(self, comment_id: int, task_id: str, raw: bytes) -> dict[str, Any]:
        compressed = gzip.compress(raw, compresslevel=6)
        digest = hashlib.sha256(raw).hexdigest()
        safe_task = re.sub(r"[^A-Za-z0-9._-]+", "_", task_id)[:80] or "task"
        day = time.strftime("%Y/%m/%d", time.gmtime())
        path = f"transport-results/{day}/{comment_id}-{safe_task}-{digest[:16]}.json.gz"
        api_path = quote(path, safe="/")
        payload = {
            "message": f"transport result {task_id}",
            "content": base64.b64encode(compressed).decode("ascii"),
            "branch": RESULTS_BRANCH,
        }

        with self.result_store_lock:
            self.ensure_results_branch()
            status, _, response = self.paced_mutation(
                "PUT", f"/repos/{OWNER}/{REPO}/contents/{api_path}", payload
            )
            if status not in (200, 201):
                if status in (409, 422):
                    check, _, existing = self.api.request(
                        "GET",
                        f"/repos/{OWNER}/{REPO}/contents/{api_path}?ref={quote(RESULTS_BRANCH, safe='')}",
                    )
                    if check != 200:
                        raise RuntimeError(
                            f"GH_LARGE_RESULT_HTTP_{status}:{response[:300]!r}"
                        )
                    check, _, stored = self.api.request(
                        "GET", f"/repos/{OWNER}/{REPO}/contents/{api_path}?ref={quote(RESULTS_BRANCH, safe='')}",
                        extra={"Accept": "application/vnd.github.raw+json"})
                    if check != 200 or hashlib.sha256(gzip.decompress(stored)).hexdigest() != digest:
                        raise RuntimeError("GH_LARGE_RESULT_EXISTING_CONTENT_CONFLICT")
                else:
                    raise RuntimeError(
                        f"GH_LARGE_RESULT_HTTP_{status}:{response[:300]!r}"
                    )

        return {
            "encoding": "gzip+json",
            "branch": RESULTS_BRANCH,
            "path": path,
            "sha256": digest,
            "original_bytes": len(raw),
            "stored_bytes": len(compressed),
        }

    def publish_result(
        self, comment: dict[str, Any], task_id: str, result: dict[str, Any]
    ) -> None:
        comment_id = int(comment["id"])
        raw = json.dumps(result, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(raw) <= MAX_INLINE_COMMENT_BYTES:
            self.queue_comment_update(comment, raw.decode("utf-8"))
            return

        large = self.store_large_result(comment_id, task_id, raw)
        manifest = {key: value for key, value in result.items() if key != "result"}
        manifest["large_result"] = large
        if len(json.dumps(manifest, ensure_ascii=False).encode()) > MAX_INLINE_COMMENT_BYTES:
            manifest["task"] = {k: v for k, v in result["task"].items() if k != "args"}
            manifest["task"]["args_sha256"] = hashlib.sha256(json.dumps(result["task"].get("args"), sort_keys=True).encode()).hexdigest()
        self.queue_comment_update(
            comment,
            json.dumps(manifest, ensure_ascii=False, separators=(",", ":")),
        )

    def process(self, comment: dict[str, Any], task: dict[str, Any], received_ms: int) -> None:
        cid = int(comment["id"])
        started = time.perf_counter()
        trace("execute_start", comment_id=cid, received_at_ms=received_ms)
        queued_for_publish = False
        try:
            retry_delay = 1.0
            while True:
                try:
                    status, payload, route = execute_task(task)
                except Exception as exc:
                    self.counters["transient_retries"] += 1
                    self.last_error = f"{type(exc).__name__}:{exc}"[:500]
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2.0, 30.0)
                    continue

                if self.transient(status, payload):
                    self.counters["transient_retries"] += 1
                    self.last_error = (
                        f"TRANSIENT_HTTP_{status}:"
                        f"{payload.get('error_code') if isinstance(payload, dict) else 'UNKNOWN'}"
                    )[:500]
                    time.sleep(retry_delay)
                    retry_delay = min(retry_delay * 2.0, 30.0)
                    continue
                if status == 503 and payload.get("error_code") == "INTERACTIVE_SESSION_REQUIRED":
                    self.retry_after[cid] = time.monotonic() + 5
                    return
                break

            ok = 200 <= status < 300 and not (
                isinstance(payload, dict) and payload.get("ok") is False
            )
            result = {
                "schema": RESULT_SCHEMA,
                "transport_version": 5,
                "inbox_issue": self.inbox,
                "comment_id": cid,
                "device": DEVICE,
                "task": task,
                "outcome": "PASS" if ok else "FAILED",
                "http_status": status,
                "route": route,
                "result": payload,
                "received_at_ms": received_ms,
                "completed_at_ms": now_ms(),
                "worker_elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
            }
            self.publish_result(comment, task["task_id"], result)
            trace("execute_end", comment_id=cid, completed_at_ms=result["completed_at_ms"])
            queued_for_publish = True
            self.etag = None
            self.retry_after.pop(cid, None)
            if ok:
                self.counters["tasks_pass"] += 1
            else:
                self.counters["tasks_failed"] += 1
            self.last_error = None
        except Exception as exc:
            self.counters["tasks_failed"] += 1
            self.last_error = f"{type(exc).__name__}:{exc}"[:500]
        finally:
            if not queued_for_publish:
                with self.active_lock:
                    self.active.discard(cid)

    def submit(self, comment: dict[str, Any]) -> None:
        task = parse_task(comment)
        if task is None:
            return
        cid = int(comment["id"])
        if self.retry_after.get(cid, 0.0) > time.monotonic():
            return
        with self.active_lock:
            if cid in self.active:
                return
            self.active.add(cid)
        self.last_received_at = time.monotonic()
        saved = self.outbox / (str(cid) + ".json")
        if saved.exists():
            item = json.loads(saved.read_text(encoding="utf-8"))
            if item.get("published"):
                (self.requests / (str(cid) + ".json")).unlink(missing_ok=True)
                with self.active_lock:
                    self.active.discard(cid)
            else:
                self.publish_queue.put(item)
            return
        request = self.requests / (str(cid) + ".json")
        if not request.exists():
            temp = request.with_suffix(".tmp")
            with temp.open("w", encoding="utf-8") as stream:
                json.dump(comment, stream, ensure_ascii=False, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, request)
        self.pool.submit(self.process, comment, task, now_ms())

    def recover_requests(self):
        if time.monotonic() - self.last_recover_at < 15:
            return
        self.last_recover_at = time.monotonic()
        for path in self.requests.glob("*.json"):
            self.submit(json.loads(path.read_text(encoding="utf-8")))

    def health(self) -> None:
        with self.active_lock:
            active = len(self.active)
        write_health(
            {
                "schema": "ff-win-github-comment-health-v5",
                "pid": os.getpid(),
                "device": DEVICE,
                "inbox_issue": self.inbox,
                "page": self.page,
                "poll_seconds_configured": POLL_SECONDS,
                "poll_seconds_effective": self.poll_interval,
                "active": active,
                "rate_remaining": self.rate_remaining,
            "api_metrics": {"publisher": self.api.metrics, "poller": self.poll_api.metrics},
            "trace_errors": _trace_error_count,
                "api_rate": {"publisher": self.api.rate, "poller": self.poll_api.rate},
                "durable_pending": len(self.durable_pending),
                "waiting_for_login": len(self.retry_after),
                "mutation_hour_count": len(self.mutation_times),
                "github_cooldown_seconds": max(0, round(_rate_gate_until-time.monotonic(),2)),
                "last_poll_ms": now_ms(),
                "last_error": self.last_error,
                **self.counters,
            }
        )

    def run(self) -> None:
        startup_delay = 1.0
        while True:
            try:
                self.recover_requests()
                self.startup_scan()
                self.last_error = None
                break
            except Exception as exc:
                self.counters["api_errors"] += 1
                self.last_error = f"{type(exc).__name__}:{exc}"[:500]
                self.health()
                time.sleep(startup_delay)
                startup_delay = min(startup_delay * 2.0, 30.0)

        next_at = time.monotonic()
        failure_delay = 1.0
        while True:
            try:
                for comment in self.poll():
                    self.submit(comment)
                self.scan_archives()
                self.recover_requests()
                self.maybe_rotate()
                self.last_error = None
                failure_delay = 1.0
            except Exception as exc:
                self.counters["api_errors"] += 1
                self.last_error = f"{type(exc).__name__}:{exc}"[:500]
                self.etag = None
                self.health()
                time.sleep(failure_delay)
                failure_delay = min(failure_delay * 2.0, 30.0)
                next_at = time.monotonic()
                continue
            self.health()
            next_at += self.poll_interval
            delay = next_at - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            else:
                next_at = time.monotonic()


def acquire_singleton():
    GH_HOME.mkdir(parents=True, exist_ok=True)
    handle = LOCK.open("a+b")
    handle.seek(0)
    if handle.tell() == 0:
        handle.write(b"1")
        handle.flush()
    handle.seek(0)
    try:
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        raise SystemExit("FF_GITHUB_COMMENT_ALREADY_RUNNING")
    return handle


def main() -> None:
    if not CONFIG_PATH.exists():
        raise SystemExit("GITHUB_TRANSPORT_CONFIG_MISSING")
    lock = acquire_singleton()
    try:
        CommentTransport().run()
    finally:
        lock.close()


if __name__ == "__main__":
    main()
