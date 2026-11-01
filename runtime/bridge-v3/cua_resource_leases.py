"""Short leases on shared desktop resources.

Independent agents may work in different windows at the same time. Only what they truly share is
serialized: the physical mouse/keyboard/focus (`input`) and a window's own input (`window:<hwnd>`).
Background routes (UIA, Chrome extension, COM) take no lease and run in parallel.

Rules that keep this safe:
- A lease covers ONE action, never a task. Holders do not wait while holding, so there is no
  hold-and-wait and therefore no deadlock between agents.
- A request takes every resource it needs at once, or none. Requests are served in arrival order
  per resource, so nobody starves and a later request cannot overtake an earlier one on the same
  resource; requests on unrelated resources do not wait for each other.
- Waiting is bounded (`LEASE_TIMEOUT`, retry_safe) and cancellable: the caller's `still_valid`
  check runs while waiting, so a revoked grant, an expired grant or the owner's Stop ends the wait
  at once (`LEASE_CANCELLED`).
- A thread cannot take a lease while it holds one (`LEASE_REENTRANT`).
- A holder that runs past `hold_warn_seconds` is reported to waiters; it is never preempted,
  because yanking the mouse from a half-finished action is worse than a clean timeout.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from contextlib import contextmanager
from typing import Callable, Iterable

INPUT = "input"


def window_resource(hwnd) -> str:
    return f"window:{int(hwnd)}"


class LeaseError(RuntimeError):
    def __init__(self, code: str, **details):
        super().__init__(code)
        self.code, self.details = code, details


class ResourceLeases:
    def __init__(self, clock: Callable[[], float] = time.monotonic, poll_seconds: float = 0.05,
                 hold_warn_seconds: float = 30.0):
        self._clock, self._poll, self._warn = clock, poll_seconds, hold_warn_seconds
        self._cond = threading.Condition()
        self._held: dict[str, dict] = {}
        self._queues: dict[str, deque] = {}
        self._ticket = 0
        self._local = threading.local()

    def holds(self, agent_id, task_id) -> bool:
        with self._cond:
            return any(h["owner"] == (agent_id, task_id) for h in self._held.values())

    def snapshot(self) -> dict:
        now = self._clock()
        with self._cond:
            return {
                "held": {r: {"agent_id": h["owner"][0], "task_id": h["owner"][1],
                             "seconds": round(now - h["since"], 3)} for r, h in self._held.items()},
                "waiting": {r: [t["owner"][0] for t in q] for r, q in self._queues.items() if q},
            }

    @contextmanager
    def acquire(self, owner: tuple, resources: Iterable[str], timeout: float = 10.0,
                still_valid: Callable[[], bool] | None = None):
        wanted = sorted(set(resources))
        if not wanted:
            yield
            return
        if getattr(self._local, "depth", 0):
            raise LeaseError("LEASE_REENTRANT")
        deadline = self._clock() + timeout
        with self._cond:
            self._ticket += 1
            ticket = {"id": self._ticket, "owner": owner}
            for r in wanted:
                self._queues.setdefault(r, deque()).append(ticket)
            try:
                while True:
                    if still_valid is not None and not still_valid():
                        raise LeaseError("LEASE_CANCELLED", retry_safe=False)
                    if all(r not in self._held and self._queues[r][0] is ticket for r in wanted):
                        break
                    remaining = deadline - self._clock()
                    if remaining <= 0:
                        blockers = {r: self._describe(r, ticket) for r in wanted
                                    if r in self._held or self._queues[r][0] is not ticket}
                        raise LeaseError("LEASE_TIMEOUT", retry_safe=True, retry_after_ms=1000,
                                         waited_seconds=round(timeout, 3), blocked_on=blockers)
                    self._cond.wait(min(self._poll, remaining))
                since = self._clock()
                for r in wanted:
                    self._held[r] = {"owner": owner, "since": since}
            finally:
                for r in wanted:
                    q = self._queues.get(r)
                    if q is not None:
                        try:
                            q.remove(ticket)
                        except ValueError:
                            pass
                self._cond.notify_all()
        self._local.depth = 1
        try:
            yield
        finally:
            self._local.depth = 0
            with self._cond:
                for r in wanted:
                    if self._held.get(r, {}).get("owner") == owner:
                        del self._held[r]
                self._cond.notify_all()

    def _describe(self, resource: str, ticket: dict) -> dict:
        held = self._held.get(resource)
        ahead = [t for t in self._queues.get(resource, ()) if t is not ticket and t["id"] < ticket["id"]]
        info = {"queued_ahead": len(ahead)}
        if held:
            seconds = self._clock() - held["since"]
            info.update(holder_agent=held["owner"][0], holder_task=held["owner"][1],
                        holder_seconds=round(seconds, 3), holder_overdue=seconds > self._warn)
        return info
