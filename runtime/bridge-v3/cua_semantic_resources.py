from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import threading
from typing import Iterable, Iterator


@dataclass
class _ResourceState:
    readers: int = 0
    writer: bool = False
    waiters: int = 0
    waiting_writers: int = 0
    condition: threading.Condition | None = None


class SemanticResourceCoordinator:
    """Route-independent reader/writer coordination for semantic UI resources."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._states: dict[str, _ResourceState] = {}

    def _get_state(self, key: str) -> _ResourceState:
        state = self._states.get(key)
        if state is None:
            state = _ResourceState()
            state.condition = threading.Condition(self._lock)
            self._states[key] = state
        return state

    def _cleanup(self, key: str, state: _ResourceState) -> None:
        if not state.writer and state.readers == 0 and state.waiters == 0 and state.waiting_writers == 0:
            if self._states.get(key) is state:
                self._states.pop(key, None)

    @contextmanager
    def read(self, key: str) -> Iterator[None]:
        if not key:
            yield
            return
        with self._lock:
            state = self._get_state(key)
            state.waiters += 1
            try:
                while state.writer or state.waiting_writers:
                    assert state.condition is not None
                    state.condition.wait()
                state.readers += 1
            finally:
                state.waiters -= 1
        try:
            yield
        finally:
            with self._lock:
                state.readers -= 1
                assert state.condition is not None
                state.condition.notify_all()
                self._cleanup(key, state)

    @contextmanager
    def write(self, key: str) -> Iterator[None]:
        if not key:
            yield
            return
        with self._lock:
            state = self._get_state(key)
            state.waiters += 1
            state.waiting_writers += 1
            try:
                while state.writer or state.readers:
                    assert state.condition is not None
                    state.condition.wait()
                state.writer = True
            finally:
                state.waiters -= 1
                state.waiting_writers -= 1
        try:
            yield
        finally:
            with self._lock:
                state.writer = False
                assert state.condition is not None
                state.condition.notify_all()
                self._cleanup(key, state)

    @staticmethod
    def _normalize_keys(keys: Iterable[str]) -> tuple[str, ...]:
        return tuple(sorted({
            key.strip()
            for key in keys
            if isinstance(key, str) and key.strip()
        }))

    @contextmanager
    def read_many(self, keys: Iterable[str]) -> Iterator[None]:
        ordered = self._normalize_keys(keys)
        with ExitStack() as stack:
            for key in ordered:
                stack.enter_context(self.read(key))
            yield

    @contextmanager
    def write_many(self, keys: Iterable[str]) -> Iterator[None]:
        ordered = self._normalize_keys(keys)
        with ExitStack() as stack:
            for key in ordered:
                stack.enter_context(self.write(key))
            yield

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            resources = {
                key: {
                    "readers": state.readers,
                    "writer": state.writer,
                    "waiters": state.waiters,
                    "waiting_writers": state.waiting_writers,
                }
                for key, state in self._states.items()
            }
            return {"resource_count": len(resources), "resources": resources}
