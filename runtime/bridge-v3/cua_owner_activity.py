"""Pause agent desktop input while the owner is using the mouse or keyboard.

Windows records the time of the last input from ANY source, including the
agent's own. The guard remembers when the agent's last action finished; input
newer than that moment can only be the owner's, so the agent is told to wait.
Before its first action the owner must have been idle for ``quiet_ms``.
"""
from __future__ import annotations

import ctypes
import time


class OwnerActive(RuntimeError):
    def __init__(self, idle_ms: int):
        super().__init__("OWNER_ACTIVE")
        self.idle_ms = idle_ms


def system_idle_ms() -> int:
    """Milliseconds since the last keyboard or mouse input in this session."""
    class LASTINPUTINFO(ctypes.Structure):
        _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

    info = LASTINPUTINFO()
    info.cbSize = ctypes.sizeof(info)
    if not ctypes.windll.user32.GetLastInputInfo(ctypes.byref(info)):
        raise OSError("GetLastInputInfo failed")
    return (ctypes.windll.kernel32.GetTickCount() - info.dwTime) & 0xFFFFFFFF


class OwnerActivityGuard:
    def __init__(self, idle_ms=system_idle_ms, clock=time.monotonic, quiet_ms=1500, margin_ms=400):
        self._idle_ms, self._clock = idle_ms, clock
        self.quiet_ms, self.margin_ms = quiet_ms, margin_ms
        self._agent_done_at = None

    def check(self) -> None:
        try:
            idle = int(self._idle_ms())
        except OSError:
            return  # cannot observe input (e.g. no interactive desktop): do not block
        if self._agent_done_at is None:
            if idle < self.quiet_ms:
                raise OwnerActive(idle)
            return
        since_agent_ms = (self._clock() - self._agent_done_at) * 1000
        if idle + self.margin_ms < since_agent_ms:
            raise OwnerActive(idle)

    def agent_input_done(self) -> None:
        self._agent_done_at = self._clock()

    def reset(self) -> None:
        self._agent_done_at = None
