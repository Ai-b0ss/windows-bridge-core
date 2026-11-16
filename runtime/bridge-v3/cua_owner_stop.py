"""Persistent owner Stop. No agent-facing operation may clear this latch."""
from pathlib import Path


def stop_requested(state_dir) -> bool:
    # lstat also treats directories and dangling links as Stop. An unreadable
    # marker/state is not evidence that the owner allowed input to resume.
    try:
        (Path(state_dir) / "stop.flag").lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True
