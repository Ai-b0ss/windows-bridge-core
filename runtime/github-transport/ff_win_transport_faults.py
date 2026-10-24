"""Opt-in barriers for isolated acceptance processes. Never enabled by installer."""
import json
import os
import time
from pathlib import Path


def barrier(stage, task):
    if os.environ.get("FF_TRANSPORT_TEST_MODE") != "isolated-fault-test":
        return
    directory = os.environ.get("FF_TRANSPORT_FAULT_DIR")
    if not directory:
        return
    root = Path(directory)
    control = root / "control.json"
    if not control.exists():
        return
    spec = json.loads(control.read_text(encoding="utf-8"))
    if spec.get("stage") != stage or spec.get("task_id") != task.get("task_id"):
        return
    root.mkdir(parents=True, exist_ok=True)
    marker = root / "reached.json"
    temp = marker.with_suffix(".tmp")
    temp.write_text(json.dumps({"stage": stage, "task_id": task["task_id"], "pid": os.getpid()}), encoding="utf-8")
    os.replace(temp, marker)
    # A timeout fails closed by terminating this test process; never dispatch
    # simply because a test controller disappeared.
    deadline = time.monotonic() + 120
    while not (root / "release").exists():
        if time.monotonic() > deadline:
            os._exit(91)
        time.sleep(0.02)
