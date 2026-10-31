"""Owner-visible notice that the agent is using the desktop, with a Stop button.

Raised only from the code path that really sends input, so it cannot fire for
read-only or hidden work. One notice per (agent, task, generation); later
actions only refresh a heartbeat file. A failure to show the notice never
blocks the owner-approved action, but is reported to the caller.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

SCRIPT = Path(__file__).with_name("cua_owner_notice.ps1")
CREATE_NO_WINDOW = 0x08000000


class OwnerNotice:
    def __init__(self, state_dir, popen=subprocess.Popen, clock=time.time, script=SCRIPT,
                 idle_seconds=60, max_seconds=4 * 3600):
        self.dir = Path(state_dir)
        self.popen, self.clock, self.script = popen, clock, Path(script)
        self.idle_seconds, self.max_seconds = idle_seconds, max_seconds
        self._key = None
        self._proc = None

    @property
    def stop_path(self) -> Path:
        return self.dir / "stop.flag"

    @property
    def heartbeat_path(self) -> Path:
        return self.dir / "notice-heartbeat"

    def stop_requested(self) -> bool:
        return self.stop_path.exists()

    def clear_stop(self) -> None:
        try:
            self.stop_path.unlink()
        except FileNotFoundError:
            pass

    def action(self, agent: str, task: str, generation, apps_text: str = "") -> bool:
        """Refresh the heartbeat and show the notice if none is running. Returns True if visible."""
        self.dir.mkdir(parents=True, exist_ok=True)
        self.heartbeat_path.write_text(str(self.clock()), encoding="ascii")
        os.utime(self.heartbeat_path, None)
        key = (agent, task, generation)
        if self._key == key and self._proc is not None and self._proc.poll() is None:
            return True
        config = {
            "title": "Windows Bridge",
            "text": f"Агент {agent} работает на вашем ПК (задача {task}). {apps_text}".strip(),
            "stop_label": "Стоп",
            "stopped_text": "Остановлено. Доступ агента отозван.",
            "done_text": "Агент закончил работу на ПК.",
            "stop_path": str(self.stop_path),
            "heartbeat_path": str(self.heartbeat_path),
            "idle_seconds": self.idle_seconds,
            "max_seconds": self.max_seconds,
        }
        config_path = self.dir / "notice-config.json"
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        try:
            self._proc = self.popen(
                ["powershell.exe", "-NoLogo", "-NoProfile", "-STA", "-WindowStyle", "Hidden",
                 "-ExecutionPolicy", "Bypass", "-File", str(self.script), "-ConfigPath", str(config_path)],
                creationflags=CREATE_NO_WINDOW, stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            self._proc = None
            return False
        self._key = key
        return True
