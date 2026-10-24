from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from cua_sidecar_supervisor import JsonLineSidecarSupervisor, SidecarError


class SidecarSupervisorError(RuntimeError):
    pass


class NativeSidecarSupervisor:
    """Compatibility wrapper around the shared fail-closed sidecar boundary.

    ``engine`` is explicit because the native sidecar now contains more than one
    backend.  Omitting it preserves the historical sidecar default (winapp), while
    ``engine='hwnd'`` makes the bounded HWND_MESSAGE backend actually reachable
    without replacing the shared supervisor implementation.
    """

    def __init__(
        self,
        sidecar_path: str | Path,
        timeout_seconds: float = 3.0,
        *,
        engine: str | None = None,
        uia3_executable: str | Path | None = None,
    ):
        if engine not in {None, "winapp", "hwnd", "uia3"}:
            raise ValueError("engine must be one of: winapp, hwnd, uia3")
        self.sidecar_path = str(sidecar_path)
        self.engine = engine
        if engine == "uia3" and uia3_executable is not None:
            argv = [sys.executable, self.sidecar_path, "--engine", "uia3", "--uia3-exe", str(uia3_executable)]
        elif engine == "uia3":
            argv = [self.sidecar_path]
        else:
            argv = [sys.executable, self.sidecar_path]
            if engine is not None:
                argv.extend(["--engine", engine])
        name = "native" if engine is None else f"native-{engine}"
        self._supervisor = JsonLineSidecarSupervisor(
            name,
            argv,
            timeout_seconds=timeout_seconds,
        )

    @property
    def process(self):
        return self._supervisor.process

    @property
    def restart_count(self) -> int:
        return self._supervisor.restart_count

    def start(self) -> None:
        self._supervisor.start()

    def stop(self) -> None:
        self._supervisor.stop()

    def restart(self) -> None:
        self._supervisor.restart()

    def health(self) -> dict[str, Any]:
        result = self._supervisor.health()
        result["engine"] = self.engine or "sidecar-default"
        return result

    def request(self, op: str, args: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            return self._supervisor.request(op, args)
        except SidecarError as exc:
            legacy = {
                "SIDECAR_TIMEOUT": "SIDECAR_TIMEOUT_RESTARTED",
                "SIDECAR_PROTOCOL_DESYNC": "SIDECAR_PROTOCOL_DESYNC_RESTARTED",
            }.get(exc.code, exc.code)
            raise SidecarSupervisorError(legacy) from exc
