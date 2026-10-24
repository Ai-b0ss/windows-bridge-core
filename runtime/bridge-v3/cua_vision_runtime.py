from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import ctypes
import ctypes.wintypes as wt
from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Mapping

from cua_capture_contract import CaptureObservation, CoordinateSpace, VisualEntity
from cua_physical_runtime import PhysicalRuntimeError, Win32TargetApi
from cua_sidecar_supervisor import JsonLineSidecarSupervisor, SidecarError
from cua_visual_action_gate import (
    FreshGrounding, GroundedVisualMatch, VisualActionError, prepare_fresh_visual_action,
)


class VisionRuntimeError(RuntimeError):
    def __init__(self, code: str, details: Mapping[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.details = dict(details or {})


@dataclass
class _CaptureState:
    observation: CaptureObservation
    pixels: bytes
    frame_ticks: int
    session_id: int
    target_state: str


@dataclass
class _GroundedCandidate:
    ref: str
    entity: VisualEntity
    label: str
    role: str | None
    class_name: str | None
    evidence_fingerprint: str

class WindowsVisionRuntime:
    ENGINE = "WINDOWS_GRAPHICS_CAPTURE"
    DETECTOR_ENGINE = "OMNIPARSER_YOLOV9E"
    DETECTOR_SCHEMA = "ff-cua-vision-detector-v1"
    OCR_ENGINE = "WINDOWS_MEDIA_OCR"
    OCR_DEFAULT_LANGUAGE = "ru"
    DETECTOR_MODEL_SHA256 = "11c6cbb77f22569fab22d86c76407a83ec81ab89dbfe28279854822d6e3fb00c"
    _DWMWA_EXTENDED_FRAME_BOUNDS = 9
    _MAX_PIXEL_BYTES = 12_000_000
    _WGC_BUILD_CACHE_SCHEMA = "ff-cua-wgc-build-cache/v1"

    def __init__(
        self, package_root: str | Path, *, supervisor: Any | None = None,
        detector_supervisor: Any | None = None,
        detector_config: Mapping[str, Any] | None = None,
        ocr_supervisor: Any | None = None,
    ):
        self.root = Path(package_root).resolve()
        self._target_api = Win32TargetApi()
        self._user32 = ctypes.WinDLL("user32", use_last_error=True)
        self._dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._user32.IsIconic.argtypes = [wt.HWND]
        self._user32.IsIconic.restype = wt.BOOL
        self._user32.GetDpiForWindow.argtypes = [wt.HWND]
        self._user32.GetDpiForWindow.restype = wt.UINT
        self._user32.MonitorFromWindow.argtypes = [wt.HWND, wt.DWORD]
        self._user32.MonitorFromWindow.restype = wt.HMONITOR
        self._dwmapi.DwmGetWindowAttribute.argtypes = [wt.HWND, wt.DWORD, ctypes.c_void_p, wt.DWORD]
        self._dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long
        self._kernel32.ProcessIdToSessionId.argtypes = [wt.DWORD, ctypes.POINTER(wt.DWORD)]
        self._kernel32.ProcessIdToSessionId.restype = wt.BOOL
        self._supervisor = supervisor or self._make_supervisor()
        self._detector_supervisor = detector_supervisor
        self._detector_config_override = dict(detector_config) if detector_config is not None else None
        self._ocr_supervisor = ocr_supervisor
        self._detector_launch_key: tuple[str, str, int, int, int, str] | None = None
        self._generation: dict[str, int] = {}
        self._captures: dict[str, _CaptureState] = {}
        self._candidates: dict[str, dict[str, _GroundedCandidate]] = {}

    def _dotnet(self) -> Path:
        bundled = self.root / "native" / "dotnet" / "dotnet.exe"
        if bundled.is_file():
            return bundled
        configured = os.environ.get("FF_CUA_DOTNET")
        candidates = [configured, str(Path.home() / ".dotnet-cua" / "dotnet.exe"), shutil.which("dotnet.exe"), shutil.which("dotnet")]
        for item in candidates:
            if item and Path(item).is_file():
                return Path(item)
        raise VisionRuntimeError("DOTNET_NOT_FOUND")

    @staticmethod
    def _sha256_path(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _wgc_source_identity(sources: list[Path]) -> tuple[str, list[dict[str, Any]]]:
        records: list[dict[str, Any]] = []
        for source in sorted(sources, key=lambda item: item.name.casefold()):
            raw = source.read_bytes()
            records.append({
                "name": source.name,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
        encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest(), records

    def _wgc_cache_valid(self, build_dir: Path, source_digest: str) -> bool:
        marker = build_dir / "build-manifest.json"
        if not marker.is_file():
            return False
        try:
            data = json.loads(marker.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return False
        if data.get("schema") != self._WGC_BUILD_CACHE_SCHEMA or data.get("source_digest") != source_digest:
            return False
        records = data.get("files")
        if not isinstance(records, list) or not records:
            return False
        seen: set[str] = set()
        for item in records:
            if not isinstance(item, dict):
                return False
            rel = item.get("path")
            expected_sha = item.get("sha256")
            expected_bytes = item.get("bytes")
            if not isinstance(rel, str) or not rel or not isinstance(expected_sha, str) or not isinstance(expected_bytes, int):
                return False
            parts = Path(rel).parts
            if Path(rel).is_absolute() or ".." in parts:
                return False
            path = build_dir.joinpath(*parts)
            if not path.is_file() or path.stat().st_size != expected_bytes:
                return False
            if self._sha256_path(path) != expected_sha:
                return False
            seen.add(rel.replace("\\", "/"))
        required = {
            "cua_wgc_native_probe.dll",
            "cua_wgc_native_probe.deps.json",
            "cua_wgc_native_probe.runtimeconfig.json",
        }
        return required <= seen

    def _resolve_wgc_probe_dll(self) -> Path:
        project = self.root / "cua_wgc_native_probe" / "cua_wgc_native_probe.csproj"
        if not project.is_file():
            raise VisionRuntimeError("WGC_PROBE_SOURCE_MISSING", {"project": str(project)})
        sources = [project, *sorted(project.parent.glob("*.cs"), key=lambda item: item.name.casefold())]
        source_digest, source_records = self._wgc_source_identity(sources)
        bundled = self.root / "native" / "wgc"
        if bundled.exists():
            if not self._wgc_cache_valid(bundled, source_digest):
                raise VisionRuntimeError("WGC_BUNDLED_HASH_OR_SOURCE_MISMATCH")
            if not (self.root / "native" / "dotnet" / "dotnet.exe").is_file():
                raise VisionRuntimeError("WGC_BUNDLED_DOTNET_MISSING")
            return bundled / "cua_wgc_native_probe.dll"
        cache_root = self.root / ".cua-wgc-build-cache"
        build_dir = cache_root / source_digest
        dll = build_dir / "cua_wgc_native_probe.dll"
        if self._wgc_cache_valid(build_dir, source_digest):
            return dll

        cache_root.mkdir(parents=True, exist_ok=True)
        if build_dir.exists():
            try:
                shutil.rmtree(build_dir)
            except OSError as exc:
                raise VisionRuntimeError(
                    "WGC_PROBE_CACHE_INVALID",
                    {"source_digest": source_digest, "type": type(exc).__name__},
                ) from exc

        build_root = Path(tempfile.mkdtemp(prefix=f".build-{source_digest[:12]}-", dir=cache_root))
        try:
            source_dir = build_root / "src"
            output_dir = build_root / "out"
            source_dir.mkdir(parents=True)
            for source in sources:
                shutil.copy2(source, source_dir / source.name)
            try:
                cp = subprocess.run(
                    [
                        str(self._dotnet()), "build", str(source_dir / project.name),
                        "-c", "Release", "-o", str(output_dir), "--nologo",
                    ],
                    cwd=source_dir,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=90,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                raise VisionRuntimeError(
                    "WGC_PROBE_BUILD_TIMEOUT", {"source_digest": source_digest}
                ) from exc
            except OSError as exc:
                raise VisionRuntimeError(
                    "WGC_PROBE_BUILD_FAILED",
                    {"source_digest": source_digest, "type": type(exc).__name__},
                ) from exc
            if cp.returncode != 0:
                raise VisionRuntimeError(
                    "WGC_PROBE_BUILD_FAILED",
                    {
                        "source_digest": source_digest,
                        "returncode": int(cp.returncode),
                        "stderr_tail": (cp.stderr or "")[-600:],
                    },
                )

            built_dll = output_dir / "cua_wgc_native_probe.dll"
            if not built_dll.is_file():
                raise VisionRuntimeError(
                    "WGC_PROBE_BUILD_OUTPUT_MISSING", {"source_digest": source_digest}
                )
            file_records: list[dict[str, Any]] = []
            for path in sorted(
                (item for item in output_dir.rglob("*") if item.is_file()),
                key=lambda item: item.relative_to(output_dir).as_posix().casefold(),
            ):
                rel = path.relative_to(output_dir).as_posix()
                file_records.append({
                    "path": rel,
                    "bytes": path.stat().st_size,
                    "sha256": self._sha256_path(path),
                })
            marker = {
                "schema": self._WGC_BUILD_CACHE_SCHEMA,
                "source_digest": source_digest,
                "sources": source_records,
                "files": file_records,
            }
            (output_dir / "build-manifest.json").write_text(
                json.dumps(marker, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
                newline="\n",
            )

            if build_dir.exists():
                if self._wgc_cache_valid(build_dir, source_digest):
                    return dll
                raise VisionRuntimeError(
                    "WGC_PROBE_CACHE_CONFLICT", {"source_digest": source_digest}
                )
            try:
                output_dir.rename(build_dir)
            except OSError as exc:
                if self._wgc_cache_valid(build_dir, source_digest):
                    return dll
                raise VisionRuntimeError(
                    "WGC_PROBE_CACHE_PUBLISH_FAILED",
                    {"source_digest": source_digest, "type": type(exc).__name__},
                ) from exc
            if not self._wgc_cache_valid(build_dir, source_digest):
                raise VisionRuntimeError(
                    "WGC_PROBE_CACHE_VERIFY_FAILED", {"source_digest": source_digest}
                )
            return dll
        finally:
            shutil.rmtree(build_root, ignore_errors=True)

    def _make_supervisor(self) -> JsonLineSidecarSupervisor:
        dll = self._resolve_wgc_probe_dll()
        return JsonLineSidecarSupervisor(
            "vision-wgc", [str(self._dotnet()), str(dll), "--jsonl-sidecar"],
            env={"DOTNET_ROOT": str(self._dotnet().parent), "DOTNET_MULTILEVEL_LOOKUP": "0"},
            cwd=dll.parent, timeout_seconds=2.5, startup_grace_seconds=0.05,
            max_line_chars=20_000_000,
        )

    def _dwm_bounds(self, hwnd: int) -> tuple[int, int, int, int]:
        rect = wt.RECT()
        hr = int(self._dwmapi.DwmGetWindowAttribute(
            wt.HWND(hwnd), self._DWMWA_EXTENDED_FRAME_BOUNDS,
            ctypes.byref(rect), ctypes.sizeof(rect)))
        if hr != 0:
            raise VisionRuntimeError("CAPTURE_DWM_BOUNDS_UNAVAILABLE", {"hresult": hr})
        result = (int(rect.left), int(rect.top), int(rect.right), int(rect.bottom))
        if result[2] <= result[0] or result[3] <= result[1]:
            raise VisionRuntimeError("CAPTURE_BOUNDS_INVALID", {"bounds": list(result)})
        return result

    def _session_id(self, pid: int) -> int:
        sid = wt.DWORD()
        if not self._kernel32.ProcessIdToSessionId(wt.DWORD(pid), ctypes.byref(sid)):
            raise VisionRuntimeError("TARGET_SESSION_UNAVAILABLE", {"pid": pid})
        return int(sid.value)

    def _fingerprint(self, hwnd: int):
        try:
            return self._target_api.fingerprint(hwnd, 1)
        except PhysicalRuntimeError as exc:
            raise VisionRuntimeError(exc.code, exc.details) from exc

    def _metadata(self, state: _CaptureState, *, include_image: bool) -> dict[str, Any]:
        obs = state.observation
        space = obs.coordinate_space
        target = obs.target
        result: dict[str, Any] = {
            "route": "VISION_SEMANTIC",
            "capture_id": obs.capture_id,
            "generation": obs.generation,
            "engine": obs.engine,
            "captured_ns": obs.captured_ns,
            "freshness_marker": state.frame_ticks,
            "target_identity": {
                "hwnd": target.hwnd, "pid": target.pid,
                "process_start_ns": target.process_start_ns,
                "session_id": state.session_id,
            },
            "target_state": state.target_state,
            "pixel_dimensions": [space.width, space.height],
            "physical_bounds": [space.origin_x, space.origin_y, space.origin_x + space.width, space.origin_y + space.height],
            "logical_bounds_dip": [0.0, 0.0, space.width * 96.0 / space.dpi_x, space.height * 96.0 / space.dpi_y],
            "dpi": [space.dpi_x, space.dpi_y],
            "scale": [space.dpi_x / 96.0, space.dpi_y / 96.0],
            "monitor_id": space.monitor_id,
            "content_sha256": obs.content_sha256,
            "fresh": True,
            "physical_input_used": False,
            "fallback_chain": [{"engine": self.ENGINE, "status": "selected"}],
            "raw_pixels_persisted": False,
        }
        if include_image:
            result["image"] = {
                "encoding": "base64", "format": "BGRA8_TOP_DOWN",
                "width": space.width, "height": space.height,
                "data": base64.b64encode(state.pixels).decode("ascii"),
            }
        return result

    def capture(self, surface_id: str, hwnd: int, *, include_image: bool = True) -> dict[str, Any]:
        if not surface_id or not hwnd:
            raise VisionRuntimeError("VISION_TARGET_INVALID")
        if self._user32.IsIconic(wt.HWND(hwnd)):
            raise VisionRuntimeError("CAPTURE_MINIMIZED_UNSUPPORTED", {
                "attempted": False,
                "fallback_chain": [{"engine": self.ENGINE, "status": "declined", "reason": "minimized"}],
            })
        before = self._fingerprint(hwnd)
        bounds_before = self._dwm_bounds(hwnd)
        dpi_before = int(self._user32.GetDpiForWindow(wt.HWND(hwnd)) or 0)
        if dpi_before <= 0:
            raise VisionRuntimeError("DPI_UNAVAILABLE")
        try:
            marker = self._supervisor.request("mark", {}, timeout_seconds=2.5)
            min_fresh_ticks = marker.get("monotonic_ticks")
            if (
                marker.get("ok") is not True
                or isinstance(min_fresh_ticks, bool)
                or not isinstance(min_fresh_ticks, int)
                or min_fresh_ticks <= 0
            ):
                raise VisionRuntimeError(
                    "CAPTURE_FRESHNESS_MARK_FAILED",
                    {"attempted": False},
                )
            response = self._supervisor.request("capture", {
                "hwnd": hwnd, "timeout_ms": 1800, "stable_frames": 1,
                "min_fresh_ticks": min_fresh_ticks, "include_pixels": True,
                "max_pixel_bytes": self._MAX_PIXEL_BYTES,
            }, timeout_seconds=2.5)
        except SidecarError as exc:
            raise VisionRuntimeError(exc.code, {"attempted": True, **exc.details}) from exc
        if not response.get("ok"):
            code = str(response.get("error") or "CAPTURE_FAILED")
            raise VisionRuntimeError(code, {"attempted": True, "engine": self.ENGINE})
        after = self._fingerprint(hwnd)
        bounds_after = self._dwm_bounds(hwnd)
        dpi_after = int(self._user32.GetDpiForWindow(wt.HWND(hwnd)) or 0)
        if before != after or bounds_before != bounds_after or dpi_before != dpi_after:
            raise VisionRuntimeError("TARGET_MOVED", {"attempted": True})
        width = bounds_after[2] - bounds_after[0]
        height = bounds_after[3] - bounds_after[1]
        if [int(response.get("frame_w", 0)), int(response.get("frame_h", 0))] != [width, height]:
            # A persistent WGC session can yield one stale-size frame after a real
            # window resize. Recreate the capture session only for that bounded
            # recovery path; steady-state captures stay persistent to avoid the
            # resource leak caused by recreating every session.
            try:
                response = self._supervisor.request("capture", {
                    "hwnd": hwnd, "timeout_ms": 1800, "stable_frames": 1,
                    "min_fresh_ticks": min_fresh_ticks, "fresh_session": True,
                    "include_pixels": True, "max_pixel_bytes": self._MAX_PIXEL_BYTES,
                }, timeout_seconds=2.5)
            except SidecarError as exc:
                raise VisionRuntimeError(exc.code, {
                    "attempted": True, "resize_recovery_attempted": True, **exc.details,
                }) from exc
            if not response.get("ok"):
                code = str(response.get("error") or "CAPTURE_FAILED")
                raise VisionRuntimeError(code, {
                    "attempted": True, "engine": self.ENGINE,
                    "resize_recovery_attempted": True,
                })
            recovery_after = self._fingerprint(hwnd)
            recovery_bounds = self._dwm_bounds(hwnd)
            recovery_dpi = int(self._user32.GetDpiForWindow(wt.HWND(hwnd)) or 0)
            if (
                after != recovery_after
                or bounds_after != recovery_bounds
                or dpi_after != recovery_dpi
            ):
                raise VisionRuntimeError("TARGET_MOVED", {
                    "attempted": True, "resize_recovery_attempted": True,
                })
            if [int(response.get("frame_w", 0)), int(response.get("frame_h", 0))] != [width, height]:
                raise VisionRuntimeError("CAPTURE_GEOMETRY_MISMATCH", {
                    "frame": [response.get("frame_w"), response.get("frame_h")],
                    "dwm_bounds": list(bounds_after),
                    "resize_recovery_attempted": True,
                })
        encoded = response.get("pixel_bgra_base64")
        if not isinstance(encoded, str) or not encoded:
            raise VisionRuntimeError("CAPTURE_PIXELS_MISSING", {"attempted": True})
        try:
            pixels = base64.b64decode(encoded, validate=True)
        except Exception as exc:
            raise VisionRuntimeError("CAPTURE_PIXELS_INVALID") from exc
        expected_bytes = width * height * 4
        if len(pixels) != expected_bytes:
            raise VisionRuntimeError("CAPTURE_PIXEL_SIZE_MISMATCH", {"expected": expected_bytes, "actual": len(pixels)})
        digest = hashlib.sha256(pixels).hexdigest()
        if digest != str(response.get("pixel_sha256") or ""):
            raise VisionRuntimeError("CAPTURE_HASH_MISMATCH")
        generation = self._generation.get(surface_id, 0) + 1
        self._generation[surface_id] = generation
        monitor = int(self._user32.MonitorFromWindow(wt.HWND(hwnd), 2) or 0)
        space = CoordinateSpace(
            "WINDOW_DWM_FRAME_PHYSICAL_PX", bounds_after[0], bounds_after[1],
            width, height, dpi_after, dpi_after, f"HMONITOR:{monitor}",
        )
        observation = CaptureObservation.new(
            generation, self.ENGINE, after, space,
            captured_ns=time.monotonic_ns(), content_sha256=digest,
        )
        state = _CaptureState(
            observation, pixels, int(response.get("frame_system_relative_ticks") or 0),
            self._session_id(after.pid), "non_minimized",
        )
        self._captures[surface_id] = state
        self._candidates[surface_id] = {}
        result = self._metadata(state, include_image=include_image)
        result.update({"attempted": True, "verified": True})
        return result


    def _validated_detector_config(self) -> dict[str, Any]:
        raw = self._detector_config_override
        config_path = self.root.parent / "vision-detector.json"
        if raw is None:
            if not config_path.is_file():
                bundled = self.root / "native" / "detector"
                if not (bundled / "model.pt").is_file():
                    raise VisionRuntimeError("VISUAL_DETECTOR_NOT_CONFIGURED")
                raw = {"schema": self.DETECTOR_SCHEMA, "enabled": True,
                       "python": str(bundled / "python" / "python.exe"),
                       "model": str(bundled / "model.pt"),
                       "model_sha256": self.DETECTOR_MODEL_SHA256, "device": "cpu"}
            else:
                try:
                    loaded = json.loads(config_path.read_text(encoding="utf-8-sig"))
                except Exception as exc:
                    raise VisionRuntimeError(
                        "VISUAL_DETECTOR_CONFIG_INVALID", {"reason": type(exc).__name__}
                    ) from exc
                if not isinstance(loaded, Mapping):
                    raise VisionRuntimeError("VISUAL_DETECTOR_CONFIG_INVALID", {"reason": "not_object"})
                raw = dict(loaded)
        if raw.get("schema") != self.DETECTOR_SCHEMA:
            raise VisionRuntimeError("VISUAL_DETECTOR_CONFIG_INVALID", {"field": "schema"})
        if raw.get("enabled") is not True:
            raise VisionRuntimeError("VISUAL_DETECTOR_DISABLED")
        if str(raw.get("engine") or self.DETECTOR_ENGINE) != self.DETECTOR_ENGINE:
            raise VisionRuntimeError("VISUAL_DETECTOR_CONFIG_INVALID", {"field": "engine"})
        python_path = Path(str(raw.get("python") or ""))
        model_path = Path(str(raw.get("model") or ""))
        if not python_path.is_absolute() or not python_path.is_file():
            raise VisionRuntimeError("VISUAL_DETECTOR_CONFIG_INVALID", {"field": "python"})
        if not model_path.is_absolute() or not model_path.is_file():
            raise VisionRuntimeError("VISUAL_DETECTOR_CONFIG_INVALID", {"field": "model"})
        expected_sha = str(raw.get("model_sha256") or "").lower()
        if expected_sha != self.DETECTOR_MODEL_SHA256:
            raise VisionRuntimeError("VISUAL_DETECTOR_CONFIG_INVALID", {"field": "model_sha256"})
        stat = model_path.stat()
        model_size = int(stat.st_size)
        model_mtime_ns = int(stat.st_mtime_ns)
        imgsz = raw.get("imgsz", 640)
        confidence = raw.get("confidence", 0.25)
        iou = raw.get("iou", 0.10)
        max_candidates = raw.get("max_candidates", 64)
        if isinstance(imgsz, bool) or not isinstance(imgsz, int) or imgsz != 640:
            raise VisionRuntimeError("VISUAL_DETECTOR_CONFIG_INVALID", {"field": "imgsz"})
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or abs(float(confidence) - 0.25) > 1e-9:
            raise VisionRuntimeError("VISUAL_DETECTOR_CONFIG_INVALID", {"field": "confidence"})
        if isinstance(iou, bool) or not isinstance(iou, (int, float)) or abs(float(iou) - 0.10) > 1e-9:
            raise VisionRuntimeError("VISUAL_DETECTOR_CONFIG_INVALID", {"field": "iou"})
        if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or not 1 <= max_candidates <= 128:
            raise VisionRuntimeError("VISUAL_DETECTOR_CONFIG_INVALID", {"field": "max_candidates"})
        device = str(raw.get("device") or "cuda").lower()
        if device not in {"cpu", "cuda"}:
            raise VisionRuntimeError("VISUAL_DETECTOR_CONFIG_INVALID", {"field": "device"})
        return {
            "python": python_path, "model": model_path, "model_sha256": expected_sha,
            "model_size": model_size, "model_mtime_ns": model_mtime_ns,
            "imgsz": 640, "confidence": 0.25, "iou": 0.10,
            "max_candidates": max_candidates, "device": device,
        }

    def _detector_runtime(self) -> tuple[Any, dict[str, Any]]:
        config = self._validated_detector_config()
        sidecar = self.root / "cua_visual_detector_sidecar.py"
        if not sidecar.is_file():
            raise VisionRuntimeError("VISUAL_DETECTOR_SIDECAR_MISSING")
        launch_key = (
            str(config["python"]), str(config["model"]), int(config["max_candidates"]),
            int(config["model_size"]), int(config["model_mtime_ns"]),
            config["device"],
        )
        supervisor = self._detector_supervisor
        if supervisor is not None and self._detector_launch_key not in {None, launch_key}:
            try:
                supervisor.stop()
            except Exception:
                pass
            supervisor = None
            self._detector_supervisor = None
        if supervisor is None:
            supervisor = JsonLineSidecarSupervisor(
                "vision-detector",
                [
                    str(config["python"]), str(sidecar),
                    "--model", str(config["model"]),
                    "--expected-sha256", str(config["model_sha256"]),
                    "--device", config["device"], "--imgsz", "640",
                    "--conf", "0.25", "--iou", "0.1",
                    "--max-det", str(config["max_candidates"]),
                ],
                cwd=self.root, timeout_seconds=10.0,
                startup_grace_seconds=0.05, max_line_chars=2_000_000,
            )
            self._detector_supervisor = supervisor
            self._detector_launch_key = launch_key
        return supervisor, config

    def _ocr_runtime(self) -> Any:
        supervisor = self._ocr_supervisor
        if supervisor is not None:
            return supervisor
        sidecar = self.root / "cua_windows_ocr_sidecar.ps1"
        if not sidecar.is_file():
            raise VisionRuntimeError("WINDOWS_OCR_SIDECAR_MISSING")
        powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if not powershell:
            raise VisionRuntimeError("WINDOWS_OCR_POWERSHELL_UNAVAILABLE")
        supervisor = JsonLineSidecarSupervisor(
            "vision-ocr",
            [
                powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
                "-ExecutionPolicy", "Bypass", "-File", str(sidecar),
            ],
            cwd=self.root, timeout_seconds=3.0,
            startup_grace_seconds=0.05, max_line_chars=1_000_000,
        )
        self._ocr_supervisor = supervisor
        return supervisor

    @staticmethod
    def _validate_ocr_request(language: str, max_words: int) -> None:
        if (
            not isinstance(language, str) or not 1 <= len(language) <= 35
            or re.fullmatch(r"[A-Za-z0-9-]+", language) is None
        ):
            raise VisionRuntimeError("WINDOWS_OCR_LANGUAGE_INVALID")
        if isinstance(max_words, bool) or not isinstance(max_words, int) or not 1 <= max_words <= 256:
            raise VisionRuntimeError("WINDOWS_OCR_MAX_WORDS_INVALID")

    @staticmethod
    def _validate_ocr_text_layout(text_layout: str) -> None:
        if not isinstance(text_layout, str) or text_layout not in {"words", "lines"}:
            raise VisionRuntimeError("WINDOWS_OCR_TEXT_LAYOUT_INVALID")

    @staticmethod
    def _group_ocr_words_into_lines(words: list[Mapping[str, Any]]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for ordinal, word in enumerate(words):
            x, y, width, height = (float(value) for value in word["bbox"])
            center_y = y + height / 2.0
            candidates = [
                (abs(center_y - row["center_y"]), row)
                for row in rows
                if abs(center_y - row["center_y"])
                <= max(6.0, 0.45 * max(height, row["height"]))
            ]
            if candidates:
                _distance, row = min(candidates, key=lambda item: item[0])
                count = len(row["words"])
                row["center_y"] = (row["center_y"] * count + center_y) / (count + 1)
                row["height"] = max(row["height"], height)
                row["words"].append((x, ordinal, word))
            else:
                rows.append({
                    "center_y": center_y, "height": height,
                    "words": [(x, ordinal, word)],
                })

        lines: list[dict[str, Any]] = []
        for row in sorted(rows, key=lambda item: item["center_y"]):
            ordered = [item[2] for item in sorted(row["words"], key=lambda item: (item[0], item[1]))]
            chunks: list[list[Mapping[str, Any]]] = []
            current: list[Mapping[str, Any]] = []
            for word in ordered:
                if current:
                    previous = current[-1]["bbox"]
                    bbox = word["bbox"]
                    gap = float(bbox[0]) - (float(previous[0]) + float(previous[2]))
                    scale = max(float(previous[3]), float(bbox[3]))
                    if gap > max(48.0, 3.0 * scale):
                        chunks.append(current)
                        current = []
                current.append(word)
            if current:
                chunks.append(current)

            for chunk in chunks:
                left = min(float(word["bbox"][0]) for word in chunk)
                top = min(float(word["bbox"][1]) for word in chunk)
                right = max(float(word["bbox"][0]) + float(word["bbox"][2]) for word in chunk)
                bottom = max(float(word["bbox"][1]) + float(word["bbox"][3]) for word in chunk)
                lines.append({
                    "text": " ".join(str(word["text"]) for word in chunk),
                    "bbox": [left, top, right - left, bottom - top],
                })
        return lines

    @staticmethod
    def _order_ocr_lines_geometrically(lines: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
        """Keep OCR-native line membership while preserving the public geometry order."""
        rows: list[dict[str, Any]] = []
        for ordinal, line in enumerate(lines):
            x, y, _width, height = (float(value) for value in line["bbox"])
            center_y = y + height / 2.0
            candidates = [
                (abs(center_y - row["center_y"]), row)
                for row in rows
                if abs(center_y - row["center_y"])
                <= max(6.0, 0.45 * max(height, row["height"]))
            ]
            if candidates:
                _distance, row = min(candidates, key=lambda item: item[0])
                count = len(row["lines"])
                row["center_y"] = (row["center_y"] * count + center_y) / (count + 1)
                row["height"] = max(row["height"], height)
                row["lines"].append((x, ordinal, line))
            else:
                rows.append({"center_y": center_y, "height": height, "lines": [(x, ordinal, line)]})
        ordered: list[Mapping[str, Any]] = []
        for row in sorted(rows, key=lambda item: item["center_y"]):
            ordered.extend(item[2] for item in sorted(row["lines"], key=lambda item: (item[0], item[1])))
        return ordered

    @staticmethod
    def _validate_detector_request(max_candidates: int) -> None:
        if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or not 1 <= max_candidates <= 128:
            raise VisionRuntimeError("VISUAL_DETECTOR_MAX_CANDIDATES_INVALID")

    def ocr(
        self, surface_id: str, capture_id: str, *,
        language: str = OCR_DEFAULT_LANGUAGE, max_words: int = 128,
    ) -> dict[str, Any]:
        state = self._capture_state(surface_id, capture_id)
        self._validate_ocr_request(language, max_words)
        supervisor = self._ocr_runtime()
        width = state.observation.coordinate_space.width
        height = state.observation.coordinate_space.height
        try:
            response = supervisor.request(
                "ocr",
                {
                    "width": width, "height": height,
                    "pixel_bgra_base64": base64.b64encode(state.pixels).decode("ascii"),
                    "language": language, "max_words": max_words,
                },
                timeout_seconds=3.0,
            )
        except SidecarError as exc:
            code = "WINDOWS_OCR_TIMEOUT" if exc.code == "SIDECAR_TIMEOUT" else "WINDOWS_OCR_UNAVAILABLE"
            raise VisionRuntimeError(code, {"sidecar_error": exc.code, **exc.details}) from exc
        if response.get("ok") is not True:
            error = response.get("error") if isinstance(response.get("error"), Mapping) else {}
            code = str(error.get("code") or "WINDOWS_OCR_FAILED")
            raise VisionRuntimeError(code, {"message": str(error.get("message") or code)})
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise VisionRuntimeError("WINDOWS_OCR_OUTPUT_INVALID", {"reason": "result"})
        if result.get("engine") != self.OCR_ENGINE or result.get("language") != language:
            raise VisionRuntimeError("WINDOWS_OCR_OUTPUT_INVALID", {"reason": "identity"})
        if result.get("raw_pixels_persisted") is not False:
            raise VisionRuntimeError("WINDOWS_OCR_OUTPUT_INVALID", {"reason": "persistence"})
        inference_ms = result.get("inference_ms")
        if (
            isinstance(inference_ms, bool) or not isinstance(inference_ms, (int, float))
            or not math.isfinite(float(inference_ms)) or float(inference_ms) < 0
        ):
            raise VisionRuntimeError("WINDOWS_OCR_OUTPUT_INVALID", {"reason": "inference_ms"})
        words = result.get("words")
        word_count = result.get("word_count")
        total_word_count = result.get("total_word_count")
        truncated = result.get("truncated")
        if (
            not isinstance(words, list) or len(words) > max_words
            or isinstance(word_count, bool) or not isinstance(word_count, int) or word_count != len(words)
            or isinstance(total_word_count, bool) or not isinstance(total_word_count, int)
            or total_word_count < word_count
            or not isinstance(truncated, bool) or truncated != (total_word_count > word_count)
        ):
            raise VisionRuntimeError("WINDOWS_OCR_OUTPUT_INVALID", {"reason": "word_count"})
        public_words: list[dict[str, Any]] = []
        for index, raw in enumerate(words, start=1):
            if not isinstance(raw, Mapping):
                raise VisionRuntimeError("WINDOWS_OCR_OUTPUT_INVALID", {"index": index})
            text = raw.get("text")
            bbox_raw = raw.get("bbox")
            if (
                not isinstance(text, str) or not text.strip() or len(text) > 512
                or any(ord(ch) < 32 for ch in text)
                or not isinstance(bbox_raw, (list, tuple)) or len(bbox_raw) != 4
                or any(
                    isinstance(v, bool) or not isinstance(v, (int, float))
                    or not math.isfinite(float(v)) for v in bbox_raw
                )
            ):
                raise VisionRuntimeError("WINDOWS_OCR_OUTPUT_INVALID", {"index": index})
            x, y, w, h = (float(v) for v in bbox_raw)
            if x < 0 or y < 0 or w <= 0 or h <= 0 or x + w > width or y + h > height:
                raise VisionRuntimeError("WINDOWS_OCR_OUTPUT_INVALID", {"index": index, "reason": "bounds"})
            public_words.append({"text": text, "bbox": [x, y, w, h]})

        public_lines: list[dict[str, Any]] | None = None
        line_count: int | None = None
        total_line_count: int | None = None
        raw_lines = result.get("lines")
        if raw_lines is not None:
            line_count = result.get("line_count")
            total_line_count = result.get("total_line_count")
            if (
                not isinstance(raw_lines, list)
                or isinstance(line_count, bool) or not isinstance(line_count, int)
                or line_count != len(raw_lines) or line_count > word_count
                or isinstance(total_line_count, bool) or not isinstance(total_line_count, int)
                or total_line_count < line_count or total_line_count > total_word_count
            ):
                raise VisionRuntimeError("WINDOWS_OCR_OUTPUT_INVALID", {"reason": "line_count"})
            public_lines = []
            line_word_total = 0
            for index, raw in enumerate(raw_lines, start=1):
                if not isinstance(raw, Mapping):
                    raise VisionRuntimeError("WINDOWS_OCR_OUTPUT_INVALID", {"line_index": index})
                text = raw.get("text")
                bbox_raw = raw.get("bbox")
                member_count = raw.get("word_count")
                if (
                    not isinstance(text, str) or not text.strip() or len(text) > 4096
                    or any(ord(ch) < 32 for ch in text)
                    or not isinstance(bbox_raw, (list, tuple)) or len(bbox_raw) != 4
                    or any(
                        isinstance(v, bool) or not isinstance(v, (int, float))
                        or not math.isfinite(float(v)) for v in bbox_raw
                    )
                    or isinstance(member_count, bool) or not isinstance(member_count, int)
                    or member_count < 1 or member_count > word_count
                ):
                    raise VisionRuntimeError("WINDOWS_OCR_OUTPUT_INVALID", {"line_index": index})
                x, y, w, h = (float(v) for v in bbox_raw)
                if x < 0 or y < 0 or w <= 0 or h <= 0 or x + w > width or y + h > height:
                    raise VisionRuntimeError(
                        "WINDOWS_OCR_OUTPUT_INVALID",
                        {"line_index": index, "reason": "bounds"},
                    )
                line_word_total += member_count
                public_lines.append({"text": text, "bbox": [x, y, w, h]})
            if line_word_total != word_count:
                raise VisionRuntimeError(
                    "WINDOWS_OCR_OUTPUT_INVALID",
                    {"reason": "line_word_partition"},
                )
        return {
            "route": "VISION_OCR",
            "capture_id": capture_id,
            "generation": state.observation.generation,
            "ocr_engine": self.OCR_ENGINE,
            "language": language,
            "words": public_words,
            "word_count": word_count,
            "total_word_count": total_word_count,
            "lines": public_lines,
            "line_count": line_count,
            "total_line_count": total_line_count,
            "truncated": truncated,
            "inference_ms": float(inference_ms),
            "actionable_candidates_created": 0,
            "attempted": False,
            "verified": True,
            "physical_input_used": False,
            "raw_pixels_persisted": False,
        }

    def detect(self, surface_id: str, capture_id: str, *, max_candidates: int = 64) -> dict[str, Any]:
        state = self._capture_state(surface_id, capture_id)
        self._validate_detector_request(max_candidates)
        supervisor, config = self._detector_runtime()
        request_limit = min(max_candidates, int(config["max_candidates"]))
        width = state.observation.coordinate_space.width
        height = state.observation.coordinate_space.height
        try:
            response = supervisor.request(
                "detect",
                {
                    "width": width, "height": height,
                    "pixel_bgra_base64": base64.b64encode(state.pixels).decode("ascii"),
                    "max_candidates": request_limit,
                },
                timeout_seconds=10.0,
            )
        except SidecarError as exc:
            code = "VISUAL_DETECTOR_TIMEOUT" if exc.code == "SIDECAR_TIMEOUT" else "VISUAL_DETECTOR_UNAVAILABLE"
            raise VisionRuntimeError(code, {"sidecar_error": exc.code, **exc.details}) from exc
        if response.get("ok") is not True:
            error = response.get("error") if isinstance(response.get("error"), Mapping) else {}
            code = str(error.get("code") or "VISUAL_DETECTOR_FAILED")
            details = error.get("details") if isinstance(error.get("details"), Mapping) else {}
            raise VisionRuntimeError(code, details)
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise VisionRuntimeError("VISUAL_DETECTOR_OUTPUT_INVALID", {"reason": "result"})
        if result.get("engine") != self.DETECTOR_ENGINE or str(result.get("model_sha256") or "").lower() != self.DETECTOR_MODEL_SHA256:
            raise VisionRuntimeError("VISUAL_DETECTOR_OUTPUT_INVALID", {"reason": "identity"})
        raw_candidates = result.get("candidates")
        if not isinstance(raw_candidates, list) or len(raw_candidates) > request_limit:
            raise VisionRuntimeError("VISUAL_DETECTOR_OUTPUT_INVALID", {"reason": "candidate_count"})
        grounded_input: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_candidates, start=1):
            if not isinstance(raw, Mapping):
                raise VisionRuntimeError("VISUAL_DETECTOR_OUTPUT_INVALID", {"index": index})
            bbox_raw = raw.get("bbox")
            confidence = raw.get("confidence")
            if (
                not isinstance(bbox_raw, (list, tuple)) or len(bbox_raw) != 4
                or any(isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(float(v)) for v in bbox_raw)
                or isinstance(confidence, bool) or not isinstance(confidence, (int, float))
                or not math.isfinite(float(confidence))
                or not float(config["confidence"]) <= float(confidence) <= 1.0
            ):
                raise VisionRuntimeError("VISUAL_DETECTOR_OUTPUT_INVALID", {"index": index})
            x, y, w, h = (float(v) for v in bbox_raw)
            if x < 0 or y < 0 or w <= 0 or h <= 0 or x + w > width or y + h > height:
                raise VisionRuntimeError("VISUAL_DETECTOR_OUTPUT_INVALID", {"index": index, "reason": "bounds"})
            grounded_input.append({
                "label": f"visual-control-{index}",
                "role": "visual_control",
                "class": "omniparser_yolov9e",
                "bbox": [x, y, w, h],
                "confidence": float(confidence),
                "evidence_kind": self.DETECTOR_ENGINE,
            })
        inference_ms = result.get("inference_ms")
        if isinstance(inference_ms, bool) or not isinstance(inference_ms, (int, float)) or not math.isfinite(float(inference_ms)) or float(inference_ms) < 0:
            raise VisionRuntimeError("VISUAL_DETECTOR_OUTPUT_INVALID", {"reason": "inference_ms"})
        if grounded_input:
            output = self.ground(surface_id, capture_id, grounded_input)
        else:
            self._candidates[surface_id] = {}
            output = {
                "capture_id": capture_id, "generation": state.observation.generation,
                "candidates": [], "candidate_count": 0,
                "attempted": False, "verified": True, "physical_input_used": False,
            }
        output.update({
            "route": "VISION_DETECTOR",
            "detector_engine": self.DETECTOR_ENGINE,
            "model_sha256": self.DETECTOR_MODEL_SHA256,
            "imgsz": int(config["imgsz"]),
            "confidence_threshold": float(config["confidence"]),
            "inference_ms": float(inference_ms),
            "raw_pixels_persisted": False,
        })
        return output

    def observe(
        self, surface_id: str, capture_id: str, *,
        language: str = OCR_DEFAULT_LANGUAGE, max_words: int = 128,
        max_candidates: int = 64, text_layout: str = "words",
    ) -> dict[str, Any]:
        state = self._capture_state(surface_id, capture_id)
        self._validate_detector_request(max_candidates)
        self._validate_ocr_request(language, max_words)
        self._validate_ocr_text_layout(text_layout)

        detector_result: dict[str, Any] | None = None
        ocr_result: dict[str, Any] | None = None
        detector_error: VisionRuntimeError | None = None
        ocr_error: VisionRuntimeError | None = None

        try:
            with ThreadPoolExecutor(max_workers=2, thread_name_prefix="cua-observe") as pool:
                detector_future = pool.submit(
                    self.detect, surface_id, capture_id, max_candidates=max_candidates,
                )
                ocr_future = pool.submit(
                    self.ocr, surface_id, capture_id, language=language, max_words=max_words,
                )
                try:
                    detector_result = detector_future.result()
                except VisionRuntimeError as exc:
                    detector_error = exc
                try:
                    ocr_result = ocr_future.result()
                except VisionRuntimeError as exc:
                    ocr_error = exc
        except Exception:
            # A programming/runtime failure must not leave action targets created
            # by the sibling component behind after the observation command failed.
            self._candidates[surface_id] = {}
            raise

        components: dict[str, Any] = {}
        if detector_result is not None:
            components["detector"] = {
                "status": "ok",
                "engine": detector_result["detector_engine"],
                "candidate_count": detector_result["candidate_count"],
                "inference_ms": detector_result["inference_ms"],
            }
        else:
            self._candidates[surface_id] = {}
            assert detector_error is not None
            components["detector"] = {
                "status": "error",
                "error_code": detector_error.code,
                "details": dict(detector_error.details),
            }

        if ocr_result is not None:
            components["ocr"] = {
                "status": "ok",
                "engine": ocr_result["ocr_engine"],
                "language": ocr_result["language"],
                "word_count": ocr_result["word_count"],
                "total_word_count": ocr_result["total_word_count"],
                "truncated": ocr_result["truncated"],
                "inference_ms": ocr_result["inference_ms"],
            }
            if ocr_result.get("lines") is not None:
                components["ocr"]["line_count"] = ocr_result["line_count"]
                components["ocr"]["total_line_count"] = ocr_result["total_line_count"]
        else:
            assert ocr_error is not None
            components["ocr"] = {
                "status": "error",
                "error_code": ocr_error.code,
                "details": dict(ocr_error.details),
            }

        if detector_result is None and ocr_result is None:
            raise VisionRuntimeError(
                "VISION_OBSERVATION_FAILED",
                {"components": components, "attempted": False},
            )

        actionable = list(detector_result["candidates"]) if detector_result is not None else []
        text_regions = []
        text_region_layout_source = "ocr_words"
        if ocr_result is not None:
            ocr_regions = ocr_result["words"]
            if text_layout == "lines":
                native_lines = ocr_result.get("lines")
                if isinstance(native_lines, list):
                    ocr_regions = self._order_ocr_lines_geometrically(native_lines)
                    text_region_layout_source = "ocr_native_lines"
                else:
                    ocr_regions = self._group_ocr_words_into_lines(ocr_regions)
                    text_region_layout_source = "heuristic_lines"
            for index, region in enumerate(ocr_regions, start=1):
                text_regions.append({
                    "region_id": f"ot{state.observation.generation}r{index}",
                    "text": region["text"],
                    "bbox": list(region["bbox"]),
                    "source": self.OCR_ENGINE,
                    "actionable": False,
                })

        degraded = detector_result is None or ocr_result is None
        return {
            "route": "VISION_OBSERVATION",
            "capture_id": capture_id,
            "generation": state.observation.generation,
            "components": components,
            "actionable_candidates": actionable,
            "actionable_candidate_count": len(actionable),
            "text_regions": text_regions,
            "text_region_count": len(text_regions),
            "text_region_layout": text_layout,
            "text_region_layout_source": text_region_layout_source,
            "ocr_text_actionable": False,
            "degraded": degraded,
            "complete": not degraded,
            "attempted": False,
            "verified": True,
            "physical_input_used": False,
            "raw_pixels_persisted": False,
        }

    def _capture_state(self, surface_id: str, capture_id: str | None = None) -> _CaptureState:
        state = self._captures.get(surface_id)
        if state is None:
            raise VisionRuntimeError("CAPTURE_REQUIRED")
        if capture_id is not None and capture_id != state.observation.capture_id:
            raise VisionRuntimeError("STALE_CAPTURE", {
                "requested_capture_id": capture_id,
                "latest_capture_id": state.observation.capture_id,
            })
        return state

    @staticmethod
    def _crop_bytes(pixels: bytes, width: int, height: int, bbox: tuple[float, float, float, float]) -> bytes:
        x, y, w, h = bbox
        left = max(0, int(math.floor(x)))
        top = max(0, int(math.floor(y)))
        right = min(width, int(math.ceil(x + w)))
        bottom = min(height, int(math.ceil(y + h)))
        if right <= left or bottom <= top:
            raise VisionRuntimeError("VISUAL_ENTITY_BOUNDS_INVALID")
        if left != int(math.floor(x)) or top != int(math.floor(y)) or right != int(math.ceil(x + w)) or bottom != int(math.ceil(y + h)):
            raise VisionRuntimeError("VISUAL_ENTITY_OUTSIDE_CAPTURE")
        row_bytes = width * 4
        crop = bytearray()
        for row in range(top, bottom):
            start = row * row_bytes + left * 4
            crop.extend(pixels[start:start + (right - left) * 4])
        return bytes(crop)

    @classmethod
    def _crop_fingerprint(cls, pixels: bytes, width: int, height: int, bbox: tuple[float, float, float, float]) -> str:
        return hashlib.sha256(cls._crop_bytes(pixels, width, height, bbox)).hexdigest()

    @staticmethod
    def _candidate_public(candidate: _GroundedCandidate) -> dict[str, Any]:
        return {
            "ref": candidate.ref,
            "label": candidate.label,
            "role": candidate.role,
            "class": candidate.class_name,
            "bbox": list(candidate.entity.bbox_local),
            "confidence": candidate.entity.confidence,
            "evidence_kind": candidate.entity.evidence_kind,
            "evidence_fingerprint": candidate.evidence_fingerprint,
        }

    def ground(self, surface_id: str, capture_id: str, candidates: list[Mapping[str, Any]]) -> dict[str, Any]:
        state = self._capture_state(surface_id, capture_id)
        if not isinstance(candidates, list) or not candidates or len(candidates) > 128:
            raise VisionRuntimeError("VISUAL_CANDIDATES_INVALID")
        grounded: dict[str, _GroundedCandidate] = {}
        public: list[dict[str, Any]] = []
        for index, raw in enumerate(candidates, start=1):
            label = str(raw.get("label") or "").strip()
            role = str(raw.get("role")).strip() if raw.get("role") is not None else None
            class_name = str(raw.get("class") or raw.get("class_name")).strip() if (raw.get("class") is not None or raw.get("class_name") is not None) else None
            bbox_raw = raw.get("bbox")
            confidence = raw.get("confidence")
            if not label or not isinstance(bbox_raw, (list, tuple)) or len(bbox_raw) != 4:
                raise VisionRuntimeError("VISUAL_CANDIDATE_INVALID", {"index": index})
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                raise VisionRuntimeError("VISUAL_CONFIDENCE_INVALID", {"index": index})
            bbox = tuple(float(v) for v in bbox_raw)
            entity = VisualEntity.from_bbox(
                state.observation, bbox, confidence=float(confidence),
                evidence_kind=str(raw.get("evidence_kind") or "VISION"),
            )
            evidence = self._crop_fingerprint(
                state.pixels, state.observation.coordinate_space.width,
                state.observation.coordinate_space.height, bbox,
            )
            ref = f"vg{state.observation.generation}e{index}"
            candidate = _GroundedCandidate(ref, entity, label, role, class_name, evidence)
            grounded[ref] = candidate
            public.append(self._candidate_public(candidate))
        self._candidates[surface_id] = grounded
        return {"route": "VISION_SEMANTIC", "capture_id": capture_id,
                "generation": state.observation.generation, "candidates": public,
                "candidate_count": len(public), "attempted": False,
                "verified": True, "physical_input_used": False}

    def _candidate(self, surface_id: str, ref: str) -> tuple[_CaptureState, _GroundedCandidate]:
        state = self._capture_state(surface_id)
        candidate = self._candidates.get(surface_id, {}).get(ref)
        if candidate is None:
            raise VisionRuntimeError("STALE_TARGET", {
                "ref": ref, "latest_generation": state.observation.generation,
                "attempted": False,
            })
        if candidate.entity.capture_id != state.observation.capture_id or candidate.entity.generation != state.observation.generation:
            raise VisionRuntimeError("STALE_TARGET", {"ref": ref, "attempted": False})
        return state, candidate

    def find(self, surface_id: str, query: Mapping[str, Any]) -> dict[str, Any]:
        state = self._capture_state(surface_id)
        label = str(query.get("label") or "").strip().lower()
        role = str(query.get("role") or "").strip().lower()
        class_name = str(query.get("class") or query.get("class_name") or "").strip().lower()
        contains = bool(query.get("contains", False))
        if not label and not role and not class_name:
            raise VisionRuntimeError("VISUAL_QUERY_INVALID")
        matches = []
        for candidate in self._candidates.get(surface_id, {}).values():
            label_ok = True
            role_ok = True
            class_ok = True
            if label:
                actual = candidate.label.lower()
                label_ok = label in actual if contains else label == actual
            if role:
                role_ok = role == str(candidate.role or "").lower()
            if class_name:
                class_ok = class_name == str(candidate.class_name or "").lower()
            if label_ok and role_ok and class_ok:
                matches.append(self._candidate_public(candidate))
        return {"route": "VISION_SEMANTIC", "capture_id": state.observation.capture_id,
                "generation": state.observation.generation, "matches": matches,
                "candidate_count": len(matches), "attempted": False,
                "verified": True, "physical_input_used": False}

    def resolve(self, surface_id: str, query: Mapping[str, Any]) -> dict[str, Any]:
        found = self.find(surface_id, query)
        count = int(found["candidate_count"])
        if count == 0:
            raise VisionRuntimeError("NO_MATCH", {"attempted": False, "candidate_count": 0})
        if count != 1:
            raise VisionRuntimeError("TARGET_AMBIGUOUS", {"attempted": False, "candidate_count": count})
        result = dict(found)
        result["resolved_target"] = result.pop("matches")[0]
        return result

    def prepare_action(
        self, surface_id: str, ref: str, *,
        minimum_confidence: float = 0.90, max_center_drift_px: float = 16.0,
    ) -> dict[str, Any]:
        old_state, old_candidate = self._candidate(surface_id, ref)
        old_observation = old_state.observation
        width = old_observation.coordinate_space.width
        height = old_observation.coordinate_space.height
        old_crop = self._crop_bytes(old_state.pixels, width, height, old_candidate.entity.bbox_local)
        initial = GroundedVisualMatch(old_candidate.entity, old_candidate.evidence_fingerprint)
        current_target = self._fingerprint(old_observation.target.hwnd)
        radius = int(math.ceil(max_center_drift_px))

        def reground(_initial: GroundedVisualMatch) -> FreshGrounding:
            fresh_meta = self.capture(surface_id, old_observation.target.hwnd, include_image=False)
            fresh_state = self._capture_state(surface_id, str(fresh_meta["capture_id"]))
            x, y, w, h = old_candidate.entity.bbox_local
            matches: list[GroundedVisualMatch] = []
            for dy in range(-radius, radius + 1):
                for dx in range(-radius, radius + 1):
                    if math.hypot(dx, dy) > max_center_drift_px:
                        continue
                    bbox = (x + dx, y + dy, w, h)
                    try:
                        crop = self._crop_bytes(
                            fresh_state.pixels, fresh_state.observation.coordinate_space.width,
                            fresh_state.observation.coordinate_space.height, bbox,
                        )
                    except VisionRuntimeError as exc:
                        if exc.code in {"VISUAL_ENTITY_BOUNDS_INVALID", "VISUAL_ENTITY_OUTSIDE_CAPTURE"}:
                            continue
                        raise
                    if crop != old_crop:
                        continue
                    entity = VisualEntity.from_bbox(
                        fresh_state.observation, bbox,
                        confidence=old_candidate.entity.confidence,
                        evidence_kind=old_candidate.entity.evidence_kind,
                    )
                    matches.append(GroundedVisualMatch(entity, old_candidate.evidence_fingerprint))
            if not matches:
                raise VisualActionError("VISUAL_EVIDENCE_CHANGED", {
                    "attempted": False, "scope": "candidate",
                    "max_center_drift_px": max_center_drift_px,
                })
            return FreshGrounding(fresh_state.observation, tuple(matches))

        try:
            prepared = prepare_fresh_visual_action(
                initial=initial, initial_observation=old_observation,
                current_target=current_target, reground=reground,
                minimum_confidence=minimum_confidence,
                max_center_drift_px=max_center_drift_px,
            )
        except VisualActionError as exc:
            raise VisionRuntimeError(exc.code, {"attempted": False, **exc.details}) from exc

        fresh_match = prepared["match"]
        fresh_state = self._capture_state(surface_id, fresh_match.entity.capture_id)
        fresh_ref = f"vg{fresh_state.observation.generation}e1"
        fresh_candidate = _GroundedCandidate(
            fresh_ref, fresh_match.entity, old_candidate.label, old_candidate.role,
            old_candidate.class_name, fresh_match.evidence_fingerprint,
        )
        self._candidates[surface_id] = {fresh_ref: fresh_candidate}
        return {
            "route": "VISION_SEMANTIC",
            "capture_id": fresh_state.observation.capture_id,
            "generation": fresh_state.observation.generation,
            "fresh": True,
            "resolved_target": self._candidate_public(fresh_candidate),
            "point_virtual_physical_px": list(prepared["point"]),
            "visual_drift_px": prepared["drift_px"],
            "attempted": False, "verified": True,
            "physical_input_used": False, "wrong_target": 0,
        }

    def validate(self, surface_id: str, ref: str) -> dict[str, Any]:
        return self.prepare_action(surface_id, ref)

    def clear_surface(self, surface_id: str) -> None:
        self._generation.pop(surface_id, None)
        self._captures.pop(surface_id, None)
        self._candidates.pop(surface_id, None)

    def health(self) -> dict[str, Any]:
        return {
            "initialized": True,
            "engine": self.ENGINE,
            "sidecar": self._supervisor.health(),
            "capture_registry_size": len(self._captures),
            "candidate_registry_size": sum(len(v) for v in self._candidates.values()),
            "visual_detector": (
                {"configured": True, **self._detector_supervisor.health()}
                if getattr(self, "_detector_supervisor", None) is not None
                else {
                    "configured": bool(
                        getattr(self, "_detector_config_override", None) is not None
                        or (self.root.parent / "vision-detector.json").is_file()
                    ),
                    "running": False,
                }
            ),
            "windows_ocr": (
                {"configured": True, **self._ocr_supervisor.health()}
                if getattr(self, "_ocr_supervisor", None) is not None
                else {
                    "configured": bool(
                        (self.root / "cua_windows_ocr_sidecar.ps1").is_file()
                        and (shutil.which("powershell.exe") or shutil.which("powershell"))
                    ),
                    "running": False,
                }
            ),
            "raw_pixels_persisted": False,
        }

    def stop(self) -> None:
        self._captures.clear()
        self._candidates.clear()
        self._generation.clear()
        try:
            self._supervisor.stop()
        except Exception:
            pass
        detector = getattr(self, "_detector_supervisor", None)
        if detector is not None:
            try:
                detector.stop()
            except Exception:
                pass
        ocr = getattr(self, "_ocr_supervisor", None)
        if ocr is not None:
            try:
                ocr.stop()
            except Exception:
                pass
